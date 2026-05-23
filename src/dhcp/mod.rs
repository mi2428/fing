//! DHCP lease ingestion.
//!
//! Lease files are a passive enrichment source: they can recover hostnames,
//! client identifiers, vendor classes, and sometimes MAC addresses without
//! probing a host. Parsers are intentionally permissive because distributions
//! and DHCP clients vary their on-disk formats.

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpLease {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub vendor_class: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub source: Option<PathBuf>,
}

pub fn default_lease_paths() -> Vec<PathBuf> {
    // Cover common macOS, ISC dhcpd/dhclient, dnsmasq, systemd-networkd, and
    // NetworkManager locations. Missing paths are filtered out before reading so
    // a normal workstation does not emit warnings for every unsupported stack.
    let mut paths = vec![
        PathBuf::from("/var/db/dhcpd_leases"),
        PathBuf::from("/var/lib/dhcp/dhcpd.leases"),
        PathBuf::from("/var/lib/dhcp/dhclient.leases"),
        PathBuf::from("/var/lib/dhcp3/dhclient.leases"),
        PathBuf::from("/var/lib/misc/dnsmasq.leases"),
        PathBuf::from("/var/db/dhcpclient/leases"),
    ];

    append_dir_entries(&mut paths, Path::new("/run/systemd/netif/leases"));
    append_dir_entries(&mut paths, Path::new("/var/lib/NetworkManager"));
    paths.sort();
    paths.dedup();
    paths.into_iter().filter(|path| path.exists()).collect()
}

pub fn read_leases(paths: &[PathBuf]) -> (Vec<DhcpLease>, Vec<String>) {
    let mut leases = Vec::new();
    let mut warnings = Vec::new();

    for path in paths {
        match read_path(path) {
            Ok(mut path_leases) => leases.append(&mut path_leases),
            Err(err) => warnings.push(format!(
                "failed to read DHCP leases {}: {err}",
                path.display()
            )),
        }
    }

    leases.sort_by_key(|lease| lease.ip);
    // Different local services can expose the same lease. Dedup on the identity
    // fields we actually consume, not on source path, so repeated reads do not
    // inflate evidence.
    leases.dedup_by(|left, right| {
        left.ip == right.ip
            && left.mac == right.mac
            && left.hostname == right.hostname
            && left.client_id == right.client_id
    });
    (leases, warnings)
}

fn append_dir_entries(paths: &mut Vec<PathBuf>, dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            paths.push(path);
        }
    }
}

fn read_path(path: &Path) -> Result<Vec<DhcpLease>> {
    if path.is_dir() {
        // Some managers store one lease per file. Read the direct children and
        // still parse every file through the same format-tolerant path.
        let mut leases = Vec::new();
        for entry in fs::read_dir(path).with_context(|| "read directory failed")? {
            let entry = entry.with_context(|| "read directory entry failed")?;
            if entry.path().is_file() {
                leases.extend(read_path(&entry.path())?);
            }
        }
        return Ok(leases);
    }

    let text = fs::read_to_string(path).with_context(|| "read failed")?;
    let now = Utc::now();
    let mut leases = parse_isc_leases_at(&text, now);
    leases.extend(parse_dnsmasq_leases_at(&text, now));
    leases.extend(parse_systemd_lease(&text));

    for lease in &mut leases {
        lease.source = Some(path.to_path_buf());
    }
    Ok(leases)
}

fn parse_isc_leases_at(input: &str, now: DateTime<Utc>) -> Vec<DhcpLease> {
    let mut leases = Vec::new();
    let mut current_ip = None;
    let mut current_body = Vec::new();

    // ISC leases are block-oriented. We keep only one block body in memory and
    // ignore malformed block headers rather than failing the whole lease file.
    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("lease ")
            && let Some((ip, _)) = rest.split_once('{')
        {
            current_ip = ip.trim().parse::<IpAddr>().ok();
            current_body.clear();
            continue;
        }
        if trimmed == "}" {
            if let Some(ip) = current_ip.take()
                && let Some(lease) = parse_isc_body(ip, &current_body, now)
            {
                leases.push(lease);
            }
            current_body.clear();
            continue;
        }
        if current_ip.is_some() {
            current_body.push(trimmed.to_string());
        }
    }

    leases
}

fn parse_dnsmasq_leases_at(input: &str, now: DateTime<Utc>) -> Vec<DhcpLease> {
    // dnsmasq uses one whitespace-delimited line:
    // expiry mac ip hostname client-id. Lines from other formats are skipped.
    input
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.contains('{') {
                return None;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 4 {
                return None;
            }
            let expiry = parts[0].parse::<i64>().ok()?;
            if expiry != 0 && expiry <= now.timestamp() {
                return None;
            }
            let ip = parts[2].parse::<IpAddr>().ok()?;
            Some(DhcpLease {
                ip,
                mac: normalize_mac(parts[1]),
                hostname: hostname_value(parts[3]),
                client_id: parts.get(4).and_then(|value| optional_value(value)),
                vendor_class: None,
                expires_at: (expiry > 0)
                    .then(|| Utc.timestamp_opt(expiry, 0).single())
                    .flatten(),
                source: None,
            })
        })
        .collect()
}

pub fn parse_systemd_lease(input: &str) -> Vec<DhcpLease> {
    // systemd-networkd lease files are key/value records. Accept a few key
    // spellings because versions and downstream patches have used both upper
    // and lower case names.
    let mut ip = None;
    let mut hostname = None;
    let mut client_id = None;
    let mut vendor_class = None;

    for line in input.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "ADDRESS" | "IP_ADDRESS" | "ip_address" => ip = value.parse::<IpAddr>().ok(),
            "HOSTNAME" | "host_name" | "name" => hostname = hostname_value(value),
            "CLIENTID" | "CLIENT_ID" | "dhcp_client_identifier" => {
                client_id = optional_value(value);
            }
            "VENDOR_CLASS_IDENTIFIER" | "vendor_class_identifier" => {
                vendor_class = optional_value(value);
            }
            _ => {}
        }
    }

    ip.map(|ip| DhcpLease {
        ip,
        mac: None,
        hostname,
        client_id,
        vendor_class,
        expires_at: None,
        source: None,
    })
    .into_iter()
    .collect()
}

fn parse_isc_body(ip: IpAddr, lines: &[String], now: DateTime<Utc>) -> Option<DhcpLease> {
    let mut lease = DhcpLease {
        ip,
        mac: None,
        hostname: None,
        client_id: None,
        vendor_class: None,
        expires_at: None,
        source: None,
    };
    let mut binding_state = None::<String>;

    for line in lines {
        let line = line.trim_end_matches(';').trim();
        if let Some(mac) = line.strip_prefix("hardware ethernet ") {
            lease.mac = normalize_mac(mac);
        } else if let Some(hostname) = line.strip_prefix("client-hostname ") {
            lease.hostname = hostname_value(hostname);
        } else if let Some(hostname) = line.strip_prefix("option host-name ") {
            lease.hostname = hostname_value(hostname);
        } else if let Some(client_id) = line.strip_prefix("uid ") {
            lease.client_id = optional_value(client_id.trim_matches('"'));
        } else if let Some((_, value)) = line.split_once("vendor-class-identifier =") {
            lease.vendor_class = optional_value(value.trim().trim_matches('"'));
        } else if let Some(value) = line.strip_prefix("option vendor-class-identifier ") {
            lease.vendor_class = optional_value(value.trim().trim_matches('"'));
        } else if let Some(value) = line.strip_prefix("binding state ") {
            binding_state = Some(value.trim().to_ascii_lowercase());
        } else if let Some(value) = line
            .strip_prefix("ends ")
            .or_else(|| line.strip_prefix("expire "))
        {
            lease.expires_at = parse_isc_lease_time(value);
        }
    }

    let active = binding_state
        .as_deref()
        .is_none_or(|state| state == "active");
    let unexpired = lease.expires_at.is_none_or(|expires_at| expires_at > now);
    (active && unexpired).then_some(lease)
}

fn parse_isc_lease_time(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim().trim_end_matches(';').trim();
    if value.eq_ignore_ascii_case("never") {
        return None;
    }

    let mut parts = value.split_whitespace();
    let first = parts.next()?;
    let (date, time) = if first.chars().all(|ch| ch.is_ascii_digit()) {
        (parts.next()?, parts.next()?)
    } else {
        (first, parts.next()?)
    };
    let naive =
        NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y/%m/%d %H:%M:%S").ok()?;
    Some(DateTime::from_naive_utc_and_offset(naive, Utc))
}

fn normalize_mac(value: &str) -> Option<String> {
    let hex = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>();
    if hex.len() != 12 {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn hostname_value(value: &str) -> Option<String> {
    optional_value(value.trim().trim_matches('"'))
}

fn optional_value(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(';').trim_matches('"');
    // Lease files use empty, "*" or "-" as placeholders. Treat them as absent
    // so they do not outrank real protocol names later.
    (!value.is_empty() && value != "*" && value != "-").then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_isc_dhcpd_lease() {
        let input = r#"
            lease 192.168.1.44 {
              hardware ethernet aa:bb:cc:dd:ee:ff;
              client-hostname "office";
              set vendor-class-identifier = "MSFT 5.0";
              binding state active;
              ends 6 2100/01/01 00:00:00;
            }
        "#;

        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let leases = parse_isc_leases_at(input, now);

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, "192.168.1.44".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(leases[0].hostname.as_deref(), Some("office"));
        assert_eq!(leases[0].vendor_class.as_deref(), Some("MSFT 5.0"));
        assert!(leases[0].expires_at.is_some());
    }

    #[test]
    fn skips_inactive_or_expired_isc_leases() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let input = r#"
            lease 192.168.1.44 {
              hardware ethernet aa:bb:cc:dd:ee:ff;
              client-hostname "active";
              binding state active;
              ends 6 2026/01/02 00:00:00;
            }
            lease 192.168.1.45 {
              hardware ethernet 00:11:22:33:44:55;
              client-hostname "expired";
              binding state active;
              ends 3 2025/12/31 00:00:00;
            }
            lease 192.168.1.46 {
              hardware ethernet 66:77:88:99:aa:bb;
              client-hostname "released";
              binding state free;
              ends 6 2026/01/02 00:00:00;
            }
        "#;

        let leases = parse_isc_leases_at(input, now);

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname.as_deref(), Some("active"));
    }

    #[test]
    fn parses_dnsmasq_lease_line() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let leases = parse_dnsmasq_leases_at(
            "4102444800 aa:bb:cc:dd:ee:ff 192.168.1.10 laptop 01:aa\n",
            now,
        );

        assert_eq!(leases[0].hostname.as_deref(), Some("laptop"));
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert!(leases[0].expires_at.is_some());
    }

    #[test]
    fn skips_expired_dnsmasq_lease_line() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let leases = parse_dnsmasq_leases_at(
            "1760000000 aa:bb:cc:dd:ee:ff 192.168.1.10 laptop 01:aa\n",
            now,
        );

        assert!(leases.is_empty());
    }

    #[test]
    fn parses_systemd_networkd_lease() {
        let leases = parse_systemd_lease("ADDRESS=192.168.1.9\nHOSTNAME=printer\nCLIENTID=abc\n");

        assert_eq!(leases[0].ip, "192.168.1.9".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].hostname.as_deref(), Some("printer"));
        assert_eq!(leases[0].client_id.as_deref(), Some("abc"));
    }
}
