//! DHCP lease ingestion.
//!
//! Lease files are a passive enrichment source: they can recover hostnames,
//! client identifiers, vendor classes, and sometimes MAC addresses without
//! probing a host. Parsers are intentionally permissive because distributions
//! and DHCP clients vary their on-disk formats.

use anyhow::{Context, Result};
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
        // Some managers store one lease per file. Recurse one directory tree but
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
    let mut leases = parse_isc_leases(&text);
    leases.extend(parse_dnsmasq_leases(&text));
    leases.extend(parse_systemd_lease(&text));

    for lease in &mut leases {
        lease.source = Some(path.to_path_buf());
    }
    Ok(leases)
}

pub fn parse_isc_leases(input: &str) -> Vec<DhcpLease> {
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
            if let Some(ip) = current_ip.take() {
                leases.push(parse_isc_body(ip, &current_body));
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

pub fn parse_dnsmasq_leases(input: &str) -> Vec<DhcpLease> {
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
            if parts.len() < 4 || parts[0].parse::<u64>().is_err() {
                return None;
            }
            let ip = parts[2].parse::<IpAddr>().ok()?;
            Some(DhcpLease {
                ip,
                mac: normalize_mac(parts[1]),
                hostname: hostname_value(parts[3]),
                client_id: parts.get(4).and_then(|value| optional_value(value)),
                vendor_class: None,
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
        source: None,
    })
    .into_iter()
    .collect()
}

fn parse_isc_body(ip: IpAddr, lines: &[String]) -> DhcpLease {
    let mut lease = DhcpLease {
        ip,
        mac: None,
        hostname: None,
        client_id: None,
        vendor_class: None,
        source: None,
    };

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
        }
    }

    lease
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

    #[test]
    fn parses_isc_dhcpd_lease() {
        let input = r#"
            lease 192.168.1.44 {
              hardware ethernet aa:bb:cc:dd:ee:ff;
              client-hostname "office";
              set vendor-class-identifier = "MSFT 5.0";
            }
        "#;

        let leases = parse_isc_leases(input);

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, "192.168.1.44".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(leases[0].hostname.as_deref(), Some("office"));
        assert_eq!(leases[0].vendor_class.as_deref(), Some("MSFT 5.0"));
    }

    #[test]
    fn parses_dnsmasq_lease_line() {
        let leases =
            parse_dnsmasq_leases("1760000000 aa:bb:cc:dd:ee:ff 192.168.1.10 laptop 01:aa\n");

        assert_eq!(leases[0].hostname.as_deref(), Some("laptop"));
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parses_systemd_networkd_lease() {
        let leases = parse_systemd_lease("ADDRESS=192.168.1.9\nHOSTNAME=printer\nCLIENTID=abc\n");

        assert_eq!(leases[0].ip, "192.168.1.9".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].hostname.as_deref(), Some("printer"));
        assert_eq!(leases[0].client_id.as_deref(), Some("abc"));
    }
}
