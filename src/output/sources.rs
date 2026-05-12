//! Display summaries for evidence sources.
//!
//! Source summaries are presentation metadata, not scanner state. They explain
//! where visible identity came from while hiding internal rule-engine entries
//! that would otherwise duplicate the underlying evidence source.

use crate::model::Device;

pub(super) const SOURCE_LEGEND: &[(&str, &str)] = &[
    ("A", "ARP"),
    ("O", "OUI"),
    ("M", "mDNS"),
    ("N", "NetBIOS"),
    ("U", "UPnP"),
    ("D", "Deep"),
    ("R", "rDNS"),
    ("L", "Local"),
    ("C", "DHCP"),
    ("Y", "LLDP"),
    ("V", "CDP"),
    ("B", "SMB"),
    ("S", "SNMP"),
    ("H", "HTTP"),
    ("T", "TLS"),
    ("I", "ICMP"),
    ("P", "TCP"),
    ("K", "Cache"),
];

pub(super) fn source_summary(device: &Device) -> String {
    collect_device_sources(device).join(",")
}

pub(super) fn compact_source_summary(device: &Device) -> String {
    // The live table has very little horizontal budget. Single-letter codes keep
    // source visibility without crowding out the identity columns.
    let mut codes = collect_device_sources(device)
        .iter()
        .map(|source| source_code(source))
        .collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    codes.into_iter().collect()
}

fn collect_device_sources(device: &Device) -> Vec<String> {
    // Identity rules are derived from observations and should not appear as a
    // separate source. Showing both "upnp" and "identity_rule" would make the
    // row look better-sourced than it really is.
    let mut sources = device
        .names
        .iter()
        .map(|name| name.source.as_str())
        .chain(device.make.iter().map(|guess| guess.source.as_str()))
        .chain(device.model.iter().map(|guess| guess.source.as_str()))
        .chain(device.os.iter().map(|guess| guess.source.as_str()))
        .chain(device.device_type.iter().map(|guess| guess.source.as_str()))
        .chain(
            device
                .evidence
                .iter()
                .map(|evidence| evidence.source.as_str()),
        )
        .chain(
            device
                .services
                .iter()
                .map(|service| service.source.as_str()),
        )
        .filter(|source| *source != "identity_rule")
        .map(str::to_string)
        .collect::<Vec<_>>();
    if device.mac.is_some() {
        sources.push("arp".to_string());
    }
    if device.vendor.is_some() {
        sources.push("oui".to_string());
    }
    sources.sort();
    sources.dedup();
    sources
}

fn source_code(source: &str) -> char {
    match source {
        "arp" => 'A',
        "oui" => 'O',
        "mdns" => 'M',
        "netbios" => 'N',
        "upnp" => 'U',
        "deep" => 'D',
        "local" => 'L',
        "rdns" => 'R',
        "dhcp" => 'C',
        "lldp" => 'Y',
        "cdp" => 'V',
        "http" => 'H',
        "tls" => 'T',
        "smb" => 'B',
        "snmp" => 'S',
        "icmp" => 'I',
        "tcp" => 'P',
        "cache" => 'K',
        other => other
            .chars()
            .next()
            .map(|ch| ch.to_ascii_uppercase())
            .unwrap_or('?'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn source_summary_hides_rule_engine_as_a_display_source() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Example Inc".to_string());
        device.set_device_type_guess("smart-home", "identity_rule", 0.68);
        device.add_evidence("identity_rule", "rule", "example-device", 0.68);

        assert_eq!(source_summary(&device), "arp,oui");
        assert_eq!(compact_source_summary(&device), "AO");
    }

    #[test]
    fn compact_source_summary_uses_single_letter_source_codes() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Example Inc".to_string());
        device.add_name("host.local", "mdns", 0.9);
        device.add_evidence("deep", "port", "443", 0.55);
        device.add_evidence("local", "hostname", "host", 0.95);

        assert_eq!(source_summary(&device), "arp,deep,local,mdns,oui");
        assert_eq!(compact_source_summary(&device), "ADLMO");
    }
}
