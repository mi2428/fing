//! Display-time redaction helpers.
//!
//! MAC addresses identify hardware and are often sensitive in screenshots or
//! shared inventory exports. We only mask at the output boundary so the scanner
//! can still correlate devices by full MAC internally and preserve useful cache
//! continuity across IP changes.

use crate::model::{Device, Guess, ScanResult};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutputOptions {
    pub mac: MacAddressDisplay,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MacAddressDisplay {
    #[default]
    Full,
    MaskLower24,
}

impl OutputOptions {
    pub fn mask_mac(self) -> bool {
        matches!(self.mac, MacAddressDisplay::MaskLower24)
    }
}

pub fn display_mac(mac: Option<&str>, options: OutputOptions) -> String {
    match mac {
        Some(value) if options.mask_mac() => mask_lower_24_bits(value),
        Some(value) => value.to_string(),
        None => "-".to_string(),
    }
}

pub fn csv_mac(mac: Option<&str>, options: OutputOptions) -> String {
    match mac {
        Some(value) if options.mask_mac() => mask_lower_24_bits(value),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

pub fn display_identity(value: &str, options: OutputOptions) -> String {
    if options.mask_mac() {
        mask_identity_text(value)
    } else {
        value.to_string()
    }
}

pub fn masked_devices(devices: &[Device], options: OutputOptions) -> Vec<Device> {
    let mut devices = devices.to_vec();
    for device in &mut devices {
        mask_device(device, options);
    }
    devices
}

pub fn masked_scan_result(result: &ScanResult, options: OutputOptions) -> ScanResult {
    let mut result = result.clone();
    result.devices = masked_devices(&result.devices, options);
    result
}

fn mask_device(device: &mut Device, options: OutputOptions) {
    if !options.mask_mac() {
        return;
    }

    if let Some(mac) = device.mac.as_deref() {
        device.mac = Some(mask_lower_24_bits(mac));
    }

    mask_optional_identity(&mut device.vendor);
    mask_optional_identity(&mut device.hostname);
    for name in &mut device.names {
        name.name = mask_identity_text(&name.name);
    }
    mask_guess_identity(&mut device.make);
    mask_guess_identity(&mut device.model);
    mask_guess_identity(&mut device.os);
    mask_guess_identity(&mut device.device_type);
    for service in &mut device.services {
        service.name = mask_identity_text(&service.name);
    }

    for evidence in &mut device.evidence {
        evidence.value = mask_mac_evidence_value(&evidence.key, &evidence.value);
    }
}

fn mask_optional_identity(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = mask_identity_text(value);
    }
}

fn mask_guess_identity(guess: &mut Option<Guess>) {
    if let Some(guess) = guess {
        guess.value = mask_identity_text(&guess.value);
    }
}

fn mask_identity_text(value: &str) -> String {
    let masked = mask_compact_mac_tokens(&mask_separated_macs_relaxed(value));
    if masked == value {
        value.to_string()
    } else {
        masked
    }
}

fn mask_mac_evidence_value(key: &str, value: &str) -> String {
    if !evidence_key_may_contain_mac(key) {
        return value.to_string();
    }

    if key.eq_ignore_ascii_case("client_id")
        && let Some(masked) = mask_dhcp_mac_client_id(value)
    {
        return masked;
    }

    let masked = mask_separated_macs(value);
    if masked != value {
        return masked;
    }

    mask_compact_mac(value).unwrap_or_else(|| value.to_string())
}

fn evidence_key_may_contain_mac(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "mac"
        || key.ends_with("_mac")
        || matches!(key.as_str(), "chassis_id" | "port_id" | "client_id")
}

fn mask_dhcp_mac_client_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    for separator in [':', '-'] {
        let parts = trimmed.split(separator).collect::<Vec<_>>();
        if parts.len() == 7
            && parts[0].eq_ignore_ascii_case("01")
            && parts
                .iter()
                .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
        {
            return Some(format!("01:{}", mask_lower_24_bits(&parts[1..].join(":"))));
        }
    }

    if trimmed.len() == 14
        && trimmed.starts_with("01")
        && trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Some(format!("01:{}", mask_lower_24_bits(&trimmed[2..])));
    }

    None
}

fn mask_separated_macs(value: &str) -> String {
    mask_separated_macs_with_boundary(value, MacBoundary::Strict)
}

fn mask_separated_macs_relaxed(value: &str) -> String {
    mask_separated_macs_with_boundary(value, MacBoundary::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacBoundary {
    Strict,
    Relaxed,
}

fn mask_separated_macs_with_boundary(value: &str, boundary: MacBoundary) -> String {
    let mut masked = String::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if let Some((end, mac)) = separated_mac_at(value, index, boundary) {
            masked.push_str(&mask_lower_24_bits(mac));
            index = end;
        } else {
            let ch = value[index..]
                .chars()
                .next()
                .expect("index should be at a valid character boundary");
            masked.push(ch);
            index += ch.len_utf8();
        }
    }
    masked
}

fn separated_mac_at(value: &str, start: usize, boundary: MacBoundary) -> Option<(usize, &str)> {
    let bytes = value.as_bytes();
    if start + 17 > bytes.len() {
        return None;
    }
    if start > 0 && !mac_start_boundary(bytes[start - 1], boundary) {
        return None;
    }

    let separator = bytes[start + 2];
    if !matches!(separator, b':' | b'-') {
        return None;
    }

    for octet in 0..6 {
        let octet_start = start + octet * 3;
        if !bytes[octet_start].is_ascii_hexdigit() || !bytes[octet_start + 1].is_ascii_hexdigit() {
            return None;
        }
        if octet < 5 && bytes[octet_start + 2] != separator {
            return None;
        }
    }

    let end = start + 17;
    if end < bytes.len() && !mac_end_boundary(bytes[end], boundary) {
        return None;
    }
    Some((end, &value[start..end]))
}

fn mac_start_boundary(byte: u8, boundary: MacBoundary) -> bool {
    match boundary {
        MacBoundary::Strict => !is_mac_token_byte(byte),
        MacBoundary::Relaxed => !byte.is_ascii_hexdigit(),
    }
}

fn mac_end_boundary(byte: u8, boundary: MacBoundary) -> bool {
    mac_start_boundary(byte, boundary)
}

fn is_mac_token_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit() || matches!(byte, b':' | b'-')
}

fn mask_compact_mac_tokens(value: &str) -> String {
    let mut masked = String::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if let Some((end, mac)) = compact_mac_token_at(value, index) {
            masked.push_str(&mask_lower_24_bits(mac));
            index = end;
        } else {
            let ch = value[index..]
                .chars()
                .next()
                .expect("index should be at a valid character boundary");
            masked.push(ch);
            index += ch.len_utf8();
        }
    }
    masked
}

fn compact_mac_token_at(value: &str, start: usize) -> Option<(usize, &str)> {
    let bytes = value.as_bytes();
    if start + 12 > bytes.len() {
        return None;
    }
    if start > 0 && bytes[start - 1].is_ascii_hexdigit() {
        return None;
    }
    if !bytes[start..start + 12]
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let end = start + 12;
    if end < bytes.len() && bytes[end].is_ascii_hexdigit() {
        return None;
    }
    Some((end, &value[start..end]))
}

fn mask_compact_mac(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 12 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(mask_lower_24_bits(trimmed))
    } else {
        None
    }
}

fn mask_lower_24_bits(mac: &str) -> String {
    // Keep the OUI/vendor half visible and redact the NIC-specific half. This
    // preserves enough information to understand device families in demos while
    // avoiding disclosure of the unique hardware identifier.
    let parts = mac.split([':', '-']).collect::<Vec<_>>();
    if parts.len() == 6 {
        return format!(
            "{}:{}:{}:**:**:**",
            parts[0].to_ascii_lowercase(),
            parts[1].to_ascii_lowercase(),
            parts[2].to_ascii_lowercase()
        );
    }

    let hex = mac
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if hex.len() == 12 {
        return format!(
            "{}:{}:{}:**:**:**",
            &hex[0..2].to_ascii_lowercase(),
            &hex[2..4].to_ascii_lowercase(),
            &hex[4..6].to_ascii_lowercase()
        );
    }

    mac.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn masks_lower_24_bits_of_colon_mac() {
        assert_eq!(mask_lower_24_bits("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:**:**:**");
    }

    #[test]
    fn masks_lower_24_bits_of_hyphen_mac() {
        assert_eq!(mask_lower_24_bits("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:**:**:**");
    }

    #[test]
    fn masks_lower_24_bits_of_compact_mac() {
        assert_eq!(mask_lower_24_bits("AABBCCDDEEFF"), "aa:bb:cc:**:**:**");
    }

    #[test]
    fn keeps_unparseable_mac_unchanged() {
        assert_eq!(mask_lower_24_bits("not-a-mac"), "not-a-mac");
    }

    #[test]
    fn masks_scan_result_without_mutating_input() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("vendor aa-bb-cc-dd-ee-ff".to_string());
        device.add_name("AABBCCDDEEFF", "mdns", 0.9);
        device.add_name("android-AABBCCDDEEFF", "netbios", 0.8);
        device.set_model_guess("aa:bb:cc:dd:ee:ff camera", "upnp", 0.85);
        device.set_os_guess("AA-BB-CC-DD-EE-FF OS", "netbios", 0.8);
        device.add_service("aa-bb-cc-dd-ee-ff", "mdns", None, 0.7);
        let result = ScanResult {
            target: "192.168.1.0/24".to_string(),
            interface: "en0".to_string(),
            scanned_at: now,
            devices: vec![device.clone()],
            warnings: Vec::new(),
        };

        let masked = masked_scan_result(
            &result,
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        );

        assert_eq!(masked.devices[0].mac.as_deref(), Some("aa:bb:cc:**:**:**"));
        assert_eq!(
            masked.devices[0].hostname.as_deref(),
            Some("aa:bb:cc:**:**:**")
        );
        assert!(
            masked.devices[0]
                .names
                .iter()
                .any(|name| name.name == "android-aa:bb:cc:**:**:**")
        );
        assert_eq!(
            masked.devices[0].vendor.as_deref(),
            Some("vendor aa:bb:cc:**:**:**")
        );
        assert_eq!(
            masked.devices[0]
                .model
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("aa:bb:cc:**:**:** camera")
        );
        assert_eq!(
            masked.devices[0]
                .os
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("aa:bb:cc:**:**:** OS")
        );
        assert_eq!(
            masked.devices[0].services[0].name.as_str(),
            "aa:bb:cc:**:**:**"
        );
        assert_eq!(result.devices[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(result.devices[0].hostname.as_deref(), Some("AABBCCDDEEFF"));
    }

    #[test]
    fn masks_mac_values_embedded_in_evidence() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.add_evidence("dhcp", "mac", "aa:bb:cc:dd:ee:ff", 0.55);
        device.add_evidence("lldp", "source_mac", "00:11:22:33:44:55", 0.76);
        device.add_evidence("lldp", "chassis_id", "66778899aabb", 0.82);
        device.add_evidence("dhcp", "client_id", "01:aa:bb:cc:dd:ee:ff", 0.55);
        device.add_evidence("tls", "tls_cert_sha256", "aabbccddeeff", 0.72);
        let result = ScanResult {
            target: "192.168.1.0/24".to_string(),
            interface: "en0".to_string(),
            scanned_at: now,
            devices: vec![device],
            warnings: Vec::new(),
        };

        let masked = masked_scan_result(
            &result,
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        );
        let values = masked.devices[0]
            .evidence
            .iter()
            .map(|evidence| evidence.value.as_str())
            .collect::<Vec<_>>();

        assert!(values.contains(&"aa:bb:cc:**:**:**"));
        assert!(values.contains(&"00:11:22:**:**:**"));
        assert!(values.contains(&"66:77:88:**:**:**"));
        assert!(values.contains(&"01:aa:bb:cc:**:**:**"));
        assert!(values.contains(&"aabbccddeeff"));
        assert!(
            result.devices[0]
                .evidence
                .iter()
                .any(|evidence| evidence.value == "aa:bb:cc:dd:ee:ff")
        );
    }
}
