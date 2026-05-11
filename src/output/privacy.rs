//! Display-time redaction helpers.
//!
//! MAC addresses identify hardware and are often sensitive in screenshots or
//! shared inventory exports. We only mask at the output boundary so the scanner
//! can still correlate devices by full MAC internally and preserve useful cache
//! continuity across IP changes.

use crate::model::{Device, ScanResult};

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

pub fn masked_scan_result(result: &ScanResult, options: OutputOptions) -> ScanResult {
    let mut result = result.clone();
    for device in &mut result.devices {
        mask_device(device, options);
    }
    result
}

fn mask_device(device: &mut Device, options: OutputOptions) {
    if let Some(mac) = device.mac.as_deref()
        && options.mask_mac()
    {
        device.mac = Some(mask_lower_24_bits(mac));
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
        assert_eq!(result.devices[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }
}
