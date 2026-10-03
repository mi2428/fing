//! Non-interactive output renderers.
//!
//! Table output is optimized for humans, while JSON and CSV preserve the fields
//! useful to scripts. Privacy options are applied here so callers can keep the
//! in-memory model unredacted.

use super::{OutputOptions, privacy, sources::source_summary};
use crate::model::{Device, ScanResult};
use anyhow::Result;
use comfy_table::{Cell, Table, presets::UTF8_FULL};

pub fn to_table(devices: &[Device], options: OutputOptions) -> String {
    // The human table omits device_type on purpose: type is mainly a rule output
    // used by CSV/JSON consumers, while terminal width is better spent on direct
    // identity fields such as make/model/name/OS.
    let masked_devices = options
        .mask_mac()
        .then(|| privacy::masked_devices(devices, options));
    let devices = masked_devices.as_deref().unwrap_or(devices);

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "IP",
        "Iface",
        "MAC",
        "Vendor",
        "Make",
        "Model",
        "Name",
        "OS",
        "Confidence",
        "Sources",
        "Last Seen",
    ]);

    for device in devices {
        table.add_row(vec![
            Cell::new(device.ip),
            Cell::new(device.interface.as_deref().unwrap_or("-")),
            Cell::new(privacy::display_mac(device.mac.as_deref(), options)),
            Cell::new(device.vendor.as_deref().unwrap_or("-")),
            Cell::new(
                device
                    .make
                    .as_ref()
                    .map(|guess| guess.value.as_str())
                    .unwrap_or("-"),
            ),
            Cell::new(
                device
                    .model
                    .as_ref()
                    .map(|guess| guess.value.as_str())
                    .unwrap_or("-"),
            ),
            Cell::new(device.hostname.as_deref().unwrap_or("-")),
            Cell::new(
                device
                    .os
                    .as_ref()
                    .map(|guess| guess.value.as_str())
                    .unwrap_or("-"),
            ),
            Cell::new(format!("{:.2}", device.identity_confidence())),
            Cell::new(source_summary(device)),
            Cell::new(device.last_seen.to_rfc3339()),
        ]);
    }

    table.to_string()
}

pub fn to_json(result: &ScanResult, options: OutputOptions) -> Result<String> {
    // Mask on a clone so exporting redacted JSON cannot corrupt cache matching
    // or later output formats in the same process.
    let result = privacy::masked_scan_result(result, options);
    Ok(serde_json::to_string_pretty(&result)?)
}

pub fn to_csv(devices: &[Device], options: OutputOptions) -> Result<String> {
    // CSV keeps device_type even though the human table omits it; spreadsheets
    // and automation usually benefit from the structured classification.
    let masked_devices = options
        .mask_mac()
        .then(|| privacy::masked_devices(devices, options));
    let devices = masked_devices.as_deref().unwrap_or(devices);

    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "ip",
        "interface",
        "mac",
        "vendor",
        "make",
        "model",
        "hostname",
        "os",
        "device_type",
        "confidence",
        "sources",
        "first_seen",
        "last_seen",
    ])?;

    for device in devices {
        writer.write_record([
            device.ip.to_string(),
            device.interface.clone().unwrap_or_default(),
            privacy::csv_mac(device.mac.as_deref(), options),
            device.vendor.clone().unwrap_or_default(),
            device
                .make
                .as_ref()
                .map(|guess| guess.value.clone())
                .unwrap_or_default(),
            device
                .model
                .as_ref()
                .map(|guess| guess.value.clone())
                .unwrap_or_default(),
            device.hostname.clone().unwrap_or_default(),
            device
                .os
                .as_ref()
                .map(|guess| guess.value.clone())
                .unwrap_or_default(),
            device
                .device_type
                .as_ref()
                .map(|guess| guess.value.clone())
                .unwrap_or_default(),
            format!("{:.2}", device.identity_confidence()),
            source_summary(device),
            device.first_seen.to_rfc3339(),
            device.last_seen.to_rfc3339(),
        ])?;
    }

    Ok(String::from_utf8(writer.into_inner()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{MacAddressDisplay, OutputOptions};
    use chrono::{TimeZone, Utc};

    #[test]
    fn csv_contains_expected_headers_and_values() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.interface = Some("en0".to_string());
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Example Inc".to_string());
        device.add_name("host", "rdns", 0.6);

        let csv = to_csv(&[device], OutputOptions::default()).unwrap();

        assert!(
            csv.contains("ip,interface,mac,vendor,make,model,hostname,os,device_type,confidence")
        );
        assert!(csv.contains("192.168.1.10"));
        assert!(csv.contains("en0"));
        assert!(csv.contains("Example Inc"));
        assert!(csv.contains(",0.60,"));
    }

    #[test]
    fn human_tables_omit_device_type_column() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.set_device_type_guess("smart-home", "identity_rule", 0.68);

        let table = to_table(&[device], OutputOptions::default());

        assert!(!table.contains("Type"));
        assert!(!table.contains("smart-home"));
    }

    #[test]
    fn csv_masks_mac_when_requested() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        let csv = to_csv(
            &[device],
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        )
        .unwrap();

        assert!(csv.contains("aa:bb:cc:**:**:**"));
        assert!(!csv.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn table_masks_mac_when_requested() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        let table = to_table(
            &[device],
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        );

        assert!(table.contains("aa:bb:cc:**:**:**"));
        assert!(!table.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn table_and_csv_mask_mac_like_identity_fields_when_requested() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.add_name("AA-BB-CC-DD-EE-FF", "mdns", 0.9);
        device.set_model_guess("AABBCCDDEEFF", "upnp", 0.85);

        let options = OutputOptions {
            mac: MacAddressDisplay::MaskLower24,
        };
        let table = to_table(&[device.clone()], options);
        let csv = to_csv(&[device], options).unwrap();

        assert!(table.contains("aa:bb:cc:**:**:**"));
        assert!(csv.contains("aa:bb:cc:**:**:**"));
        assert!(!table.contains("AA-BB-CC-DD-EE-FF"));
        assert!(!csv.contains("AABBCCDDEEFF"));
    }

    #[test]
    fn json_masks_mac_without_mutating_result() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.add_evidence("dhcp", "mac", "aa:bb:cc:dd:ee:ff", 0.55);
        let result = ScanResult {
            target: "192.168.1.0/24".to_string(),
            interface: "en0".to_string(),
            scanned_at: now,
            devices: vec![device],
            warnings: Vec::new(),
        };

        let json = to_json(
            &result,
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        )
        .unwrap();

        assert!(json.contains("aa:bb:cc:**:**:**"));
        assert!(!json.contains("aa:bb:cc:dd:ee:ff"));
        assert_eq!(result.devices[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            result.devices[0].evidence[0].value.as_str(),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn json_masks_identity_evidence_without_changing_hashes_or_source() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.0.2.10".parse().unwrap(), now);
        device.add_name("host-00:00:5e:00:53:01", "snmp", 0.82);
        device.add_evidence("snmp", "sysName", "host-00:00:5e:00:53:01", 0.82);
        device.add_evidence("snmp", "sysDescr", "00-00-5E-00-53-01", 0.82);
        device.add_evidence("cdp", "device_id", "node-00005e005301", 0.82);
        device.add_evidence("tls", "tls_cert_sha256", "00005e005301", 0.72);
        device.add_evidence("http", "favicon_sha256", "00005e005301deadbeef", 0.72);
        device.add_evidence("smb", "share", "00:00:5e:00:53:01", 0.65);
        device.add_evidence("test", "shadow", "00-00-5E-00-53-01", 0.65);
        device.add_evidence("http", "http_header_share", "node-00005e005301", 0.65);
        device.add_evidence("snmp", "sysObjectID", "1.3.6.1.4.1.9", 0.85);
        device.add_evidence(
            "smb",
            "smb_server_guid",
            "00005e005301deadbeef0123456789abcd",
            0.65,
        );
        let result = ScanResult {
            target: "192.0.2.0/24".to_string(),
            interface: "test0".to_string(),
            scanned_at: now,
            devices: vec![device],
            warnings: Vec::new(),
        };
        let original = result.clone();
        let masked = to_json(
            &result,
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        )
        .unwrap();
        let output: ScanResult = serde_json::from_str(&masked).unwrap();
        let values = &output.devices[0].evidence;
        assert_eq!(
            output.devices[0].hostname.as_deref(),
            Some("host-00:00:5e:**:**:**")
        );
        assert_eq!(values[0].value, "host-00:00:5e:**:**:**");
        assert_eq!(values[1].value, "00:00:5e:**:**:**");
        assert_eq!(values[2].value, "node-00:00:5e:**:**:**");
        assert_eq!(values[3].value, "00005e005301");
        assert_eq!(values[4].value, "00005e005301deadbeef");
        assert_eq!(values[5].value, "00:00:5e:**:**:**");
        assert_eq!(values[6].value, "00:00:5e:**:**:**");
        assert_eq!(values[7].value, "node-00:00:5e:**:**:**");
        assert_eq!(values[8].value, "1.3.6.1.4.1.9");
        assert_eq!(values[9].value, "00005e005301deadbeef0123456789abcd");
        assert_eq!(output.devices[0].names[0].name, "host-00:00:5e:**:**:**");
        assert_eq!(
            to_json(&result, OutputOptions::default()).unwrap(),
            serde_json::to_string_pretty(&result).unwrap()
        );
        assert_eq!(result, original);
    }
}
