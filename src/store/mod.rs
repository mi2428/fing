//! Last-scan cache persistence.
//!
//! The cache is not a source of truth for current reachability. It only carries
//! stable identity fields forward when a newly observed device can be matched by
//! MAC address or by the interface/IP tuple that produced the old evidence.

use crate::model::Device;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub fn default_scan_cache_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("fing")
        .join("last_scan.json")
}

pub fn load_scan_cache(path: &Path) -> Result<Vec<Device>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn save_scan_cache(path: &Path, devices: &[Device]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(devices)?)?;
    Ok(())
}

pub fn merge_previous_scan(current: &mut [Device], previous: &[Device]) {
    let mut by_key = HashMap::new();
    for device in previous {
        for key in identity_keys(device) {
            by_key.insert(key, device);
        }
    }

    for device in current {
        // Preserve the current scan's reachability and timestamps except for
        // first_seen. Cached identity fills gaps only; a fresh protocol result
        // should always win over a stale cached guess.
        if let Some(previous) = identity_keys(device)
            .into_iter()
            .find_map(|key| by_key.get(&key).copied())
            .filter(|previous| !known_mac_conflict(device, previous))
        {
            device.first_seen = previous.first_seen;
            if device.vendor.is_none() {
                device.vendor = previous.vendor.clone();
            }
            if device.hostname.is_none() {
                device.hostname = previous.hostname.clone();
                device.names = previous.names.clone();
            }
            if device.make.is_none() {
                device.make = previous.make.clone();
            }
            if device.model.is_none() {
                device.model = previous.model.clone();
            }
            if device.os.is_none() {
                device.os = previous.os.clone();
            }
            if device.device_type.is_none() {
                device.device_type = previous.device_type.clone();
            }
        }
    }
}

fn known_mac_conflict(current: &Device, previous: &Device) -> bool {
    matches!(
        (current.mac.as_deref(), previous.mac.as_deref()),
        (Some(current), Some(previous)) if normalize_mac(current) != normalize_mac(previous)
    )
}

fn normalize_mac(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(char::to_lowercase)
        .collect()
}

fn identity_keys(device: &Device) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(mac) = &device.mac {
        keys.push(format!("mac:{}", mac.to_ascii_lowercase()));
    }
    // Interface is part of the fallback key because overlapping RFC1918 ranges
    // are common across VLANs, VPNs, and guest networks.
    if let Some(interface) = &device.interface {
        keys.push(format!("iface-ip:{}:{}", interface, device.ip));
    } else {
        keys.push(format!("ip:{}", device.ip));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Device;
    use chrono::{TimeZone, Utc};

    #[test]
    fn merges_first_seen_by_mac_even_if_ip_changed() {
        let old_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

        let mut previous = Device::new("192.168.1.10".parse().unwrap(), old_time);
        previous.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        previous.add_name("old-name", "mdns", 0.9);

        let mut current = Device::new("192.168.1.20".parse().unwrap(), new_time);
        current.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        merge_previous_scan(std::slice::from_mut(&mut current), &[previous]);

        assert_eq!(current.first_seen, old_time);
        assert_eq!(current.hostname.as_deref(), Some("old-name"));
    }

    #[test]
    fn does_not_merge_cached_identity_by_ip_when_macs_conflict() {
        let old_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

        let mut previous = Device::new("192.168.1.10".parse().unwrap(), old_time);
        previous.interface = Some("en0".to_string());
        previous.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        previous.add_name("old-name", "mdns", 0.9);

        let mut current = Device::new("192.168.1.10".parse().unwrap(), new_time);
        current.interface = Some("en0".to_string());
        current.mac = Some("00:11:22:33:44:55".to_string());

        merge_previous_scan(std::slice::from_mut(&mut current), &[previous]);

        assert_eq!(current.first_seen, new_time);
        assert!(current.hostname.is_none());
    }
}
