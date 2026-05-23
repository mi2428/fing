//! Last-scan cache persistence.
//!
//! The cache is not a source of truth for current reachability. It carries
//! stable identity fields forward only when a newly observed device can be
//! matched by MAC address. Interface/IP matches preserve first-seen continuity,
//! but do not copy names or guesses because DHCP address reuse is common.

use crate::model::Device;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const CACHE_SOURCE: &str = "cache";

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
    let mut by_mac = HashMap::new();
    let mut by_reachability = HashMap::new();
    for device in previous {
        if let Some(key) = mac_identity_key(device) {
            by_mac.insert(key, device);
        }
        by_reachability.insert(reachability_key(device), device);
    }

    for device in current {
        // A MAC match is stable enough to carry identity forward. An interface/IP
        // match only keeps first_seen continuity so DHCP address reuse cannot
        // relabel a newly observed host with stale names or guesses.
        if let Some(previous) = mac_identity_key(device).and_then(|key| by_mac.get(&key).copied()) {
            copy_cached_identity(device, previous);
        } else if let Some(previous) = by_reachability
            .get(&reachability_key(device))
            .copied()
            .filter(|previous| !known_mac_conflict(device, previous))
        {
            device.first_seen = previous.first_seen;
        }
    }
}

fn copy_cached_identity(device: &mut Device, previous: &Device) {
    device.first_seen = previous.first_seen;
    if device.vendor.is_none() {
        copy_cached_vendor(device, previous);
    }
    if device.hostname.is_none() {
        copy_cached_names(device, previous);
    }
    if device.make.is_none()
        && let Some(guess) = &previous.make
    {
        device.set_make_guess(&guess.value, CACHE_SOURCE, guess.confidence);
    }
    if device.model.is_none()
        && let Some(guess) = &previous.model
    {
        device.set_model_guess(&guess.value, CACHE_SOURCE, guess.confidence);
    }
    if device.os.is_none()
        && let Some(guess) = &previous.os
    {
        device.set_os_guess(&guess.value, CACHE_SOURCE, guess.confidence);
    }
    if device.device_type.is_none()
        && let Some(guess) = &previous.device_type
    {
        device.set_device_type_guess(&guess.value, CACHE_SOURCE, guess.confidence);
    }
}

fn copy_cached_vendor(device: &mut Device, previous: &Device) {
    let Some(vendor) = &previous.vendor else {
        return;
    };
    device.vendor = Some(vendor.clone());
    device.add_evidence(CACHE_SOURCE, "vendor", vendor, 0.55);
}

fn copy_cached_names(device: &mut Device, previous: &Device) {
    for name in &previous.names {
        device.add_name(name.name.clone(), CACHE_SOURCE, name.confidence);
    }
    if device.hostname.is_none()
        && let Some(hostname) = &previous.hostname
    {
        device.add_name(hostname.clone(), CACHE_SOURCE, 0.6);
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

fn mac_identity_key(device: &Device) -> Option<String> {
    let mac = normalize_mac(device.mac.as_deref()?);
    (mac.len() == 12).then(|| format!("mac:{mac}"))
}

fn reachability_key(device: &Device) -> String {
    // Interface is part of the fallback key because overlapping RFC1918 ranges
    // are common across VLANs, VPNs, and guest networks.
    if let Some(interface) = &device.interface {
        format!("iface-ip:{}:{}", interface, device.ip)
    } else {
        format!("ip:{}", device.ip)
    }
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
    fn cached_identity_is_marked_as_cache_source() {
        let old_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

        let mut previous = Device::new("192.168.1.10".parse().unwrap(), old_time);
        previous.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        previous.vendor = Some("Example Inc".to_string());
        previous.add_name("old-name", "mdns", 0.9);
        previous.set_model_guess("Example Camera", "upnp", 0.85);
        previous.set_os_guess("Embedded Linux", "snmp", 0.8);

        let mut current = Device::new("192.168.1.20".parse().unwrap(), new_time);
        current.mac = Some("AA-BB-CC-DD-EE-FF".to_string());

        merge_previous_scan(std::slice::from_mut(&mut current), &[previous]);

        assert_eq!(current.first_seen, old_time);
        assert_eq!(current.hostname.as_deref(), Some("old-name"));
        assert!(current.names.iter().all(|name| name.source == CACHE_SOURCE));
        assert_eq!(
            current.model.as_ref().map(|guess| guess.source.as_str()),
            Some(CACHE_SOURCE)
        );
        assert_eq!(
            current.os.as_ref().map(|guess| guess.source.as_str()),
            Some(CACHE_SOURCE)
        );
        assert!(current.evidence.iter().any(|evidence| {
            evidence.source == CACHE_SOURCE
                && evidence.key == "vendor"
                && evidence.value == "Example Inc"
        }));
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

    #[test]
    fn ip_fallback_preserves_first_seen_without_copying_identity() {
        let old_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

        let mut previous = Device::new("192.168.1.10".parse().unwrap(), old_time);
        previous.interface = Some("en0".to_string());
        previous.vendor = Some("Example Inc".to_string());
        previous.add_name("old-name", "mdns", 0.9);
        previous.set_model_guess("Example Camera", "upnp", 0.85);
        previous.set_os_guess("Embedded Linux", "snmp", 0.8);

        let mut current = Device::new("192.168.1.10".parse().unwrap(), new_time);
        current.interface = Some("en0".to_string());

        merge_previous_scan(std::slice::from_mut(&mut current), &[previous]);

        assert_eq!(current.first_seen, old_time);
        assert!(current.vendor.is_none());
        assert!(current.hostname.is_none());
        assert!(current.model.is_none());
        assert!(current.os.is_none());
    }
}
