//! Core scan data model.
//!
//! Collectors append raw names, services, and evidence; identity rules and
//! output code read those facts and write best-effort guesses. Keeping both the
//! raw observations and the chosen guesses in the model lets exports explain why
//! a device was classified without making every collector know every rule.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    pub target: String,
    pub interface: String,
    pub scanned_at: DateTime<Utc>,
    pub devices: Vec<Device>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    #[serde(default)]
    pub interface: Option<String>,
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub names: Vec<NameEvidence>,
    #[serde(default)]
    pub make: Option<Guess>,
    #[serde(default)]
    pub model: Option<Guess>,
    pub os: Option<Guess>,
    pub device_type: Option<Guess>,
    pub services: Vec<ServiceEvidence>,
    pub evidence: Vec<Evidence>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameEvidence {
    pub name: String,
    pub source: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Guess {
    pub value: String,
    pub source: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceEvidence {
    pub name: String,
    pub source: String,
    pub port: Option<u16>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub source: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
}

impl Device {
    pub fn new(ip: IpAddr, now: DateTime<Utc>) -> Self {
        Self {
            interface: None,
            ip,
            mac: None,
            vendor: None,
            hostname: None,
            names: Vec::new(),
            make: None,
            model: None,
            os: None,
            device_type: None,
            services: Vec::new(),
            evidence: Vec::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    pub fn add_name(&mut self, name: impl Into<String>, source: &str, confidence: f32) {
        // Keep per-source duplicates out of the model while still allowing the
        // same name from independent protocols. Cross-source agreement is useful
        // evidence, but repeated packets from one protocol are just noise.
        let name = normalize_name(&name.into());
        if name.is_empty() {
            return;
        }

        if !self
            .names
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&name) && existing.source == source)
        {
            self.names.push(NameEvidence {
                name,
                source: source.to_string(),
                confidence,
            });
        }
        self.refresh_hostname();
    }

    pub fn add_evidence(
        &mut self,
        source: &str,
        key: &str,
        value: impl Into<String>,
        confidence: f32,
    ) {
        let value = value.into();
        if value.trim().is_empty() {
            return;
        }
        if !self
            .evidence
            .iter()
            .any(|item| item.source == source && item.key == key && item.value == value)
        {
            self.evidence.push(Evidence {
                source: source.to_string(),
                key: key.to_string(),
                value,
                confidence,
            });
        }
    }

    pub fn add_service(
        &mut self,
        name: impl Into<String>,
        source: &str,
        port: Option<u16>,
        confidence: f32,
    ) {
        let name = name.into();
        if name.trim().is_empty() {
            return;
        }
        if !self
            .services
            .iter()
            .any(|item| item.name == name && item.source == source && item.port == port)
        {
            self.services.push(ServiceEvidence {
                name,
                source: source.to_string(),
                port,
                confidence,
            });
        }
    }

    pub fn set_make_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        set_best_guess(&mut self.make, value, source, confidence);
    }

    pub fn set_model_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        set_best_guess(&mut self.model, value, source, confidence);
    }

    pub fn set_os_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        set_best_guess(&mut self.os, value, source, confidence);
    }

    pub fn set_device_type_guess(
        &mut self,
        value: impl Into<String>,
        source: &str,
        confidence: f32,
    ) {
        set_best_guess(&mut self.device_type, value, source, confidence);
    }

    fn refresh_hostname(&mut self) {
        // Prefer the strongest name signal. When confidence ties, shorter names
        // usually make better row labels than verbose service-instance names.
        self.hostname = self
            .names
            .iter()
            .max_by(|left, right| {
                left.confidence
                    .partial_cmp(&right.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| right.name.len().cmp(&left.name.len()))
            })
            .map(|name| name.name.clone());
    }

    pub fn identity_confidence(&self) -> f32 {
        let candidates = self
            .names
            .iter()
            .map(|name| name.confidence)
            .chain(self.make.iter().map(|guess| guess.confidence))
            .chain(self.model.iter().map(|guess| guess.confidence))
            .chain(self.os.iter().map(|guess| guess.confidence))
            .chain(self.device_type.iter().map(|guess| guess.confidence))
            .chain(self.services.iter().map(|service| service.confidence))
            .chain(self.evidence.iter().map(|evidence| evidence.confidence))
            .chain(self.vendor.as_ref().map(|_| 0.55))
            .chain(self.mac.as_ref().map(|_| 0.5));

        candidates
            .fold(0.0_f32, |best, confidence| best.max(confidence))
            .clamp(0.0, 1.0)
    }
}

fn set_best_guess(
    slot: &mut Option<Guess>,
    value: impl Into<String>,
    source: &str,
    confidence: f32,
) {
    let value = value.into();
    if value.trim().is_empty() {
        return;
    }
    // Equal-confidence guesses keep the first writer. Earlier phases tend to be
    // closer to direct protocol identity, while later rule passes can still win
    // by assigning a higher confidence.
    let should_replace = slot
        .as_ref()
        .is_none_or(|existing| confidence > existing.confidence);
    if should_replace {
        *slot = Some(Guess {
            value,
            source: source.to_string(),
            confidence,
        });
    }
}

pub fn normalize_name(name: &str) -> String {
    // Most local discovery protocols return FQDN-like names. Store the compact
    // host label so table search and cache continuity do not depend on suffixes.
    name.trim()
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .trim_end_matches(".lan")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_picks_highest_confidence_hostname() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);

        device.add_name("weak.local.", "rdns", 0.5);
        device.add_name("strong.local.", "mdns", 0.9);

        assert_eq!(device.hostname.as_deref(), Some("strong"));
    }

    #[test]
    fn duplicate_name_source_is_ignored() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);

        device.add_name("host.local", "mdns", 0.9);
        device.add_name("host.local", "mdns", 0.9);
        device.add_name("host.local", "netbios", 0.8);

        assert_eq!(device.names.len(), 2);
    }

    #[test]
    fn identity_confidence_uses_best_available_signal() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);

        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(device.identity_confidence(), 0.5);

        device.add_name("host.local", "mdns", 0.9);
        assert_eq!(device.identity_confidence(), 0.9);
    }
}
