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
    // Internal scan-round provenance; never changes the export/cache schema.
    #[serde(skip)]
    pub(crate) observation_round: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameEvidence {
    pub name: String,
    pub source: String,
    pub confidence: f32,
    #[serde(skip)]
    pub(crate) observation_round: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Guess {
    pub value: String,
    pub source: String,
    pub confidence: f32,
    #[serde(skip)]
    pub(crate) observation_round: u64,
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
    #[serde(skip)]
    pub(crate) observation_round: u64,
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
            observation_round: 0,
        }
    }

    pub fn add_name(&mut self, name: impl Into<String>, source: &str, confidence: f32) {
        self.add_name_in_round(name.into(), source, confidence, self.observation_round);
    }

    fn add_name_in_round(&mut self, name: String, source: &str, confidence: f32, round: u64) {
        // Keep per-source duplicates out of the model while still allowing the
        // same name from independent protocols. Cross-source agreement is useful
        // evidence, but repeated packets from one protocol are just noise.
        let name = normalize_name(&name);
        if name.is_empty() {
            return;
        }
        if self
            .names
            .iter()
            .any(|item| item.source == source && item.observation_round > round)
        {
            return;
        }
        // New same-source observations retire only older, no-stronger names.
        // Partial/weak updates retain richer names; current-round aliases union.
        self.names.retain(|item| {
            item.source != source || item.observation_round >= round || item.confidence > confidence
        });

        if !self
            .names
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&name) && existing.source == source)
        {
            self.names.push(NameEvidence {
                name,
                source: source.to_string(),
                confidence,
                observation_round: round,
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
        self.add_evidence_in_round(
            source,
            key,
            value.into(),
            confidence,
            self.observation_round,
        );
    }

    fn add_evidence_in_round(
        &mut self,
        source: &str,
        key: &str,
        value: String,
        confidence: f32,
        round: u64,
    ) {
        if value.trim().is_empty() {
            return;
        }
        // Replace only older rounds of this key, not independent keys or the
        // legitimate multiple values collected in the current round.
        if self
            .evidence
            .iter()
            .any(|item| item.source == source && item.key == key && item.observation_round > round)
        {
            return;
        }
        self.evidence.retain(|item| {
            item.source != source || item.key != key || item.observation_round >= round
        });
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
                observation_round: round,
            });
        }
    }

    pub(crate) fn mark_observation_round(&mut self, round: u64) {
        self.observation_round = round;
        for name in &mut self.names {
            if name.observation_round == 0 {
                name.observation_round = round;
            }
        }
        for guess in [
            &mut self.make,
            &mut self.model,
            &mut self.os,
            &mut self.device_type,
        ]
        .into_iter()
        .flatten()
        {
            if guess.observation_round == 0 {
                guess.observation_round = round;
            }
        }
        for item in &mut self.evidence {
            if item.observation_round == 0 {
                item.observation_round = round;
            }
        }
    }

    pub(crate) fn merge_evidence_snapshot(&mut self, incoming: Vec<Evidence>) {
        for item in incoming {
            self.add_evidence_in_round(
                &item.source,
                &item.key,
                item.value,
                item.confidence,
                item.observation_round,
            );
        }
    }

    pub(crate) fn merge_identity_snapshot(&mut self, incoming: &mut Device) {
        for name in std::mem::take(&mut incoming.names) {
            self.add_name_in_round(
                name.name,
                &name.source,
                name.confidence,
                name.observation_round,
            );
        }
        if self.hostname.is_none() {
            self.hostname = incoming.hostname.take();
        }
        for (slot, incoming) in [
            (&mut self.make, &mut incoming.make),
            (&mut self.model, &mut incoming.model),
            (&mut self.os, &mut incoming.os),
            (&mut self.device_type, &mut incoming.device_type),
        ] {
            if let Some(guess) = incoming.take() {
                set_best_guess(
                    slot,
                    guess.value,
                    &guess.source,
                    guess.confidence,
                    guess.observation_round,
                );
            }
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
        set_best_guess(
            &mut self.make,
            value,
            source,
            confidence,
            self.observation_round,
        );
    }

    pub fn set_model_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        set_best_guess(
            &mut self.model,
            value,
            source,
            confidence,
            self.observation_round,
        );
    }

    pub fn set_os_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        set_best_guess(
            &mut self.os,
            value,
            source,
            confidence,
            self.observation_round,
        );
    }

    pub fn set_device_type_guess(
        &mut self,
        value: impl Into<String>,
        source: &str,
        confidence: f32,
    ) {
        set_best_guess(
            &mut self.device_type,
            value,
            source,
            confidence,
            self.observation_round,
        );
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
    round: u64,
) {
    let value = value.into();
    if value.trim().is_empty() {
        return;
    }
    // Keep first-writer precedence within a round and across independent sources,
    // but let a newer same-source, no-weaker snapshot refresh an obsolete value.
    let should_replace = slot.as_ref().is_none_or(|existing| {
        confidence > existing.confidence
            || (existing.source == source
                    && round > existing.observation_round
                    && confidence >= existing.confidence
                    // Re-running a rule on retained facts is not a new identity
                    // observation. Do not promote its unchanged guess's age.
                    && (source != "identity_rule" || existing.value != value))
    });
    if should_replace {
        *slot = Some(Guess {
            value,
            source: source.to_string(),
            confidence,
            observation_round: round,
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
    fn identity_snapshots_refresh_same_source_without_erasing_richer_partials() {
        let ip = "192.0.2.10".parse().unwrap();
        let mut device = Device::new(ip, Utc::now());
        device.add_name("old", "mdns", 0.9);
        device.set_os_guess("old-os", "snmp", 0.85);
        device.set_model_guess("old-model", "upnp", 0.85);
        device.mark_observation_round(1);
        for round in 2..=3 {
            let mut partial = Device::new(ip, Utc::now());
            if round == 3 {
                partial.add_name("weak", "mdns", 0.5);
                partial.set_os_guess("weak-os", "snmp", 0.4);
            }
            partial.mark_observation_round(round);
            device.merge_identity_snapshot(&mut partial);
            assert_eq!(device.hostname.as_deref(), Some("old"));
            assert_eq!(device.os.as_ref().unwrap().value, "old-os");
            assert_eq!(device.model.as_ref().unwrap().value, "old-model");
        }
        let mut update = Device::new(ip, Utc::now());
        update.add_name("renamed-device", "mdns", 0.9);
        update.add_name("renamed-device-secondary", "mdns", 0.9);
        update.set_os_guess("new-os", "snmp", 0.85);
        update.set_model_guess("new-model", "upnp", 0.85);
        update.mark_observation_round(4);
        device.merge_identity_snapshot(&mut update);
        assert_eq!(device.hostname.as_deref(), Some("renamed-device"));
        assert_eq!(device.names.len(), 2);
        assert_eq!(device.os.as_ref().unwrap().value, "new-os");
        assert_eq!(device.model.as_ref().unwrap().value, "new-model");
        let mut delayed = Device::new(ip, Utc::now());
        delayed.add_name("old", "mdns", 0.9);
        delayed.set_os_guess("old-os", "snmp", 0.85);
        delayed.mark_observation_round(1);
        device.merge_identity_snapshot(&mut delayed);
        assert_eq!(device.hostname.as_deref(), Some("renamed-device"));
        assert_eq!(device.os.as_ref().unwrap().value, "new-os");
        let json = serde_json::to_value(&device).unwrap();
        assert!(json["os"].get("observation_round").is_none());
        assert!(
            json["names"]
                .as_array()
                .unwrap()
                .iter()
                .all(|name| name.get("observation_round").is_none())
        );
        device.observation_round = 5;
        device.set_device_type_guess("old-type", "identity_rule", 0.9);
        device.observation_round = 6;
        device.set_device_type_guess("old-type", "identity_rule", 0.9);
        device.set_device_type_guess("new-type", "identity_rule", 0.9);
        assert_eq!(device.device_type.as_ref().unwrap().value, "new-type");
    }

    #[test]
    fn evidence_snapshots_replace_older_rounds_without_collapsing_current_values() {
        let mut device = Device::new("192.0.2.10".parse().unwrap(), Utc::now());
        device.add_evidence("snmp", "sysObjectID", "1.3.6.1.4.1.8072", 0.85);
        for round in 1..=1_000 {
            let mut snapshot = Device::new(device.ip, Utc::now());
            for port in [80, 443] {
                snapshot.add_evidence(
                    "http",
                    "http_header_x_request_id",
                    format!("{round}-{port}"),
                    0.75,
                );
            }
            for ip in ["192.0.2.10", "192.0.2.11"] {
                snapshot.add_evidence("lldp", "management_address", ip, 0.84);
            }
            snapshot.mark_observation_round(round);
            device.merge_evidence_snapshot(snapshot.evidence);
            assert_eq!(device.evidence.len(), 5);
            assert!(
                device
                    .evidence
                    .iter()
                    .any(|item| item.value == format!("{round}-80"))
            );
            assert!(
                device
                    .evidence
                    .iter()
                    .any(|item| item.value == format!("{round}-443"))
            );
        }
        let mut delayed = Device::new(device.ip, Utc::now());
        delayed.add_evidence("http", "http_header_x_request_id", "obsolete", 0.75);
        delayed.mark_observation_round(999);
        device.merge_evidence_snapshot(delayed.evidence);
        assert_eq!(device.evidence.len(), 5);
        let json = serde_json::to_value(&device).unwrap();
        assert!(json.get("observation_round").is_none());
        assert!(
            json["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item.get("observation_round").is_none())
        );
    }

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
