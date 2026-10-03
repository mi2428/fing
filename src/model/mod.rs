//! Core scan data model.
//!
//! Collectors append raw names, services, and evidence; identity rules and
//! output code read those facts and write best-effort guesses. Keeping both the
//! raw observations and the chosen guesses in the model lets exports explain why
//! a device was classified without making every collector know every rule.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

type ObservationKey = (String, String);
static OBSERVATION_REVISION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_observation_revision() -> u64 {
    OBSERVATION_REVISION.fetch_add(1, Ordering::Relaxed)
}

fn unscoped_observation() -> BTreeSet<String> {
    BTreeSet::from([String::new()])
}

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
    #[serde(skip)]
    observations: BTreeMap<ObservationKey, u64>,
    #[serde(skip)]
    active_observation: Option<ObservationKey>,
    #[serde(skip)]
    pub(crate) observation_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameEvidence {
    pub name: String,
    pub source: String,
    pub confidence: f32,
    #[serde(skip)]
    pub(crate) observation_round: u64,
    #[serde(skip, default = "unscoped_observation")]
    scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Guess {
    pub value: String,
    pub source: String,
    pub confidence: f32,
    #[serde(skip)]
    pub(crate) observation_round: u64,
    #[serde(skip)]
    observation: Option<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceEvidence {
    pub name: String,
    pub source: String,
    pub port: Option<u16>,
    pub confidence: f32,
    #[serde(skip, default = "unscoped_observation")]
    scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub source: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    #[serde(skip)]
    #[serde(default = "unscoped_observation")]
    scopes: BTreeSet<String>,
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
            observations: BTreeMap::new(),
            active_observation: None,
            observation_revision: None,
        }
    }

    pub fn add_name(&mut self, name: impl Into<String>, source: &str, confidence: f32) {
        let scope = self.observation_scope(source);
        self.add_name_in_round(
            name.into(),
            source,
            confidence,
            self.observation_round,
            &scope,
        );
    }

    fn add_name_in_round(
        &mut self,
        name: String,
        source: &str,
        confidence: f32,
        round: u64,
        scope: &str,
    ) {
        // Keep per-source duplicates out of the model while still allowing the
        // same name from independent protocols. Cross-source agreement is useful
        // evidence, but repeated packets from one protocol are just noise.
        let name = normalize_name(&name);
        if name.is_empty() {
            return;
        }
        if self.names.iter().any(|item| {
            item.source == source && item.scopes.contains(scope) && item.observation_round > round
        }) {
            return;
        }
        // New same-source observations retire only older, no-stronger names.
        // Partial/weak updates retain richer names; current-round aliases union.
        self.names.retain_mut(|item| {
            if item.source == source
                && item.observation_round < round
                && item.confidence <= confidence
            {
                item.scopes.remove(scope);
            }
            !item.scopes.is_empty()
        });

        if let Some(existing) = self
            .names
            .iter_mut()
            .find(|existing| existing.name.eq_ignore_ascii_case(&name) && existing.source == source)
        {
            existing.scopes.insert(scope.to_string());
        } else {
            self.names.push(NameEvidence {
                name,
                source: source.to_string(),
                confidence,
                observation_round: round,
                scopes: BTreeSet::from([scope.to_string()]),
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
        let scope = self.observation_scope(source);
        self.add_evidence_in_scope(source, key, value.into(), confidence, &scope);
    }

    fn add_evidence_in_scope(
        &mut self,
        source: &str,
        key: &str,
        value: String,
        confidence: f32,
        scope: &str,
    ) {
        if value.trim().is_empty() {
            return;
        }
        if let Some(existing) = self
            .evidence
            .iter_mut()
            .find(|item| item.source == source && item.key == key && item.value == value)
        {
            existing.scopes.insert(scope.to_string());
        } else {
            self.evidence.push(Evidence {
                source: source.to_string(),
                key: key.to_string(),
                value,
                confidence,
                scopes: BTreeSet::from([scope.to_string()]),
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
    }

    fn observation_scope(&self, source: &str) -> String {
        self.active_observation
            .as_ref()
            .filter(|(active, _)| active == source)
            .map(|(_, scope)| scope.clone())
            .unwrap_or_default()
    }

    fn guess_observation(&self, source: &str) -> Option<(String, u64)> {
        let scope = self.observation_scope(source);
        self.observations
            .get(&(source.to_string(), scope.clone()))
            .map(|revision| (scope, *revision))
    }

    pub(crate) fn observe(
        &mut self,
        source: &str,
        scope: String,
        collect: impl FnOnce(&mut Device),
    ) {
        let key = (source.to_string(), scope);
        let revision = self
            .observation_revision
            .unwrap_or_else(next_observation_revision);
        if self
            .observations
            .get(&key)
            .is_some_and(|current| *current > revision)
        {
            return;
        }
        // Build just this observation, then replace its old facts as a set. This
        // preserves multiple current aliases/ports/addresses without any cap.
        let mut snapshot = Device::new(self.ip, self.first_seen);
        snapshot.last_seen = self.last_seen;
        snapshot.mac = self.mac.clone();
        snapshot.vendor = self.vendor.clone();
        snapshot.observation_round = self.observation_round;
        snapshot.observations.insert(key.clone(), revision);
        snapshot.active_observation = Some(key);
        collect(&mut snapshot);
        // Keep current protocol hints observable even if a stronger displayed
        // guess wins the scalar slot (especially a prior rule-derived guess).
        for (field, guess) in [
            ("make", snapshot.make.clone()),
            ("model", snapshot.model.clone()),
            ("os", snapshot.os.clone()),
            ("device_type", snapshot.device_type.clone()),
        ] {
            if let Some(guess) = guess
                && guess.source == source
            {
                snapshot.add_evidence(source, field, guess.value, guess.confidence);
            }
        }
        if self.mac.is_none() {
            self.mac = snapshot.mac.take();
        }
        if self.vendor.is_none() {
            self.vendor = snapshot.vendor.take();
        }
        self.merge_observation_snapshot(&mut snapshot);
    }

    fn scopes_are_current(&self, incoming: &Device, source: &str, scope: &str) -> bool {
        let key = (source.to_string(), scope.to_string());
        self.observations.get(&key) == incoming.observations.get(&key)
    }

    pub(crate) fn merge_observation_snapshot(&mut self, incoming: &mut Device) {
        for ((source, scope), revision) in &incoming.observations {
            let key = (source.clone(), scope.clone());
            if self
                .observations
                .get(&key)
                .is_none_or(|current| current < revision)
            {
                if incoming
                    .evidence
                    .iter()
                    .any(|item| item.source == *source && item.scopes.contains(scope))
                {
                    self.evidence.retain_mut(|item| {
                        if item.source == *source {
                            item.scopes.remove(scope);
                        }
                        !item.scopes.is_empty()
                    });
                }
                let name_confidence = incoming
                    .names
                    .iter()
                    .filter(|item| item.source == *source && item.scopes.contains(scope))
                    .map(|item| item.confidence)
                    .reduce(f32::max);
                self.names.retain_mut(|item| {
                    if item.source == *source
                        && name_confidence.is_some_and(|confidence| item.confidence <= confidence)
                    {
                        item.scopes.remove(scope);
                    }
                    !item.scopes.is_empty()
                });
                if incoming
                    .services
                    .iter()
                    .any(|item| item.source == *source && item.scopes.contains(scope))
                {
                    self.services.retain_mut(|item| {
                        if item.source == *source {
                            item.scopes.remove(scope);
                        }
                        !item.scopes.is_empty()
                    });
                }
                self.observations.insert(key, *revision);
            }
        }
        self.merge_identity_snapshot(incoming);
        for item in std::mem::take(&mut incoming.evidence) {
            for scope in &item.scopes {
                if self.scopes_are_current(incoming, &item.source, scope) {
                    self.add_evidence_in_scope(
                        &item.source,
                        &item.key,
                        item.value.clone(),
                        item.confidence,
                        scope,
                    );
                }
            }
        }
        for item in std::mem::take(&mut incoming.services) {
            for scope in &item.scopes {
                if self.scopes_are_current(incoming, &item.source, scope) {
                    self.add_service_in_scope(
                        item.name.clone(),
                        &item.source,
                        item.port,
                        item.confidence,
                        scope,
                    );
                }
            }
        }
    }

    pub(crate) fn merge_identity_snapshot(&mut self, incoming: &mut Device) {
        for name in std::mem::take(&mut incoming.names) {
            for scope in &name.scopes {
                if self.scopes_are_current(incoming, &name.source, scope) {
                    self.add_name_in_round(
                        name.name.clone(),
                        &name.source,
                        name.confidence,
                        name.observation_round,
                        scope,
                    );
                }
            }
        }
        if self.hostname.is_none() {
            self.hostname = incoming.hostname.take();
        }
        let observations = &self.observations;
        for (slot, incoming) in [
            (&mut self.make, &mut incoming.make),
            (&mut self.model, &mut incoming.model),
            (&mut self.os, &mut incoming.os),
            (&mut self.device_type, &mut incoming.device_type),
        ] {
            if let Some(guess) = incoming.take() {
                if guess.observation.as_ref().is_some_and(|(scope, revision)| {
                    observations
                        .get(&(guess.source.clone(), scope.clone()))
                        .is_some_and(|current| current != revision)
                }) {
                    continue;
                }
                set_best_guess(
                    slot,
                    guess.value,
                    &guess.source,
                    guess.confidence,
                    guess.observation_round,
                    guess.observation,
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
        let scope = self.observation_scope(source);
        self.add_service_in_scope(name.into(), source, port, confidence, &scope);
    }

    fn add_service_in_scope(
        &mut self,
        name: String,
        source: &str,
        port: Option<u16>,
        confidence: f32,
        scope: &str,
    ) {
        if name.trim().is_empty() {
            return;
        }
        if let Some(existing) = self
            .services
            .iter_mut()
            .find(|item| item.name == name && item.source == source && item.port == port)
        {
            existing.scopes.insert(scope.to_string());
        } else {
            self.services.push(ServiceEvidence {
                name,
                source: source.to_string(),
                port,
                confidence,
                scopes: BTreeSet::from([scope.to_string()]),
            });
        }
    }

    pub fn set_make_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        let observation = self.guess_observation(source);
        set_best_guess(
            &mut self.make,
            value,
            source,
            confidence,
            self.observation_round,
            observation,
        );
    }

    pub fn set_model_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        let observation = self.guess_observation(source);
        set_best_guess(
            &mut self.model,
            value,
            source,
            confidence,
            self.observation_round,
            observation,
        );
    }

    pub fn set_os_guess(&mut self, value: impl Into<String>, source: &str, confidence: f32) {
        let observation = self.guess_observation(source);
        set_best_guess(
            &mut self.os,
            value,
            source,
            confidence,
            self.observation_round,
            observation,
        );
    }

    pub fn set_device_type_guess(
        &mut self,
        value: impl Into<String>,
        source: &str,
        confidence: f32,
    ) {
        let observation = self.guess_observation(source);
        set_best_guess(
            &mut self.device_type,
            value,
            source,
            confidence,
            self.observation_round,
            observation,
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
    observation: Option<(String, u64)>,
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
                    && (round > existing.observation_round || observation.as_ref().zip(existing.observation.as_ref())
                        .is_some_and(|((scope, revision), (old_scope, old_revision))| scope == old_scope && revision > old_revision))
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
            observation,
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
    fn evidence_snapshots_replace_logical_observations_without_collapsing_current_values() {
        let mut device = Device::new("192.0.2.10".parse().unwrap(), Utc::now());
        device.add_evidence("snmp", "sysObjectID", "1.3.6.1.4.1.8072", 0.85);
        let mut delayed = None;
        for sequence in 1..=1_000 {
            let mut snapshot = Device::new(device.ip, Utc::now());
            for port in [80, 443] {
                snapshot.observe("http", port.to_string(), |snapshot| {
                    snapshot.add_evidence(
                        "http",
                        &format!("http_header_x_key_{sequence}"),
                        format!("{sequence}-{port}"),
                        0.75,
                    );
                    snapshot.add_evidence("http", "http_header_server", "shared", 0.75);
                });
            }
            snapshot.observe("lldp", "synthetic-peer|port1".into(), |snapshot| {
                for ip in ["192.0.2.10", "192.0.2.11"] {
                    snapshot.add_evidence("lldp", "management_address", ip, 0.84);
                }
                snapshot.add_evidence("lldp", "system_description", sequence.to_string(), 0.9);
            });
            snapshot.mark_observation_round(1); // no round boundary/pause required
            if sequence == 1 {
                delayed = Some(snapshot.clone());
            }
            device.merge_observation_snapshot(&mut snapshot);
            assert_eq!(device.evidence.len(), 7);
            assert_eq!(device.observations.len(), 3);
            assert!(
                device
                    .evidence
                    .iter()
                    .any(|item| item.value == format!("{sequence}-80"))
            );
            assert!(
                device
                    .evidence
                    .iter()
                    .any(|item| item.value == format!("{sequence}-443"))
            );
        }
        device.merge_observation_snapshot(&mut delayed.unwrap());
        assert_eq!(device.evidence.len(), 7);
        device.observe("http", "80".into(), |snapshot| {
            snapshot.add_evidence("http", "new_key", "new", 0.75)
        });
        assert_eq!(device.evidence.len(), 7);
        assert!(
            device
                .evidence
                .iter()
                .any(|item| item.key == "http_header_server" && item.value == "shared")
        ); // still current on 443
        assert!(!device.evidence.iter().any(|item| item.value == "1000-80"));
        assert!(device.evidence.iter().any(|item| item.value == "1000-443"));
        for sequence in 1..=1_000 {
            device.observe("mdns", String::new(), |snapshot| {
                for suffix in ["a", "b"] {
                    snapshot.add_name(format!("alias-{sequence}-{suffix}"), "mdns", 0.9);
                }
                for port in [80, 443] {
                    snapshot.add_service("web", "mdns", Some(port), 0.75);
                }
                snapshot.set_model_guess(format!("model-{sequence}"), "mdns", 0.85);
            });
            assert_eq!(device.names.len(), 2);
            assert_eq!(device.services.len(), 2);
            assert_eq!(
                device.model.as_ref().unwrap().value,
                format!("model-{sequence}")
            );
        }
        let json = serde_json::to_value(&device).unwrap();
        assert!(json.get("observation_round").is_none());
        assert!(json.get("observations").is_none());
        assert_eq!(json.as_object().unwrap().len(), 14);
        assert!(
            json["names"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item.as_object().unwrap().len() == 3)
        );
        assert!(
            json["services"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item.as_object().unwrap().len() == 4)
        );
        assert_eq!(json["model"].as_object().unwrap().len(), 3);
        assert!(
            json["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item.as_object().unwrap().len() == 4)
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
