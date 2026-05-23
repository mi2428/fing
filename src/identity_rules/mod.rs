//! Built-in identity rule engine.
//!
//! Rules consume normalized observations from every collector and write
//! confidence-scored guesses back to the device. The rule engine never deletes
//! raw evidence, so classification remains explainable in exports and future
//! site-specific rules can be added without changing probe code.

use crate::model::{Device, Guess};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    pub source: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuleDb {
    pub rules: Vec<IdentityRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityRule {
    pub id: String,
    #[serde(default)]
    pub priority: i32,
    pub confidence: f32,
    #[serde(default)]
    pub matches: Vec<RuleMatch>,
    #[serde(default)]
    pub set: RuleOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleMatch {
    #[serde(default)]
    pub source: Option<String>,
    pub key: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub confidence_min: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuleOutput {
    #[serde(default)]
    pub make: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
}

pub fn load_rule_db() -> Result<RuleDb> {
    let mut db = builtin_rule_db()?;
    db.rules.sort_by_key(|rule| Reverse(rule.priority));
    Ok(db)
}

pub fn builtin_rule_db() -> Result<RuleDb> {
    serde_json::from_str(BUILTIN_RULES).context("failed to parse built-in identity rules")
}

pub fn observations_for_device(device: &Device) -> Vec<Observation> {
    let mut observations = Vec::new();

    // Normalize every collector into the same source/key/value/confidence shape.
    // This keeps the identity-rule engine simple across protocols:
    // "model contains BRAVIA" can match UPnP or mDNS without needing
    // protocol-specific Rust code.
    if let Some(vendor) = &device.vendor {
        push(&mut observations, "oui", "vendor", vendor, 0.55);
    }

    for name in &device.names {
        push(
            &mut observations,
            &name.source,
            "name",
            &name.name,
            name.confidence,
        );
    }

    push_guess(&mut observations, "make", &device.make);
    push_guess(&mut observations, "model", &device.model);
    push_guess(&mut observations, "os", &device.os);
    push_guess(&mut observations, "device_type", &device.device_type);

    for service in &device.services {
        push(
            &mut observations,
            &service.source,
            "service",
            &service.name,
            service.confidence,
        );
        if let Some(port) = service.port {
            push(
                &mut observations,
                &service.source,
                "port",
                port.to_string(),
                service.confidence,
            );
        }
    }

    for evidence in &device.evidence {
        push(
            &mut observations,
            &evidence.source,
            &evidence.key,
            &evidence.value,
            evidence.confidence,
        );
    }

    observations
}

pub fn apply_identity_rules(device: &mut Device, db: &RuleDb) {
    let observations = observations_for_device(device);
    for rule in &db.rules {
        if rule.matches.is_empty()
            || !rule
                .matches
                .iter()
                .all(|matcher| matcher.matches(&observations))
        {
            continue;
        }
        let source = "identity_rule";
        // Rules never erase raw observations. They only write best guesses with
        // a confidence score, so users can inspect why a row became "tv" or
        // "Windows" and override the rule set for their own LAN.
        if let Some(make) = &rule.set.make {
            device.set_make_guess(make, source, rule.confidence);
        }
        if let Some(model) = &rule.set.model {
            device.set_model_guess(model, source, rule.confidence);
        }
        if let Some(os) = &rule.set.os {
            device.set_os_guess(os, source, rule.confidence);
        }
        if let Some(device_type) = &rule.set.device_type {
            device.set_device_type_guess(device_type, source, rule.confidence);
        }
        device.add_evidence(source, "rule", &rule.id, rule.confidence);
    }
}

impl RuleMatch {
    fn matches(&self, observations: &[Observation]) -> bool {
        // A rule match is satisfied by any one observation with the right key,
        // optional source, confidence floor, and value predicate. Multiple
        // `matches` on the rule are ANDed by `apply_identity_rules`.
        observations.iter().any(|observation| {
            if observation.key != self.key {
                return false;
            }
            if let Some(source) = &self.source
                && observation.source != *source
            {
                return false;
            }
            if let Some(min) = self.confidence_min
                && observation.confidence < min
            {
                return false;
            }

            let value = observation.value.to_ascii_lowercase();
            if let Some(expected) = &self.equals {
                return value == expected.to_ascii_lowercase();
            }
            if let Some(needle) = &self.contains
                && !value.contains(&needle.to_ascii_lowercase())
            {
                return false;
            }
            if !self.any_of.is_empty()
                && !self
                    .any_of
                    .iter()
                    .any(|needle| value.contains(&needle.to_ascii_lowercase()))
            {
                return false;
            }
            true
        })
    }
}

fn push(
    observations: &mut Vec<Observation>,
    source: &str,
    key: &str,
    value: impl Into<String>,
    confidence: f32,
) {
    let value = value.into();
    if value.trim().is_empty() {
        return;
    }
    observations.push(Observation {
        source: source.to_string(),
        key: key.to_string(),
        value,
        confidence,
    });
}

fn push_guess(observations: &mut Vec<Observation>, key: &str, guess: &Option<Guess>) {
    if let Some(guess) = guess
        && guess.source != "identity_rule"
    {
        // Do not feed rule outputs back into the rule engine. That prevents a
        // derived guess from recursively satisfying another rule as if it were a
        // direct protocol observation.
        push(
            observations,
            &guess.source,
            key,
            &guess.value,
            guess.confidence,
        );
    }
}

const BUILTIN_RULES: &str = r#"
{
  "rules": [
    {
      "id": "apple-mac-model",
      "priority": 100,
      "confidence": 0.92,
      "matches": [{"key": "model", "any_of": ["MacBook", "Mac mini", "MacBookPro", "iMac", "Mac Studio"]}],
      "set": {"make": "Apple", "os": "macOS", "device_type": "computer"}
    },
    {
      "id": "apple-tv",
      "priority": 100,
      "confidence": 0.92,
      "matches": [{"key": "model", "any_of": ["AppleTV", "Apple TV"]}],
      "set": {"make": "Apple", "os": "tvOS", "device_type": "media-streamer"}
    },
    {
      "id": "airplay-device",
      "priority": 90,
      "confidence": 0.78,
      "matches": [{"key": "service", "any_of": ["airplay", "raop", "airdrop"]}],
      "set": {"make": "Apple", "device_type": "media-device"}
    },
    {
      "id": "bravia-tv",
      "priority": 95,
      "confidence": 0.9,
      "matches": [{"key": "model", "contains": "BRAVIA"}],
      "set": {"make": "Sony", "os": "Android TV", "device_type": "tv"}
    },
    {
      "id": "dial-tv-or-cast",
      "priority": 80,
      "confidence": 0.78,
      "matches": [{"key": "service", "contains": "dial"}],
      "set": {"device_type": "media-streamer"}
    },
    {
      "id": "google-cast",
      "priority": 90,
      "confidence": 0.86,
      "matches": [{"key": "service", "any_of": ["googlecast", "chromecast", "cast"]}],
      "set": {"make": "Google", "device_type": "media-streamer"}
    },
    {
      "id": "nintendo-console",
      "priority": 80,
      "confidence": 0.75,
      "matches": [{"key": "vendor", "contains": "Nintendo"}],
      "set": {"make": "Nintendo", "device_type": "game-console"}
    },
    {
      "id": "amazon-device",
      "priority": 70,
      "confidence": 0.68,
      "matches": [{"key": "vendor", "contains": "Amazon"}],
      "set": {"make": "Amazon", "device_type": "smart-home"}
    },
    {
      "id": "printer-ipp-or-raw",
      "priority": 85,
      "confidence": 0.78,
      "matches": [{"key": "port", "any_of": ["631", "9100"]}],
      "set": {"device_type": "printer"}
    },
    {
      "id": "synology-nas",
      "priority": 95,
      "confidence": 0.9,
      "matches": [{"key": "vendor", "contains": "Synology"}],
      "set": {"make": "Synology", "device_type": "nas", "os": "DSM"}
    },
    {
      "id": "qnap-nas",
      "priority": 95,
      "confidence": 0.9,
      "matches": [{"key": "vendor", "contains": "QNAP"}],
      "set": {"make": "QNAP", "device_type": "nas", "os": "QTS"}
    },
    {
      "id": "openwrt-http",
      "priority": 95,
      "confidence": 0.88,
      "matches": [{"key": "http_header_server", "any_of": ["OpenWrt", "uhttpd"]}],
      "set": {"os": "OpenWrt", "device_type": "router"}
    },
    {
      "id": "dropbear-embedded",
      "priority": 70,
      "confidence": 0.66,
      "matches": [{"key": "ssh_banner", "contains": "dropbear"}],
      "set": {"os": "Linux/embedded"}
    },
    {
      "id": "dhcp-msft-windows",
      "priority": 80,
      "confidence": 0.72,
      "matches": [{"source": "dhcp", "key": "vendor_class", "contains": "MSFT"}],
      "set": {"os": "Windows", "device_type": "computer"}
    },
    {
      "id": "dhcp-android",
      "priority": 80,
      "confidence": 0.72,
      "matches": [{"source": "dhcp", "key": "vendor_class", "contains": "android"}],
      "set": {"os": "Android"}
    },
    {
      "id": "samba-server",
      "priority": 70,
      "confidence": 0.68,
      "matches": [{"key": "smb_native_lanman", "contains": "Samba"}],
      "set": {"os": "Unix-like", "device_type": "file-server"}
    },
    {
      "id": "windows-smb",
      "priority": 70,
      "confidence": 0.72,
      "matches": [{"key": "smb_native_os", "contains": "Windows"}],
      "set": {"os": "Windows", "device_type": "computer"}
    }
  ]
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn observations_include_names_services_and_evidence() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Nintendo Co.,Ltd".to_string());
        device.add_name("switch", "mdns", 0.9);
        device.add_service("http", "deep", Some(80), 0.7);
        device.add_evidence("arp", "mac", "aa:bb:cc:dd:ee:ff", 0.5);
        device.add_evidence("http", "http_header_server", "uhttpd", 0.8);

        let observations = observations_for_device(&device);

        assert!(
            observations
                .iter()
                .any(|item| item.source == "arp" && item.key == "mac")
        );
        assert!(observations.iter().any(|item| item.key == "vendor"));
        assert!(observations.iter().any(|item| item.key == "name"));
        assert!(observations.iter().any(|item| item.value == "80"));
        assert!(
            observations
                .iter()
                .any(|item| item.key == "http_header_server")
        );
    }

    #[test]
    fn mac_without_arp_evidence_is_not_an_arp_observation() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        let observations = observations_for_device(&device);

        assert!(
            observations
                .iter()
                .all(|item| item.source != "arp" && item.key != "mac_oui")
        );
    }

    #[test]
    fn builtin_rules_identify_vendor_backed_devices() {
        let now = Utc::now();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.vendor = Some("Nintendo Co.,Ltd".to_string());
        let db = builtin_rule_db().unwrap();

        apply_identity_rules(&mut device, &db);

        assert_eq!(
            device.make.as_ref().map(|guess| guess.value.as_str()),
            Some("Nintendo")
        );
        assert_eq!(
            device
                .device_type
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("game-console")
        );
    }

    #[test]
    fn builtin_rules_are_sorted_by_priority() {
        let db = load_rule_db().unwrap();

        assert!(
            db.rules
                .windows(2)
                .all(|window| window[0].priority >= window[1].priority)
        );
    }
}
