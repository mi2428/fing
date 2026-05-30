//! Scanner configuration and event types shared by CLI and output layers.
//!
//! `ScanConfig` is intentionally concrete: each value describes one interface
//! and one normalized target range. Higher-level orchestration can run multiple
//! configs, but each scanner pass always has one L2 context for evidence.

use crate::model::Device;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub enum ScanProfile {
    None,
    Fast,
    Normal,
    Deep,
}

impl ScanProfile {
    pub fn default_timeout(self) -> Duration {
        match self {
            Self::None => Duration::from_millis(1200),
            Self::Fast => Duration::from_millis(650),
            Self::Normal => Duration::from_millis(1200),
            Self::Deep => Duration::from_millis(2500),
        }
    }
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Fast => write!(f, "fast"),
            Self::Normal => write!(f, "normal"),
            Self::Deep => write!(f, "deep"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: Option<String>,
    // One config scans one L2 interface. Multi-interface scans are coordinated
    // above this type so raw ARP sockets, multicast sockets, and lease matching
    // remain tied to the interface that produced the evidence.
    pub iface: Option<String>,
    pub profile: ScanProfile,
    pub timeout: Duration,
    pub concurrency: usize,
    pub oui: bool,
    pub rdns: bool,
    pub mdns: bool,
    pub netbios: bool,
    pub upnp: bool,
    pub deep: bool,
    pub ssh: bool,
    pub http: bool,
    pub tls: bool,
    pub smb: bool,
    pub snmp: bool,
    pub snmp_community: String,
    pub lldp: bool,
    pub cdp: bool,
    pub dhcp: bool,
    pub dhcp_paths: Vec<PathBuf>,
    // Identity rules turn raw fingerprints into make/model/OS/type guesses.
    // They are always active; protocol collection itself is controlled by the
    // per-protocol flags above.
    pub cache_enabled: bool,
    pub cache_path: PathBuf,
    pub oui_path: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        target: String,
        interface: String,
        profile: ScanProfile,
    },
    RoundStarted {
        round: u64,
    },
    RoundFinished {
        round: u64,
    },
    Phase(String),
    DeviceUpdated(Box<Device>),
    Warning(String),
    Finished {
        devices: Vec<Device>,
        warnings: Vec<String>,
    },
}
