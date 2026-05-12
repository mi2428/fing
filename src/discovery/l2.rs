//! Shared passive L2 listener for link-local discovery protocols.
//!
//! LLDP and CDP are both received from the selected datalink interface. Keeping
//! one raw listener per interface avoids duplicating sockets and centralizes the
//! frame demux logic.

use super::{cdp, lldp};
use crate::net::InterfaceInfo;
use anyhow::{Context, Result, anyhow};
use pnet::datalink::{self, Channel, Config};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

const READ_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Protocols {
    pub lldp: bool,
    pub cdp: bool,
}

impl L2Protocols {
    pub fn any(self) -> bool {
        self.lldp || self.cdp
    }

    pub fn label(self) -> &'static str {
        match (self.lldp, self.cdp) {
            (true, true) => "LLDP/CDP",
            (true, false) => "LLDP",
            (false, true) => "CDP",
            (false, false) => "L2",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Advertisement {
    Lldp(lldp::LldpInfo),
    Cdp(cdp::CdpInfo),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L2Advertisements {
    pub lldp: Vec<lldp::LldpInfo>,
    pub cdp: Vec<cdp::CdpInfo>,
}

pub fn listen_with_callback<F>(
    iface: &InterfaceInfo,
    protocols: L2Protocols,
    timeout: Duration,
    on_advertisement: F,
) -> Result<L2Advertisements>
where
    F: FnMut(&L2Advertisement),
{
    let deadline = Instant::now() + timeout;
    listen_until(
        iface,
        protocols,
        || Instant::now() >= deadline,
        on_advertisement,
    )
}

pub fn listen_until<F, ShouldStop>(
    iface: &InterfaceInfo,
    protocols: L2Protocols,
    mut should_stop: ShouldStop,
    mut on_advertisement: F,
) -> Result<L2Advertisements>
where
    F: FnMut(&L2Advertisement),
    ShouldStop: FnMut() -> bool,
{
    if !protocols.any() {
        return Ok(L2Advertisements::default());
    }

    let pnet_iface = datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == iface.name)
        .ok_or_else(|| anyhow!("interface {} is not available to pnet", iface.name))?;

    let config = Config {
        read_timeout: Some(READ_TIMEOUT),
        read_buffer_size: 65536,
        ..Default::default()
    };

    let (_tx, mut rx) = match datalink::channel(&pnet_iface, config)
        .with_context(|| format!("failed to open datalink channel on {}", iface.name))?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel type")),
    };

    let mut result = L2Advertisements::default();
    let mut lldp_keys = BTreeSet::new();
    let mut cdp_keys = BTreeSet::new();
    while !should_stop() {
        let Ok(packet) = rx.next() else {
            continue;
        };

        if protocols.lldp
            && let Some(info) = lldp::parse_lldp_frame(packet)
            && lldp_keys.insert(info.identity_key())
        {
            let advertisement = L2Advertisement::Lldp(info.clone());
            on_advertisement(&advertisement);
            result.lldp.push(info);
            continue;
        }

        if protocols.cdp
            && let Some(info) = cdp::parse_cdp_frame(packet)
            && cdp_keys.insert(info.identity_key())
        {
            let advertisement = L2Advertisement::Cdp(info.clone());
            on_advertisement(&advertisement);
            result.cdp.push(info);
        }
    }

    Ok(result)
}
