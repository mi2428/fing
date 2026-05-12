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

        if let Some(advertisement) = demux_frame(packet, protocols, &mut lldp_keys, &mut cdp_keys) {
            on_advertisement(&advertisement);
            match advertisement {
                L2Advertisement::Lldp(info) => result.lldp.push(info),
                L2Advertisement::Cdp(info) => result.cdp.push(info),
            }
        }
    }

    Ok(result)
}

fn demux_frame(
    packet: &[u8],
    protocols: L2Protocols,
    lldp_keys: &mut BTreeSet<String>,
    cdp_keys: &mut BTreeSet<String>,
) -> Option<L2Advertisement> {
    if protocols.lldp
        && let Some(info) = lldp::parse_lldp_frame(packet)
        && lldp_keys.insert(info.identity_key())
    {
        return Some(L2Advertisement::Lldp(info));
    }

    if protocols.cdp
        && let Some(info) = cdp::parse_cdp_frame(packet)
        && cdp_keys.insert(info.identity_key())
    {
        return Some(L2Advertisement::Cdp(info));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, net::Ipv4Addr};

    #[test]
    fn l2_demux_respects_enabled_protocols_and_dedupes() {
        let mut lldp_keys = BTreeSet::new();
        let mut cdp_keys = BTreeSet::new();
        let protocols = L2Protocols {
            lldp: true,
            cdp: false,
        };

        assert!(matches!(
            demux_frame(&lldp_frame(), protocols, &mut lldp_keys, &mut cdp_keys),
            Some(L2Advertisement::Lldp(_))
        ));
        assert!(demux_frame(&lldp_frame(), protocols, &mut lldp_keys, &mut cdp_keys).is_none());
        assert!(demux_frame(&cdp_frame(), protocols, &mut lldp_keys, &mut cdp_keys).is_none());
    }

    #[test]
    fn l2_demux_parses_cdp_when_enabled() {
        let mut lldp_keys = BTreeSet::new();
        let mut cdp_keys = BTreeSet::new();
        let protocols = L2Protocols {
            lldp: true,
            cdp: true,
        };

        let advertisement = demux_frame(&cdp_frame(), protocols, &mut lldp_keys, &mut cdp_keys);

        assert!(matches!(advertisement, Some(L2Advertisement::Cdp(_))));
    }

    fn lldp_frame() -> Vec<u8> {
        vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // destination
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source
            0x88, 0xcc, // ethertype
            0x02, 0x07, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // chassis
            0x04, 0x08, 0x05, b'G', b'i', b'1', b'/', b'0', b'/', b'1', // port
            0x06, 0x02, 0x00, 0x78, // ttl
            0x0a, 0x07, b's', b'w', b'i', b't', b'c', b'h', b'1', // name
            0x00, 0x00, // end
        ]
    }

    fn cdp_frame() -> Vec<u8> {
        const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
        const LLC_SNAP_HEADER: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];

        let payload = [
            vec![2, 180, 0, 0],
            cdp_tlv(0x0001, b"switch1"),
            cdp_tlv(0x0002, &cdp_address_tlv(Ipv4Addr::new(192, 168, 1, 2))),
            cdp_tlv(0x0003, b"GigabitEthernet1/0/1"),
        ]
        .concat();
        let mut frame = Vec::new();
        frame.extend_from_slice(&CDP_MULTICAST);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&((LLC_SNAP_HEADER.len() + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&LLC_SNAP_HEADER);
        frame.extend_from_slice(&payload);
        frame
    }

    fn cdp_tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&tlv_type.to_be_bytes());
        tlv.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        tlv.extend_from_slice(value);
        tlv
    }

    fn cdp_address_tlv(ip: Ipv4Addr) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&1_u32.to_be_bytes());
        value.extend_from_slice(&[1, 1, 0xcc]);
        value.extend_from_slice(&4_u16.to_be_bytes());
        value.extend_from_slice(&ip.octets());
        value
    }
}
