//! Passive LLDP collection from the selected L2 interface.
//!
//! LLDP is a link-local advertisement protocol rather than a request/response
//! probe. A listener can identify adjacent switches, routers, and access points
//! when they publish a management address or when their chassis MAC matches an
//! already discovered neighbor.

use crate::net::InterfaceInfo;
use anyhow::{Context, Result, anyhow};
use pnet::{
    datalink::{self, Channel, Config},
    packet::{
        Packet,
        ethernet::{EtherTypes, EthernetPacket},
    },
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpInfo {
    pub source_mac: String,
    pub chassis_id: Option<String>,
    pub chassis_id_subtype: Option<String>,
    pub chassis_mac: Option<String>,
    pub port_id: Option<String>,
    pub port_id_subtype: Option<String>,
    pub ttl: Option<u16>,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub system_capabilities: Vec<String>,
    pub enabled_capabilities: Vec<String>,
    pub management_addresses: Vec<IpAddr>,
}

impl LldpInfo {
    fn new(source_mac: String) -> Self {
        Self {
            source_mac,
            chassis_id: None,
            chassis_id_subtype: None,
            chassis_mac: None,
            port_id: None,
            port_id_subtype: None,
            ttl: None,
            port_description: None,
            system_name: None,
            system_description: None,
            system_capabilities: Vec::new(),
            enabled_capabilities: Vec::new(),
            management_addresses: Vec::new(),
        }
    }

    fn identity_key(&self) -> String {
        let management = self
            .management_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}|{}|{}|{}",
            self.source_mac,
            self.chassis_id.as_deref().unwrap_or(""),
            self.port_id.as_deref().unwrap_or(""),
            management
        )
    }
}

pub fn listen_with_callback<F>(
    iface: &InterfaceInfo,
    timeout: Duration,
    mut on_info: F,
) -> Result<Vec<LldpInfo>>
where
    F: FnMut(&LldpInfo),
{
    let pnet_iface = datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == iface.name)
        .ok_or_else(|| anyhow!("interface {} is not available to pnet", iface.name))?;

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        read_buffer_size: 65536,
        ..Default::default()
    };

    let (_tx, mut rx) = match datalink::channel(&pnet_iface, config)
        .with_context(|| format!("failed to open datalink channel on {}", iface.name))?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel type")),
    };

    let mut infos = BTreeMap::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(packet) = rx.next()
            && let Some(info) = parse_lldp_frame(packet)
            && let std::collections::btree_map::Entry::Vacant(entry) =
                infos.entry(info.identity_key())
        {
            on_info(&info);
            entry.insert(info);
        }
    }

    Ok(infos.into_values().collect())
}

pub fn parse_lldp_frame(packet: &[u8]) -> Option<LldpInfo> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Lldp {
        return None;
    }
    parse_lldp_payload(ethernet.payload(), ethernet.get_source().to_string())
}

pub fn parse_lldp_payload(payload: &[u8], source_mac: String) -> Option<LldpInfo> {
    let mut info = LldpInfo::new(source_mac);
    let mut offset = 0;

    while offset + 2 <= payload.len() {
        let header = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        let tlv_type = header >> 9;
        let tlv_len = usize::from(header & 0x01ff);
        if offset + tlv_len > payload.len() {
            return None;
        }
        let value = &payload[offset..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            0 => break,
            1 => apply_chassis_id(&mut info, value),
            2 => apply_port_id(&mut info, value),
            3 => info.ttl = parse_u16(value),
            4 => info.port_description = clean_text(value),
            5 => info.system_name = clean_text(value),
            6 => info.system_description = clean_text(value),
            7 => apply_system_capabilities(&mut info, value),
            8 => {
                if let Some(address) = parse_management_address(value)
                    && !info.management_addresses.contains(&address)
                {
                    info.management_addresses.push(address);
                }
            }
            _ => {}
        }
    }

    if info.chassis_id.is_none()
        && info.port_id.is_none()
        && info.system_name.is_none()
        && info.management_addresses.is_empty()
    {
        return None;
    }

    Some(info)
}

fn apply_chassis_id(info: &mut LldpInfo, value: &[u8]) {
    if let Some((subtype, id, mac)) = parse_id_tlv(value, chassis_subtype_name, 4, 5) {
        info.chassis_id_subtype = Some(subtype);
        info.chassis_id = Some(id);
        info.chassis_mac = mac;
    }
}

fn apply_port_id(info: &mut LldpInfo, value: &[u8]) {
    if let Some((subtype, id, _)) = parse_id_tlv(value, port_subtype_name, 3, 4) {
        info.port_id_subtype = Some(subtype);
        info.port_id = Some(id);
    }
}

fn parse_id_tlv(
    value: &[u8],
    subtype_name: fn(u8) -> &'static str,
    mac_subtype: u8,
    network_subtype: u8,
) -> Option<(String, String, Option<String>)> {
    let (&subtype, body) = value.split_first()?;
    let subtype = subtype_name(subtype).to_string();
    let (id, mac) = match value[0] {
        kind if kind == mac_subtype && body.len() == 6 => {
            let mac = format_mac(body)?;
            (mac.clone(), Some(mac))
        }
        kind if kind == network_subtype => (
            parse_network_address(body).map_or_else(|| hex::encode(body), |ip| ip.to_string()),
            None,
        ),
        _ => (clean_text(body).unwrap_or_else(|| hex::encode(body)), None),
    };
    Some((subtype, id, mac))
}

fn parse_management_address(value: &[u8]) -> Option<IpAddr> {
    let address_string_len = usize::from(*value.first()?);
    if address_string_len < 2 || value.len() < 1 + address_string_len {
        return None;
    }
    parse_address_family(&value[1..1 + address_string_len])
}

fn parse_network_address(value: &[u8]) -> Option<IpAddr> {
    parse_address_family(value)
}

fn parse_address_family(value: &[u8]) -> Option<IpAddr> {
    let (&address_family, address) = value.split_first()?;
    match address_family {
        1 if address.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))),
        2 if address.len() == 16 => {
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(address);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn apply_system_capabilities(info: &mut LldpInfo, value: &[u8]) {
    if value.len() < 4 {
        return;
    }
    let system = u16::from_be_bytes([value[0], value[1]]);
    let enabled = u16::from_be_bytes([value[2], value[3]]);
    info.system_capabilities = capability_names(system);
    info.enabled_capabilities = capability_names(enabled);
}

fn capability_names(bits: u16) -> Vec<String> {
    [
        (0x0001, "other"),
        (0x0002, "repeater"),
        (0x0004, "bridge"),
        (0x0008, "wlan-access-point"),
        (0x0010, "router"),
        (0x0020, "telephone"),
        (0x0040, "docsis-cable-device"),
        (0x0080, "station-only"),
        (0x0100, "c-vlan"),
        (0x0200, "s-vlan"),
        (0x0400, "two-port-mac-relay"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name.to_string())
    .collect()
}

fn parse_u16(value: &[u8]) -> Option<u16> {
    (value.len() == 2).then(|| u16::from_be_bytes([value[0], value[1]]))
}

fn clean_text(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value)
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn format_mac(value: &[u8]) -> Option<String> {
    if value.len() != 6 {
        return None;
    }
    Some(
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn chassis_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        1 => "chassis-component",
        2 => "interface-alias",
        3 => "port-component",
        4 => "mac-address",
        5 => "network-address",
        6 => "interface-name",
        7 => "locally-assigned",
        _ => "unknown",
    }
}

fn port_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        1 => "interface-alias",
        2 => "port-component",
        3 => "mac-address",
        4 => "network-address",
        5 => "interface-name",
        6 => "agent-circuit-id",
        7 => "locally-assigned",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lldp_frame_with_management_address_and_capabilities() {
        let mut frame = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // destination
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // source
            0x88, 0xcc, // ethertype
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // chassis
            0x04, 0x08, 0x05, b'G', b'i', b'1', b'/', b'0', b'/', b'1', // port
            0x06, 0x02, 0x00, 0x78, // ttl
            0x0a, 0x07, b's', b'w', b'i', b't', b'c', b'h', b'1', // name
            0x0e, 0x04, 0x00, 0x14, 0x00, 0x04, // capabilities
            0x10, 0x0c, 0x05, 0x01, 192, 168, 1, 2, 0x02, 0x00, 0x00, 0x00, 0x05,
            0x00, // management address
            0x00, 0x00, // end
        ];
        frame.extend_from_slice(&[0, 0, 0, 0]);

        let info = parse_lldp_frame(&frame).unwrap();

        assert_eq!(info.source_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(info.chassis_mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(info.port_id.as_deref(), Some("Gi1/0/1"));
        assert_eq!(info.ttl, Some(120));
        assert_eq!(info.system_name.as_deref(), Some("switch1"));
        assert_eq!(info.enabled_capabilities, vec!["bridge"]);
        assert_eq!(
            info.management_addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))]
        );
    }

    #[test]
    fn ignores_non_lldp_ethernet_frames() {
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06,
        ];

        assert!(parse_lldp_frame(&frame).is_none());
    }
}
