//! Passive Cisco Discovery Protocol collection from the selected L2 interface.
//!
//! CDP uses 802.3 LLC/SNAP frames rather than an Ethernet II EtherType. The
//! collector listens for Cisco's SNAP PID and extracts the common identity TLVs
//! exposed by switches, routers, access points, and phones.

use std::net::{IpAddr, Ipv4Addr};

const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
const LLC_SNAP_HEADER: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
const ETHERNET_HEADER_LEN: usize = 14;
const LLC_SNAP_LEN: usize = 8;
const CDP_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpInfo {
    pub source_mac: String,
    pub version: u8,
    pub ttl: u8,
    pub device_id: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub port_id: Option<String>,
    pub capabilities: Vec<String>,
    pub software_version: Option<String>,
    pub platform: Option<String>,
    pub native_vlan: Option<u16>,
    pub duplex: Option<String>,
    pub management_addresses: Vec<IpAddr>,
}

impl CdpInfo {
    fn new(source_mac: String, version: u8, ttl: u8) -> Self {
        Self {
            source_mac,
            version,
            ttl,
            device_id: None,
            addresses: Vec::new(),
            port_id: None,
            capabilities: Vec::new(),
            software_version: None,
            platform: None,
            native_vlan: None,
            duplex: None,
            management_addresses: Vec::new(),
        }
    }

    pub(crate) fn identity_key(&self) -> String {
        let addresses = self
            .addresses
            .iter()
            .chain(&self.management_addresses)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}|{}|{}|{}",
            self.source_mac,
            self.device_id.as_deref().unwrap_or(""),
            self.port_id.as_deref().unwrap_or(""),
            addresses
        )
    }
}

pub fn parse_cdp_frame(packet: &[u8]) -> Option<CdpInfo> {
    if packet.len() < ETHERNET_HEADER_LEN + LLC_SNAP_LEN + CDP_HEADER_LEN {
        return None;
    }
    if packet[..6] != CDP_MULTICAST {
        return None;
    }
    let frame_len = u16::from_be_bytes([packet[12], packet[13]]);
    if frame_len > 1500 {
        return None;
    }
    let frame_len = usize::from(frame_len);
    if frame_len < LLC_SNAP_LEN + CDP_HEADER_LEN {
        return None;
    }
    let frame_end = ETHERNET_HEADER_LEN + frame_len;
    if frame_end > packet.len() {
        return None;
    }
    if packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + LLC_SNAP_LEN] != LLC_SNAP_HEADER {
        return None;
    }

    let source_mac = format_mac(&packet[6..12])?;
    parse_cdp_payload(
        &packet[ETHERNET_HEADER_LEN + LLC_SNAP_LEN..frame_end],
        source_mac,
    )
}

pub fn parse_cdp_payload(payload: &[u8], source_mac: String) -> Option<CdpInfo> {
    if payload.len() < CDP_HEADER_LEN {
        return None;
    }
    let mut info = CdpInfo::new(source_mac, payload[0], payload[1]);
    let mut offset = CDP_HEADER_LEN;

    while offset + 4 <= payload.len() {
        let tlv_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_len = usize::from(u16::from_be_bytes([
            payload[offset + 2],
            payload[offset + 3],
        ]));
        if tlv_len < 4 || offset + tlv_len > payload.len() {
            return None;
        }
        let value = &payload[offset + 4..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            0x0001 => info.device_id = clean_text(value),
            0x0002 => merge_addresses(&mut info.addresses, parse_address_records(value)),
            0x0003 => info.port_id = clean_text(value),
            0x0004 => info.capabilities = parse_capabilities(value),
            0x0005 => info.software_version = clean_text(value),
            0x0006 => info.platform = clean_text(value),
            0x000a => info.native_vlan = parse_u16(value),
            0x000b => info.duplex = parse_duplex(value),
            0x0016 => {
                merge_addresses(&mut info.management_addresses, parse_address_records(value));
            }
            _ => {}
        }
    }

    if info.device_id.is_none()
        && info.port_id.is_none()
        && info.addresses.is_empty()
        && info.management_addresses.is_empty()
    {
        return None;
    }

    Some(info)
}

fn parse_address_records(value: &[u8]) -> Vec<IpAddr> {
    if value.len() < 4 {
        return Vec::new();
    }

    let count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as usize;
    let mut offset = 4;
    let mut addresses = Vec::new();
    for _ in 0..count {
        if offset + 2 > value.len() {
            break;
        }
        let protocol_type = value[offset];
        let protocol_len = usize::from(value[offset + 1]);
        offset += 2;
        if offset + protocol_len + 2 > value.len() {
            break;
        }
        let protocol = &value[offset..offset + protocol_len];
        offset += protocol_len;

        let address_len = usize::from(u16::from_be_bytes([value[offset], value[offset + 1]]));
        offset += 2;
        if offset + address_len > value.len() {
            break;
        }
        let address = &value[offset..offset + address_len];
        offset += address_len;

        if protocol_type == 1
            && protocol == [0xcc]
            && address_len == 4
            && let Some(address) = parse_ipv4(address)
        {
            addresses.push(IpAddr::V4(address));
        }
    }
    addresses
}

fn merge_addresses(addresses: &mut Vec<IpAddr>, incoming: Vec<IpAddr>) {
    for address in incoming {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
}

fn parse_capabilities(value: &[u8]) -> Vec<String> {
    if value.len() < 4 {
        return Vec::new();
    }
    let bits = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    [
        (0x0000_0001, "router"),
        (0x0000_0002, "transparent-bridge"),
        (0x0000_0004, "source-route-bridge"),
        (0x0000_0008, "switch"),
        (0x0000_0010, "host"),
        (0x0000_0020, "igmp-capable"),
        (0x0000_0040, "repeater"),
        (0x0000_0080, "phone"),
        (0x0000_0100, "remote-management"),
        (0x0000_0200, "cvta"),
        (0x0000_0400, "two-port-mac-relay"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, capability)| capability.to_string())
    .collect()
}

fn parse_duplex(value: &[u8]) -> Option<String> {
    match value.first()? {
        0 => Some("half".to_string()),
        1 => Some("full".to_string()),
        _ => None,
    }
}

fn parse_u16(value: &[u8]) -> Option<u16> {
    (value.len() == 2).then(|| u16::from_be_bytes([value[0], value[1]]))
}

fn parse_ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    (value.len() == 4).then(|| Ipv4Addr::new(value[0], value[1], value[2], value[3]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cdp_frame_with_identity_and_addresses() {
        let payload = [
            cdp_header(),
            tlv(0x0001, b"switch1"),
            tlv(0x0002, &address_tlv(Ipv4Addr::new(192, 168, 1, 2))),
            tlv(0x0003, b"GigabitEthernet1/0/1"),
            tlv(0x0004, &0x0000_0009_u32.to_be_bytes()),
            tlv(0x0005, b"Cisco IOS Software"),
            tlv(0x0006, b"cisco WS-C2960X"),
            tlv(0x000a, &100_u16.to_be_bytes()),
            tlv(0x000b, &[1]),
            tlv(0x0016, &address_tlv(Ipv4Addr::new(192, 168, 1, 3))),
        ]
        .concat();
        let frame = cdp_frame(&payload);

        let info = parse_cdp_frame(&frame).unwrap();

        assert_eq!(info.source_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(info.version, 2);
        assert_eq!(info.ttl, 180);
        assert_eq!(info.device_id.as_deref(), Some("switch1"));
        assert_eq!(info.port_id.as_deref(), Some("GigabitEthernet1/0/1"));
        assert_eq!(
            info.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))]
        );
        assert_eq!(
            info.management_addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))]
        );
        assert_eq!(info.capabilities, vec!["router", "switch"]);
        assert_eq!(info.native_vlan, Some(100));
        assert_eq!(info.duplex.as_deref(), Some("full"));
    }

    #[test]
    fn ignores_non_cdp_frames() {
        let frame = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        assert!(parse_cdp_frame(&frame).is_none());
    }

    #[test]
    fn parses_cdp_frame_with_ethernet_padding() {
        let payload = [
            cdp_header(),
            tlv(0x0001, b"switch1"),
            tlv(0x0003, b"GigabitEthernet1/0/1"),
        ]
        .concat();
        let mut frame = cdp_frame(&payload);
        frame.extend_from_slice(&[0_u8; 32]);

        let info = parse_cdp_frame(&frame).unwrap();

        assert_eq!(info.device_id.as_deref(), Some("switch1"));
        assert_eq!(info.port_id.as_deref(), Some("GigabitEthernet1/0/1"));
    }

    fn cdp_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&CDP_MULTICAST);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&((LLC_SNAP_LEN + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&LLC_SNAP_HEADER);
        frame.extend_from_slice(payload);
        frame
    }

    fn cdp_header() -> Vec<u8> {
        vec![2, 180, 0, 0]
    }

    fn tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&tlv_type.to_be_bytes());
        tlv.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        tlv.extend_from_slice(value);
        tlv
    }

    fn address_tlv(ip: Ipv4Addr) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&1_u32.to_be_bytes());
        value.extend_from_slice(&[1, 1, 0xcc]);
        value.extend_from_slice(&4_u16.to_be_bytes());
        value.extend_from_slice(&ip.octets());
        value
    }
}
