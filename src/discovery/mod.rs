//! Host discovery from ARP traffic and local neighbor tables.
//!
//! Active ARP sweep gives fresh L2 reachability for the selected interface.
//! Reading the OS ARP/neighbor table is a best-effort fallback that can discover
//! recently contacted hosts even when raw socket access is unavailable.

use crate::net::InterfaceInfo;
use anyhow::{Context, Result, anyhow};
use ipnet::Ipv4Net;
use pnet::{
    datalink::{self, Channel, Config},
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    },
    util::MacAddr,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    process::Command,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArpHit {
    pub ip: Ipv4Addr,
    pub mac: String,
}

pub fn arp_sweep_with_callback<F>(
    iface: &InterfaceInfo,
    target: Ipv4Net,
    timeout: Duration,
    mut on_hit: F,
) -> Result<Vec<ArpHit>>
where
    F: FnMut(&ArpHit),
{
    // Open the datalink channel on the exact interface selected by the scanner.
    // ARP is link-local, so using a default interface here would silently scan
    // the wrong VLAN or physical adapter.
    let pnet_iface = datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == iface.name)
        .ok_or_else(|| anyhow!("interface {} is not available to pnet", iface.name))?;

    let source_mac = pnet_iface
        .mac
        .ok_or_else(|| anyhow!("interface {} has no hardware address", iface.name))?;

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&pnet_iface, config)
        .with_context(|| format!("failed to open datalink channel on {}", iface.name))?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel type")),
    };

    for target_ip in target.hosts() {
        if target_ip == iface.ip {
            continue;
        }
        // Broadcast one ARP request per host. Responses are collected below and
        // deduped by sender IP because devices can retransmit replies.
        let packet = build_arp_request(source_mac, iface.ip, target_ip)?;
        match tx.send_to(&packet, None) {
            Some(Ok(())) => {}
            Some(Err(err)) => return Err(err).context("failed to send ARP request"),
            None => return Err(anyhow!("datalink sender refused ARP packet")),
        }
    }

    let mut hits = BTreeMap::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(packet) = rx.next()
            && let Some(hit) = parse_arp_reply(packet)
            && target.contains(&hit.ip)
            && let std::collections::btree_map::Entry::Vacant(entry) = hits.entry(hit.ip)
        {
            on_hit(&hit);
            entry.insert(hit);
        }
    }

    Ok(hits.into_values().collect())
}

pub fn arp_table(target: Ipv4Net) -> Vec<ArpHit> {
    let mut hits = BTreeMap::new();
    for command in arp_table_commands() {
        // Try platform-native commands in order. Failure of one command is not a
        // warning: minimal containers and non-root sessions often have only one.
        let output = Command::new(command.0).args(command.1).output();
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for hit in parse_arp_table(&text) {
            if target.contains(&hit.ip) {
                hits.insert(hit.ip, hit);
            }
        }
    }
    hits.into_values().collect()
}

fn arp_table_commands() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("arp", &["-an"]), ("ip", &["neigh", "show"])]
}

fn build_arp_request(
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<[u8; 42]> {
    let mut buffer = [0_u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer)
        .ok_or_else(|| anyhow!("failed to allocate ethernet packet"))?;
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut())
        .ok_or_else(|| anyhow!("failed to allocate ARP packet"))?;
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    Ok(buffer)
}

pub fn parse_arp_reply(packet: &[u8]) -> Option<ArpHit> {
    // Parse only ARP replies. Requests and non-ARP Ethernet frames are normal
    // background traffic on a raw datalink channel and should be ignored.
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    Some(ArpHit {
        ip: arp.get_sender_proto_addr(),
        mac: arp.get_sender_hw_addr().to_string(),
    })
}

pub fn parse_arp_table(output: &str) -> Vec<ArpHit> {
    output
        .lines()
        .filter_map(parse_arp_table_line)
        .collect::<Vec<_>>()
}

fn parse_arp_table_line(line: &str) -> Option<ArpHit> {
    // macOS/BSD prints `? (ip) at mac`; Linux neigh prints `ip dev ... lladdr
    // mac`. Keep the parser branchy but small rather than normalizing through a
    // brittle regular expression.
    let ip = parse_parenthesized_ip(line).or_else(|| parse_leading_ip(line))?;
    let mac = parse_mac_after_at(line).or_else(|| parse_linux_neigh_mac(line))?;
    if mac.eq_ignore_ascii_case("(incomplete)") || mac.eq_ignore_ascii_case("incomplete") {
        return None;
    }
    Some(ArpHit { ip, mac })
}

fn parse_parenthesized_ip(line: &str) -> Option<Ipv4Addr> {
    let start = line.find('(')? + 1;
    let end = line[start..].find(')')? + start;
    line[start..end].parse().ok()
}

fn parse_leading_ip(line: &str) -> Option<Ipv4Addr> {
    line.split_whitespace().next()?.parse().ok()
}

fn parse_mac_after_at(line: &str) -> Option<String> {
    let at = line.find(" at ")? + 4;
    let mac = line[at..].split_whitespace().next()?.trim();
    if is_mac_like(mac) {
        Some(mac.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_linux_neigh_mac(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "lladdr" {
            let mac = parts.next()?;
            if is_mac_like(mac) {
                return Some(mac.to_ascii_lowercase());
            }
        }
    }
    None
}

fn is_mac_like(value: &str) -> bool {
    let hex_count = value.chars().filter(|ch| ch.is_ascii_hexdigit()).count();
    hex_count == 12
        && value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch == ':' || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_arp_table() {
        let input = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n";
        let hits = parse_arp_table(input);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hits[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_linux_neigh_table() {
        let input = "192.168.1.20 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE\n";
        let hits = parse_arp_table(input);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, "192.168.1.20".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hits[0].mac, "11:22:33:44:55:66");
    }
}
