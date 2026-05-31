//! Host discovery from ARP traffic and local neighbor tables.
//!
//! Active ARP sweep gives fresh L2 reachability for the selected interface.
//! Reading the OS ARP/neighbor table is a best-effort fallback that can discover
//! recently contacted hosts even when raw socket access is unavailable.

pub mod cdp;
pub mod l2;
pub mod lldp;

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
    io,
    net::Ipv4Addr,
    process::Command,
    time::{Duration, Instant},
};

const ARP_READ_TIMEOUT: Duration = Duration::from_millis(1);
const ARP_INTER_BATCH_RECEIVE_WINDOW: Duration = Duration::from_millis(2);
const ARP_INTER_PASS_RECEIVE_WINDOW: Duration = Duration::from_millis(30);
const ARP_MIN_BATCH_SIZE: usize = 8;

fn retryable_datalink_read_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArpHit {
    pub ip: Ipv4Addr,
    pub mac: String,
    #[serde(default)]
    pub interface: Option<String>,
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
        read_timeout: Some(ARP_READ_TIMEOUT),
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

    let targets = arp_target_hosts(target, iface.ip);
    let pass_count = arp_retry_passes(targets.len(), timeout);
    let inter_batch_receive_window = timeout.min(ARP_INTER_BATCH_RECEIVE_WINDOW);
    let inter_pass_receive_window = timeout.min(ARP_INTER_PASS_RECEIVE_WINDOW);
    let mut hits = BTreeMap::new();
    let mut batch_size = arp_batch_size(targets.len());

    for pass in 0..pass_count {
        let unresolved = unresolved_targets(&targets, &hits);
        if unresolved.is_empty() {
            break;
        }

        for chunk in unresolved.chunks(batch_size) {
            // Wide ranges used to be sent as one large microburst, which could
            // make some devices skip replying at all. Smaller bursts with a
            // quick read phase in between are measurably more reliable.
            for target_ip in chunk {
                let packet = build_arp_request(source_mac, iface.ip, *target_ip)?;
                match tx.send_to(&packet, None) {
                    Some(Ok(())) => {}
                    Some(Err(err)) => return Err(err).context("failed to send ARP request"),
                    None => return Err(anyhow!("datalink sender refused ARP packet")),
                }
            }
            drain_arp_replies_for(
                &mut *rx,
                target,
                inter_batch_receive_window,
                &mut hits,
                &mut on_hit,
            )?;
        }

        let receive_window = if pass + 1 == pass_count {
            timeout
        } else {
            inter_pass_receive_window
        };
        drain_arp_replies_for(&mut *rx, target, receive_window, &mut hits, &mut on_hit)?;
        batch_size = (batch_size / 2).max(ARP_MIN_BATCH_SIZE);
    }

    Ok(hits.into_values().collect())
}

fn arp_target_hosts(target: Ipv4Net, source_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    target
        .hosts()
        .filter(|target_ip| *target_ip != source_ip)
        .collect()
}

fn unresolved_targets(targets: &[Ipv4Addr], hits: &BTreeMap<Ipv4Addr, ArpHit>) -> Vec<Ipv4Addr> {
    targets
        .iter()
        .copied()
        .filter(|target_ip| !hits.contains_key(target_ip))
        .collect()
}

fn arp_batch_size(host_count: usize) -> usize {
    match host_count {
        0..=256 => 16,
        257..=4096 => 32,
        4097..=16384 => 64,
        _ => 128,
    }
}

fn arp_retry_passes(host_count: usize, timeout: Duration) -> usize {
    if host_count <= arp_batch_size(host_count) || timeout < Duration::from_millis(800) {
        1
    } else if timeout >= Duration::from_millis(1800) {
        3
    } else {
        2
    }
}

fn drain_arp_replies_for<F>(
    rx: &mut dyn datalink::DataLinkReceiver,
    target: Ipv4Net,
    duration: Duration,
    hits: &mut BTreeMap<Ipv4Addr, ArpHit>,
    on_hit: &mut F,
) -> Result<()>
where
    F: FnMut(&ArpHit),
{
    if duration.is_zero() {
        return Ok(());
    }

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => record_arp_reply(packet, target, hits, on_hit),
            Err(err) if retryable_datalink_read_error(&err) => continue,
            Err(err) => return Err(err).context("failed to receive ARP replies"),
        }
    }

    Ok(())
}

fn record_arp_reply<F>(
    packet: &[u8],
    target: Ipv4Net,
    hits: &mut BTreeMap<Ipv4Addr, ArpHit>,
    on_hit: &mut F,
) where
    F: FnMut(&ArpHit),
{
    if let Some(hit) = parse_arp_reply(packet)
        && target.contains(&hit.ip)
        && let std::collections::btree_map::Entry::Vacant(entry) = hits.entry(hit.ip)
    {
        on_hit(&hit);
        entry.insert(hit);
    }
}

pub fn arp_table(target: Ipv4Net, interface: &str) -> Vec<ArpHit> {
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
            if arp_hit_matches_target_interface(&hit, target, interface) {
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
        interface: None,
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
    Some(ArpHit {
        ip,
        mac,
        interface: parse_arp_table_interface(line),
    })
}

fn arp_hit_matches_target_interface(hit: &ArpHit, target: Ipv4Net, interface: &str) -> bool {
    target.contains(&hit.ip) && hit.interface.as_deref() == Some(interface)
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

fn parse_arp_table_interface(line: &str) -> Option<String> {
    if let Some(interface) = value_after_token(line, "dev") {
        return Some(interface.to_string());
    }
    if let Some((_, rest)) = line.split_once(" on ") {
        return rest.split_whitespace().next().map(str::to_string);
    }
    None
}

fn value_after_token<'a>(line: &'a str, token: &str) -> Option<&'a str> {
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        if part == token {
            return parts.next();
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
        assert_eq!(hits[0].interface.as_deref(), Some("en0"));
    }

    #[test]
    fn parses_linux_neigh_table() {
        let input = "192.168.1.20 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE\n";
        let hits = parse_arp_table(input);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, "192.168.1.20".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hits[0].mac, "11:22:33:44:55:66");
        assert_eq!(hits[0].interface.as_deref(), Some("wlan0"));
    }

    #[test]
    fn arp_table_fallback_requires_matching_interface() {
        let target = "192.168.1.0/24".parse::<Ipv4Net>().unwrap();
        let hits = parse_arp_table(
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
             ? (192.168.1.2) at 11:22:33:44:55:66 on en1 ifscope [ethernet]\n",
        );
        let filtered = hits
            .into_iter()
            .filter(|hit| arp_hit_matches_target_interface(hit, target, "en0"))
            .collect::<Vec<_>>();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].ip, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn arp_reply_recording_dedupes_callback_by_sender_ip() {
        let target = "192.168.1.0/24".parse::<Ipv4Net>().unwrap();
        let packet = arp_reply_packet(
            "192.168.1.20".parse().unwrap(),
            MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
        );
        let mut hits = BTreeMap::new();
        let mut callbacks = 0;

        {
            let mut callback = |_: &ArpHit| callbacks += 1;
            record_arp_reply(&packet, target, &mut hits, &mut callback);
            record_arp_reply(&packet, target, &mut hits, &mut callback);
        }

        assert_eq!(callbacks, 1);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn arp_batch_size_scales_down_for_smaller_ranges() {
        assert_eq!(arp_batch_size(32), 16);
        assert_eq!(arp_batch_size(128), 16);
        assert_eq!(arp_batch_size(2048), 32);
        assert_eq!(arp_batch_size(8192), 64);
        assert_eq!(arp_batch_size(32768), 128);
    }

    #[test]
    fn arp_retry_passes_add_an_extra_retry_for_deeper_timeouts() {
        assert_eq!(arp_retry_passes(128, Duration::from_millis(2500)), 3);
        assert_eq!(arp_retry_passes(128, Duration::from_millis(1200)), 2);
        assert_eq!(arp_retry_passes(128, Duration::from_millis(650)), 1);
    }

    #[test]
    fn arp_retry_passes_only_retry_when_timeout_budget_allows_it() {
        assert_eq!(arp_retry_passes(16, Duration::from_millis(1200)), 1);
        assert_eq!(arp_retry_passes(128, Duration::from_millis(650)), 1);
        assert_eq!(arp_retry_passes(128, Duration::from_millis(1200)), 2);
    }

    #[test]
    fn unresolved_targets_skip_ips_already_recorded() {
        let targets = vec![
            "192.168.1.10".parse().unwrap(),
            "192.168.1.11".parse().unwrap(),
            "192.168.1.12".parse().unwrap(),
        ];
        let mut hits = BTreeMap::new();
        hits.insert(
            "192.168.1.11".parse().unwrap(),
            ArpHit {
                ip: "192.168.1.11".parse().unwrap(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                interface: None,
            },
        );

        assert_eq!(
            unresolved_targets(&targets, &hits),
            vec![
                "192.168.1.10".parse::<Ipv4Addr>().unwrap(),
                "192.168.1.12".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn retries_only_transient_datalink_read_errors() {
        assert!(retryable_datalink_read_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timeout"
        )));
        assert!(retryable_datalink_read_error(&io::Error::new(
            io::ErrorKind::WouldBlock,
            "would block"
        )));
        assert!(retryable_datalink_read_error(&io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted"
        )));
        assert!(!retryable_datalink_read_error(&io::Error::new(
            io::ErrorKind::BrokenPipe,
            "broken pipe"
        )));
    }

    fn arp_reply_packet(sender_ip: Ipv4Addr, sender_mac: MacAddr) -> [u8; 42] {
        let mut buffer = [0_u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(sender_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Reply);
        arp_packet.set_sender_hw_addr(sender_mac);
        arp_packet.set_sender_proto_addr(sender_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr("192.168.1.2".parse().unwrap());
        buffer
    }
}
