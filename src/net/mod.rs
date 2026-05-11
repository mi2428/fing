//! Local interface and target-network selection.
//!
//! Scanner code works on normalized IPv4 CIDRs and concrete interface metadata.
//! This module isolates OS-specific route/interface probing so the rest of the
//! scan pipeline can stay platform-neutral.

use anyhow::{Context, Result, anyhow, bail};
use if_addrs::{IfAddr, get_if_addrs};
use ipnet::Ipv4Net;
use std::{net::Ipv4Addr, process::Command};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub prefix: u8,
    pub network: Ipv4Net,
    pub mac: Option<String>,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    // `if_addrs` gives portable IPv4 address/netmask data but not always MACs;
    // pnet fills in hardware addresses using the interface name as the join key.
    let pnet_macs = pnet::datalink::interfaces()
        .into_iter()
        .map(|iface| (iface.name, iface.mac.map(|mac| mac.to_string())))
        .collect::<std::collections::HashMap<_, _>>();

    let mut interfaces = Vec::new();
    for iface in get_if_addrs().context("failed to list interfaces")? {
        let IfAddr::V4(v4) = &iface.addr else {
            continue;
        };

        if iface.is_loopback() {
            continue;
        }

        let prefix = prefix_from_netmask(v4.netmask)
            .with_context(|| format!("invalid netmask {} on {}", v4.netmask, iface.name))?;
        let raw = Ipv4Net::new(v4.ip, prefix)?;
        let network = Ipv4Net::new(raw.network(), prefix)?;

        interfaces.push(InterfaceInfo {
            name: iface.name.clone(),
            ip: v4.ip,
            netmask: v4.netmask,
            prefix,
            network,
            mac: pnet_macs.get(&iface.name).cloned().flatten(),
        });
    }

    interfaces.sort_by(|left, right| left.name.cmp(&right.name).then(left.ip.cmp(&right.ip)));
    Ok(interfaces)
}

pub fn select_interface(requested: Option<&str>) -> Result<InterfaceInfo> {
    let interfaces = list_interfaces()?;
    if let Some(name) = requested {
        return interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| anyhow!("interface {name} was not found or has no IPv4 address"));
    }

    // Prefer the OS default route when available. It usually matches the LAN the
    // user expects to scan, and it avoids selecting VPN/tunnel interfaces first.
    if let Some(default_name) = default_interface_name()
        && let Some(iface) = interfaces.iter().find(|iface| iface.name == default_name)
    {
        return Ok(iface.clone());
    }

    interfaces
        .into_iter()
        .find(|iface| !looks_virtual_or_special(&iface.name))
        .ok_or_else(|| anyhow!("no usable IPv4 interface found"))
}

pub fn parse_target(target: Option<&str>, iface: &InterfaceInfo) -> Result<Ipv4Net> {
    match target {
        Some(value) => parse_cidr_target(value),
        None => Ok(iface.network),
    }
}

pub fn parse_cidr_target(value: &str) -> Result<Ipv4Net> {
    let net = value
        .parse::<Ipv4Net>()
        .with_context(|| format!("invalid IPv4 CIDR target: {value}"))?;
    // Normalize host-address CIDRs such as 192.168.1.42/24 to the network form
    // so cache keys, status text, and equality checks are stable.
    Ipv4Net::new(net.network(), net.prefix_len()).context("failed to normalize IPv4 CIDR target")
}

pub fn normalize_cidr_target(value: &str) -> Result<String> {
    Ok(parse_cidr_target(value)?.to_string())
}

pub fn default_interface_name() -> Option<String> {
    // macOS exposes the default route through `route -n get default`; Linux uses
    // `ip route show default`. Try both and keep the parser tests pure.
    default_interface_name_from_route_get()
        .or_else(default_interface_name_from_ip_route)
        .filter(|name| !name.is_empty())
}

pub fn prefix_from_netmask(mask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    // A valid IPv4 netmask is all ones followed by all zeros. Count the ones and
    // rebuild that ideal mask; any mismatch means the OS returned a discontiguous
    // mask that cannot be represented as a CIDR prefix.
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };

    if bits != expected {
        bail!("netmask is not contiguous: {mask}");
    }

    Ok(ones as u8)
}

fn looks_virtual_or_special(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "lo",
        "utun",
        "awdl",
        "llw",
        "bridge",
        "vmnet",
        "vbox",
        "docker",
        "tailscale",
        "zt",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn default_interface_name_from_route_get() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_get_default_interface(&String::from_utf8_lossy(&output.stdout))
}

fn default_interface_name_from_ip_route() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ip_route_default_interface(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_route_get_default_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:")
            .map(str::trim)
            .map(str::to_string)
    })
}

pub fn parse_ip_route_default_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                return parts.next().map(str::to_string);
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_default_interface() {
        let output = "route to: default\ninterface: en0\n";
        assert_eq!(
            parse_route_get_default_interface(output).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn parses_linux_default_interface() {
        let output = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.5 metric 600\n";
        assert_eq!(
            parse_ip_route_default_interface(output).as_deref(),
            Some("wlan0")
        );
    }

    #[test]
    fn computes_contiguous_prefix() {
        assert_eq!(
            prefix_from_netmask("255.255.255.0".parse().unwrap()).unwrap(),
            24
        );
        assert_eq!(
            prefix_from_netmask("255.255.0.0".parse().unwrap()).unwrap(),
            16
        );
    }

    #[test]
    fn rejects_non_contiguous_netmask() {
        assert!(prefix_from_netmask("255.0.255.0".parse().unwrap()).is_err());
    }
}
