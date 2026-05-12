//! Async scan phase helpers.
//!
//! The scanner streams progressive updates while phase futures are still
//! running. Each helper starts one logical group of work, forwards per-host
//! callbacks to the caller, then returns the aggregate result for final merging.

use super::{ScanConfig, ScanEvent};
use crate::{
    discovery::lldp,
    enrich,
    model::Device,
    net::InterfaceInfo,
    probes::{deep, snmp, upnp},
};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    watch,
};

pub(super) type MdnsRun = Result<BTreeMap<IpAddr, enrich::MdnsInfo>>;
pub(super) type UpnpRun = Result<BTreeMap<IpAddr, upnp::UpnpInfo>>;
pub(super) type RdnsRun = HashMap<IpAddr, String>;
pub(super) type NetbiosRun = HashMap<IpAddr, Vec<String>>;
pub(super) type DeepRun = HashMap<IpAddr, Vec<deep::PortProbe>>;
pub(super) type SnmpRun = HashMap<IpAddr, snmp::SnmpInfo>;
pub(super) type LldpRun = Result<Vec<lldp::LldpInfo>>;

pub(super) struct LldpDiscovery {
    pub updates: UnboundedReceiver<lldp::LldpInfo>,
    pub listener: tokio::task::JoinHandle<LldpRun>,
}

pub(super) enum MulticastUpdate {
    Mdns(IpAddr, enrich::MdnsInfo),
    Upnp(IpAddr, upnp::UpnpInfo),
}

pub(super) enum NameUpdate {
    Rdns(IpAddr, String),
    Netbios(IpAddr, Vec<String>),
}

pub(super) enum ProbeUpdate {
    Deep(IpAddr, deep::PortProbe),
    Snmp(IpAddr, snmp::SnmpInfo),
}

const DEEP_LLDP_LISTEN_TIMEOUT: Duration = Duration::from_secs(30);

fn lldp_listen_timeout(config: &ScanConfig) -> Duration {
    if config.profile.includes_lldp_fingerprints() {
        config.timeout.max(DEEP_LLDP_LISTEN_TIMEOUT)
    } else {
        config.timeout
    }
}

pub(super) fn idle_phase(interval: Duration, round: u64) -> Option<String> {
    (!interval.is_zero()).then(|| format!("idle {}ms after round {round}", interval.as_millis()))
}

pub(super) async fn wait_until_resumed(
    pause_rx: &mut watch::Receiver<bool>,
    events: &UnboundedSender<ScanEvent>,
) {
    if !*pause_rx.borrow() {
        return;
    }
    // Pausing is cooperative: the live UI controls a watch channel, and scan
    // phases check it between network steps so raw socket tasks are not aborted
    // mid-packet.
    let _ = events.send(ScanEvent::Phase("paused".to_string()));
    while *pause_rx.borrow_and_update() {
        if pause_rx.changed().await.is_err() {
            return;
        }
    }
}

pub(super) async fn wait_interval_or_pause(
    interval: Duration,
    pause_rx: &mut watch::Receiver<bool>,
) {
    tokio::select! {
        _ = tokio::time::sleep(interval) => {}
        changed = pause_rx.changed() => {
            let _ = changed;
        }
    }
}

pub(super) async fn forward_child_events(
    mut child_rx: UnboundedReceiver<ScanEvent>,
    events: Option<UnboundedSender<ScanEvent>>,
) {
    let mut child_interface = String::from("?");

    // Multi-interface scans run a normal child scanner per interface. Rewrite
    // child phase/warning events with an interface prefix, but forward device
    // updates unchanged so the live table can merge them by interface/IP.
    while let Some(event) = child_rx.recv().await {
        match event {
            ScanEvent::Started {
                target, interface, ..
            } => {
                child_interface = interface.clone();
                emit(
                    &events,
                    ScanEvent::Phase(format!("{interface}: scanning {target}")),
                );
            }
            ScanEvent::Phase(phase) => {
                emit(
                    &events,
                    ScanEvent::Phase(format!("{child_interface}: {phase}")),
                );
            }
            ScanEvent::DeviceUpdated(device) => {
                emit(&events, ScanEvent::DeviceUpdated(device));
            }
            ScanEvent::Warning(warning) => {
                emit(
                    &events,
                    ScanEvent::Warning(format!("{child_interface}: {warning}")),
                );
            }
            ScanEvent::Finished { .. } => {}
        }
    }
}

pub(super) fn start_lldp_discovery(
    config: &ScanConfig,
    iface: InterfaceInfo,
    events: &Option<UnboundedSender<ScanEvent>>,
) -> Option<LldpDiscovery> {
    if !config.lldp {
        return None;
    }

    let timeout = lldp_listen_timeout(config);
    emit(
        events,
        ScanEvent::Phase(format!("LLDP discovery ({}ms)", timeout.as_millis())),
    );

    let (tx, updates) = tokio::sync::mpsc::unbounded_channel();
    let listener = tokio::task::spawn_blocking(move || {
        lldp::listen_with_callback(&iface, timeout, move |info| {
            let _ = tx.send(info.clone());
        })
    });

    Some(LldpDiscovery { updates, listener })
}

pub(super) async fn run_multicast_enrichment(
    config: &ScanConfig,
    interface_ip: Ipv4Addr,
    target: Ipv4Net,
    events: &Option<UnboundedSender<ScanEvent>>,
    mut on_update: impl FnMut(MulticastUpdate),
) -> (Option<MdnsRun>, Option<UpnpRun>) {
    if config.mdns {
        emit(
            events,
            ScanEvent::Phase("mDNS/Bonjour enrichment".to_string()),
        );
    }
    if config.upnp {
        emit(events, ScanEvent::Phase("UPnP/SSDP enrichment".to_string()));
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mdns_tx = tx.clone();
    let upnp_tx = tx.clone();
    drop(tx);

    // mDNS and UPnP are blocking UDP loops internally, so their callbacks feed a
    // local channel. The select loop below drains that channel while both tasks
    // are still running, giving the live UI progressive enrichment.
    let mdns = async {
        if config.mdns {
            Some(run_mdns(interface_ip, target, config.timeout, mdns_tx).await)
        } else {
            None
        }
    };
    let upnp = async {
        if config.upnp {
            Some(run_upnp(interface_ip, target, config.timeout, upnp_tx).await)
        } else {
            None
        }
    };

    let enrichment = async move { tokio::join!(mdns, upnp) };
    tokio::pin!(enrichment);
    loop {
        tokio::select! {
            result = &mut enrichment => {
                while let Ok(update) = rx.try_recv() {
                    on_update(update);
                }
                return result;
            }
            Some(update) = rx.recv() => on_update(update),
        }
    }
}

pub(super) async fn run_name_enrichment(
    config: &ScanConfig,
    ips: Vec<IpAddr>,
    events: &Option<UnboundedSender<ScanEvent>>,
    mut on_update: impl FnMut(NameUpdate),
) -> (Option<RdnsRun>, Option<NetbiosRun>) {
    if config.rdns {
        emit(
            events,
            ScanEvent::Phase("reverse DNS enrichment".to_string()),
        );
    }
    if config.netbios {
        emit(events, ScanEvent::Phase("NetBIOS enrichment".to_string()));
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let rdns_tx = tx.clone();
    let netbios_tx = tx.clone();
    drop(tx);

    // Reverse DNS and NetBIOS are independent name sources. Run them together
    // and stream whichever answers first instead of waiting for both maps.
    let rdns_ips = ips.clone();
    let netbios_ips = ips;
    let rdns = async {
        if config.rdns {
            Some(
                enrich::reverse_dns_with_callback(
                    rdns_ips,
                    config.timeout,
                    config.concurrency,
                    move |ip, name| {
                        let _ = rdns_tx.send(NameUpdate::Rdns(ip, name));
                    },
                )
                .await,
            )
        } else {
            None
        }
    };
    let netbios = async {
        if config.netbios {
            Some(
                enrich::netbios_probe_with_callback(
                    netbios_ips,
                    config.timeout,
                    config.concurrency,
                    move |ip, names| {
                        let _ = netbios_tx.send(NameUpdate::Netbios(ip, names));
                    },
                )
                .await,
            )
        } else {
            None
        }
    };

    let enrichment = async move { tokio::join!(rdns, netbios) };
    tokio::pin!(enrichment);
    loop {
        tokio::select! {
            result = &mut enrichment => {
                while let Ok(update) = rx.try_recv() {
                    on_update(update);
                }
                return result;
            }
            Some(update) = rx.recv() => on_update(update),
        }
    }
}

pub(super) async fn run_deep_and_snmp_enrichment(
    config: &ScanConfig,
    ips: Vec<IpAddr>,
    events: &Option<UnboundedSender<ScanEvent>>,
    mut on_update: impl FnMut(ProbeUpdate),
) -> (Option<DeepRun>, Option<SnmpRun>) {
    if config.profile.includes_deep_probes() {
        emit(
            events,
            ScanEvent::Phase("deep port/banner enrichment".to_string()),
        );
    }
    if config.snmp {
        emit(
            events,
            ScanEvent::Phase("SNMP system enrichment".to_string()),
        );
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let deep_tx = tx.clone();
    let snmp_tx = tx.clone();
    drop(tx);

    // Deep TCP probes and SNMP both add protocol facts, but they have different
    // timeout behavior. Keeping them in one phase lets the UI show one stream
    // of "probe" updates while each collector owns its concurrency limits.
    let deep_ips = ips.clone();
    let snmp_ips = ips;
    let deep = async {
        if config.profile.includes_deep_probes() {
            Some(
                deep::probe_hosts_with_callback(
                    deep_ips,
                    config.timeout,
                    config.concurrency,
                    move |ip, probe| {
                        let _ = deep_tx.send(ProbeUpdate::Deep(ip, probe));
                    },
                )
                .await,
            )
        } else {
            None
        }
    };
    let snmp = async {
        if config.snmp {
            Some(
                snmp::probe_system_with_callback(
                    snmp_ips,
                    config.snmp_community.clone(),
                    config.timeout,
                    config.concurrency,
                    move |ip, info| {
                        let _ = snmp_tx.send(ProbeUpdate::Snmp(ip, info));
                    },
                )
                .await,
            )
        } else {
            None
        }
    };

    let enrichment = async move { tokio::join!(deep, snmp) };
    tokio::pin!(enrichment);
    loop {
        tokio::select! {
            result = &mut enrichment => {
                while let Ok(update) = rx.try_recv() {
                    on_update(update);
                }
                return result;
            }
            Some(update) = rx.recv() => on_update(update),
        }
    }
}

async fn run_mdns(
    interface_ip: Ipv4Addr,
    target: Ipv4Net,
    timeout: Duration,
    updates: tokio::sync::mpsc::UnboundedSender<MulticastUpdate>,
) -> Result<BTreeMap<IpAddr, enrich::MdnsInfo>> {
    let callback_target = target;
    // The mDNS collector uses a std UDP socket with multicast socket options.
    // Run it on the blocking pool and filter both callback and final maps back
    // to the selected IPv4 target.
    let mdns = tokio::task::spawn_blocking(move || {
        enrich::mdns_probe_with_callback(interface_ip, timeout, move |ip, info| {
            if target_contains_ip(callback_target, ip) {
                let _ = updates.send(MulticastUpdate::Mdns(ip, info));
            }
        })
    })
    .await
    .context("mDNS worker failed")??;

    Ok(mdns
        .into_iter()
        .filter(|(ip, _)| match ip {
            IpAddr::V4(ipv4) => target.contains(ipv4),
            IpAddr::V6(_) => false,
        })
        .collect())
}

async fn run_upnp(
    interface_ip: Ipv4Addr,
    target: Ipv4Net,
    timeout: Duration,
    updates: tokio::sync::mpsc::UnboundedSender<MulticastUpdate>,
) -> Result<BTreeMap<IpAddr, upnp::UpnpInfo>> {
    let callback_target = target;
    // UPnP discovery can optionally fetch HTTP description XML, so it also runs
    // off the async executor. The callback still preserves progressive updates.
    let upnp = tokio::task::spawn_blocking(move || {
        upnp::ssdp_probe_with_callback(interface_ip, timeout, true, move |ip, info| {
            if target_contains_ip(callback_target, ip) {
                let _ = updates.send(MulticastUpdate::Upnp(ip, info));
            }
        })
    })
    .await
    .context("UPnP worker failed")??;

    Ok(upnp
        .into_iter()
        .filter(|(ip, _)| match ip {
            IpAddr::V4(ipv4) => target.contains(ipv4),
            IpAddr::V6(_) => false,
        })
        .collect())
}

pub(super) fn target_contains_ip(target: Ipv4Net, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => target.contains(&ipv4),
        IpAddr::V6(_) => false,
    }
}

pub(super) fn emit(events: &Option<UnboundedSender<ScanEvent>>, event: ScanEvent) {
    if let Some(events) = events {
        // Event receivers are best-effort UI/export observers. Dropping the
        // receiver should not fail the scan itself.
        let _ = events.send(event);
    }
}

pub(super) fn emit_device(events: &Option<UnboundedSender<ScanEvent>>, device: &Device) {
    emit(events, ScanEvent::DeviceUpdated(Box::new(device.clone())));
}

pub(super) fn scan_target_summary(configs: &[ScanConfig]) -> String {
    let mut targets = Vec::new();
    for config in configs {
        let target = config
            .target
            .as_deref()
            .unwrap_or("selected interface network");
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanProfile;
    use chrono::Utc;

    #[test]
    fn zero_interval_skips_idle_phase() {
        assert_eq!(idle_phase(Duration::ZERO, 3), None);
        assert_eq!(
            idle_phase(Duration::from_millis(250), 3),
            Some("idle 250ms after round 3".to_string())
        );
    }

    #[tokio::test]
    async fn child_events_are_forwarded_as_parent_phase_stream() {
        let (child_tx, child_rx) = tokio::sync::mpsc::unbounded_channel();
        let (parent_tx, mut parent_rx) = tokio::sync::mpsc::unbounded_channel();
        let now = Utc::now();
        let device = Device::new("192.168.1.44".parse().unwrap(), now);

        child_tx
            .send(ScanEvent::Started {
                target: "192.168.1.0/24".to_string(),
                interface: "en0".to_string(),
                profile: ScanProfile::Normal,
            })
            .unwrap();
        child_tx
            .send(ScanEvent::Phase("ARP discovery".to_string()))
            .unwrap();
        child_tx
            .send(ScanEvent::Warning("ARP fallback".to_string()))
            .unwrap();
        child_tx
            .send(ScanEvent::DeviceUpdated(Box::new(device.clone())))
            .unwrap();
        child_tx
            .send(ScanEvent::Finished {
                devices: vec![device],
                warnings: vec!["ignored".to_string()],
            })
            .unwrap();
        drop(child_tx);

        forward_child_events(child_rx, Some(parent_tx)).await;

        let mut events = Vec::new();
        while let Some(event) = parent_rx.recv().await {
            events.push(event);
        }

        assert_eq!(events.len(), 4);
        assert!(matches!(
            &events[0],
            ScanEvent::Phase(phase) if phase == "en0: scanning 192.168.1.0/24"
        ));
        assert!(matches!(
            &events[1],
            ScanEvent::Phase(phase) if phase == "en0: ARP discovery"
        ));
        assert!(matches!(
            &events[2],
            ScanEvent::Warning(warning) if warning == "en0: ARP fallback"
        ));
        assert!(
            matches!(&events[3], ScanEvent::DeviceUpdated(device) if device.ip.to_string() == "192.168.1.44")
        );
    }

    #[test]
    fn scan_target_summary_deduplicates_configured_ranges() {
        let mut config = ScanConfig {
            target: Some("192.168.1.0/24".to_string()),
            iface: Some("en0".to_string()),
            profile: ScanProfile::Normal,
            timeout: Duration::from_millis(1),
            concurrency: 1,
            oui: false,
            rdns: false,
            mdns: false,
            netbios: false,
            upnp: false,
            snmp: false,
            snmp_community: "public".to_string(),
            lldp: false,
            dhcp: false,
            dhcp_paths: Vec::new(),
            cache_enabled: false,
            cache_path: "cache.json".into(),
            oui_path: "oui.json".into(),
        };
        let same = config.clone();
        config.target = Some("10.0.0.0/24".to_string());

        assert_eq!(
            scan_target_summary(&[same, config]),
            "192.168.1.0/24,10.0.0.0/24"
        );
    }
}
