//! Scan orchestration.
//!
//! A scan is deliberately split into discovery first, enrichment second:
//! ARP/multicast tells us which hosts exist, then protocol probes add identity
//! evidence. The live TUI receives every intermediate `DeviceUpdated` event so
//! rows can appear immediately and gain names/OS/type over time.

mod apply;
mod phases;
mod types;

pub use types::{ScanConfig, ScanEvent, ScanProfile};

use crate::{
    dhcp, discovery, identity_rules,
    model::{Device, ScanResult},
    net,
    probes::smb,
    store,
};
use anyhow::{Context, Result};
use apply::{
    apply_deep_probes, apply_dhcp_lease, apply_lldp_info, apply_mdns_info, apply_oui,
    apply_smb_info, apply_snmp_info, apply_upnp_info, merge_devices_by_interface_ip,
};
use chrono::Utc;
use phases::{
    LldpDiscovery, LldpRun, MulticastUpdate, NameUpdate, ProbeUpdate, emit, emit_device,
    forward_child_events, idle_phase, run_deep_and_snmp_enrichment, run_multicast_enrichment,
    run_name_enrichment, scan_target_summary, start_lldp_discovery, target_contains_ip,
    wait_interval_or_pause, wait_until_resumed,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{
    Semaphore,
    mpsc::{UnboundedReceiver, UnboundedSender},
    watch,
};

pub async fn scan_many(configs: Vec<ScanConfig>) -> Result<ScanResult> {
    scan_many_inner(configs, None, true).await
}

pub async fn scan_continuously_with_events(
    configs: Vec<ScanConfig>,
    events: UnboundedSender<ScanEvent>,
    mut pause_rx: watch::Receiver<bool>,
    interval: Duration,
) -> Result<()> {
    if configs.is_empty() {
        anyhow::bail!("no scan targets configured");
    }

    let mut round = 1_u64;
    loop {
        wait_until_resumed(&mut pause_rx, &events).await;
        emit(
            &Some(events.clone()),
            ScanEvent::Phase(format!("scan round {round}")),
        );
        if let Err(err) = scan_many_inner(configs.clone(), Some(events.clone()), false).await {
            emit(
                &Some(events.clone()),
                ScanEvent::Warning(format!("scan round {round} failed: {err}")),
            );
        }
        if let Some(phase) = idle_phase(interval, round) {
            emit(&Some(events.clone()), ScanEvent::Phase(phase));
            wait_interval_or_pause(interval, &mut pause_rx).await;
        } else {
            // A zero interval means "scan continuously": start the next round
            // as soon as the previous discovery/enrichment pass completes.
            // Yielding keeps the async runtime responsive without introducing
            // a user-visible delay.
            tokio::task::yield_now().await;
        }
        round = round.saturating_add(1);
    }
}

async fn scan_many_inner(
    mut configs: Vec<ScanConfig>,
    events: Option<UnboundedSender<ScanEvent>>,
    emit_finished: bool,
) -> Result<ScanResult> {
    if configs.len() <= 1 {
        let Some(config) = configs.pop() else {
            anyhow::bail!("no scan targets configured");
        };
        return scan_inner(config, events, emit_finished).await;
    }

    let scanned_at = Utc::now();
    let profile = configs[0].profile;
    let cache_enabled = configs[0].cache_enabled;
    let cache_path = configs[0].cache_path.clone();
    let identity_rules = identity_rules::load_rule_db()?;
    let interface_summary = configs
        .iter()
        .map(|config| config.iface.as_deref().unwrap_or("default"))
        .collect::<Vec<_>>()
        .join(",");

    emit(
        &events,
        ScanEvent::Started {
            target: scan_target_summary(&configs),
            interface: interface_summary,
            profile,
        },
    );

    let mut targets = Vec::new();
    let mut interfaces = Vec::new();
    let mut warnings = Vec::new();
    let mut devices = Vec::new();

    let scan_concurrency = configs[0].concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(scan_concurrency));
    let mut handles = Vec::new();

    for mut config in configs {
        // Reuse the single-interface scanner for each NIC/VLAN, but suppress
        // child cache writes and child Finished events. The TUI should behave
        // like one combined scan, not briefly complete after every interface.
        config.cache_enabled = false;
        let events = events.clone();
        let semaphore = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .context("scan concurrency limiter closed")?;
            let (child_tx, child_rx) = tokio::sync::mpsc::unbounded_channel();
            let forwarder = tokio::spawn(forward_child_events(child_rx, events));
            let result = scan_inner(config, Some(child_tx), false).await;
            let _ = forwarder.await;
            result
        }));
    }

    for handle in handles {
        let child_result = handle.await.context("scan task failed")??;
        targets.push(child_result.target.clone());
        interfaces.push(child_result.interface.clone());
        for warning in child_result.warnings {
            push_unique_warning(
                &mut warnings,
                format!("{}: {warning}", child_result.interface),
            );
        }
        devices.extend(child_result.devices);
    }

    let mut devices = merge_devices_by_interface_ip(devices);
    devices.sort_by_key(|device| {
        (
            device.interface.clone().unwrap_or_default(),
            ip_sort_key(device.ip),
        )
    });

    if cache_enabled {
        // Merge/save cache once after all interfaces are done. Per-interface
        // cache writes would make the last completed interface overwrite facts
        // learned by earlier interfaces in this same invocation.
        emit(
            &events,
            ScanEvent::Phase("multi-interface cache merge".to_string()),
        );
        match store::load_scan_cache(&cache_path) {
            Ok(previous) => {
                store::merge_previous_scan(&mut devices, &previous);
                finish_devices_update(&events, devices.iter_mut(), &identity_rules);
                if let Err(err) = store::save_scan_cache(&cache_path, &devices) {
                    let warning = format!("failed to save scan cache: {err}");
                    push_unique_warning(&mut warnings, warning.clone());
                    emit(&events, ScanEvent::Warning(warning));
                }
            }
            Err(err) => {
                let warning = format!("failed to load scan cache: {err}");
                push_unique_warning(&mut warnings, warning.clone());
                emit(&events, ScanEvent::Warning(warning));
            }
        }
    }

    let result = ScanResult {
        target: targets.join(","),
        interface: interfaces.join(","),
        scanned_at,
        devices,
        warnings,
    };

    if emit_finished {
        emit(
            &events,
            ScanEvent::Finished {
                devices: result.devices.clone(),
                warnings: result.warnings.clone(),
            },
        );
    }

    Ok(result)
}

async fn scan_inner(
    config: ScanConfig,
    events: Option<UnboundedSender<ScanEvent>>,
    emit_finished: bool,
) -> Result<ScanResult> {
    let scanned_at = Utc::now();
    let iface = net::select_interface(config.iface.as_deref())?;
    let target = net::parse_target(config.target.as_deref(), &iface)?;
    let oui_db = crate::enrich::load_oui_db(&config.oui_path).unwrap_or_default();
    let identity_rules = identity_rules::load_rule_db()?;

    let mut warnings = Vec::new();
    let mut devices = BTreeMap::<IpAddr, Device>::new();

    emit(
        &events,
        ScanEvent::Started {
            target: target.to_string(),
            interface: iface.name.clone(),
            profile: config.profile,
        },
    );
    emit(&events, ScanEvent::Phase("ARP discovery".to_string()));

    let arp_iface = iface.clone();
    let arp_target = target;
    let arp_timeout = config.timeout;
    let arp_events = events.clone();
    let arp_oui_db = oui_db.clone();
    let arp_rules = identity_rules.clone();
    let arp_oui_enabled = config.oui;
    let arp_result = tokio::task::spawn_blocking(move || {
        discovery::arp_sweep_with_callback(&arp_iface, arp_target, arp_timeout, |hit| {
            let mut device = Device::new(IpAddr::V4(hit.ip), scanned_at);
            device.interface = Some(arp_iface.name.clone());
            device.mac = Some(hit.mac.clone());
            if arp_oui_enabled {
                device.vendor = crate::enrich::lookup_vendor(&hit.mac, &arp_oui_db);
            }
            identity_rules::apply_identity_rules(&mut device, &arp_rules);
            emit_device(&arp_events, &device);
        })
    })
    .await
    .context("ARP worker failed")?;

    match arp_result {
        Ok(hits) => {
            for hit in hits {
                let device =
                    upsert_device(&mut devices, IpAddr::V4(hit.ip), scanned_at, &iface.name);
                if config.oui {
                    device.vendor = crate::enrich::lookup_vendor(&hit.mac, &oui_db);
                }
                device.mac = Some(hit.mac);
                finish_device_update(&events, device, &identity_rules);
            }
        }
        Err(err) => {
            let warning = format!("ARP sweep failed ({err}); falling back to the OS ARP table");
            warnings.push(warning.clone());
            emit(&events, ScanEvent::Warning(warning));
            for hit in discovery::arp_table(target) {
                let device =
                    upsert_device(&mut devices, IpAddr::V4(hit.ip), scanned_at, &iface.name);
                if config.oui {
                    device.vendor = crate::enrich::lookup_vendor(&hit.mac, &oui_db);
                }
                device.mac = Some(hit.mac);
                finish_device_update(&events, device, &identity_rules);
            }
        }
    }

    if target.contains(&iface.ip) {
        let self_device =
            upsert_device(&mut devices, IpAddr::V4(iface.ip), scanned_at, &iface.name);
        if self_device.mac.is_none() {
            self_device.mac = iface.mac.clone();
        }
        self_device.add_name(
            local_hostname().unwrap_or_else(|| iface.name.clone()),
            "local",
            0.95,
        );
        finish_device_update(&events, self_device, &identity_rules);
    }

    if config.oui {
        apply_oui(&mut devices, &oui_db);
    }
    finish_devices_update(&events, devices.values_mut(), &identity_rules);

    let lldp_context = LldpApplyContext {
        now: scanned_at,
        interface: &iface.name,
        target,
        oui_db: config.oui.then_some(&oui_db),
        events: &events,
        rules: &identity_rules,
    };
    let mut lldp_discovery = start_lldp_discovery(&config, iface.clone(), &events);

    if config.dhcp {
        emit(
            &events,
            ScanEvent::Phase("DHCP lease enrichment".to_string()),
        );
        let paths = if config.dhcp_paths.is_empty() {
            dhcp::default_lease_paths()
        } else {
            config.dhcp_paths.clone()
        };
        if !paths.is_empty() {
            let dhcp_worker = tokio::task::spawn_blocking(move || dhcp::read_leases(&paths));
            let (leases, dhcp_warnings) = await_with_lldp(
                dhcp_worker,
                &mut lldp_discovery,
                &mut devices,
                &lldp_context,
            )
            .await
            .context("DHCP lease worker failed")?;
            for warning in dhcp_warnings {
                warnings.push(warning.clone());
                emit(&events, ScanEvent::Warning(warning));
            }
            for lease in leases {
                // Lease files are often host-global rather than per-interface.
                // Scope them back to this interface's target network before
                // using hostnames or vendor-class strings as identity evidence.
                if !target_contains_ip(target, lease.ip) {
                    continue;
                }
                let device = upsert_device(&mut devices, lease.ip, scanned_at, &iface.name);
                apply_dhcp_lease(device, lease, config.oui.then_some(&oui_db));
                finish_device_update(&events, device, &identity_rules);
            }
        }
    }

    let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::unbounded_channel();
    let multicast_future =
        run_multicast_enrichment(&config, iface.ip, target, &events, move |update| {
            let _ = multicast_tx.send(update);
        });
    let (mdns_result, upnp_result) = await_with_lldp_and_phase_updates(
        multicast_future,
        &mut multicast_rx,
        &mut lldp_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            MulticastUpdate::Mdns(ip, mdns) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_mdns_info(device, mdns);
                finish_device_update(&events, device, &identity_rules);
            }
            MulticastUpdate::Upnp(ip, info) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_upnp_info(device, info);
                finish_device_update(&events, device, &identity_rules);
            }
        },
    )
    .await;

    if let Some(Err(err)) = mdns_result {
        let warning = format!("mDNS enrichment failed: {err}");
        warnings.push(warning.clone());
        emit(&events, ScanEvent::Warning(warning));
    }

    if let Some(Err(err)) = upnp_result {
        let warning = format!("UPnP/SSDP enrichment failed: {err}");
        warnings.push(warning.clone());
        emit(&events, ScanEvent::Warning(warning));
    }

    let ips = devices.keys().copied().collect::<Vec<_>>();
    let (name_tx, mut name_rx) = tokio::sync::mpsc::unbounded_channel();
    let name_future = run_name_enrichment(&config, ips.clone(), &events, move |update| {
        let _ = name_tx.send(update);
    });
    let _ = await_with_lldp_and_phase_updates(
        name_future,
        &mut name_rx,
        &mut lldp_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            NameUpdate::Rdns(ip, name) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                device.add_name(name, "rdns", 0.65);
                finish_device_update(&events, device, &identity_rules);
            }
            NameUpdate::Netbios(ip, names) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                for name in names {
                    device.add_name(name, "netbios", 0.8);
                }
                device.set_os_guess("Windows/SMB capable", "netbios", 0.45);
                finish_device_update(&events, device, &identity_rules);
            }
        },
    )
    .await;

    let ips = devices.keys().copied().collect::<Vec<_>>();
    let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel();
    let probe_future = run_deep_and_snmp_enrichment(&config, ips.clone(), &events, move |update| {
        let _ = probe_tx.send(update);
    });
    let _ = await_with_lldp_and_phase_updates(
        probe_future,
        &mut probe_rx,
        &mut lldp_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            ProbeUpdate::Deep(ip, probe) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_deep_probes(device, vec![probe]);
                finish_device_update(&events, device, &identity_rules);
            }
            ProbeUpdate::Snmp(ip, info) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_snmp_info(device, info);
                finish_device_update(&events, device, &identity_rules);
            }
        },
    )
    .await;

    if config.profile.includes_deep_probes() {
        // A listening 445/139 port only proves SMB reachability. SMB2 negotiate
        // adds dialect/signing/native strings before identity rules promote
        // the device toward Windows, Samba, NAS, or file-server hints.
        let smb_ips = devices
            .iter()
            .filter(|(_, device)| {
                device
                    .services
                    .iter()
                    .any(|service| matches!(service.port, Some(445)))
            })
            .map(|(ip, _)| *ip)
            .collect::<Vec<_>>();
        if !smb_ips.is_empty() {
            emit(&events, ScanEvent::Phase("SMB fingerprinting".to_string()));
            let (smb_tx, mut smb_rx) = tokio::sync::mpsc::unbounded_channel();
            let smb_future = smb::probe_hosts_with_callback(
                smb_ips,
                config.timeout,
                config.concurrency,
                move |ip, info| {
                    let _ = smb_tx.send((ip, info));
                },
            );
            let _ = await_with_lldp_and_phase_updates(
                smb_future,
                &mut smb_rx,
                &mut lldp_discovery,
                &mut devices,
                &lldp_context,
                |devices, (ip, info)| {
                    let device = upsert_device(devices, ip, scanned_at, &iface.name);
                    apply_smb_info(device, info);
                    finish_device_update(&events, device, &identity_rules);
                },
            )
            .await;
        }
    }

    if let Some(Err(err)) =
        finish_lldp_discovery(lldp_discovery.take(), &mut devices, &lldp_context).await
    {
        let warning = format!("LLDP discovery failed: {err}");
        warnings.push(warning.clone());
        emit(&events, ScanEvent::Warning(warning));
    }

    let mut devices = devices.into_values().collect::<Vec<_>>();
    devices.sort_by_key(|device| ip_sort_key(device.ip));

    if config.cache_enabled {
        emit(&events, ScanEvent::Phase("cache merge".to_string()));
        match store::load_scan_cache(&config.cache_path) {
            Ok(previous) => {
                store::merge_previous_scan(&mut devices, &previous);
                finish_devices_update(&events, devices.iter_mut(), &identity_rules);
                if let Err(err) = store::save_scan_cache(&config.cache_path, &devices) {
                    let warning = format!("failed to save scan cache: {err}");
                    warnings.push(warning.clone());
                    emit(&events, ScanEvent::Warning(warning));
                }
            }
            Err(err) => {
                let warning = format!("failed to load scan cache: {err}");
                warnings.push(warning.clone());
                emit(&events, ScanEvent::Warning(warning));
            }
        }
    }

    let result = ScanResult {
        target: target.to_string(),
        interface: iface.name,
        scanned_at,
        devices,
        warnings,
    };

    if emit_finished {
        emit(
            &events,
            ScanEvent::Finished {
                devices: result.devices.clone(),
                warnings: result.warnings.clone(),
            },
        );
    }

    Ok(result)
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.iter().any(|existing| existing == &warning) {
        warnings.push(warning);
    }
}

fn upsert_device<'a>(
    devices: &'a mut BTreeMap<IpAddr, Device>,
    ip: IpAddr,
    now: chrono::DateTime<Utc>,
    interface: &str,
) -> &'a mut Device {
    let device = devices.entry(ip).or_insert_with(|| Device::new(ip, now));
    if device.interface.is_none() {
        device.interface = Some(interface.to_string());
    }
    device
}

async fn await_with_lldp<F, T>(
    future: F,
    lldp: &mut Option<LldpDiscovery>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) -> T
where
    F: Future<Output = T>,
{
    let mut lldp_open = lldp.is_some();
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                drain_lldp_updates(lldp, devices, context);
                return result;
            }
            info = recv_lldp_update(lldp), if lldp_open => {
                if let Some(info) = info {
                    apply_lldp_discovery_update(devices, info, context);
                } else {
                    lldp_open = false;
                }
            }
        }
    }
}

async fn await_with_lldp_and_phase_updates<F, T, U, ApplyUpdate>(
    future: F,
    phase_rx: &mut UnboundedReceiver<U>,
    lldp: &mut Option<LldpDiscovery>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
    mut apply_update: ApplyUpdate,
) -> T
where
    F: Future<Output = T>,
    ApplyUpdate: FnMut(&mut BTreeMap<IpAddr, Device>, U),
{
    let mut phase_open = true;
    let mut lldp_open = lldp.is_some();
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                drain_phase_updates(phase_rx, devices, &mut apply_update);
                drain_lldp_updates(lldp, devices, context);
                return result;
            }
            update = phase_rx.recv(), if phase_open => {
                if let Some(update) = update {
                    apply_update(devices, update);
                } else {
                    phase_open = false;
                }
            }
            info = recv_lldp_update(lldp), if lldp_open => {
                if let Some(info) = info {
                    apply_lldp_discovery_update(devices, info, context);
                } else {
                    lldp_open = false;
                }
            }
        }
    }
}

async fn recv_lldp_update(lldp: &mut Option<LldpDiscovery>) -> Option<discovery::lldp::LldpInfo> {
    match lldp {
        Some(discovery) => discovery.updates.recv().await,
        None => None,
    }
}

fn drain_phase_updates<U, ApplyUpdate>(
    phase_rx: &mut UnboundedReceiver<U>,
    devices: &mut BTreeMap<IpAddr, Device>,
    apply_update: &mut ApplyUpdate,
) where
    ApplyUpdate: FnMut(&mut BTreeMap<IpAddr, Device>, U),
{
    while let Ok(update) = phase_rx.try_recv() {
        apply_update(devices, update);
    }
}

fn drain_lldp_updates(
    lldp: &mut Option<LldpDiscovery>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) {
    let Some(discovery) = lldp else {
        return;
    };
    while let Ok(info) = discovery.updates.try_recv() {
        apply_lldp_discovery_update(devices, info, context);
    }
}

async fn finish_lldp_discovery(
    lldp: Option<LldpDiscovery>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) -> Option<LldpRun> {
    let mut discovery = lldp?;
    let mut updates_open = true;

    Some(loop {
        tokio::select! {
            result = &mut discovery.listener => {
                drain_lldp_receiver(&mut discovery.updates, devices, context);
                break result
                    .context("LLDP worker failed")
                    .and_then(|listener_result| listener_result);
            }
            info = discovery.updates.recv(), if updates_open => {
                if let Some(info) = info {
                    apply_lldp_discovery_update(devices, info, context);
                } else {
                    updates_open = false;
                }
            }
        }
    })
}

fn drain_lldp_receiver(
    updates: &mut UnboundedReceiver<discovery::lldp::LldpInfo>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) {
    while let Ok(info) = updates.try_recv() {
        apply_lldp_discovery_update(devices, info, context);
    }
}

struct LldpApplyContext<'a> {
    now: chrono::DateTime<Utc>,
    interface: &'a str,
    target: ipnet::Ipv4Net,
    oui_db: Option<&'a std::collections::HashMap<String, String>>,
    events: &'a Option<UnboundedSender<ScanEvent>>,
    rules: &'a identity_rules::RuleDb,
}

fn apply_lldp_discovery_update(
    devices: &mut BTreeMap<IpAddr, Device>,
    info: discovery::lldp::LldpInfo,
    context: &LldpApplyContext<'_>,
) {
    for ip in lldp_device_ips(devices, &info, context.target) {
        let device = upsert_device(devices, ip, context.now, context.interface);
        apply_lldp_info(device, info.clone(), context.oui_db);
        finish_device_update(context.events, device, context.rules);
    }
}

fn lldp_device_ips(
    devices: &BTreeMap<IpAddr, Device>,
    info: &discovery::lldp::LldpInfo,
    target: ipnet::Ipv4Net,
) -> Vec<IpAddr> {
    let mut ips = BTreeSet::new();
    for ip in &info.management_addresses {
        if target_contains_ip(target, *ip) {
            ips.insert(*ip);
        }
    }

    for mac in lldp_candidate_macs(info) {
        if let Some((ip, _)) = devices.iter().find(|(_, device)| {
            device
                .mac
                .as_deref()
                .is_some_and(|device_mac| same_mac(device_mac, &mac))
        }) {
            ips.insert(*ip);
        }
    }

    ips.into_iter().collect()
}

fn lldp_candidate_macs(info: &discovery::lldp::LldpInfo) -> Vec<String> {
    let mut macs = Vec::new();
    if let Some(mac) = &info.chassis_mac {
        macs.push(mac.clone());
    }
    macs.push(info.source_mac.clone());
    macs
}

fn same_mac(left: &str, right: &str) -> bool {
    normalize_mac(left) == normalize_mac(right)
}

fn normalize_mac(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(char::to_lowercase)
        .collect()
}

fn finish_device_update(
    events: &Option<UnboundedSender<ScanEvent>>,
    device: &mut Device,
    rules: &identity_rules::RuleDb,
) {
    // Identity rules are intentionally re-run after every enrichment phase. That
    // keeps the live UI progressive: a row can appear from ARP, gain a name from
    // mDNS, then gain OS/type from UPnP/SNMP without waiting for scan completion.
    identity_rules::apply_identity_rules(device, rules);
    emit_device(events, device);
}

fn finish_devices_update<'a, I>(
    events: &Option<UnboundedSender<ScanEvent>>,
    devices: I,
    rules: &identity_rules::RuleDb,
) where
    I: IntoIterator<Item = &'a mut Device>,
{
    for device in devices {
        finish_device_update(events, device, rules);
    }
}

fn local_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
}

fn ip_sort_key(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(ipv4) => (4, u32::from(ipv4) as u128),
        IpAddr::V6(ipv6) => (6, u128::from(ipv6)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_timeouts_are_ordered_by_depth() {
        assert!(ScanProfile::Fast.default_timeout() < ScanProfile::Normal.default_timeout());
        assert!(ScanProfile::Normal.default_timeout() < ScanProfile::Deep.default_timeout());
    }

    #[test]
    fn ip_sort_key_orders_ipv4_numerically() {
        let mut ips = [
            "192.168.1.20".parse::<IpAddr>().unwrap(),
            "192.168.1.2".parse::<IpAddr>().unwrap(),
        ];
        ips.sort_by_key(|ip| ip_sort_key(*ip));

        assert_eq!(ips[0], "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn multi_interface_merge_keeps_same_ip_on_different_interfaces() {
        let now = Utc::now();
        let mut left = Device::new("192.168.1.10".parse().unwrap(), now);
        left.interface = Some("en0".to_string());
        let mut right = Device::new("192.168.1.10".parse().unwrap(), now);
        right.interface = Some("en0.100".to_string());

        let merged = merge_devices_by_interface_ip(vec![left, right]);

        assert_eq!(merged.len(), 2);
    }
}
