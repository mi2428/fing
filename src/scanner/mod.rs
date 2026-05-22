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
    dhcp, discovery, enrich, identity_rules,
    model::{Device, ScanResult},
    net,
    probes::smb,
    store,
};
use anyhow::{Context, Result};
use apply::{
    apply_cdp_info, apply_deep_probes, apply_dhcp_lease, apply_lldp_info, apply_mdns_info,
    apply_oui, apply_smb_info, apply_snmp_info, apply_upnp_info, merge_devices_by_interface_ip,
};
use chrono::{DateTime, Utc};
use phases::{
    L2Discovery, L2Run, MulticastUpdate, NameUpdate, ProbeUpdate, emit, emit_device,
    forward_child_events, idle_phase, run_deep_and_snmp_enrichment, run_multicast_enrichment,
    run_name_enrichment, scan_target_summary, start_l2_discovery, target_contains_ip,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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

    let (mut passive_manager, mut passive_rx, _passive_listeners) =
        ContinuousPassiveManager::start(&configs)?;
    let round_configs = round_scan_configs(&configs);
    let mut round = 1_u64;
    loop {
        wait_until_resumed_with_passive(
            &mut pause_rx,
            &events,
            &mut passive_rx,
            &mut passive_manager,
        )
        .await;
        emit(&Some(events.clone()), ScanEvent::RoundStarted { round });
        emit(
            &Some(events.clone()),
            ScanEvent::Phase(format!("scan round {round}")),
        );
        if let Err(err) = run_scan_round_with_passive_updates(
            round_configs.clone(),
            events.clone(),
            &mut passive_rx,
            &mut passive_manager,
        )
        .await
        {
            emit(
                &Some(events.clone()),
                ScanEvent::Warning(format!("scan round {round} failed: {err}")),
            );
        }
        if let Some(phase) = idle_phase(interval, round) {
            emit(&Some(events.clone()), ScanEvent::Phase(phase));
            wait_interval_or_pause_with_passive(
                interval,
                &mut pause_rx,
                &events,
                &mut passive_rx,
                &mut passive_manager,
            )
            .await;
        } else {
            // A zero interval means "scan continuously": start the next round
            // as soon as the previous discovery/enrichment pass completes.
            // Yielding keeps the async runtime responsive without introducing
            // a user-visible delay.
            drain_continuous_passive_updates(&events, &mut passive_rx, &mut passive_manager);
            tokio::task::yield_now().await;
        }
        round = round.saturating_add(1);
    }
}

#[derive(Debug, Clone)]
enum ContinuousPassiveUpdate {
    Observation {
        interface: String,
        observation: Box<PassiveObservation>,
    },
    Warning(String),
}

struct ContinuousPassiveListenerGuard {
    cancel: Arc<AtomicBool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for ContinuousPassiveListenerGuard {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        for handle in &self.handles {
            handle.abort();
        }
    }
}

#[derive(Debug, Clone)]
struct ContinuousPassiveInterface {
    iface: net::InterfaceInfo,
    targets: Vec<ipnet::Ipv4Net>,
    oui: bool,
    lldp: bool,
    cdp: bool,
}

struct ContinuousPassiveManager {
    states: BTreeMap<String, ContinuousPassiveInterfaceState>,
    rules: identity_rules::RuleDb,
    oui_db: HashMap<String, String>,
}

struct ContinuousPassiveInterfaceState {
    targets: Vec<ipnet::Ipv4Net>,
    oui: bool,
    devices: BTreeMap<IpAddr, Device>,
    pending_observations: BTreeMap<String, PassiveObservation>,
}

const DEFAULT_LLDP_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
struct PassiveObservation {
    key: String,
    received_at: DateTime<Utc>,
    ttl: Duration,
    candidate_ips: Vec<IpAddr>,
    candidate_macs: Vec<String>,
    advertisement: discovery::l2::L2Advertisement,
}

impl PassiveObservation {
    fn from_advertisement(advertisement: discovery::l2::L2Advertisement) -> Self {
        Self::from_advertisement_at(advertisement, Utc::now())
    }

    fn from_advertisement_at(
        advertisement: discovery::l2::L2Advertisement,
        received_at: DateTime<Utc>,
    ) -> Self {
        match &advertisement {
            discovery::l2::L2Advertisement::Lldp(info) => Self {
                key: format!("lldp|{}", info.identity_key()),
                received_at,
                ttl: info
                    .ttl
                    .map(|ttl| Duration::from_secs(u64::from(ttl)))
                    .unwrap_or(DEFAULT_LLDP_TTL),
                candidate_ips: info.management_addresses.clone(),
                candidate_macs: lldp_candidate_macs(info),
                advertisement,
            },
            discovery::l2::L2Advertisement::Cdp(info) => Self {
                key: format!("cdp|{}", info.identity_key()),
                received_at,
                ttl: Duration::from_secs(u64::from(info.ttl)),
                candidate_ips: info
                    .management_addresses
                    .iter()
                    .chain(&info.addresses)
                    .copied()
                    .collect(),
                candidate_macs: vec![info.source_mac.clone()],
                advertisement,
            },
        }
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(self.received_at)
            .to_std()
            .is_ok_and(|age| age >= self.ttl)
    }

    fn target_ips(
        &self,
        devices: &BTreeMap<IpAddr, Device>,
        targets: &[ipnet::Ipv4Net],
    ) -> Vec<IpAddr> {
        let mut ips = BTreeSet::new();
        for target in targets {
            for ip in &self.candidate_ips {
                if target_contains_ip(*target, *ip) {
                    ips.insert(*ip);
                }
            }
        }

        for mac in &self.candidate_macs {
            if let Some((ip, _)) = devices.iter().find(|(_, device)| {
                device
                    .mac
                    .as_deref()
                    .is_some_and(|device_mac| same_mac(device_mac, mac))
            }) {
                ips.insert(*ip);
            }
        }

        ips.into_iter().collect()
    }

    fn matches_device(&self, device: &Device) -> bool {
        self.candidate_ips.contains(&device.ip)
            || self.candidate_macs.iter().any(|mac| {
                device
                    .mac
                    .as_deref()
                    .is_some_and(|device_mac| same_mac(device_mac, mac))
            })
    }

    fn apply_to_device(&self, device: &mut Device, oui_db: Option<&HashMap<String, String>>) {
        match &self.advertisement {
            discovery::l2::L2Advertisement::Lldp(info) => {
                apply_lldp_info(device, info.clone(), oui_db);
            }
            discovery::l2::L2Advertisement::Cdp(info) => {
                apply_cdp_info(device, info.clone(), oui_db);
            }
        }
    }
}

impl ContinuousPassiveManager {
    fn start(
        configs: &[ScanConfig],
    ) -> Result<(
        Self,
        UnboundedReceiver<ContinuousPassiveUpdate>,
        ContinuousPassiveListenerGuard,
    )> {
        let interfaces = continuous_passive_interfaces(configs)?;
        let mut states = BTreeMap::new();
        for interface in &interfaces {
            states.insert(
                interface.iface.name.clone(),
                ContinuousPassiveInterfaceState {
                    targets: interface.targets.clone(),
                    oui: interface.oui,
                    devices: BTreeMap::new(),
                    pending_observations: BTreeMap::new(),
                },
            );
        }

        let oui_path = configs
            .first()
            .map(|config| config.oui_path.clone())
            .unwrap_or_else(enrich::default_oui_db_path);
        let manager = Self {
            states,
            rules: identity_rules::load_rule_db()?,
            oui_db: enrich::load_oui_db(&oui_path).unwrap_or_default(),
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for interface in interfaces {
            handles.push(tokio::spawn(continuous_l2_listener(
                interface.iface.clone(),
                discovery::l2::L2Protocols {
                    lldp: interface.lldp,
                    cdp: interface.cdp,
                },
                Arc::clone(&cancel),
                tx.clone(),
            )));
        }

        Ok((
            manager,
            rx,
            ContinuousPassiveListenerGuard { cancel, handles },
        ))
    }

    fn observe_scan_event(&mut self, event: ScanEvent) -> ScanEvent {
        match event {
            ScanEvent::DeviceUpdated(mut device) => {
                self.observe_device(&mut device);
                ScanEvent::DeviceUpdated(device)
            }
            ScanEvent::Finished {
                mut devices,
                warnings,
            } => {
                for device in &mut devices {
                    self.observe_device(device);
                }
                ScanEvent::Finished { devices, warnings }
            }
            other => other,
        }
    }

    fn observe_device(&mut self, device: &mut Device) {
        let Some(interface) = device.interface.clone() else {
            return;
        };
        let Some(state) = self.states.get_mut(&interface) else {
            return;
        };
        prune_expired_observations(state, Utc::now());
        merge_known_device(state, device.clone());
        let mut merged = state
            .devices
            .get(&device.ip)
            .cloned()
            .unwrap_or_else(|| device.clone());
        apply_pending_passive(&mut merged, state, &self.oui_db, &self.rules);
        state.devices.insert(device.ip, merged.clone());
        *device = merged;
    }

    fn apply_passive_update(&mut self, update: ContinuousPassiveUpdate) -> Vec<ScanEvent> {
        match update {
            ContinuousPassiveUpdate::Observation {
                interface,
                observation,
            } => self.apply_observation(&interface, *observation),
            ContinuousPassiveUpdate::Warning(warning) => vec![ScanEvent::Warning(warning)],
        }
    }

    fn apply_observation(
        &mut self,
        interface: &str,
        observation: PassiveObservation,
    ) -> Vec<ScanEvent> {
        let Some(state) = self.states.get_mut(interface) else {
            return Vec::new();
        };
        let now = Utc::now();
        prune_expired_observations(state, now);
        if observation.is_expired(now) {
            return Vec::new();
        }
        state
            .pending_observations
            .insert(observation.key.clone(), observation.clone());
        let received_at = observation.received_at;

        let mut events = Vec::new();
        for ip in observation.target_ips(&state.devices, &state.targets) {
            let device = state
                .devices
                .entry(ip)
                .or_insert_with(|| passive_device(ip, interface, received_at));
            let before = device.clone();
            device.last_seen = received_at;
            observation.apply_to_device(device, state.oui.then_some(&self.oui_db));
            identity_rules::apply_identity_rules(device, &self.rules);
            if *device != before {
                events.push(ScanEvent::DeviceUpdated(Box::new(device.clone())));
            }
        }
        events
    }
}

fn continuous_passive_interfaces(
    configs: &[ScanConfig],
) -> Result<Vec<ContinuousPassiveInterface>> {
    let mut interfaces = BTreeMap::<String, ContinuousPassiveInterface>::new();
    for config in configs {
        if !config.lldp && !config.cdp {
            continue;
        }
        let iface = net::select_interface(config.iface.as_deref())?;
        let target = net::parse_target(config.target.as_deref(), &iface)?;
        let entry =
            interfaces
                .entry(iface.name.clone())
                .or_insert_with(|| ContinuousPassiveInterface {
                    iface: iface.clone(),
                    targets: Vec::new(),
                    oui: false,
                    lldp: false,
                    cdp: false,
                });
        if !entry.targets.contains(&target) {
            entry.targets.push(target);
        }
        entry.oui |= config.oui;
        entry.lldp |= config.lldp;
        entry.cdp |= config.cdp;
    }
    Ok(interfaces.into_values().collect())
}

async fn continuous_l2_listener(
    iface: net::InterfaceInfo,
    protocols: discovery::l2::L2Protocols,
    cancel: Arc<AtomicBool>,
    updates: UnboundedSender<ContinuousPassiveUpdate>,
) {
    let iface_name = iface.name.clone();
    let worker_iface = iface.clone();
    let stop_updates = updates.clone();
    let worker_updates = updates.clone();
    let worker_cancel = Arc::clone(&cancel);
    let result = tokio::task::spawn_blocking(move || {
        discovery::l2::listen_until_repeating(
            &worker_iface,
            protocols,
            || worker_cancel.load(Ordering::Relaxed) || stop_updates.is_closed(),
            move |advertisement| {
                let observation = PassiveObservation::from_advertisement(advertisement.clone());
                let _ = worker_updates.send(ContinuousPassiveUpdate::Observation {
                    interface: iface_name.clone(),
                    observation: Box::new(observation),
                });
            },
        )
    })
    .await;

    if cancel.load(Ordering::Relaxed) || updates.is_closed() {
        return;
    }
    if let Err(warning) = passive_listener_warning(protocols.label(), &iface.name, result) {
        let _ = updates.send(ContinuousPassiveUpdate::Warning(warning));
    }
}

fn passive_listener_warning<T>(
    protocol: &str,
    interface: &str,
    result: std::result::Result<Result<T>, tokio::task::JoinError>,
) -> std::result::Result<(), String> {
    match result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(format!("{protocol} listener failed on {interface}: {err}")),
        Err(err) => Err(format!(
            "{protocol} listener task failed on {interface}: {err}"
        )),
    }
}

fn round_scan_configs(configs: &[ScanConfig]) -> Vec<ScanConfig> {
    configs
        .iter()
        .cloned()
        .map(|mut config| {
            config.lldp = false;
            config.cdp = false;
            config
        })
        .collect()
}

async fn run_scan_round_with_passive_updates(
    configs: Vec<ScanConfig>,
    events: UnboundedSender<ScanEvent>,
    passive_rx: &mut UnboundedReceiver<ContinuousPassiveUpdate>,
    passive_manager: &mut ContinuousPassiveManager,
) -> Result<()> {
    let (round_tx, mut round_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut round =
        tokio::spawn(async move { scan_many_inner(configs, Some(round_tx), false).await });
    let mut round_events_open = true;
    let mut passive_open = true;

    loop {
        tokio::select! {
            result = &mut round => {
                while let Ok(event) = round_rx.try_recv() {
                    forward_scan_event(&events, passive_manager, event);
                }
                result.context("scan task failed")??;
                return Ok(());
            }
            event = round_rx.recv(), if round_events_open => {
                if let Some(event) = event {
                    forward_scan_event(&events, passive_manager, event);
                } else {
                    round_events_open = false;
                }
            }
            update = passive_rx.recv(), if passive_open => {
                if let Some(update) = update {
                    forward_passive_update(&events, passive_manager, update);
                } else {
                    passive_open = false;
                }
            }
        }
    }
}

fn forward_scan_event(
    events: &UnboundedSender<ScanEvent>,
    passive_manager: &mut ContinuousPassiveManager,
    event: ScanEvent,
) {
    let event = passive_manager.observe_scan_event(event);
    let _ = events.send(event);
}

fn forward_passive_update(
    events: &UnboundedSender<ScanEvent>,
    passive_manager: &mut ContinuousPassiveManager,
    update: ContinuousPassiveUpdate,
) {
    for event in passive_manager.apply_passive_update(update) {
        let _ = events.send(event);
    }
}

fn drain_continuous_passive_updates(
    events: &UnboundedSender<ScanEvent>,
    passive_rx: &mut UnboundedReceiver<ContinuousPassiveUpdate>,
    passive_manager: &mut ContinuousPassiveManager,
) {
    while let Ok(update) = passive_rx.try_recv() {
        forward_passive_update(events, passive_manager, update);
    }
}

async fn wait_interval_or_pause_with_passive(
    interval: Duration,
    pause_rx: &mut watch::Receiver<bool>,
    events: &UnboundedSender<ScanEvent>,
    passive_rx: &mut UnboundedReceiver<ContinuousPassiveUpdate>,
    passive_manager: &mut ContinuousPassiveManager,
) {
    let sleep = tokio::time::sleep(interval);
    tokio::pin!(sleep);
    let mut passive_open = true;
    loop {
        tokio::select! {
            _ = &mut sleep => return,
            changed = pause_rx.changed() => {
                let _ = changed;
                return;
            }
            update = passive_rx.recv(), if passive_open => {
                if let Some(update) = update {
                    forward_passive_update(events, passive_manager, update);
                } else {
                    passive_open = false;
                }
            }
        }
    }
}

async fn wait_until_resumed_with_passive(
    pause_rx: &mut watch::Receiver<bool>,
    events: &UnboundedSender<ScanEvent>,
    passive_rx: &mut UnboundedReceiver<ContinuousPassiveUpdate>,
    passive_manager: &mut ContinuousPassiveManager,
) {
    if !*pause_rx.borrow() {
        drain_continuous_passive_updates(events, passive_rx, passive_manager);
        return;
    }

    let _ = events.send(ScanEvent::Phase("paused".to_string()));
    let mut passive_open = true;
    while *pause_rx.borrow_and_update() {
        tokio::select! {
            changed = pause_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            update = passive_rx.recv(), if passive_open => {
                if let Some(update) = update {
                    forward_passive_update(events, passive_manager, update);
                } else {
                    passive_open = false;
                }
            }
        }
    }
}

fn passive_device(ip: IpAddr, interface: &str, now: DateTime<Utc>) -> Device {
    let mut device = Device::new(ip, now);
    device.interface = Some(interface.to_string());
    device
}

fn merge_known_device(state: &mut ContinuousPassiveInterfaceState, incoming: Device) {
    if let Some(existing) = state.devices.get_mut(&incoming.ip) {
        if device_mac_changed(existing, &incoming) {
            *existing = incoming;
        } else {
            merge_device_snapshot(existing, incoming);
        }
    } else {
        state.devices.insert(incoming.ip, incoming);
    }
}

fn merge_device_snapshot(existing: &mut Device, mut incoming: Device) {
    if existing.interface.is_none() {
        existing.interface = incoming.interface.take();
    }
    if existing.mac.is_none() {
        existing.mac = incoming.mac.take();
    }
    if existing.vendor.is_none() {
        existing.vendor = incoming.vendor.take();
    }
    if existing.hostname.is_none() {
        existing.hostname = incoming.hostname.take();
    }
    for name in incoming.names {
        existing.add_name(name.name, &name.source, name.confidence);
    }
    if let Some(make) = incoming.make {
        existing.set_make_guess(make.value, &make.source, make.confidence);
    }
    if let Some(model) = incoming.model {
        existing.set_model_guess(model.value, &model.source, model.confidence);
    }
    if let Some(os) = incoming.os {
        existing.set_os_guess(os.value, &os.source, os.confidence);
    }
    if let Some(device_type) = incoming.device_type {
        existing.set_device_type_guess(
            device_type.value,
            &device_type.source,
            device_type.confidence,
        );
    }
    for service in incoming.services {
        existing.add_service(
            service.name,
            &service.source,
            service.port,
            service.confidence,
        );
    }
    for evidence in incoming.evidence {
        existing.add_evidence(
            &evidence.source,
            &evidence.key,
            evidence.value,
            evidence.confidence,
        );
    }
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
}

fn prune_expired_observations(state: &mut ContinuousPassiveInterfaceState, now: DateTime<Utc>) {
    state
        .pending_observations
        .retain(|_, observation| !observation.is_expired(now));
}

fn apply_pending_passive(
    device: &mut Device,
    state: &ContinuousPassiveInterfaceState,
    oui_db: &HashMap<String, String>,
    rules: &identity_rules::RuleDb,
) {
    let matches = state
        .pending_observations
        .values()
        .filter(|observation| observation.matches_device(device))
        .cloned()
        .collect::<Vec<_>>();
    for observation in matches {
        observation.apply_to_device(device, state.oui.then_some(oui_db));
    }
    identity_rules::apply_identity_rules(device, rules);
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
                finish_device_snapshots(&events, devices.iter_mut(), &identity_rules);
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
            finish_observed_device_update(&arp_events, &mut device, &arp_rules);
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
                finish_observed_device_update(&events, device, &identity_rules);
            }
        }
        Err(err) => {
            let warning = format!("ARP sweep failed ({err}); falling back to the OS ARP table");
            warnings.push(warning.clone());
            emit(&events, ScanEvent::Warning(warning));
            for hit in discovery::arp_table(target, &iface.name) {
                let device =
                    upsert_device(&mut devices, IpAddr::V4(hit.ip), scanned_at, &iface.name);
                if config.oui {
                    device.vendor = crate::enrich::lookup_vendor(&hit.mac, &oui_db);
                }
                device.mac = Some(hit.mac);
                finish_observed_device_update(&events, device, &identity_rules);
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
        finish_observed_device_update(&events, self_device, &identity_rules);
    }

    if config.oui {
        apply_oui(&mut devices, &oui_db);
    }
    finish_device_snapshots(&events, devices.values_mut(), &identity_rules);

    let lldp_context = LldpApplyContext {
        now: scanned_at,
        interface: &iface.name,
        target,
        oui_db: config.oui.then_some(&oui_db),
        events: &events,
        rules: &identity_rules,
    };
    let mut passive_discovery = PassiveDiscovery {
        l2: start_l2_discovery(&config, iface.clone(), &events),
    };

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
                &mut passive_discovery,
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
                finish_observed_device_update(&events, device, &identity_rules);
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
        &mut passive_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            MulticastUpdate::Mdns(ip, mdns) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_mdns_info(device, mdns);
                finish_observed_device_update(&events, device, &identity_rules);
            }
            MulticastUpdate::Upnp(ip, info) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_upnp_info(device, info);
                finish_observed_device_update(&events, device, &identity_rules);
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
        &mut passive_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            NameUpdate::Rdns(ip, name) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                device.add_name(name, "rdns", 0.65);
                finish_observed_device_update(&events, device, &identity_rules);
            }
            NameUpdate::Netbios(ip, names) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                for name in names {
                    device.add_name(name, "netbios", 0.8);
                }
                device.set_os_guess("Windows/SMB capable", "netbios", 0.45);
                finish_observed_device_update(&events, device, &identity_rules);
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
        &mut passive_discovery,
        &mut devices,
        &lldp_context,
        |devices, update| match update {
            ProbeUpdate::Deep(ip, probe) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_deep_probes(device, vec![probe]);
                finish_observed_device_update(&events, device, &identity_rules);
            }
            ProbeUpdate::Snmp(ip, info) => {
                let device = upsert_device(devices, ip, scanned_at, &iface.name);
                apply_snmp_info(device, info);
                finish_observed_device_update(&events, device, &identity_rules);
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
                &mut passive_discovery,
                &mut devices,
                &lldp_context,
                |devices, (ip, info)| {
                    let device = upsert_device(devices, ip, scanned_at, &iface.name);
                    apply_smb_info(device, info);
                    finish_observed_device_update(&events, device, &identity_rules);
                },
            )
            .await;
        }
    }

    if let Some(Err(err)) =
        finish_l2_discovery(passive_discovery.l2.take(), &mut devices, &lldp_context).await
    {
        let warning = format!("L2 passive discovery failed: {err}");
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
                finish_device_snapshots(&events, devices.iter_mut(), &identity_rules);
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
    passive: &mut PassiveDiscovery,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) -> T
where
    F: Future<Output = T>,
{
    let mut passive_open = passive.has_open_updates();
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                drain_passive_updates(passive, devices, context);
                return result;
            }
            update = recv_passive_update(passive), if passive_open => {
                if let Some(update) = update {
                    apply_passive_update(devices, update, context);
                } else {
                    passive_open = false;
                }
            }
        }
    }
}

async fn await_with_lldp_and_phase_updates<F, T, U, ApplyUpdate>(
    future: F,
    phase_rx: &mut UnboundedReceiver<U>,
    passive: &mut PassiveDiscovery,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
    mut apply_update: ApplyUpdate,
) -> T
where
    F: Future<Output = T>,
    ApplyUpdate: FnMut(&mut BTreeMap<IpAddr, Device>, U),
{
    let mut phase_open = true;
    let mut passive_open = passive.has_open_updates();
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                drain_phase_updates(phase_rx, devices, &mut apply_update);
                drain_passive_updates(passive, devices, context);
                return result;
            }
            update = phase_rx.recv(), if phase_open => {
                if let Some(update) = update {
                    apply_update(devices, update);
                } else {
                    phase_open = false;
                }
            }
            update = recv_passive_update(passive), if passive_open => {
                if let Some(update) = update {
                    apply_passive_update(devices, update, context);
                } else {
                    passive_open = false;
                }
            }
        }
    }
}

struct PassiveDiscovery {
    l2: Option<L2Discovery>,
}

impl PassiveDiscovery {
    fn has_open_updates(&self) -> bool {
        self.l2.is_some()
    }
}

type PassiveUpdate = PassiveObservation;

async fn recv_passive_update(passive: &mut PassiveDiscovery) -> Option<PassiveUpdate> {
    match &mut passive.l2 {
        Some(l2) => match l2.updates.recv().await {
            Some(advertisement) => Some(PassiveObservation::from_advertisement(advertisement)),
            None => {
                passive.l2 = None;
                None
            }
        },
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

fn drain_passive_updates(
    passive: &mut PassiveDiscovery,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) {
    if let Some(discovery) = &mut passive.l2 {
        while let Ok(advertisement) = discovery.updates.try_recv() {
            apply_passive_update(
                devices,
                PassiveObservation::from_advertisement(advertisement),
                context,
            );
        }
    }
}

fn apply_passive_update(
    devices: &mut BTreeMap<IpAddr, Device>,
    update: PassiveUpdate,
    context: &LldpApplyContext<'_>,
) {
    for ip in update.target_ips(devices, &[context.target]) {
        let device = upsert_device(devices, ip, context.now, context.interface);
        update.apply_to_device(device, context.oui_db);
        finish_observed_device_update(context.events, device, context.rules);
    }
}

async fn finish_l2_discovery(
    l2: Option<L2Discovery>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) -> Option<L2Run> {
    let mut discovery = l2?;
    let mut updates_open = true;

    Some(loop {
        tokio::select! {
            result = &mut discovery.listener => {
                drain_l2_receiver(&mut discovery.updates, devices, context);
                break result
                    .context("L2 passive worker failed")
                    .and_then(|listener_result| listener_result);
            }
            advertisement = discovery.updates.recv(), if updates_open => {
                if let Some(advertisement) = advertisement {
                    apply_passive_update(
                        devices,
                        PassiveObservation::from_advertisement(advertisement),
                        context,
                    );
                } else {
                    updates_open = false;
                }
            }
        }
    })
}

fn drain_l2_receiver(
    updates: &mut UnboundedReceiver<discovery::l2::L2Advertisement>,
    devices: &mut BTreeMap<IpAddr, Device>,
    context: &LldpApplyContext<'_>,
) {
    while let Ok(advertisement) = updates.try_recv() {
        apply_passive_update(
            devices,
            PassiveObservation::from_advertisement(advertisement),
            context,
        );
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

fn device_mac_changed(existing: &Device, incoming: &Device) -> bool {
    matches!(
        (existing.mac.as_deref(), incoming.mac.as_deref()),
        (Some(existing), Some(incoming)) if !same_mac(existing, incoming)
    )
}

fn normalize_mac(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(char::to_lowercase)
        .collect()
}

fn finish_observed_device_update(
    events: &Option<UnboundedSender<ScanEvent>>,
    device: &mut Device,
    rules: &identity_rules::RuleDb,
) {
    device.last_seen = Utc::now();
    finish_device_snapshot(events, device, rules);
}

fn finish_device_snapshot(
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

fn finish_device_snapshots<'a, I>(
    events: &Option<UnboundedSender<ScanEvent>>,
    devices: I,
    rules: &identity_rules::RuleDb,
) where
    I: IntoIterator<Item = &'a mut Device>,
{
    for device in devices {
        finish_device_snapshot(events, device, rules);
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
    use chrono::TimeZone;

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

    #[test]
    fn continuous_passive_lldp_update_emits_device_by_management_address() {
        let mut manager = passive_manager();

        let events = manager.apply_passive_update(ContinuousPassiveUpdate::Observation {
            interface: "en0".to_string(),
            observation: Box::new(PassiveObservation::from_advertisement(
                discovery::l2::L2Advertisement::Lldp(discovery::lldp::LldpInfo {
                    source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                    chassis_id: Some("aa:bb:cc:dd:ee:ff".to_string()),
                    chassis_id_subtype: Some("mac-address".to_string()),
                    chassis_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                    port_id: Some("Gi1/0/1".to_string()),
                    port_id_subtype: Some("interface-name".to_string()),
                    ttl: Some(120),
                    port_description: None,
                    system_name: Some("edge-switch".to_string()),
                    system_description: None,
                    system_capabilities: vec!["bridge".to_string()],
                    enabled_capabilities: vec!["bridge".to_string()],
                    management_addresses: vec!["192.168.1.2".parse().unwrap()],
                }),
            )),
        });

        let [ScanEvent::DeviceUpdated(device)] = events.as_slice() else {
            panic!("expected one device update");
        };
        assert_eq!(device.ip.to_string(), "192.168.1.2");
        assert_eq!(device.interface.as_deref(), Some("en0"));
        assert_eq!(device.hostname.as_deref(), Some("edge-switch"));
        assert_eq!(
            device
                .device_type
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("switch")
        );
    }

    #[test]
    fn continuous_passive_cdp_pending_update_enriches_later_scan_device() {
        let mut manager = passive_manager();

        let events = manager.apply_passive_update(ContinuousPassiveUpdate::Observation {
            interface: "en0".to_string(),
            observation: Box::new(PassiveObservation::from_advertisement(
                discovery::l2::L2Advertisement::Cdp(discovery::cdp::CdpInfo {
                    source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                    version: 2,
                    ttl: 180,
                    device_id: Some("access-switch".to_string()),
                    addresses: Vec::new(),
                    port_id: Some("GigabitEthernet1/0/1".to_string()),
                    capabilities: vec!["switch".to_string()],
                    software_version: Some("Cisco IOS Software".to_string()),
                    platform: Some("cisco WS-C2960X".to_string()),
                    native_vlan: None,
                    duplex: None,
                    management_addresses: Vec::new(),
                }),
            )),
        });
        assert!(events.is_empty());

        let mut device = Device::new("192.168.1.44".parse().unwrap(), Utc::now());
        device.interface = Some("en0".to_string());
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        let event = manager.observe_scan_event(ScanEvent::DeviceUpdated(Box::new(device)));
        let ScanEvent::DeviceUpdated(device) = event else {
            panic!("expected device update");
        };

        assert_eq!(device.hostname.as_deref(), Some("access-switch"));
        assert_eq!(
            device.make.as_ref().map(|guess| guess.value.as_str()),
            Some("Cisco")
        );
        assert!(
            device
                .evidence
                .iter()
                .any(|item| item.source == "cdp" && item.key == "software_version")
        );
    }

    #[test]
    fn continuous_passive_replaces_same_ip_when_scan_mac_changes() {
        let mut manager = passive_manager();
        let ip = "192.168.1.44".parse().unwrap();
        let first_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let later_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();

        let mut first = Device::new(ip, first_seen);
        first.interface = Some("en0".to_string());
        first.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        first.add_name("old-host.local", "mdns", 0.9);
        let _ = manager.observe_scan_event(ScanEvent::DeviceUpdated(Box::new(first)));

        let mut replacement = Device::new(ip, later_seen);
        replacement.interface = Some("en0".to_string());
        replacement.mac = Some("00:11:22:33:44:55".to_string());
        let event = manager.observe_scan_event(ScanEvent::DeviceUpdated(Box::new(replacement)));
        let ScanEvent::DeviceUpdated(device) = event else {
            panic!("expected device update");
        };

        assert_eq!(device.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert!(device.hostname.is_none());
        assert_eq!(device.first_seen, later_seen);
        assert_eq!(device.last_seen, later_seen);
    }

    #[test]
    fn continuous_passive_duplicate_observation_refreshes_last_seen() {
        let mut manager = passive_manager();
        let advertisement = discovery::l2::L2Advertisement::Lldp(discovery::lldp::LldpInfo {
            source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            chassis_id: Some("aa:bb:cc:dd:ee:ff".to_string()),
            chassis_id_subtype: Some("mac-address".to_string()),
            chassis_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            port_id: Some("Gi1/0/1".to_string()),
            port_id_subtype: Some("interface-name".to_string()),
            ttl: Some(120),
            port_description: None,
            system_name: Some("edge-switch".to_string()),
            system_description: None,
            system_capabilities: vec!["bridge".to_string()],
            enabled_capabilities: vec!["bridge".to_string()],
            management_addresses: vec!["192.168.1.2".parse().unwrap()],
        });
        let first_seen = Utc::now();
        let later_seen = first_seen + chrono::Duration::seconds(5);

        let first =
            manager.apply_passive_update(passive_update_at(advertisement.clone(), first_seen));
        let second = manager.apply_passive_update(passive_update_at(advertisement, later_seen));

        assert_eq!(first.len(), 1);
        let [ScanEvent::DeviceUpdated(device)] = second.as_slice() else {
            panic!("expected refreshed device update");
        };
        assert_eq!(device.last_seen, later_seen);
    }

    #[test]
    fn expired_passive_observation_is_not_applied_to_later_scan_device() {
        let mut manager = passive_manager();
        let observation = PassiveObservation::from_advertisement_at(
            discovery::l2::L2Advertisement::Cdp(discovery::cdp::CdpInfo {
                source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                version: 2,
                ttl: 1,
                device_id: Some("expired-switch".to_string()),
                addresses: Vec::new(),
                port_id: Some("GigabitEthernet1/0/1".to_string()),
                capabilities: vec!["switch".to_string()],
                software_version: Some("Cisco IOS Software".to_string()),
                platform: Some("cisco WS-C2960X".to_string()),
                native_vlan: None,
                duplex: None,
                management_addresses: Vec::new(),
            }),
            Utc::now() - chrono::Duration::seconds(10),
        );
        manager
            .states
            .get_mut("en0")
            .unwrap()
            .pending_observations
            .insert(observation.key.clone(), observation);

        let mut device = Device::new("192.168.1.44".parse().unwrap(), Utc::now());
        device.interface = Some("en0".to_string());
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());

        let event = manager.observe_scan_event(ScanEvent::DeviceUpdated(Box::new(device)));
        let ScanEvent::DeviceUpdated(device) = event else {
            panic!("expected device update");
        };

        assert!(device.hostname.is_none());
        assert!(
            manager
                .states
                .get("en0")
                .unwrap()
                .pending_observations
                .is_empty()
        );
    }

    fn passive_update_at(
        advertisement: discovery::l2::L2Advertisement,
        received_at: DateTime<Utc>,
    ) -> ContinuousPassiveUpdate {
        ContinuousPassiveUpdate::Observation {
            interface: "en0".to_string(),
            observation: Box::new(PassiveObservation::from_advertisement_at(
                advertisement,
                received_at,
            )),
        }
    }

    fn passive_manager() -> ContinuousPassiveManager {
        let mut states = BTreeMap::new();
        states.insert(
            "en0".to_string(),
            ContinuousPassiveInterfaceState {
                targets: vec!["192.168.1.0/24".parse().unwrap()],
                oui: false,
                devices: BTreeMap::new(),
                pending_observations: BTreeMap::new(),
            },
        );
        ContinuousPassiveManager {
            states,
            rules: identity_rules::RuleDb::default(),
            oui_db: HashMap::new(),
        }
    }
}
