//! Deterministic live TUI demo data for README recordings.
//!
//! This example deliberately lives outside the production binary. It reuses the
//! existing live renderer but never starts a scanner, opens sockets, reads local
//! interfaces, or exposes the host network. Run it under a terminal recorder,
//! wait for the `complete` status, then send Ctrl-C to leave the TUI.

#![allow(dead_code, unused_imports)]

use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

// Pull the production renderer into this example without adding demo branches to
// the real CLI. The Makefile records this binary through a wrapper named `fing`,
// so the README GIF still shows the public command being typed.
#[path = "../src/model/mod.rs"]
mod model;
#[path = "../src/output/mod.rs"]
mod output;
#[path = "../src/scanner/types.rs"]
mod scanner;

// `output::live` references `crate::net::InterfaceInfo`; this mirror keeps the
// example self-contained while matching the fields the renderer reads.
mod net {
    use ipnet::Ipv4Net;
    use std::net::Ipv4Addr;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InterfaceInfo {
        pub name: String,
        pub ip: Ipv4Addr,
        pub netmask: Ipv4Addr,
        pub prefix: u8,
        pub network: Ipv4Net,
        pub mac: Option<String>,
    }
}

use model::Device;
use net::InterfaceInfo;
use output::{LiveInterfacePanel, MacAddressDisplay, OutputOptions};
use scanner::{ScanEvent, ScanProfile};

const TARGET_RANGES: &str = "192.0.2.0/24,198.51.100.0/24";
const SCAN_INTERFACES: &str = "en0,en7";
const QUIET_HOST_WARNING: &str = "SNMP timed out on 14 quiet hosts";

// Bursty timing is more convincing than a metronome. These base delays create
// short runs of near-immediate updates, then small gaps where the live log can
// be read. The recorder path clamps each update gap to at least one GIF frame
// so the highlighted row can visibly follow the row that just changed.
const DISCOVERY_DELAYS_MS: &[u64] = &[0, 14, 0, 38, 7, 0, 55, 18, 0, 24, 6, 0, 42, 11, 0, 65];
const ENRICHMENT_DELAYS_MS: &[u64] = &[0, 28, 8, 0, 46, 13, 0, 60];
const DEFAULT_DEMO_FRAMERATE: u64 = 24;

// Interleave Wi-Fi and Ethernet hosts so the recording looks like concurrent
// scans on en0 and en7 instead of one interface completing before the other.
const ALL_HOSTS: [usize; 32] = [
    0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23, 8, 24, 9, 25, 10, 26, 11, 27, 12, 28,
    13, 29, 14, 30, 15, 31,
];
const DHCP_HOSTS: [usize; 18] = [
    8, 16, 9, 17, 10, 18, 11, 20, 12, 22, 13, 24, 14, 26, 15, 27, 28, 31,
];
const MDNS_HOSTS: [usize; 17] = [0, 16, 1, 17, 2, 18, 3, 4, 8, 9, 10, 24, 13, 14, 15, 28, 31];
const UPNP_HOSTS: [usize; 11] = [0, 16, 2, 3, 5, 8, 10, 21, 13, 28, 31];
const SMB_HOSTS: [usize; 10] = [1, 17, 2, 6, 11, 23, 12, 14, 26, 27];
const DEEP_HOSTS: [usize; 23] = [
    0, 16, 2, 18, 5, 21, 6, 7, 8, 9, 10, 24, 11, 20, 12, 25, 13, 14, 28, 15, 23, 27, 31,
];

#[derive(Clone, Copy)]
struct DemoScene {
    phase: &'static str,
    lead_in_ms: u64,
    hosts: &'static [usize],
    delays_ms: &'static [u64],
}

struct EnrichmentScene {
    timeline: DemoScene,
    apply: fn(&mut [Device]),
}

#[derive(Clone, Copy)]
struct DemoInterfaceSeed {
    name: &'static str,
    ip: &'static str,
    netmask: &'static str,
    prefix: u8,
    network: &'static str,
    mac: &'static str,
}

impl DemoInterfaceSeed {
    fn to_interface(self) -> InterfaceInfo {
        InterfaceInfo {
            name: self.name.to_string(),
            ip: self.ip.parse().expect("valid demo interface IP"),
            netmask: self.netmask.parse().expect("valid demo netmask"),
            prefix: self.prefix,
            network: self.network.parse().expect("valid demo network"),
            mac: Some(self.mac.to_string()),
        }
    }
}

const DEMO_INTERFACES: &[DemoInterfaceSeed] = &[
    DemoInterfaceSeed {
        name: "en0",
        ip: "192.0.2.42",
        netmask: "255.255.255.0",
        prefix: 24,
        network: "192.0.2.0/24",
        mac: "02:00:5e:10:00:01",
    },
    DemoInterfaceSeed {
        name: "bridge0",
        ip: "198.51.100.10",
        netmask: "255.255.255.0",
        prefix: 24,
        network: "198.51.100.0/24",
        mac: "02:00:5e:10:00:02",
    },
    DemoInterfaceSeed {
        name: "en7",
        ip: "198.51.100.42",
        netmask: "255.255.255.0",
        prefix: 24,
        network: "198.51.100.0/24",
        mac: "02:00:5e:10:00:07",
    },
    DemoInterfaceSeed {
        name: "utun6",
        ip: "203.0.113.8",
        netmask: "255.255.255.255",
        prefix: 32,
        network: "203.0.113.8/32",
        mac: "02:00:5e:10:00:03",
    },
];

#[derive(Clone, Copy)]
enum HostIdentity {
    KnownOui {
        mac: &'static str,
        vendor: &'static str,
    },
    UnknownOui {
        mac: &'static str,
    },
    AddressOnly,
}

#[derive(Clone, Copy)]
struct DemoHost {
    ip: &'static str,
    iface: &'static str,
    identity: HostIdentity,
}

impl DemoHost {
    const fn known(
        ip: &'static str,
        iface: &'static str,
        mac: &'static str,
        vendor: &'static str,
    ) -> Self {
        Self {
            ip,
            iface,
            identity: HostIdentity::KnownOui { mac, vendor },
        }
    }

    const fn unknown_oui(ip: &'static str, iface: &'static str, mac: &'static str) -> Self {
        Self {
            ip,
            iface,
            identity: HostIdentity::UnknownOui { mac },
        }
    }

    const fn address_only(ip: &'static str, iface: &'static str) -> Self {
        Self {
            ip,
            iface,
            identity: HostIdentity::AddressOnly,
        }
    }

    fn to_device(self) -> Device {
        let mut device = Device::new(self.ip.parse().expect("valid demo device IP"), now());
        device.interface = Some(self.iface.to_string());

        match self.identity {
            HostIdentity::KnownOui { mac, vendor } => {
                device.mac = Some(mac.to_string());
                device.vendor = Some(vendor.to_string());
                device.add_evidence("arp", "reply", "received", 0.5);
                device.add_evidence("oui", "vendor", vendor, 0.55);
            }
            HostIdentity::UnknownOui { mac } => {
                device.mac = Some(mac.to_string());
                device.add_evidence("arp", "reply", "received", 0.5);
            }
            HostIdentity::AddressOnly => {
                device.add_evidence("icmp", "echo", "reply", 0.38);
                device.add_evidence("tcp", "syn_ack", "open", 0.34);
            }
        }

        device
    }
}

// Device table fixture. The two documentation ranges avoid real addresses:
// en0 uses 192.0.2.0/24 and en7 uses 198.51.100.0/24. Known OUI, unknown OUI,
// and address-only hosts are all present so Vendor/MAC/Model/Name columns have
// the same gaps a real scan usually produces.
const DEMO_HOSTS: &[DemoHost] = &[
    DemoHost::known("192.0.2.1", "en0", "02:00:5e:00:01:01", "Ubiquiti Inc."),
    DemoHost::known("192.0.2.18", "en0", "02:00:5e:00:01:12", "Apple, Inc."),
    DemoHost::known("192.0.2.27", "en0", "02:00:5e:00:01:1b", "Synology Inc."),
    DemoHost::known(
        "192.0.2.31",
        "en0",
        "02:00:5e:00:01:1f",
        "Amazon Technologies Inc.",
    ),
    DemoHost::known(
        "192.0.2.44",
        "en0",
        "02:00:5e:00:01:2c",
        "Nintendo Co., Ltd.",
    ),
    DemoHost::unknown_oui("192.0.2.63", "en0", "6a:cb:05:15:4c:63"),
    DemoHost::unknown_oui("192.0.2.79", "en0", "7e:24:9b:60:01:79"),
    DemoHost::known(
        "192.0.2.120",
        "en0",
        "02:00:5e:00:01:78",
        "Brother Industries",
    ),
    DemoHost::known(
        "192.0.2.134",
        "en0",
        "02:00:5e:00:01:86",
        "Samsung Electronics Co., Ltd.",
    ),
    DemoHost::known("192.0.2.141", "en0", "02:00:5e:00:01:8d", "Google LLC"),
    DemoHost::known(
        "192.0.2.150",
        "en0",
        "02:00:5e:00:01:96",
        "Signify Netherlands B.V.",
    ),
    DemoHost::known("192.0.2.166", "en0", "02:00:5e:00:01:a6", "Dell Inc."),
    DemoHost::unknown_oui("192.0.2.177", "en0", "5a:7d:3c:91:10:b1"),
    DemoHost::known("192.0.2.188", "en0", "02:00:5e:00:01:bc", "Sonos, Inc."),
    DemoHost::unknown_oui("192.0.2.202", "en0", "72:4f:e8:2a:4d:ca"),
    DemoHost::known(
        "192.0.2.214",
        "en0",
        "02:00:5e:00:01:d6",
        "Valve Corporation",
    ),
    DemoHost::known(
        "198.51.100.1",
        "en7",
        "02:00:5e:00:02:01",
        "Cisco Systems, Inc.",
    ),
    DemoHost::known("198.51.100.12", "en7", "02:00:5e:00:02:0c", "Apple, Inc."),
    DemoHost::known(
        "198.51.100.25",
        "en7",
        "02:00:5e:00:02:19",
        "QNAP Systems, Inc.",
    ),
    DemoHost::address_only("198.51.100.38", "en7"),
    DemoHost::known("198.51.100.51", "en7", "02:00:5e:00:02:33", "Canon Inc."),
    DemoHost::unknown_oui("198.51.100.66", "en7", "6e:12:8d:31:42:66"),
    DemoHost::known(
        "198.51.100.74",
        "en7",
        "02:00:5e:00:02:4a",
        "TP-Link Technologies Co., Ltd.",
    ),
    DemoHost::unknown_oui("198.51.100.89", "en7", "4a:43:c4:c9:79:f0"),
    DemoHost::known(
        "198.51.100.104",
        "en7",
        "02:00:5e:00:02:68",
        "Axis Communications AB",
    ),
    DemoHost::unknown_oui("198.51.100.119", "en7", "de:ad:4e:23:4a:77"),
    DemoHost::known(
        "198.51.100.132",
        "en7",
        "02:00:5e:00:02:84",
        "APC by Schneider Electric",
    ),
    DemoHost::known(
        "198.51.100.145",
        "en7",
        "02:00:5e:00:02:91",
        "Super Micro Computer, Inc.",
    ),
    DemoHost::known(
        "198.51.100.156",
        "en7",
        "02:00:5e:00:02:9c",
        "Yamaha Corporation",
    ),
    DemoHost::address_only("198.51.100.171", "en7"),
    DemoHost::unknown_oui("198.51.100.188", "en7", "ba:39:20:4b:09:8a"),
    DemoHost::known(
        "198.51.100.205",
        "en7",
        "02:00:5e:00:02:cd",
        "NVIDIA Corporation",
    ),
];

const DISCOVERY_SCENE: DemoScene = DemoScene {
    phase: "en0/en7 ARP discovery",
    lead_in_ms: 0,
    hosts: &ALL_HOSTS,
    delays_ms: DISCOVERY_DELAYS_MS,
};

// VHS scenes after the first table fill:
//
// 1. OUI replay keeps known vendors visible while unknown OUIs stay blank.
// 2. DHCP/mDNS/UPnP/SMB progressively fill Name, Model, OS, and Sources.
// 3. Deep probes add late HTTP/TLS/SNMP hints and leave some rows unresolved.
const ENRICHMENT_SCENES: &[EnrichmentScene] = &[
    EnrichmentScene {
        timeline: DemoScene {
            phase: "parallel OUI vendor enrichment",
            lead_in_ms: 90,
            hosts: &ALL_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: retain_oui_state,
    },
    EnrichmentScene {
        timeline: DemoScene {
            phase: "DHCP lease enrichment",
            lead_in_ms: 90,
            hosts: &DHCP_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: enrich_dhcp,
    },
    EnrichmentScene {
        timeline: DemoScene {
            phase: "mDNS/Bonjour enrichment",
            lead_in_ms: 120,
            hosts: &MDNS_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: enrich_mdns,
    },
    EnrichmentScene {
        timeline: DemoScene {
            phase: "UPnP/SSDP enrichment",
            lead_in_ms: 110,
            hosts: &UPNP_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: enrich_upnp,
    },
    EnrichmentScene {
        timeline: DemoScene {
            phase: "NetBIOS and SMB fingerprinting",
            lead_in_ms: 120,
            hosts: &SMB_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: enrich_smb,
    },
    EnrichmentScene {
        timeline: DemoScene {
            phase: "HTTP/TLS and SNMP fingerprinting",
            lead_in_ms: 130,
            hosts: &DEEP_HOSTS,
            delays_ms: ENRICHMENT_DELAYS_MS,
        },
        apply: enrich_deep,
    },
];

#[tokio::main]
async fn main() -> std::io::Result<()> {
    crossterm::style::force_color_output(true);

    let (tx, rx) = mpsc::unbounded_channel();
    let (pause_tx, _pause_rx) = watch::channel(false);
    let panel = demo_interfaces();

    tokio::spawn(async move {
        if let Err(err) = send_demo_events(tx).await {
            eprintln!("demo event stream stopped: {err}");
        }
    });

    output::run_live_table(
        rx,
        pause_tx,
        OutputOptions {
            mac: MacAddressDisplay::Full,
        },
        panel,
    )
    .await
    .map(|_| ())
}

async fn send_demo_events(tx: mpsc::UnboundedSender<ScanEvent>) -> Result<(), &'static str> {
    // Scene 0: draw the TUI chrome, mark en0/en7 as active scan targets, and
    // give VHS a short beat after Enter before rows begin to stream in.
    send(
        &tx,
        ScanEvent::Started {
            target: TARGET_RANGES.to_string(),
            interface: SCAN_INTERFACES.to_string(),
            profile: ScanProfile::Normal,
        },
    )?;
    pause(140).await;

    let mut devices = demo_devices();

    // Scene 1: fill the device table quickly from ARP/ICMP/TCP observations.
    // The first view is intentionally sparse: many rows have only IP/MAC/vendor.
    play_scene(&tx, &devices, DISCOVERY_SCENE).await?;

    for scene in ENRICHMENT_SCENES {
        // Scenes 2..7: replay only the hosts touched by the current probe family
        // so the GIF shows identity columns filling in over time.
        (scene.apply)(&mut devices);
        play_scene(&tx, &devices, scene.timeline).await?;
    }

    // Final scene: keep one realistic warning in the log, then leave the table
    // on a stable `complete` frame for README viewers.
    send(&tx, ScanEvent::Warning(QUIET_HOST_WARNING.to_string()))?;
    pause(160).await;
    send(
        &tx,
        ScanEvent::Finished {
            devices,
            warnings: vec![QUIET_HOST_WARNING.to_string()],
        },
    )?;

    Ok(())
}

async fn play_scene(
    tx: &mpsc::UnboundedSender<ScanEvent>,
    devices: &[Device],
    scene: DemoScene,
) -> Result<(), &'static str> {
    send(tx, ScanEvent::Phase(scene.phase.to_string()))?;
    pause(scene.lead_in_ms).await;
    send_device_updates(tx, devices, scene.hosts.iter().copied(), scene.delays_ms).await
}

fn demo_interfaces() -> LiveInterfacePanel {
    // Interface panel scene: show both scan targets plus ordinary non-scanned
    // interfaces so the GIF reads like a real workstation, not a fixture dump.
    LiveInterfacePanel {
        interfaces: DEMO_INTERFACES
            .iter()
            .copied()
            .map(DemoInterfaceSeed::to_interface)
            .collect(),
        default_interface: Some("en0".to_string()),
        scan_interfaces: vec!["en0".to_string(), "en7".to_string()],
    }
}

fn demo_devices() -> Vec<Device> {
    DEMO_HOSTS
        .iter()
        .copied()
        .map(DemoHost::to_device)
        .collect()
}

fn retain_oui_state(_: &mut [Device]) {
    // OUI was attached when the ARP observations were built. This scene exists
    // to keep the live log moving while preserving the intentionally unknown
    // Vendor cells.
}

// The enrichment functions below mutate accumulated evidence only. The scene
// table decides which changed hosts are replayed, making the visible GIF flow
// easy to tune without touching the fixture data itself.
fn enrich_dhcp(devices: &mut [Device]) {
    devices[8].add_name("living-room-tv", "dhcp", 0.72);
    devices[8].set_device_type_guess("smart tv", "dhcp", 0.66);

    devices[9].add_name("kitchen-display", "dhcp", 0.72);
    devices[9].set_device_type_guess("smart display", "dhcp", 0.66);

    devices[10].add_name("hue-bridge", "dhcp", 0.74);
    devices[10].set_device_type_guess("smart-home hub", "dhcp", 0.68);

    devices[11].add_name("finance-ws", "dhcp", 0.72);
    devices[11].set_device_type_guess("workstation", "dhcp", 0.64);

    devices[12].add_name("front-door-cam", "dhcp", 0.72);
    devices[12].set_device_type_guess("camera", "dhcp", 0.66);

    devices[13].add_name("sonos-arc", "dhcp", 0.72);
    devices[13].set_device_type_guess("speaker", "dhcp", 0.64);

    devices[14].add_name("home-assistant", "dhcp", 0.72);
    devices[14].set_device_type_guess("automation controller", "dhcp", 0.66);

    devices[15].add_name("steamdeck", "dhcp", 0.70);
    devices[15].set_device_type_guess("handheld console", "dhcp", 0.64);

    devices[16].add_name("core-switch", "dhcp", 0.70);
    devices[16].set_device_type_guess("switch", "dhcp", 0.64);

    devices[17].add_name("design-imac", "dhcp", 0.72);
    devices[17].set_device_type_guess("desktop", "dhcp", 0.64);

    devices[18].add_name("backup-qnap", "dhcp", 0.72);
    devices[18].set_device_type_guess("nas", "dhcp", 0.66);

    devices[20].add_name("copy-room-canon", "dhcp", 0.70);
    devices[20].set_device_type_guess("printer", "dhcp", 0.64);

    devices[22].add_name("garage-ap", "dhcp", 0.70);
    devices[22].set_device_type_guess("access point", "dhcp", 0.64);

    devices[24].add_name("loading-dock-cam", "dhcp", 0.70);
    devices[24].set_device_type_guess("camera", "dhcp", 0.64);

    devices[26].add_name("ups-rack", "dhcp", 0.70);
    devices[26].set_device_type_guess("ups", "dhcp", 0.64);

    devices[27].add_name("build-server", "dhcp", 0.70);
    devices[27].set_device_type_guess("server", "dhcp", 0.64);

    devices[28].add_name("musiccast-avr", "dhcp", 0.70);
    devices[28].set_device_type_guess("receiver", "dhcp", 0.64);

    devices[31].add_name("shield-tv", "dhcp", 0.70);
    devices[31].set_device_type_guess("streaming box", "dhcp", 0.64);
}

fn enrich_mdns(devices: &mut [Device]) {
    devices[0].add_name("gateway.local", "mdns", 0.88);
    devices[0].set_device_type_guess("router", "mdns", 0.70);

    devices[1].add_name("maya-macbook.local", "mdns", 0.94);
    devices[1].set_make_guess("Apple", "mdns", 0.84);
    devices[1].set_model_guess("MacBook Pro", "mdns", 0.82);
    devices[1].set_os_guess("macOS", "mdns", 0.80);

    devices[2].add_name("studio-nas.local", "mdns", 0.91);
    devices[2].set_device_type_guess("nas", "mdns", 0.76);

    devices[3].add_name("living-room-echo.local", "mdns", 0.86);
    devices[3].set_device_type_guess("smart speaker", "mdns", 0.72);

    devices[4].add_name("switch.local", "mdns", 0.82);
    devices[4].set_device_type_guess("game console", "mdns", 0.70);

    devices[8].add_name("living-room-tv.local", "mdns", 0.84);
    devices[8].set_make_guess("Samsung", "mdns", 0.76);
    devices[8].set_model_guess("QN90C", "mdns", 0.74);
    devices[8].set_os_guess("Tizen", "mdns", 0.72);

    devices[9].add_name("kitchen-display.local", "mdns", 0.84);
    devices[9].set_make_guess("Google", "mdns", 0.78);
    devices[9].set_model_guess("Nest Hub", "mdns", 0.76);

    devices[10].add_name("hue-bridge.local", "mdns", 0.82);
    devices[10].set_make_guess("Philips Hue", "mdns", 0.76);
    devices[10].set_model_guess("Bridge v2", "mdns", 0.74);

    devices[13].add_name("sonos-arc.local", "mdns", 0.82);
    devices[13].set_make_guess("Sonos", "mdns", 0.78);
    devices[13].set_model_guess("Arc", "mdns", 0.76);

    devices[14].add_name("home-assistant.local", "mdns", 0.82);
    devices[14].set_os_guess("Linux", "mdns", 0.72);

    devices[15].add_name("steamdeck.local", "mdns", 0.80);
    devices[15].set_make_guess("Valve", "mdns", 0.74);
    devices[15].set_model_guess("Steam Deck", "mdns", 0.72);
    devices[15].set_os_guess("SteamOS", "mdns", 0.70);

    devices[16].add_name("core-switch.local", "mdns", 0.78);
    devices[16].set_make_guess("Cisco", "mdns", 0.70);

    devices[17].add_name("design-imac.local", "mdns", 0.90);
    devices[17].set_make_guess("Apple", "mdns", 0.82);
    devices[17].set_model_guess("iMac", "mdns", 0.78);
    devices[17].set_os_guess("macOS", "mdns", 0.78);

    devices[18].add_name("backup-qnap.local", "mdns", 0.86);
    devices[18].set_make_guess("QNAP", "mdns", 0.78);
    devices[18].set_model_guess("TS-464", "mdns", 0.76);

    devices[24].add_name("loading-dock-cam.local", "mdns", 0.76);
    devices[24].set_make_guess("Axis", "mdns", 0.72);

    devices[28].add_name("musiccast-avr.local", "mdns", 0.80);
    devices[28].set_make_guess("Yamaha", "mdns", 0.74);
    devices[28].set_model_guess("RX-V6A", "mdns", 0.72);

    devices[31].add_name("shield-tv.local", "mdns", 0.78);
    devices[31].set_make_guess("NVIDIA", "mdns", 0.72);
    devices[31].set_model_guess("SHIELD TV", "mdns", 0.70);
    devices[31].set_os_guess("Android TV", "mdns", 0.68);
}

fn enrich_upnp(devices: &mut [Device]) {
    devices[0].set_model_guess("Dream Router", "upnp", 0.88);
    devices[0].add_service("ssdp", "upnp", Some(1900), 0.70);
    devices[0].add_evidence("upnp", "presentation_url", "http://192.0.2.1/", 0.72);

    devices[2].set_make_guess("Synology", "upnp", 0.86);
    devices[2].set_model_guess("DS923+", "upnp", 0.86);
    devices[2].add_service("upnp", "upnp", Some(5000), 0.72);

    devices[3].set_make_guess("Amazon", "upnp", 0.78);
    devices[3].set_model_guess("Echo Studio", "upnp", 0.78);
    devices[3].add_service("alexa", "upnp", Some(4070), 0.68);

    devices[5].add_name("living-room-playstation", "upnp", 0.82);
    devices[5].set_make_guess("Sony", "upnp", 0.82);
    devices[5].set_model_guess("PlayStation 5", "upnp", 0.80);
    devices[5].set_device_type_guess("game console", "upnp", 0.76);

    devices[8].set_model_guess("QN90C", "upnp", 0.82);
    devices[8].add_service("dlna", "upnp", Some(8001), 0.72);
    devices[8].add_evidence("upnp", "manufacturer", "Samsung", 0.74);

    devices[10].set_make_guess("Philips Hue", "upnp", 0.82);
    devices[10].set_model_guess("Hue Bridge", "upnp", 0.82);
    devices[10].add_service("hue-api", "upnp", Some(80), 0.72);

    devices[13].set_make_guess("Sonos", "upnp", 0.82);
    devices[13].set_model_guess("Arc", "upnp", 0.82);
    devices[13].add_service("sonos", "upnp", Some(1400), 0.72);

    devices[16].set_model_guess("Catalyst 1000", "upnp", 0.70);
    devices[16].add_service("ssdp", "upnp", Some(1900), 0.58);

    devices[21].set_make_guess("Roku", "upnp", 0.76);
    devices[21].set_model_guess("Ultra", "upnp", 0.72);
    devices[21].add_service("ecp", "upnp", Some(8060), 0.70);

    devices[28].set_make_guess("Yamaha", "upnp", 0.78);
    devices[28].set_model_guess("MusicCast Receiver", "upnp", 0.76);
    devices[28].add_service("musiccast", "upnp", Some(49152), 0.70);

    devices[31].set_make_guess("NVIDIA", "upnp", 0.76);
    devices[31].set_model_guess("SHIELD Android TV", "upnp", 0.74);
    devices[31].add_service("cast", "upnp", Some(8008), 0.66);
}

fn enrich_smb(devices: &mut [Device]) {
    devices[1].add_service("smb", "smb", Some(445), 0.65);
    devices[1].add_evidence("smb", "signing", "required", 0.60);

    devices[2].add_name("STUDIO-NAS", "netbios", 0.88);
    devices[2].set_os_guess("DSM", "smb", 0.82);
    devices[2].add_service("smb", "smb", Some(445), 0.78);
    devices[2].add_evidence("smb", "server", "Synology NAS", 0.80);

    devices[6].add_name("workbench-pi", "netbios", 0.76);
    devices[6].set_make_guess("Raspberry Pi", "netbios", 0.70);
    devices[6].set_os_guess("Linux", "netbios", 0.68);
    devices[6].set_device_type_guess("single-board computer", "netbios", 0.66);

    devices[11].add_name("FINANCE-WS", "netbios", 0.88);
    devices[11].set_make_guess("Dell", "smb", 0.78);
    devices[11].set_model_guess("OptiPlex", "smb", 0.72);
    devices[11].set_os_guess("Windows 11", "smb", 0.82);
    devices[11].add_service("smb", "smb", Some(445), 0.78);
    devices[11].add_evidence("smb", "server", "Windows workstation", 0.76);

    devices[12].add_name("FRONT-CAM", "netbios", 0.62);

    devices[14].add_name("HOMEASSISTANT", "netbios", 0.68);
    devices[14].add_service("smb", "smb", Some(445), 0.58);

    devices[17].add_service("smb", "smb", Some(445), 0.62);
    devices[17].add_evidence("smb", "signing", "required", 0.58);

    devices[18].add_name("BACKUP-QNAP", "netbios", 0.82);
    devices[18].set_os_guess("QTS", "smb", 0.78);
    devices[18].add_service("smb", "smb", Some(445), 0.76);
    devices[18].add_evidence("smb", "server", "QNAP NAS", 0.76);

    devices[23].add_service("smb", "smb", Some(445), 0.58);
    devices[23].set_os_guess("Windows", "smb", 0.62);

    devices[27].add_name("BUILD-SERVER", "netbios", 0.74);
    devices[27].set_os_guess("Linux/SMB capable", "smb", 0.66);
    devices[27].add_service("smb", "smb", Some(445), 0.66);
}

fn enrich_deep(devices: &mut [Device]) {
    devices[0].add_service("https", "tls", Some(443), 0.78);
    devices[0].add_evidence("tls", "issuer", "Ubiquiti Local CA", 0.72);

    devices[2].add_service("http", "http", Some(5000), 0.72);
    devices[2].add_service("https", "tls", Some(5001), 0.75);
    devices[2].add_evidence("http", "title", "Synology DiskStation", 0.82);

    devices[5].add_service("http", "http", Some(80), 0.55);
    devices[5].add_evidence("http", "server", "Sony Device Server", 0.62);

    devices[6].add_service("ssh", "deep", Some(22), 0.72);
    devices[6].add_service("http", "http", Some(8080), 0.62);
    devices[6].add_evidence("snmp", "sys_descr", "Linux workbench-pi", 0.68);

    devices[7].add_name("office-printer.local", "mdns", 0.88);
    devices[7].set_make_guess("Brother", "snmp", 0.80);
    devices[7].set_model_guess("HL-L2370DW", "snmp", 0.78);
    devices[7].set_device_type_guess("printer", "snmp", 0.80);
    devices[7].add_service("ipp", "mdns", Some(631), 0.78);
    devices[7].add_evidence("snmp", "sys_name", "office-printer", 0.78);

    devices[8].add_service("http", "http", Some(8001), 0.68);
    devices[8].add_service("https", "tls", Some(8002), 0.68);
    devices[8].add_evidence("http", "server", "Samsung Smart TV", 0.72);

    devices[9].add_service("cast", "mdns", Some(8008), 0.76);
    devices[9].add_service("https", "tls", Some(8443), 0.62);
    devices[9].add_evidence("http", "title", "Google Cast", 0.74);

    devices[10].add_service("http", "http", Some(80), 0.76);
    devices[10].add_evidence("http", "title", "Philips Hue Bridge", 0.80);

    devices[11].add_service("rdp", "deep", Some(3389), 0.66);
    devices[11].add_evidence("tls", "subject", "finance-ws", 0.66);

    devices[12].set_make_guess("Hikvision", "http", 0.78);
    devices[12].set_model_guess("DS-2CD", "http", 0.70);
    devices[12].set_device_type_guess("camera", "http", 0.76);
    devices[12].add_service("rtsp", "deep", Some(554), 0.72);
    devices[12].add_service("http", "http", Some(80), 0.70);
    devices[12].add_evidence("http", "title", "IP Camera", 0.72);

    devices[13].add_service("http", "http", Some(1400), 0.72);
    devices[13].add_evidence("http", "server", "Sonos ZonePlayer", 0.74);

    devices[14].add_service("ssh", "deep", Some(22), 0.70);
    devices[14].add_service("http", "http", Some(8123), 0.80);
    devices[14].add_evidence("http", "title", "Home Assistant", 0.82);

    devices[15].add_service("ssh", "deep", Some(22), 0.64);
    devices[15].add_evidence("deep", "banner", "SteamOS", 0.66);

    devices[16].add_service("https", "tls", Some(443), 0.66);
    devices[16].add_evidence("tls", "issuer", "Cisco Local CA", 0.62);

    devices[18].add_service("http", "http", Some(8080), 0.72);
    devices[18].add_service("https", "tls", Some(443), 0.72);
    devices[18].add_evidence("http", "title", "QNAP Turbo NAS", 0.78);

    devices[20].set_make_guess("Canon", "snmp", 0.76);
    devices[20].set_model_guess("imageCLASS", "snmp", 0.68);
    devices[20].add_service("ipp", "deep", Some(631), 0.70);
    devices[20].add_service("http", "http", Some(80), 0.62);

    devices[21].add_service("http", "http", Some(8060), 0.70);
    devices[21].add_evidence("http", "server", "Roku ECP", 0.72);

    devices[23].add_service("rdp", "deep", Some(3389), 0.58);
    devices[23].add_evidence("tls", "subject", "unknown-windows", 0.54);

    devices[24].set_make_guess("Axis", "http", 0.76);
    devices[24].set_model_guess("M3065-V", "http", 0.70);
    devices[24].add_service("rtsp", "deep", Some(554), 0.70);
    devices[24].add_service("http", "http", Some(80), 0.66);

    devices[25].add_service("ipp", "deep", Some(631), 0.60);
    devices[25].add_service("http", "http", Some(80), 0.56);
    devices[25].add_evidence("http", "server", "printer web ui", 0.54);

    devices[27].add_service("ssh", "deep", Some(22), 0.70);
    devices[27].add_service("https", "tls", Some(8443), 0.62);
    devices[27].add_evidence("tls", "subject", "build-server", 0.62);

    devices[28].add_service("http", "http", Some(80), 0.64);
    devices[28].add_evidence("http", "title", "MusicCast Controller", 0.70);

    devices[31].add_service("https", "tls", Some(8443), 0.60);
    devices[31].add_evidence("http", "server", "Android TV", 0.62);
}

fn send(tx: &mpsc::UnboundedSender<ScanEvent>, event: ScanEvent) -> Result<(), &'static str> {
    tx.send(event).map_err(|_| "receiver closed")
}

async fn send_device_updates<I>(
    tx: &mpsc::UnboundedSender<ScanEvent>,
    devices: &[Device],
    indices: I,
    delays_ms: &[u64],
) -> Result<(), &'static str>
where
    I: IntoIterator<Item = usize>,
{
    for (offset, index) in indices.into_iter().enumerate() {
        let device = devices.get(index).ok_or("demo device index out of range")?;
        send(tx, ScanEvent::DeviceUpdated(Box::new(device.clone())))?;
        let delay = delays_ms
            .get(offset % delays_ms.len())
            .copied()
            .unwrap_or(0);
        pause_update_gap(delay).await;
    }
    Ok(())
}

async fn pause_update_gap(base_milliseconds: u64) {
    let scaled_milliseconds = base_milliseconds.saturating_mul(demo_delay_scale());
    let milliseconds = scaled_milliseconds.max(demo_frame_milliseconds());
    tokio::time::sleep(Duration::from_millis(milliseconds)).await;
}

async fn pause(milliseconds: u64) {
    tokio::time::sleep(Duration::from_millis(
        milliseconds.saturating_mul(demo_delay_scale()),
    ))
    .await;
}

fn demo_delay_scale() -> u64 {
    // `make vhs` sets this to slow only the TUI scan portion. Command typing
    // remains at normal VHS speed because the delay is applied inside the demo.
    std::env::var("FING_DEMO_DELAY_SCALE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|scale| *scale > 0)
        .unwrap_or(1)
}

fn demo_frame_milliseconds() -> u64 {
    let frames_per_second = std::env::var("FING_DEMO_FRAMERATE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|framerate| *framerate > 0)
        .unwrap_or(DEFAULT_DEMO_FRAMERATE);
    1000_u64.div_ceil(frames_per_second).max(1)
}

fn now() -> DateTime<Utc> {
    Utc::now()
}
