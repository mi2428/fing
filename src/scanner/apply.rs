//! Evidence-to-device merge helpers for scanner phases.
//!
//! Protocol collectors return small, protocol-shaped records. This module is
//! the boundary where those records become the common `Device` model: raw
//! evidence is preserved, best guesses are updated by confidence, and services
//! are attached without letting one protocol erase another.

use crate::{
    dhcp,
    discovery::{cdp, lldp},
    enrich,
    model::Device,
    probes::{deep, smb, snmp, upnp},
};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

pub(super) fn apply_mdns_info(device: &mut Device, mdns: enrich::MdnsInfo) {
    // mDNS is usually name-rich and often model-rich. Store the raw model as
    // evidence before promoting it so identity rules can still inspect it even
    // if another source later wins the best-guess slot.
    for name in mdns.names {
        device.add_name(name, "mdns", 0.9);
    }
    if let Some(model) = mdns.model {
        device.add_evidence("mdns", "model", model.clone(), 0.85);
        device.set_model_guess(model.clone(), "mdns", 0.85);
        device.set_device_type_guess(model, "mdns", 0.65);
    }
    if let Some(os) = mdns.os {
        device.set_os_guess(os, "mdns", 0.85);
    }
    for service in mdns.services {
        device.add_service(service.name, "mdns", service.port, 0.75);
    }
}

pub(super) fn apply_upnp_info(device: &mut Device, info: upnp::UpnpInfo) {
    // UPnP descriptions provide both human labels and structured device types.
    // Keep the raw URN in evidence and expose the friendly type as the guess.
    for name in info.names {
        device.add_name(name, "upnp", 0.85);
    }
    if let Some(manufacturer) = info.manufacturer {
        device.set_make_guess(manufacturer.clone(), "upnp", 0.8);
        device.add_evidence("upnp", "manufacturer", manufacturer, 0.8);
    }
    if let Some(model) = info.model {
        device.set_model_guess(model.clone(), "upnp", 0.85);
        device.add_evidence("upnp", "model", model.clone(), 0.85);
        device.set_device_type_guess(model, "upnp", 0.6);
    }
    if let Some(device_type) = info.device_type {
        let friendly = upnp::friendly_device_type(&device_type);
        device.add_evidence("upnp", "device_type", device_type, 0.8);
        device.set_device_type_guess(friendly, "upnp", 0.75);
    }
    if let Some(server) = info.server {
        device.add_evidence("upnp", "server", server.clone(), 0.65);
        if let Some((hint, confidence)) = deep::os_hint_from_banner("http", &server) {
            device.set_os_guess(hint, "upnp", confidence);
        }
    }
    if let Some(location) = info.location {
        device.add_evidence("upnp", "location", location, 0.55);
    }
    for usn in info.usns {
        device.add_evidence("upnp", "usn", usn, 0.55);
    }
    for service in info.services {
        device.add_service(service, "upnp", None, 0.7);
    }
}

pub(super) fn apply_deep_probes(
    device: &mut Device,
    probes: Vec<deep::PortProbe>,
    options: deep::ProbeOptions,
) {
    for probe in probes {
        if options.deep {
            // An open port is weak identity by itself, but it is still useful as
            // a service signal and as input to built-in identity rules.
            device.add_service(probe.service.clone(), "deep", Some(probe.port), 0.7);
            if let Some((device_type, confidence)) = deep::device_type_hint_from_port(probe.port) {
                device.set_device_type_guess(device_type, "deep", confidence);
            }
            if probe.port == 445 || probe.port == 139 {
                device.set_os_guess("Windows/SMB capable", "deep", 0.45);
            }
            if let Some(banner) = &probe.banner {
                device.add_evidence(
                    "deep",
                    &format!("{}_banner", probe.service),
                    banner.clone(),
                    0.75,
                );
                if let Some(server) = deep::http_server_from_banner(banner) {
                    device.add_evidence("deep", "http_server", server, 0.7);
                }
                if let Some((os, confidence)) = deep::os_hint_from_banner(&probe.service, banner) {
                    device.set_os_guess(os, "deep", confidence);
                }
            }
        }

        if options.http {
            // HTTP headers get their own source because they often outlive the
            // generic TCP probe in exports and rule matching.
            for header in probe.http_headers {
                let key = deep::header_evidence_key(&header.name);
                device.add_evidence("http", &key, header.value.clone(), 0.75);
                if header.name == "server" {
                    device.add_evidence("http", "http_server", header.value.clone(), 0.75);
                    if let Some((os, confidence)) = deep::os_hint_from_banner("http", &header.value)
                    {
                        device.set_os_guess(os, "http", confidence);
                    }
                }
            }
            if let Some(favicon) = probe.favicon {
                device.add_evidence("http", "favicon_sha256", favicon.sha256, 0.72);
                device.add_evidence("http", "favicon_url", favicon.url, 0.55);
                device.add_evidence("http", "favicon_bytes", favicon.bytes.to_string(), 0.5);
            }
        }

        if options.tls
            && let Some(tls) = probe.tls
        {
            device.add_evidence("tls", "tls_cert_sha256", tls.sha256, 0.72);
            if let Some(subject) = tls.subject {
                device.add_evidence("tls", "tls_subject", subject, 0.7);
            }
            if let Some(issuer) = tls.issuer {
                device.add_evidence("tls", "tls_issuer", issuer, 0.65);
            }
            if let Some(not_after) = tls.not_after {
                device.add_evidence("tls", "tls_not_after", not_after, 0.55);
            }
        }
    }
}

pub(super) fn apply_dhcp_lease(
    device: &mut Device,
    lease: dhcp::DhcpLease,
    oui_db: Option<&HashMap<String, String>>,
) {
    // DHCP is passive and sometimes stale. It can fill missing MAC/vendor/name
    // fields, but it must not replace direct ARP or protocol evidence.
    let lease_mac = lease.mac;
    if let Some(mac) = lease_mac.as_ref() {
        if device.mac.is_none() {
            device.mac = Some(mac.clone());
        }
        device.add_evidence("dhcp", "mac", mac.clone(), 0.55);
    }
    let vendor_mac = device.mac.as_deref().or(lease_mac.as_deref());
    if device.vendor.is_none()
        && let (Some(mac), Some(oui_db)) = (vendor_mac, oui_db)
    {
        device.vendor = enrich::lookup_vendor(mac, oui_db);
    }
    if let Some(hostname) = lease.hostname {
        device.add_name(hostname, "dhcp", 0.72);
    }
    if let Some(client_id) = lease.client_id {
        device.add_evidence("dhcp", "client_id", client_id, 0.55);
    }
    if let Some(vendor_class) = lease.vendor_class {
        device.add_evidence("dhcp", "vendor_class", vendor_class, 0.65);
    }
    if let Some(source) = lease.source {
        device.add_evidence("dhcp", "lease_source", source.display().to_string(), 0.35);
    }
}

pub(super) fn apply_snmp_info(device: &mut Device, info: snmp::SnmpInfo) {
    // SNMP system group fields are high-signal for routers, switches, printers,
    // and NAS devices. Preserve every field so site-specific rules can refine
    // classification later.
    device.add_service("snmp", "snmp", Some(161), 0.75);
    if let Some(sys_name) = info.sys_name {
        device.add_name(sys_name.clone(), "snmp", 0.82);
        device.add_evidence("snmp", "sysName", sys_name, 0.82);
    }
    if let Some(description) = info.sys_descr {
        device.add_evidence("snmp", "sysDescr", description.clone(), 0.9);
        device.set_os_guess(description, "snmp", 0.85);
    }
    if let Some(object_id) = info.sys_object_id {
        device.add_evidence("snmp", "sysObjectID", object_id, 0.85);
    }
    if let Some(sys_services) = info.sys_services {
        device.add_evidence("snmp", "sysServices", sys_services.to_string(), 0.75);
        if sys_services & 0b100 != 0 {
            device.set_device_type_guess("network-device", "snmp", 0.55);
        }
    }
    if let Some(contact) = info.sys_contact {
        device.add_evidence("snmp", "sysContact", contact, 0.45);
    }
    if let Some(location) = info.sys_location {
        device.add_evidence("snmp", "sysLocation", location, 0.45);
    }
}

pub(super) fn apply_lldp_info(
    device: &mut Device,
    info: lldp::LldpInfo,
    oui_db: Option<&HashMap<String, String>>,
) {
    device.add_service("lldp", "lldp", None, 0.72);
    if device.mac.is_none() {
        device.mac = info.chassis_mac.clone().or(Some(info.source_mac.clone()));
    }
    if device.vendor.is_none()
        && let (Some(mac), Some(oui_db)) = (&device.mac, oui_db)
    {
        device.vendor = enrich::lookup_vendor(mac, oui_db);
    }

    device.add_evidence("lldp", "source_mac", info.source_mac, 0.76);
    if let Some(chassis_id) = info.chassis_id {
        device.add_evidence("lldp", "chassis_id", chassis_id, 0.82);
    }
    if let Some(chassis_id_subtype) = info.chassis_id_subtype {
        device.add_evidence("lldp", "chassis_id_subtype", chassis_id_subtype, 0.62);
    }
    if let Some(chassis_mac) = info.chassis_mac {
        device.add_evidence("lldp", "chassis_mac", chassis_mac, 0.82);
    }
    if let Some(port_id) = info.port_id {
        device.add_evidence("lldp", "port_id", port_id, 0.7);
    }
    if let Some(port_id_subtype) = info.port_id_subtype {
        device.add_evidence("lldp", "port_id_subtype", port_id_subtype, 0.55);
    }
    if let Some(ttl) = info.ttl {
        device.add_evidence("lldp", "ttl", ttl.to_string(), 0.45);
    }
    if let Some(port_description) = info.port_description {
        device.add_evidence("lldp", "port_description", port_description, 0.65);
    }
    if let Some(system_name) = info.system_name {
        device.add_name(system_name.clone(), "lldp", 0.88);
        device.add_evidence("lldp", "system_name", system_name, 0.88);
    }
    if let Some(system_description) = info.system_description {
        device.add_evidence(
            "lldp",
            "system_description",
            system_description.clone(),
            0.9,
        );
        device.set_os_guess(system_description, "lldp", 0.82);
    }
    for capability in &info.system_capabilities {
        device.add_evidence("lldp", "system_capability", capability.as_str(), 0.7);
    }
    for capability in &info.enabled_capabilities {
        device.add_evidence("lldp", "enabled_capability", capability.as_str(), 0.82);
    }
    for address in info.management_addresses {
        device.add_evidence("lldp", "management_address", address.to_string(), 0.84);
    }

    if info
        .enabled_capabilities
        .iter()
        .any(|capability| capability == "wlan-access-point")
    {
        device.set_device_type_guess("wireless-ap", "lldp", 0.88);
    } else if info
        .enabled_capabilities
        .iter()
        .any(|capability| capability == "router")
    {
        device.set_device_type_guess("router", "lldp", 0.86);
    } else if info
        .enabled_capabilities
        .iter()
        .any(|capability| capability == "bridge")
    {
        device.set_device_type_guess("switch", "lldp", 0.86);
    } else if !info.enabled_capabilities.is_empty() {
        device.set_device_type_guess("network-device", "lldp", 0.72);
    }
}

pub(super) fn apply_cdp_info(
    device: &mut Device,
    info: cdp::CdpInfo,
    oui_db: Option<&HashMap<String, String>>,
) {
    device.add_service("cdp", "cdp", None, 0.72);
    if device.mac.is_none() {
        device.mac = Some(info.source_mac.clone());
    }
    if device.vendor.is_none()
        && let (Some(mac), Some(oui_db)) = (&device.mac, oui_db)
    {
        device.vendor = enrich::lookup_vendor(mac, oui_db);
    }

    device.add_evidence("cdp", "source_mac", info.source_mac, 0.76);
    device.add_evidence("cdp", "version", info.version.to_string(), 0.45);
    device.add_evidence("cdp", "ttl", info.ttl.to_string(), 0.45);
    if let Some(device_id) = info.device_id {
        device.add_name(device_id.clone(), "cdp", 0.88);
        device.add_evidence("cdp", "device_id", device_id, 0.88);
    }
    if let Some(port_id) = info.port_id {
        device.add_evidence("cdp", "port_id", port_id, 0.7);
    }
    if let Some(software_version) = info.software_version {
        device.add_evidence("cdp", "software_version", software_version.clone(), 0.9);
        device.set_os_guess(software_version, "cdp", 0.82);
    }
    if let Some(platform) = info.platform {
        device.add_evidence("cdp", "platform", platform.clone(), 0.86);
        device.set_model_guess(platform, "cdp", 0.82);
        device.set_make_guess("Cisco", "cdp", 0.78);
    }
    if let Some(native_vlan) = info.native_vlan {
        device.add_evidence("cdp", "native_vlan", native_vlan.to_string(), 0.55);
    }
    if let Some(duplex) = info.duplex {
        device.add_evidence("cdp", "duplex", duplex, 0.45);
    }
    for capability in &info.capabilities {
        device.add_evidence("cdp", "capability", capability.as_str(), 0.82);
    }
    for address in info.addresses {
        device.add_evidence("cdp", "address", address.to_string(), 0.78);
    }
    for address in info.management_addresses {
        device.add_evidence("cdp", "management_address", address.to_string(), 0.84);
    }

    if info
        .capabilities
        .iter()
        .any(|capability| capability == "phone")
    {
        device.set_device_type_guess("phone", "cdp", 0.88);
    } else if info
        .capabilities
        .iter()
        .any(|capability| capability == "router")
    {
        device.set_device_type_guess("router", "cdp", 0.86);
    } else if info
        .capabilities
        .iter()
        .any(|capability| capability == "switch")
    {
        device.set_device_type_guess("switch", "cdp", 0.86);
    } else if !info.capabilities.is_empty() {
        device.set_device_type_guess("network-device", "cdp", 0.72);
    }
}

pub(super) fn apply_smb_info(device: &mut Device, info: smb::SmbInfo) {
    // SMB negotiate/session-setup data is intentionally shallow: it identifies
    // the server stack and host names without authenticating or enumerating
    // shares.
    device.add_service("smb", "smb", Some(445), 0.78);
    if let Some(dialect) = info.dialect {
        device.add_evidence("smb", "smb_dialect", dialect, 0.78);
    }
    if let Some(signing_required) = info.signing_required {
        device.add_evidence(
            "smb",
            "smb_signing_required",
            signing_required.to_string(),
            0.65,
        );
    }
    if let Some(guid) = info.server_guid {
        device.add_evidence("smb", "smb_server_guid", guid, 0.65);
    }
    if let Some(native_os) = info.native_os {
        device.add_evidence("smb", "smb_native_os", native_os.clone(), 0.85);
        if native_os.to_ascii_lowercase().contains("windows") {
            device.set_os_guess("Windows", "smb", 0.78);
        }
    }
    if let Some(native_lanman) = info.native_lanman {
        device.add_evidence("smb", "smb_native_lanman", native_lanman.clone(), 0.78);
        if native_lanman.to_ascii_lowercase().contains("samba") {
            device.set_os_guess("Unix-like", "smb", 0.68);
        }
    }
    if let Some(dns_name) = info.dns_computer_name {
        device.add_name(dns_name.clone(), "smb", 0.86);
        device.add_evidence("smb", "smb_dns_computer_name", dns_name, 0.86);
    }
    if let Some(netbios_name) = info.netbios_computer_name {
        device.add_name(netbios_name.clone(), "smb", 0.82);
        device.add_evidence("smb", "smb_netbios_computer_name", netbios_name, 0.82);
    }
}

pub(super) fn apply_oui(devices: &mut BTreeMap<IpAddr, Device>, oui_db: &HashMap<String, String>) {
    for device in devices.values_mut() {
        if let Some(mac) = &device.mac {
            device.vendor = enrich::lookup_vendor(mac, oui_db);
        }
    }
}

pub(super) fn merge_devices_by_interface_ip(devices: Vec<Device>) -> Vec<Device> {
    // Parallel enrichment paths can produce partial snapshots for the same host.
    // Collapse by interface/IP after all phases so multi-interface scans still
    // keep overlapping addresses separate.
    let mut merged = BTreeMap::<(String, IpAddr), Device>::new();
    for device in devices {
        let key = (device.interface.clone().unwrap_or_default(), device.ip);
        if let Some(existing) = merged.get_mut(&key) {
            merge_device(existing, device);
        } else {
            merged.insert(key, device);
        }
    }
    merged.into_values().collect()
}

fn merge_device(existing: &mut Device, mut incoming: Device) {
    // Merge as a union of observations. Optional scalar identity fields only
    // fill blanks; confidence-bearing guesses go through Device's normal
    // highest-confidence replacement rules.
    if existing.mac.is_none() {
        existing.mac = incoming.mac.take();
    }
    if existing.vendor.is_none() {
        existing.vendor = incoming.vendor.take();
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
            evidence.source.as_str(),
            evidence.key.as_str(),
            evidence.value,
            evidence.confidence,
        );
    }
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::MdnsService;
    use chrono::{TimeZone, Utc};

    fn device() -> Device {
        Device::new(
            "192.168.1.10".parse().unwrap(),
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        )
    }

    fn has_evidence(device: &Device, source: &str, key: &str, value: &str) -> bool {
        device
            .evidence
            .iter()
            .any(|item| item.source == source && item.key == key && item.value == value)
    }

    #[test]
    fn multicast_identity_adds_names_services_and_raw_evidence() {
        let mut device = device();

        apply_mdns_info(
            &mut device,
            enrich::MdnsInfo {
                names: vec!["printer.local".to_string()],
                os: Some("AirPrint OS".to_string()),
                model: Some("OfficeJet Pro".to_string()),
                services: vec![MdnsService {
                    name: "_ipp._tcp.local".to_string(),
                    port: Some(631),
                }],
            },
        );
        apply_upnp_info(
            &mut device,
            upnp::UpnpInfo {
                names: vec!["Office Printer".to_string()],
                manufacturer: Some("HP".to_string()),
                model: Some("OfficeJet Pro 9010".to_string()),
                device_type: Some("urn:schemas-upnp-org:device:Printer:1".to_string()),
                server: Some("Linux UPnP".to_string()),
                location: Some("http://192.168.1.10/root.xml".to_string()),
                services: vec!["urn:schemas-upnp-org:service:PrintBasic:1".to_string()],
                usns: vec!["uuid:printer::upnp:rootdevice".to_string()],
            },
        );

        assert_eq!(device.hostname.as_deref(), Some("printer"));
        assert_eq!(
            device.make.as_ref().map(|guess| guess.value.as_str()),
            Some("HP")
        );
        assert_eq!(
            device.model.as_ref().map(|guess| guess.value.as_str()),
            Some("OfficeJet Pro")
        );
        assert!(
            device
                .services
                .iter()
                .any(|service| service.source == "mdns" && service.port == Some(631))
        );
        assert!(has_evidence(&device, "mdns", "model", "OfficeJet Pro"));
        assert!(has_evidence(&device, "upnp", "manufacturer", "HP"));
        assert!(has_evidence(&device, "upnp", "model", "OfficeJet Pro 9010"));
        assert!(has_evidence(
            &device,
            "upnp",
            "location",
            "http://192.168.1.10/root.xml"
        ));
    }

    #[test]
    fn deep_snmp_and_smb_keep_protocol_specific_evidence() {
        let mut device = device();

        apply_deep_probes(
            &mut device,
            vec![deep::PortProbe {
                port: 443,
                service: "https".to_string(),
                banner: Some("HTTP 200 | server: OpenWrt".to_string()),
                http_headers: vec![deep::HttpHeader {
                    name: "server".to_string(),
                    value: "uhttpd".to_string(),
                }],
                favicon: Some(deep::FaviconFingerprint {
                    url: "https://192.168.1.10/favicon.ico".to_string(),
                    sha256: "abc123".to_string(),
                    bytes: 42,
                }),
                tls: Some(deep::TlsCertificate {
                    sha256: "def456".to_string(),
                    subject: Some("CN=router".to_string()),
                    issuer: None,
                    not_before: None,
                    not_after: Some("2028-01-01".to_string()),
                }),
            }],
            deep::ProbeOptions {
                deep: true,
                http: true,
                tls: true,
            },
        );
        apply_snmp_info(
            &mut device,
            snmp::SnmpInfo {
                sys_descr: Some("Linux router 6.1".to_string()),
                sys_object_id: Some("1.3.6.1.4.1.8072".to_string()),
                sys_services: Some(4),
                ..snmp::SnmpInfo::default()
            },
        );
        apply_smb_info(
            &mut device,
            smb::SmbInfo {
                dialect: Some("SMB 3.1.1".to_string()),
                signing_required: Some(true),
                server_guid: None,
                native_os: Some("Windows Server".to_string()),
                native_lanman: None,
                netbios_computer_name: Some("FILES".to_string()),
                dns_computer_name: Some("files.local".to_string()),
            },
        );

        assert!(has_evidence(
            &device,
            "http",
            "http_header_server",
            "uhttpd"
        ));
        assert!(has_evidence(&device, "http", "favicon_sha256", "abc123"));
        assert!(has_evidence(&device, "tls", "tls_cert_sha256", "def456"));
        assert!(has_evidence(
            &device,
            "snmp",
            "sysObjectID",
            "1.3.6.1.4.1.8072"
        ));
        assert!(has_evidence(&device, "smb", "smb_dialect", "SMB 3.1.1"));
        assert!(
            device
                .services
                .iter()
                .any(|service| service.source == "snmp" && service.port == Some(161))
        );
        assert!(
            device
                .services
                .iter()
                .any(|service| service.source == "smb" && service.port == Some(445))
        );
    }

    #[test]
    fn deep_probe_application_respects_source_options() {
        let mut device = device();

        apply_deep_probes(
            &mut device,
            vec![deep::PortProbe {
                port: 443,
                service: "https".to_string(),
                banner: Some("HTTP 200 | server: OpenWrt".to_string()),
                http_headers: vec![deep::HttpHeader {
                    name: "server".to_string(),
                    value: "uhttpd".to_string(),
                }],
                favicon: None,
                tls: Some(deep::TlsCertificate {
                    sha256: "def456".to_string(),
                    subject: None,
                    issuer: None,
                    not_before: None,
                    not_after: None,
                }),
            }],
            deep::ProbeOptions {
                deep: false,
                http: true,
                tls: false,
            },
        );

        assert!(
            !device
                .services
                .iter()
                .any(|service| service.source == "deep")
        );
        assert!(!device.evidence.iter().any(|item| item.source == "deep"));
        assert!(has_evidence(
            &device,
            "http",
            "http_header_server",
            "uhttpd"
        ));
        assert!(!device.evidence.iter().any(|item| item.source == "tls"));
    }

    #[test]
    fn lldp_adds_network_device_identity() {
        let mut device = device();

        apply_lldp_info(
            &mut device,
            lldp::LldpInfo {
                source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                chassis_id: Some("00:11:22:33:44:55".to_string()),
                chassis_id_subtype: Some("mac-address".to_string()),
                chassis_mac: Some("00:11:22:33:44:55".to_string()),
                port_id: Some("Gi1/0/1".to_string()),
                port_id_subtype: Some("interface-name".to_string()),
                ttl: Some(120),
                port_description: Some("uplink".to_string()),
                system_name: Some("core-switch".to_string()),
                system_description: Some("ExampleOS 1.0".to_string()),
                system_capabilities: vec!["bridge".to_string(), "router".to_string()],
                enabled_capabilities: vec!["bridge".to_string()],
                management_addresses: vec!["192.168.1.2".parse().unwrap()],
            },
            None,
        );

        assert_eq!(device.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(device.hostname.as_deref(), Some("core-switch"));
        assert_eq!(
            device
                .device_type
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("switch")
        );
        assert!(has_evidence(
            &device,
            "lldp",
            "system_description",
            "ExampleOS 1.0"
        ));
        assert!(has_evidence(
            &device,
            "lldp",
            "management_address",
            "192.168.1.2"
        ));
    }

    #[test]
    fn cdp_adds_cisco_network_device_identity() {
        let mut device = device();

        apply_cdp_info(
            &mut device,
            cdp::CdpInfo {
                source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                version: 2,
                ttl: 180,
                device_id: Some("access-switch".to_string()),
                addresses: vec!["192.168.1.2".parse().unwrap()],
                port_id: Some("GigabitEthernet1/0/1".to_string()),
                capabilities: vec!["switch".to_string()],
                software_version: Some("Cisco IOS Software".to_string()),
                platform: Some("cisco WS-C2960X".to_string()),
                native_vlan: Some(100),
                duplex: Some("full".to_string()),
                management_addresses: vec!["192.168.1.3".parse().unwrap()],
            },
            None,
        );

        assert_eq!(device.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(device.hostname.as_deref(), Some("access-switch"));
        assert_eq!(
            device.make.as_ref().map(|guess| guess.value.as_str()),
            Some("Cisco")
        );
        assert_eq!(
            device
                .device_type
                .as_ref()
                .map(|guess| guess.value.as_str()),
            Some("switch")
        );
        assert!(has_evidence(
            &device,
            "cdp",
            "software_version",
            "Cisco IOS Software"
        ));
        assert!(has_evidence(
            &device,
            "cdp",
            "management_address",
            "192.168.1.3"
        ));
    }

    #[test]
    fn dhcp_lease_does_not_use_conflicting_mac_for_vendor() {
        let mut device = device();
        device.mac = Some("00:11:22:33:44:55".to_string());
        let ip = device.ip;
        let oui_db = HashMap::from([
            ("AABBCC".to_string(), "Lease Vendor".to_string()),
            ("001122".to_string(), "Observed Vendor".to_string()),
        ]);

        apply_dhcp_lease(
            &mut device,
            dhcp::DhcpLease {
                ip,
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                hostname: Some("workstation".to_string()),
                client_id: Some("client-1".to_string()),
                vendor_class: Some("MSFT 5.0".to_string()),
                expires_at: None,
                source: Some("/tmp/leases".into()),
            },
            Some(&oui_db),
        );

        assert_eq!(device.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(device.vendor.as_deref(), Some("Observed Vendor"));
        assert_eq!(device.hostname.as_deref(), Some("workstation"));
        assert!(has_evidence(&device, "dhcp", "mac", "aa:bb:cc:dd:ee:ff"));
        assert!(has_evidence(&device, "dhcp", "vendor_class", "MSFT 5.0"));
    }

    #[test]
    fn merged_devices_keep_all_evidence_for_the_same_interface_ip() {
        let early = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let late = Utc.with_ymd_and_hms(2026, 1, 1, 0, 1, 0).unwrap();
        let mut left = Device::new("192.168.1.10".parse().unwrap(), early);
        left.interface = Some("en0".to_string());
        left.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        left.add_name("left", "mdns", 0.9);

        let mut right = Device::new(left.ip, late);
        right.interface = Some("en0".to_string());
        right.add_service("http", "deep", Some(80), 0.7);
        right.add_evidence("http", "server", "nginx", 0.7);

        let merged = merge_devices_by_interface_ip(vec![left, right]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].first_seen, early);
        assert_eq!(merged[0].last_seen, late);
        assert_eq!(merged[0].hostname.as_deref(), Some("left"));
        assert!(
            merged[0]
                .services
                .iter()
                .any(|service| service.name == "http")
        );
        assert!(has_evidence(&merged[0], "http", "server", "nginx"));
    }
}
