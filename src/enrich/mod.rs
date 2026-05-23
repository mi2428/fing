//! Passive and multicast enrichment collectors.
//!
//! These collectors gather LAN identity hints that do not require a TCP session
//! with every host: OUI vendor lookup, reverse DNS, mDNS/Bonjour, and NetBIOS
//! name service. They return raw protocol facts and leave classification to the
//! scanner/apply and identity-rule layers.

use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::{
    TokioResolver,
    lookup::Lookup,
    proto::rr::{Name, RData},
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinSet};

const IEEE_OUI_CSV: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdnsInfo {
    pub names: Vec<String>,
    pub os: Option<String>,
    pub model: Option<String>,
    pub services: Vec<MdnsService>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdnsService {
    pub name: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsRecord {
    Address {
        host: String,
        ip: IpAddr,
    },
    Ptr {
        name: String,
        target: String,
    },
    Srv {
        name: String,
        target: String,
        port: u16,
    },
    Txt {
        name: String,
        attrs: Vec<String>,
    },
}

pub fn default_oui_db_path() -> PathBuf {
    default_cache_dir().join("oui.json")
}

pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("fing")
}

pub fn update_oui_db(path: &Path) -> Result<usize> {
    let response = reqwest::blocking::get(IEEE_OUI_CSV)
        .with_context(|| format!("failed to download {IEEE_OUI_CSV}"))?;
    if !response.status().is_success() {
        bail!("OUI download failed with status {}", response.status());
    }
    let text = response.text().context("failed to read OUI CSV body")?;
    let db = parse_ieee_oui_csv(&text)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&db)?)?;
    Ok(db.len())
}

pub fn load_oui_db(path: &Path) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let db = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(db)
}

pub fn lookup_vendor(mac: &str, db: &HashMap<String, String>) -> Option<String> {
    normalize_oui_prefix(mac).and_then(|prefix| db.get(&prefix).cloned())
}

pub fn normalize_oui_prefix(mac: &str) -> Option<String> {
    let hex = mac
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>();
    if hex.len() < 6 {
        return None;
    }
    Some(hex[..6].to_string())
}

pub fn parse_ieee_oui_csv(input: &str) -> Result<HashMap<String, String>> {
    let mut rdr = csv::Reader::from_reader(input.as_bytes());
    let headers = rdr.headers()?.clone();
    // IEEE has adjusted CSV header text over time. Resolve columns by header
    // name when possible and keep conservative fallbacks for older snapshots.
    let assignment_idx = find_header(&headers, "Assignment")
        .or_else(|| find_header(&headers, "assignment"))
        .unwrap_or(1);
    let organization_idx = find_header(&headers, "Organization Name")
        .or_else(|| find_header(&headers, "Organization"))
        .unwrap_or(2);

    let mut db = HashMap::new();
    for record in rdr.records() {
        let record = record?;
        let Some(prefix) = record.get(assignment_idx).and_then(normalize_oui_prefix) else {
            continue;
        };
        let Some(org) = record.get(organization_idx).map(str::trim) else {
            continue;
        };
        if org.is_empty() {
            continue;
        }
        db.insert(prefix, org.to_string());
    }
    Ok(db)
}

fn find_header(headers: &csv::StringRecord, name: &str) -> Option<usize> {
    headers
        .iter()
        .position(|header| header.trim().eq_ignore_ascii_case(name))
}

pub async fn reverse_dns_with_callback<F>(
    ips: Vec<IpAddr>,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    mut on_result: F,
) -> HashMap<IpAddr, String>
where
    F: FnMut(IpAddr, String),
{
    // Hickory performs PTR queries on Tokio instead of parking blocking libc
    // resolver calls on the blocking pool. A timed-out lookup can now be
    // dropped without leaving a worker thread stuck in getnameinfo.
    let resolver = match TokioResolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(resolver) => Arc::new(resolver),
        Err(_) => return HashMap::new(),
    };
    let mut tasks = JoinSet::new();

    for ip in ips {
        let resolver = Arc::clone(&resolver);
        let limiter = Arc::clone(&limiter);
        tasks.spawn(async move {
            let Ok(_permit) = limiter.acquire_owned().await else {
                return None;
            };
            let lookup =
                tokio::time::timeout(timeout, resolver.reverse_lookup(reverse_lookup_name(ip)))
                    .await
                    .ok()?
                    .ok()?;
            ptr_hostname(&lookup).map(|name| (ip, name))
        });
    }

    let mut result = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((ip, name))) = joined {
            on_result(ip, name.clone());
            result.insert(ip, name);
        }
    }
    result
}

fn reverse_lookup_name(ip: IpAddr) -> Name {
    let mut name = Name::from(ip);
    name.set_fqdn(true);
    name
}

fn ptr_hostname(lookup: &Lookup) -> Option<String> {
    lookup
        .answers()
        .iter()
        .find_map(|record| match &record.data {
            RData::PTR(ptr) => Some(ptr.0.to_utf8().trim_end_matches('.').to_string()),
            _ => None,
        })
}

pub fn mdns_probe_with_callback<F>(
    interface_ip: Ipv4Addr,
    timeout: Duration,
    mut on_result: F,
) -> Result<HashMap<IpAddr, MdnsInfo>>
where
    F: FnMut(IpAddr, MdnsInfo),
{
    let socket = mdns_socket(interface_ip)?;
    // Query a small set of service types that commonly expose device identity.
    // Additional records from responses are still parsed; the query list only
    // nudges devices to answer.
    let query = build_mdns_query(&[
        "_services._dns-sd._udp.local",
        "_device-info._tcp.local",
        "_workstation._tcp.local",
        "_smb._tcp.local",
        "_ssh._tcp.local",
        "_http._tcp.local",
    ])?;
    socket
        .send_to(&query, SocketAddrV4::new(MDNS_ADDR, MDNS_PORT))
        .context("failed to send mDNS query")?;

    let mut records = Vec::new();
    let mut emitted = HashMap::<IpAddr, MdnsInfo>::new();
    let deadline = Instant::now() + timeout;
    let mut buffer = [0_u8; 9000];

    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => {
                records.extend(parse_mdns_packet(&buffer[..len]));
                // mDNS answers often arrive in several packets. Recompute the
                // aggregate view and emit only when a host gains new facts.
                for (ip, info) in records_to_mdns_info(&records) {
                    if emitted.get(&ip) == Some(&info) {
                        continue;
                    }
                    emitted.insert(ip, info.clone());
                    on_result(ip, info);
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err).context("failed to read mDNS response"),
        }
    }

    Ok(records_to_mdns_info(&records))
}

fn mdns_socket(interface_ip: Ipv4Addr) -> Result<UdpSocket> {
    // Port 5353 is ideal because devices reply multicast-to-multicast, but some
    // OSes already have mDNSResponder bound there. Falling back to an ephemeral
    // port still allows useful unicast answers.
    match bind_mdns_socket(interface_ip, MDNS_PORT) {
        Ok(socket) => Ok(socket),
        Err(_) => bind_mdns_socket(interface_ip, 0),
    }
}

fn bind_mdns_socket(interface_ip: Ipv4Addr, port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        port,
    )))?;
    socket.join_multicast_v4(&MDNS_ADDR, &interface_ip)?;
    socket.set_multicast_if_v4(&interface_ip)?;
    Ok(socket.into())
}

fn build_mdns_query(names: &[&str]) -> Result<Vec<u8>> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&(names.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());

    for name in names {
        write_dns_name(&mut packet, name)?;
        packet.extend_from_slice(&12_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
    }

    Ok(packet)
}

fn write_dns_name(packet: &mut Vec<u8>, name: &str) -> Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(anyhow!("DNS label is too long: {label}"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    Ok(())
}

pub fn parse_mdns_packet(buf: &[u8]) -> Vec<MdnsRecord> {
    if buf.len() < 12 {
        return Vec::new();
    }

    let qd = read_u16(buf, 4).unwrap_or(0) as usize;
    let an = read_u16(buf, 6).unwrap_or(0) as usize;
    let ns = read_u16(buf, 8).unwrap_or(0) as usize;
    let ar = read_u16(buf, 10).unwrap_or(0) as usize;
    let mut offset = 12;

    // Skip questions first; answers, authority, and additional sections share
    // the same resource-record layout and can all contain identity clues.
    for _ in 0..qd {
        let Some((_, next)) = read_dns_name(buf, offset) else {
            return Vec::new();
        };
        offset = next.saturating_add(4);
        if offset > buf.len() {
            return Vec::new();
        }
    }

    let mut records = Vec::new();
    for _ in 0..(an + ns + ar) {
        let Some((name, next)) = read_dns_name(buf, offset) else {
            break;
        };
        offset = next;
        if offset + 10 > buf.len() {
            break;
        }

        let record_type = read_u16(buf, offset).unwrap_or(0);
        let _class = read_u16(buf, offset + 2).unwrap_or(0);
        let _ttl = read_u32(buf, offset + 4).unwrap_or(0);
        let rdlen = read_u16(buf, offset + 8).unwrap_or(0) as usize;
        offset += 10;
        if offset + rdlen > buf.len() {
            break;
        }
        let rdata = &buf[offset..offset + rdlen];

        match record_type {
            1 if rdlen == 4 => {
                records.push(MdnsRecord::Address {
                    host: normalize_dns_name(&name),
                    ip: IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                });
            }
            28 if rdlen == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(rdata);
                records.push(MdnsRecord::Address {
                    host: normalize_dns_name(&name),
                    ip: IpAddr::V6(octets.into()),
                });
            }
            12 => {
                if let Some((target, _)) = read_dns_name(buf, offset) {
                    records.push(MdnsRecord::Ptr {
                        name: normalize_dns_name(&name),
                        target: normalize_dns_name(&target),
                    });
                }
            }
            33 if rdlen >= 6 => {
                if let Some((target, _)) = read_dns_name(buf, offset + 6) {
                    records.push(MdnsRecord::Srv {
                        name: normalize_dns_name(&name),
                        target: normalize_dns_name(&target),
                        port: u16::from_be_bytes([rdata[4], rdata[5]]),
                    });
                }
            }
            16 => {
                records.push(MdnsRecord::Txt {
                    name: normalize_dns_name(&name),
                    attrs: parse_txt_records(rdata),
                });
            }
            _ => {}
        }

        offset += rdlen;
    }

    records
}

fn records_to_mdns_info(records: &[MdnsRecord]) -> HashMap<IpAddr, MdnsInfo> {
    // mDNS identity is relational: A/AAAA maps host -> IP, SRV maps service
    // instance -> host, TXT hangs attributes off either. Build those indexes
    // first, then materialize one MdnsInfo per IP.
    let mut host_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut host_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut host_txt_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut host_services: HashMap<String, Vec<MdnsService>> = HashMap::new();
    let mut txt_by_name: HashMap<String, Vec<String>> = HashMap::new();
    let mut ptr_targets = HashSet::new();

    for record in records {
        match record {
            MdnsRecord::Address { host, ip } => {
                host_ips.entry(host.clone()).or_default().push(*ip);
            }
            MdnsRecord::Ptr { target, .. } => {
                ptr_targets.insert(target.clone());
            }
            MdnsRecord::Srv { name, target, port } => {
                host_names
                    .entry(target.clone())
                    .or_default()
                    .insert(service_instance_name(name));
                host_txt_names
                    .entry(target.clone())
                    .or_default()
                    .insert(name.clone());
                host_services
                    .entry(target.clone())
                    .or_default()
                    .push(MdnsService {
                        name: service_type_name(name),
                        port: (*port != 0).then_some(*port),
                    });
            }
            MdnsRecord::Txt { name, attrs } => {
                txt_by_name
                    .entry(name.clone())
                    .or_default()
                    .extend(attrs.iter().cloned());
            }
        }
    }

    for target in ptr_targets {
        host_names
            .entry(target.clone())
            .or_default()
            .insert(service_instance_name(&target));
    }

    let mut info_by_ip = HashMap::new();
    for (host, ips) in host_ips {
        for ip in ips {
            let mut info = MdnsInfo::default();
            info.names.push(host.clone());
            if let Some(names) = host_names.get(&host) {
                info.names.extend(names.iter().cloned());
            }
            if let Some(services) = host_services.get(&host) {
                info.services.extend(services.iter().cloned());
            }

            for (name, attrs) in &txt_by_name {
                if name == &host
                    || host_txt_names
                        .get(&host)
                        .is_some_and(|names| names.contains(name))
                {
                    apply_mdns_txt(&mut info, attrs);
                }
            }

            info.names.sort();
            info.names.dedup();
            info_by_ip.insert(ip, info);
        }
    }

    info_by_ip
}

fn apply_mdns_txt(info: &mut MdnsInfo, attrs: &[String]) {
    for attr in attrs {
        let lower = attr.to_ascii_lowercase();
        if let Some(model) = attr.strip_prefix("model=") {
            info.model = Some(model.to_string());
            if model.contains("Mac") || model.contains("iMac") {
                info.os = Some("macOS".to_string());
            } else if model.contains("AppleTV") {
                info.os = Some("tvOS".to_string());
            }
        } else if let Some(version) = lower.strip_prefix("osxvers=") {
            info.os = Some(format!("macOS {version}"));
        }
    }
}

fn parse_txt_records(rdata: &[u8]) -> Vec<String> {
    let mut attrs = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let len = rdata[offset] as usize;
        offset += 1;
        if offset + len > rdata.len() {
            break;
        }
        attrs.push(String::from_utf8_lossy(&rdata[offset..offset + len]).to_string());
        offset += len;
    }
    attrs
}

fn service_instance_name(name: &str) -> String {
    name.split("._").next().unwrap_or(name).to_string()
}

fn service_type_name(name: &str) -> String {
    name.split('.')
        .find(|part| part.starts_with('_') && !part.eq(&"_tcp") && !part.eq(&"_udp"))
        .unwrap_or(name)
        .trim_start_matches('_')
        .to_string()
}

fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
    ]))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
        *buf.get(offset + 2)?,
        *buf.get(offset + 3)?,
    ]))
}

fn read_dns_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next = offset;
    let mut seen_offsets = HashSet::new();

    loop {
        // DNS compression pointers can form loops in malformed packets. Track
        // visited offsets so a bad LAN packet cannot spin this parser forever.
        if !seen_offsets.insert(offset) {
            return None;
        }
        let len = *buf.get(offset)?;
        if len & 0xc0 == 0xc0 {
            let second = *buf.get(offset + 1)? as usize;
            let pointer = (((len & 0x3f) as usize) << 8) | second;
            if !jumped {
                next = offset + 2;
            }
            jumped = true;
            offset = pointer;
            continue;
        }
        if len == 0 {
            if !jumped {
                next = offset + 1;
            }
            break;
        }

        offset += 1;
        let end = offset + len as usize;
        if end > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[offset..end]).to_string());
        offset = end;
    }

    Some((labels.join("."), next))
}

pub async fn netbios_probe_with_callback<F>(
    ips: Vec<IpAddr>,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    mut on_result: F,
) -> HashMap<IpAddr, Vec<String>>
where
    F: FnMut(IpAddr, Vec<String>),
{
    // NetBIOS name service is UDP/137 and still useful for Windows and Samba
    // hosts that do not publish richer multicast records.
    let mut tasks = JoinSet::new();

    for ip in ips {
        let IpAddr::V4(ipv4) = ip else {
            continue;
        };
        let limiter = Arc::clone(&limiter);
        tasks.spawn(async move {
            let Ok(_permit) = limiter.acquire_owned().await else {
                return None;
            };
            let query = build_netbios_query(0x4000);
            let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .await
                .ok()?;
            let _ = socket.send_to(&query, (ipv4, 137)).await.ok()?;
            let mut buf = [0_u8; 1500];
            match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    let names = parse_netbios_response(&buf[..len]).names;
                    if names.is_empty() {
                        None
                    } else {
                        Some((IpAddr::V4(ipv4), names))
                    }
                }
                _ => None,
            }
        });
    }

    let mut result = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((ip, names))) = joined {
            on_result(ip, names.clone());
            result.insert(ip, names);
        }
    }
    result
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetbiosResponse {
    pub transaction_id: u16,
    pub names: Vec<String>,
}

pub fn build_netbios_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.push(32);
    packet.extend_from_slice(&encode_netbios_name("*").unwrap());
    packet.push(0);
    packet.extend_from_slice(&0x0021_u16.to_be_bytes());
    packet.extend_from_slice(&0x0001_u16.to_be_bytes());
    packet
}

fn encode_netbios_name(name: &str) -> Result<[u8; 32]> {
    let mut raw = [b' '; 16];
    for (idx, byte) in name.as_bytes().iter().take(15).enumerate() {
        raw[idx] = byte.to_ascii_uppercase();
    }
    raw[15] = 0;

    let mut encoded = [0_u8; 32];
    for (idx, byte) in raw.iter().enumerate() {
        encoded[idx * 2] = b'A' + ((byte >> 4) & 0x0f);
        encoded[idx * 2 + 1] = b'A' + (byte & 0x0f);
    }
    Ok(encoded)
}

pub fn parse_netbios_response(buf: &[u8]) -> NetbiosResponse {
    if buf.len() < 12 {
        return NetbiosResponse::default();
    }
    let transaction_id = read_u16(buf, 0).unwrap_or(0);
    let question_count = read_u16(buf, 4).unwrap_or(0) as usize;
    let answer_count = read_u16(buf, 6).unwrap_or(0) as usize;

    let mut offset = 12;
    for _ in 0..question_count {
        let Some(next) = skip_nbns_name(buf, offset) else {
            return NetbiosResponse {
                transaction_id,
                names: Vec::new(),
            };
        };
        offset = next.saturating_add(4);
        if offset > buf.len() {
            return NetbiosResponse {
                transaction_id,
                names: Vec::new(),
            };
        }
    }

    let mut names = BTreeMap::<String, ()>::new();
    for _ in 0..answer_count {
        let Some(next) = skip_nbns_name(buf, offset) else {
            break;
        };
        offset = next;
        if offset + 10 > buf.len() {
            break;
        }
        let record_type = read_u16(buf, offset).unwrap_or(0);
        let rdlen = read_u16(buf, offset + 8).unwrap_or(0) as usize;
        offset += 10;
        if offset + rdlen > buf.len() {
            break;
        }
        if record_type == 0x0021 && rdlen > 0 {
            parse_netbios_name_table(&buf[offset..offset + rdlen], &mut names);
        }
        offset += rdlen;
    }

    NetbiosResponse {
        transaction_id,
        names: names.into_keys().collect(),
    }
}

fn skip_nbns_name(buf: &[u8], offset: usize) -> Option<usize> {
    let first = *buf.get(offset)?;
    if first & 0xc0 == 0xc0 {
        return Some(offset + 2);
    }
    let len = first as usize;
    let end = offset + 1 + len;
    if *buf.get(end)? != 0 {
        return None;
    }
    Some(end + 1)
}

fn parse_netbios_name_table(rdata: &[u8], names: &mut BTreeMap<String, ()>) {
    let Some(count) = rdata.first().copied() else {
        return;
    };
    let mut offset = 1;
    for _ in 0..count {
        if offset + 18 > rdata.len() {
            break;
        }
        let name = String::from_utf8_lossy(&rdata[offset..offset + 15])
            .trim()
            .to_string();
        let suffix = rdata[offset + 15];
        let flags = u16::from_be_bytes([rdata[offset + 16], rdata[offset + 17]]);
        let is_group = flags & 0x8000 != 0;
        // Keep workstation, messenger, and file-server names. Group names such
        // as WORKGROUP are topology labels, not device identities.
        if !name.is_empty() && !is_group && matches!(suffix, 0x00 | 0x03 | 0x20) {
            names.insert(name, ());
        }
        offset += 18;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_oui_prefix() {
        assert_eq!(
            normalize_oui_prefix("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("AABBCC")
        );
        assert_eq!(normalize_oui_prefix("aabb").as_deref(), None);
    }

    #[test]
    fn parses_ieee_oui_csv() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Example Inc,Somewhere\n";
        let db = parse_ieee_oui_csv(csv).unwrap();

        assert_eq!(db.get("AABBCC").map(String::as_str), Some("Example Inc"));
    }

    #[test]
    fn builds_fqdn_reverse_lookup_name() {
        let ipv4 = reverse_lookup_name("192.168.1.20".parse().unwrap());
        let ipv6 = reverse_lookup_name("2001:db8::1".parse().unwrap());

        assert_eq!(ipv4.to_ascii(), "20.1.168.192.in-addr.arpa.");
        assert!(ipv6.is_fqdn());
        assert!(ipv6.to_ascii().ends_with(".ip6.arpa."));
    }

    #[test]
    fn parses_mdns_a_record_with_compressed_name() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0x8400_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        write_dns_name(&mut packet, "host.local").unwrap();
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0xc00c_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&[192, 168, 1, 20]);

        let records = parse_mdns_packet(&packet);
        assert_eq!(
            records,
            vec![MdnsRecord::Address {
                host: "host.local".to_string(),
                ip: "192.168.1.20".parse().unwrap()
            }]
        );
    }

    #[test]
    fn mdns_txt_for_service_instance_enriches_srv_target_host() {
        let records = vec![
            MdnsRecord::Address {
                host: "printer.local".to_string(),
                ip: "192.168.1.20".parse().unwrap(),
            },
            MdnsRecord::Srv {
                name: "Office._ipp._tcp.local".to_string(),
                target: "printer.local".to_string(),
                port: 631,
            },
            MdnsRecord::Txt {
                name: "Office._ipp._tcp.local".to_string(),
                attrs: vec!["model=OfficeJet Pro".to_string()],
            },
        ];

        let info = records_to_mdns_info(&records);
        let device = info
            .get(&"192.168.1.20".parse().unwrap())
            .expect("mDNS info should be keyed by the SRV target host IP");

        assert_eq!(device.model.as_deref(), Some("OfficeJet Pro"));
        assert!(device.names.iter().any(|name| name == "Office"));
        assert!(
            device
                .services
                .iter()
                .any(|service| { service.name == "ipp" && service.port == Some(631) })
        );
    }

    #[test]
    fn parses_netbios_name_table_response() {
        let query = build_netbios_query(0x1234);
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234_u16.to_be_bytes());
        response.extend_from_slice(&0x8500_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&0x0021_u16.to_be_bytes());
        response.extend_from_slice(&0x0001_u16.to_be_bytes());
        response.extend_from_slice(&30_u32.to_be_bytes());
        response.extend_from_slice(&37_u16.to_be_bytes());
        response.push(2);
        let mut name = [b' '; 15];
        name[..6].copy_from_slice(b"OFFICE");
        response.extend_from_slice(&name);
        response.push(0x00);
        response.extend_from_slice(&0_u16.to_be_bytes());
        let mut group = [b' '; 15];
        group[..9].copy_from_slice(b"WORKGROUP");
        response.extend_from_slice(&group);
        response.push(0x00);
        response.extend_from_slice(&0x8000_u16.to_be_bytes());

        let parsed = parse_netbios_response(&response);
        assert_eq!(parsed.transaction_id, 0x1234);
        assert_eq!(parsed.names, vec!["OFFICE".to_string()]);
    }
}
