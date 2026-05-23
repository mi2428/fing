//! Minimal SNMPv2c system-group probe.
//!
//! The implementation builds and parses the small subset of BER needed for a
//! single GET request. Keeping the codec local avoids a broad SNMP dependency
//! while still collecting stable sysName/sysDescr/sysObjectID identity fields.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet};

const SYS_DESCR_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_CONTACT_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
const SYS_NAME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYS_LOCATION_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
const SYS_SERVICES_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];
const SYSTEM_OIDS: &[(&str, &[u32])] = &[
    ("sysDescr", SYS_DESCR_OID),
    ("sysObjectID", SYS_OBJECT_ID_OID),
    ("sysContact", SYS_CONTACT_OID),
    ("sysName", SYS_NAME_OID),
    ("sysLocation", SYS_LOCATION_OID),
    ("sysServices", SYS_SERVICES_OID),
];
static NEXT_REQUEST_ID: AtomicI32 = AtomicI32::new(0x4f52_0002);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnmpInfo {
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub sys_contact: Option<String>,
    pub sys_name: Option<String>,
    pub sys_location: Option<String>,
    pub sys_services: Option<u32>,
}

pub async fn probe_system_with_callback<F>(
    ips: Vec<IpAddr>,
    local_addr: IpAddr,
    community: String,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    mut on_result: F,
) -> HashMap<IpAddr, SnmpInfo>
where
    F: FnMut(IpAddr, SnmpInfo),
{
    let mut tasks = JoinSet::new();

    for ip in ips {
        let community = community.clone();
        let limiter = Arc::clone(&limiter);
        tasks.spawn(async move {
            let Ok(_permit) = limiter.acquire_owned().await else {
                return None;
            };
            probe_system_one(ip, local_addr, community, timeout)
                .await
                .map(|value| (ip, value))
        });
    }

    let mut result = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((ip, value))) = joined {
            on_result(ip, value.clone());
            result.insert(ip, value);
        }
    }
    result
}

async fn probe_system_one(
    ip: IpAddr,
    local_addr: IpAddr,
    community: String,
    timeout: Duration,
) -> Option<SnmpInfo> {
    if !super::same_ip_family(local_addr, ip) {
        return None;
    }

    // Request the system group fields in one packet. Devices that reject SNMP,
    // time out, or return an error simply produce no evidence for that host.
    let oids = SYSTEM_OIDS.iter().map(|(_, oid)| *oid).collect::<Vec<_>>();
    let request_id = next_request_id();
    let packet = build_get_request_for_oids(request_id, &community, &oids);
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(local_addr, 0))
        .await
        .ok()?;
    socket.send_to(&packet, (ip, 161)).await.ok()?;

    let mut buffer = [0_u8; 4096];
    tokio::time::timeout(timeout, async {
        loop {
            let (len, source) = socket.recv_from(&mut buffer).await.ok()?;
            if source.ip() != ip {
                continue;
            }
            if let Some(info) = parse_system_response_for_request(&buffer[..len], request_id) {
                return Some(info);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn next_request_id() -> i32 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn build_get_request_for_oids(request_id: i32, community: &str, oids: &[&[u32]]) -> Vec<u8> {
    let varbinds = oids
        .iter()
        .map(|oid_parts| sequence([oid(oid_parts), tlv(0x05, &[])]))
        .collect::<Vec<_>>();
    let varbind_list = tlv(0x30, &varbinds.into_iter().flatten().collect::<Vec<_>>());
    let pdu = tlv(
        0xa0,
        &concat([integer(request_id), integer(0), integer(0), varbind_list]),
    );

    sequence([integer(1), tlv(0x04, community.as_bytes()), pdu])
}

#[cfg(test)]
pub fn parse_system_response(buf: &[u8]) -> Option<SnmpInfo> {
    parse_system_response_with_request_id(buf, None)
}

fn parse_system_response_for_request(buf: &[u8], request_id: i32) -> Option<SnmpInfo> {
    parse_system_response_with_request_id(buf, Some(request_id))
}

fn parse_system_response_with_request_id(
    buf: &[u8],
    expected_request_id: Option<i32>,
) -> Option<SnmpInfo> {
    let values = parse_response_values_with_request_id(buf, expected_request_id)?;
    let sys_services = values
        .get(&oid_key(SYS_SERVICES_OID))
        .and_then(|value| value.parse::<u32>().ok());

    let info = SnmpInfo {
        sys_descr: values.get(&oid_key(SYS_DESCR_OID)).cloned(),
        sys_object_id: values.get(&oid_key(SYS_OBJECT_ID_OID)).cloned(),
        sys_contact: values.get(&oid_key(SYS_CONTACT_OID)).cloned(),
        sys_name: values.get(&oid_key(SYS_NAME_OID)).cloned(),
        sys_location: values.get(&oid_key(SYS_LOCATION_OID)).cloned(),
        sys_services,
    };

    (info.sys_descr.is_some()
        || info.sys_object_id.is_some()
        || info.sys_contact.is_some()
        || info.sys_name.is_some()
        || info.sys_location.is_some()
        || info.sys_services.is_some())
    .then_some(info)
}

fn parse_response_values_with_request_id(
    buf: &[u8],
    expected_request_id: Option<i32>,
) -> Option<HashMap<String, String>> {
    // SNMP responses are BER TLV trees. Parse structurally and reject error
    // status values before trusting any varbind payloads.
    let (_, message) = read_tlv_expect(buf, 0x30)?;
    let mut top = message;
    let _version = read_next(&mut top, 0x02)?;
    let _community = read_next(&mut top, 0x04)?;
    let pdu = read_next_any(&mut top)?;
    if pdu.tag != 0xa2 {
        return None;
    }

    let mut pdu_body = pdu.value;
    let request_id = read_next(&mut pdu_body, 0x02).and_then(decode_integer)?;
    if expected_request_id.is_some_and(|expected| request_id != i64::from(expected)) {
        return None;
    }
    let error_status = read_next(&mut pdu_body, 0x02)?;
    if error_status.iter().any(|byte| *byte != 0) {
        return None;
    }
    let _error_index = read_next(&mut pdu_body, 0x02)?;
    let varbind_list = read_next(&mut pdu_body, 0x30)?;
    let mut varbinds = varbind_list;

    let mut values = HashMap::new();
    while !varbinds.is_empty() {
        let mut varbind = read_next(&mut varbinds, 0x30)?;
        let oid = read_next(&mut varbind, 0x06).and_then(decode_oid)?;
        let value = read_next_any(&mut varbind)?;
        if let Some(value) = decode_value(value) {
            values.insert(oid_key(&oid), value);
        }
    }

    Some(values)
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv_expect(buf: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let tlv = read_tlv(buf)?;
    if tlv.tag != tag {
        return None;
    }
    let header_len = buf.len() - tlv.value.len() - tlv.rest_len();
    let rest = &buf[header_len + tlv.value.len()..];
    Some((rest, tlv.value))
}

impl<'a> Tlv<'a> {
    fn rest_len(&self) -> usize {
        0
    }
}

fn read_next<'a>(buf: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let tlv = read_next_any(buf)?;
    (tlv.tag == tag).then_some(tlv.value)
}

fn read_next_any<'a>(buf: &mut &'a [u8]) -> Option<Tlv<'a>> {
    let (tlv, rest) = read_tlv_with_rest(buf)?;
    *buf = rest;
    Some(tlv)
}

fn read_tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    read_tlv_with_rest(buf).map(|(tlv, _)| tlv)
}

fn read_tlv_with_rest(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    let (len, header_len) = read_len(&buf[1..])?;
    let start = 1 + header_len;
    let end = start + len;
    if end > buf.len() {
        return None;
    }
    Some((
        Tlv {
            tag,
            value: &buf[start..end],
        },
        &buf[end..],
    ))
}

fn read_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()? as usize;
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    // BER long-form lengths may use several bytes. Cap at usize-safe four
    // octets because scan responses are tiny and larger lengths are suspicious.
    let octets = first & 0x7f;
    if octets == 0 || octets > 4 || octets > buf.len().saturating_sub(1) {
        return None;
    }
    let mut len = 0;
    for byte in &buf[1..=octets] {
        len = (len << 8) | (*byte as usize);
    }
    Some((len, 1 + octets))
}

fn sequence<const N: usize>(parts: [Vec<u8>; N]) -> Vec<u8> {
    tlv(0x30, &concat(parts))
}

fn integer(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    // BER integers are signed and minimally encoded. Strip redundant sign
    // extension bytes while preserving the sign bit of the remaining first byte.
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}

fn oid(parts: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push((parts[0] * 40 + parts[1]) as u8);
    for part in &parts[2..] {
        encode_base128(*part, &mut body);
    }
    tlv(0x06, &body)
}

fn decode_oid(buf: &[u8]) -> Option<Vec<u32>> {
    let first = *buf.first()? as u32;
    let mut parts = vec![first / 40, first % 40];
    let mut value = 0_u32;
    for byte in &buf[1..] {
        value = (value << 7) | (byte & 0x7f) as u32;
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    Some(parts)
}

fn oid_key(parts: &[u32]) -> String {
    parts
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn decode_value(value: Tlv<'_>) -> Option<String> {
    // Decode only primitive value types the system group can realistically
    // return. Unknown tags are ignored rather than surfaced as lossy bytes.
    match value.tag {
        0x02 => decode_integer(value.value).map(|number| number.to_string()),
        0x04 => Some(String::from_utf8_lossy(value.value).trim().to_string()),
        0x05 => None,
        0x06 => decode_oid(value.value).map(|oid| oid_key(&oid)),
        0x40 if value.value.len() == 4 => Some(format!(
            "{}.{}.{}.{}",
            value.value[0], value.value[1], value.value[2], value.value[3]
        )),
        0x41..=0x46 => decode_unsigned(value.value).map(|number| number.to_string()),
        _ => None,
    }
    .filter(|value| !value.is_empty())
}

fn decode_integer(buf: &[u8]) -> Option<i64> {
    let first = *buf.first()?;
    let mut value = if first & 0x80 != 0 { -1_i64 } else { 0_i64 };
    for byte in buf {
        value = (value << 8) | (*byte as i64);
    }
    Some(value)
}

fn decode_unsigned(buf: &[u8]) -> Option<u64> {
    if buf.len() > 8 {
        return None;
    }
    let mut value = 0_u64;
    for byte in buf {
        value = (value << 8) | (*byte as u64);
    }
    Some(value)
}

fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut stack = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        stack.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.extend(stack.into_iter().rev());
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    write_len(value.len(), &mut result);
    result.extend_from_slice(value);
    result
}

fn concat<const N: usize>(parts: [Vec<u8>; N]) -> Vec<u8> {
    parts.into_iter().flatten().collect()
}

fn write_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_snmp_get_request() {
        let packet = build_get_request_for_oids(1, "public", &[SYS_DESCR_OID]);

        assert_eq!(packet[0], 0x30);
        assert!(packet.windows(6).any(|window| window == b"public"));
        assert!(packet.contains(&0xa0));
    }

    #[test]
    fn parses_sysdescr_response() {
        let value = tlv(0x04, b"Linux router 6.1");
        let varbind = sequence([oid(SYS_DESCR_OID), value]);
        let response_pdu = tlv(
            0xa2,
            &concat([integer(7), integer(0), integer(0), sequence([varbind])]),
        );
        let packet = sequence([integer(1), tlv(0x04, b"public"), response_pdu]);

        let info = parse_system_response(&packet).unwrap();

        assert_eq!(info.sys_descr.as_deref(), Some("Linux router 6.1"));
    }

    #[test]
    fn rejects_response_for_different_request_id() {
        let value = tlv(0x04, b"Linux router 6.1");
        let varbind = sequence([oid(SYS_DESCR_OID), value]);
        let response_pdu = tlv(
            0xa2,
            &concat([integer(7), integer(0), integer(0), sequence([varbind])]),
        );
        let packet = sequence([integer(1), tlv(0x04, b"public"), response_pdu]);

        assert!(parse_system_response_for_request(&packet, 8).is_none());
        assert!(parse_system_response_for_request(&packet, 7).is_some());
    }

    #[test]
    fn builds_multi_oid_snmp_get_request() {
        let packet = build_get_request_for_oids(1, "public", &[SYS_DESCR_OID, SYS_NAME_OID]);

        assert!(packet.contains(&0xa0));
        assert!(packet.windows(2).any(|window| window == [0x05, 0x00]));
        assert!(packet.len() > build_get_request_for_oids(1, "public", &[SYS_DESCR_OID]).len());
    }

    #[test]
    fn parses_system_response_values() {
        let descr = sequence([oid(SYS_DESCR_OID), tlv(0x04, b"Linux router 6.1")]);
        let name = sequence([oid(SYS_NAME_OID), tlv(0x04, b"gateway")]);
        let object_id = sequence([oid(SYS_OBJECT_ID_OID), oid(&[1, 3, 6, 1, 4, 1, 8072])]);
        let services = sequence([oid(SYS_SERVICES_OID), integer(72)]);
        let response_pdu = tlv(
            0xa2,
            &concat([
                integer(7),
                integer(0),
                integer(0),
                tlv(0x30, &concat([descr, name, object_id, services])),
            ]),
        );
        let packet = sequence([integer(1), tlv(0x04, b"public"), response_pdu]);

        let info = parse_system_response(&packet).unwrap();

        assert_eq!(info.sys_descr.as_deref(), Some("Linux router 6.1"));
        assert_eq!(info.sys_name.as_deref(), Some("gateway"));
        assert_eq!(info.sys_object_id.as_deref(), Some("1.3.6.1.4.1.8072"));
        assert_eq!(info.sys_services, Some(72));
    }
}
