//! SMB2 identity probe.
//!
//! The probe stops at negotiation/session-setup metadata. It does not
//! authenticate, enumerate shares, or request file data; the goal is to collect
//! stack, dialect, signing, and host-name evidence for device identification.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmbInfo {
    pub dialect: Option<String>,
    pub signing_required: Option<bool>,
    pub server_guid: Option<String>,
    pub native_os: Option<String>,
    pub native_lanman: Option<String>,
    pub netbios_computer_name: Option<String>,
    pub dns_computer_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtlmHostInfo {
    pub target_name: Option<String>,
    pub netbios_computer_name: Option<String>,
    pub netbios_domain_name: Option<String>,
    pub dns_computer_name: Option<String>,
    pub dns_domain_name: Option<String>,
}

const MAX_SMB_RESPONSE_BYTES: usize = 128 * 1024;

pub async fn probe_hosts_with_callback<F>(
    ips: Vec<IpAddr>,
    local_addr: IpAddr,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    mut on_result: F,
) -> HashMap<IpAddr, SmbInfo>
where
    F: FnMut(IpAddr, SmbInfo),
{
    let mut tasks = JoinSet::new();

    for ip in ips {
        let limiter = Arc::clone(&limiter);
        tasks.spawn(async move {
            let Ok(_permit) = limiter.acquire_owned().await else {
                return None;
            };
            probe_one(ip, local_addr, timeout)
                .await
                .map(|info| (ip, info))
        });
    }

    let mut result = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((ip, info))) = joined {
            on_result(ip, info.clone());
            result.insert(ip, info);
        }
    }
    result
}

async fn probe_one(ip: IpAddr, local_addr: IpAddr, timeout: Duration) -> Option<SmbInfo> {
    // The negotiate request is a low-impact identity probe: it stops before
    // authentication and records protocol metadata rather than enumerating
    // shares. That is enough to separate Windows, Samba, NAS, and embedded SMB
    // stacks when combined with vendor/name evidence.
    let mut stream = super::connect_tcp_from(local_addr, ip, 445, timeout).await?;
    let request = smb2_negotiate_request();
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .ok()?
        .ok()?;

    let packet = read_netbios_session_packet(&mut stream, timeout, MAX_SMB_RESPONSE_BYTES).await?;
    let mut info = parse_smb2_negotiate_response(&packet)?;
    if let Some(host_info) = smb2_ntlm_hostname_probe(&mut stream, timeout).await {
        info.netbios_computer_name = host_info.netbios_computer_name;
        info.dns_computer_name = host_info.dns_computer_name;
    }
    Some(info)
}

pub fn smb2_negotiate_request() -> Vec<u8> {
    // Offer modern SMB2/3 dialects in one negotiate request. The server's chosen
    // dialect and signing mode are enough to identify many NAS and Windows hosts.
    let dialects = [0x0202_u16, 0x0210, 0x0300, 0x0302, 0x0311];
    let mut body = Vec::new();
    push_u16(&mut body, 36);
    push_u16(&mut body, dialects.len() as u16);
    push_u16(&mut body, 1);
    push_u16(&mut body, 0);
    push_u32(&mut body, 0);
    body.extend_from_slice(&[
        0x46, 0x49, 0x4e, 0x47, 0x2d, 0x52, 0x53, 0x2d, 0x53, 0x4d, 0x42, 0x32, 0x30, 0x32, 0x36,
        0x00,
    ]);
    push_u32(&mut body, 0);
    push_u16(&mut body, 0);
    push_u16(&mut body, 0);
    for dialect in dialects {
        push_u16(&mut body, dialect);
    }

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&smb2_header());
    packet.extend_from_slice(&body);
    let len = (packet.len() - 4) as u32;
    packet[1] = ((len >> 16) & 0xff) as u8;
    packet[2] = ((len >> 8) & 0xff) as u8;
    packet[3] = (len & 0xff) as u8;
    packet
}

pub fn parse_smb2_negotiate_response(buf: &[u8]) -> Option<SmbInfo> {
    // SMB over TCP is usually wrapped in a 4-byte NetBIOS session header. Parser
    // helpers accept both wrapped packets and raw SMB2 frames used in tests.
    let start = smb2_start(buf)?;
    if start + 64 + 64 > buf.len() {
        return None;
    }
    let header = &buf[start..start + 64];
    if header.get(12..14) != Some(&[0x00, 0x00]) {
        return None;
    }
    let status = read_u32_le(header, 8)?;
    if status != 0 {
        return None;
    }

    let body = &buf[start + 64..];
    if read_u16_le(body, 0)? != 65 {
        return None;
    }
    let security_mode = read_u16_le(body, 2)?;
    let dialect = read_u16_le(body, 4)?;
    let guid = body.get(8..24).map(hex_guid);
    let security_offset = read_u16_le(body, 56).unwrap_or(0) as usize;
    let security_len = read_u16_le(body, 58).unwrap_or(0) as usize;
    let security_blob = start
        .checked_add(security_offset)
        .and_then(|security_start| {
            security_start
                .checked_add(security_len)
                .and_then(|security_end| buf.get(security_start..security_end))
        })
        .filter(|_| security_len > 0)
        .unwrap_or(&[]);
    // Some servers leak native OS/LANMAN strings in the security blob. Treat
    // them as hints only; the NTLM challenge below gives cleaner host names.
    let ascii = ascii_tokens(security_blob);

    Some(SmbInfo {
        dialect: Some(dialect_name(dialect).to_string()),
        signing_required: Some(security_mode & 0x0002 != 0),
        server_guid: guid,
        native_os: ascii
            .iter()
            .find(|value| value.to_ascii_lowercase().contains("windows"))
            .cloned(),
        native_lanman: ascii
            .iter()
            .find(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("samba") || lower.contains("lan manager")
            })
            .cloned(),
        netbios_computer_name: None,
        dns_computer_name: None,
    })
}

async fn smb2_ntlm_hostname_probe(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Option<NtlmHostInfo> {
    let request = smb2_session_setup_request();
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .ok()?
        .ok()?;

    let packet = read_netbios_session_packet(stream, timeout, MAX_SMB_RESPONSE_BYTES).await?;
    parse_smb2_session_setup_ntlm_host_info(&packet)
}

async fn read_netbios_session_packet<R>(
    stream: &mut R,
    timeout: Duration,
    max_payload_len: usize,
) -> Option<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, async {
        loop {
            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).await.ok()?;
            let payload_len = netbios_session_payload_len(header);
            if header[0] == 0x85 && payload_len == 0 {
                continue;
            }
            if header[0] != 0 || payload_len == 0 || payload_len > max_payload_len {
                return None;
            }

            let mut packet = Vec::with_capacity(4 + payload_len);
            packet.extend_from_slice(&header);
            packet.resize(4 + payload_len, 0);
            stream.read_exact(&mut packet[4..]).await.ok()?;
            return Some(packet);
        }
    })
    .await
    .ok()
    .flatten()
}

pub fn smb2_session_setup_request() -> Vec<u8> {
    let security_blob = spnego_ntlm_negotiate_blob();
    let mut body = Vec::new();
    push_u16(&mut body, 25);
    body.push(0);
    body.push(1);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    push_u16(&mut body, (64 + 24) as u16);
    push_u16(&mut body, security_blob.len() as u16);
    push_u64(&mut body, 0);
    body.extend_from_slice(&security_blob);

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0, 0, 0, 0]);
    let mut header = smb2_header();
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[24..32].copy_from_slice(&1_u64.to_le_bytes());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&body);
    set_netbios_len(&mut packet);
    packet
}

pub fn parse_smb2_session_setup_ntlm_host_info(buf: &[u8]) -> Option<NtlmHostInfo> {
    let start = smb2_start(buf)?;
    if start + 64 + 8 > buf.len() {
        return None;
    }
    let header = &buf[start..start + 64];
    if read_u16_le(header, 12)? != 1 {
        return None;
    }
    let status = read_u32_le(header, 8)?;
    if status != 0 && status != 0xc000_0016 {
        return None;
    }

    let body = &buf[start + 64..];
    if read_u16_le(body, 0)? != 9 {
        return None;
    }
    let security_offset = read_u16_le(body, 4)? as usize;
    let security_len = read_u16_le(body, 6)? as usize;
    let security_start = start.checked_add(security_offset)?;
    let security_end = security_start.checked_add(security_len)?;
    let security_blob = buf.get(security_start..security_end)?;
    parse_ntlm_challenge_host_info(security_blob)
}

pub fn parse_ntlm_challenge_host_info(blob: &[u8]) -> Option<NtlmHostInfo> {
    // The NTLM challenge target-info AV pairs often contain NetBIOS and DNS host
    // names before authentication completes.
    let ntlm_start = find_bytes(blob, b"NTLMSSP\0")?;
    let ntlm = blob.get(ntlm_start..)?;
    if read_u32_le(ntlm, 8)? != 2 {
        return None;
    }

    let flags = read_u32_le(ntlm, 20).unwrap_or(0);
    let unicode = flags & 0x0000_0001 != 0;
    let target_name =
        read_ntlm_security_buffer(ntlm, 12).and_then(|value| decode_ntlm_string(value, unicode));
    let target_info = read_ntlm_security_buffer(ntlm, 40).unwrap_or(&[]);
    let mut info = NtlmHostInfo {
        target_name,
        ..NtlmHostInfo::default()
    };

    let mut offset = 0;
    while offset + 4 <= target_info.len() {
        let av_id = read_u16_le(target_info, offset)?;
        let len = read_u16_le(target_info, offset + 2)? as usize;
        offset += 4;
        if av_id == 0 {
            break;
        }
        let value = target_info.get(offset..offset + len)?;
        let decoded = decode_utf16le(value)?;
        match av_id {
            1 => info.netbios_computer_name = Some(decoded),
            2 => info.netbios_domain_name = Some(decoded),
            3 => info.dns_computer_name = Some(decoded),
            4 => info.dns_domain_name = Some(decoded),
            _ => {}
        }
        offset += len;
    }

    Some(info)
}

fn smb2_header() -> [u8; 64] {
    let mut header = [0_u8; 64];
    header[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    header[4..6].copy_from_slice(&64_u16.to_le_bytes());
    header[12..14].copy_from_slice(&0_u16.to_le_bytes());
    header[14..16].copy_from_slice(&1_u16.to_le_bytes());
    header[20..24].copy_from_slice(&0_u32.to_le_bytes());
    header[24..32].copy_from_slice(&0_u64.to_le_bytes());
    header[32..36].copy_from_slice(&0xfeff_u32.to_le_bytes());
    header
}

fn smb2_start(buf: &[u8]) -> Option<usize> {
    if buf.starts_with(&[0xfe, b'S', b'M', b'B']) {
        return Some(0);
    }
    if buf.len() >= 8 && buf[4..8] == [0xfe, b'S', b'M', b'B'] {
        return Some(4);
    }
    None
}

fn netbios_session_payload_len(header: [u8; 4]) -> usize {
    ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize
}

fn dialect_name(dialect: u16) -> &'static str {
    match dialect {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        _ => "SMB unknown",
    }
}

fn ascii_tokens(bytes: &[u8]) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            if current.len() >= 5 {
                tokens.push(String::from_utf8_lossy(&current).trim().to_string());
            }
            current.clear();
        }
    }
    if current.len() >= 5 {
        tokens.push(String::from_utf8_lossy(&current).trim().to_string());
    }
    tokens
}

fn hex_guid(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn spnego_ntlm_negotiate_blob() -> Vec<u8> {
    // Wrap a minimal NTLMSSP negotiate token in SPNEGO so servers respond with
    // a challenge that includes target-info names.
    let mech_types = der_tlv(
        0xa0,
        &der_tlv(0x30, &der_oid(&[1, 3, 6, 1, 4, 1, 311, 2, 2, 10])),
    );
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, &ntlm_negotiate_message()));
    let neg_token_init = der_tlv(0xa0, &der_tlv(0x30, &[mech_types, mech_token].concat()));
    der_tlv(
        0x60,
        &[der_oid(&[1, 3, 6, 1, 5, 5, 2]), neg_token_init].concat(),
    )
}

fn ntlm_negotiate_message() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\0");
    push_u32(&mut msg, 1);
    push_u32(&mut msg, 0x0088_8207);
    push_u16(&mut msg, 0);
    push_u16(&mut msg, 0);
    push_u32(&mut msg, 0);
    push_u16(&mut msg, 0);
    push_u16(&mut msg, 0);
    push_u32(&mut msg, 0);
    msg
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    write_der_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn der_oid(parts: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push((parts[0] * 40 + parts[1]) as u8);
    for part in &parts[2..] {
        encode_base128(*part, &mut body);
    }
    der_tlv(0x06, &body)
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

fn write_der_len(len: usize, out: &mut Vec<u8>) {
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

fn read_ntlm_security_buffer(buf: &[u8], offset: usize) -> Option<&[u8]> {
    // NTLM security buffers store length and absolute payload offset. Bounds
    // checks here keep malformed challenge blobs from panicking parsers.
    let len = read_u16_le(buf, offset)? as usize;
    let data_offset = read_u32_le(buf, offset + 4)? as usize;
    buf.get(data_offset..data_offset + len)
}

fn decode_ntlm_string(bytes: &[u8], unicode: bool) -> Option<String> {
    if unicode {
        decode_utf16le(bytes)
    } else {
        Some(String::from_utf8_lossy(bytes).trim().to_string())
    }
    .filter(|value| !value.is_empty())
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .ok()
        .map(|value| value.trim_end_matches('\0').trim().to_string())
        .filter(|value| !value.is_empty())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn set_netbios_len(packet: &mut [u8]) {
    let len = (packet.len() - 4) as u32;
    packet[1] = ((len >> 16) & 0xff) as u8;
    packet[2] = ((len >> 8) & 0xff) as u8;
    packet[3] = (len & 0xff) as u8;
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
    ]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
        *buf.get(offset + 2)?,
        *buf.get(offset + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_smb2_negotiate_request() {
        let packet = smb2_negotiate_request();

        assert_eq!(&packet[4..8], &[0xfe, b'S', b'M', b'B']);
        assert!(
            packet
                .windows(2)
                .any(|window| window == 0x0311_u16.to_le_bytes())
        );
    }

    #[test]
    fn parses_smb2_negotiate_response() {
        let packet = smb2_negotiate_response_packet();

        let parsed = parse_smb2_negotiate_response(&packet).unwrap();

        assert_eq!(parsed.dialect.as_deref(), Some("SMB 3.1.1"));
        assert_eq!(parsed.signing_required, Some(true));
        assert_eq!(parsed.native_os.as_deref(), Some("Windows Server"));
    }

    #[tokio::test]
    async fn reads_netbios_session_packet_across_fragmented_writes() {
        let packet = smb2_negotiate_response_packet();
        let expected = packet.clone();
        let (mut client, mut server) = tokio::io::duplex(8);
        let writer = tokio::spawn(async move {
            for chunk in packet.chunks(3) {
                server.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let read = read_netbios_session_packet(
            &mut client,
            Duration::from_secs(1),
            MAX_SMB_RESPONSE_BYTES,
        )
        .await
        .unwrap();
        writer.await.unwrap();

        assert_eq!(read, expected);
        assert!(parse_smb2_negotiate_response(&read).is_some());
    }

    #[test]
    fn builds_smb2_session_setup_request_with_ntlmssp() {
        let packet = smb2_session_setup_request();

        assert_eq!(&packet[4..8], &[0xfe, b'S', b'M', b'B']);
        assert_eq!(read_u16_le(&packet[4..68], 12), Some(1));
        assert!(packet.windows(8).any(|window| window == b"NTLMSSP\0"));
    }

    #[test]
    fn parses_ntlm_challenge_host_info() {
        let blob = ntlm_challenge_blob("WORKSTATION01", "workstation01.example.test");
        let parsed = parse_ntlm_challenge_host_info(&blob).unwrap();

        assert_eq!(
            parsed.netbios_computer_name.as_deref(),
            Some("WORKSTATION01")
        );
        assert_eq!(
            parsed.dns_computer_name.as_deref(),
            Some("workstation01.example.test")
        );
    }

    #[test]
    fn parses_session_setup_response_host_info() {
        let security = ntlm_challenge_blob("WINBOX", "winbox.example.test");
        let mut packet = vec![0, 0, 0, 0];
        let mut header = smb2_header();
        header[8..12].copy_from_slice(&0xc000_0016_u32.to_le_bytes());
        header[12..14].copy_from_slice(&1_u16.to_le_bytes());
        packet.extend_from_slice(&header);
        let body_start = packet.len();
        packet.resize(body_start + 8, 0);
        packet[body_start..body_start + 2].copy_from_slice(&9_u16.to_le_bytes());
        let security_offset = (64 + 8) as u16;
        packet[body_start + 4..body_start + 6].copy_from_slice(&security_offset.to_le_bytes());
        packet[body_start + 6..body_start + 8]
            .copy_from_slice(&(security.len() as u16).to_le_bytes());
        packet.extend_from_slice(&security);
        set_netbios_len(&mut packet);

        let parsed = parse_smb2_session_setup_ntlm_host_info(&packet).unwrap();

        assert_eq!(parsed.netbios_computer_name.as_deref(), Some("WINBOX"));
        assert_eq!(
            parsed.dns_computer_name.as_deref(),
            Some("winbox.example.test")
        );
    }

    fn ntlm_challenge_blob(nb_name: &str, dns_name: &str) -> Vec<u8> {
        let target_name = utf16le("EXAMPLE");
        let mut target_info = Vec::new();
        push_av_pair(&mut target_info, 1, &utf16le(nb_name));
        push_av_pair(&mut target_info, 3, &utf16le(dns_name));
        push_av_pair(&mut target_info, 0, &[]);

        let target_name_offset = 56_u32;
        let target_info_offset = target_name_offset + target_name.len() as u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(b"NTLMSSP\0");
        push_u32(&mut blob, 2);
        push_security_buffer(&mut blob, target_name.len() as u16, target_name_offset);
        push_u32(&mut blob, 0x0088_8207);
        blob.extend_from_slice(&[0_u8; 8]);
        blob.extend_from_slice(&[0_u8; 8]);
        push_security_buffer(&mut blob, target_info.len() as u16, target_info_offset);
        blob.extend_from_slice(&[0_u8; 8]);
        blob.extend_from_slice(&target_name);
        blob.extend_from_slice(&target_info);
        blob
    }

    fn push_security_buffer(out: &mut Vec<u8>, len: u16, offset: u32) {
        push_u16(out, len);
        push_u16(out, len);
        push_u32(out, offset);
    }

    fn push_av_pair(out: &mut Vec<u8>, av_id: u16, value: &[u8]) {
        push_u16(out, av_id);
        push_u16(out, value.len() as u16);
        out.extend_from_slice(value);
    }

    fn utf16le(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn smb2_negotiate_response_packet() -> Vec<u8> {
        let mut packet = vec![0, 0, 0, 0];
        packet.extend_from_slice(&smb2_header());
        let body_start = packet.len();
        packet.resize(body_start + 64, 0);
        packet[body_start..body_start + 2].copy_from_slice(&65_u16.to_le_bytes());
        packet[body_start + 2..body_start + 4].copy_from_slice(&2_u16.to_le_bytes());
        packet[body_start + 4..body_start + 6].copy_from_slice(&0x0311_u16.to_le_bytes());
        packet[body_start + 8..body_start + 24].copy_from_slice(&[1_u8; 16]);
        let security = b"Windows Server\x00";
        let security_offset = (64 + 64) as u16;
        packet.extend_from_slice(security);
        packet[body_start + 56..body_start + 58].copy_from_slice(&security_offset.to_le_bytes());
        packet[body_start + 58..body_start + 60]
            .copy_from_slice(&(security.len() as u16).to_le_bytes());
        set_netbios_len(&mut packet);
        packet
    }
}
