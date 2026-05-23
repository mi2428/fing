//! Shallow TCP/HTTP/TLS enrichment probes.
//!
//! These probes only run for hosts already found by discovery. They collect
//! banners, selected HTTP headers, favicon hashes, and TLS certificate metadata
//! as identity evidence without attempting vulnerability checks or enumeration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream as StdTcpStream},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortProbe {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    #[serde(default)]
    pub http_headers: Vec<HttpHeader>,
    #[serde(default)]
    pub favicon: Option<FaviconFingerprint>,
    #[serde(default)]
    pub tls: Option<TlsCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaviconFingerprint {
    pub url: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsCertificate {
    pub sha256: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

const PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (80, "http"),
    (139, "netbios-ssn"),
    (443, "https"),
    (445, "smb"),
    (631, "ipp"),
    (5000, "upnp-http"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8080, "http-proxy"),
    (9100, "printer"),
];
const MAX_FAVICON_BYTES: usize = 256 * 1024;

// Deep probing stays deliberately narrow: only ports already useful for device
// identity are touched, and only for hosts discovered by ARP/mDNS/UPnP/etc. This
// keeps the tool in "inventory enrichment" territory rather than becoming a
// broad port scanner or vulnerability probe.
pub async fn probe_hosts_with_callback<F>(
    ips: Vec<IpAddr>,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    mut on_probe: F,
) -> HashMap<IpAddr, Vec<PortProbe>>
where
    F: FnMut(IpAddr, PortProbe),
{
    let mut tasks = JoinSet::new();

    for ip in ips {
        for (port, service) in PORTS {
            let limiter = Arc::clone(&limiter);
            let service = (*service).to_string();
            let port = *port;
            tasks.spawn(async move {
                let Ok(_permit) = limiter.acquire_owned().await else {
                    return None;
                };
                probe_port(ip, port, service, timeout)
                    .await
                    .map(|probe| (ip, probe))
            });
        }
    }

    let mut result = HashMap::<IpAddr, Vec<PortProbe>>::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((ip, probe))) = joined {
            on_probe(ip, probe.clone());
            result.entry(ip).or_default().push(probe);
        }
    }

    for probes in result.values_mut() {
        probes.sort_by_key(|probe| probe.port);
    }
    result
}

async fn probe_port(
    ip: IpAddr,
    port: u16,
    service: String,
    timeout: Duration,
) -> Option<PortProbe> {
    // A successful TCP connect is enough to record the service. Protocol-specific
    // reads below enrich the row when they succeed, but failure to read a banner
    // should not discard the open-port signal.
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;

    let mut probe = PortProbe {
        port,
        service: service.clone(),
        banner: None,
        http_headers: Vec::new(),
        favicon: None,
        tls: None,
    };

    match service.as_str() {
        "http" | "http-alt" | "http-proxy" | "upnp-http" => {
            // HTTP metadata often contains product strings even when a device
            // has no mDNS/UPnP name. Capture headers and favicon hashes as
            // evidence for rules, but do not classify directly here.
            if let Some(web) = web_probe(ip, port, false, timeout).await {
                probe.banner = web.banner;
                probe.http_headers = web.headers;
                probe.favicon = web.favicon;
            } else {
                probe.banner = http_banner(&mut stream, ip, timeout).await;
            }
        }
        "https" => {
            // TLS subjects/issuers are useful for appliance UIs and embedded
            // web servers. Invalid/self-signed certs are accepted because local
            // devices commonly use them; the hash is the fingerprint.
            if let Some(web) = web_probe(ip, port, true, timeout).await {
                probe.banner = web.banner;
                probe.http_headers = web.headers;
                probe.favicon = web.favicon;
            }
            probe.tls = tls_certificate_probe(ip, port, timeout).await;
        }
        "ssh" | "ftp" | "telnet" => {
            probe.banner = passive_banner(&mut stream, timeout).await;
        }
        _ => {}
    }

    Some(probe)
}

async fn http_banner(stream: &mut TcpStream, ip: IpAddr, timeout: Duration) -> Option<String> {
    let request = format!("HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buffer = [0_u8; 1024];
    let len = tokio::time::timeout(timeout, stream.read(&mut buffer))
        .await
        .ok()?
        .ok()?;
    sanitize_banner(&buffer[..len])
}

async fn passive_banner(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
    let mut buffer = [0_u8; 512];
    let len = tokio::time::timeout(timeout, stream.read(&mut buffer))
        .await
        .ok()?
        .ok()?;
    sanitize_banner(&buffer[..len])
}

fn sanitize_banner(bytes: &[u8]) -> Option<String> {
    // Banners can include prompts, terminal control bytes, or long error pages.
    // Keep a compact printable prefix that is safe to place in evidence and logs.
    let text = String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join(" | ");
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(240).collect())
    }
}

struct WebProbe {
    banner: Option<String>,
    headers: Vec<HttpHeader>,
    favicon: Option<FaviconFingerprint>,
}

async fn web_probe(ip: IpAddr, port: u16, https: bool, timeout: Duration) -> Option<WebProbe> {
    tokio::task::spawn_blocking(move || blocking_web_probe(ip, port, https, timeout))
        .await
        .ok()
        .flatten()
}

fn blocking_web_probe(ip: IpAddr, port: u16, https: bool, timeout: Duration) -> Option<WebProbe> {
    // reqwest's blocking client handles redirects and invalid local certs more
    // robustly than a hand-rolled HTTP parser. It is isolated on the blocking
    // pool by the async wrapper.
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()
        .ok()?;
    let scheme = if https { "https" } else { "http" };
    let base_url = format!("{scheme}://{ip}:{port}");

    let response = client.head(&base_url).send().ok()?;
    let mut headers = interesting_headers(response.headers());
    let banner = http_banner_from_response(response.status().as_u16(), &headers);

    let favicon_url = format!("{base_url}/favicon.ico");
    let favicon = client
        .get(&favicon_url)
        .send()
        .ok()
        .and_then(|response| favicon_fingerprint_from_response(response, favicon_url));

    headers.truncate(16);
    Some(WebProbe {
        banner,
        headers,
        favicon,
    })
}

fn favicon_fingerprint_from_response(
    response: reqwest::blocking::Response,
    url: String,
) -> Option<FaviconFingerprint> {
    if !response.status().is_success() {
        return None;
    }
    let content_length = response.content_length();
    favicon_fingerprint_from_reader(response, url, content_length)
}

fn favicon_fingerprint_from_reader(
    reader: impl Read,
    url: String,
    content_length: Option<u64>,
) -> Option<FaviconFingerprint> {
    // Favicons are fingerprints, not payloads. Reject known-oversized bodies
    // before reading, and cap unknown-size reads to MAX_FAVICON_BYTES + 1 so a
    // misconfigured local device cannot force an unbounded allocation here.
    if content_length.is_some_and(|len| len > MAX_FAVICON_BYTES as u64) {
        return None;
    }

    let mut bytes = Vec::new();
    let mut limited = reader.take(MAX_FAVICON_BYTES as u64 + 1);
    limited.read_to_end(&mut bytes).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_FAVICON_BYTES {
        return None;
    }

    Some(FaviconFingerprint {
        url,
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes: bytes.len(),
    })
}

async fn tls_certificate_probe(ip: IpAddr, port: u16, timeout: Duration) -> Option<TlsCertificate> {
    tokio::task::spawn_blocking(move || blocking_tls_certificate_probe(ip, port, timeout))
        .await
        .ok()
        .flatten()
}

fn blocking_tls_certificate_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<TlsCertificate> {
    let stream = StdTcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let tls = connector.connect(&ip.to_string(), stream).ok()?;
    let cert = tls.peer_certificate().ok()??;
    let der = cert.to_der().ok()?;
    let sha256 = hex::encode(Sha256::digest(&der));
    let parsed = x509_parser::parse_x509_certificate(&der).ok();

    let (subject, issuer, not_before, not_after) = parsed
        .as_ref()
        .map(|(_, cert)| {
            (
                Some(cert.subject().to_string()),
                Some(cert.issuer().to_string()),
                Some(cert.validity().not_before.to_string()),
                Some(cert.validity().not_after.to_string()),
            )
        })
        .unwrap_or((None, None, None, None));

    Some(TlsCertificate {
        sha256,
        subject,
        issuer,
        not_before,
        not_after,
    })
}

fn interesting_headers(headers: &reqwest::header::HeaderMap) -> Vec<HttpHeader> {
    // Product and framework headers carry the most identity value. Include all
    // x-* headers because appliances frequently expose model data there.
    headers
        .iter()
        .filter_map(|(name, value)| {
            let key = name.as_str().to_ascii_lowercase();
            let interesting = matches!(
                key.as_str(),
                "server"
                    | "x-powered-by"
                    | "www-authenticate"
                    | "via"
                    | "location"
                    | "content-type"
                    | "x-upnp-model"
                    | "x-apple-processing"
                    | "x-plex-protocol"
            ) || key.starts_with("x-");
            if !interesting {
                return None;
            }
            Some(HttpHeader {
                name: key,
                value: value.to_str().ok()?.chars().take(180).collect(),
            })
        })
        .collect()
}

fn http_banner_from_response(status: u16, headers: &[HttpHeader]) -> Option<String> {
    let mut lines = vec![format!("HTTP {status}")];
    lines.extend(
        headers
            .iter()
            .take(4)
            .map(|header| format!("{}: {}", header.name, header.value)),
    );
    Some(lines.join(" | "))
}

pub fn http_server_from_banner(banner: &str) -> Option<String> {
    banner.split('|').find_map(|line| {
        let line = line.trim();
        line.strip_prefix("Server:")
            .or_else(|| line.strip_prefix("server:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

pub fn header_evidence_key(name: &str) -> String {
    format!("http_header_{}", name.replace('-', "_"))
}

pub fn os_hint_from_banner(service: &str, banner: &str) -> Option<(&'static str, f32)> {
    let lower = banner.to_ascii_lowercase();
    if service == "ssh" && lower.contains("dropbear") {
        Some(("Linux/embedded", 0.6))
    } else if service == "ssh" && lower.contains("openssh") {
        Some(("Unix-like", 0.55))
    } else if lower.contains("microsoft") || lower.contains("windows") {
        Some(("Windows", 0.6))
    } else {
        None
    }
}

pub fn device_type_hint_from_port(port: u16) -> Option<(&'static str, f32)> {
    match port {
        631 | 9100 => Some(("printer", 0.65)),
        445 | 139 => Some(("smb-capable", 0.45)),
        80 | 443 | 8080 | 8000 | 8008 => Some(("web-service", 0.35)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_http_server_header() {
        let banner = "HTTP/1.1 200 OK | Server: nginx/1.25 | Date: now";
        assert_eq!(
            http_server_from_banner(banner).as_deref(),
            Some("nginx/1.25")
        );
    }

    #[test]
    fn derives_os_hint_from_ssh_banner() {
        assert_eq!(
            os_hint_from_banner("ssh", "SSH-2.0-OpenSSH_9.8").unwrap(),
            ("Unix-like", 0.55)
        );
    }

    #[test]
    fn derives_device_type_from_printer_port() {
        assert_eq!(device_type_hint_from_port(9100).unwrap(), ("printer", 0.65));
    }

    #[test]
    fn normalizes_http_header_evidence_keys() {
        assert_eq!(
            header_evidence_key("x-powered-by"),
            "http_header_x_powered_by"
        );
    }

    #[test]
    fn builds_http_banner_from_headers() {
        let banner = http_banner_from_response(
            200,
            &[HttpHeader {
                name: "server".to_string(),
                value: "nginx".to_string(),
            }],
        )
        .unwrap();

        assert!(banner.contains("HTTP 200"));
        assert!(banner.contains("server: nginx"));
    }

    #[test]
    fn favicon_fingerprint_rejects_large_content_length_without_reading() {
        struct PanicReader;

        impl std::io::Read for PanicReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("oversized favicon should be rejected before reading")
            }
        }

        let fingerprint = favicon_fingerprint_from_reader(
            PanicReader,
            "http://192.168.1.1/favicon.ico".to_string(),
            Some(MAX_FAVICON_BYTES as u64 + 1),
        );

        assert!(fingerprint.is_none());
    }

    #[test]
    fn favicon_fingerprint_rejects_unknown_size_body_above_limit() {
        let body = vec![b'a'; MAX_FAVICON_BYTES + 1];
        let fingerprint = favicon_fingerprint_from_reader(
            std::io::Cursor::new(body),
            "http://192.168.1.1/favicon.ico".to_string(),
            None,
        );

        assert!(fingerprint.is_none());
    }
}
