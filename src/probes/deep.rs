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
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Semaphore, watch},
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeOptions {
    pub deep: bool,
    pub ssh: bool,
    pub http: bool,
    pub tls: bool,
}

impl ProbeOptions {
    pub fn any(self) -> bool {
        self.deep || self.ssh || self.http || self.tls
    }

    pub fn includes_deep_service(self, service: &str) -> bool {
        match service {
            "ssh" => self.ssh,
            _ => self.deep,
        }
    }
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
    local_addr: IpAddr,
    timeout: Duration,
    limiter: Arc<Semaphore>,
    options: ProbeOptions,
    mut on_probe: F,
) -> HashMap<IpAddr, Vec<PortProbe>>
where
    F: FnMut(IpAddr, PortProbe),
{
    let mut tasks = JoinSet::new();

    for ip in ips {
        for &(port, service) in PORTS {
            if !probe_source_enabled(service, options) {
                continue;
            }
            let limiter = Arc::clone(&limiter);
            let service = service.to_string();
            tasks.spawn(async move {
                let Ok(_permit) = limiter.acquire_owned().await else {
                    return None;
                };
                probe_port(ip, local_addr, port, service, timeout, options)
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
    local_addr: IpAddr,
    port: u16,
    service: String,
    timeout: Duration,
    options: ProbeOptions,
) -> Option<PortProbe> {
    // A successful TCP connect is enough to record the service. Protocol-specific
    // reads below enrich the row when they succeed, but failure to read a banner
    // should not discard the open-port signal.
    let mut stream = super::connect_tcp_from(local_addr, ip, port, timeout).await?;

    let mut probe = PortProbe {
        port,
        service: service.clone(),
        banner: None,
        http_headers: Vec::new(),
        favicon: None,
        tls: None,
    };

    match service.as_str() {
        "http" | "http-alt" | "http-proxy" | "upnp-http" if options.deep || options.http => {
            // HTTP metadata often contains product strings even when a device
            // has no mDNS/UPnP name. Capture headers and favicon hashes as
            // evidence for rules, but do not classify directly here.
            if let Some(web) = web_probe(ip, local_addr, port, false, timeout, options.http).await {
                probe.banner = web.banner;
                probe.http_headers = web.headers;
                probe.favicon = web.favicon;
            } else if options.deep {
                probe.banner = http_banner(&mut stream, ip, timeout).await;
            }
        }
        "https" => {
            // TLS subjects/issuers are useful for appliance UIs and embedded
            // web servers. Invalid/self-signed certs are accepted because local
            // devices commonly use them; the hash is the fingerprint.
            if (options.deep || options.http)
                && let Some(web) =
                    web_probe(ip, local_addr, port, true, timeout, options.http).await
            {
                probe.banner = web.banner;
                probe.http_headers = web.headers;
                probe.favicon = web.favicon;
            }
            if options.tls {
                probe.tls = tls_certificate_probe(ip, local_addr, port, timeout).await;
            }
        }
        "ssh" if options.ssh => {
            probe.banner = passive_banner(&mut stream, timeout).await;
        }
        "ftp" | "telnet" if options.deep => {
            probe.banner = passive_banner(&mut stream, timeout).await;
        }
        _ => {}
    }

    probe_has_enabled_evidence(&probe, options).then_some(probe)
}

fn probe_source_enabled(service: &str, options: ProbeOptions) -> bool {
    options.includes_deep_service(service)
        || (options.http && web_probe_service(service))
        || (options.tls && service == "https")
}

fn web_probe_service(service: &str) -> bool {
    matches!(
        service,
        "http" | "http-alt" | "http-proxy" | "upnp-http" | "https"
    )
}

fn probe_has_enabled_evidence(probe: &PortProbe, options: ProbeOptions) -> bool {
    options.includes_deep_service(&probe.service)
        || (options.http && (!probe.http_headers.is_empty() || probe.favicon.is_some()))
        || (options.tls && probe.tls.is_some())
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

async fn web_probe(
    ip: IpAddr,
    local_addr: IpAddr,
    port: u16,
    https: bool,
    timeout: Duration,
    fetch_favicon: bool,
) -> Option<WebProbe> {
    run_blocking_probe(move |cancel| {
        blocking_web_probe(ip, local_addr, port, https, timeout, fetch_favicon, || {
            cancel.has_changed().is_err()
        })
    })
    .await
}

async fn run_blocking_probe<T: Send + 'static>(
    probe: impl FnOnce(watch::Receiver<()>) -> Option<T> + Send + 'static,
) -> Option<T> {
    // Dropping the async owner closes this channel even if spawn_blocking was
    // already running. The queued closure also checks before starting traffic.
    let (alive, cancel) = watch::channel(());
    let result = tokio::task::spawn_blocking(move || probe(cancel))
        .await
        .ok()
        .flatten();
    drop(alive);
    result
}

fn blocking_web_probe(
    ip: IpAddr,
    local_addr: IpAddr,
    port: u16,
    https: bool,
    timeout: Duration,
    fetch_favicon: bool,
    mut should_stop: impl FnMut() -> bool,
) -> Option<WebProbe> {
    if should_stop() || !super::same_ip_family(local_addr, ip) {
        return None;
    }

    // reqwest's blocking client handles redirects and invalid local certs more
    // robustly than a hand-rolled HTTP parser. It is isolated on the blocking
    // pool by the async wrapper.
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .local_address(local_addr)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let scheme = if https { "https" } else { "http" };
    let base_url = format!("{scheme}://{ip}:{port}");

    if should_stop() {
        return None;
    }
    let response = client.head(&base_url).send().ok()?;
    let mut headers = interesting_headers(response.headers());
    let banner = http_banner_from_response(response.status().as_u16(), &headers);

    // An in-flight request may use its configured timeout, but cancellation must
    // not start the next request (notably the favicon GET after a slow HEAD).
    let favicon = if fetch_favicon && !should_stop() {
        let favicon_url = format!("{base_url}/favicon.ico");
        client
            .get(&favicon_url)
            .send()
            .ok()
            .and_then(|response| favicon_fingerprint_from_response(response, favicon_url))
    } else {
        None
    };

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

async fn tls_certificate_probe(
    ip: IpAddr,
    local_addr: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<TlsCertificate> {
    run_blocking_probe(move |cancel| {
        blocking_tls_certificate_probe(ip, local_addr, port, timeout, || {
            cancel.has_changed().is_err()
        })
    })
    .await
}

fn blocking_tls_certificate_probe(
    ip: IpAddr,
    local_addr: IpAddr,
    port: u16,
    timeout: Duration,
    mut should_stop: impl FnMut() -> bool,
) -> Option<TlsCertificate> {
    if should_stop() {
        return None;
    }
    let deadline = Instant::now().checked_add(timeout)?;
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let stream = super::connect_blocking_tcp_from(local_addr, ip, port, remaining)?;
    stream.set_nonblocking(true).ok()?;
    if should_stop() || Instant::now() >= deadline {
        return None;
    }
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let mut handshake = connector.connect(&ip.to_string(), stream);
    let tls = loop {
        if should_stop() || Instant::now() >= deadline {
            return None;
        }
        match handshake {
            Ok(tls) => break tls,
            Err(native_tls::HandshakeError::WouldBlock(pending)) => {
                // Nonblocking TLS cannot extend the absolute deadline by slowly
                // dribbling bytes; cancellation is checked at most every 10ms.
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                if should_stop() || Instant::now() >= deadline {
                    return None;
                }
                handshake = pending.handshake();
            }
            Err(native_tls::HandshakeError::Failure(_)) => return None,
        }
    };
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
    use std::{
        io::Write as _,
        net::{Ipv4Addr, TcpListener},
        sync::mpsc,
        thread,
        time::{Duration as StdDuration, Instant},
    };

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
    fn ssh_source_can_run_without_generic_deep_probes() {
        let options = ProbeOptions {
            deep: false,
            ssh: true,
            http: false,
            tls: false,
        };

        assert!(probe_source_enabled("ssh", options));
        assert!(!probe_source_enabled("ftp", options));
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
    fn cancellation_stops_blocking_probes_before_any_socket() {
        let ip = "192.0.2.10".parse().unwrap();
        let local = "192.0.2.1".parse().unwrap();
        assert!(
            blocking_web_probe(ip, local, 80, false, Duration::from_secs(1), true, || true)
                .is_none()
        );
        assert!(
            blocking_tls_certificate_probe(ip, local, 443, Duration::from_secs(1), || true)
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancellation_during_http_head_does_not_start_favicon_get() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(StdDuration::from_secs(1)))
                .unwrap();
            let mut request = [0; 1024];
            let len = stream.read(&mut request).unwrap();
            assert!(request[..len].starts_with(b"HEAD "));
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nServer: synthetic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + StdDuration::from_secs(2);
            while Instant::now() < deadline {
                if listener.accept().is_ok() {
                    return false;
                }
                if finished_rx.try_recv().is_ok() {
                    return true;
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            false
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let probe = tokio::spawn(run_blocking_probe(move |cancel| {
            let result =
                blocking_web_probe(ip, ip, port, false, Duration::from_secs(1), true, || {
                    cancel.has_changed().is_err()
                });
            let _ = finished_tx.send(());
            result
        }));
        tokio::time::timeout(Duration::from_secs(1), ready_rx)
            .await
            .unwrap()
            .unwrap();
        probe.abort();
        assert!(matches!(probe.await, Err(err) if err.is_cancelled()));
        release_tx.send(()).unwrap();
        assert!(
            tokio::task::spawn_blocking(move || server.join().unwrap())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn cancellation_and_deadline_bound_a_stalled_tls_handshake() {
        for cancel in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(1)))
                    .unwrap();
                ready_tx.send(()).unwrap();
                let mut buffer = [0; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => return true,
                        Ok(_) => {}
                        Err(_) => return false,
                    }
                }
            });
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let timeout = if cancel {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(100)
            };
            let probe = tokio::spawn(tls_certificate_probe(ip, ip, port, timeout));
            tokio::time::timeout(Duration::from_secs(1), ready_rx)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                probe.abort();
                assert!(probe.await.unwrap_err().is_cancelled());
            } else {
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), probe)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_none()
                );
            }
            assert!(
                tokio::task::spawn_blocking(move || server.join().unwrap())
                    .await
                    .unwrap()
            );
        }
    }

    #[test]
    fn web_probe_does_not_follow_redirects() {
        let redirect_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        redirect_listener.set_nonblocking(true).unwrap();
        let redirect_port = redirect_listener.local_addr().unwrap().port();
        let (hit_tx, hit_rx) = mpsc::channel();
        let redirect_target = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_millis(400);
            while Instant::now() < deadline {
                match redirect_listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                        let _ = hit_tx.send(());
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let redirect_url = format!("http://127.0.0.1:{redirect_port}/outside");
        let server = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_secs(2);
            let mut handled = 0;
            while handled < 2 && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(StdDuration::from_millis(10));
                    continue;
                };
                let mut request = [0_u8; 1024];
                let len = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..len]);
                let response = if request.starts_with("HEAD ") {
                    format!(
                        "HTTP/1.1 302 Found\r\n\
                         Location: {redirect_url}\r\n\
                         Server: redirector\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                };
                stream.write_all(response.as_bytes()).unwrap();
                handled += 1;
            }
        });

        let probe = blocking_web_probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            false,
            Duration::from_millis(500),
            true,
            || false,
        )
        .unwrap();

        server.join().unwrap();
        redirect_target.join().unwrap();

        assert!(hit_rx.try_recv().is_err());
        assert!(
            probe.banner.as_deref().is_some_and(|banner| {
                banner.contains("HTTP 302") && banner.contains("location:")
            })
        );
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
    fn self_signed_https_preserves_web_and_tls_fingerprints() {
        use std::io::{BufRead as _, BufReader};

        // Public, generated TEST-ONLY material: never use this key outside tests.
        // The self-signed DNS name deliberately does not match the loopback IP.
        const CERT: &[u8] = include_bytes!("fixtures/loopback-test-only-cert.pem");
        const KEY: &[u8] = include_bytes!("fixtures/loopback-test-only-key.pem");
        const FAVICON: &[u8] = b"synthetic test-only favicon";
        let identity = native_tls::Identity::from_pkcs8(CERT, KEY).unwrap();
        let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
        let der = native_tls::Certificate::from_pem(CERT)
            .unwrap()
            .to_der()
            .unwrap();
        let (_, certificate) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(
            certificate.subject().to_string(),
            "CN=fing-fixture.invalid, O=Fing Test Only"
        );
        assert_eq!(certificate.subject(), certificate.issuer());
        assert_eq!(
            certificate
                .subject_alternative_name()
                .unwrap()
                .unwrap()
                .value
                .general_names,
            [x509_parser::extensions::GeneralName::DNSName(
                "fing-fixture.invalid"
            )]
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let timeout = StdDuration::from_secs(3);

        thread::scope(|scope| {
            let server = scope.spawn(move || {
                let deadline = Instant::now() + StdDuration::from_secs(15);
                for expected in [Some("HEAD / HTTP/1.1"), Some("GET /favicon.ico HTTP/1.1"), None] {
                    let stream = loop {
                        assert!(Instant::now() < deadline, "TLS fixture accept timed out");
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(StdDuration::from_millis(10));
                            }
                            Err(error) => panic!("TLS fixture accept failed: {error}"),
                        }
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(timeout)).unwrap();
                    stream.set_write_timeout(Some(timeout)).unwrap();
                    let mut tls = acceptor.accept(stream).unwrap();
                    if let Some(expected) = expected {
                        let mut request = String::new();
                        BufReader::new(&mut tls).read_line(&mut request).unwrap();
                        assert_eq!(request.trim_end(), expected);
                        let body = if expected.starts_with("GET ") { FAVICON } else { &[] };
                        write!(tls, "HTTP/1.1 200 OK\r\nServer: fing-fixture\r\nX-Fixture: test-only\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                        tls.write_all(body).unwrap();
                        tls.flush().unwrap();
                    }
                }
            });
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let web = blocking_web_probe(ip, ip, port, true, timeout, true, || false);
            let tls = blocking_tls_certificate_probe(ip, ip, port, timeout, || false);
            server.join().unwrap();

            let web = web.expect(
                "production HTTPS probe must tolerate the self-signed/mismatched certificate",
            );
            let banner = web.banner.unwrap();
            assert!(banner.contains("HTTP 200") && banner.contains("server: fing-fixture"));
            assert!(web.headers.contains(&HttpHeader {
                name: "x-fixture".to_string(),
                value: "test-only".to_string()
            }));
            assert_eq!(
                web.favicon.unwrap(),
                FaviconFingerprint {
                    url: format!("https://127.0.0.1:{port}/favicon.ico"),
                    sha256: hex::encode(Sha256::digest(FAVICON)),
                    bytes: FAVICON.len(),
                }
            );
            assert_eq!(
                tls.expect(
                    "production TLS probe must tolerate the self-signed/mismatched certificate"
                ),
                TlsCertificate {
                    sha256: hex::encode(Sha256::digest(&der)),
                    subject: Some(certificate.subject().to_string()),
                    issuer: Some(certificate.issuer().to_string()),
                    not_before: Some(certificate.validity().not_before.to_string()),
                    not_after: Some(certificate.validity().not_after.to_string()),
                }
            );
        });
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
