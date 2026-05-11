//! UPnP/SSDP discovery and description parsing.
//!
//! SSDP gives immediate server/location/service hints, while optional device
//! description XML adds friendly names, manufacturer, model, and device type.
//! The scanner later decides how strongly to trust those facts.

use anyhow::{Context, Result};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpnpInfo {
    pub names: Vec<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub device_type: Option<String>,
    pub server: Option<String>,
    pub location: Option<String>,
    pub services: Vec<String>,
    pub usns: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsdpResponse {
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpnpDescription {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    pub device_type: Option<String>,
    pub services: Vec<String>,
}

pub fn ssdp_probe_with_callback<F>(
    interface_ip: Ipv4Addr,
    timeout: Duration,
    fetch_descriptions: bool,
    mut on_result: F,
) -> Result<HashMap<IpAddr, UpnpInfo>>
where
    F: FnMut(IpAddr, UpnpInfo),
{
    let socket = ssdp_socket(interface_ip)?;
    let request = ssdp_request();
    // Send twice because SSDP is UDP multicast and home devices commonly drop
    // one request while waking radios or low-power network stacks.
    for _ in 0..2 {
        socket
            .send_to(request.as_bytes(), SocketAddrV4::new(SSDP_ADDR, SSDP_PORT))
            .context("failed to send SSDP M-SEARCH")?;
    }

    let deadline = Instant::now() + timeout;
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("failed to build UPnP HTTP client")?;

    let mut responses = HashMap::<IpAddr, UpnpInfo>::new();
    let mut fetched_locations = HashSet::<String>::new();
    let mut buffer = [0_u8; 8192];

    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                let source_ip = source.ip();
                let Some(response) = parse_ssdp_response(&buffer[..len]) else {
                    continue;
                };
                let info = responses.entry(source_ip).or_default();
                merge_ssdp_headers(info, &response.headers);
                on_result(source_ip, info.clone());

                // Fetch each LOCATION once per scan. Several SSDP responses from
                // the same device often point at the same XML description.
                if fetch_descriptions
                    && let Some(location) = info.location.clone()
                    && fetched_locations.insert(location.clone())
                    && let Ok(description) = fetch_description(&client, &location)
                {
                    merge_description(info, description);
                    on_result(source_ip, info.clone());
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err).context("failed to read SSDP response"),
        }
    }

    Ok(responses)
}

fn ssdp_socket(interface_ip: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_multicast_if_v4(&interface_ip)?;
    socket.set_multicast_ttl_v4(2)?;
    Ok(socket.into())
}

fn ssdp_request() -> &'static str {
    "M-SEARCH * HTTP/1.1\r\n\
     HOST: 239.255.255.250:1900\r\n\
     MAN: \"ssdp:discover\"\r\n\
     MX: 1\r\n\
     ST: ssdp:all\r\n\
     USER-AGENT: fing/0.1 UPnP/1.1\r\n\
     \r\n"
}

pub fn parse_ssdp_response(buf: &[u8]) -> Option<SsdpResponse> {
    // SSDP is HTTP-like but not full HTTP. A small tolerant parser is enough and
    // avoids rejecting devices that vary header casing or line endings.
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.lines();
    let status = lines.next()?.trim();
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Some(SsdpResponse { headers })
}

fn merge_ssdp_headers(info: &mut UpnpInfo, headers: &HashMap<String, String>) {
    if info.server.is_none() {
        info.server = headers.get("server").cloned();
    }
    if info.location.is_none() {
        info.location = headers.get("location").cloned();
    }
    if let Some(service) = headers.get("st").or_else(|| headers.get("nt")) {
        push_unique(&mut info.services, service.clone());
    }
    if let Some(usn) = headers.get("usn") {
        push_unique(&mut info.usns, usn.clone());
    }
}

fn fetch_description(
    client: &reqwest::blocking::Client,
    location: &str,
) -> Result<UpnpDescription> {
    let response = client
        .get(location)
        .send()
        .with_context(|| format!("failed to fetch UPnP description from {location}"))?;
    let text = response
        .text()
        .with_context(|| format!("failed to read UPnP description from {location}"))?;
    parse_upnp_description(&text)
}

pub fn parse_upnp_description(xml: &str) -> Result<UpnpDescription> {
    // Parse only the device-description fields that become identity evidence.
    // Unknown XML is ignored so vendor extensions cannot break discovery.
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut current = String::new();
    let mut description = UpnpDescription::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = String::from_utf8_lossy(event.name().as_ref()).to_string();
            }
            Ok(Event::Text(event)) => {
                let text = event.decode()?.trim().to_string();
                if text.is_empty() {
                    continue;
                }
                match current.as_str() {
                    "friendlyName" => description.friendly_name = Some(text),
                    "manufacturer" => description.manufacturer = Some(text),
                    "modelName" => description.model_name = Some(text),
                    "modelDescription" => description.model_description = Some(text),
                    "deviceType" => description.device_type = Some(text),
                    "serviceType" => push_unique(&mut description.services, text),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => current.clear(),
            Ok(Event::Eof) => break,
            Err(err) => return Err(err).context("failed to parse UPnP description XML"),
            _ => {}
        }
    }

    Ok(description)
}

fn merge_description(info: &mut UpnpInfo, description: UpnpDescription) {
    // Header-level SSDP fields arrive before description XML. XML fills gaps and
    // appends services, but it should not erase facts already emitted live.
    if let Some(name) = description.friendly_name {
        push_unique(&mut info.names, name);
    }
    if info.manufacturer.is_none() {
        info.manufacturer = description.manufacturer;
    }
    if info.model.is_none() {
        info.model = description.model_name.or(description.model_description);
    }
    if info.device_type.is_none() {
        info.device_type = description.device_type;
    }
    for service in description.services {
        push_unique(&mut info.services, service);
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    let value = value.trim().to_string();
    if value.is_empty() {
        return;
    }
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

pub fn friendly_device_type(raw: &str) -> String {
    raw.rsplit(':')
        .nth(1)
        .filter(|part| !part.is_empty())
        .unwrap_or(raw)
        .replace('-', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssdp_headers_case_insensitively() {
        let response = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/root.xml\r\nSERVER: Linux UPnP/1.0\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n";
        let parsed = parse_ssdp_response(response).unwrap();

        assert_eq!(
            parsed.headers.get("location").map(String::as_str),
            Some("http://192.168.1.1/root.xml")
        );
        assert_eq!(
            parsed.headers.get("server").map(String::as_str),
            Some("Linux UPnP/1.0")
        );
    }

    #[test]
    fn parses_upnp_description_xml() {
        let xml = r#"
            <root>
              <device>
                <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
                <friendlyName>Living Room TV</friendlyName>
                <manufacturer>Sony</manufacturer>
                <modelName>BRAVIA</modelName>
                <serviceList>
                  <service><serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType></service>
                </serviceList>
              </device>
            </root>
        "#;

        let description = parse_upnp_description(xml).unwrap();
        assert_eq!(description.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(description.manufacturer.as_deref(), Some("Sony"));
        assert_eq!(description.model_name.as_deref(), Some("BRAVIA"));
        assert_eq!(description.services.len(), 1);
    }

    #[test]
    fn converts_friendly_device_type() {
        assert_eq!(
            friendly_device_type("urn:schemas-upnp-org:device:MediaServer:1"),
            "MediaServer"
        );
    }
}
