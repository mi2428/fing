//! Active protocol probes used after a host has already been discovered.
//!
//! These modules intentionally live below `probes` rather than at crate root:
//! they all perform network I/O against known hosts and produce identity
//! evidence. Discovery modules answer "is there a host?", while probe modules
//! answer "what does this host look like?".

use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    net::{IpAddr, SocketAddr, TcpStream as StdTcpStream},
    time::Duration,
};
use tokio::net::{TcpSocket, TcpStream};

pub mod deep;
pub mod smb;
pub mod snmp;
pub mod upnp;

pub(super) async fn connect_tcp_from(
    local_addr: IpAddr,
    remote_addr: IpAddr,
    remote_port: u16,
    timeout: Duration,
) -> Option<TcpStream> {
    if !same_ip_family(local_addr, remote_addr) {
        return None;
    }

    let socket = match remote_addr {
        IpAddr::V4(_) => TcpSocket::new_v4().ok()?,
        IpAddr::V6(_) => TcpSocket::new_v6().ok()?,
    };
    socket.bind(SocketAddr::new(local_addr, 0)).ok()?;
    tokio::time::timeout(
        timeout,
        socket.connect(SocketAddr::new(remote_addr, remote_port)),
    )
    .await
    .ok()?
    .ok()
}

pub(super) fn connect_blocking_tcp_from(
    local_addr: IpAddr,
    remote_addr: IpAddr,
    remote_port: u16,
    timeout: Duration,
) -> Option<StdTcpStream> {
    if !same_ip_family(local_addr, remote_addr) {
        return None;
    }

    let socket = match remote_addr {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, None).ok()?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::STREAM, None).ok()?,
    };
    socket
        .bind(&SockAddr::from(SocketAddr::new(local_addr, 0)))
        .ok()?;
    socket
        .connect_timeout(
            &SockAddr::from(SocketAddr::new(remote_addr, remote_port)),
            timeout,
        )
        .ok()?;
    Some(socket.into())
}

pub(super) fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}
