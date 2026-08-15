//! Runtime-neutral socket setup used by the async DNS transports.

use std::net::SocketAddr;

use crate::{Error, ErrorKind, Result};

pub(crate) async fn bind_udp_socket(
    bind_address: SocketAddr,
    target: SocketAddr,
    bind_interface: Option<&str>,
    label: &str,
) -> Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(bind_address)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("{label} UDP bind: {error}")))?;
    let bind_interface = interface_for_address(target, bind_interface);
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(socket);
    };
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("{label} UDP interface {interface:?}: {error}"),
            )
        })?;
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    let _ = (interface, label);
    Ok(socket)
}

pub(crate) async fn connect_tcp(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    bind_interface: Option<&str>,
    timeout: std::time::Duration,
) -> Result<tokio::net::TcpStream> {
    if local_bind.is_some_and(|local| local.is_ipv4() != address.is_ipv4()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "local bind address and TCP destination use different address families",
        ));
    }
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .map_err(|error| Error::new(ErrorKind::Io, format!("create DNS TCP socket: {error}")))?;
    let bind_interface = interface_for_address(address, bind_interface);
    if let Some(interface) = bind_interface.and_then(resolve_bind_interface) {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Io,
                    format!("bind DNS TCP socket to interface {interface:?}: {error}"),
                )
            })?;
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        let _ = interface;
    }
    if let Some(local_bind) = local_bind {
        socket
            .bind(local_bind)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS TCP socket: {error}")))?;
    }
    tokio::time::timeout(timeout, socket.connect(address))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP connect timed out"))?
        .map_err(|error| Error::new(ErrorKind::Io, format!("DNS TCP connect: {error}")))
}

fn interface_for_address(address: SocketAddr, bind_interface: Option<&str>) -> Option<&str> {
    if address.ip().is_loopback()
        && bind_interface
            .is_some_and(|interface| interface.trim() == "__yuhaiin_default_interface__")
    {
        None
    } else {
        bind_interface
    }
}

fn resolve_bind_interface(bind_interface: &str) -> Option<String> {
    let bind_interface = bind_interface.trim();
    if bind_interface.is_empty() {
        return None;
    }
    if bind_interface == "__yuhaiin_default_interface__" {
        return default_route_interface();
    }
    Some(bind_interface.to_owned())
}

#[cfg(target_os = "linux")]
fn default_route_interface() -> Option<String> {
    std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|content| {
            content.lines().skip(1).find_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
                    return None;
                }
                let interface = fields[0];
                (!ignored_default_interface(interface)).then(|| interface.to_owned())
            })
        })
        .or_else(|| {
            std::fs::read_to_string("/proc/net/ipv6_route")
                .ok()
                .and_then(|content| {
                    content.lines().find_map(|line| {
                        let fields = line.split_whitespace().collect::<Vec<_>>();
                        if fields.len() < 10
                            || fields[0].len() != 32
                            || !fields[0].bytes().all(|byte| byte == b'0')
                            || fields[1] != "00000000"
                        {
                            return None;
                        }
                        let interface = fields[9];
                        (!ignored_default_interface(interface)).then(|| interface.to_owned())
                    })
                })
        })
}

#[cfg(not(target_os = "linux"))]
fn default_route_interface() -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn ignored_default_interface(interface: &str) -> bool {
    ["tailscale", "wg", "tun", "yuhaiin"]
        .iter()
        .any(|prefix| interface.starts_with(prefix))
}
