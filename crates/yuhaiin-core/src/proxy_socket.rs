//! Socket and interface binding helpers.

use super::*;

pub async fn connect_tokio_tcp(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    connect_tokio_tcp_with_interface(address, local_bind, None, timeout).await
}

pub async fn connect_tokio_tcp_with_interface(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    bind_interface: Option<&str>,
    timeout: Duration,
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
    .map_err(|error| Error::new(ErrorKind::Io, format!("create TCP socket: {error}")))?;
    bind_tokio_tcp_socket_to_interface(&socket, interface_for_address(address, bind_interface))?;
    if let Some(local_bind) = local_bind {
        socket
            .bind(local_bind)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind TCP socket: {error}")))?;
    }
    tokio::time::timeout(timeout, socket.connect(address))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "TCP connect timed out"))?
        .map_err(|error| Error::new(ErrorKind::Io, format!("TCP connect: {error}")))
}

pub fn bind_socket_to_interface(socket: &Socket, bind_interface: Option<&str>) -> Result<()> {
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(());
    };
    bind_socket_to_interface_platform(socket, &interface)
}

fn resolve_bind_interface(bind_interface: &str) -> Option<String> {
    let bind_interface = bind_interface.trim();
    if bind_interface.is_empty() {
        return None;
    }
    if bind_interface == DEFAULT_INTERFACE {
        return default_route_interface();
    }
    Some(bind_interface.to_owned())
}

pub(super) fn interface_for_address(
    address: SocketAddr,
    bind_interface: Option<&str>,
) -> Option<&str> {
    if address.ip().is_loopback()
        && bind_interface.is_some_and(|interface| interface.trim() == DEFAULT_INTERFACE)
    {
        None
    } else {
        bind_interface
    }
}

#[cfg(target_os = "linux")]
fn default_route_interface() -> Option<String> {
    std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|content| default_route_interface_v4(&content))
        .or_else(|| {
            std::fs::read_to_string("/proc/net/ipv6_route")
                .ok()
                .and_then(|content| default_route_interface_v6(&content))
        })
}

#[cfg(not(target_os = "linux"))]
fn default_route_interface() -> Option<String> {
    // Non-Linux platforms use the OS route and the source-address fallback.
    // Keeping the marker unresolved is preferable to binding to a stale or
    // guessed interface name.
    None
}

#[cfg(target_os = "linux")]
pub(super) fn default_route_interface_v4(content: &str) -> Option<String> {
    content.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            return None;
        }
        let interface = fields[0];
        (!ignored_default_interface(interface)).then(|| interface.to_owned())
    })
}

#[cfg(target_os = "linux")]
pub(super) fn default_route_interface_v6(content: &str) -> Option<String> {
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
}

#[cfg(target_os = "linux")]
fn ignored_default_interface(interface: &str) -> bool {
    ["tailscale", "wg", "tun", "yuhaiin"]
        .iter()
        .any(|prefix| interface.starts_with(prefix))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_socket_to_interface_platform(socket: &Socket, interface: &str) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("bind socket to interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_socket_to_interface_platform(_socket: &Socket, _interface: &str) -> Result<()> {
    // macOS and Windows use the source-address fallback supplied by the
    // runtime interface snapshot. Their native interface-index APIs are
    // platform-specific and are intentionally kept out of this shared core.
    Ok(())
}

fn bind_tokio_tcp_socket_to_interface(
    socket: &tokio::net::TcpSocket,
    bind_interface: Option<&str>,
) -> Result<()> {
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(());
    };
    bind_tokio_tcp_socket_to_interface_platform(socket, &interface)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_tokio_tcp_socket_to_interface_platform(
    socket: &tokio::net::TcpSocket,
    interface: &str,
) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("bind TCP socket to interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_tokio_tcp_socket_to_interface_platform(
    _socket: &tokio::net::TcpSocket,
    _interface: &str,
) -> Result<()> {
    Ok(())
}

pub async fn bind_tokio_udp_socket_for_target(
    bind_address: SocketAddr,
    target: SocketAddr,
    bind_interface: Option<&str>,
    label: &str,
) -> Result<tokio::net::UdpSocket> {
    bind_tokio_udp_socket_with_target(bind_address, Some(target), bind_interface, label).await
}

async fn bind_tokio_udp_socket_with_target(
    bind_address: SocketAddr,
    target: Option<SocketAddr>,
    bind_interface: Option<&str>,
    label: &str,
) -> Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(bind_address)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("{label} UDP bind: {error}")))?;
    let bind_interface = target.map_or(bind_interface, |target| {
        interface_for_address(target, bind_interface)
    });
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(socket);
    };
    bind_tokio_udp_socket_to_interface(&socket, &interface, label)?;
    Ok(socket)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_tokio_udp_socket_to_interface(
    socket: &tokio::net::UdpSocket,
    interface: &str,
    label: &str,
) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("{label} UDP interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_tokio_udp_socket_to_interface(
    _socket: &tokio::net::UdpSocket,
    _interface: &str,
    _label: &str,
) -> Result<()> {
    Ok(())
}
