//! Linux transparent inbound socket adapters.
//!
//! TPROXY and REDIRECT are listener-side network adapters rather than route
//! policy.  This module owns the Linux socket options and original-destination
//! decoding; the runtime only supplies the route/flow handler after a packet
//! or stream has crossed this boundary.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, getsockopt, recvmsg, setsockopt, sockopt,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpListener, TcpStream};

use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};
use doradus_types::{InboundUdpCodec, InboundUdpFlowId, InboundUdpRequest, InboundUdpResponse};

const BACKLOG: i32 = 256;

/// Bind a TCP listener for either TPROXY (`transparent = true`) or REDIRECT.
pub fn bind_listener(listen: SocketAddr, transparent: bool) -> Result<TcpListener> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    if transparent {
        set_ip_transparent(&socket, listen)?;
    }
    socket
        .bind(&listen.into())
        .map_err(|error| capability_error("transparent bind", error))?;
    socket.listen(BACKLOG).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).map_err(io_error)
}

/// Return the destination recovered from a transparent TCP connection.
pub fn tcp_destination(stream: &TcpStream, tproxy: bool) -> Result<SocketAddr> {
    if tproxy {
        stream.local_addr().map_err(io_error)
    } else {
        original_destination(stream)
    }
}

/// UDP codec for Linux TPROXY ancillary original-destination packets.
pub struct UdpServer {
    socket: AsyncFd<Socket>,
    packet: Vec<u8>,
}

impl UdpServer {
    pub fn bind(listen: SocketAddr, buffer_size: usize) -> Result<Self> {
        Ok(Self {
            socket: bind_udp_socket(listen)?,
            packet: vec![0u8; buffer_size.max(512)],
        })
    }
}

impl InboundUdpCodec for UdpServer {
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let (length, peer, destination) = recv_udp(&self.socket, &mut self.packet).await?;
            let target = Endpoint::ip(Network::Udp, destination);
            Ok(Some(InboundUdpRequest {
                id: InboundUdpFlowId {
                    peer,
                    target: target.clone(),
                    authentication: None,
                },
                peer: Endpoint::ip(Network::Udp, peer),
                target,
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let client = response
                .peer
                .addr()
                .ok_or_else(|| Error::invalid("transparent UDP peer has no IP address"))?;
            let destination = response
                .id
                .target
                .addr()
                .ok_or_else(|| Error::invalid("transparent UDP target has no IP address"))?;
            send_udp_reply(&response.payload, destination, client).await
        })
    }
}

fn bind_udp_socket(listen: SocketAddr) -> Result<AsyncFd<Socket>> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    set_ip_transparent(&socket, listen)?;
    if listen.is_ipv4() {
        setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("IP_ORIGDSTADDR socket option failed: {error}"),
            )
        })?;
    } else {
        setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("IPV6_ORIGDSTADDR socket option failed: {error}"),
            )
        })?;
    }
    socket
        .bind(&listen.into())
        .map_err(|error| capability_error("transparent UDP bind", error))?;
    // Keep this post-bind as well as the pre-bind setup above. Go's
    // net.ListenUDP path applies the transparent option after bind, and this
    // makes the Rust socket contract explicit for kernels that inspect the
    // bound UDP socket during TPROXY lookup.
    set_ip_transparent(&socket, listen)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    AsyncFd::new(socket).map_err(io_error)
}

fn set_ip_transparent(socket: &Socket, listen: SocketAddr) -> Result<()> {
    if listen.is_ipv4() {
        socket
            .set_ip_transparent_v4(true)
            .map_err(|error| capability_error("IP_TRANSPARENT", error))?;
        if !socket
            .ip_transparent_v4()
            .map_err(|error| capability_error("IP_TRANSPARENT readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IP_TRANSPARENT readback was disabled",
            ));
        }
    } else {
        socket
            .set_ip_transparent_v6(true)
            .map_err(|error| capability_error("IPV6_TRANSPARENT", error))?;
        if !socket
            .ip_transparent_v6()
            .map_err(|error| capability_error("IPV6_TRANSPARENT readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IPV6_TRANSPARENT readback was disabled",
            ));
        }
    }
    Ok(())
}

async fn recv_udp(
    socket: &AsyncFd<Socket>,
    payload: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        let mut guard = socket.readable().await.map_err(io_error)?;
        match guard.try_io(|inner| recv_udp_now(inner.get_ref(), payload)) {
            Ok(result) => return result.map_err(io_error),
            Err(_would_block) => continue,
        }
    }
}

fn recv_udp_now(
    socket: &Socket,
    payload: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = [IoSliceMut::new(payload)];
    let mut cmsg = nix::cmsg_space!(nix::libc::sockaddr_in, nix::libc::sockaddr_in6);
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(errno_to_io)?;
    let peer = message
        .address
        .as_ref()
        .and_then(sockaddr_to_socket_addr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP peer address missing"))?;
    let destination = message
        .cmsgs()
        .map_err(errno_to_io)?
        .find_map(|message| match message {
            ControlMessageOwned::Ipv4OrigDstAddr(address) => Some(SocketAddr::new(
                IpAddr::V4(decode_original_ipv4(address.sin_addr.s_addr)),
                u16::from_be(address.sin_port),
            )),
            ControlMessageOwned::Ipv6OrigDstAddr(address) => Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            )),
            _ => None,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "transparent UDP original destination missing",
            )
        })?;
    Ok((message.bytes, peer, destination))
}

fn sockaddr_to_socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(address) = address.as_sockaddr_in() {
        return Some(SocketAddr::new(IpAddr::V4(address.ip()), address.port()));
    }
    address
        .as_sockaddr_in6()
        .map(|address| SocketAddr::new(IpAddr::V6(address.ip()), address.port()))
}

fn decode_original_ipv4(raw: u32) -> Ipv4Addr {
    // Linux exposes the network-order address through a native-endian
    // integer. `from_be` restores the integer representation expected by
    // `Ipv4Addr::from` on every target endian.
    Ipv4Addr::from(u32::from_be(raw))
}

async fn send_udp_reply(payload: &[u8], source: SocketAddr, destination: SocketAddr) -> Result<()> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "transparent UDP reply address families differ",
        ));
    }
    let domain = if source.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    set_ip_transparent(&socket, source)?;
    socket.bind(&source.into()).map_err(io_error)?;
    socket.connect(&destination.into()).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    let socket = tokio::net::UdpSocket::from_std(socket.into()).map_err(io_error)?;
    socket.send(payload).await.map_err(io_error)?;
    Ok(())
}

fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    let local = stream.local_addr().map_err(io_error)?;
    if local.is_ipv4() {
        let raw = getsockopt(stream, sockopt::OriginalDst).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("SO_ORIGINAL_DST unavailable for redir inbound: {error}"),
            )
        })?;
        return Ok(SocketAddr::new(
            // `sin_addr` is stored in network byte order but exposed as a
            // native-endian integer by libc on Linux. Converting from network
            // order avoids reversing 10.254.0.3 into 3.0.254.10.
            IpAddr::V4(decode_original_ipv4(raw.sin_addr.s_addr)),
            u16::from_be(raw.sin_port),
        ));
    }
    let raw = getsockopt(stream, sockopt::Ip6tOriginalDst).map_err(|error| {
        Error::new(
            ErrorKind::Io,
            format!("IP6T_SO_ORIGINAL_DST unavailable for redir inbound: {error}"),
        )
    })?;
    Ok(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)),
        u16::from_be(raw.sin6_port),
    ))
}

fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn io_error(error: impl Into<io::Error>) -> Error {
    Error::new(ErrorKind::Io, error.into().to_string())
}

fn capability_error(option: &str, error: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Io,
        format!("Linux transparent socket option {option} failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn redir_listener_binds_an_ephemeral_tcp_port_without_transparent_capability() {
        let listener = bind_listener("127.0.0.1:0".parse().unwrap(), false).unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn original_destination_ipv4_decodes_network_order() {
        let raw = u32::from_ne_bytes([10, 254, 0, 3]);
        assert_eq!(decode_original_ipv4(raw), Ipv4Addr::new(10, 254, 0, 3));
    }

    #[test]
    fn recv_udp_now_reads_linux_ipv4_original_destination_ancillary() {
        let receiver = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        setsockopt(&receiver, sockopt::Ipv4OrigDstAddr, &true).unwrap();
        receiver
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"ipv4-orig-dst", destination).unwrap();

        let mut payload = [0u8; 64];
        let (length, peer, original) = recv_until_ready(&receiver, &mut payload);
        assert_eq!(&payload[..length], b"ipv4-orig-dst");
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(original, destination);
    }

    #[test]
    fn recv_udp_now_reads_linux_ipv6_original_destination_ancillary() {
        let receiver = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        setsockopt(&receiver, sockopt::Ipv6OrigDstAddr, &true).unwrap();
        receiver
            .bind(&"[::1]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind("[::1]:0").unwrap();
        sender.send_to(b"ipv6-orig-dst", destination).unwrap();

        let mut payload = [0u8; 64];
        let (length, peer, original) = recv_until_ready(&receiver, &mut payload);
        assert_eq!(&payload[..length], b"ipv6-orig-dst");
        assert_eq!(peer.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(original, destination);
    }

    fn recv_until_ready(socket: &Socket, payload: &mut [u8]) -> (usize, SocketAddr, SocketAddr) {
        for _ in 0..100 {
            match recv_udp_now(socket, payload) {
                Ok(result) => return result,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("receive original destination ancillary: {error}"),
            }
        }
        panic!("timed out waiting for original destination ancillary");
    }
}
