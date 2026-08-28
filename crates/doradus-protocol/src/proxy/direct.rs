//! Direct proxy.

use super::*;

use super::datagrams::{TokioDatagram, resolve_direct_addresses};
use doradus_core::network::interface_for_address;

#[derive(Debug, Clone, Copy)]
pub struct DirectAsyncProxy {
    pub timeout: Duration,
}

static NEXT_ICMP_SEQUENCE: AtomicU16 = AtomicU16::new(1);

impl AsyncProxy for DirectAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let addresses = resolve_direct_addresses(&destination, preferred_ipv4).await?;
            let mut last_error = None;
            for address in addresses {
                match connect_tokio_tcp_with_interface(
                    address,
                    context.local_bind_for(address),
                    bind_interface.as_deref(),
                    self.timeout,
                )
                .await
                {
                    Ok(stream) => {
                        let local_addr = stream.local_addr().ok();
                        return Ok(with_stream_socket_addrs(
                            Box::new(stream) as BoxAsyncStream,
                            local_addr,
                            Some(address),
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("direct destination has no address")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let address = resolve_direct_addresses(&destination, preferred_ipv4)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| Error::invalid("direct destination has no address"))?;
            let bind_address: SocketAddr = match address {
                std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let bind_address = context.local_bind_for(address).unwrap_or(bind_address);
            let socket = bind_tokio_udp_socket_for_target(
                bind_address,
                address,
                bind_interface.as_deref(),
                "direct",
            )
            .await?;
            Ok(Box::new(TokioDatagram { socket }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let local_bind_addresses = context.local_bind_addresses.clone();
        let bind_interface = context.bind_interface.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let addresses = resolve_direct_addresses(&destination, preferred_ipv4).await?;
            let started = std::time::Instant::now();
            let mut last_error = None;
            for address in addresses {
                let target = SocketAddr::new(address.ip(), 0);
                let local_bind = local_bind_addresses
                    .iter()
                    .copied()
                    .find(|local| local.is_ipv4() == target.is_ipv4())
                    .map(|local| SocketAddr::new(local, 0));
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    last_error = Some(Error::new(ErrorKind::Timeout, "direct ICMP ping timed out"));
                    break;
                }
                match tokio::time::timeout(
                    remaining,
                    direct_icmp_ping_once(target, local_bind, bind_interface.as_deref()),
                )
                .await
                {
                    Ok(Ok(elapsed)) => return Ok(elapsed),
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        last_error = Some(Error::new(
                            ErrorKind::Timeout,
                            format!("direct ICMP ping timed out for {target}"),
                        ));
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| Error::invalid("direct destination has no usable ICMP address")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn direct_icmp_ping_once(
    target: SocketAddr,
    local_bind: Option<SocketAddr>,
    bind_interface: Option<&str>,
) -> Result<Duration> {
    let (domain, protocol) = if target.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4)
    } else {
        (Domain::IPV6, Protocol::ICMPV6)
    };
    if local_bind.is_some_and(|local| local.is_ipv4() != target.is_ipv4()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "local bind address and ICMP destination use different address families",
        ));
    }
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))
        .map_err(|error| Error::new(ErrorKind::Io, format!("create ICMP socket: {error}")))?;
    bind_socket_to_interface(&socket, interface_for_address(target, bind_interface))?;
    if let Some(local_bind) = local_bind {
        socket
            .bind(&local_bind.into())
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind ICMP socket: {error}")))?;
    }
    socket.set_nonblocking(true).map_err(|error| {
        Error::new(
            ErrorKind::Io,
            format!("set ICMP socket nonblocking: {error}"),
        )
    })?;
    let socket: std::net::UdpSocket = socket.into();
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|error| Error::new(ErrorKind::Io, format!("adopt ICMP socket: {error}")))?;
    socket
        .connect(target)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("connect ICMP socket: {error}")))?;
    let source = socket
        .local_addr()
        .map_err(|error| Error::new(ErrorKind::Io, format!("read ICMP local address: {error}")))?
        .ip();
    let identifier = (std::process::id() & u32::from(u16::MAX)) as u16;
    let sequence = NEXT_ICMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let payload = icmp_ping_payload(identifier, sequence);
    let packet = build_icmp_echo_request(source, target.ip(), identifier, sequence, &payload)?;
    let started = std::time::Instant::now();
    socket
        .send(&packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("send ICMP echo request: {error}")))?;
    let mut response = [0u8; 2048];
    loop {
        let length = socket.recv(&mut response).await.map_err(|error| {
            Error::new(ErrorKind::Io, format!("receive ICMP echo reply: {error}"))
        })?;
        if icmp_echo_reply_matches(&response[..length], target.ip(), sequence, &payload) {
            return Ok(started.elapsed());
        }
    }
}

fn icmp_ping_payload(identifier: u16, sequence: u16) -> Vec<u8> {
    [
        b'y',
        b'u',
        b'h',
        b'a',
        b'i',
        b'i',
        (identifier >> 8) as u8,
        identifier as u8,
        (sequence >> 8) as u8,
        sequence as u8,
        0x52,
        0x75,
        0x73,
        0x74,
        0x50,
        0x69,
    ]
    .to_vec()
}

fn build_icmp_echo_request(
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut packet = vec![0u8; 8 + payload.len()];
    packet[0] = if destination.is_ipv4() { 8 } else { 128 };
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(payload);
    let checksum = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => internet_checksum(&packet),
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            icmpv6_checksum(source, destination, &packet)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ICMP source and destination use different address families",
            ));
        }
    };
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn icmp_echo_reply_matches(
    packet: &[u8],
    destination: IpAddr,
    sequence: u16,
    payload: &[u8],
) -> bool {
    let packet = match destination {
        IpAddr::V4(_) if packet.first().is_some_and(|byte| byte >> 4 == 4) => {
            let header_length = packet
                .first()
                .map(|byte| usize::from(byte & 0x0f) * 4)
                .unwrap_or(0);
            packet.get(header_length..).unwrap_or_default()
        }
        IpAddr::V6(_) if packet.first().is_some_and(|byte| byte >> 4 == 6) => {
            packet.get(40..).unwrap_or_default()
        }
        _ => packet,
    };
    let expected_type = if destination.is_ipv4() { 0 } else { 129 };
    packet.len() >= 8
        && packet[0] == expected_type
        && packet[1] == 0
        && u16::from_be_bytes([packet[6], packet[7]]) == sequence
        && packet[8..] == *payload
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + packet.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(packet);
    internet_checksum(&pseudo)
}
