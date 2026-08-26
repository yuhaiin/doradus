//! Datagram implementations.

use super::*;

/// Resolve a domain only when a caller reaches the low-level direct transport
/// without the runtime's configured resolver wrapper. Runtime traffic still
/// resolves through `ResolvingProxy` first, so hosts/FakeIP/route resolver
/// policy remain authoritative; this fallback prevents standalone direct
/// users from failing merely because they supplied a domain endpoint.
pub(super) async fn resolve_direct_addresses(
    destination: &Endpoint,
    preferred_ipv4: Option<bool>,
) -> Result<Vec<SocketAddr>> {
    if let Some(address) = destination.addr() {
        return Ok(vec![address]);
    }
    let host = destination
        .host()
        .ok_or_else(|| Error::invalid("direct destination has no host"))?;
    let port = destination
        .port()
        .ok_or_else(|| Error::invalid("direct destination has no port"))?;
    let addresses = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("resolve direct destination {host}:{port}: {error}"),
            )
        })?;
    let addresses = addresses.collect::<Vec<_>>();
    let preferred = addresses
        .iter()
        .copied()
        .filter(|address| preferred_ipv4.is_none_or(|ipv4| address.is_ipv4() == ipv4))
        .collect::<Vec<_>>();
    if !preferred.is_empty() {
        return Ok(preferred);
    }
    if !addresses.is_empty() {
        return Ok(addresses);
    }
    Err(Error::invalid(format!(
        "direct destination {host}:{port} resolved to no usable address"
    )))
}

pub(super) struct Socks5UdpDatagram {
    pub(super) socket: tokio::net::UdpSocket,
    pub(super) relay: SocketAddr,
    // SOCKS5 keeps the TCP control connection open for the lifetime of the
    // UDP association. The mutex is only needed to make the datagram object
    // satisfy the shared AsyncDatagram Send + Sync contract; no I/O is done
    // through it after the handshake.
    pub(super) control: Mutex<Option<tokio::net::TcpStream>>,
    // Keep the SOCKS5 header scratch space with the association. The TUN
    // caller's buffer is payload-sized, so a maximum-sized allocation here
    // would multiply memory by the number of live UDP associations.
    pub(super) receive_buffer: AsyncMutex<Vec<u8>>,
}

impl AsyncDatagram for Socks5UdpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("SOCKS5 UDP target has wrong network"));
            }
            let (atyp, address) = socks_address(&target)?;
            let mut packet = Vec::with_capacity(4 + address.len() + 2 + payload.len());
            packet.extend_from_slice(&[0, 0, 0, atyp]);
            packet.extend_from_slice(&address);
            packet.extend_from_slice(&target.port().unwrap_or_default().to_be_bytes());
            packet.extend_from_slice(payload);
            self.socket
                .send_to(&packet, self.relay)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("SOCKS5 UDP send: {error}")))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            // The TUN UDP relay already supplies the maximum legal UDP
            // datagram buffer. Read the SOCKS5 packet directly into it so a
            // high-rate relay does not allocate a fresh 64 KiB Vec for every
            // response. Smaller callers retain the historical fallback so
            // the output buffer can remain payload-sized.
            if buffer.len() >= u16::MAX as usize {
                let length = self.socket.recv(buffer).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("SOCKS5 UDP receive: {error}"))
                })?;
                let (target, offset) = decode_socks5_udp_endpoint(&buffer[..length])?;
                let payload_len = length.saturating_sub(offset);
                buffer.copy_within(offset..length, 0);
                return Ok((payload_len, target));
            }

            const SOCKS5_UDP_MAX_HEADER_SIZE: usize = 262;
            let mut packet = self.receive_buffer.lock().await;
            let required = buffer
                .len()
                .saturating_add(SOCKS5_UDP_MAX_HEADER_SIZE)
                .min(u16::MAX as usize);
            if packet.len() < required {
                packet.resize(required, 0);
            }
            let length = self.socket.recv(&mut packet).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("SOCKS5 UDP receive: {error}"))
            })?;
            let (target, offset) = decode_socks5_udp_endpoint(&packet[..length])?;
            let payload = &packet[offset..length];
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "SOCKS5 UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("SOCKS5 UDP local address: {error}"))
            })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        if let Ok(mut control) = self.control.lock() {
            control.take();
        }
        Box::pin(async { Ok(()) })
    }
}

fn decode_socks5_udp_endpoint(packet: &[u8]) -> Result<(Endpoint, usize)> {
    if packet.len() < 4 || packet[0..2] != [0, 0] {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid SOCKS5 UDP response header",
        ));
    }
    if packet[2] != 0 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP responses are not supported",
        ));
    }
    let atyp = packet[3];
    let mut offset = 4;
    let host = match atyp {
        1 => {
            let end = offset + 4;
            let bytes = packet.get(offset..end).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP IPv4 address is truncated")
            })?;
            offset = end;
            IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).expect("validated IPv4 length"),
            ))
            .to_string()
        }
        4 => {
            let end = offset + 16;
            let bytes = packet.get(offset..end).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP IPv6 address is truncated")
            })?;
            offset = end;
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).expect("validated IPv6 length"),
            ))
            .to_string()
        }
        3 => {
            let length = usize::from(*packet.get(offset).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain length is missing")
            })?);
            offset += 1;
            let end = offset + length;
            let bytes = packet
                .get(offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain is truncated"))?;
            offset = end;
            String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain is invalid"))?
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid SOCKS5 UDP address type",
            ));
        }
    };
    let port_end = offset + 2;
    let port_bytes = packet
        .get(offset..port_end)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 UDP port is truncated"))?;
    let port = u16::from_be_bytes(port_bytes.try_into().expect("validated port length"));
    offset = port_end;
    let endpoint = match host.parse::<IpAddr>() {
        Ok(address) => Endpoint::ip(Network::Udp, SocketAddr::new(address, port)),
        Err(_) => Endpoint::domain(Network::Udp, DomainName::new(&host)?, port),
    };
    Ok((endpoint, offset))
}

pub(super) struct TokioDatagram {
    pub(super) socket: tokio::net::UdpSocket,
}

pub(super) struct FixedDatagram {
    pub(super) socket: tokio::net::UdpSocket,
    pub(super) target: SocketAddr,
}

impl AsyncDatagram for TokioDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("UDP datagram target has wrong network"));
            }
            let preferred_ipv4 = self
                .socket
                .local_addr()
                .ok()
                .map(|address| address.is_ipv4());
            let addresses = resolve_direct_addresses(&target, preferred_ipv4).await?;
            let mut last_error = None;
            for address in addresses {
                match self.socket.send_to(payload, address).await {
                    Ok(length) => return Ok(length),
                    Err(error) => {
                        last_error = Some(Error::new(
                            ErrorKind::Io,
                            format!("UDP send to {address}: {error}"),
                        ));
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| Error::invalid("direct UDP destination has no address")))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (length, address) = self
                .socket
                .recv_from(buffer)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("UDP receive: {error}")))?;
            Ok((length, Endpoint::ip(Network::Udp, address)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AsyncDatagram for FixedDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("UDP datagram target has wrong network"));
            }
            self.socket
                .send_to(payload, self.target)
                .await
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Io,
                        format!("fixed UDP send to {}: {error}", self.target),
                    )
                })
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (length, _) = self.socket.recv_from(buffer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("fixed UDP receive: {error}"))
            })?;
            Ok((length, Endpoint::ip(Network::Udp, self.target)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("fixed UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

pub(super) fn socks_address(destination: &Endpoint) -> Result<(u8, Vec<u8>)> {
    match destination {
        Endpoint::Ip { addr, .. } => match addr.ip() {
            IpAddr::V4(value) => Ok((1, value.octets().to_vec())),
            IpAddr::V6(value) => Ok((4, value.octets().to_vec())),
        },
        Endpoint::Domain { host, .. } => {
            if host.as_str().len() > 255 {
                return Err(Error::invalid("SOCKS5 domain is too long"));
            }
            let mut value = vec![host.as_str().len() as u8];
            value.extend_from_slice(host.as_str().as_bytes());
            Ok((3, value))
        }
    }
}

pub(super) fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
