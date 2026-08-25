//! SOCKS5 proxy.

use super::*;

use super::datagrams::{Socks5UdpDatagram, io_error, socks_address};

/// Native asynchronous SOCKS5 proxy.
///
/// Runtime outbound proxies use this implementation so SOCKS5 UDP ASSOCIATE
/// shares the same `AsyncProxy` contract as direct and Yuubinsya datagrams.
#[derive(Clone)]
pub struct Socks5AsyncProxy {
    pub proxy: SocketAddr,
    pub timeout: Duration,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl AsyncProxy for Socks5AsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        let local_bind = context.local_bind_for(self.proxy);
        let bind_interface = context.bind_interface.clone();
        let proxy = self.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut stream = connect_tokio_tcp_with_interface(
                    proxy.proxy,
                    local_bind,
                    bind_interface.as_deref(),
                    proxy.timeout,
                )
                .await
                .map_err(|error| socks5_stage("proxy TCP connect", error))?;
                socks5_authenticate(
                    &mut stream,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
                .map_err(|error| socks5_stage("authentication", error))?;
                socks5_request(&mut stream, 1, &destination)
                    .await
                    .map_err(|error| socks5_stage("CONNECT", error))?;
                Ok::<_, Error>(stream)
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "SOCKS5 CONNECT timed out"))??;
            let local_addr = result.local_addr().ok();
            Ok(with_stream_local_addr(
                Box::new(result) as BoxAsyncStream,
                local_addr,
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let proxy = self.clone();
        let local_bind = context.local_bind_for(self.proxy).unwrap_or_else(|| {
            if self.proxy.is_ipv4() {
                "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
            } else {
                "[::]:0".parse().expect("valid IPv6 wildcard")
            }
        });
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut control = connect_tokio_tcp_with_interface(
                    proxy.proxy,
                    Some(local_bind),
                    bind_interface.as_deref(),
                    proxy.timeout,
                )
                .await
                .map_err(|error| socks5_stage("UDP associate TCP connect", error))?;
                socks5_authenticate(
                    &mut control,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
                .map_err(|error| socks5_stage("UDP associate authentication", error))?;
                let unspecified = if proxy.proxy.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                } else {
                    SocketAddr::from(([0u16; 8], 0))
                };
                let reply =
                    socks5_request(&mut control, 3, &Endpoint::ip(Network::Udp, unspecified))
                        .await
                        .map_err(|error| socks5_stage("UDP associate request", error))?;
                let relay = if reply.ip().is_unspecified() {
                    SocketAddr::new(proxy.proxy.ip(), reply.port())
                } else {
                    reply
                };
                if relay.is_ipv4() != local_bind.is_ipv4() {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "SOCKS5 UDP relay and local bind use different address families",
                    ));
                }
                let socket = bind_tokio_udp_socket_for_target(
                    local_bind,
                    proxy.proxy,
                    bind_interface.as_deref(),
                    "SOCKS5",
                )
                .await?;
                Ok::<_, Error>(Socks5UdpDatagram {
                    socket,
                    relay,
                    control: Mutex::new(Some(control)),
                    receive_buffer: AsyncMutex::new(Vec::new()),
                })
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "SOCKS5 UDP ASSOCIATE timed out"))??;
            Ok(Box::new(result) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn socks5_authenticate(
    stream: &mut tokio::net::TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let has_auth = username.is_some() && password.is_some();
    let methods: &[u8] = if has_auth { &[0, 2] } else { &[0] };
    stream
        .write_all(&[5, methods.len() as u8])
        .await
        .map_err(io_error)?;
    stream.write_all(methods).await.map_err(io_error)?;
    let mut selected = [0; 2];
    stream.read_exact(&mut selected).await.map_err(io_error)?;
    match selected[1] {
        0 => {}
        2 if has_auth => {
            let username = username.unwrap_or_default();
            let password = password.unwrap_or_default();
            if username.len() > 255 || password.len() > 255 {
                return Err(Error::invalid("SOCKS5 credentials are too long"));
            }
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await.map_err(io_error)?;
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.map_err(io_error)?;
            if response != [1, 0] {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "SOCKS5 authentication failed",
                ));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 no acceptable method",
            ));
        }
    }
    Ok(())
}

fn socks5_stage(stage: &str, error: Error) -> Error {
    Error::new(error.kind, format!("SOCKS5 {stage}: {}", error.message))
}

async fn socks5_request(
    stream: &mut tokio::net::TcpStream,
    command: u8,
    destination: &Endpoint,
) -> Result<SocketAddr> {
    let (atyp, address) = socks_address(destination)?;
    let mut request = vec![5, command, 0, atyp];
    request.extend_from_slice(&address);
    request.extend_from_slice(&destination.port().unwrap_or_default().to_be_bytes());
    stream.write_all(&request).await.map_err(io_error)?;

    let mut head = [0; 4];
    stream.read_exact(&mut head).await.map_err(io_error)?;
    if head[1] != 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("SOCKS5 request failed with code {}", head[1]),
        ));
    }
    let (host, port) = match head[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            (
                IpAddr::V4(bytes.into()).to_string(),
                read_u16(stream).await?,
            )
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            (
                IpAddr::V6(bytes.into()).to_string(),
                read_u16(stream).await?,
            )
        }
        3 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            let mut bytes = vec![0; usize::from(length[0])];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            let host = String::from_utf8(bytes)
                .map_err(|_| Error::new(ErrorKind::Protocol, "SOCKS5 reply domain is invalid"))?;
            (host, read_u16(stream).await?)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid SOCKS5 reply address type",
            ));
        }
    };
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("resolve SOCKS5 relay: {error}")))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 relay resolved to no address"))
}

async fn read_u16(stream: &mut tokio::net::TcpStream) -> Result<u16> {
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes).await.map_err(io_error)?;
    Ok(u16::from_be_bytes(bytes))
}
