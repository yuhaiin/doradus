//! Synchronous stream proxy connectors.
//!
//! The connector is deliberately small: runtime-specific adapters can execute
//! it on a blocking pool, while protocol-specific handshakes remain testable
//! without Tokio. UDP/Yuubinsya are separate boundaries and do not share this
//! TCP handshake state.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::{DomainName, Endpoint, Error, ErrorKind, Result};

#[cfg(feature = "async-proxy")]
use crate::{BoxFuture, FlowContext, Network};

#[cfg(feature = "async-proxy")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait StreamConnector: Send + Sync {
    fn connect(&self, destination: &Endpoint) -> Result<TcpStream>;

    fn connect_with_local(
        &self,
        destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        if local_bind.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "stream connector does not support a local bind address",
            ));
        }
        self.connect(destination)
    }

    fn connect_target(&self) -> Option<SocketAddr> {
        None
    }
}

fn connect_std_tcp(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<TcpStream> {
    let Some(local_bind) = local_bind else {
        return TcpStream::connect_timeout(&address, timeout)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()));
    };
    if local_bind.is_ipv4() != address.is_ipv4() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "local bind address and TCP destination use different address families",
        ));
    }
    let socket = Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|error| Error::new(ErrorKind::Io, format!("create TCP socket: {error}")))?;
    socket
        .bind(&local_bind.into())
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind TCP socket: {error}")))?;
    socket
        .connect_timeout(&address.into(), timeout)
        .map_err(|error| Error::new(ErrorKind::Io, format!("connect TCP socket: {error}")))?;
    Ok(socket.into())
}

#[cfg(feature = "async-proxy")]
pub async fn connect_tokio_tcp(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
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
pub trait SecureStream: Read + Write + Send {}
impl<T: Read + Write + Send> SecureStream for T {}

/// TLS is an injected protocol layer rather than a hard-coded crypto backend.
/// A platform crate can implement this with rustls plus its selected provider
/// and still reuse all direct/proxy handshakes from this crate.
pub trait TlsClient: Send + Sync {
    type Stream: SecureStream + 'static;

    fn connect(&self, stream: TcpStream, server_name: &str) -> Result<Self::Stream>;
}

pub struct TlsStreamConnector<T> {
    pub upstream: Arc<dyn StreamConnector>,
    pub tls: T,
}

impl<T: TlsClient> TlsStreamConnector<T> {
    pub fn connect_secure(&self, destination: &Endpoint) -> Result<T::Stream> {
        let stream = self.upstream.connect(destination)?;
        let server_name = destination
            .host()
            .map(|host| host.as_str().to_owned())
            .or_else(|| destination.addr().map(|addr| addr.ip().to_string()))
            .ok_or_else(|| Error::invalid("TLS destination has no server name"))?;
        self.tls.connect(stream, &server_name)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DirectConnector {
    pub timeout: Duration,
}

impl StreamConnector for DirectConnector {
    fn connect(&self, destination: &Endpoint) -> Result<TcpStream> {
        let address = destination.addr().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "direct connector requires an already-resolved IP endpoint",
            )
        })?;
        connect_std_tcp(address, None, self.timeout)
    }

    fn connect_with_local(
        &self,
        destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        let address = destination.addr().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "direct connector requires an already-resolved IP endpoint",
            )
        })?;
        connect_std_tcp(address, local_bind, self.timeout)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DropConnector;

impl StreamConnector for DropConnector {
    fn connect(&self, _destination: &Endpoint) -> Result<TcpStream> {
        Err(Error::new(
            ErrorKind::Closed,
            "connection dropped by route policy",
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedConnector {
    pub address: SocketAddr,
    pub timeout: Duration,
}

impl StreamConnector for FixedConnector {
    fn connect(&self, _destination: &Endpoint) -> Result<TcpStream> {
        connect_std_tcp(self.address, None, self.timeout)
    }

    fn connect_with_local(
        &self,
        _destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        connect_std_tcp(self.address, local_bind, self.timeout)
    }

    fn connect_target(&self) -> Option<SocketAddr> {
        Some(self.address)
    }
}

pub struct HttpProxyConnector {
    pub proxy: SocketAddr,
    pub timeout: Duration,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl StreamConnector for HttpProxyConnector {
    fn connect(&self, destination: &Endpoint) -> Result<TcpStream> {
        self.connect_with_local(destination, None)
    }

    fn connect_with_local(
        &self,
        destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        let mut stream = connect_std_tcp(self.proxy, local_bind, self.timeout)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        let authority = authority(destination)?;
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&base64_basic(username, password));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        let response = read_headers(&mut stream)?;
        let status = response
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid HTTP proxy response"))?;
        if status / 100 != 2 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("HTTP proxy CONNECT failed with status {status}"),
            ));
        }
        Ok(stream)
    }

    fn connect_target(&self) -> Option<SocketAddr> {
        Some(self.proxy)
    }
}

pub struct Socks5Connector {
    pub proxy: SocketAddr,
    pub timeout: Duration,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl StreamConnector for Socks5Connector {
    fn connect(&self, destination: &Endpoint) -> Result<TcpStream> {
        self.connect_with_local(destination, None)
    }

    fn connect_with_local(
        &self,
        destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        let mut stream = connect_std_tcp(self.proxy, local_bind, self.timeout)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;

        let has_auth = self.username.is_some() && self.password.is_some();
        let methods = if has_auth { vec![0, 2] } else { vec![0] };
        stream
            .write_all(&[5, methods.len() as u8])
            .and_then(|_| stream.write_all(&methods))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        let mut selected = [0; 2];
        stream
            .read_exact(&mut selected)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        match selected[1] {
            0 => {}
            2 if has_auth => {
                let username = self.username.as_deref().unwrap_or_default();
                let password = self.password.as_deref().unwrap_or_default();
                if username.len() > 255 || password.len() > 255 {
                    return Err(Error::invalid("SOCKS5 credentials are too long"));
                }
                let mut auth = vec![1, username.len() as u8];
                auth.extend_from_slice(username.as_bytes());
                auth.push(password.len() as u8);
                auth.extend_from_slice(password.as_bytes());
                stream
                    .write_all(&auth)
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
                let mut response = [0; 2];
                stream
                    .read_exact(&mut response)
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
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

        let (atyp, address) = socks_address(destination)?;
        let mut request = vec![5, 1, 0, atyp];
        request.extend_from_slice(&address);
        request.extend_from_slice(&destination.port().unwrap_or_default().to_be_bytes());
        stream
            .write_all(&request)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        let mut head = [0; 4];
        stream
            .read_exact(&mut head)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        if head[1] != 0 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("SOCKS5 CONNECT failed with code {}", head[1]),
            ));
        }
        let remaining = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => {
                let mut length = [0; 1];
                stream.read_exact(&mut length).map_err(io_error)?;
                usize::from(length[0]) + 2
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "invalid SOCKS5 address type",
                ));
            }
        };
        let mut discard = vec![0; remaining];
        stream.read_exact(&mut discard).map_err(io_error)?;
        Ok(stream)
    }

    fn connect_target(&self) -> Option<SocketAddr> {
        Some(self.proxy)
    }
}

pub struct FixedProxy {
    pub inner: Arc<dyn StreamConnector>,
}

impl StreamConnector for FixedProxy {
    fn connect(&self, destination: &Endpoint) -> Result<TcpStream> {
        self.inner.connect(destination)
    }

    fn connect_with_local(
        &self,
        destination: &Endpoint,
        local_bind: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        self.inner.connect_with_local(destination, local_bind)
    }

    fn connect_target(&self) -> Option<SocketAddr> {
        self.inner.connect_target()
    }
}

#[cfg(feature = "async-proxy")]
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

#[cfg(feature = "async-proxy")]
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

#[cfg(feature = "async-proxy")]
pub type BoxAsyncStream = Box<dyn AsyncStream>;

#[cfg(feature = "async-proxy")]
pub trait AsyncDatagram: Send + Sync {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>>;
    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>>;
    fn local_addr(&self) -> Result<Endpoint>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

#[cfg(feature = "async-proxy")]
pub trait AsyncProxy: Send + Sync {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>>;
    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>>;
    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "proxy does not provide ping",
            ))
        })
    }
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

#[cfg(feature = "async-proxy")]
pub trait AsyncProxySelector: Send + Sync {
    /// Annotate a mutable flow with the route snapshot used for selection.
    /// Static selectors intentionally leave this as a no-op; runtime-backed
    /// selectors use it to keep management metadata and proxy choice aligned.
    fn route_context(&self, _context: &mut FlowContext) {}

    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy>;
}

#[cfg(feature = "async-proxy")]
pub struct StaticProxySelector {
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxySelector for StaticProxySelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        match context.route_mode {
            crate::RouteMode::Direct => Arc::clone(&self.direct),
            crate::RouteMode::Proxy => Arc::clone(&self.proxy),
            crate::RouteMode::Bypass => Arc::clone(&self.bypass),
            crate::RouteMode::Block => Arc::clone(&self.drop),
        }
    }
}

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy)]
pub struct DirectAsyncProxy {
    pub timeout: Duration,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxy for DirectAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        Box::pin(async move {
            let addresses = resolve_direct_addresses(&destination, preferred_ipv4).await?;
            let mut last_error = None;
            for address in addresses {
                match connect_tokio_tcp(address, context.local_bind_for(address), self.timeout)
                    .await
                {
                    Ok(stream) => return Ok(Box::new(stream) as BoxAsyncStream),
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
            let socket = tokio::net::UdpSocket::bind(bind_address)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("direct UDP bind: {error}")))?;
            Ok(Box::new(TokioDatagram { socket }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Resolve a domain only when a caller reaches the low-level direct transport
/// without the runtime's configured resolver wrapper. Runtime traffic still
/// resolves through `ResolvingProxy` first, so hosts/FakeIP/route resolver
/// policy remain authoritative; this fallback prevents standalone direct
/// users from failing merely because they supplied a domain endpoint.
#[cfg(feature = "async-proxy")]
async fn resolve_direct_addresses(
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

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, Default)]
pub struct DropAsyncProxy;

#[cfg(feature = "async-proxy")]
impl AsyncProxy for DropAsyncProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "connection dropped by route policy",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "datagram dropped by route policy",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy)]
pub struct FixedAsyncProxy {
    pub address: SocketAddr,
    pub timeout: Duration,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxy for FixedAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let local_bind = context.local_bind_for(self.address);
        Box::pin(async move {
            let stream = connect_tokio_tcp(self.address, local_bind, self.timeout).await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "fixed async proxy has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Run an existing synchronous handshake on Tokio's blocking pool.  This is
/// an explicit adapter for HTTP CONNECT/SOCKS5; it prevents the sync parser
/// from blocking the TUN or async proxy executor and makes its boundary easy
/// to replace with a native async implementation later.
#[cfg(feature = "async-proxy")]
pub struct BlockingStreamProxy {
    pub connector: Arc<dyn StreamConnector>,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxy for BlockingStreamProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let connector = Arc::clone(&self.connector);
        let destination = context.effective_destination();
        let local_bind = connector
            .connect_target()
            .and_then(|address| context.local_bind_for(address));
        Box::pin(async move {
            let stream = tokio::task::spawn_blocking(move || {
                connector.connect_with_local(&destination, local_bind)
            })
            .await
            .map_err(|error| Error::new(ErrorKind::Closed, format!("proxy task: {error}")))??;
            stream.set_nonblocking(true).map_err(|error| {
                Error::new(ErrorKind::Io, format!("proxy nonblocking mode: {error}"))
            })?;
            let stream = tokio::net::TcpStream::from_std(stream).map_err(|error| {
                Error::new(ErrorKind::Io, format!("proxy Tokio stream: {error}"))
            })?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "synchronous stream proxy has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Native asynchronous SOCKS5 proxy.
///
/// The synchronous connector above remains the small reusable TCP handshake
/// boundary used by callers that only need a blocking stream. Runtime
/// outbound proxies use this implementation so SOCKS5 UDP ASSOCIATE shares
/// the same `AsyncProxy` contract as direct and Yuubinsya datagrams.
#[cfg(feature = "async-proxy")]
#[derive(Clone)]
pub struct Socks5AsyncProxy {
    pub proxy: SocketAddr,
    pub timeout: Duration,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxy for Socks5AsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        let local_bind = context.local_bind_for(self.proxy);
        let proxy = self.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut stream = connect_tokio_tcp(proxy.proxy, local_bind, proxy.timeout).await?;
                socks5_authenticate(
                    &mut stream,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await?;
                socks5_request(&mut stream, 1, &destination).await?;
                Ok::<_, Error>(stream)
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "SOCKS5 CONNECT timed out"))??;
            Ok(Box::new(result) as BoxAsyncStream)
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
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut control =
                    connect_tokio_tcp(proxy.proxy, Some(local_bind), proxy.timeout).await?;
                socks5_authenticate(
                    &mut control,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await?;
                let unspecified = if proxy.proxy.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                } else {
                    SocketAddr::from(([0u16; 8], 0))
                };
                let reply =
                    socks5_request(&mut control, 3, &Endpoint::ip(Network::Udp, unspecified))
                        .await?;
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
                let socket = tokio::net::UdpSocket::bind(local_bind)
                    .await
                    .map_err(|error| {
                        Error::new(ErrorKind::Io, format!("bind SOCKS5 UDP socket: {error}"))
                    })?;
                Ok::<_, Error>(Socks5UdpDatagram {
                    socket,
                    relay,
                    control: Mutex::new(Some(control)),
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

#[cfg(feature = "async-proxy")]
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

#[cfg(feature = "async-proxy")]
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

#[cfg(feature = "async-proxy")]
async fn read_u16(stream: &mut tokio::net::TcpStream) -> Result<u16> {
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes).await.map_err(io_error)?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(feature = "async-proxy")]
struct Socks5UdpDatagram {
    socket: tokio::net::UdpSocket,
    relay: SocketAddr,
    // SOCKS5 keeps the TCP control connection open for the lifetime of the
    // UDP association. The mutex is only needed to make the datagram object
    // satisfy the shared AsyncDatagram Send + Sync contract; no I/O is done
    // through it after the handshake.
    control: Mutex<Option<tokio::net::TcpStream>>,
}

#[cfg(feature = "async-proxy")]
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
            let mut packet = vec![0; 64 * 1024];
            let length = self.socket.recv(&mut packet).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("SOCKS5 UDP receive: {error}"))
            })?;
            if length < 4 || packet[0..2] != [0, 0] {
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

#[cfg(feature = "async-proxy")]
fn decode_socks5_udp_endpoint(packet: &[u8]) -> Result<(Endpoint, usize)> {
    if packet.len() < 4 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "SOCKS5 UDP packet is too short",
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

#[cfg(feature = "async-proxy")]
struct TokioDatagram {
    socket: tokio::net::UdpSocket,
}

#[cfg(feature = "async-proxy")]
impl AsyncDatagram for TokioDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("UDP datagram target has wrong network"));
            }
            let address = target.addr().ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "direct UDP datagram requires an IP endpoint",
                )
            })?;
            self.socket
                .send_to(payload, address)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("UDP send: {error}")))
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

/// Authenticated Yuubinsya native-UDP adapter over any async datagram
/// transport.  The underlying transport only knows the fixed Yuubinsya server
/// endpoint; the original destination remains inside the authenticated packet
/// so full-cone NAT and proxy routing can preserve it independently.
#[cfg(feature = "async-proxy")]
pub struct YuubinsyaUdpDatagram {
    transport: Box<dyn AsyncDatagram>,
    password_hash: [u8; 32],
    server: Endpoint,
    socks5_prefix: bool,
}

/// Async proxy boundary for a native Yuubinsya UDP node.
///
/// Yuubinsya native UDP has no TCP stream operation.  Keeping that fact in
/// the proxy implementation makes accidental stream fallback impossible,
/// while `open_datagram` still creates one authenticated socket per TUN flow.
#[cfg(feature = "async-proxy")]
pub struct YuubinsyaUdpProxy {
    pub server: SocketAddr,
    pub password_hash: [u8; 32],
    pub socks5_prefix: bool,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxy for YuubinsyaUdpProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "native Yuubinsya UDP proxy has no TCP stream path",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let server = self.server;
        let password_hash = self.password_hash;
        let socks5_prefix = self.socks5_prefix;
        let fallback = match server {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let bind_address = context.local_bind_for(server).unwrap_or(fallback);
        Box::pin(async move {
            Ok(Box::new(
                YuubinsyaUdpDatagram::bind(
                    bind_address,
                    password_hash,
                    Endpoint::ip(Network::Udp, server),
                    socks5_prefix,
                )
                .await?,
            ) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Native Yuubinsya UDP server boundary.  It is intentionally transport
/// agnostic so a platform UDP socket, a TUN-facing relay, or a test fixture
/// can provide the actual datagram I/O.
#[cfg(feature = "async-proxy")]
pub struct YuubinsyaUdpServer {
    transport: Box<dyn AsyncDatagram>,
    password_hash: [u8; 32],
    socks5_prefix: bool,
}

#[cfg(feature = "async-proxy")]
impl YuubinsyaUdpServer {
    pub async fn bind(
        address: SocketAddr,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    ) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(address)
            .await
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind Yuubinsya UDP server: {error}"))
            })?;
        Ok(Self::new(
            Box::new(TokioDatagram { socket }),
            password_hash,
            socks5_prefix,
        ))
    }

    pub fn new(
        transport: Box<dyn AsyncDatagram>,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    ) -> Self {
        Self {
            transport,
            password_hash,
            socks5_prefix,
        }
    }

    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Endpoint, Endpoint)> {
        let mut packet = vec![0u8; crate::yuubinsya::MAX_SEGMENT_SIZE + 32 + 3 + 260];
        let (length, peer) = self.transport.recv_from(&mut packet).await?;
        let (target, payload) = crate::yuubinsya::decode_udp_packet(
            &self.password_hash,
            &packet[..length],
            self.socks5_prefix,
        )?;
        if buffer.len() < payload.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Yuubinsya UDP server buffer is too small",
            ));
        }
        buffer[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), target, peer))
    }

    pub async fn send_to(&self, payload: &[u8], target: Endpoint, peer: Endpoint) -> Result<usize> {
        if peer.network() != Network::Udp || peer.addr().is_none() {
            return Err(Error::invalid(
                "Yuubinsya UDP peer must be an IP UDP endpoint",
            ));
        }
        let packet = crate::yuubinsya::encode_udp_packet(
            &self.password_hash,
            &target,
            payload,
            self.socks5_prefix,
        )?;
        self.transport.send_to(&packet, peer).await?;
        Ok(payload.len())
    }

    pub fn local_addr(&self) -> Result<Endpoint> {
        self.transport.local_addr()
    }

    pub fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.transport.close()
    }
}

#[cfg(feature = "async-proxy")]
impl YuubinsyaUdpDatagram {
    pub async fn bind(
        address: SocketAddr,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
    ) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(address)
            .await
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind Yuubinsya UDP client: {error}"))
            })?;
        Self::new(
            Box::new(TokioDatagram { socket }),
            password_hash,
            server,
            socks5_prefix,
        )
    }

    pub fn new(
        transport: Box<dyn AsyncDatagram>,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
    ) -> Result<Self> {
        if server.network() != Network::Udp || server.addr().is_none() {
            return Err(Error::invalid(
                "Yuubinsya native UDP server must be an IP UDP endpoint",
            ));
        }
        Ok(Self {
            transport,
            password_hash,
            server,
            socks5_prefix,
        })
    }
}

#[cfg(feature = "async-proxy")]
impl AsyncDatagram for YuubinsyaUdpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid(
                    "Yuubinsya native UDP target has wrong network",
                ));
            }
            let packet = crate::yuubinsya::encode_udp_packet(
                &self.password_hash,
                &target,
                payload,
                self.socks5_prefix,
            )?;
            self.transport.send_to(&packet, self.server.clone()).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            // Password + optional prefix + max address + max payload.  Keep
            // this bounded and independent from the caller's output buffer so
            // truncated caller buffers cannot desynchronize the next packet.
            let mut packet = vec![0u8; crate::yuubinsya::MAX_SEGMENT_SIZE + 32 + 3 + 260];
            let (length, _) = self.transport.recv_from(&mut packet).await?;
            let (target, payload) = crate::yuubinsya::decode_udp_packet(
                &self.password_hash,
                &packet[..length],
                self.socks5_prefix,
            )?;
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Yuubinsya UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.transport.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.transport.close()
    }
}

fn authority(destination: &Endpoint) -> Result<String> {
    match destination {
        Endpoint::Ip { addr, .. } => Ok(addr.to_string()),
        Endpoint::Domain { host, port, .. } => Ok(format!("{host}:{port}")),
    }
}

fn socks_address(destination: &Endpoint) -> Result<(u8, Vec<u8>)> {
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

fn read_headers(stream: &mut TcpStream) -> Result<String> {
    let mut response = Vec::with_capacity(512);
    let mut byte = [0; 1];
    while response.len() < 16 * 1024 {
        stream.read_exact(&mut byte).map_err(io_error)?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            return String::from_utf8(response)
                .map_err(|_| Error::new(ErrorKind::Protocol, "proxy response is not UTF-8"));
        }
    }
    Err(Error::new(
        ErrorKind::Protocol,
        "proxy headers are too large",
    ))
}

fn base64_basic(username: &str, password: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = format!("{username}:{password}").into_bytes();
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DomainName, Network};
    #[cfg(feature = "async-proxy")]
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[cfg(feature = "async-proxy")]
    use std::sync::Mutex;
    use std::thread;

    #[cfg(feature = "async-proxy")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn endpoint() -> Endpoint {
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    }

    #[test]
    fn drop_and_fixed_have_expected_boundaries() {
        assert_eq!(
            DropConnector.connect(&endpoint()).unwrap_err().kind,
            ErrorKind::Closed
        );
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind test listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || listener.accept().unwrap());
        let connector = FixedConnector {
            address,
            timeout: Duration::from_secs(1),
        };
        let _stream = connector.connect(&endpoint()).unwrap();
        assert!(handle.join().is_ok());
    }

    #[test]
    fn direct_connector_honors_local_bind_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || listener.accept().unwrap().0.peer_addr().unwrap());
        let connector = DirectConnector {
            timeout: Duration::from_secs(1),
        };
        let stream = connector
            .connect_with_local(
                &Endpoint::ip(Network::Tcp, address),
                Some("127.0.0.2:0".parse().unwrap()),
            )
            .unwrap();
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(handle.join().unwrap(), stream.local_addr().unwrap());
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn direct_async_proxy_resolves_domain_when_called_without_runtime_wrapper() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0u8; 13];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        });

        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("localhost").unwrap(),
            address.port(),
        ));
        let proxy = DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        };
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"direct-domain").await.unwrap();
        assert_eq!(server.await.unwrap(), *b"direct-domain");
    }

    #[test]
    fn socks_address_encodes_domain_and_ip() {
        assert_eq!(socks_address(&endpoint()).unwrap().0, 3);
        let ip = Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap());
        assert_eq!(socks_address(&ip).unwrap(), (1, vec![192, 0, 2, 1]));
    }

    fn run_socks5_case<F>(username: Option<&str>, password: Option<&str>, handler: F) -> ErrorKind
    where
        F: FnOnce(&mut std::net::TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).unwrap();
            let mut methods = vec![0u8; usize::from(greeting[1])];
            stream.read_exact(&mut methods).unwrap();
            handler(&mut stream);
        });
        let connector = Socks5Connector {
            proxy: address,
            timeout: Duration::from_secs(1),
            username: username.map(str::to_owned),
            password: password.map(str::to_owned),
        };
        let error = connector.connect(&endpoint()).unwrap_err();
        server.join().unwrap();
        error.kind
    }

    #[test]
    fn socks5_rejects_malformed_method_auth_and_reply_matrix() {
        assert_eq!(
            run_socks5_case(None, None, |stream| {
                stream.write_all(&[5, 0xff]).unwrap();
            }),
            ErrorKind::Protocol
        );
        assert_eq!(
            run_socks5_case(None, None, |stream| {
                stream.write_all(&[5, 2]).unwrap();
            }),
            ErrorKind::Protocol
        );
        assert_eq!(
            run_socks5_case(None, None, |stream| {
                stream.write_all(&[5, 0]).unwrap();
                stream.write_all(&[5, 0, 0, 9]).unwrap();
            }),
            ErrorKind::Protocol
        );
        assert_eq!(
            run_socks5_case(Some("user"), Some("pass"), |stream| {
                stream.write_all(&[5, 2]).unwrap();
                let mut auth_header = [0u8; 2];
                stream.read_exact(&mut auth_header).unwrap();
                let mut auth_body = vec![0u8; usize::from(auth_header[1]) + 1];
                stream.read_exact(&mut auth_body).unwrap();
                stream.write_all(&[1, 1]).unwrap();
            }),
            ErrorKind::Protocol
        );
    }

    #[test]
    fn basic_auth_encoding_is_rfc4648_base64() {
        assert_eq!(base64_basic("user", "pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn http_proxy_rejects_headers_without_an_end_before_the_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let response = vec![b'x'; 16 * 1024];
            std::io::Write::write_all(&mut stream, &response).unwrap();
        });
        let connector = HttpProxyConnector {
            proxy: address,
            timeout: Duration::from_secs(1),
            username: None,
            password: None,
        };
        let error = connector.connect(&endpoint()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Protocol);
        server.join().unwrap();
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn blocking_http_connect_enters_async_stream_runtime() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                std::io::Read::read_exact(&mut stream, &mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"CONNECT example.com:443 HTTP/1.1"));
            std::io::Write::write_all(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut payload = [0u8; 5];
            std::io::Read::read_exact(&mut stream, &mut payload).unwrap();
            std::io::Write::write_all(&mut stream, &payload).unwrap();
        });
        let connector = BlockingStreamProxy {
            connector: Arc::new(HttpProxyConnector {
                proxy: address,
                timeout: Duration::from_secs(1),
                username: None,
                password: None,
            }),
        };
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        ));
        let mut stream = connector.connect(&context).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello");
        server.join().unwrap();
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn blocking_socks5_enters_async_stream_runtime() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            std::io::Read::read_exact(&mut stream, &mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            std::io::Write::write_all(&mut stream, &[5, 0]).unwrap();
            let mut request = [0u8; 10];
            std::io::Read::read_exact(&mut stream, &mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            std::io::Write::write_all(&mut stream, &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80]).unwrap();
            let mut payload = [0u8; 5];
            std::io::Read::read_exact(&mut stream, &mut payload).unwrap();
            std::io::Write::write_all(&mut stream, &payload).unwrap();
        });
        let connector = BlockingStreamProxy {
            connector: Arc::new(Socks5Connector {
                proxy: address,
                timeout: Duration::from_secs(1),
                username: None,
                password: None,
            }),
        };
        let context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        let mut stream = connector.connect(&context).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello");
        server.join().unwrap();
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_socks5_udp_associate_round_trips_authenticated_domain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 4];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            control.write_all(&[5, 2]).await.unwrap();

            let mut auth = [0u8; 1];
            control.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth[0], 1);
            let mut username_length = [0u8; 1];
            control.read_exact(&mut username_length).await.unwrap();
            let mut username = vec![0u8; usize::from(username_length[0])];
            control.read_exact(&mut username).await.unwrap();
            let mut password_length = [0u8; 1];
            control.read_exact(&mut password_length).await.unwrap();
            let mut password = vec![0u8; usize::from(password_length[0])];
            control.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            control.write_all(&[1, 0]).await.unwrap();

            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 3, 0, 1]);
            control
                .write_all(&[
                    5,
                    0,
                    0,
                    1,
                    127,
                    0,
                    0,
                    1,
                    relay_address.port().to_be_bytes()[0],
                    relay_address.port().to_be_bytes()[1],
                ])
                .await
                .unwrap();

            let mut packet = [0u8; 2048];
            let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
            assert!(length >= 12);
            assert_eq!(&packet[..4], &[0, 0, 0, 3]);
            let host_length = usize::from(packet[4]);
            let host_end = 5 + host_length;
            assert_eq!(&packet[5..host_end], b"example.com");
            let port = u16::from_be_bytes([packet[host_end], packet[host_end + 1]]);
            assert_eq!(port, 53);
            assert_eq!(&packet[host_end + 2..length], b"ping");

            let mut response = vec![0, 0, 0, 3, 11];
            response.extend_from_slice(b"example.com");
            response.extend_from_slice(&53u16.to_be_bytes());
            response.extend_from_slice(b"pong");
            relay.send_to(&response, peer).await.unwrap();

            let mut closed = [0u8; 1];
            let _ = control.read(&mut closed).await;
        });

        let proxy = Socks5AsyncProxy {
            proxy: proxy_address,
            timeout: Duration::from_secs(1),
            username: Some("user".to_owned()),
            password: Some("pass".to_owned()),
        };
        let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        let mut context = FlowContext::new(target.clone());
        context
            .local_bind_addresses
            .push("127.0.0.2".parse().unwrap());
        let datagram = proxy.open_datagram(&context).await.unwrap();
        assert_eq!(
            datagram.local_addr().unwrap().addr().unwrap().ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(datagram.send_to(b"ping", target.clone()).await.unwrap(), 4);

        let mut buffer = [0u8; 64];
        let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"pong");
        assert_eq!(response_target, target);
        datagram.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "async-proxy")]
    #[derive(Clone, Default)]
    struct MemoryDatagram {
        sent: Arc<Mutex<Vec<(Vec<u8>, Endpoint)>>>,
        received: Arc<Mutex<VecDeque<(Vec<u8>, Endpoint)>>>,
    }

    #[cfg(feature = "async-proxy")]
    impl AsyncDatagram for MemoryDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.sent.lock().unwrap().push((payload.to_vec(), target));
                Ok(payload.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async move {
                let (payload, source) = self
                    .received
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| Error::new(ErrorKind::Timeout, "memory datagram empty"))?;
                if buffer.len() < payload.len() {
                    return Err(Error::invalid("memory datagram buffer is too small"));
                }
                buffer[..payload.len()].copy_from_slice(&payload);
                Ok((payload.len(), source))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(
                Network::Udp,
                "127.0.0.1:10000".parse().unwrap(),
            ))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn yuubinsya_native_udp_adapter_authenticates_and_decodes() {
        let transport = MemoryDatagram::default();
        let received = transport.received.clone();
        let sent = transport.sent.clone();
        let password = crate::yuubinsya::derive_salt(b"password");
        let server = Endpoint::ip(Network::Udp, "192.0.2.53:5353".parse().unwrap());
        let adapter =
            YuubinsyaUdpDatagram::new(Box::new(transport), password, server.clone(), true).unwrap();
        let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        assert_eq!(adapter.send_to(b"query", target.clone()).await.unwrap(), 5);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let (decoded_target, decoded_payload) =
            crate::yuubinsya::decode_udp_packet(&password, &sent[0].0, true).unwrap();
        assert_eq!(sent[0].1, server);
        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, b"query");
        drop(sent);

        let response =
            crate::yuubinsya::encode_udp_packet(&password, &target, b"answer", true).unwrap();
        received.lock().unwrap().push_back((
            response,
            Endpoint::ip(Network::Udp, "198.51.100.8:4444".parse().unwrap()),
        ));
        let mut buffer = [0u8; 32];
        let (length, decoded_target) = adapter.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"answer");
        assert_eq!(decoded_target, target);
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn yuubinsya_native_udp_server_authenticates_and_routes_peer() {
        let transport = MemoryDatagram::default();
        let received = transport.received.clone();
        let sent = transport.sent.clone();
        let password = crate::yuubinsya::derive_salt(b"password");
        let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        let peer = Endpoint::ip(Network::Udp, "198.51.100.8:4444".parse().unwrap());
        let packet =
            crate::yuubinsya::encode_udp_packet(&password, &target, b"query", true).unwrap();
        received.lock().unwrap().push_back((packet, peer.clone()));

        let server = YuubinsyaUdpServer::new(Box::new(transport), password, true);
        let mut buffer = [0u8; 32];
        let (length, decoded_target, decoded_peer) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"query");
        assert_eq!(decoded_target, target);
        assert_eq!(decoded_peer, peer);

        assert_eq!(
            server
                .send_to(b"answer", target.clone(), peer.clone())
                .await
                .unwrap(),
            6
        );
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, peer);
        let (response_target, response_payload) =
            crate::yuubinsya::decode_udp_packet(&password, &sent[0].0, true).unwrap();
        assert_eq!(response_target, target);
        assert_eq!(response_payload, b"answer");

        let invalid_peer =
            Endpoint::domain(Network::Udp, DomainName::new("peer.test").unwrap(), 53);
        assert!(
            server
                .send_to(b"answer", target, invalid_peer)
                .await
                .is_err()
        );
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn yuubinsya_native_udp_socket_client_and_server_round_trip() {
        let password = crate::yuubinsya::derive_salt(b"password");
        let server = YuubinsyaUdpServer::bind("127.0.0.1:0".parse().unwrap(), password, true)
            .await
            .unwrap();
        let server_address = server.local_addr().unwrap();
        let client = YuubinsyaUdpDatagram::bind(
            "127.0.0.1:0".parse().unwrap(),
            password,
            server_address,
            true,
        )
        .await
        .unwrap();
        let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);

        client.send_to(b"query", target.clone()).await.unwrap();
        let mut server_buffer = [0u8; 64];
        let (server_length, decoded_target, peer) =
            server.recv_from(&mut server_buffer).await.unwrap();
        assert_eq!(&server_buffer[..server_length], b"query");
        assert_eq!(decoded_target, target);
        server
            .send_to(b"answer", target.clone(), peer)
            .await
            .unwrap();

        let mut client_buffer = [0u8; 64];
        let (client_length, client_target) = client.recv_from(&mut client_buffer).await.unwrap();
        assert_eq!(&client_buffer[..client_length], b"answer");
        assert_eq!(client_target, target);
    }
}
