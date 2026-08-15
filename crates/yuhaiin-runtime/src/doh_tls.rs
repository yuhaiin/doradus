//! Direct TLS/TCP transport shared by DoH and DoT.
//!
//! DNS framing remains in the core crate. This module owns only direct socket
//! dialing and the RustCrypto-backed TLS handshake; proxy/bootstrap variants
//! can continue using the generic injected connector boundary.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use yuhaiin_core::http2::H2DohConnector;
use yuhaiin_core::proxy::{
    BoxAsyncStream, connect_tokio_tcp_with_interface, stream_local_addr, with_stream_local_addr,
};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, Result, RouteMode};

use crate::resolver::ResolverProxyBridge;

pub type RustCryptoTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Clone)]
pub struct RustCryptoTlsDialer {
    tls: TlsConnector,
    timeout: Duration,
    local_bind_addresses: Arc<[IpAddr]>,
    bind_interface: Option<String>,
}

impl RustCryptoTlsDialer {
    pub fn from_root_store(root_store: RootCertStore, timeout: Duration) -> Result<Self> {
        Ok(Self::from_config(client_config(root_store)?, timeout))
    }

    pub fn from_config(config: Arc<ClientConfig>, timeout: Duration) -> Self {
        Self {
            tls: TlsConnector::from(config),
            timeout,
            local_bind_addresses: Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
            bind_interface: None,
        }
    }

    pub fn with_local_bind_addresses(mut self, addresses: &[IpAddr]) -> Self {
        self.local_bind_addresses = Arc::from(addresses.to_vec().into_boxed_slice());
        self
    }

    pub fn with_bind_interface(mut self, interface: Option<&str>) -> Self {
        self.bind_interface = interface.map(str::to_owned);
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("resolve TLS endpoint: {error}")))?;
        let mut last_error = None;
        let stream = loop {
            let Some(remote) = addresses.next() else {
                return Err(last_error.unwrap_or_else(|| {
                    Error::new(ErrorKind::Io, "TLS endpoint has no addresses")
                }));
            };
            let local_bind = self
                .local_bind_addresses
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == remote.ip().is_ipv4())
                .map(|address| std::net::SocketAddr::new(address, 0));
            match connect_tokio_tcp_with_interface(
                remote,
                local_bind,
                self.bind_interface.as_deref(),
                self.timeout,
            )
            .await
            {
                Ok(stream) => break stream,
                Err(error) => last_error = Some(error),
            }
        };
        stream
            .set_nodelay(true)
            .map_err(|error| Error::new(ErrorKind::Io, format!("TLS TCP_NODELAY: {error}")))?;
        Ok(stream)
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<RustCryptoTlsStream> {
        let stream = self.connect_tcp(host, port).await?;
        self.connect_stream(server_name, stream).await
    }

    /// Complete a RustCrypto TLS handshake over an already established stream.
    /// This is shared by proxy-aware management downloads and direct DoH/DoT
    /// dialing, so TLS never needs to know how the underlying connection was
    /// routed.
    pub async fn connect_boxed_stream(
        &self,
        server_name: &str,
        stream: BoxAsyncStream,
    ) -> Result<tokio_rustls::client::TlsStream<BoxAsyncStream>> {
        self.connect_stream(server_name, stream).await
    }

    async fn connect_stream<S>(
        &self,
        server_name: &str,
        stream: S,
    ) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let server_name = tls_server_name(server_name)?;
        tokio::time::timeout(self.timeout, self.tls.connect(server_name, stream))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "TLS handshake timed out"))?
            .map_err(tls_error)
    }
}

/// Wrap an already-routed stream in client TLS using the same public root set
/// as the runtime's HTTPS management and reverse-proxy paths.  Keeping this
/// at the shared TLS boundary is important: an HTTP inbound must perform the
/// origin handshake *after* its selected outbound proxy has connected, rather
/// than opening a second direct socket and bypassing routing.
pub(crate) async fn wrap_system_tls_stream(
    server_name: &str,
    stream: BoxAsyncStream,
) -> Result<BoxAsyncStream> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let dialer = RustCryptoTlsDialer::from_root_store(roots, Duration::from_secs(10))?;
    let local_addr = stream_local_addr(&*stream);
    let stream = dialer.connect_boxed_stream(server_name, stream).await?;
    Ok(with_stream_local_addr(Box::new(stream), local_addr))
}

/// A reusable direct TLS connector for one DoH endpoint.
#[derive(Clone)]
pub struct RustCryptoH2Connector {
    dialer: RustCryptoTlsDialer,
    server_name: Option<String>,
}

impl RustCryptoH2Connector {
    pub fn from_root_store(
        root_store: RootCertStore,
        server_name: Option<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let mut config = (*client_config(root_store)?).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self::from_config(Arc::new(config), server_name, timeout))
    }

    pub fn from_config(
        config: Arc<ClientConfig>,
        server_name: Option<String>,
        timeout: Duration,
    ) -> Self {
        let mut config = (*config).clone();
        if !config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol == b"h2")
        {
            config.alpn_protocols.push(b"h2".to_vec());
        }
        Self {
            dialer: RustCryptoTlsDialer::from_config(Arc::new(config), timeout),
            server_name,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.dialer.timeout()
    }

    pub fn with_local_bind_addresses(mut self, addresses: &[IpAddr]) -> Self {
        self.dialer = self.dialer.with_local_bind_addresses(addresses);
        self
    }

    pub fn with_bind_interface(mut self, interface: Option<&str>) -> Self {
        self.dialer = self.dialer.with_bind_interface(interface);
        self
    }
}

impl H2DohConnector for RustCryptoH2Connector {
    type Stream = RustCryptoTlsStream;

    fn connect<'a>(&'a self, uri: &'a http::Uri) -> BoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move {
            if uri.scheme_str() != Some("https") {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "DoH TLS connector requires an https URI",
                ));
            }
            let host = uri
                .host()
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "DoH URI has no host"))?;
            let port = uri.port_u16().unwrap_or(443);
            let server_name = self.server_name.as_deref().unwrap_or(host);
            let stream = self.dialer.connect(host, port, server_name).await?;
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "DoH TLS negotiated {:?}, expected h2",
                        stream.get_ref().1.alpn_protocol()
                    ),
                ));
            }
            Ok(stream)
        })
    }
}

/// DoH connector whose underlying TCP stream can be supplied by the runtime
/// proxy selector. The TLS layer remains identical to the direct connector;
/// only the stream acquisition boundary differs.
#[derive(Clone)]
pub(crate) struct RoutedRustCryptoH2Connector {
    dialer: RustCryptoTlsDialer,
    server_name: Option<String>,
    proxy_bridge: Option<Arc<ResolverProxyBridge>>,
    route_mode: Option<RouteMode>,
}

impl RoutedRustCryptoH2Connector {
    pub(crate) fn from_config(
        config: Arc<ClientConfig>,
        server_name: Option<String>,
        timeout: Duration,
        proxy_bridge: Option<Arc<ResolverProxyBridge>>,
        route_mode: Option<RouteMode>,
    ) -> Self {
        let mut config = (*config).clone();
        if !config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol == b"h2")
        {
            config.alpn_protocols.push(b"h2".to_vec());
        }
        Self {
            dialer: RustCryptoTlsDialer::from_config(Arc::new(config), timeout),
            server_name,
            proxy_bridge,
            route_mode,
        }
    }

    pub(crate) fn with_local_bind_addresses(mut self, addresses: &[IpAddr]) -> Self {
        self.dialer = self.dialer.with_local_bind_addresses(addresses);
        self
    }

    pub(crate) fn with_bind_interface(mut self, interface: Option<&str>) -> Self {
        self.dialer = self.dialer.with_bind_interface(interface);
        self
    }
}

impl H2DohConnector for RoutedRustCryptoH2Connector {
    type Stream = tokio_rustls::client::TlsStream<BoxAsyncStream>;

    fn connect<'a>(&'a self, uri: &'a http::Uri) -> BoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move {
            if uri.scheme_str() != Some("https") {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "DoH TLS connector requires an https URI",
                ));
            }
            let host = uri
                .host()
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "DoH URI has no host"))?;
            let port = uri.port_u16().unwrap_or(443);
            let server_name = self.server_name.as_deref().unwrap_or(host);
            let proxied = match (&self.proxy_bridge, self.route_mode) {
                (Some(bridge), Some(RouteMode::Direct)) => {
                    Some(bridge.connect_direct(host, port).await?)
                }
                (Some(bridge), Some(RouteMode::Proxy)) => bridge.connect(host, port, true).await?,
                (Some(_), Some(RouteMode::Bypass | RouteMode::Block)) => {
                    return Err(Error::invalid("unsupported DoH resolver route mode"));
                }
                _ => None,
            };
            let result = async {
                let raw = match proxied {
                    Some(stream) => stream,
                    None => Box::new(self.dialer.connect_tcp(host, port).await?) as BoxAsyncStream,
                };
                let stream = self.dialer.connect_boxed_stream(server_name, raw).await?;
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        format!(
                            "DoH TLS negotiated {:?}, expected h2",
                            stream.get_ref().1.alpn_protocol()
                        ),
                    ));
                }
                Ok(stream)
            }
            .await;
            if let Err(error) = &result
                && let Some(bridge) = &self.proxy_bridge
            {
                bridge.record_failure(host, port, error);
            }
            result
        })
    }
}

pub(crate) fn tls_server_name(name: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(name.to_owned())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))
}

pub(crate) fn client_config(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(tls_error)?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS: {error}"))
}

pub fn root_store(certificates: &[Vec<u8>]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for certificate in certificates {
        store
            .add(CertificateDer::from(certificate.clone()))
            .map_err(tls_error)?;
    }
    Ok(store)
}
