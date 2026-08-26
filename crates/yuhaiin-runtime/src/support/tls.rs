//! Runtime-owned ring-backed TLS helpers for already-routed streams and direct
//! management connections. DNS protocol framing and encrypted DNS clients
//! live in `yuhaiin-dns`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use yuhaiin_core::network::connect_tokio_tcp_with_interface;
use yuhaiin_core::proxy::{BoxAsyncStream, stream_local_addr, with_stream_local_addr};
use yuhaiin_core::{Error, ErrorKind, Result};

pub type RustlsTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Clone)]
pub struct RustlsTlsDialer {
    tls: TlsConnector,
    timeout: Duration,
    local_bind_addresses: Arc<[IpAddr]>,
    bind_interface: Option<String>,
}

impl RustlsTlsDialer {
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
    ) -> Result<RustlsTlsStream> {
        let stream = self.connect_tcp(host, port).await?;
        self.connect_stream(server_name, stream).await
    }

    /// Complete a ring-backed TLS handshake over an already established stream.
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
    let dialer = RustlsTlsDialer::from_root_store(roots, Duration::from_secs(10))?;
    let local_addr = stream_local_addr(&*stream);
    let stream = dialer.connect_boxed_stream(server_name, stream).await?;
    Ok(with_stream_local_addr(Box::new(stream), local_addr))
}

pub(crate) fn tls_server_name(name: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(name.to_owned())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))
}

pub(crate) fn client_config(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
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
