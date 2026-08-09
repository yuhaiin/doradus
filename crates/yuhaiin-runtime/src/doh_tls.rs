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
use yuhaiin_core::proxy::{BoxAsyncStream, connect_tokio_tcp};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, Result};

pub type RustCryptoTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Clone)]
pub struct RustCryptoTlsDialer {
    tls: TlsConnector,
    timeout: Duration,
    local_bind_addresses: Arc<[IpAddr]>,
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
        }
    }

    pub fn with_local_bind_addresses(mut self, addresses: &[IpAddr]) -> Self {
        self.local_bind_addresses = Arc::from(addresses.to_vec().into_boxed_slice());
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<RustCryptoTlsStream> {
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
            match connect_tokio_tcp(remote, local_bind, self.timeout).await {
                Ok(stream) => break stream,
                Err(error) => last_error = Some(error),
            }
        };
        stream
            .set_nodelay(true)
            .map_err(|error| Error::new(ErrorKind::Io, format!("TLS TCP_NODELAY: {error}")))?;
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
