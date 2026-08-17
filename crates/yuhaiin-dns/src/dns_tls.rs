//! DNS-over-TLS and DNS-over-HTTPS transport implementations.
//!
//! DNS framing, TLS handshakes and encrypted resolver composition live here.
//! Hosts that need a proxy chain only provide a [`DnsStreamConnector`]; the
//! runtime does not need to own DoH/DoT protocol code.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, validate_query_packet,
    validate_response_packet,
};
use crate::dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery,
};
use crate::http2::{H2DohClient, H2DohConnector};
use crate::transport::connect_tcp;
use crate::{BoxFuture, DomainName, Error, ErrorKind, LocalBoxFuture, Result};

const MAX_DNS_FRAME: usize = u16::MAX as usize;

pub trait DnsIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> DnsIo for T {}

pub type DnsIoStream = Pin<Box<dyn DnsIo>>;
pub type DnsTlsStream = tokio_rustls::client::TlsStream<DnsIoStream>;

pub trait DnsStreamConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        port: u16,
        local_bind_addresses: &'a [IpAddr],
        bind_interface: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<DnsIoStream>>>;
}

pub trait DnsTlsConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        port: u16,
        server_name: &'a str,
        local_bind_addresses: &'a [IpAddr],
        bind_interface: Option<&'a str>,
    ) -> BoxFuture<'a, Result<DnsTlsStream>>;
}

#[derive(Debug, Clone)]
pub struct DnsTlsResolverConfig {
    pub id: String,
    pub host: String,
    pub server_name: Option<String>,
    pub local_bind_addresses: Vec<IpAddr>,
    pub bind_interface: Option<String>,
}

#[derive(Clone)]
pub struct RustCryptoTlsConnector {
    tls: TlsConnector,
    timeout: Duration,
    stream_connector: Option<Arc<dyn DnsStreamConnector>>,
}

impl RustCryptoTlsConnector {
    pub fn from_config(config: Arc<ClientConfig>, timeout: Duration) -> Self {
        Self {
            tls: TlsConnector::from(config),
            timeout,
            stream_connector: None,
        }
    }

    pub fn with_stream_connector(mut self, connector: Arc<dyn DnsStreamConnector>) -> Self {
        self.stream_connector = Some(connector);
        self
    }

    async fn connect_inner(
        &self,
        resolver_id: &str,
        host: &str,
        port: u16,
        server_name: &str,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<DnsTlsStream> {
        let raw = match &self.stream_connector {
            Some(connector) => match connector
                .connect(
                    resolver_id,
                    host,
                    port,
                    local_bind_addresses,
                    bind_interface,
                )
                .await?
            {
                Some(stream) => stream,
                None => {
                    direct_stream(
                        host,
                        port,
                        local_bind_addresses,
                        bind_interface,
                        self.timeout,
                    )
                    .await?
                }
            },
            None => {
                direct_stream(
                    host,
                    port,
                    local_bind_addresses,
                    bind_interface,
                    self.timeout,
                )
                .await?
            }
        };
        let server_name = tls_server_name(server_name)?;
        tokio::time::timeout(self.timeout, self.tls.connect(server_name, raw))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TLS handshake timed out"))?
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("DNS TLS handshake: {error}")))
    }
}

impl DnsTlsConnector for RustCryptoTlsConnector {
    fn connect<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        port: u16,
        server_name: &'a str,
        local_bind_addresses: &'a [IpAddr],
        bind_interface: Option<&'a str>,
    ) -> BoxFuture<'a, Result<DnsTlsStream>> {
        Box::pin(async move {
            self.connect_inner(
                resolver_id,
                host,
                port,
                server_name,
                local_bind_addresses,
                bind_interface,
            )
            .await
        })
    }
}

#[derive(Clone)]
pub struct RustCryptoH2Connector {
    tls: RustCryptoTlsConnector,
    resolver_id: String,
    server_name: Option<String>,
    local_bind_addresses: Arc<[IpAddr]>,
    bind_interface: Option<String>,
}

impl RustCryptoH2Connector {
    pub fn new(
        tls: RustCryptoTlsConnector,
        resolver_id: String,
        server_name: Option<String>,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Self {
        Self {
            tls,
            resolver_id,
            server_name,
            local_bind_addresses: Arc::from(local_bind_addresses.to_vec().into_boxed_slice()),
            bind_interface: bind_interface.map(str::to_owned),
        }
    }
}

impl H2DohConnector for RustCryptoH2Connector {
    type Stream = DnsTlsStream;

    fn connect<'a>(&'a self, uri: &'a Uri) -> BoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| Error::invalid("DoH endpoint has no host"))?;
            let port = uri.port_u16().unwrap_or(443);
            let server_name = self.server_name.as_deref().unwrap_or(host);
            let stream = self
                .tls
                .connect(
                    &self.resolver_id,
                    host,
                    port,
                    server_name,
                    &self.local_bind_addresses,
                    self.bind_interface.as_deref(),
                )
                .await?;
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

#[derive(Clone)]
pub struct DohResolverFactory {
    client_config: Arc<ClientConfig>,
    timeout: Duration,
    cache_capacity: usize,
    stream_connector: Option<Arc<dyn DnsStreamConnector>>,
}

impl DohResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self::from_client_config(
            client_config(root_store(root_certificates)?)?,
            timeout,
            cache_capacity,
        ))
    }

    pub fn from_client_config(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            client_config,
            timeout,
            cache_capacity,
            stream_connector: None,
        }
    }

    pub fn with_stream_connector(mut self, connector: Arc<dyn DnsStreamConnector>) -> Self {
        self.stream_connector = Some(connector);
        self
    }

    pub fn build(&self, config: DnsTlsResolverConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        let endpoint = doh_endpoint(&config.host, &config.id)?;
        let mut client_config = (*self.client_config).clone();
        if !client_config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol == b"h2")
        {
            client_config.alpn_protocols.push(b"h2".to_vec());
        }
        let tls = RustCryptoTlsConnector::from_config(Arc::new(client_config), self.timeout);
        let tls = match &self.stream_connector {
            Some(connector) => tls.with_stream_connector(connector.clone()),
            None => tls,
        };
        let client = H2DohClient::new(
            endpoint,
            RustCryptoH2Connector::new(
                tls,
                config.id,
                config.server_name,
                &config.local_bind_addresses,
                config.bind_interface.as_deref(),
            ),
        );
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(crate::dns::DnsCache::new(self.cache_capacity.max(1))?);
        Ok(Arc::new(resolver))
    }
}

#[derive(Clone)]
pub struct DotResolverFactory {
    client_config: Arc<ClientConfig>,
    timeout: Duration,
    cache_capacity: usize,
    stream_connector: Option<Arc<dyn DnsStreamConnector>>,
}

impl DotResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self::from_client_config(
            client_config(root_store(root_certificates)?)?,
            timeout,
            cache_capacity,
        ))
    }

    pub fn from_client_config(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            client_config,
            timeout,
            cache_capacity,
            stream_connector: None,
        }
    }

    pub fn with_stream_connector(mut self, connector: Arc<dyn DnsStreamConnector>) -> Self {
        self.stream_connector = Some(connector);
        self
    }

    pub fn build(&self, config: DnsTlsResolverConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        let (host, port) = split_dot_endpoint(&config.host, &config.id)?;
        let server_name = config
            .server_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| host.trim_matches(['[', ']']).to_owned());
        tls_server_name(&server_name)?;
        let tls = RustCryptoTlsConnector::from_config(self.client_config.clone(), self.timeout);
        let tls = match &self.stream_connector {
            Some(connector) => tls.with_stream_connector(connector.clone()),
            None => tls,
        };
        let client = DotClient {
            tls,
            resolver_id: config.id,
            host,
            port,
            server_name,
            max_packet_size: 4096,
            local_bind_addresses: Arc::from(config.local_bind_addresses.into_boxed_slice()),
            bind_interface: config.bind_interface,
        };
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(crate::dns::DnsCache::new(self.cache_capacity.max(1))?);
        Ok(Arc::new(resolver))
    }
}

#[derive(Clone)]
struct DotClient {
    tls: RustCryptoTlsConnector,
    resolver_id: String,
    host: String,
    port: u16,
    server_name: String,
    max_packet_size: usize,
    local_bind_addresses: Arc<[IpAddr]>,
    bind_interface: Option<String>,
}

impl DotClient {
    async fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let request = encode_query(next_transaction_id(), domain, record_type)?;
        let mut stream = self
            .tls
            .connect(
                &self.resolver_id,
                &self.host,
                self.port,
                &self.server_name,
                &self.local_bind_addresses,
                self.bind_interface.as_deref(),
            )
            .await?;
        write_frame(&mut stream, &request).await?;
        let response = read_frame(&mut stream, &request, self.max_packet_size).await?;
        decode_response(
            &response,
            u16::from_be_bytes([request[0], request[1]]),
            record_type,
        )
    }
}

impl SendAsyncDnsQuery for DotClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }
}

impl AsyncDnsQuery for DotClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }
}

pub fn root_store(certificates: &[Vec<u8>]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for certificate in certificates {
        store
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS root certificate: {error}"),
                )
            })?;
    }
    Ok(store)
}

pub fn client_config(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS provider: {error}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn webpki_client_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config(roots)
}

fn tls_server_name(name: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(name.to_owned())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))
}

async fn direct_stream(
    host: &str,
    port: u16,
    local_bind_addresses: &[IpAddr],
    bind_interface: Option<&str>,
    timeout: Duration,
) -> Result<DnsIoStream> {
    let addresses = crate::dns_resolver_async::resolve_internet_addresses(host, port).await?;
    let mut last_error = None;
    for address in addresses {
        let local_bind = local_bind_addresses
            .iter()
            .copied()
            .find(|local| local.is_ipv4() == address.ip().is_ipv4())
            .map(|local| SocketAddr::new(local, 0));
        match connect_tcp(address, local_bind, bind_interface, timeout).await {
            Ok(stream) => return Ok(Box::pin(stream)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::new(ErrorKind::Io, "DNS TLS endpoint has no address")))
}

fn doh_endpoint(host: &str, id: &str) -> Result<Uri> {
    let value = if host.contains("://") {
        host.to_owned()
    } else {
        format!("https://{host}/dns-query")
    };
    value.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has invalid DoH endpoint: {error}"),
        )
    })
}

fn split_dot_endpoint(value: &str, id: &str) -> Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() || value.contains("://") {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has an invalid DoT endpoint"),
        ));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok((value.to_owned(), 853));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port.parse::<u16>()
        && port != 0
    {
        return Ok((host.trim_matches(['[', ']']).to_owned(), port));
    }
    Ok((value.trim_matches(['[', ']']).to_owned(), 853))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, packet: &[u8]) -> Result<()> {
    if packet.is_empty() || packet.len() > MAX_DNS_FRAME {
        return Err(Error::new(ErrorKind::Protocol, "DoT request is too large"));
    }
    validate_query_packet(packet)?;
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DoT frame: {error}")))?;
    stream
        .write_all(packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DoT frame: {error}")))
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    query: &[u8],
    max_packet_size: usize,
) -> Result<Vec<u8>> {
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("read DoT frame: {error}")))?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > max_packet_size.min(MAX_DNS_FRAME) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DoT response frame exceeds limit",
        ));
    }
    let mut packet = vec![0u8; length];
    stream
        .read_exact(&mut packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("read DoT frame: {error}")))?;
    validate_response_packet(query, &packet)?;
    Ok(packet)
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
