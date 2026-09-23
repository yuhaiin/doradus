//! DNS-over-QUIC transport (RFC 9250) backed by Quinn.
//!
//! The resolver keeps the existing packet-level DNS boundary. Quinn owns the
//! QUIC connection and stream state, while the runtime proxy datagram is
//! adapted to Quinn's polling socket contract when the resolver is routed
//! through a proxy chain.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, validate_query_packet,
    validate_response_packet,
};
use crate::dns_datagram::{DnsDatagramConnector, resolve_server_with_resolver};
use crate::dns_resolver::{AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery};
use crate::{BoxFuture, DomainName, Error, ErrorKind, LocalBoxFuture, Result};
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::Mutex as AsyncMutex;

const DOQ_ALPN_PROTOCOLS: &[&[u8]] = &[
    b"http/1.1",
    b"doq-i02",
    b"doq-i01",
    b"doq-i00",
    b"doq",
    b"dq",
    b"h2",
];
const DOQ_DEFAULT_PORT: u16 = 784;
const MAX_DNS_FRAME: usize = u16::MAX as usize;

#[derive(Debug, Clone)]
pub struct DoqResolverConfig {
    pub id: String,
    pub host: String,
    pub server_name: Option<String>,
    pub local_bind_addresses: Vec<IpAddr>,
    pub bind_interface: Option<String>,
}

#[derive(Clone)]
pub struct DoqResolverFactory {
    client_config: Arc<ClientConfig>,
    timeout: Duration,
    max_packet_size: usize,
    cache_capacity: usize,
    datagram_connector: Option<Arc<dyn DnsDatagramConnector>>,
    server_resolver: Option<Arc<dyn AsyncIpResolver>>,
}

impl DoqResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self::from_client_config(
            quic_client_config(root_store(root_certificates)?)?,
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
            max_packet_size: 4096,
            cache_capacity,
            datagram_connector: None,
            server_resolver: None,
        }
    }

    pub fn from_webpki_roots(timeout: Duration, cache_capacity: usize) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self::from_client_config(
            quic_client_config(roots)?,
            timeout,
            cache_capacity,
        ))
    }

    pub fn with_datagram_connector(mut self, connector: Arc<dyn DnsDatagramConnector>) -> Self {
        self.datagram_connector = Some(connector);
        self
    }

    pub fn with_server_resolver(mut self, resolver: Arc<dyn AsyncIpResolver>) -> Self {
        self.server_resolver = Some(resolver);
        self
    }

    pub fn with_max_packet_size(mut self, max_packet_size: usize) -> Self {
        self.max_packet_size = max_packet_size.clamp(512, MAX_DNS_FRAME);
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn build(&self, config: DoqResolverConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        let (host, port) = split_doq_endpoint(&config.host, &config.id)?;
        let server_name = config
            .server_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| host.trim_matches(['[', ']']).to_owned());
        validate_server_name(&server_name)?;
        let client = DoqClient::new(
            self.client_config.clone(),
            config.id,
            host,
            port,
            server_name,
            self.timeout,
            self.max_packet_size,
            &config.local_bind_addresses,
            config.bind_interface.as_deref(),
            self.datagram_connector.clone(),
            self.server_resolver.clone(),
        );
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(crate::dns::DnsCache::new(self.cache_capacity.max(1))?);
        Ok(Arc::new(resolver))
    }

    pub async fn query(
        &self,
        config: DoqResolverConfig,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        let resolver = self.build(config)?;
        tokio::time::timeout(self.timeout, resolver.query(domain, record_type))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "DoQ query timed out"))?
    }
}

pub async fn query_doq(
    factory: &DoqResolverFactory,
    config: DoqResolverConfig,
    domain: &DomainName,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    factory.query(config, domain, record_type).await
}

pub async fn probe_doq(
    factory: &DoqResolverFactory,
    config: DoqResolverConfig,
    domain: &DomainName,
    timeout: Duration,
) -> Result<Duration> {
    let started = std::time::Instant::now();
    tokio::time::timeout(timeout, factory.query(config, domain, DnsRecordType::A))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DoQ latency probe timed out"))??;
    Ok(started.elapsed())
}

#[derive(Clone)]
struct DoqClient {
    client_config: Arc<ClientConfig>,
    resolver_id: String,
    host: String,
    port: u16,
    server_name: String,
    timeout: Duration,
    max_packet_size: usize,
    local_bind_addresses: Arc<[IpAddr]>,
    bind_interface: Option<String>,
    datagram_connector: Option<Arc<dyn DnsDatagramConnector>>,
    server_resolver: Option<Arc<dyn AsyncIpResolver>>,
    endpoint: Arc<AsyncMutex<Option<Arc<DoqEndpoint>>>>,
    connection: Arc<AsyncMutex<Option<quinn::Connection>>>,
}

impl DoqClient {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_config: Arc<ClientConfig>,
        resolver_id: String,
        host: String,
        port: u16,
        server_name: String,
        timeout: Duration,
        max_packet_size: usize,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
        datagram_connector: Option<Arc<dyn DnsDatagramConnector>>,
        server_resolver: Option<Arc<dyn AsyncIpResolver>>,
    ) -> Self {
        Self {
            client_config,
            resolver_id,
            host,
            port,
            server_name,
            timeout,
            max_packet_size: max_packet_size.clamp(512, MAX_DNS_FRAME),
            local_bind_addresses: Arc::from(local_bind_addresses.to_vec().into_boxed_slice()),
            bind_interface: bind_interface.map(str::to_owned),
            datagram_connector,
            server_resolver,
            endpoint: Arc::new(AsyncMutex::new(None)),
            connection: Arc::new(AsyncMutex::new(None)),
        }
    }

    async fn endpoint(&self) -> Result<Arc<DoqEndpoint>> {
        let mut stored = self.endpoint.lock().await;
        if let Some(endpoint) = stored.as_ref() {
            return Ok(endpoint.clone());
        }

        let server =
            resolve_server_with_resolver(&self.host, self.port, self.server_resolver.as_deref())
                .await?;
        let datagram = match &self.datagram_connector {
            Some(connector) => match connector
                .open(
                    &self.resolver_id,
                    &self.host,
                    server,
                    &self.local_bind_addresses,
                    self.bind_interface.as_deref(),
                )
                .await?
            {
                Some(datagram) => datagram,
                None => Box::new(
                    DirectDatagram::bind(
                        server,
                        &self.local_bind_addresses,
                        self.bind_interface.as_deref(),
                    )
                    .await?,
                ),
            },
            None => Box::new(
                DirectDatagram::bind(
                    server,
                    &self.local_bind_addresses,
                    self.bind_interface.as_deref(),
                )
                .await?,
            ),
        };
        let socket = Arc::new(QuinnDatagram::new(datagram)?);
        let runtime = Arc::new(quinn::TokioRuntime);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .map_err(|error| Error::new(ErrorKind::Io, format!("create DoQ endpoint: {error}")))?;
        endpoint.set_default_client_config(self.quinn_client_config()?);
        let endpoint = Arc::new(DoqEndpoint { endpoint, server });
        *stored = Some(endpoint.clone());
        Ok(endpoint)
    }

    fn quinn_client_config(&self) -> Result<quinn::ClientConfig> {
        let mut tls = (*self.client_config).clone();
        tls.alpn_protocols = DOQ_ALPN_PROTOCOLS
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        // QUIC requires a provider with packet-protection support. The
        // default constructor supplies a ring-backed config; callers using
        // from_client_config must provide a QUIC-capable provider too.
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("configure DoQ TLS: {error}"))
            })?;
        Ok(quinn::ClientConfig::new(Arc::new(crypto)))
    }

    async fn connection(&self) -> Result<quinn::Connection> {
        let mut stored = self.connection.lock().await;
        if let Some(connection) = stored.as_ref() {
            return Ok(connection.clone());
        }
        let endpoint = self.endpoint().await?;
        let connecting = endpoint
            .endpoint
            .connect(endpoint.server, &self.server_name)
            .map_err(|error| Error::new(ErrorKind::Io, format!("start DoQ connection: {error}")))?;
        let connection = tokio::time::timeout(self.timeout, connecting)
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "DoQ connection timed out"))?
            .map_err(|error| Error::new(ErrorKind::Io, format!("connect DoQ server: {error}")))?;
        *stored = Some(connection.clone());
        Ok(connection)
    }

    async fn query_frame(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let connection = self.connection().await?;
        match self.query_frame_on(&connection, packet).await {
            Ok(response) => Ok(response),
            Err(error) => {
                *self.connection.lock().await = None;
                Err(error)
            }
        }
    }

    async fn query_frame_on(
        &self,
        connection: &quinn::Connection,
        packet: &[u8],
    ) -> Result<Vec<u8>> {
        if packet.is_empty() || packet.len() > MAX_DNS_FRAME {
            return Err(Error::new(
                ErrorKind::Protocol,
                "DoQ DNS message exceeds 65535 bytes",
            ));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("open DoQ stream: {error}")))?;
        send.write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("write DoQ length: {error}")))?;
        send.write_all(packet)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("write DoQ query: {error}")))?;
        send.finish()
            .map_err(|error| Error::new(ErrorKind::Io, format!("finish DoQ query: {error}")))?;
        let frame = recv
            .read_to_end(self.max_packet_size.saturating_add(2))
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("read DoQ response: {error}")))?;
        read_doq_frame(&frame, self.max_packet_size)
    }

    async fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let packet = encode_query(0, domain, record_type)?;
        let response = self.query_frame(&packet).await?;
        decode_response(&response, 0, record_type)
    }

    async fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let request_id = packet
            .get(..2)
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "DoQ query has no transaction ID"))?;
        let request_id = [request_id[0], request_id[1]];
        let mut doq_packet = packet.to_vec();
        doq_packet[..2].fill(0);
        let mut response = self.query_frame(&doq_packet).await?;
        if response.len() < 2 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "DoQ response has no transaction ID",
            ));
        }
        response[..2].copy_from_slice(&request_id);
        validate_response_packet(packet, &response)?;
        Ok(response)
    }
}

impl SendAsyncDnsQuery for DoqClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

impl AsyncDnsQuery for DoqClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

struct DoqEndpoint {
    endpoint: quinn::Endpoint,
    server: SocketAddr,
}

impl Drop for DoqEndpoint {
    fn drop(&mut self) {
        let endpoint = &self.endpoint;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            endpoint.close(quinn::VarInt::from_u32(0), b"DoQ resolver dropped");
        }));
    }
}

fn quic_client_config(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("DoQ TLS: {error}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn root_store(certificates: &[Vec<u8>]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for certificate in certificates {
        store
            .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("DoQ root certificate: {error}"),
                )
            })?;
    }
    Ok(store)
}

fn validate_server_name(name: &str) -> Result<()> {
    if name.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    rustls::pki_types::ServerName::try_from(name.to_owned())
        .map(|_| ())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid DoQ TLS server name"))
}

fn read_doq_frame(frame: &[u8], max_packet_size: usize) -> Result<Vec<u8>> {
    let length = frame
        .get(..2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]) as usize)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DoQ response has no length prefix"))?;
    if length == 0 || length > max_packet_size.min(MAX_DNS_FRAME) {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DoQ response frame exceeds configured limit: {length}"),
        ));
    }
    if frame.len() != length + 2 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!(
                "DoQ response contains {} bytes, expected {length}",
                frame.len() - 2
            ),
        ));
    }
    Ok(frame[2..].to_vec())
}

fn split_doq_endpoint(value: &str, id: &str) -> Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() || value.contains("://") {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has an invalid DoQ endpoint"),
        ));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    let host_without_brackets = value.trim_matches(['[', ']']);
    if host_without_brackets.parse::<IpAddr>().is_ok() {
        return Ok((host_without_brackets.to_owned(), DOQ_DEFAULT_PORT));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port.parse::<u16>()
        && port != 0
    {
        return Ok((host.trim_matches(['[', ']']).to_owned(), port));
    }
    Ok((value.trim_matches(['[', ']']).to_owned(), DOQ_DEFAULT_PORT))
}

#[path = "doq_socket.rs"]
mod socket;
#[cfg(test)]
use socket::QUINN_DATAGRAM_QUEUE_CAPACITY;
use socket::{DirectDatagram, QuinnDatagram};

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dns_datagram::AsyncDnsDatagram;
    use std::io;
    use tokio::sync::Notify;

    struct BlockingDatagram {
        local_addr: SocketAddr,
        send_gate: Arc<Notify>,
    }

    impl AsyncDnsDatagram for BlockingDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: SocketAddr,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.send_gate.notified().await;
                Ok(payload.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, SocketAddr)>> {
            Box::pin(std::future::pending())
        }

        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn test_transmit(payload: &[u8]) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination: "192.0.2.53:853".parse().unwrap(),
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        }
    }

    #[test]
    fn doq_response_frame_requires_exact_length() {
        assert_eq!(read_doq_frame(&[0, 2, 1, 2], 4096).unwrap(), vec![1, 2]);
        assert!(read_doq_frame(&[0, 2, 1], 4096).is_err());
        assert!(read_doq_frame(&[0, 1, 1, 2], 4096).is_err());
    }

    #[test]
    fn doq_endpoint_defaults_to_go_default_port() {
        assert_eq!(
            split_doq_endpoint("dns.example", "test").unwrap(),
            ("dns.example".into(), 784)
        );
        assert_eq!(
            split_doq_endpoint("dns.example:8853", "test").unwrap().1,
            8853
        );
        assert_eq!(
            split_doq_endpoint("[2001:db8::1]", "test").unwrap(),
            ("2001:db8::1".into(), 784)
        );
    }

    #[test]
    fn quinn_accepts_the_doq_ring_provider() {
        let client = DoqClient::new(
            quic_client_config(root_store(&[]).unwrap()).unwrap(),
            "192.0.2.1".to_owned(),
            "192.0.2.1".to_owned(),
            853,
            "192.0.2.1".to_owned(),
            Duration::from_secs(1),
            4096,
            &[],
            None,
            None,
            None,
        );
        let result = client.quinn_client_config();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn doq_factory_builds_without_opening_the_network() {
        let factory = DoqResolverFactory::new(&[], Duration::from_secs(1), 8).unwrap();
        let resolver = factory
            .build(DoqResolverConfig {
                id: "doq-test".to_owned(),
                host: "192.0.2.1:853".to_owned(),
                server_name: Some(String::new()),
                local_bind_addresses: Vec::new(),
                bind_interface: None,
            })
            .unwrap();
        let _ = resolver;
    }

    #[tokio::test]
    async fn quinn_datagram_backpressures_and_wakes_after_capacity_returns() {
        let send_gate = Arc::new(Notify::new());
        let socket = Arc::new(
            QuinnDatagram::new(Box::new(BlockingDatagram {
                local_addr: "127.0.0.1:53000".parse().unwrap(),
                send_gate: send_gate.clone(),
            }))
            .unwrap(),
        );
        let transmit = test_transmit(&[1]);

        // Let the worker take one datagram and block in the underlying
        // transport, then fill every bounded queue slot behind it.
        quinn::AsyncUdpSocket::try_send(socket.as_ref(), &transmit).unwrap();
        tokio::task::yield_now().await;
        for _ in 0..QUINN_DATAGRAM_QUEUE_CAPACITY {
            quinn::AsyncUdpSocket::try_send(socket.as_ref(), &transmit).unwrap();
        }
        let error = quinn::AsyncUdpSocket::try_send(socket.as_ref(), &transmit).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        let mut poller = quinn::AsyncUdpSocket::create_io_poller(socket.clone());
        let release = send_gate.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            release.notify_one();
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .expect("Quinn send poller was not woken after queue capacity returned")
        .unwrap();
    }
}
