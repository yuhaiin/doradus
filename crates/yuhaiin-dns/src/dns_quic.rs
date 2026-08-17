//! DNS-over-QUIC transport (RFC 9250) backed by Quinn.
//!
//! The resolver keeps the existing packet-level DNS boundary. Quinn owns the
//! QUIC connection and stream state, while the runtime proxy datagram is
//! adapted to Quinn's polling socket contract when the resolver is routed
//! through a proxy chain.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, validate_query_packet,
    validate_response_packet,
};
use crate::dns_datagram::{AsyncDnsDatagram, DnsDatagramConnector, resolve_server_with_resolver};
use crate::dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery,
};
use crate::transport::bind_udp_socket;
use crate::{BoxFuture, DomainName, Error, ErrorKind, LocalBoxFuture, Result};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

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
const MAX_QUIC_DATAGRAM: usize = 65_535;

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
        // rustls-rustcrypto currently exposes no QUIC packet suite. The
        // default constructor therefore supplies a ring-backed config; callers
        // using from_client_config must provide a QUIC-capable provider too.
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

#[derive(Debug)]
struct DirectDatagram {
    socket: Arc<UdpSocket>,
}

impl DirectDatagram {
    async fn bind(
        server: SocketAddr,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<Self> {
        let bind_address = local_bind_addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == server.is_ipv4())
            .map(|address| SocketAddr::new(address, 0))
            .unwrap_or_else(|| {
                if server.is_ipv4() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                }
            });
        let socket = bind_udp_socket(bind_address, server, bind_interface, "DoQ").await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }
}

impl AsyncDnsDatagram for DirectDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.socket
                .send_to(payload, target)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("send DoQ UDP packet: {error}")))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (length, address) = self.socket.recv_from(buffer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("receive DoQ UDP packet: {error}"))
            })?;
            Ok((length, address))
        })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, format!("DoQ UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
struct InboundDatagram {
    payload: Vec<u8>,
    source: SocketAddr,
}

#[derive(Debug)]
struct OutboundDatagram {
    payload: Vec<u8>,
    target: SocketAddr,
}

struct QuinnDatagram {
    local_addr: SocketAddr,
    send: mpsc::UnboundedSender<OutboundDatagram>,
    recv: Mutex<mpsc::UnboundedReceiver<InboundDatagram>>,
    send_closed: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    closed: Arc<AtomicBool>,
}

impl fmt::Debug for QuinnDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuinnDatagram")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl QuinnDatagram {
    fn new(datagram: Box<dyn AsyncDnsDatagram>) -> Result<Self> {
        let datagram: Arc<dyn AsyncDnsDatagram> = Arc::from(datagram);
        let local_addr = datagram.local_addr()?;
        let (send, mut send_rx) = mpsc::unbounded_channel::<OutboundDatagram>();
        let (recv_tx, recv) = mpsc::unbounded_channel::<InboundDatagram>();
        let send_closed = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let sender_datagram = datagram.clone();
        let sender_shutdown = shutdown.clone();
        let sender_closed = closed.clone();
        let sender_send_closed = send_closed.clone();
        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = sender_shutdown.notified() => break,
                    packet = send_rx.recv() => packet,
                };
                let Some(packet) = packet else {
                    break;
                };
                if sender_datagram
                    .send_to(&packet.payload, packet.target)
                    .await
                    .is_err()
                {
                    sender_send_closed.store(true, Ordering::Release);
                    break;
                }
            }
            let _ = sender_datagram.close().await;
            sender_closed.store(true, Ordering::Release);
        });

        let receiver_datagram = datagram;
        let receiver_shutdown = shutdown.clone();
        let receiver_closed = closed.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_QUIC_DATAGRAM];
            loop {
                if receiver_closed.load(Ordering::Acquire) {
                    break;
                };
                let received = tokio::select! {
                    _ = receiver_shutdown.notified() => break,
                    received = receiver_datagram.recv_from(&mut buffer) => received,
                };
                let Ok((length, source)) = received else {
                    break;
                };
                if recv_tx
                    .send(InboundDatagram {
                        payload: buffer[..length].to_vec(),
                        source,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Self {
            local_addr,
            send,
            recv: Mutex::new(recv),
            send_closed,
            shutdown,
            closed,
        })
    }
}

impl Drop for QuinnDatagram {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
    }
}

impl quinn::AsyncUdpSocket for QuinnDatagram {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        let _ = self;
        Box::pin(AlwaysWritablePoller)
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        if self.send_closed.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP sender closed",
            ));
        }
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 {
            return Ok(());
        }
        for payload in transmit.contents.chunks(segment_size) {
            self.send
                .send(OutboundDatagram {
                    payload: payload.to_vec(),
                    target: transmit.destination,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DoQ UDP sender closed"))?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(metadata) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut recv = match self.recv.lock() {
            Ok(recv) => recv,
            Err(_) => return Poll::Ready(Err(io::Error::other("DoQ UDP receive lock poisoned"))),
        };
        match Pin::new(&mut *recv).poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let length = packet.payload.len().min(buffer.len());
                buffer[..length].copy_from_slice(&packet.payload[..length]);
                *metadata = quinn::udp::RecvMeta {
                    addr: packet.source,
                    len: length,
                    stride: length,
                    ..Default::default()
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP receiver closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct AlwaysWritablePoller;

impl quinn::UdpPoller for AlwaysWritablePoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
