//! Builtin UDP and TCP resolver transports.

use super::*;

/// Controls what happens when a configured resolver transport cannot be
/// constructed.  `KeepUnavailable` is useful during a live reload: the
/// snapshot remains publishable, while selecting that resolver still returns
/// its recorded error instead of silently using another transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverFailurePolicy {
    FailBuild,
    KeepUnavailable,
}

/// Bounds the complete upstream resolver operation, including the response
/// body after a successful TCP/TLS connection. Dropping the timed-out future
/// also cancels the underlying h2 driver and socket operation.
#[derive(Clone)]
pub struct TimeoutResolver {
    pub inner: Arc<dyn AsyncIpResolver>,
    pub timeout: Duration,
}

impl TimeoutResolver {
    pub fn new(inner: Arc<dyn AsyncIpResolver>, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl AsyncIpResolver for TimeoutResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.inner.resolve(domain, strategy))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "DNS resolver query timed out"))?
        })
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: doradus_core::dns::DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.inner.query(domain, record_type))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "DNS resolver query timed out"))?
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.inner.query_packet(packet))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "DNS resolver query timed out"))?
        })
    }
}

#[derive(Clone)]
pub struct BuiltinResolverFactory {
    pub timeout: Duration,
    pub cache_capacity: usize,
    pub max_packet_size: usize,
    proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

impl BuiltinResolverFactory {
    pub fn new(timeout: Duration, cache_capacity: usize) -> Self {
        Self {
            timeout,
            cache_capacity,
            max_packet_size: 4096,
            proxy_bridge: None,
        }
    }

    /// Route configured UDP/TCP resolver transports through the same live
    /// selector used by inbound traffic. The bootstrap resolver is included
    /// as well, but its selector route is forced to `direct`.
    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.proxy_bridge = Some(bridge);
        self
    }
}

const MAX_DNS_TCP_FRAME: usize = u16::MAX as usize;

#[derive(Clone)]
enum RoutedDnsClient {
    Udp {
        resolver_id: String,
        server: SocketAddr,
        timeout: Duration,
        max_packet_size: usize,
        bridge: Arc<ResolverProxyBridge>,
        route_mode: RouteMode,
    },
    Tcp {
        resolver_id: String,
        server: SocketAddr,
        timeout: Duration,
        max_packet_size: usize,
        bridge: Arc<ResolverProxyBridge>,
        route_mode: RouteMode,
    },
}

impl RoutedDnsClient {
    async fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request).await?;
        decode_response(&response, id, record_type)
    }

    async fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        match self {
            Self::Udp {
                resolver_id,
                server,
                timeout,
                max_packet_size,
                bridge,
                route_mode,
            } => {
                let host = server.ip().to_string();
                let datagram = tokio::time::timeout(*timeout, async {
                    match route_mode {
                        RouteMode::Direct => {
                            bridge
                                .open_datagram_direct_for_resolver(
                                    resolver_id,
                                    &host,
                                    server.port(),
                                )
                                .await
                        }
                        RouteMode::Proxy => bridge
                            .open_datagram_for_resolver(resolver_id, &host, server.port(), true)
                            .await?
                            .ok_or_else(|| {
                                Error::invalid("proxy DNS UDP transport was not opened")
                            }),
                        RouteMode::Bypass | RouteMode::Block => {
                            Err(Error::invalid("unsupported DNS resolver route mode"))
                        }
                    }
                })
                .await
                .map_err(|_| {
                    Error::new(ErrorKind::Timeout, "connect DNS UDP resolver timed out")
                })??;
                let result = tokio::time::timeout(*timeout, async {
                    let target = Endpoint::ip(Network::Udp, *server);
                    datagram.send_to(packet, target).await?;
                    let mut response = vec![0u8; (*max_packet_size).max(512)];
                    let (size, _) = datagram.recv_from(&mut response).await?;
                    validate_response_packet(packet, &response[..size])?;
                    Ok(response[..size].to_vec())
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "DNS UDP proxy query timed out"))?;
                let close_result = datagram.close().await;
                let response = match (result, close_result) {
                    (Ok(response), Ok(())) => Ok(response),
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                }?;
                if response_is_truncated(&response)? {
                    return Self::Tcp {
                        resolver_id: resolver_id.clone(),
                        server: *server,
                        timeout: *timeout,
                        max_packet_size: *max_packet_size,
                        bridge: bridge.clone(),
                        route_mode: *route_mode,
                    }
                    .query_packet_tcp(packet)
                    .await;
                }
                Ok(response)
            }
            Self::Tcp { .. } => self.query_packet_tcp(packet).await,
        }
    }

    async fn query_packet_tcp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let Self::Tcp {
            resolver_id,
            server,
            timeout,
            max_packet_size,
            bridge,
            route_mode,
        } = self
        else {
            return Err(Error::invalid(
                "TCP DNS fallback requested for UDP transport",
            ));
        };
        if packet.len() > MAX_DNS_TCP_FRAME {
            return Err(Error::new(
                ErrorKind::Protocol,
                "DNS TCP request is too large",
            ));
        }
        let host = server.ip().to_string();
        let stream = tokio::time::timeout(*timeout, async {
            match route_mode {
                RouteMode::Direct => {
                    bridge
                        .connect_direct_for_resolver(resolver_id, &host, server.port())
                        .await
                }
                RouteMode::Proxy => bridge
                    .connect_for_resolver(resolver_id, &host, server.port(), true)
                    .await?
                    .ok_or_else(|| Error::invalid("proxy DNS TCP transport was not opened")),
                RouteMode::Bypass | RouteMode::Block => {
                    Err(Error::invalid("unsupported DNS resolver route mode"))
                }
            }
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "connect DNS TCP resolver timed out"))??;
        let response = tokio::time::timeout(*timeout, async {
            query_tcp_stream(stream, packet, *max_packet_size).await
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP proxy query timed out"))??;
        validate_response_packet(packet, &response)?;
        Ok(response)
    }
}

impl SendAsyncDnsQuery for RoutedDnsClient {
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

impl AsyncDnsQuery for RoutedDnsClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> doradus_core::LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }

    fn query_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> doradus_core::LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

async fn query_tcp_stream(
    mut stream: BoxAsyncStream,
    packet: &[u8],
    max_packet_size: usize,
) -> Result<Vec<u8>> {
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .map_err(|error| {
            Error::new(ErrorKind::Io, format!("write DNS TCP proxy frame: {error}"))
        })?;
    stream.write_all(packet).await.map_err(|error| {
        Error::new(ErrorKind::Io, format!("write DNS TCP proxy query: {error}"))
    })?;
    stream.flush().await.map_err(|error| {
        Error::new(ErrorKind::Io, format!("flush DNS TCP proxy query: {error}"))
    })?;
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("read DNS TCP proxy frame: {error}")))?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > max_packet_size.min(MAX_DNS_TCP_FRAME) {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DNS TCP proxy response exceeds configured limit: {length}"),
        ));
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).await.map_err(|error| {
        Error::new(
            ErrorKind::Io,
            format!("read DNS TCP proxy response: {error}"),
        )
    })?;
    Ok(response)
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl ResolverTransportFactory for BuiltinResolverFactory {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy(config, &[])
    }

    fn build_with_policy(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy_and_interface(config, local_bind_addresses, None)
    }

    fn build_with_policy_and_interface(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        let local_bind_addresses = Arc::from(local_bind_addresses.to_vec().into_boxed_slice());
        let bind_interface = bind_interface.map(str::to_owned);
        match config.transport {
            GoResolverTransport::System => Ok(Arc::new(SystemAsyncIpResolver)),
            GoResolverTransport::Udp => {
                let server = parse_dns_server(&config.host, 53, &config.id)?;
                if let Some((bridge, route_mode)) = self.proxy_bridge.as_ref().and_then(|bridge| {
                    bridge
                        .route_mode_for_resolver(&config.id)
                        .map(|route_mode| (bridge.clone(), route_mode))
                }) {
                    let client = RoutedDnsClient::Udp {
                        resolver_id: config.id.clone(),
                        server,
                        timeout: self.timeout,
                        max_packet_size: self.max_packet_size,
                        bridge,
                        route_mode,
                    };
                    let resolver = AsyncDnsResolver::new(client)
                        .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                    Ok(Arc::new(resolver))
                } else {
                    let client = AsyncUdpDnsClient::new(
                        server,
                        self.timeout,
                        self.max_packet_size,
                        local_bind_addresses,
                        bind_interface.clone(),
                    );
                    let resolver = AsyncDnsResolver::new(client)
                        .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                    Ok(Arc::new(resolver))
                }
            }
            GoResolverTransport::Tcp => {
                let server = parse_dns_server(&config.host, 53, &config.id)?;
                if let Some((bridge, route_mode)) = self.proxy_bridge.as_ref().and_then(|bridge| {
                    bridge
                        .route_mode_for_resolver(&config.id)
                        .map(|route_mode| (bridge.clone(), route_mode))
                }) {
                    let client = RoutedDnsClient::Tcp {
                        resolver_id: config.id.clone(),
                        server,
                        timeout: self.timeout,
                        max_packet_size: self.max_packet_size,
                        bridge,
                        route_mode,
                    };
                    let resolver = AsyncDnsResolver::new(client)
                        .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                    Ok(Arc::new(resolver))
                } else {
                    let client = AsyncTcpDnsClient {
                        server,
                        timeout: self.timeout,
                        max_packet_size: self.max_packet_size,
                        local_bind_addresses,
                        bind_interface,
                    };
                    let resolver = AsyncDnsResolver::new(client)
                        .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                    Ok(Arc::new(resolver))
                }
            }
            GoResolverTransport::Doh
            | GoResolverTransport::Dot
            | GoResolverTransport::Doq
            | GoResolverTransport::Doh3 => Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "resolver {} transport {:?} needs an injected connector",
                    config.id, config.transport
                ),
            )),
        }
    }
}

pub fn parse_dns_server(host: &str, default_port: u16, id: &str) -> Result<SocketAddr> {
    let host = host.trim();
    if host.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has an empty DNS server"),
        ));
    }
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let ip = host.parse::<IpAddr>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} DNS server must be a numeric IP address: {error}"),
        )
    })?;
    Ok(SocketAddr::new(ip, default_port))
}
