//! Runtime resolver transport selection.
//!
//! The registry keeps transport construction separate from configuration
//! loading.  UDP, TCP and system DNS have safe built-ins; encrypted transports
//! are intentionally injected by the platform/application because their
//! connector, trust store and bootstrap policy are deployment-specific.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

#[cfg(feature = "http2")]
use std::marker::PhantomData;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use yuhaiin_core::dns::{
    DnsCache, DnsRecordType, DnsResponse, decode_response, encode_query, response_is_truncated,
    validate_query_packet, validate_response_packet,
};
use yuhaiin_core::dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery, SystemAsyncIpResolver,
};
use yuhaiin_core::dns_tcp_async::AsyncTcpDnsClient;
use yuhaiin_core::dns_udp_async::AsyncUdpDnsClient;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network,
    ResolveStrategy, Result, RouteMode,
};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::ConnectionMonitor;

#[cfg(feature = "http2")]
use yuhaiin_core::http2::{H2DohClient, H2DohConnector};
#[cfg(feature = "doh-tls")]
use yuhaiin_dns::{
    DnsIoStream, DnsStreamConnector, DnsTlsResolverConfig, DohResolverFactory, DotResolverFactory,
};

pub trait ResolverTransportFactory: Send + Sync {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>>;

    /// Build a resolver while honoring the runtime's selected source
    /// addresses. Existing custom factories remain source-compatible and can
    /// opt in only when their transport owns a direct socket dialer.
    fn build_with_policy(
        &self,
        config: &GoResolverRuntimeConfig,
        _local_bind_addresses: &[IpAddr],
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build(config)
    }

    /// Build a resolver with both the source-address fallback and the
    /// interface policy used by runtime-owned outbound sockets. The default
    /// keeps third-party factories source-compatible; built-in transports
    /// override it because they own their sockets.
    fn build_with_policy_and_interface(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
        _bind_interface: Option<&str>,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy(config, local_bind_addresses)
    }
}

/// Late-bound outbound path used by resolver transports that are configured to
/// use the runtime's proxy resolver.
///
/// Resolver construction happens before inbound listeners create their
/// `RuntimeProxySelector`. Keeping the selector behind this bridge avoids a
/// construction cycle while still making the resolver observe the same live
/// selector and reloads as ordinary inbound flows.
#[derive(Clone, Default)]
pub struct ResolverProxyBridge {
    selector: Arc<RwLock<Option<Arc<dyn AsyncProxySelector>>>>,
    proxy_resolver_id: Arc<RwLock<Option<String>>>,
    configured_resolver_ids: Arc<RwLock<BTreeSet<String>>>,
    monitor: Arc<RwLock<Option<Weak<ConnectionMonitor>>>>,
}

impl ResolverProxyBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the resolver ID whose transport must use the proxy selector.
    /// Runtime controllers update this from the persisted route snapshot.
    pub fn set_proxy_resolver_id(&self, id: Option<&str>) {
        *self
            .proxy_resolver_id
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = id
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
    }

    /// Publish the resolver registry known by the current runtime snapshot.
    /// Go routes every configured resolver through its common DNS dialer. The
    /// reserved `bootstrap` resolver is part of that registry too; its dialer
    /// route is forced to `direct` so it can break DNS bootstrap cycles.
    pub fn set_configured_resolver_ids<I, S>(&self, ids: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let ids = ids
            .into_iter()
            .map(|id| id.as_ref().trim().to_owned())
            .filter(|id| !id.is_empty())
            .collect();
        *self
            .configured_resolver_ids
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ids;
    }

    #[cfg(test)]
    pub(crate) fn is_proxy_resolver(&self, id: &str) -> bool {
        self.route_mode_for_resolver(id) == Some(RouteMode::Proxy)
    }

    /// Return the route used by the resolver's dialer. This is intentionally
    /// separate from `is_proxy_resolver`: bootstrap must use the selector and
    /// the same direct outbound proxy as ordinary flows, while never being
    /// allowed to select the configured proxy DNS route.
    pub(crate) fn route_mode_for_resolver(&self, id: &str) -> Option<RouteMode> {
        if id.trim() == "bootstrap" {
            return Some(RouteMode::Direct);
        }
        let selected = self
            .proxy_resolver_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_deref()
            .is_some_and(|proxy_id| proxy_id == id);
        if selected
            || self
                .configured_resolver_ids
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(id)
        {
            Some(RouteMode::Proxy)
        } else {
            None
        }
    }

    /// Publish the selector used by subsequent proxy-resolver connections.
    /// Existing resolver instances observe the replacement without being
    /// rebuilt, which keeps reloads from interrupting DNS caches.
    pub fn set_selector(&self, selector: Arc<dyn AsyncProxySelector>) {
        *self
            .selector
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(selector);
    }

    #[cfg(test)]
    pub(crate) fn has_selector(&self) -> bool {
        self.selector
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    pub(crate) fn set_monitor(&self, monitor: &Arc<ConnectionMonitor>) {
        *self
            .monitor
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::downgrade(monitor));
    }

    /// Connect to a resolver endpoint through the currently published proxy
    /// selector. Proxy-routed connections fail closed until the inbound
    /// selector has been published, so bootstrap cannot silently bypass the
    /// configured route.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        use_proxy: bool,
    ) -> Result<Option<BoxAsyncStream>> {
        if !use_proxy {
            return Ok(None);
        }
        self.connect_via_selector(host, port, RouteMode::Proxy)
            .await
            .map(Some)
    }

    /// Connect through the runtime selector with a forced route mode. This is
    /// used by Go-compatible bootstrap DNS: it still enters the common
    /// dialer/monitor path, but the selected outbound slot is always direct.
    pub(crate) async fn connect_direct(&self, host: &str, port: u16) -> Result<BoxAsyncStream> {
        self.connect_via_selector(host, port, RouteMode::Direct)
            .await
    }

    async fn connect_via_selector(
        &self,
        host: &str,
        port: u16,
        route_mode: RouteMode,
    ) -> Result<BoxAsyncStream> {
        let selector = self
            .selector
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(selector) = selector else {
            let error = Error::new(ErrorKind::NotFound, "selected tcp node not found");
            self.record_failure_with_protocol("tcp", host, port, &error);
            return Err(error);
        };
        let destination = resolver_endpoint(host, port, Network::Tcp)?;
        let mut context = FlowContext::new(destination);
        context.route_mode = route_mode;
        context.skip_route = route_mode == RouteMode::Direct;
        context.skip_resolve = true;
        selector.route_context(&mut context);
        let proxy = selector.select(&context);
        match proxy.connect(&context).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.record_failure_with_protocol("tcp", host, port, &error);
                Err(error)
            }
        }
    }

    /// Open a resolver UDP endpoint through the currently published proxy
    /// selector. This is the UDP equivalent of [`Self::connect`]; keeping it
    /// on the same late-bound bridge is what makes UDP/TCP/DoH/DoT resolver
    /// traffic follow one live chain after reload.
    pub async fn open_datagram(
        &self,
        host: &str,
        port: u16,
        use_proxy: bool,
    ) -> Result<Option<Box<dyn AsyncDatagram>>> {
        if !use_proxy {
            return Ok(None);
        }
        self.open_datagram_via_selector(host, port, RouteMode::Proxy)
            .await
            .map(Some)
    }

    /// Open a UDP resolver endpoint through the common selector while forcing
    /// the direct route. See [`Self::connect_direct`].
    pub(crate) async fn open_datagram_direct(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn AsyncDatagram>> {
        self.open_datagram_via_selector(host, port, RouteMode::Direct)
            .await
    }

    async fn open_datagram_via_selector(
        &self,
        host: &str,
        port: u16,
        route_mode: RouteMode,
    ) -> Result<Box<dyn AsyncDatagram>> {
        let selector = self
            .selector
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(selector) = selector else {
            let error = Error::new(ErrorKind::NotFound, "selected udp node not found");
            self.record_failure_with_protocol("udp", host, port, &error);
            return Err(error);
        };
        let destination = resolver_endpoint(host, port, Network::Udp)?;
        let mut context = FlowContext::new(destination);
        context.route_mode = route_mode;
        context.skip_route = route_mode == RouteMode::Direct;
        selector.route_context(&mut context);
        let proxy = selector.select(&context);
        match proxy.open_datagram(&context).await {
            Ok(datagram) => Ok(datagram),
            Err(error) => {
                self.record_failure_with_protocol("udp", host, port, &error);
                Err(error)
            }
        }
    }

    fn record_failure_with_protocol(&self, protocol: &str, host: &str, port: u16, error: &Error) {
        let monitor = self
            .monitor
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(monitor) = monitor {
            monitor.record_failure(protocol, &resolver_authority(host, port), &error.message);
        }
    }
}

fn resolver_endpoint(host: &str, port: u16, network: Network) -> Result<Endpoint> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(network, SocketAddr::new(ip, port)));
    }
    Ok(Endpoint::domain(
        network,
        DomainName::new(host.trim_matches(['[', ']']))?,
        port,
    ))
}

fn resolver_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Controls what happens when a configured resolver transport cannot be
/// constructed.  `KeepUnavailable` is useful during a live reload: the
/// snapshot remains publishable, while selecting that resolver still returns
/// its recorded error instead of silently using another transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverFailurePolicy {
    FailBuild,
    KeepUnavailable,
}

/// Query-time fallback used for a resolver that was constructed successfully
/// but later loses its network or proxy path.  The fallback is the already
/// assembled application resolver, so it retains hosts/FakeIP policy and does
/// not create a second bootstrap chain.
#[derive(Clone)]
pub struct FallbackResolver {
    pub primary: Arc<dyn AsyncIpResolver>,
    pub fallback: Arc<dyn AsyncIpResolver>,
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
        record_type: yuhaiin_core::dns::DnsRecordType,
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

impl FallbackResolver {
    pub fn new(primary: Arc<dyn AsyncIpResolver>, fallback: Arc<dyn AsyncIpResolver>) -> Self {
        Self { primary, fallback }
    }
}

impl AsyncIpResolver for FallbackResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            match self.primary.resolve(domain, strategy).await {
                Ok(addresses) if !addresses.is_empty() => Ok(addresses),
                Ok(_) => self.fallback.resolve(domain, strategy).await,
                Err(primary_error) => self
                    .fallback
                    .resolve(domain, strategy)
                    .await
                    .map_err(|fallback_error| {
                        Error::new(
                            ErrorKind::Io,
                            format!(
                                "resolver primary failed: {primary_error}; fallback failed: {fallback_error}"
                            ),
                        )
                    }),
            }
        })
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: yuhaiin_core::dns::DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            match self.primary.query(domain, record_type).await {
                Ok(response) if !dns_response_empty(&response) => Ok(response),
                Ok(_) => self.fallback.query(domain, record_type).await,
                Err(primary_error) => self
                    .fallback
                    .query(domain, record_type)
                    .await
                    .map_err(|fallback_error| {
                        Error::new(
                            ErrorKind::Io,
                            format!(
                                "resolver primary failed: {primary_error}; fallback failed: {fallback_error}"
                            ),
                        )
                    }),
            }
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            match self.primary.query_packet(packet).await {
                Ok(response) => Ok(response),
                Err(primary_error) => self
                    .fallback
                    .query_packet(packet)
                    .await
                    .map_err(|fallback_error| {
                        Error::new(
                            ErrorKind::Io,
                            format!(
                                "resolver primary failed: {primary_error}; fallback failed: {fallback_error}"
                            ),
                        )
                    }),
            }
        })
    }
}

fn dns_response_empty(response: &DnsResponse) -> bool {
    response.addresses.is_empty()
        && response.ptr_names.is_empty()
        && response.service_bindings.is_empty()
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
        server: SocketAddr,
        timeout: Duration,
        max_packet_size: usize,
        bridge: Arc<ResolverProxyBridge>,
        route_mode: RouteMode,
    },
    Tcp {
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
                            bridge.open_datagram_direct(&host, server.port()).await
                        }
                        RouteMode::Proxy => bridge
                            .open_datagram(&host, server.port(), true)
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
                RouteMode::Direct => bridge.connect_direct(&host, server.port()).await,
                RouteMode::Proxy => bridge
                    .connect(&host, server.port(), true)
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
    ) -> yuhaiin_core::LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }

    fn query_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> yuhaiin_core::LocalBoxFuture<'a, Result<Vec<u8>>> {
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

/// DoH resolver factory backed by the core HTTP/2 DNS implementation.
///
/// The closure creates the connector for each persisted resolver config, so
/// the application can inject TLS verification, proxy dialing and bootstrap
/// policy without making the store or runtime depend on a concrete client.
#[cfg(feature = "http2")]
pub struct H2DohResolverFactory<F, C> {
    pub builtin: BuiltinResolverFactory,
    pub connector: F,
    connector_type: PhantomData<fn() -> C>,
}

#[cfg(feature = "http2")]
impl<F, C> H2DohResolverFactory<F, C> {
    pub fn new(timeout: Duration, cache_capacity: usize, connector: F) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            connector,
            connector_type: PhantomData,
        }
    }
}

#[cfg(feature = "http2")]
impl<F, C> ResolverTransportFactory for H2DohResolverFactory<F, C>
where
    F: Fn(&GoResolverRuntimeConfig) -> Result<C> + Send + Sync,
    C: H2DohConnector + 'static,
{
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        if config.transport != GoResolverTransport::Doh {
            return self.builtin.build(config);
        }
        let endpoint = doh_endpoint(&config.host, &config.id)?;
        let client = H2DohClient::new(endpoint, (self.connector)(config)?);
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(DnsCache::new(self.builtin.cache_capacity.max(1))?);
        Ok(Arc::new(TimeoutResolver::new(
            Arc::new(resolver),
            self.builtin.timeout,
        )))
    }
}

#[cfg(feature = "doh-tls")]
struct ResolverBridgeStreamConnector {
    bridge: Arc<ResolverProxyBridge>,
}

#[cfg(feature = "doh-tls")]
struct RuntimeDnsIoStream(BoxAsyncStream);

#[cfg(feature = "doh-tls")]
impl AsyncRead for RuntimeDnsIoStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buffer)
    }
}

#[cfg(feature = "doh-tls")]
impl AsyncWrite for RuntimeDnsIoStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

#[cfg(feature = "doh-tls")]
impl DnsStreamConnector for ResolverBridgeStreamConnector {
    fn connect<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        port: u16,
        _local_bind_addresses: &'a [IpAddr],
        _bind_interface: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<DnsIoStream>>> {
        Box::pin(async move {
            let Some(route_mode) = self.bridge.route_mode_for_resolver(resolver_id) else {
                return Ok(None);
            };
            let stream = match route_mode {
                RouteMode::Direct => self.bridge.connect_direct(host, port).await?,
                RouteMode::Proxy => self
                    .bridge
                    .connect(host, port, true)
                    .await?
                    .ok_or_else(|| Error::invalid("DNS proxy TCP transport was not opened"))?,
                RouteMode::Bypass | RouteMode::Block => {
                    return Err(Error::invalid("unsupported DNS resolver route mode"));
                }
            };
            let stream: DnsIoStream = Box::pin(RuntimeDnsIoStream(stream));
            Ok(Some(stream))
        })
    }
}

#[cfg(feature = "http2")]
fn doh_endpoint(host: &str, id: &str) -> Result<http::Uri> {
    let host = host.trim();
    let endpoint = if host.contains("://") {
        host.to_owned()
    } else {
        format!("https://{host}/dns-query")
    };
    endpoint.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has invalid DoH endpoint: {error}"),
        )
    })
}

#[cfg(feature = "doh-tls")]
fn dns_tls_config(
    config: &GoResolverRuntimeConfig,
    local_bind_addresses: &[IpAddr],
    bind_interface: Option<&str>,
) -> DnsTlsResolverConfig {
    DnsTlsResolverConfig {
        id: config.id.clone(),
        host: config.host.clone(),
        server_name: config.tls_server_name.clone(),
        local_bind_addresses: local_bind_addresses.to_vec(),
        bind_interface: bind_interface.map(str::to_owned),
    }
}

#[cfg(feature = "doh-tls")]
#[derive(Clone)]
pub struct RustCryptoDohResolverFactory {
    pub builtin: BuiltinResolverFactory,
    inner: DohResolverFactory,
}

#[cfg(feature = "doh-tls")]
impl RustCryptoDohResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            inner: DohResolverFactory::new(root_certificates, timeout, cache_capacity)?,
        })
    }

    pub fn from_client_config(
        config: Arc<rustls::ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            inner: DohResolverFactory::from_client_config(config, timeout, cache_capacity),
        }
    }

    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.builtin = self.builtin.with_proxy_bridge(bridge.clone());
        self.inner = self
            .inner
            .with_stream_connector(Arc::new(ResolverBridgeStreamConnector { bridge }));
        self
    }
}

#[cfg(feature = "doh-tls")]
impl ResolverTransportFactory for RustCryptoDohResolverFactory {
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
        if config.transport != GoResolverTransport::Doh {
            return self.builtin.build_with_policy_and_interface(
                config,
                local_bind_addresses,
                bind_interface,
            );
        }
        let resolver =
            self.inner
                .build(dns_tls_config(config, local_bind_addresses, bind_interface))?;
        Ok(Arc::new(TimeoutResolver::new(
            resolver,
            self.builtin.timeout,
        )))
    }
}

#[cfg(feature = "doh-tls")]
#[derive(Clone)]
pub struct RustCryptoDotResolverFactory {
    pub builtin: BuiltinResolverFactory,
    inner: DotResolverFactory,
}

#[cfg(feature = "doh-tls")]
impl RustCryptoDotResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            inner: DotResolverFactory::new(root_certificates, timeout, cache_capacity)?,
        })
    }

    pub fn from_client_config(
        config: Arc<rustls::ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            inner: DotResolverFactory::from_client_config(config, timeout, cache_capacity),
        }
    }

    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.builtin = self.builtin.with_proxy_bridge(bridge.clone());
        self.inner = self
            .inner
            .with_stream_connector(Arc::new(ResolverBridgeStreamConnector { bridge }));
        self
    }
}

#[cfg(feature = "doh-tls")]
impl ResolverTransportFactory for RustCryptoDotResolverFactory {
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
        if config.transport != GoResolverTransport::Dot {
            return self.builtin.build_with_policy_and_interface(
                config,
                local_bind_addresses,
                bind_interface,
            );
        }
        let resolver =
            self.inner
                .build(dns_tls_config(config, local_bind_addresses, bind_interface))?;
        Ok(Arc::new(TimeoutResolver::new(
            resolver,
            self.builtin.timeout,
        )))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yuhaiin_core::dns::{
        AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
    };
    use yuhaiin_core::dns_tcp_async::AsyncTcpDnsServer;
    use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector};
    use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};

    struct BridgeProxy {
        calls: Arc<AtomicUsize>,
        fail: bool,
        saw_skip_resolve: Option<Arc<std::sync::atomic::AtomicBool>>,
    }

    impl AsyncProxy for BridgeProxy {
        fn connect<'a>(
            &'a self,
            context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            let calls = self.calls.clone();
            let fail = self.fail;
            if let Some(flag) = &self.saw_skip_resolve {
                flag.store(context.skip_resolve, Ordering::Relaxed);
            }
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                if fail {
                    Err(Error::new(ErrorKind::Io, "proxy resolver failed"))
                } else {
                    let (stream, _peer) = tokio::io::duplex(64);
                    Ok(Box::new(stream) as BoxAsyncStream)
                }
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "test proxy has no UDP")) })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct FixedBridgeSelector {
        proxy: Arc<dyn AsyncProxy>,
    }

    impl AsyncProxySelector for FixedBridgeSelector {
        fn select(&self, _context: &FlowContext) -> Arc<dyn AsyncProxy> {
            self.proxy.clone()
        }
    }

    struct RouteModeBridgeSelector {
        direct: Arc<dyn AsyncProxy>,
        proxy: Arc<dyn AsyncProxy>,
    }

    impl AsyncProxySelector for RouteModeBridgeSelector {
        fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
            match context.route_mode {
                RouteMode::Direct => self.direct.clone(),
                RouteMode::Proxy => self.proxy.clone(),
                RouteMode::Bypass | RouteMode::Block => self.direct.clone(),
            }
        }
    }

    struct ProxyDnsDatagram {
        response: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl AsyncDatagram for ProxyDnsDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                assert_eq!(target.network(), Network::Udp);
                let query = decode_query(payload)?;
                let response = encode_response(
                    payload,
                    &DnsResponse {
                        addresses: IpSet {
                            v4: vec!["192.0.2.123".parse().unwrap()],
                            v6: Vec::new(),
                        },
                        ptr_names: Vec::new(),
                        service_bindings: Vec::new(),
                        minimum_ttl: Some(30),
                    },
                )?;
                assert_eq!(query.domain.as_str(), "proxy.example");
                *self
                    .response
                    .lock()
                    .map_err(|_| Error::new(ErrorKind::Closed, "DNS proxy response poisoned"))? =
                    Some(response);
                Ok(payload.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async move {
                let response = self
                    .response
                    .lock()
                    .map_err(|_| Error::new(ErrorKind::Closed, "DNS proxy response poisoned"))?
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::Timeout, "DNS proxy response missing"))?;
                let length = response.len();
                buffer[..length].copy_from_slice(&response);
                Ok((
                    length,
                    Endpoint::ip(Network::Udp, "127.0.0.1:53".parse().unwrap()),
                ))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(
                Network::Udp,
                "127.0.0.1:40000".parse().unwrap(),
            ))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ProxyDnsProxy {
        udp_calls: Arc<AtomicUsize>,
        tcp_calls: Arc<AtomicUsize>,
    }

    impl AsyncProxy for ProxyDnsProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            let calls = self.tcp_calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                let (stream, mut peer) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut length = [0u8; 2];
                    peer.read_exact(&mut length).await.unwrap();
                    let length = u16::from_be_bytes(length) as usize;
                    let mut query = vec![0; length];
                    peer.read_exact(&mut query).await.unwrap();
                    let response = encode_response(
                        &query,
                        &DnsResponse {
                            addresses: IpSet {
                                v4: vec!["192.0.2.124".parse().unwrap()],
                                v6: Vec::new(),
                            },
                            ptr_names: Vec::new(),
                            service_bindings: Vec::new(),
                            minimum_ttl: Some(30),
                        },
                    )
                    .unwrap();
                    peer.write_all(&(response.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    peer.write_all(&response).await.unwrap();
                });
                Ok(Box::new(stream) as BoxAsyncStream)
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            let calls = self.udp_calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(Box::new(ProxyDnsDatagram {
                    response: std::sync::Mutex::new(None),
                }) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ErrorResolver;

    impl AsyncIpResolver for ErrorResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async { Err(Error::new(ErrorKind::Timeout, "primary timeout")) })
        }
    }

    struct StaticResolver;

    struct StaticDnsHandler;

    impl AsyncDnsHandler for StaticDnsHandler {
        fn answer<'a>(
            &'a self,
            packet: &'a [u8],
        ) -> yuhaiin_core::LocalBoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                let query = decode_query(packet)?;
                assert_eq!(query.record_type, DnsRecordType::A);
                encode_response(
                    packet,
                    &DnsResponse {
                        addresses: IpSet {
                            v4: vec!["192.0.2.53".parse().unwrap()],
                            v6: Vec::new(),
                        },
                        ptr_names: Vec::new(),
                        service_bindings: Vec::new(),
                        minimum_ttl: Some(30),
                    },
                )
            })
        }
    }

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec!["192.0.2.99".parse::<std::net::Ipv4Addr>().unwrap()],
                    v6: Vec::new(),
                })
            })
        }
    }

    fn config(transport: GoResolverTransport, host: &str) -> GoResolverRuntimeConfig {
        GoResolverRuntimeConfig {
            id: "resolver-1".to_owned(),
            transport,
            host: host.to_owned(),
            subnet: None,
            tls_server_name: None,
        }
    }

    #[test]
    fn numeric_dns_server_accepts_common_ipv4_and_ipv6_forms() {
        assert_eq!(
            parse_dns_server("1.1.1.1", 53, "r").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_dns_server("[::1]", 5353, "r").unwrap(),
            "[::1]:5353".parse().unwrap()
        );
        assert_eq!(
            parse_dns_server("192.0.2.53:853", 53, "r").unwrap(),
            "192.0.2.53:853".parse().unwrap()
        );
    }

    #[test]
    fn builtins_construct_system_udp_and_tcp_without_connecting() {
        let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
        assert!(
            factory
                .build(&config(GoResolverTransport::System, "system default"))
                .is_ok()
        );
        assert!(
            factory
                .build(&config(GoResolverTransport::Udp, "192.0.2.53:53"))
                .is_ok()
        );
        assert!(
            factory
                .build(&config(GoResolverTransport::Tcp, "192.0.2.53:53"))
                .is_ok()
        );
    }

    #[test]
    fn builtin_tcp_resolver_performs_an_async_dns_query() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = AsyncTcpDnsServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                StaticDnsHandler,
                2048,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            let address = server.local_addr().unwrap();
            let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
            let resolver = factory
                .build_with_policy(
                    &config(GoResolverTransport::Tcp, &address.to_string()),
                    &["127.0.0.2".parse::<IpAddr>().unwrap()],
                )
                .unwrap();
            let domain = DomainName::new("example.com").unwrap();
            let (server_result, resolve_result) = tokio::join!(
                server.serve_once(),
                resolver.resolve(&domain, ResolveStrategy::OnlyIpv4)
            );
            assert!(server_result.unwrap() > 2);
            assert_eq!(
                resolve_result.unwrap().v4,
                vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
            );
        });
    }

    #[test]
    fn builtin_udp_resolver_uses_the_proxy_chain_for_proxy_dns() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bridge = Arc::new(ResolverProxyBridge::new());
            bridge.set_proxy_resolver_id(Some("resolver-1"));
            let udp_calls = Arc::new(AtomicUsize::new(0));
            let tcp_calls = Arc::new(AtomicUsize::new(0));
            bridge.set_selector(Arc::new(FixedBridgeSelector {
                proxy: Arc::new(ProxyDnsProxy {
                    udp_calls: udp_calls.clone(),
                    tcp_calls,
                }),
            }));
            let factory =
                BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
            let resolver = factory
                .build(&config(GoResolverTransport::Udp, "127.0.0.1:9"))
                .unwrap();
            let domain = DomainName::new("proxy.example").unwrap();
            let addresses = resolver
                .resolve(&domain, ResolveStrategy::OnlyIpv4)
                .await
                .unwrap();
            assert_eq!(
                addresses.v4,
                vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
            );
            assert_eq!(udp_calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn builtin_bootstrap_udp_resolver_enters_selector_but_uses_direct_slot() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bridge = Arc::new(ResolverProxyBridge::new());
            bridge.set_configured_resolver_ids(["bootstrap"]);
            let direct_calls = Arc::new(AtomicUsize::new(0));
            let proxy_calls = Arc::new(AtomicUsize::new(0));
            bridge.set_selector(Arc::new(RouteModeBridgeSelector {
                direct: Arc::new(ProxyDnsProxy {
                    udp_calls: direct_calls.clone(),
                    tcp_calls: Arc::new(AtomicUsize::new(0)),
                }),
                proxy: Arc::new(ProxyDnsProxy {
                    udp_calls: proxy_calls.clone(),
                    tcp_calls: Arc::new(AtomicUsize::new(0)),
                }),
            }));
            let factory =
                BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
            let resolver = factory
                .build(&GoResolverRuntimeConfig {
                    id: "bootstrap".to_owned(),
                    transport: GoResolverTransport::Udp,
                    host: "127.0.0.1:9".to_owned(),
                    subnet: None,
                    tls_server_name: None,
                })
                .unwrap();
            let domain = DomainName::new("proxy.example").unwrap();
            let addresses = resolver
                .resolve(&domain, ResolveStrategy::OnlyIpv4)
                .await
                .unwrap();
            assert_eq!(
                addresses.v4,
                vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
            );
            assert_eq!(direct_calls.load(Ordering::Relaxed), 1);
            assert_eq!(proxy_calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn builtin_tcp_resolver_uses_the_proxy_chain_for_proxy_dns() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bridge = Arc::new(ResolverProxyBridge::new());
            bridge.set_proxy_resolver_id(Some("resolver-1"));
            let udp_calls = Arc::new(AtomicUsize::new(0));
            let tcp_calls = Arc::new(AtomicUsize::new(0));
            bridge.set_selector(Arc::new(FixedBridgeSelector {
                proxy: Arc::new(ProxyDnsProxy {
                    udp_calls,
                    tcp_calls: tcp_calls.clone(),
                }),
            }));
            let factory =
                BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
            let resolver = factory
                .build(&config(GoResolverTransport::Tcp, "127.0.0.1:9"))
                .unwrap();
            let domain = DomainName::new("proxy.example").unwrap();
            let addresses = resolver
                .resolve(&domain, ResolveStrategy::OnlyIpv4)
                .await
                .unwrap();
            assert_eq!(
                addresses.v4,
                vec!["192.0.2.124".parse::<std::net::Ipv4Addr>().unwrap()]
            );
            assert_eq!(tcp_calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn encrypted_transports_require_an_injected_connector() {
        let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
        let error = match factory.build(&config(GoResolverTransport::Doh, "https://dns.example")) {
            Ok(_) => panic!("DoH unexpectedly had a built-in connector"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn resolver_proxy_bridge_routes_configured_resolvers_and_bootstrap_direct() {
        let calls = Arc::new(AtomicUsize::new(0));
        let saw_skip_resolve = Arc::new(AtomicBool::new(false));
        let bridge = ResolverProxyBridge::new();
        bridge.set_proxy_resolver_id(Some("proxy"));
        assert!(bridge.is_proxy_resolver("proxy"));
        assert!(!bridge.is_proxy_resolver("direct"));
        bridge.set_configured_resolver_ids(["direct", "bootstrap"]);
        assert!(bridge.is_proxy_resolver("direct"));
        assert!(!bridge.is_proxy_resolver("bootstrap"));
        assert_eq!(
            bridge.route_mode_for_resolver("bootstrap"),
            Some(RouteMode::Direct)
        );
        bridge.set_selector(Arc::new(FixedBridgeSelector {
            proxy: Arc::new(BridgeProxy {
                calls: calls.clone(),
                fail: false,
                saw_skip_resolve: Some(saw_skip_resolve.clone()),
            }),
        }));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(
                bridge
                    .connect("resolver.example", 443, false)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                bridge
                    .connect("resolver.example", 443, true)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(bridge.connect_direct("resolver.example", 443).await.is_ok());
        });
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(saw_skip_resolve.load(Ordering::Relaxed));
    }

    #[test]
    fn resolver_proxy_bridge_records_only_actual_proxy_connect_failures() {
        let bridge = ResolverProxyBridge::new();
        let monitor = Arc::new(ConnectionMonitor::new());
        bridge.set_monitor(&monitor);
        bridge.set_selector(Arc::new(FixedBridgeSelector {
            proxy: Arc::new(BridgeProxy {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: true,
                saw_skip_resolve: None,
            }),
        }));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = match runtime.block_on(bridge.connect("resolver.example", 443, true)) {
            Ok(_) => panic!("proxy bridge unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Io);
        let history = monitor.failed_history_value();
        assert_eq!(history["items"][0]["protocol"], "tcp");
        assert_eq!(history["items"][0]["host"], "resolver.example:443");
    }

    #[cfg(feature = "http2")]
    #[test]
    fn h2_doh_factory_constructs_a_cached_resolver_from_injected_connector() {
        struct DuplexConnector;

        impl H2DohConnector for DuplexConnector {
            type Stream = tokio::io::DuplexStream;

            fn connect<'a>(&'a self, _uri: &'a http::Uri) -> BoxFuture<'a, Result<Self::Stream>> {
                Box::pin(async {
                    let (stream, _peer) = tokio::io::duplex(4096);
                    Ok(stream)
                })
            }
        }

        let factory = H2DohResolverFactory::<_, DuplexConnector>::new(
            Duration::from_secs(1),
            8,
            |_config: &GoResolverRuntimeConfig| -> Result<DuplexConnector> { Ok(DuplexConnector) },
        );
        let resolver = factory
            .build(&config(
                GoResolverTransport::Doh,
                "https://dns.example/dns-query",
            ))
            .unwrap();
        let _ = resolver;
    }

    #[test]
    fn query_fallback_retries_empty_or_failed_primary() {
        let domain = DomainName::new("example.com").unwrap();
        let resolver = FallbackResolver::new(Arc::new(ErrorResolver), Arc::new(StaticResolver));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = runtime
            .block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv4))
            .unwrap();
        assert_eq!(
            result.v4,
            vec!["192.0.2.99".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }
}
