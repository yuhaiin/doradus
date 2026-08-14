//! Runtime resolver transport selection.
//!
//! The registry keeps transport construction separate from configuration
//! loading.  UDP, TCP and system DNS have safe built-ins; encrypted transports
//! are intentionally injected by the platform/application because their
//! connector, trust store and bootstrap policy are deployment-specific.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

#[cfg(feature = "http2")]
use std::marker::PhantomData;

use yuhaiin_core::dns::{DnsCache, DnsResponse};
use yuhaiin_core::dns_resolver_async::{AsyncDnsResolver, AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::dns_tcp_async::AsyncTcpDnsClient;
use yuhaiin_core::dns_udp_async::AsyncUdpDnsClient;
use yuhaiin_core::proxy::{AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network,
    ResolveStrategy, Result, RouteMode,
};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::ConnectionMonitor;

#[cfg(feature = "doh-tls")]
use crate::doh_tls::{RoutedRustCryptoH2Connector, root_store};
#[cfg(feature = "http2")]
use yuhaiin_core::http2::{H2DohClient, H2DohConnector};

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

    pub(crate) fn is_proxy_resolver(&self, id: &str) -> bool {
        self.proxy_resolver_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_deref()
            .is_some_and(|proxy_id| proxy_id == id)
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
        let selector = self
            .selector
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(selector) = selector else {
            let error = Error::new(ErrorKind::NotFound, "selected tcp node not found");
            self.record_failure(host, port, &error);
            return Err(error);
        };
        let destination = resolver_endpoint(host, port)?;
        let mut context = FlowContext::new(destination);
        context.route_mode = RouteMode::Proxy;
        let proxy = selector.select(&context);
        match proxy.connect(&context).await {
            Ok(stream) => Ok(Some(stream)),
            Err(error) => {
                self.record_failure(host, port, &error);
                Err(error)
            }
        }
    }

    pub(crate) fn record_failure(&self, host: &str, port: u16, error: &Error) {
        let monitor = self
            .monitor
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(monitor) = monitor {
            monitor.record_failure("tcp", &resolver_authority(host, port), &error.message);
        }
    }
}

fn resolver_endpoint(host: &str, port: u16) -> Result<Endpoint> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(Network::Tcp, SocketAddr::new(ip, port)));
    }
    Ok(Endpoint::domain(
        Network::Tcp,
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

#[derive(Debug, Clone, Copy)]
pub struct BuiltinResolverFactory {
    pub timeout: Duration,
    pub cache_capacity: usize,
    pub max_packet_size: usize,
}

impl BuiltinResolverFactory {
    pub fn new(timeout: Duration, cache_capacity: usize) -> Self {
        Self {
            timeout,
            cache_capacity,
            max_packet_size: 4096,
        }
    }
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
        let client = H2DohClient {
            endpoint,
            connector: (self.connector)(config)?,
        };
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(DnsCache::new(self.builtin.cache_capacity.max(1))?);
        Ok(Arc::new(TimeoutResolver::new(
            Arc::new(resolver),
            self.builtin.timeout,
        )))
    }
}

/// Direct DoH factory using the selected RustCrypto TLS provider.
///
/// This is the ready-to-use application path. Deployments that need to dial
/// through a yuhaiin proxy or use a custom bootstrap resolver can keep using
/// [`H2DohResolverFactory`] with their own `H2DohConnector`.
#[cfg(feature = "doh-tls")]
#[derive(Clone)]
pub struct RustCryptoDohResolverFactory {
    pub builtin: BuiltinResolverFactory,
    client_config: Arc<rustls::ClientConfig>,
    proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

#[cfg(feature = "doh-tls")]
impl RustCryptoDohResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        let provider = Arc::new(rustls_rustcrypto::provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("DoH TLS: {error}")))?
            .with_root_certificates(root_store(root_certificates)?)
            .with_no_client_auth();
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            client_config: Arc::new(config),
            proxy_bridge: None,
        })
    }

    pub fn from_client_config(
        config: Arc<rustls::ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            client_config: config,
            proxy_bridge: None,
        }
    }

    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.proxy_bridge = Some(bridge);
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
        let endpoint = doh_endpoint(&config.host, &config.id)?;
        let connector = RoutedRustCryptoH2Connector::from_config(
            self.client_config.clone(),
            config
                .tls_server_name
                .clone()
                .filter(|name| !name.trim().is_empty()),
            self.builtin.timeout,
            self.proxy_bridge.clone(),
            self.proxy_bridge
                .as_ref()
                .is_some_and(|bridge| bridge.is_proxy_resolver(&config.id)),
        )
        .with_local_bind_addresses(local_bind_addresses)
        .with_bind_interface(bind_interface);
        let client = H2DohClient {
            endpoint,
            connector,
        };
        let resolver = AsyncDnsResolver::new(client)
            .with_cache(DnsCache::new(self.builtin.cache_capacity.max(1))?);
        Ok(Arc::new(TimeoutResolver::new(
            Arc::new(resolver),
            self.builtin.timeout,
        )))
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
                let client = AsyncUdpDnsClient {
                    server: parse_dns_server(&config.host, 53, &config.id)?,
                    timeout: self.timeout,
                    max_packet_size: self.max_packet_size,
                    local_bind_addresses,
                    bind_interface: bind_interface.clone(),
                };
                let resolver = AsyncDnsResolver::new(client)
                    .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                Ok(Arc::new(resolver))
            }
            GoResolverTransport::Tcp => {
                let client = AsyncTcpDnsClient {
                    server: parse_dns_server(&config.host, 53, &config.id)?,
                    timeout: self.timeout,
                    max_packet_size: self.max_packet_size,
                    local_bind_addresses,
                    bind_interface,
                };
                let resolver = AsyncDnsResolver::new(client)
                    .with_cache(DnsCache::new(self.cache_capacity.max(1))?);
                Ok(Arc::new(resolver))
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use yuhaiin_core::dns::{
        AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
    };
    use yuhaiin_core::dns_tcp_async::AsyncTcpDnsServer;
    use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector};
    use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};

    struct BridgeProxy {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl AsyncProxy for BridgeProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            let calls = self.calls.clone();
            let fail = self.fail;
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
    fn encrypted_transports_require_an_injected_connector() {
        let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
        let error = match factory.build(&config(GoResolverTransport::Doh, "https://dns.example")) {
            Ok(_) => panic!("DoH unexpectedly had a built-in connector"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn resolver_proxy_bridge_uses_the_live_selector_only_for_proxy_resolvers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let bridge = ResolverProxyBridge::new();
        bridge.set_proxy_resolver_id(Some("proxy"));
        assert!(bridge.is_proxy_resolver("proxy"));
        assert!(!bridge.is_proxy_resolver("direct"));
        bridge.set_selector(Arc::new(FixedBridgeSelector {
            proxy: Arc::new(BridgeProxy {
                calls: calls.clone(),
                fail: false,
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
        });
        assert_eq!(calls.load(Ordering::Relaxed), 1);
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
