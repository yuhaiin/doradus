//! Encrypted resolver transports.

use super::*;

/// DoH resolver factory backed by the core HTTP/2 DNS implementation.
///
/// The closure creates the connector for each persisted resolver config, so
/// the application can inject TLS verification, proxy dialing and bootstrap
/// policy without making the store or runtime depend on a concrete client.
#[cfg(feature = "http2")]
pub struct DnsOverHttpResolverFactory<F, C> {
    pub builtin: BuiltinResolverFactory,
    pub connector: F,
    connector_type: PhantomData<fn() -> C>,
}

#[cfg(feature = "http2")]
impl<F, C> DnsOverHttpResolverFactory<F, C> {
    pub fn new(timeout: Duration, cache_capacity: usize, connector: F) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            connector,
            connector_type: PhantomData,
        }
    }
}

#[cfg(feature = "http2")]
impl<F, C> ResolverTransportFactory for DnsOverHttpResolverFactory<F, C>
where
    F: Fn(&GoResolverRuntimeConfig) -> Result<C> + Send + Sync,
    C: DnsOverHttpConnector + 'static,
{
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        if config.transport != GoResolverTransport::Doh {
            return self.builtin.build(config);
        }
        let endpoint = doh_endpoint(&config.host, &config.id)?;
        let client = DnsOverHttp::new(endpoint, (self.connector)(config)?);
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
                RouteMode::Direct => {
                    self.bridge
                        .connect_direct_for_resolver(resolver_id, host, port)
                        .await?
                }
                RouteMode::Proxy => self
                    .bridge
                    .connect_for_resolver(resolver_id, host, port, true)
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
pub struct RustlsDohResolverFactory {
    pub builtin: BuiltinResolverFactory,
    inner: DohResolverFactory,
}

#[cfg(feature = "doh-tls")]
impl RustlsDohResolverFactory {
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
impl ResolverTransportFactory for RustlsDohResolverFactory {
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
pub struct RustlsDotResolverFactory {
    pub builtin: BuiltinResolverFactory,
    inner: DotResolverFactory,
}

#[cfg(feature = "doh-tls")]
impl RustlsDotResolverFactory {
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
impl ResolverTransportFactory for RustlsDotResolverFactory {
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
