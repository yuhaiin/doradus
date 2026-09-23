use super::*;

/// The selected runtime proxy plus its persisted public configuration.
/// Keeping both together makes future HTTP handlers able to expose stable
/// metadata without reconstructing or serializing protocol internals.
pub struct ProxyBuild {
    pub config: GoProxyRuntimeConfig,
    pub proxy: Arc<dyn AsyncProxy>,
}

/// Resolve final domain destinations once per accepted flow before a direct
/// socket is opened. The context still carries the domain, so protocol layers
/// such as TLS, HTTP/2 and Yuubinsya preserve their domain/SNI semantics; only
/// the direct transport reads `FlowContext::proxy_destination`.
pub struct ResolvingProxy {
    inner: Arc<dyn AsyncProxy>,
    direct_resolver: Arc<dyn AsyncIpResolver>,
    proxy_resolver: Arc<dyn AsyncIpResolver>,
}

impl ResolvingProxy {
    pub(in crate::plane) fn new(
        inner: Arc<dyn AsyncProxy>,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Self {
        Self {
            inner,
            direct_resolver: Arc::clone(&resolver),
            proxy_resolver: resolver,
        }
    }

    pub(in crate::plane) fn with_route_resolvers(
        inner: Arc<dyn AsyncProxy>,
        direct_resolver: Arc<dyn AsyncIpResolver>,
        proxy_resolver: Arc<dyn AsyncIpResolver>,
    ) -> Self {
        Self {
            inner,
            direct_resolver,
            proxy_resolver,
        }
    }

    fn resolve_context<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<FlowContext>> {
        let mut resolved = context.clone();
        if resolved.skip_resolve {
            return Box::pin(async move { Ok(resolved) });
        }
        let destination = resolved.effective_destination();
        let Endpoint::Domain { host, port, .. } = destination else {
            return Box::pin(async move { Ok(resolved) });
        };
        let resolver = match context.route_mode {
            RouteMode::Proxy => Arc::clone(&self.proxy_resolver),
            RouteMode::Direct | RouteMode::Bypass | RouteMode::Block => {
                Arc::clone(&self.direct_resolver)
            }
        };
        let strategy = resolved.resolver_policy.strategy;
        Box::pin(async move {
            let addresses = resolver.resolve(&host, strategy).await?;
            let address = select_resolved_address(&addresses, strategy).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("resolver returned no usable address for {host}"),
                )
            })?;
            resolved.resolved_destination = Some(vec![SocketAddr::new(address, port)]);
            Ok(resolved)
        })
    }
}

impl AsyncProxy for ResolvingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.connect(&context).await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.open_datagram(&context).await
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.ping(&context).await
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

pub fn select_resolved_address(
    addresses: &IpSet,
    strategy: ResolveStrategy,
) -> Option<std::net::IpAddr> {
    match strategy {
        ResolveStrategy::OnlyIpv6 => addresses.v6.first().copied().map(std::net::IpAddr::V6),
        ResolveStrategy::OnlyIpv4 => addresses.v4.first().copied().map(std::net::IpAddr::V4),
        ResolveStrategy::PreferIpv4 => addresses
            .v4
            .first()
            .copied()
            .map(std::net::IpAddr::V4)
            .or_else(|| addresses.v6.first().copied().map(std::net::IpAddr::V6)),
        // The v2 default is IPv6-first; a usable IPv4 answer remains a
        // fallback when no IPv6 candidate is available.
        ResolveStrategy::PreferIpv6 | ResolveStrategy::Default => addresses
            .v6
            .first()
            .copied()
            .map(std::net::IpAddr::V6)
            .or_else(|| addresses.v4.first().copied().map(std::net::IpAddr::V4)),
    }
}
