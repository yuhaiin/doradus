//! Resolver proxy bridge.

use super::*;

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
        self.connect_for_resolver("", host, port, use_proxy).await
    }

    pub(crate) async fn connect_for_resolver(
        &self,
        resolver_id: &str,
        host: &str,
        port: u16,
        use_proxy: bool,
    ) -> Result<Option<BoxAsyncStream>> {
        if !use_proxy {
            return Ok(None);
        }
        self.connect_via_selector(resolver_id, host, port, RouteMode::Proxy)
            .await
            .map(Some)
    }

    /// Connect through the runtime selector with a forced route mode. This is
    /// used by Go-compatible bootstrap DNS: it still enters the common
    /// dialer/monitor path, but the selected outbound slot is always direct.
    pub(crate) async fn connect_direct_for_resolver(
        &self,
        resolver_id: &str,
        host: &str,
        port: u16,
    ) -> Result<BoxAsyncStream> {
        self.connect_via_selector(resolver_id, host, port, RouteMode::Direct)
            .await
    }

    async fn connect_via_selector(
        &self,
        resolver_id: &str,
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
        annotate_resolver_context(&mut context, resolver_id, host)?;
        let proxy = selector.select(&context);
        match proxy.connect(&context).await {
            Ok(stream) => {
                let stream = self.observe_stream(stream, context);
                Ok(stream)
            }
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
        self.open_datagram_for_resolver("", host, port, use_proxy)
            .await
    }

    pub(crate) async fn open_datagram_for_resolver(
        &self,
        resolver_id: &str,
        host: &str,
        port: u16,
        use_proxy: bool,
    ) -> Result<Option<Box<dyn AsyncDatagram>>> {
        if !use_proxy {
            return Ok(None);
        }
        self.open_datagram_via_selector(resolver_id, host, port, RouteMode::Proxy)
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
        self.open_datagram_direct_for_resolver("", host, port).await
    }

    pub(crate) async fn open_datagram_direct_for_resolver(
        &self,
        resolver_id: &str,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn AsyncDatagram>> {
        self.open_datagram_via_selector(resolver_id, host, port, RouteMode::Direct)
            .await
    }

    async fn open_datagram_via_selector(
        &self,
        resolver_id: &str,
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
        annotate_resolver_context(&mut context, resolver_id, host)?;
        let proxy = selector.select(&context);
        match proxy.open_datagram(&context).await {
            Ok(datagram) => Ok(self.observe_datagram(datagram, context)),
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

    fn observe_stream(&self, stream: BoxAsyncStream, context: FlowContext) -> BoxAsyncStream {
        let observer = self
            .monitor
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|monitor| monitor as Arc<dyn yuhaiin_core::flow::FlowObserver>);
        match observer {
            Some(observer) => crate::monitoring::observe_stream(observer, stream, context),
            None => stream,
        }
    }

    fn observe_datagram(
        &self,
        datagram: Box<dyn AsyncDatagram>,
        context: FlowContext,
    ) -> Box<dyn AsyncDatagram> {
        let observer = self
            .monitor
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|monitor| monitor as Arc<dyn yuhaiin_core::flow::FlowObserver>);
        match observer {
            Some(observer) => crate::monitoring::observe_datagram(observer, datagram, context),
            None => datagram,
        }
    }
}

fn annotate_resolver_context(
    context: &mut FlowContext,
    resolver_id: &str,
    host: &str,
) -> Result<()> {
    context.component = Some(if resolver_id.trim().is_empty() {
        "dns".to_owned()
    } else {
        format!("dns:{resolver_id}")
    });
    if !resolver_id.trim().is_empty() {
        context.resolver = Some(resolver_id.trim().to_owned());
    }
    if host.parse::<IpAddr>().is_err() {
        context.original_domain = Some(DomainName::new(host.trim_matches(['[', ']']))?);
    }
    Ok(())
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
