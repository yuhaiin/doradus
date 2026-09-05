//! Immutable runtime snapshot and flow-facing helpers.

use super::*;

/// Immutable configuration/runtime snapshot published after a successful
/// load. Existing flows can keep using an older snapshot during reload.
#[derive(Clone)]
pub struct RuntimeSnapshot {
    /// Process-lifetime metrics shared by every selector and data-plane
    /// owner created from this snapshot.
    pub(crate) metrics: Arc<RuntimeMetrics>,
    pub settings: RuntimeSettings,
    /// Inbound-wide policy shared by TUN and socket-based inbound servers.
    pub inbound_settings: InboundSettings,
    /// Shared Happy Eyeballs state for this immutable snapshot.  The state is
    /// replaced on reload while existing flows retain their old dialer.
    pub(crate) happy_eyeballs: Arc<doradus_core::network::HappyEyeballsV2Dialer>,
    /// Source addresses used when settings request a named/default network
    /// interface. An empty list preserves the OS default route.
    pub(crate) socket_bind_addresses: Arc<[IpAddr]>,
    /// Interface policy applied to every runtime-owned outbound socket. The
    /// automatic value is a dynamic core marker, not a cached interface name.
    pub(crate) socket_bind_interface: Option<String>,
    pub resolver: Arc<dyn AsyncIpResolver>,
    /// Resolver used by inbound DNS hijacking when the inbound FakeIP switch
    /// is enabled. It is independent from the global FakeDNS resolver.
    pub(crate) inbound_resolver: Arc<dyn AsyncIpResolver>,
    /// Resolver without FakeIP transformation, used when DNS hijacking is
    /// enabled but the `hijackDnsFakeIp` switch is disabled.
    pub(crate) dns_resolver: Arc<dyn AsyncIpResolver>,
    pub hosts: HostsTable,
    pub fakeip: Option<FakeIpPools>,
    /// FakeIP pool owned by inbound DNS hijacking. It may exist while the
    /// global `resolver.fakedns` pool is disabled.
    pub(crate) inbound_fakeip: Option<FakeIpPools>,
    pub resolvers: Vec<GoResolverRuntimeConfig>,
    pub route: Option<GoRouteRuntimeConfig>,
    pub route_rules: Vec<GoRouteRuleRecord>,
    /// Go node tags are part of routing, not only a management/API view. A
    /// route rule's tag can select a node or a mirrored tag at flow time.
    pub node_tags: Vec<GoNodeTagRecord>,
    /// Immutable route-list data shared with proxy selectors instead of
    /// being deep-cloned for every selector metadata snapshot.
    pub route_lists: Arc<RouteListSnapshot>,
    pub router: RouterRuntime,
    pub resolver_by_id: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    /// Configured resolvers wrapped with the inbound FakeIP policy.
    pub(crate) inbound_resolver_by_id: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    /// Configured resolvers without FakeIP transformation. DNS listeners use
    /// this parallel registry when inbound FakeIP responses are disabled,
    /// while `resolver_by_id` remains the flow-resolution registry.
    pub(crate) dns_resolver_by_id: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    pub resolver_errors: BTreeMap<String, String>,
    pub resolver_registry_enabled: bool,
    pub geo_metadata: Vec<MaxMindMetadataRecord>,
    pub geo: Option<Arc<dyn GeoLookup>>,
    pub proxies: Vec<GoProxyRuntimeConfig>,
    /// Persisted NAT policy shared by TUN and future management handlers.
    /// The store rejects restricted NAT, so this is always endpoint-independent
    /// Full Cone NAT for a successfully built snapshot.
    pub nat: NatConfigRecord,
}

impl RuntimeSnapshot {
    fn route_resolver_id(&self, mode: RouteMode) -> Option<&str> {
        self.route.as_ref().and_then(|route| {
            let id = match mode {
                RouteMode::Proxy => route.proxy_resolver.trim(),
                RouteMode::Direct | RouteMode::Bypass => route.direct_resolver.trim(),
                RouteMode::Block => "",
            };
            (!id.is_empty()).then_some(id)
        })
    }

    fn resolver_for_route_mode_from(
        &self,
        mode: RouteMode,
        default: &Arc<dyn AsyncIpResolver>,
        registry: &BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        let Some(id) = self.route_resolver_id(mode) else {
            return Ok(default.clone());
        };
        if !self.resolver_registry_enabled {
            return Ok(default.clone());
        }
        if let Some(resolver) = registry.get(id) {
            return Ok(resolver.clone());
        }
        if let Some(error) = self.resolver_errors.get(id) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("resolver {id:?} is unavailable: {error}"),
            ));
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("resolver {id:?} is not present in the runtime registry"),
        ))
    }

    pub fn proxy_config(&self, id: &str) -> Option<&GoProxyRuntimeConfig> {
        self.proxies.iter().find(|proxy| proxy.id == id)
    }

    pub fn require_proxy_config(&self, id: &str) -> Result<&GoProxyRuntimeConfig> {
        self.proxy_config(id).ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("proxy runtime config {id:?} was not found"),
            )
        })
    }

    pub fn resolver_for(&self, id: &str) -> Option<Arc<dyn AsyncIpResolver>> {
        self.resolver_by_id.get(id).cloned()
    }

    pub fn dns_resolver_for(&self, id: &str) -> Option<Arc<dyn AsyncIpResolver>> {
        self.dns_resolver_by_id.get(id).cloned()
    }

    pub fn require_resolver(&self, id: &str) -> Result<Arc<dyn AsyncIpResolver>> {
        if let Some(resolver) = self.resolver_for(id) {
            return Ok(resolver);
        }
        if let Some(error) = self.resolver_errors.get(id) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("resolver {id:?} is unavailable: {error}"),
            ));
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("resolver {id:?} is not present in the runtime registry"),
        ))
    }

    /// Select the resolver named by Go route settings.  An empty ID means the
    /// shared application resolver.  If no factory was supplied, the injected
    /// shared resolver is intentionally used for every route ID; this keeps
    /// the builder useful for callers that own transport construction.
    pub fn resolver_for_route_mode(&self, mode: RouteMode) -> Result<Arc<dyn AsyncIpResolver>> {
        self.resolver_for_route_mode_from(mode, &self.resolver, &self.resolver_by_id)
    }

    /// Select the configured resolver for an inbound DNS query without
    /// changing its answer into a FakeIP. The route ID is deliberately the
    /// same one used by `resolver_for_route_mode`, so toggling FakeIP cannot
    /// silently switch DNS back to the process/system resolver.
    pub fn dns_resolver_for_route_mode(&self, mode: RouteMode) -> Result<Arc<dyn AsyncIpResolver>> {
        self.resolver_for_route_mode_from(mode, &self.dns_resolver, &self.dns_resolver_by_id)
    }

    pub(crate) fn inbound_resolver_for_route_mode(
        &self,
        mode: RouteMode,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.resolver_for_route_mode_from(
            mode,
            &self.inbound_resolver,
            &self.inbound_resolver_by_id,
        )
    }

    /// Apply route mode/policy and return the resolver selected by the same
    /// snapshot.  This is the small application-facing seam used by TUN and a
    /// future HTTP/reload handler; it does not introduce another DTO layer.
    pub fn apply_route_and_select_resolver(
        &self,
        context: &mut FlowContext,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        let decision = self.apply_route(context);
        self.resolver_for_route_mode(decision.mode)
    }

    pub fn apply_route(&self, context: &mut FlowContext) -> RouteDecision {
        let matched_lists = self.route_lists.matching_names(context);
        // Go fills ConnOptions.lists from the host/process tries before the
        // nested route matcher runs. Router history must see that immutable
        // membership while each List matcher records its result.
        context.lists = matched_lists.clone();
        let decision = self.router.apply_to_context(context);
        // Keep the same snapshot-derived list after routing as well. This is
        // the complete flow-level membership used by API and statistics.
        context.lists = matched_lists;
        context.resolver = self.route_resolver_id(decision.mode).map(str::to_owned);
        decision
    }

    /// Create the NAT state and timeout that should be passed to
    /// `TunProxyRuntime::with_nat`. This keeps the persisted idle timeout and
    /// the Full Cone invariant in the same snapshot as the proxy selector.
    pub fn new_full_cone_nat(&self) -> Result<(NatTable, Duration)> {
        if !self.nat.full_cone {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "runtime only supports endpoint-independent Full Cone NAT",
            ));
        }
        let millis = u64::try_from(self.nat.idle_timeout_ms)
            .map_err(|_| Error::invalid("NAT idle timeout must be positive"))?;
        if millis == 0 {
            return Err(Error::invalid("NAT idle timeout must be positive"));
        }
        Ok((NatTable::new(), Duration::from_millis(millis)))
    }
}
