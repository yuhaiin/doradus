//! Application-neutral runtime assembly for configuration, DNS and proxies.
//!
//! The snapshot deliberately reuses the store's existing Go compatibility
//! models. It is suitable for a future HTTP/doradus-react handler without
//! introducing a second DTO tree or exposing SQLite connections.
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::interfaces;
use crate::proxy::{new_dialer, reconfigure_dialer};
use doradus_core::dns_hosts::HostsTable;
use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::dns_resolver_stack::AsyncHostsResolver;
use doradus_core::nat::NatTable;
use doradus_core::{
    DomainName, Error, ErrorKind, FlowContext, GeoLookup, ResolverPolicy, Result, RouteMode,
};
use doradus_geo::{GeoDatabaseManager, GeoMetadata};
use doradus_metrics::RuntimeMetrics;
use doradus_store::fakeip::{FakeIpPool, FakeIpPoolOptions, FakeIpV6Pool};
use doradus_store::{
    ConfigRepository, ConfigStore, FakeIpPolicy, FakeIpPools, FakeIpResolver, GoNodeTagRecord,
    GoProxyRuntimeConfig, GoResolverRuntimeConfig, GoRouteRuleRecord, GoRouteRuntimeConfig,
    InboundSettings, MaxMindMetadataRecord, NatConfigRecord,
};
use doradus_trie::router::{RouteDecision, RouterRuntime};

pub use crate::controller::RuntimeController;
pub use crate::data_plane::{
    RuntimeDnsHandler, run_dns_supervisor, wait_for_shutdown_or_inbound_reload,
    wait_for_shutdown_or_reload,
};
#[cfg(feature = "tun")]
pub use crate::data_plane::{
    TunRuntimeConfig, load_tun_config, run_tun_device_until, run_tun_device_until_ref,
};
pub use crate::defaults::DefaultAddressPlan;
pub use crate::handle::RuntimeHandle;
pub use crate::log::RuntimeLog;
pub use crate::monitor::ConnectionMonitor;
pub use crate::proxy::{ProxyBuild, RuntimeProxySelector};
#[cfg(feature = "http2")]
pub use crate::resolver::DnsOverHttpResolverFactory;
#[cfg(feature = "doh-tls")]
pub use crate::resolver::RustlsDohResolverFactory;
#[cfg(feature = "doh-tls")]
pub use crate::resolver::RustlsDotResolverFactory;
pub use crate::resolver::{
    BuiltinResolverFactory, ResolverFailurePolicy, ResolverProxyBridge, ResolverTransportFactory,
    TimeoutResolver, parse_dns_server,
};
#[cfg(feature = "doh-tls")]
pub use crate::resolver_registry::RuntimeResolverRegistry;
pub use crate::route::{
    ProxyRouteListTransport, RouteListRefreshReport, RouteListSnapshot, RouteListTransport,
    compile_go_route_rules, compile_go_route_rules_with_geo, compile_go_route_rules_with_lists,
    download_route_url_with_transport, expand_go_route_rule, load_route_lists,
    refresh_route_list_caches, refresh_route_list_caches_with_transport, route_list_cache_dir,
    route_list_cache_path, route_rule_from_go_record,
};
pub use crate::settings::{Ipv6PolicyResolver, RuntimeSettings};
#[cfg(feature = "doh-tls")]
pub use crate::tls::RustlsTlsDialer;

/// Runtime-only knobs that are not part of the persisted Go schema.
#[derive(Debug, Clone)]
pub struct RuntimeBuildOptions {
    /// Apply the same bounded FakeIP options to both address families when
    /// the persisted configuration does not provide a more specific value.
    pub fakeip_options: Option<FakeIpPoolOptions>,
    /// Preserve Go's mode that allocates FakeIP without checking upstream.
    pub fakeip_skip_check_upstream: bool,
    /// Fallback used when no persisted route rule matches.
    pub route_fallback: RouteDecision,
    /// Whether one malformed/unavailable optional resolver prevents the whole
    /// snapshot from being published.
    pub resolver_failure_policy: ResolverFailurePolicy,
}

impl Default for RuntimeBuildOptions {
    fn default() -> Self {
        Self {
            fakeip_options: None,
            fakeip_skip_check_upstream: false,
            route_fallback: RouteDecision {
                // Go's Matchers.Match returns ProxyMode when no persisted
                // rule matches. Keep the service default proxy-oriented;
                // callers that intentionally run a direct-only fixture can
                // still override this in RuntimeBuildOptions.
                mode: RouteMode::Proxy,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
            resolver_failure_policy: ResolverFailurePolicy::FailBuild,
        }
    }
}

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

    fn inbound_resolver_for(&self, id: &str) -> Option<Arc<dyn AsyncIpResolver>> {
        self.inbound_resolver_by_id.get(id).cloned()
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

    fn require_dns_resolver(&self, id: &str) -> Result<Arc<dyn AsyncIpResolver>> {
        if let Some(resolver) = self.dns_resolver_for(id) {
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

    fn require_inbound_resolver(&self, id: &str) -> Result<Arc<dyn AsyncIpResolver>> {
        if let Some(resolver) = self.inbound_resolver_for(id) {
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
        let Some(route) = &self.route else {
            return Ok(self.resolver.clone());
        };
        let id = match mode {
            RouteMode::Proxy => route.proxy_resolver.trim(),
            RouteMode::Direct | RouteMode::Bypass => route.direct_resolver.trim(),
            RouteMode::Block => "",
        };
        if id.is_empty() || !self.resolver_registry_enabled {
            return Ok(self.resolver.clone());
        }
        self.require_resolver(id)
    }

    /// Select the configured resolver for an inbound DNS query without
    /// changing its answer into a FakeIP. The route ID is deliberately the
    /// same one used by `resolver_for_route_mode`, so toggling FakeIP cannot
    /// silently switch DNS back to the process/system resolver.
    pub fn dns_resolver_for_route_mode(&self, mode: RouteMode) -> Result<Arc<dyn AsyncIpResolver>> {
        let Some(route) = &self.route else {
            return Ok(self.dns_resolver.clone());
        };
        let id = match mode {
            RouteMode::Proxy => route.proxy_resolver.trim(),
            RouteMode::Direct | RouteMode::Bypass => route.direct_resolver.trim(),
            RouteMode::Block => "",
        };
        if id.is_empty() || !self.resolver_registry_enabled {
            return Ok(self.dns_resolver.clone());
        }
        self.require_dns_resolver(id)
    }

    pub(crate) fn inbound_resolver_for_route_mode(
        &self,
        mode: RouteMode,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        let Some(route) = &self.route else {
            return Ok(self.inbound_resolver.clone());
        };
        let id = match mode {
            RouteMode::Proxy => route.proxy_resolver.trim(),
            RouteMode::Direct | RouteMode::Bypass => route.direct_resolver.trim(),
            RouteMode::Block => "",
        };
        if id.is_empty() || !self.resolver_registry_enabled {
            return Ok(self.inbound_resolver.clone());
        }
        self.require_inbound_resolver(id)
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
        context.resolver = self.route.as_ref().and_then(|route| {
            let id = match decision.mode {
                RouteMode::Proxy => route.proxy_resolver.trim(),
                RouteMode::Direct | RouteMode::Bypass => route.direct_resolver.trim(),
                RouteMode::Block => "",
            };
            (!id.is_empty()).then(|| id.to_owned())
        });
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

/// Builds one snapshot from a typed store and an already-created upstream
/// resolver. The latter is injected because its UDP/DoH connector may itself
/// depend on a proxy chain and must not be constructed recursively here.
pub struct RuntimeBuilder {
    store: ConfigStore,
    upstream: Arc<dyn AsyncIpResolver>,
    metrics: Arc<RuntimeMetrics>,
    happy_eyeballs: Arc<doradus_core::network::HappyEyeballsV2Dialer>,
    options: RuntimeBuildOptions,
    resolver_factory: Option<Arc<dyn ResolverTransportFactory>>,
    resolver_proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

/// Store-backed inputs loaded before any resolver, FakeIP or route runtime is
/// constructed. Keeping this phase typed makes fallback precedence explicit
/// and lets `build` focus on assembling immutable runtime components.
struct RuntimeInputs {
    settings: RuntimeSettings,
    inbound_settings: InboundSettings,
    socket_bind_addresses: Arc<[IpAddr]>,
    socket_bind_interface: Option<String>,
    nat: NatConfigRecord,
    hosts: HostsTable,
    resolvers: Vec<GoResolverRuntimeConfig>,
    route: Option<GoRouteRuntimeConfig>,
    route_rules: Vec<GoRouteRuleRecord>,
    node_tags: Vec<GoNodeTagRecord>,
    route_lists: Arc<RouteListSnapshot>,
    proxies: Vec<GoProxyRuntimeConfig>,
    geo_metadata: Vec<MaxMindMetadataRecord>,
    geo: Option<Arc<dyn GeoLookup>>,
    fakeip_config: Option<doradus_store::GoFakeIpRuntimeConfig>,
    fakeip_policy: FakeIpPolicy,
}

impl RuntimeBuilder {
    pub fn new(store: ConfigStore, upstream: Arc<dyn AsyncIpResolver>) -> Self {
        let metrics = Arc::new(RuntimeMetrics::new());
        Self {
            store,
            upstream,
            happy_eyeballs: new_dialer(0, Arc::clone(&metrics)),
            metrics,
            options: RuntimeBuildOptions::default(),
            resolver_factory: None,
            resolver_proxy_bridge: None,
        }
    }

    pub fn with_options(mut self, options: RuntimeBuildOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_resolver_factory(mut self, factory: Arc<dyn ResolverTransportFactory>) -> Self {
        self.resolver_factory = Some(factory);
        self
    }

    pub fn with_resolver_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.resolver_proxy_bridge = Some(bridge);
        self
    }

    pub(crate) fn resolver_proxy_bridge(&self) -> Option<Arc<ResolverProxyBridge>> {
        self.resolver_proxy_bridge.clone()
    }

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    pub(crate) fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.metrics)
    }

    async fn load_inputs(&self) -> Result<RuntimeInputs> {
        crate::defaults::ensure_go_defaults(&self.store).await?;
        let repository = self.store.repository();
        let settings = RuntimeSettings::load(&self.store).await?;
        let inbound_settings = repository.get_inbound_settings().await?;
        let socket_bind_addresses =
            Arc::from(interfaces::bind_addresses_for_settings(&settings).into_boxed_slice());
        let socket_bind_interface = interfaces::bind_interface_for_settings(&settings);
        let nat = repository.get_nat_config_or_default("default").await?;
        let hosts = load_hosts(&repository, &self.store).await?;
        let resolvers = repository.list_go_resolver_runtime_configs().await?;
        let route = repository.load_go_route_runtime_config().await?;
        if let Some(bridge) = &self.resolver_proxy_bridge {
            bridge
                .set_configured_resolver_ids(resolvers.iter().map(|resolver| resolver.id.as_str()));
            bridge.set_proxy_resolver_id(route.as_ref().map(|route| route.proxy_resolver.as_str()));
        }
        let route_rules = repository.list_go_route_rules().await?;
        let node_tags = repository.list_go_node_tags().await?;
        let route_list_records = repository.list_go_route_lists().await?;
        let route_lists = Arc::new(load_route_lists(&route_list_records));
        let proxies = repository.list_go_proxy_runtime_configs().await?;
        let geo_metadata = repository.list_maxmind_metadata().await?;
        let geo_manager = GeoDatabaseManager::new();
        let geo = geo_metadata
            .first()
            .map(|metadata| {
                geo_manager
                    .load(GeoMetadata {
                        id: metadata.id.clone(),
                        path: metadata.path.clone().into(),
                        sha256: metadata.sha256.clone(),
                        size: u64::try_from(metadata.size).map_err(|_| {
                            Error::invalid("MaxMind metadata size cannot be negative")
                        })?,
                        updated_at: metadata.updated_at,
                    })
                    .map(|snapshot| snapshot.database())
            })
            .transpose()?
            .map(|database| database as Arc<dyn GeoLookup>);

        // The Rust/API overlay wins over the legacy Go row when present.
        let fakeip_config = match load_fakeip_config(&self.store).await? {
            Some(config) => Some(config),
            None => repository.load_go_fakeip_runtime_config().await?,
        };
        let fakeip_policy = load_fakeip_policy(&self.store, &repository).await?;
        Ok(RuntimeInputs {
            settings,
            inbound_settings,
            socket_bind_addresses,
            socket_bind_interface,
            nat,
            hosts,
            resolvers,
            route,
            route_rules,
            node_tags,
            route_lists,
            proxies,
            geo_metadata,
            geo,
            fakeip_config,
            fakeip_policy,
        })
    }

    pub async fn build(&self) -> Result<RuntimeSnapshot> {
        let RuntimeInputs {
            settings,
            inbound_settings,
            socket_bind_addresses,
            socket_bind_interface,
            nat,
            hosts,
            resolvers,
            route,
            route_rules,
            node_tags,
            route_lists,
            proxies,
            geo_metadata,
            geo,
            fakeip_config,
            fakeip_policy,
        } = self.load_inputs().await?;
        let fakeip = match fakeip_config.as_ref() {
            Some(config) if config.enabled => {
                Some(open_fakeip_pools(&self.store, config, self.options.fakeip_options).await?)
            }
            _ => None,
        };
        let inbound_fakeip = if inbound_settings.hijack_dns_fakeip {
            match fakeip.clone() {
                Some(pools) => Some(pools),
                None => {
                    let config = match fakeip_config.as_ref() {
                        Some(config) => config.clone(),
                        None => default_fakeip_runtime_config()?,
                    };
                    Some(
                        open_fakeip_pools(&self.store, &config, self.options.fakeip_options)
                            .await?,
                    )
                }
            }
        } else {
            None
        };

        let (resolver, inbound_resolver, dns_resolver) = wrap_resolver_variants(
            self.upstream.clone(),
            &hosts,
            fakeip.as_ref(),
            inbound_fakeip.as_ref(),
            self.options.fakeip_skip_check_upstream,
            &fakeip_policy,
            settings.ipv6,
        );
        let mut resolver_registries = ResolverRegistries::default();
        let mut resolver_errors = BTreeMap::new();
        let resolver_registry_enabled = self.resolver_factory.is_some();
        if let Some(factory) = &self.resolver_factory {
            for config in &resolvers {
                match factory.build_with_policy_and_interface(
                    config,
                    &socket_bind_addresses,
                    socket_bind_interface.as_deref(),
                ) {
                    Ok(raw) => {
                        let (wrapped, inbound_wrapped, dns_wrapped) = wrap_resolver_variants(
                            raw,
                            &hosts,
                            fakeip.as_ref(),
                            inbound_fakeip.as_ref(),
                            self.options.fakeip_skip_check_upstream,
                            &fakeip_policy,
                            settings.ipv6,
                        );
                        resolver_registries
                            .insert(config.id.clone(), (wrapped, inbound_wrapped, dns_wrapped));
                    }
                    Err(error) => match self.options.resolver_failure_policy {
                        ResolverFailurePolicy::FailBuild => return Err(error),
                        ResolverFailurePolicy::KeepUnavailable => {
                            resolver_errors.insert(config.id.clone(), error.to_string());
                        }
                    },
                }
            }
        }
        let router = compile_go_route_rules_with_lists(
            &route_rules,
            &route_lists,
            self.options.route_fallback.clone(),
            geo.clone(),
        )?;
        let happy_eyeballs = reconfigure_dialer(
            &self.happy_eyeballs,
            settings.happy_eyeballs_semaphore,
            Arc::clone(&self.metrics),
        );
        let ResolverRegistryParts {
            flow: resolver_by_id,
            inbound_dns: inbound_resolver_by_id,
            dns: dns_resolver_by_id,
        } = resolver_registries.into_parts();
        Ok(RuntimeSnapshot {
            metrics: Arc::clone(&self.metrics),
            resolver,
            inbound_resolver,
            dns_resolver,
            settings,
            inbound_settings,
            happy_eyeballs,
            socket_bind_addresses,
            socket_bind_interface,
            hosts,
            fakeip,
            inbound_fakeip,
            resolvers,
            route,
            route_rules,
            node_tags,
            route_lists,
            router,
            resolver_by_id,
            inbound_resolver_by_id,
            dns_resolver_by_id,
            resolver_errors,
            resolver_registry_enabled,
            geo_metadata,
            geo,
            proxies,
            nat,
        })
    }

    pub async fn build_handle(&self) -> Result<RuntimeHandle> {
        Ok(RuntimeHandle::new(self.build().await?))
    }
}

fn wrap_resolver(
    upstream: Arc<dyn AsyncIpResolver>,
    hosts: &HostsTable,
    fakeip: Option<&FakeIpPools>,
    skip_check_upstream: bool,
    fakeip_policy: &FakeIpPolicy,
    ipv6_enabled: bool,
) -> Arc<dyn AsyncIpResolver> {
    let upstream = match fakeip {
        Some(pools) => Arc::new(FakeIpResolver::new_with_policy(
            upstream,
            pools.clone(),
            skip_check_upstream,
            fakeip_policy.clone(),
        )) as Arc<dyn AsyncIpResolver>,
        None => upstream,
    };
    let upstream =
        Arc::new(AsyncHostsResolver::new(hosts.clone(), upstream)) as Arc<dyn AsyncIpResolver>;
    Arc::new(Ipv6PolicyResolver::new(upstream, ipv6_enabled))
}

fn wrap_resolver_variants(
    upstream: Arc<dyn AsyncIpResolver>,
    hosts: &HostsTable,
    fakeip: Option<&FakeIpPools>,
    inbound_fakeip: Option<&FakeIpPools>,
    skip_check_upstream: bool,
    fakeip_policy: &FakeIpPolicy,
    ipv6_enabled: bool,
) -> (
    Arc<dyn AsyncIpResolver>,
    Arc<dyn AsyncIpResolver>,
    Arc<dyn AsyncIpResolver>,
) {
    let resolver = wrap_resolver(
        upstream.clone(),
        hosts,
        fakeip,
        skip_check_upstream,
        fakeip_policy,
        ipv6_enabled,
    );
    let inbound_resolver = wrap_resolver(
        upstream.clone(),
        hosts,
        inbound_fakeip,
        skip_check_upstream,
        fakeip_policy,
        ipv6_enabled,
    );
    let dns_resolver = wrap_resolver(
        upstream,
        hosts,
        None,
        skip_check_upstream,
        fakeip_policy,
        ipv6_enabled,
    );
    (resolver, inbound_resolver, dns_resolver)
}

#[derive(Default)]
struct ResolverRegistries {
    by_id: BTreeMap<String, ResolverVariants>,
}

struct ResolverVariants {
    flow: Arc<dyn AsyncIpResolver>,
    inbound_dns: Arc<dyn AsyncIpResolver>,
    dns: Arc<dyn AsyncIpResolver>,
}

struct ResolverRegistryParts {
    flow: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    inbound_dns: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
    dns: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
}

impl ResolverRegistries {
    fn insert(
        &mut self,
        id: String,
        variants: (
            Arc<dyn AsyncIpResolver>,
            Arc<dyn AsyncIpResolver>,
            Arc<dyn AsyncIpResolver>,
        ),
    ) {
        let (flow, inbound_dns, dns) = variants;
        self.by_id.insert(
            id,
            ResolverVariants {
                flow,
                inbound_dns,
                dns,
            },
        );
    }

    fn into_parts(self) -> ResolverRegistryParts {
        let mut flow = BTreeMap::new();
        let mut inbound_dns = BTreeMap::new();
        let mut dns = BTreeMap::new();
        for (id, variants) in self.by_id {
            flow.insert(id.clone(), variants.flow);
            inbound_dns.insert(id.clone(), variants.inbound_dns);
            dns.insert(id, variants.dns);
        }
        ResolverRegistryParts {
            flow,
            inbound_dns,
            dns,
        }
    }
}

async fn open_fakeip_pools(
    store: &ConfigStore,
    config: &doradus_store::GoFakeIpRuntimeConfig,
    options: Option<FakeIpPoolOptions>,
) -> Result<FakeIpPools> {
    let ipv4 = Arc::new(match options {
        Some(options) => FakeIpPool::open_with_options(store.clone(), config.ipv4, options).await?,
        None => FakeIpPool::open(store.clone(), config.ipv4).await?,
    });
    let ipv6 = Arc::new(match options {
        Some(options) => {
            FakeIpV6Pool::open_with_options(store.clone(), config.ipv6, options).await?
        }
        None => FakeIpV6Pool::open(store.clone(), config.ipv6).await?,
    });
    Ok(FakeIpPools::new(ipv4, ipv6))
}

fn default_fakeip_runtime_config() -> Result<doradus_store::GoFakeIpRuntimeConfig> {
    doradus_store::GoDnsSettingsRecord {
        id: 0,
        server: String::new(),
        fakedns_enabled: false,
        fakedns_ipv4_range: "10.2.0.1/24".to_owned(),
        fakedns_ipv6_range: "fc00::/64".to_owned(),
    }
    .to_fakeip_runtime_config()
}

async fn load_hosts(
    repository: &doradus_store::ConfigRepository,
    store: &ConfigStore,
) -> Result<HostsTable> {
    let hosts = HostsTable::new();
    load_system_hosts(&hosts);

    let persisted = repository.list_go_dns_hosts().await?;
    if !persisted.is_empty() {
        let configured = repository.load_go_dns_hosts_table().await?;
        hosts.overlay(&configured)?;
        return Ok(hosts);
    }
    let Some(bytes) = store.get_config("resolver.hosts").await? else {
        return Ok(hosts);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver.hosts is invalid JSON: {error}"),
        )
    })?;
    let object = value
        .get("hosts")
        .and_then(serde_json::Value::as_object)
        .or_else(|| value.as_object())
        .ok_or_else(|| Error::invalid("resolver.hosts must be a JSON object"))?;
    let configured = HostsTable::new();
    for (host, target) in object {
        let Some(target) = target.as_str() else {
            return Err(Error::invalid("resolver.hosts targets must be strings"));
        };
        configured.insert_host_target(host, target)?;
    }
    hosts.overlay(&configured)?;
    Ok(hosts)
}

/// Load the host file used by the platform resolver as the lowest-priority
/// hosts layer.  A missing/unreadable file is normal on some targets and must
/// not prevent the service from starting; malformed individual rows are
/// ignored with the same fail-soft behavior as libc-style hosts parsing.
fn load_system_hosts(hosts: &HostsTable) {
    let Ok(contents) = std::fs::read_to_string(system_hosts_path()) else {
        return;
    };
    for (address, domain) in parse_system_hosts(&contents) {
        let _ = hosts.insert_ip(domain, address);
    }
}

#[cfg(not(windows))]
fn system_hosts_path() -> &'static str {
    "/etc/hosts"
}

#[cfg(windows)]
fn system_hosts_path() -> &'static str {
    r"C:\Windows\System32\drivers\etc\hosts"
}

fn parse_system_hosts(contents: &str) -> Vec<(IpAddr, DomainName)> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        for host in fields {
            let host = host.trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            if let Ok(domain) = DomainName::new(host) {
                entries.push((address, domain));
            }
        }
    }
    entries
}

async fn load_fakeip_config(
    store: &ConfigStore,
) -> Result<Option<doradus_store::GoFakeIpRuntimeConfig>> {
    let Some(bytes) = store.get_config("resolver.fakedns").await? else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver.fakedns is invalid JSON: {error}"),
        )
    })?;
    let enabled = value
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let ipv4_range = value
        .get("ipv4Range")
        .or_else(|| value.get("ipv4_range"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("10.2.0.1/24");
    let ipv6_range = value
        .get("ipv6Range")
        .or_else(|| value.get("ipv6_range"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("fc00::/64");
    let record = doradus_store::GoDnsSettingsRecord {
        id: 0,
        server: String::new(),
        fakedns_enabled: enabled,
        fakedns_ipv4_range: ipv4_range.to_owned(),
        fakedns_ipv6_range: ipv6_range.to_owned(),
    };
    record.to_fakeip_runtime_config().map(Some)
}

async fn load_fakeip_policy(
    store: &ConfigStore,
    repository: &ConfigRepository,
) -> Result<FakeIpPolicy> {
    if let Some(bytes) = store.get_config("resolver.fakedns").await? {
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("resolver.fakedns is invalid JSON: {error}"),
            )
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| Error::invalid("resolver.fakedns must be a JSON object"))?;
        let whitelist = parse_fakeip_list(object, &["whitelist"], "whitelist")?;
        let skip_check = parse_fakeip_list(
            object,
            &["skipCheckList", "skip_check_list"],
            "skipCheckList",
        )?;
        if whitelist.is_some() || skip_check.is_some() {
            return FakeIpPolicy::from_lists(
                whitelist.as_deref().unwrap_or_default(),
                skip_check.as_deref().unwrap_or_default(),
            );
        }
    }

    let mut whitelist = Vec::new();
    let mut skip_check = Vec::new();
    for record in repository.list_go_dns_fakedns_lists().await? {
        match record.kind.as_str() {
            "whitelist" => whitelist.push(record.value),
            "skip_check" => skip_check.push(record.value),
            _ => {}
        }
    }
    FakeIpPolicy::from_lists(&whitelist, &skip_check)
}

fn parse_fakeip_list(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    field: &str,
) -> Result<Option<Vec<String>>> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| Error::invalid(format!("resolver.fakedns.{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                Error::invalid(format!("resolver.fakedns.{field} entries must be strings"))
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

#[cfg(test)]
#[path = "assembly_tests.rs"]
mod tests;
