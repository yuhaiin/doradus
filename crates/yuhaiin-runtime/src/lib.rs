//! Application-neutral runtime assembly for configuration, DNS and proxies.
//!
//! The snapshot deliberately reuses the store's existing Go compatibility
//! models. It is suitable for a future HTTP/yuhaiin-react handler without
//! introducing a second DTO tree or exposing SQLite connections.

#[cfg(feature = "http-api")]
pub mod api;
mod controller;
mod data_plane;
mod defaults;
#[cfg(feature = "doh-tls")]
mod doh_tls;
#[cfg(feature = "doh-tls")]
mod dot_tls;
mod handle;
#[path = "inbounds/mod.rs"]
pub mod inbound;
mod interfaces;
pub mod latency;
pub mod log;
mod loopback;
pub mod monitor;
mod proxy;
mod resolver;
mod route;
#[cfg(feature = "doh-tls")]
mod rustcrypto_resolver;
#[cfg(feature = "http-api")]
pub mod service;
mod settings;
#[cfg(feature = "update")]
pub mod update;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use yuhaiin_core::dns_hosts::HostsTable;
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::dns_resolver_stack::AsyncHostsResolver;
use yuhaiin_core::nat::NatTable;
use yuhaiin_core::{
    DomainName, Error, ErrorKind, FlowContext, GeoLookup, ResolverPolicy, Result, RouteMode,
};
use yuhaiin_geo::{GeoDatabaseManager, GeoMetadata};
use yuhaiin_store::fakeip::{FakeIpPool, FakeIpPoolOptions, FakeIpV6Pool};
use yuhaiin_store::{
    ConfigRepository, ConfigStore, FakeIpPolicy, FakeIpPools, FakeIpResolver, GoProxyRuntimeConfig,
    GoResolverRuntimeConfig, GoRouteRuleRecord, GoRouteRuntimeConfig, InboundSettings,
    MaxMindMetadataRecord, NatConfigRecord,
};
use yuhaiin_trie::router::{RouteDecision, RouterRuntime};

pub use controller::RuntimeController;
pub use data_plane::{RuntimeDnsHandler, run_dns_supervisor, wait_for_shutdown_or_reload};
#[cfg(feature = "tun")]
pub use data_plane::{
    TunRuntimeConfig, load_tun_config, run_tun_device_until, run_tun_device_until_ref,
};
#[cfg(feature = "doh-tls")]
pub use doh_tls::{RustCryptoH2Connector, RustCryptoTlsDialer, root_store as doh_root_store};
#[cfg(feature = "doh-tls")]
pub use dot_tls::RustCryptoDotResolverFactory;
pub use handle::RuntimeHandle;
pub use log::RuntimeLog;
pub use monitor::ConnectionMonitor;
pub use proxy::{ProxyBuild, RuntimeProxySelector};
#[cfg(feature = "http2")]
pub use resolver::H2DohResolverFactory;
#[cfg(feature = "doh-tls")]
pub use resolver::RustCryptoDohResolverFactory;
pub use resolver::{
    BuiltinResolverFactory, FallbackResolver, ResolverFailurePolicy, ResolverTransportFactory,
    TimeoutResolver, parse_dns_server,
};
pub use route::{
    ProxyRouteListTransport, RouteListRefreshReport, RouteListSnapshot, RouteListTransport,
    compile_go_route_rules, compile_go_route_rules_with_geo, compile_go_route_rules_with_lists,
    download_route_url_with_transport, expand_go_route_rule, load_route_lists,
    refresh_route_list_caches, refresh_route_list_caches_with_transport, route_list_cache_dir,
    route_list_cache_path, route_rule_from_go_record,
};
#[cfg(feature = "doh-tls")]
pub use rustcrypto_resolver::RustCryptoResolverFactory;
pub use settings::{Ipv6PolicyResolver, RuntimeSettings};

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
    /// Whether configured resolver IDs should retry through the main resolver
    /// after a transport-level failure or an empty answer.
    pub resolver_query_fallback: bool,
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
            resolver_query_fallback: true,
            resolver_failure_policy: ResolverFailurePolicy::FailBuild,
        }
    }
}

/// Immutable configuration/runtime snapshot published after a successful
/// load. Existing flows can keep using an older snapshot during reload.
#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub settings: RuntimeSettings,
    /// Inbound-wide policy shared by TUN and socket-based inbound servers.
    pub inbound_settings: InboundSettings,
    /// Shared connect budget for the immutable snapshot. New flows acquire
    /// one permit while establishing a TCP proxy connection; reload builds a
    /// new budget without changing existing flows.
    pub(crate) connect_semaphore: Arc<Semaphore>,
    /// Source addresses used when settings request a named/default network
    /// interface. An empty list preserves the OS default route.
    pub(crate) socket_bind_addresses: Arc<[IpAddr]>,
    pub resolver: Arc<dyn AsyncIpResolver>,
    /// Resolver without FakeIP transformation, used when DNS hijacking is
    /// enabled but the `hijackDnsFakeIp` switch is disabled.
    pub(crate) dns_resolver: Arc<dyn AsyncIpResolver>,
    pub hosts: HostsTable,
    pub fakeip: Option<FakeIpPools>,
    pub resolvers: Vec<GoResolverRuntimeConfig>,
    pub route: Option<GoRouteRuntimeConfig>,
    pub route_rules: Vec<GoRouteRuleRecord>,
    pub route_lists: RouteListSnapshot,
    pub router: RouterRuntime,
    pub resolver_by_id: BTreeMap<String, Arc<dyn AsyncIpResolver>>,
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
    options: RuntimeBuildOptions,
    resolver_factory: Option<Arc<dyn ResolverTransportFactory>>,
}

impl RuntimeBuilder {
    pub fn new(store: ConfigStore, upstream: Arc<dyn AsyncIpResolver>) -> Self {
        Self {
            store,
            upstream,
            options: RuntimeBuildOptions::default(),
            resolver_factory: None,
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

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    pub async fn build(&self) -> Result<RuntimeSnapshot> {
        defaults::ensure_go_defaults(&self.store).await?;
        let repository = self.store.repository();
        let settings = RuntimeSettings::load(&self.store).await?;
        let inbound_settings = repository.get_inbound_settings().await?;
        let socket_bind_addresses =
            Arc::from(interfaces::bind_addresses_for_settings(&settings).into_boxed_slice());
        let nat = repository.get_nat_config_or_default("default").await?;
        let hosts = load_hosts(&repository, &self.store).await?;
        let resolvers = repository.list_go_resolver_runtime_configs().await?;
        let route = repository.load_go_route_runtime_config().await?;
        let route_rules = repository.list_go_route_rules().await?;
        let route_list_records = repository.list_go_route_lists().await?;
        let route_lists = load_route_lists(&route_list_records);
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

        // A Rust/API overlay is authoritative when present. This matters
        // for a Go database: the compatibility `dns_settings` row remains
        // readable, but a frontend FakeDNS update is persisted under
        // `resolver.fakedns` and must take effect after reload.
        let fakeip_config = match load_fakeip_config(&self.store).await? {
            Some(config) => Some(config),
            None => repository.load_go_fakeip_runtime_config().await?,
        };
        let fakeip_policy = load_fakeip_policy(&self.store, &repository).await?;
        let fakeip = match fakeip_config {
            Some(config) if config.enabled => {
                let options = self.options.fakeip_options;
                let ipv4 = Arc::new(match options {
                    Some(options) => {
                        FakeIpPool::open_with_options(self.store.clone(), config.ipv4, options)
                            .await?
                    }
                    None => FakeIpPool::open(self.store.clone(), config.ipv4).await?,
                });
                let ipv6 = Arc::new(match options {
                    Some(options) => {
                        FakeIpV6Pool::open_with_options(self.store.clone(), config.ipv6, options)
                            .await?
                    }
                    None => FakeIpV6Pool::open(self.store.clone(), config.ipv6).await?,
                });
                let pools = FakeIpPools::new(ipv4, ipv6);
                Some(pools)
            }
            _ => None,
        };

        let resolver = wrap_resolver(
            self.upstream.clone(),
            &hosts,
            fakeip.as_ref(),
            self.options.fakeip_skip_check_upstream,
            &fakeip_policy,
            settings.ipv6,
        );
        let dns_resolver = wrap_resolver(
            self.upstream.clone(),
            &hosts,
            None,
            self.options.fakeip_skip_check_upstream,
            &fakeip_policy,
            settings.ipv6,
        );
        let mut resolver_by_id = BTreeMap::new();
        let mut resolver_errors = BTreeMap::new();
        let resolver_registry_enabled = self.resolver_factory.is_some();
        if let Some(factory) = &self.resolver_factory {
            for config in &resolvers {
                match factory.build_with_policy(config, &socket_bind_addresses) {
                    Ok(raw) => {
                        let wrapped = wrap_resolver(
                            raw,
                            &hosts,
                            fakeip.as_ref(),
                            self.options.fakeip_skip_check_upstream,
                            &fakeip_policy,
                            settings.ipv6,
                        );
                        let wrapped = if self.options.resolver_query_fallback {
                            Arc::new(FallbackResolver::new(wrapped, resolver.clone()))
                                as Arc<dyn AsyncIpResolver>
                        } else {
                            wrapped
                        };
                        resolver_by_id.insert(config.id.clone(), wrapped);
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
        let connect_semaphore = Arc::new(Semaphore::new(settings.happy_eyeballs_semaphore));
        Ok(RuntimeSnapshot {
            resolver,
            dns_resolver,
            settings,
            inbound_settings,
            connect_semaphore,
            socket_bind_addresses,
            hosts,
            fakeip,
            resolvers,
            route,
            route_rules,
            route_lists,
            router,
            resolver_by_id,
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

async fn load_hosts(
    repository: &yuhaiin_store::ConfigRepository,
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
        configured.insert_target(DomainName::new(host)?, target)?;
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
) -> Result<Option<yuhaiin_store::GoFakeIpRuntimeConfig>> {
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
        .unwrap_or("198.18.0.0/15");
    let ipv6_range = value
        .get("ipv6Range")
        .or_else(|| value.get("ipv6_range"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("fc00::/18");
    let record = yuhaiin_store::GoDnsSettingsRecord {
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
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};
    use yuhaiin_store::{GoRouteListRecord, GoUdpProxyFqdnStrategy};
    use yuhaiin_trie::router::Router;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn system_hosts_parser_handles_comments_aliases_and_invalid_rows() {
        let entries = parse_system_hosts(
            "# comment\n192.0.2.10 example.test alias.example.test # trailing\n\
             2001:db8::10 v6.example.test\nnot-an-ip ignored.example.test\n",
        );
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1, DomainName::new("example.test").unwrap());
        assert_eq!(entries[1].1, DomainName::new("alias.example.test").unwrap());
        assert_eq!(entries[2].0, "2001:db8::10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn fakeip_policy_loads_json_lists_with_go_field_names() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(store.put_config(
            "resolver.fakedns",
            br#"{"enabled":true,"whitelist":["example.com"],"skipCheckList":["*.skip.example.com"]}"#,
        ))
        .unwrap();

        let policy = block_on(load_fakeip_policy(&store, &store.repository())).unwrap();
        assert!(policy.is_whitelisted(&DomainName::new("api.example.com").unwrap()));
        assert!(policy.is_skip_check(&DomainName::new("one.skip.example.com").unwrap()));
        assert!(!policy.is_skip_check(&DomainName::new("deep.two.skip.example.com").unwrap()));
    }

    #[test]
    fn fakeip_json_overlay_controls_runtime_enablement_over_legacy_settings() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(store.put_config(
            "resolver.fakedns",
            br#"{"enabled":true,"ipv4Range":"198.18.10.0/30","ipv6Range":"fc00:10::/126","whitelist":[],"skipCheckList":[]}"#,
        ))
        .unwrap();

        let snapshot = block_on(
            RuntimeBuilder::new(
                store,
                Arc::new(StaticResolver {
                    address: Ipv4Addr::new(192, 0, 2, 55),
                }),
            )
            .build(),
        )
        .unwrap();
        let resolved = block_on(snapshot.resolver.resolve(
            &DomainName::new("overlay.example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        ))
        .unwrap();
        assert_eq!(resolved.v4, vec![Ipv4Addr::new(198, 18, 10, 0)]);
    }

    #[test]
    fn configured_hosts_overlay_system_hosts_in_one_snapshot() {
        let system = HostsTable::new();
        let configured = HostsTable::new();
        let domain = DomainName::new("example.test").unwrap();
        system
            .insert_ip(domain.clone(), "192.0.2.10".parse().unwrap())
            .unwrap();
        configured
            .insert_ip(domain.clone(), "192.0.2.20".parse().unwrap())
            .unwrap();
        system.overlay(&configured).unwrap();
        assert_eq!(
            system.resolve(&domain).unwrap().unwrap().v4,
            vec!["192.0.2.20".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }

    struct StaticResolver {
        address: Ipv4Addr,
    }

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![self.address],
                    v6: Vec::new(),
                })
            })
        }
    }

    #[test]
    fn builder_publishes_one_shared_resolver_snapshot() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        let snapshot = block_on(
            RuntimeBuilder::new(
                store,
                Arc::new(StaticResolver {
                    address: Ipv4Addr::new(192, 0, 2, 55),
                }),
            )
            .build(),
        )
        .unwrap();
        let domain = DomainName::new("example.com").unwrap();
        let resolved = block_on(
            snapshot
                .resolver
                .resolve(&domain, ResolveStrategy::OnlyIpv4),
        )
        .unwrap();
        assert_eq!(resolved.v4, vec![Ipv4Addr::new(192, 0, 2, 55)]);
        assert!(snapshot.fakeip.is_none());
        assert!(snapshot.proxies.is_empty());
        assert!(snapshot.resolver_by_id.is_empty());
    }

    #[test]
    fn builder_loads_inbound_settings_from_the_frontend_overlay() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(store.put_config(
            "inbounds.config",
            br#"{"hijackDns":true,"hijackDnsFakeIp":false,"sniff":false}"#,
        ))
        .unwrap();
        let snapshot =
            block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
        assert_eq!(
            snapshot.inbound_settings,
            yuhaiin_store::InboundSettings {
                hijack_dns: true,
                hijack_dns_fakeip: false,
                sniff: false,
            }
        );
    }

    struct DualStackResolver;

    impl AsyncIpResolver for DualStackResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 55)],
                    v6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 55)],
                })
            })
        }
    }

    #[test]
    fn settings_ipv6_is_published_and_applied_to_the_shared_resolver() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(store.put_config("settings", br#"{"ipv6":false}"#)).unwrap();
        let snapshot =
            block_on(RuntimeBuilder::new(store.clone(), Arc::new(DualStackResolver)).build())
                .unwrap();
        assert!(!snapshot.settings.ipv6);
        let domain = DomainName::new("example.com").unwrap();
        let resolved =
            block_on(snapshot.resolver.resolve(&domain, ResolveStrategy::Default)).unwrap();
        assert_eq!(resolved.v4.len(), 1);
        assert!(resolved.v6.is_empty());

        block_on(store.put_config("settings", br#"{"ipv6":true}"#)).unwrap();
        let snapshot =
            block_on(RuntimeBuilder::new(store, Arc::new(DualStackResolver)).build()).unwrap();
        assert!(snapshot.settings.ipv6);
        assert_eq!(
            block_on(snapshot.resolver.resolve(&domain, ResolveStrategy::Default))
                .unwrap()
                .v6
                .len(),
            1
        );
    }

    #[test]
    fn empty_store_keeps_system_resolver_as_an_explicit_compatible_input() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        let builder = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver));
        let snapshot = block_on(builder.build()).unwrap();
        assert_eq!(snapshot.resolvers.len(), 1);
        assert_eq!(snapshot.resolvers[0].id, "bootstrap");
        assert_eq!(
            snapshot.route.as_ref().unwrap().direct_resolver,
            "bootstrap"
        );
        assert_eq!(snapshot.route_lists.values("LAN").unwrap().len(), 18);
        assert_eq!(snapshot.route_rules.len(), 1);
    }

    #[test]
    fn builder_publishes_route_list_contents_into_the_router_snapshot() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(
            store.repository().put_go_route_list(&GoRouteListRecord {
                name: "local-domains".to_owned(),
                list_type: "host".to_owned(),
                source_type: "local".to_owned(),
                updated_at: 1,
                data_json: br#"{
                "name":"local-domains",
                "type":"host",
                "source":{"type":"local","local":{"lists":["example.test"]}}
            }"#
                .to_vec(),
            }),
        )
        .unwrap();
        block_on(
            store.repository().put_go_route_rule(&GoRouteRuleRecord {
                id: "list-rule".to_owned(),
                name: "list-rule".to_owned(),
                priority: 1,
                disabled: false,
                action_mode: "proxy".to_owned(),
                match_type: "all".to_owned(),
                tag: "test".to_owned(),
                updated_at: 2,
                data_json: br#"{
                "mode":"proxy",
                "rules":[{"type":"host","host":{"list":"local-domains"}}]
            }"#
                .to_vec(),
            }),
        )
        .unwrap();
        let snapshot =
            block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
        assert_eq!(
            snapshot.route_lists.values("local-domains").unwrap(),
            ["example.test"]
        );
        let endpoint = yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            DomainName::new("www.example.test").unwrap(),
            443,
        );
        assert_eq!(
            snapshot.router.decide(&endpoint).mode,
            yuhaiin_core::RouteMode::Proxy
        );
    }

    #[test]
    fn apply_route_exposes_go_list_membership_to_rejected_nested_matchers() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        for (name, list_type, values) in [
            ("domains", "host", "example.test"),
            ("apps", "process", "/usr/bin/curl"),
        ] {
            block_on(store.repository().put_go_route_list(&GoRouteListRecord {
                name: name.to_owned(),
                list_type: list_type.to_owned(),
                source_type: "local".to_owned(),
                updated_at: 1,
                data_json: format!(
                    r#"{{"type":"{list_type}","source":{{"type":"local","local":{{"lists":["{values}"]}}}}}}"#
                )
                .into_bytes(),
            }))
            .unwrap();
        }
        block_on(
            store.repository().put_go_route_rule(&GoRouteRuleRecord {
                id: "process-gated".to_owned(),
                name: "process-gated".to_owned(),
                priority: 1,
                disabled: false,
                action_mode: "direct".to_owned(),
                match_type: "all".to_owned(),
                tag: "test".to_owned(),
                updated_at: 1,
                data_json: br#"{
                "mode":"direct",
                "rules":[{"type":"all","all":[
                    {"type":"host","host":{"list":"domains"}},
                    {"type":"process","process":{"list":"apps"}}
                ]}]
            }"#
                .to_vec(),
            }),
        )
        .unwrap();
        block_on(
            store.repository().put_go_route_rule(&GoRouteRuleRecord {
                id: "host-fallback".to_owned(),
                name: "host-fallback".to_owned(),
                priority: 2,
                disabled: false,
                action_mode: "proxy".to_owned(),
                match_type: "host".to_owned(),
                tag: "test".to_owned(),
                updated_at: 2,
                data_json: br#"{
                "mode":"proxy",
                "rules":[{"type":"host","host":{"list":"domains"}}]
            }"#
                .to_vec(),
            }),
        )
        .unwrap();

        let snapshot =
            block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
        let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            DomainName::new("www.example.test").unwrap(),
            443,
        ));
        context.process = Some("/usr/bin/browser".to_owned());

        assert_eq!(snapshot.apply_route(&mut context).mode, RouteMode::Proxy);
        assert_eq!(context.lists, vec!["domains"]);
        let rejected = &context.match_history[0];
        assert_eq!(rejected.rule_name, "process-gated");
        assert!(
            rejected
                .history
                .iter()
                .any(|entry| entry.list_name == "List apps" && !entry.matched)
        );
        assert!(
            !rejected
                .history
                .iter()
                .any(|entry| entry.list_name == "List domains")
        );
    }

    #[test]
    fn runtime_snapshot_loads_full_cone_nat_timeout_for_tun_assembly() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(store.repository().put_nat_config(&NatConfigRecord {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: 45_000,
        }))
        .unwrap();

        let snapshot =
            block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
        assert!(snapshot.nat.full_cone);
        assert_eq!(snapshot.nat.idle_timeout_ms, 45_000);
        let (_table, timeout) = snapshot.new_full_cone_nat().unwrap();
        assert_eq!(timeout, Duration::from_secs(45));

        let mut restricted = snapshot.clone();
        restricted.nat.full_cone = false;
        assert!(restricted.new_full_cone_nat().is_err());
    }

    #[test]
    fn builtin_resolver_factory_publishes_a_resolver_registry() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        let snapshot = block_on(
            RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
                .with_resolver_factory(Arc::new(BuiltinResolverFactory::new(
                    Duration::from_secs(1),
                    8,
                )))
                .build(),
        )
        .unwrap();
        assert_eq!(snapshot.resolver_by_id.len(), 1);
        assert!(snapshot.resolver_by_id.contains_key("bootstrap"));
    }

    #[test]
    fn route_settings_select_resolver_from_the_same_snapshot() {
        let main = Arc::new(StaticResolver {
            address: Ipv4Addr::new(192, 0, 2, 1),
        }) as Arc<dyn AsyncIpResolver>;
        let direct = Arc::new(StaticResolver {
            address: Ipv4Addr::new(192, 0, 2, 2),
        }) as Arc<dyn AsyncIpResolver>;
        let proxy = Arc::new(StaticResolver {
            address: Ipv4Addr::new(192, 0, 2, 3),
        }) as Arc<dyn AsyncIpResolver>;
        let mut resolver_by_id = BTreeMap::new();
        resolver_by_id.insert("direct".to_owned(), direct);
        resolver_by_id.insert("proxy".to_owned(), proxy);
        let router = RouterRuntime::new(
            Router::compile(
                Vec::new(),
                RouteDecision {
                    mode: RouteMode::Proxy,
                    resolver_policy: ResolverPolicy::default(),
                    priority: 0,
                },
            )
            .unwrap(),
        );
        let snapshot = RuntimeSnapshot {
            settings: RuntimeSettings::default(),
            connect_semaphore: Arc::new(Semaphore::new(250)),
            socket_bind_addresses: Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
            resolver: main,
            dns_resolver: Arc::new(SystemAsyncIpResolver),
            hosts: HostsTable::new(),
            fakeip: None,
            inbound_settings: yuhaiin_store::InboundSettings::default(),
            resolvers: Vec::new(),
            route: Some(GoRouteRuntimeConfig {
                direct_resolver: "direct".to_owned(),
                proxy_resolver: "proxy".to_owned(),
                resolve_locally: true,
                udp_proxy_fqdn: GoUdpProxyFqdnStrategy::Resolve,
            }),
            route_rules: Vec::new(),
            route_lists: RouteListSnapshot::default(),
            router,
            resolver_by_id,
            resolver_errors: BTreeMap::new(),
            resolver_registry_enabled: true,
            geo_metadata: Vec::new(),
            geo: None,
            proxies: Vec::new(),
            nat: NatConfigRecord::default(),
        };
        let domain = DomainName::new("example.com").unwrap();
        let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            domain.clone(),
            443,
        ));
        let resolver = snapshot
            .apply_route_and_select_resolver(&mut context)
            .unwrap();
        assert_eq!(context.route_mode, RouteMode::Proxy);
        assert_eq!(
            block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv4))
                .unwrap()
                .v4,
            vec![Ipv4Addr::new(192, 0, 2, 3)]
        );
        assert_eq!(
            block_on(
                snapshot
                    .resolver_for_route_mode(RouteMode::Direct)
                    .unwrap()
                    .resolve(&domain, ResolveStrategy::OnlyIpv4,)
            )
            .unwrap()
            .v4,
            vec![Ipv4Addr::new(192, 0, 2, 2)]
        );
    }

    #[test]
    fn rebuilding_store_publishes_new_route_snapshot_without_mutating_old_flows() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        let repository = store.repository();
        let mut record = GoRouteRuleRecord {
            id: "reload-rule".to_owned(),
            name: "reload-rule".to_owned(),
            priority: 10,
            disabled: false,
            action_mode: "direct".to_owned(),
            match_type: "domain".to_owned(),
            tag: "test".to_owned(),
            updated_at: 1,
            data_json: br#"{"match":{"domain":"example.com"},"mode":"direct"}"#.to_vec(),
        };
        block_on(repository.put_go_route_rule(&record)).unwrap();
        let first = block_on(
            RuntimeBuilder::new(
                store.clone(),
                Arc::new(StaticResolver {
                    address: Ipv4Addr::new(192, 0, 2, 55),
                }),
            )
            .build(),
        )
        .unwrap();

        record.action_mode = "proxy".to_owned();
        record.updated_at = 2;
        record.data_json = br#"{"match":{"domain":"example.com"},"mode":"proxy"}"#.to_vec();
        block_on(repository.put_go_route_rule(&record)).unwrap();
        let second = block_on(
            RuntimeBuilder::new(
                store,
                Arc::new(StaticResolver {
                    address: Ipv4Addr::new(192, 0, 2, 55),
                }),
            )
            .build(),
        )
        .unwrap();

        let endpoint = yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        );
        let mut old_context = FlowContext::new(endpoint.clone());
        let mut new_context = FlowContext::new(endpoint);
        assert_eq!(first.apply_route(&mut old_context).mode, RouteMode::Direct);
        assert_eq!(second.apply_route(&mut new_context).mode, RouteMode::Proxy);
    }

    #[test]
    fn route_settings_repository_rows_are_loaded_by_runtime_reload() {
        let store = block_on(ConfigStore::open_memory()).unwrap();
        block_on(
            store
                .repository()
                .put_go_route_settings(&yuhaiin_store::GoRouteSettingsRecord {
                    id: 1,
                    direct_resolver: "direct".to_owned(),
                    proxy_resolver: "proxy".to_owned(),
                    resolve_locally: true,
                    udp_proxy_fqdn: 2,
                }),
        )
        .unwrap();
        let snapshot = block_on(
            RuntimeBuilder::new(
                store,
                Arc::new(StaticResolver {
                    address: Ipv4Addr::new(192, 0, 2, 55),
                }),
            )
            .build(),
        )
        .unwrap();
        let route = snapshot.route.unwrap();
        assert_eq!(route.direct_resolver, "direct");
        assert_eq!(route.proxy_resolver, "proxy");
        assert!(route.resolve_locally);
        assert_eq!(route.udp_proxy_fqdn, GoUdpProxyFqdnStrategy::SkipResolve);
    }
}
