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

#[path = "assembly_snapshot.rs"]
mod assembly_snapshot;
pub use assembly_snapshot::RuntimeSnapshot;

#[path = "assembly_config_loader.rs"]
mod assembly_config_loader;
use assembly_config_loader::RuntimeInputs;
#[cfg(test)]
use assembly_config_loader::{load_fakeip_policy, parse_system_hosts};

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

#[cfg(test)]
#[path = "assembly_tests.rs"]
mod tests;
