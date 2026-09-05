use super::*;
use arc_swap::ArcSwap;
use doradus_metrics::{RouteAction, RuntimeMetrics};

#[path = "selector_metadata.rs"]
mod selector_metadata;
#[path = "selector_routing.rs"]
mod selector_routing;

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    metrics: Arc<RuntimeMetrics>,
    state: ArcSwap<SelectorState>,
    direct_id: String,
    proxy_id: String,
    udp_proxy_id: String,
    bypass_id: String,
    drop_id: String,
    timeout: Duration,
    loopback: LoopbackDetector,
}

#[derive(Clone)]
struct SelectorState {
    current: RuntimeRoutedProxySelector,
    udp_current: RuntimeRoutedProxySelector,
    tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    udp_tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    closed_nodes: BTreeSet<String>,
    retargeted_nodes: BTreeSet<String>,
    metadata: Arc<ProxyContextMetadata>,
    settings: crate::RuntimeSettings,
}

#[derive(Clone, Default)]
struct ProxyContextMetadata {
    hosts: doradus_core::dns_hosts::HostsTable,
    route_lists: Arc<RouteListSnapshot>,
    geo: Option<Arc<dyn GeoLookup>>,
    fakeip_view: Option<FakeIpViewStore>,
    fakeip_pools: Option<FakeIpPools>,
    endpoints: BTreeMap<String, SocketAddr>,
    tag_endpoints: BTreeMap<String, SocketAddr>,
    tag_node_ids: BTreeMap<String, String>,
    node_names: BTreeMap<String, String>,
    direct_resolver: Option<String>,
    proxy_resolver: Option<String>,
}

impl RuntimeProxySelector {
    pub(crate) fn active_node_ids(&self) -> Vec<String> {
        let state = self.state.load();
        [
            self.direct_id.as_str(),
            self.proxy_id.as_str(),
            self.udp_proxy_id.as_str(),
            self.bypass_id.as_str(),
            self.drop_id.as_str(),
        ]
        .into_iter()
        .filter(|id| {
            !id.is_empty()
                && !state.closed_nodes.contains(*id)
                && !state.retargeted_nodes.contains(*id)
        })
        .map(str::to_owned)
        .collect()
    }

    pub(super) async fn from_snapshot(
        snapshot: &RuntimeSnapshot,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let loopback = LoopbackDetector::new();
        let current = snapshot
            .build_routed_proxy_selector(direct_id, tcp_proxy_id, bypass_id, drop_id, timeout)
            .await?;
        let udp_current = snapshot
            .build_routed_proxy_selector(direct_id, udp_proxy_id, bypass_id, drop_id, timeout)
            .await?;
        let tagged = snapshot.build_tagged_proxies(timeout).await?;
        // Tags describe node sets, not a transport family. The proxy values
        // are Arc-backed and can be shared by TCP and UDP selectors; building
        // them twice would reopen every tagged node during startup/reload.
        let udp_tagged = tagged.clone();
        let metadata = Arc::new(
            snapshot
                .proxy_context_metadata(direct_id, tcp_proxy_id, udp_proxy_id, bypass_id, drop_id)
                .await?,
        );
        Ok(Self {
            metrics: Arc::clone(&snapshot.metrics),
            state: ArcSwap::from_pointee(SelectorState {
                current: track_selector(current, &loopback),
                udp_current: track_selector(udp_current, &loopback),
                tagged: track_tagged_proxies(tagged, &loopback),
                udp_tagged: track_tagged_proxies(udp_tagged, &loopback),
                closed_nodes: BTreeSet::new(),
                retargeted_nodes: BTreeSet::new(),
                metadata,
                settings: snapshot.settings.clone(),
            }),
            direct_id: direct_id.to_owned(),
            proxy_id: tcp_proxy_id.to_owned(),
            udp_proxy_id: udp_proxy_id.to_owned(),
            bypass_id: bypass_id.to_owned(),
            drop_id: drop_id.to_owned(),
            timeout,
            loopback,
        })
    }

    pub(crate) async fn prepare(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<PreparedProxySelector> {
        let state = self.state.load();
        let direct_id = self.effective_node_id(&state, &self.direct_id);
        let proxy_id = self.effective_node_id(&state, &self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&state, &self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&state, &self.bypass_id);
        let drop_id = self.effective_node_id(&state, &self.drop_id);
        let tagged = snapshot.build_tagged_proxies(self.timeout).await?;
        let udp_tagged = tagged.clone();
        Ok(PreparedProxySelector {
            selector: track_selector(
                snapshot
                    .build_routed_proxy_selector(
                        &direct_id,
                        &proxy_id,
                        &bypass_id,
                        &drop_id,
                        self.timeout,
                    )
                    .await?,
                &self.loopback,
            ),
            udp_selector: track_selector(
                snapshot
                    .build_routed_proxy_selector(
                        &direct_id,
                        &udp_proxy_id,
                        &bypass_id,
                        &drop_id,
                        self.timeout,
                    )
                    .await?,
                &self.loopback,
            ),
            tagged: track_tagged_proxies(tagged, &self.loopback),
            udp_tagged: track_tagged_proxies(udp_tagged, &self.loopback),
            metadata: Arc::new(
                snapshot
                    .proxy_context_metadata(
                        &direct_id,
                        &proxy_id,
                        &udp_proxy_id,
                        &bypass_id,
                        &drop_id,
                    )
                    .await?,
            ),
            settings: snapshot.settings.clone(),
        })
    }

    pub(crate) fn replace(&self, next: PreparedProxySelector) {
        self.state.store(Arc::new(SelectorState {
            current: next.selector,
            udp_current: next.udp_selector,
            tagged: next.tagged,
            udp_tagged: next.udp_tagged,
            closed_nodes: BTreeSet::new(),
            retargeted_nodes: BTreeSet::new(),
            metadata: next.metadata,
            settings: next.settings,
        }));
    }

    /// Close every slot that currently points at `id`, then make new flows
    /// fail closed until the next successful runtime reload. Existing flows
    /// keep their selected `Arc`, so closing the old instances also mirrors
    /// Go's `ProxyStore.Delete` behavior for those flows.
    pub(crate) async fn close_node(&self, id: &str) {
        self.close_node_with_retarget(id, false).await;
    }

    async fn close_node_with_retarget(&self, id: &str, retarget: bool) {
        let mut old_proxies = Vec::new();
        let mut closed_proxy_ids = BTreeSet::new();
        let current = self.state.load_full();
        let mut next = (*current).clone();

        macro_rules! close_slot {
            ($slot_id:expr, $slot:expr) => {
                if $slot_id == id {
                    let proxy = Arc::clone($slot);
                    if closed_proxy_ids.insert(Arc::as_ptr(&proxy).cast::<()>() as usize) {
                        old_proxies.push(proxy);
                    }
                    *$slot = Arc::new(DropAsyncProxy);
                }
            };
        }
        close_slot!(&self.direct_id, &mut next.current.direct);
        close_slot!(&self.proxy_id, &mut next.current.proxy);
        close_slot!(&self.bypass_id, &mut next.current.bypass);
        close_slot!(&self.drop_id, &mut next.current.drop);
        close_slot!(&self.direct_id, &mut next.udp_current.direct);
        close_slot!(&self.udp_proxy_id, &mut next.udp_current.proxy);
        close_slot!(&self.bypass_id, &mut next.udp_current.bypass);
        close_slot!(&self.drop_id, &mut next.udp_current.drop);
        if !old_proxies.is_empty() {
            for proxy in std::mem::take(&mut next.tagged).into_values() {
                if closed_proxy_ids.insert(Arc::as_ptr(&proxy).cast::<()>() as usize) {
                    old_proxies.push(proxy);
                }
            }
            for proxy in std::mem::take(&mut next.udp_tagged).into_values() {
                if closed_proxy_ids.insert(Arc::as_ptr(&proxy).cast::<()>() as usize) {
                    old_proxies.push(proxy);
                }
            }
            next.closed_nodes.insert(id.to_owned());
        }
        if retarget {
            next.retargeted_nodes.insert(id.to_owned());
        }
        if !old_proxies.is_empty() || retarget {
            self.state.store(Arc::new(next));
        }

        for proxy in old_proxies {
            let _ = proxy.close().await;
        }
    }

    /// Retarget a node that is about to be deleted to the built-in direct
    /// slot. Go removes a selected node and reloads the inbound runtime in one
    /// management operation; keeping the old ID in a live selector would
    /// make that reload fail while preparing the selector. Existing flows are
    /// already closed by `close_node`; the next successful replacement then
    /// installs the direct fallback for new flows.
    pub(crate) async fn retarget_node_to_direct(&self, id: &str) {
        self.close_node_with_retarget(id, true).await;
    }

    fn effective_node_id(&self, state: &SelectorState, id: &str) -> String {
        if state.retargeted_nodes.contains(id) {
            String::new()
        } else {
            id.to_owned()
        }
    }

    pub(crate) fn relay_buffer_size(&self) -> usize {
        self.state.load().settings.relay_buffer_size
    }

    pub(crate) fn udp_buffer_size(&self) -> usize {
        self.state.load().settings.udp_buffer_size
    }

    pub(crate) fn udp_ringbuffer_size(&self) -> usize {
        self.state.load().settings.udp_ringbuffer_size
    }

    #[cfg(test)]
    pub(super) fn tagged_proxy(
        &self,
        network: doradus_core::Network,
        tag: &str,
    ) -> Option<Arc<dyn AsyncProxy>> {
        let state = self.state.load();
        let tagged = if network == doradus_core::Network::Udp {
            &state.udp_tagged
        } else {
            &state.tagged
        };
        tagged.get(tag).cloned()
    }
}

pub(crate) struct PreparedProxySelector {
    pub(crate) selector: RuntimeRoutedProxySelector,
    pub(crate) udp_selector: RuntimeRoutedProxySelector,
    tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    udp_tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    metadata: Arc<ProxyContextMetadata>,
    settings: crate::RuntimeSettings,
}

impl RuntimeSnapshot {
    fn node_tag_definitions(&self) -> Result<BTreeMap<String, NodeTagDefinition>> {
        let mut definitions = BTreeMap::new();
        for record in &self.node_tags {
            let name = if record.name.trim().is_empty() {
                record.id.trim()
            } else {
                record.name.trim()
            };
            if name.is_empty() {
                return Err(Error::invalid("node tag name is empty"));
            }
            definitions.insert(name.to_owned(), parse_node_tag(record)?);
        }
        Ok(definitions)
    }

    async fn build_tagged_proxies(
        &self,
        timeout: Duration,
    ) -> Result<BTreeMap<String, Arc<dyn AsyncProxy>>> {
        let definitions = self.node_tag_definitions()?;

        let mut tagged = BTreeMap::new();
        for (tag, definition) in &definitions {
            let ids = resolve_node_tag_targets(tag, &definitions, &mut BTreeSet::new());
            let mut members = Vec::new();
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(id.clone()) {
                    continue;
                }
                // Go's node set skips members that cannot be opened and lets
                // the ordinary route-mode slot handle an empty set. This is
                // important during a partial node migration or after a node
                // was disabled without deleting its tag membership.
                if let Ok(build) = self.build_proxy(&id, timeout).await {
                    members.push(build.proxy);
                }
            }
            if members.is_empty() {
                continue;
            }
            let proxy = if members.len() == 1 {
                members.pop().expect("one node tag member was checked")
            } else {
                Arc::new(NodeSetProxy::new(members, definition.round_robin)?)
            };
            tagged.insert(tag.clone(), proxy);
        }
        Ok(tagged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use doradus_core::dns_resolver::AsyncIpResolver;
    use doradus_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        address: Ipv4Addr,
    }

    impl AsyncIpResolver for CountingResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, doradus_core::Result<IpSet>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let address = self.address;
            Box::pin(async move {
                Ok(IpSet {
                    v4: vec![address],
                    v6: Vec::new(),
                })
            })
        }
    }

    fn metadata_snapshot(
        endpoint_resolver: Arc<dyn AsyncIpResolver>,
        configured_resolver: Arc<dyn AsyncIpResolver>,
    ) -> RuntimeSnapshot {
        let metrics = Arc::new(RuntimeMetrics::new());
        RuntimeSnapshot {
            metrics: Arc::clone(&metrics),
            settings: crate::RuntimeSettings::default(),
            inbound_settings: doradus_store::InboundSettings::default(),
            happy_eyeballs: crate::proxy::new_dialer(0, metrics),
            socket_bind_addresses: Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
            socket_bind_interface: None,
            resolver: Arc::clone(&endpoint_resolver),
            inbound_resolver: Arc::clone(&endpoint_resolver),
            dns_resolver: endpoint_resolver,
            hosts: doradus_core::dns_hosts::HostsTable::new(),
            fakeip: None,
            inbound_fakeip: None,
            resolvers: Vec::new(),
            route: Some(doradus_store::GoRouteRuntimeConfig {
                direct_resolver: "bootstrap".to_owned(),
                proxy_resolver: "bootstrap".to_owned(),
                resolve_locally: false,
                udp_proxy_fqdn: doradus_store::GoUdpProxyFqdnStrategy::Default,
            }),
            route_rules: Vec::new(),
            node_tags: Vec::new(),
            route_lists: Arc::new(crate::RouteListSnapshot::default()),
            router: doradus_trie::router::RouterRuntime::new(
                doradus_trie::router::Router::compile(
                    Vec::new(),
                    doradus_trie::router::RouteDecision {
                        mode: RouteMode::Direct,
                        resolver_policy: doradus_core::ResolverPolicy::default(),
                        priority: 0,
                    },
                )
                .unwrap(),
            ),
            resolver_by_id: BTreeMap::new(),
            inbound_resolver_by_id: BTreeMap::new(),
            dns_resolver_by_id: BTreeMap::from([("bootstrap".to_owned(), configured_resolver)]),
            resolver_errors: BTreeMap::new(),
            resolver_registry_enabled: true,
            geo_metadata: Vec::new(),
            geo: None,
            proxies: vec![GoProxyRuntimeConfig {
                id: "node".to_owned(),
                name: "node".to_owned(),
                group_name: "default".to_owned(),
                origin: "test".to_owned(),
                enabled: true,
                chain_types: vec!["fixedv2".to_owned()],
                layers: vec![GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "proxy.example", "port": 443}]
                    }),
                }],
                transport: GoProxyTransport::Fixed,
                data_json: Vec::new(),
            }],
            nat: doradus_store::NatConfigRecord::default(),
        }
    }

    #[tokio::test]
    async fn endpoint_metadata_does_not_route_through_bootstrap_selector() {
        let configured_calls = Arc::new(AtomicUsize::new(0));
        let endpoint_calls = Arc::new(AtomicUsize::new(0));
        let snapshot = metadata_snapshot(
            Arc::new(CountingResolver {
                calls: Arc::clone(&endpoint_calls),
                address: Ipv4Addr::new(192, 0, 2, 44),
            }),
            Arc::new(CountingResolver {
                calls: Arc::clone(&configured_calls),
                address: Ipv4Addr::new(192, 0, 2, 45),
            }),
        );

        let metadata = snapshot
            .proxy_context_metadata("", "node", "", "", "")
            .await
            .unwrap();

        assert_eq!(configured_calls.load(Ordering::SeqCst), 0);
        assert_eq!(endpoint_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            metadata.endpoints.get("node").copied(),
            Some("192.0.2.44:443".parse().unwrap())
        );
    }
}
