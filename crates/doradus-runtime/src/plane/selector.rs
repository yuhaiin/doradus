use super::*;
use arc_swap::ArcSwap;
use doradus_metrics::{RouteAction, RuntimeMetrics};

#[path = "selector_metadata.rs"]
mod selector_metadata;
#[path = "selector_routing.rs"]
mod selector_routing;
#[path = "selector_state.rs"]
mod selector_state;
use selector_state::*;

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    metrics: Arc<RuntimeMetrics>,
    state: ArcSwap<SelectorState>,
    timeout: Duration,
    loopback: LoopbackDetector,
}

#[derive(Clone)]
pub(crate) struct SelectorState {
    current: RuntimeRoutedProxySelector,
    udp_current: RuntimeRoutedProxySelector,
    selection: ProxySelection,
    nodes: BTreeMap<String, Arc<dyn AsyncProxy>>,
    tagged: BTreeMap<String, TaggedProxy>,
    closed_nodes: BTreeSet<String>,
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
        state
            .selection
            .ids()
            .into_iter()
            .chain(state.nodes.keys().map(String::as_str))
            .filter(|id| !id.is_empty() && !state.closed_nodes.contains(*id))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
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
        let selection =
            ProxySelection::new(direct_id, tcp_proxy_id, udp_proxy_id, bypass_id, drop_id);
        let state = SelectorBuild::new(snapshot, timeout, &loopback)
            .build(selection)
            .await?;
        Ok(Self {
            metrics: Arc::clone(&snapshot.metrics),
            state: ArcSwap::from_pointee(state),
            timeout,
            loopback,
        })
    }

    pub(crate) async fn prepare(&self, snapshot: &RuntimeSnapshot) -> Result<SelectorState> {
        let selection = self.state.load().selection.clone();
        SelectorBuild::new(snapshot, self.timeout, &self.loopback)
            .build(selection)
            .await
    }

    pub(crate) fn replace(&self, next: SelectorState) {
        self.state.store(Arc::new(next));
    }

    /// Close every slot that currently points at `id`, then make new flows
    /// fail closed until the next successful runtime reload. Existing flows
    /// keep their selected `Arc`, so closing the old instances also mirrors
    /// Go's `ProxyStore.Delete` behavior for those flows.
    pub(crate) async fn close_node(&self, id: &str) {
        self.close_node_with_retarget(id, false).await;
    }

    async fn close_node_with_retarget(&self, id: &str, retarget: bool) {
        let current = self.state.load_full();
        let mut next = (*current).clone();
        let proxy = next.nodes.remove(id);
        let mut changed = proxy.is_some();
        macro_rules! close_slot {
            ($slot_id:expr, $slot:expr) => {
                if $slot_id == id {
                    *$slot = Arc::new(DropAsyncProxy);
                    changed = true;
                }
            };
        }
        close_slot!(&next.selection.direct, &mut next.current.direct);
        close_slot!(&next.selection.tcp, &mut next.current.proxy);
        close_slot!(&next.selection.bypass, &mut next.current.bypass);
        close_slot!(&next.selection.drop, &mut next.current.drop);
        close_slot!(&next.selection.direct, &mut next.udp_current.direct);
        close_slot!(&next.selection.udp, &mut next.udp_current.proxy);
        close_slot!(&next.selection.bypass, &mut next.udp_current.bypass);
        close_slot!(&next.selection.drop, &mut next.udp_current.drop);
        for (tag, binding) in &mut next.tagged {
            if let Some(index) = binding.members.iter().position(|(member, _)| member == id) {
                binding.members.remove(index);
                binding.rebuild();
                let metadata = Arc::make_mut(&mut next.metadata);
                metadata.tag_endpoints.remove(tag);
                match binding.members.first() {
                    Some((member, _)) => {
                        metadata.tag_node_ids.insert(tag.clone(), member.clone());
                    }
                    None => {
                        metadata.tag_node_ids.remove(tag);
                    }
                }
                changed = true;
            }
        }
        if !changed {
            return;
        }
        next.closed_nodes.insert(id.to_owned());
        if retarget {
            next.selection.retarget_to_direct(id);
        }
        self.state.store(Arc::new(next));
        if let Some(proxy) = proxy {
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
        let _ = network;
        state.tagged.get(tag).map(|binding| binding.proxy.clone())
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use doradus_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};
    use doradus_types::AsyncIpResolver;
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
