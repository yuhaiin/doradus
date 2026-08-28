use super::*;

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    current: RwLock<RuntimeRoutedProxySelector>,
    udp_current: RwLock<RuntimeRoutedProxySelector>,
    pub(super) tagged: RwLock<BTreeMap<String, Arc<dyn AsyncProxy>>>,
    pub(super) udp_tagged: RwLock<BTreeMap<String, Arc<dyn AsyncProxy>>>,
    direct_id: String,
    proxy_id: String,
    udp_proxy_id: String,
    bypass_id: String,
    drop_id: String,
    timeout: Duration,
    closed_nodes: RwLock<BTreeSet<String>>,
    retargeted_nodes: RwLock<BTreeSet<String>>,
    metadata: RwLock<Arc<ProxyContextMetadata>>,
    settings: RwLock<crate::RuntimeSettings>,
    loopback: LoopbackDetector,
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
        let closed_nodes = self
            .closed_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retargeted_nodes = self
            .retargeted_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        [
            self.direct_id.as_str(),
            self.proxy_id.as_str(),
            self.udp_proxy_id.as_str(),
            self.bypass_id.as_str(),
            self.drop_id.as_str(),
        ]
        .into_iter()
        .filter(|id| {
            !id.is_empty() && !closed_nodes.contains(*id) && !retargeted_nodes.contains(*id)
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
        Ok(Self {
            current: RwLock::new(track_selector(current, &loopback)),
            udp_current: RwLock::new(track_selector(udp_current, &loopback)),
            tagged: RwLock::new(track_tagged_proxies(tagged, &loopback)),
            udp_tagged: RwLock::new(track_tagged_proxies(udp_tagged, &loopback)),
            direct_id: direct_id.to_owned(),
            proxy_id: tcp_proxy_id.to_owned(),
            udp_proxy_id: udp_proxy_id.to_owned(),
            bypass_id: bypass_id.to_owned(),
            drop_id: drop_id.to_owned(),
            timeout,
            closed_nodes: RwLock::new(BTreeSet::new()),
            retargeted_nodes: RwLock::new(BTreeSet::new()),
            metadata: RwLock::new(Arc::new(
                snapshot
                    .proxy_context_metadata(
                        direct_id,
                        tcp_proxy_id,
                        udp_proxy_id,
                        bypass_id,
                        drop_id,
                    )
                    .await?,
            )),
            settings: RwLock::new(snapshot.settings.clone()),
            loopback,
        })
    }

    pub(crate) async fn prepare(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<PreparedProxySelector> {
        let direct_id = self.effective_node_id(&self.direct_id);
        let proxy_id = self.effective_node_id(&self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&self.bypass_id);
        let drop_id = self.effective_node_id(&self.drop_id);
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
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = next.selector;
        *self
            .udp_current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.udp_selector;
        *self
            .tagged
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.tagged;
        *self
            .udp_tagged
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.udp_tagged;
        self.closed_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.retargeted_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .metadata
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.metadata;
        *self
            .settings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.settings;
    }

    /// Close every slot that currently points at `id`, then make new flows
    /// fail closed until the next successful runtime reload. Existing flows
    /// keep their selected `Arc`, so closing the old instances also mirrors
    /// Go's `ProxyStore.Delete` behavior for those flows.
    pub(crate) async fn close_node(&self, id: &str) {
        let mut old_proxies = Vec::new();
        let mut closed_proxy_ids = BTreeSet::new();
        {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut closed_nodes = self
                .closed_nodes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

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
            close_slot!(&self.direct_id, &mut current.direct);
            close_slot!(&self.proxy_id, &mut current.proxy);
            close_slot!(&self.bypass_id, &mut current.bypass);
            close_slot!(&self.drop_id, &mut current.drop);
            let mut udp_current = self
                .udp_current
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            close_slot!(&self.direct_id, &mut udp_current.direct);
            close_slot!(&self.udp_proxy_id, &mut udp_current.proxy);
            close_slot!(&self.bypass_id, &mut udp_current.bypass);
            close_slot!(&self.drop_id, &mut udp_current.drop);
            let mut tagged = self
                .tagged
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for proxy in std::mem::take(&mut *tagged).into_values() {
                if closed_proxy_ids.insert(Arc::as_ptr(&proxy).cast::<()>() as usize) {
                    old_proxies.push(proxy);
                }
            }
            let mut udp_tagged = self
                .udp_tagged
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for proxy in std::mem::take(&mut *udp_tagged).into_values() {
                if closed_proxy_ids.insert(Arc::as_ptr(&proxy).cast::<()>() as usize) {
                    old_proxies.push(proxy);
                }
            }
            if !old_proxies.is_empty() {
                closed_nodes.insert(id.to_owned());
            }
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
        self.close_node(id).await;
        self.retargeted_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.to_owned());
    }

    fn effective_node_id(&self, id: &str) -> String {
        if self
            .retargeted_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(id)
        {
            String::new()
        } else {
            id.to_owned()
        }
    }

    pub(crate) fn relay_buffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .relay_buffer_size
    }

    pub(crate) fn udp_buffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .udp_buffer_size
    }

    pub(crate) fn udp_ringbuffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .udp_ringbuffer_size
    }
}

impl RuntimeProxySelector {
    /// Restore the domain hidden behind FakeIP before any host or route-list
    /// matcher runs. An address inside a configured pool without a reverse
    /// mapping is fail-closed and never reaches the ordinary route trie.
    fn restore_fakeip_destination(
        &self,
        context: &mut FlowContext,
        metadata: &ProxyContextMetadata,
    ) {
        if context.original_domain.is_none()
            && let Some(address) = context.destination.addr()
        {
            if let Some(fakeip_view) = &metadata.fakeip_view
                && let Some(domain) = fakeip_view.lookup_domain_ip(address.ip())
            {
                context.original_domain = Some(domain.clone());
                context.fake_ip = Some(address.ip().to_string());
                context.destination = Endpoint::domain(context.network, domain, address.port());
            } else if metadata
                .fakeip_pools
                .as_ref()
                .is_some_and(|pools| pools.contains_ip(address.ip()))
            {
                context.route_mode = RouteMode::Block;
                context.skip_route = true;
                context.tag = Some("fakeip_unmapped".to_owned());
                context.match_history.clear();
            }
        }
    }

    /// Apply hosts before route-list membership and trie evaluation. The
    /// explicit helper keeps this ordering visible at the pipeline boundary.
    fn apply_hosts_override(&self, context: &mut FlowContext, metadata: &ProxyContextMetadata) {
        let hosts_target = if !context.skip_route {
            match &context.destination {
                Endpoint::Domain { host, port, .. } => metadata
                    .hosts
                    .resolve_domain_target(host, *port)
                    .ok()
                    .flatten(),
                Endpoint::Ip { addr, .. } if context.original_domain.is_none() => metadata
                    .hosts
                    .resolve_ip_target(addr.ip(), addr.port())
                    .ok()
                    .flatten(),
                _ => None,
            }
        } else {
            None
        };
        let Some(target) = hosts_target else {
            return;
        };
        let source_port = match &context.destination {
            Endpoint::Ip { addr, .. } => addr.port(),
            Endpoint::Domain { port, .. } => *port,
        };
        if context.hosts.is_none() {
            context.hosts = Some(hosts_context_value(&context.destination));
        }
        let port = target.port.unwrap_or(source_port);
        match target.target {
            doradus_core::dns_hosts::HostsTarget::Ip(target) => {
                context.destination = Endpoint::ip(context.network, SocketAddr::new(target, port));
            }
            doradus_core::dns_hosts::HostsTarget::Domain(target) => {
                context.destination = Endpoint::domain(context.network, target.clone(), port);
                if context.original_domain.is_none() {
                    context.original_domain = Some(target);
                }
            }
        }
    }

    /// Evaluate loopback and route rules against the list membership computed
    /// from the immutable snapshot, then restore that complete membership for
    /// metadata consumers after the trie applies a specific rule.
    fn evaluate_route(&self, context: &mut FlowContext, metadata: &ProxyContextMetadata) {
        let matched_lists = metadata.route_lists.matching_names(context);
        context.lists = matched_lists.clone();
        if let Some(reason) = self.loopback.reason(context) {
            context.route_mode = RouteMode::Block;
            context.skip_route = true;
            context.tag = Some(reason.to_owned());
            context.match_history.clear();
        } else {
            let current = self
                .current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            current.route_context(context);
        }
        context.lists = matched_lists;
    }

    fn resolver_for_route_mode(
        &self,
        context: &FlowContext,
        metadata: &ProxyContextMetadata,
    ) -> Option<String> {
        match context.route_mode {
            RouteMode::Proxy => metadata.proxy_resolver.clone(),
            RouteMode::Direct | RouteMode::Bypass => metadata.direct_resolver.clone(),
            RouteMode::Block => None,
        }
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

impl AsyncProxySelector for RuntimeProxySelector {
    fn route_context(&self, context: &mut FlowContext) {
        let direct_id = self.effective_node_id(&self.direct_id);
        let proxy_id = self.effective_node_id(&self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&self.bypass_id);
        let metadata = self
            .metadata
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.restore_fakeip_destination(context, &metadata);
        self.apply_hosts_override(context, &metadata);
        self.evaluate_route(context, &metadata);
        context.resolver = self.resolver_for_route_mode(context, &metadata);
        annotate_connection_metadata(
            context,
            &metadata,
            &direct_id,
            &proxy_id,
            &udp_proxy_id,
            &bypass_id,
        );
    }

    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        if context.route_mode != doradus_core::RouteMode::Block {
            let tagged = if context.network == doradus_core::Network::Udp {
                self.udp_tagged
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            } else {
                self.tagged
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            };
            if let Some(tag) = context.tag.as_deref().filter(|tag| !tag.trim().is_empty())
                && let Some(proxy) = tagged.get(tag)
            {
                return Arc::clone(proxy);
            }
        }
        let current = if context.network == doradus_core::Network::Udp {
            self.udp_current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        } else {
            self.current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        current.select(context)
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

    async fn proxy_context_metadata(
        &self,
        direct_id: &str,
        proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
    ) -> Result<ProxyContextMetadata> {
        let proxy_resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
        let mut endpoints = BTreeMap::new();
        for id in [direct_id, proxy_id, udp_proxy_id, bypass_id, drop_id]
            .into_iter()
            .filter(|id| !id.trim().is_empty())
        {
            let Some(config) = self.proxy_config(id) else {
                continue;
            };
            if let Ok(Some(endpoint)) = config
                .resolved_fixed_endpoint(proxy_resolver.as_ref())
                .await
            {
                endpoints.insert(id.to_owned(), endpoint);
            }
        }
        let (tag_endpoints, tag_node_ids) = self.tag_metadata().await?;
        let node_names = self
            .proxies
            .iter()
            .filter(|config| !config.name.trim().is_empty())
            .map(|config| (config.id.clone(), config.name.clone()))
            .collect();
        let (direct_resolver, proxy_resolver) = self
            .route
            .as_ref()
            .map(|route| {
                (
                    (!route.direct_resolver.trim().is_empty())
                        .then(|| route.direct_resolver.trim().to_owned()),
                    (!route.proxy_resolver.trim().is_empty())
                        .then(|| route.proxy_resolver.trim().to_owned()),
                )
            })
            .unwrap_or_default();
        let fakeip_view = match self.inbound_fakeip.as_ref().or(self.fakeip.as_ref()) {
            Some(pools) => {
                pools.snapshot().await;
                Some(pools.view_store())
            }
            None => None,
        };
        let fakeip_pools = self
            .inbound_fakeip
            .as_ref()
            .or(self.fakeip.as_ref())
            .cloned();
        Ok(ProxyContextMetadata {
            hosts: self.hosts.clone(),
            route_lists: Arc::clone(&self.route_lists),
            geo: self.geo.clone(),
            fakeip_view,
            fakeip_pools,
            endpoints,
            tag_endpoints,
            tag_node_ids,
            node_names,
            direct_resolver,
            proxy_resolver,
        })
    }

    async fn tag_metadata(
        &self,
    ) -> Result<(BTreeMap<String, SocketAddr>, BTreeMap<String, String>)> {
        let definitions = self.node_tag_definitions()?;
        let proxy_resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;

        let mut endpoints = BTreeMap::new();
        let mut node_ids = BTreeMap::new();
        for tag in definitions.keys() {
            let ids = resolve_node_tag_targets(tag, &definitions, &mut BTreeSet::new());
            for id in ids {
                let Some(config) = self.proxy_config(&id) else {
                    continue;
                };
                if !config.enabled {
                    continue;
                }
                node_ids.entry(tag.clone()).or_insert_with(|| id.clone());
                if let Ok(Some(endpoint)) = config
                    .resolved_fixed_endpoint(proxy_resolver.as_ref())
                    .await
                {
                    endpoints.insert(tag.clone(), endpoint);
                    break;
                }
            }
        }
        Ok((endpoints, node_ids))
    }
}

fn annotate_connection_metadata(
    context: &mut FlowContext,
    metadata: &ProxyContextMetadata,
    direct_id: &str,
    proxy_id: &str,
    udp_proxy_id: &str,
    bypass_id: &str,
) {
    if context.hosts.is_none() {
        let domain = context
            .original_domain
            .as_ref()
            .or_else(|| context.destination.host());
        if let Some(domain) = domain
            && metadata.hosts.resolve(domain).ok().flatten().is_some()
        {
            context.hosts = Some(
                context
                    .destination
                    .port()
                    .map(|port| format!("{domain}:{port}"))
                    .unwrap_or_else(|| domain.to_string()),
            );
        }
    }

    let selected_proxy_id = if context.network == doradus_core::Network::Udp {
        udp_proxy_id
    } else {
        proxy_id
    };
    let selected_id = match context.route_mode {
        doradus_core::RouteMode::Direct => direct_id,
        doradus_core::RouteMode::Proxy => selected_proxy_id,
        doradus_core::RouteMode::Bypass => bypass_id,
        doradus_core::RouteMode::Block => return,
    };
    if context.route_mode == doradus_core::RouteMode::Proxy && !selected_id.is_empty() {
        context.outbound = context
            .tag
            .as_deref()
            .and_then(|tag| metadata.tag_node_ids.get(tag))
            .cloned()
            .or_else(|| Some(selected_id.to_owned()));
    }
    if let Some(node_id) = context.outbound.as_deref() {
        context.outbound_name = metadata.node_names.get(node_id).cloned();
    }
    let endpoint = context
        .tag
        .as_deref()
        .and_then(|tag| metadata.tag_endpoints.get(tag).copied())
        .or_else(|| metadata.endpoints.get(selected_id).copied())
        .or_else(|| context.destination.addr())
        .or_else(|| context.effective_destination().addr());
    let Some(endpoint) = endpoint else {
        return;
    };
    if context.outbound_addr.is_none() {
        context.outbound_addr = Some(Endpoint::ip(context.network, endpoint));
    }
    if context.interface.is_none() {
        context.interface = crate::interfaces::interface_for_ip(endpoint.ip());
    }
    if context.outbound_geo.is_none() {
        context.outbound_geo = metadata
            .geo
            .as_ref()
            .and_then(|geo| geo.country_code(endpoint.ip()).ok().flatten());
    }
}
