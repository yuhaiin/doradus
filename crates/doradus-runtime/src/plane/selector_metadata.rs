//! Selector observability and endpoint metadata assembly.

use super::selector::*;

impl RuntimeSnapshot {
    pub(super) async fn proxy_context_metadata(
        &self,
        direct_id: &str,
        proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
    ) -> Result<ProxyContextMetadata> {
        // Endpoint metadata is advisory and is built while the selector is
        // still being published. Do not route this lookup through the
        // configured bootstrap resolver: a ResolverProxyBridge may not have
        // this selector installed yet, which would make startup depend on a
        // selector that is currently waiting on this metadata.
        //
        // Actual proxy construction and flow DNS resolution continue to use
        // their route-specific resolvers; this only avoids a startup cycle in
        // the optional observability metadata.
        let endpoint_resolver = self.dns_resolver.clone();
        let mut endpoints = BTreeMap::new();
        for id in [direct_id, proxy_id, udp_proxy_id, bypass_id, drop_id]
            .into_iter()
            .filter(|id| !id.trim().is_empty())
        {
            let Some(config) = self.proxy_config(id) else {
                continue;
            };
            if let Ok(Some(endpoint)) = config
                .resolved_fixed_endpoint(endpoint_resolver.as_ref())
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
        // Keep tag endpoint metadata on the same non-routed resolver as the
        // node metadata above. Tags are optional observability data and must
        // not create a bootstrap-selector dependency during publication.
        let endpoint_resolver = self.dns_resolver.clone();

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
                    .resolved_fixed_endpoint(endpoint_resolver.as_ref())
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

pub(super) fn annotate_connection_metadata(
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
