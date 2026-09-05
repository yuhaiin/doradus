//! Flow routing pipeline for RuntimeProxySelector.

use super::selector::*;
use super::selector_metadata::annotate_connection_metadata;

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
            if let Some(fakeip_view) = &metadata.fakeip_view {
                if let Some(domain) = fakeip_view.lookup_domain_ip(address.ip()) {
                    self.metrics
                        .fakeip_operation(doradus_metrics::ResultKind::Hit);
                    context.original_domain = Some(domain.clone());
                    context.fake_ip = Some(address.ip().to_string());
                    context.destination = Endpoint::domain(context.network, domain, address.port());
                } else {
                    self.metrics
                        .fakeip_operation(doradus_metrics::ResultKind::Miss);
                    if metadata
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
            } else if metadata
                .fakeip_pools
                .as_ref()
                .is_some_and(|pools| pools.contains_ip(address.ip()))
            {
                self.metrics
                    .fakeip_operation(doradus_metrics::ResultKind::Miss);
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

impl AsyncProxySelector for RuntimeProxySelector {
    fn route_context(&self, context: &mut FlowContext) {
        let state = self.state.load();
        let direct_id = self.effective_node_id(&state, &self.direct_id);
        let proxy_id = self.effective_node_id(&state, &self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&state, &self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&state, &self.bypass_id);
        let metadata = Arc::clone(&state.metadata);
        self.restore_fakeip_destination(context, &metadata);
        self.apply_hosts_override(context, &metadata);
        let matched_lists = metadata.route_lists.matching_names(context);
        context.lists = matched_lists.clone();
        if let Some(reason) = self.loopback.reason(context) {
            context.route_mode = RouteMode::Block;
            context.skip_route = true;
            context.tag = Some(reason.to_owned());
            context.match_history.clear();
        } else {
            state.current.route_context(context);
        }
        context.lists = matched_lists;
        self.metrics.route_match(match context.route_mode {
            RouteMode::Direct => RouteAction::Direct,
            RouteMode::Proxy => RouteAction::Proxy,
            RouteMode::Bypass => RouteAction::Direct,
            RouteMode::Block => RouteAction::Block,
        });
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
        let state = self.state.load();
        if context.route_mode != doradus_core::RouteMode::Block {
            let tagged = if context.network == doradus_core::Network::Udp {
                &state.udp_tagged
            } else {
                &state.tagged
            };
            if let Some(tag) = context.tag.as_deref().filter(|tag| !tag.trim().is_empty())
                && let Some(proxy) = tagged.get(tag)
            {
                return Arc::clone(proxy);
            }
        }
        let current = if context.network == doradus_core::Network::Udp {
            &state.udp_current
        } else {
            &state.current
        };
        current.select(context)
    }
}
