use super::*;
use crate::RuntimeSnapshot;
use base64::Engine;
use doradus_core::dns_resolver::SystemAsyncIpResolver;
use doradus_core::{FlowContext, GeoLookup, RouteMode};
use doradus_protocol::YuubinsyaUdpServer;
use doradus_protocol::proxy::{DirectAsyncProxy, FixedAsyncProxy};
use doradus_protocol::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use doradus_protocol::quic::{QuicServer, QuicServerConfig};
use doradus_protocol::trojan::{self, Command};
use doradus_store::GoProxyLayer;
use doradus_store::GoProxyTransport;
use doradus_trie::router::{RouteDecision, Router, RouterRuntime};
#[cfg(feature = "doh-tls")]
use std::io::Cursor;
use std::sync::Arc;

fn snapshot(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
    snapshot_with_resolver(config, Arc::new(SystemAsyncIpResolver))
}

fn snapshot_with_resolver(
    config: GoProxyRuntimeConfig,
    resolver: Arc<dyn AsyncIpResolver>,
) -> RuntimeSnapshot {
    let metrics = Arc::new(doradus_metrics::RuntimeMetrics::new());
    RuntimeSnapshot {
        metrics: Arc::clone(&metrics),
        settings: crate::RuntimeSettings::default(),
        happy_eyeballs: crate::proxy::new_dialer(0, metrics),
        socket_bind_addresses: Arc::from(Vec::<std::net::IpAddr>::new().into_boxed_slice()),
        socket_bind_interface: None,
        resolver: Arc::clone(&resolver),
        inbound_resolver: Arc::clone(&resolver),
        dns_resolver: resolver,
        hosts: doradus_core::dns_hosts::HostsTable::new(),
        fakeip: None,
        inbound_fakeip: None,
        inbound_settings: doradus_store::InboundSettings::default(),
        resolvers: Vec::new(),
        route: None,
        route_rules: Vec::new(),
        node_tags: Vec::new(),
        route_lists: Arc::new(crate::RouteListSnapshot::default()),
        router: RouterRuntime::new(
            Router::compile(
                Vec::new(),
                RouteDecision {
                    mode: doradus_core::RouteMode::Direct,
                    resolver_policy: doradus_core::ResolverPolicy::default(),
                    priority: 0,
                },
            )
            .unwrap(),
        ),
        resolver_by_id: std::collections::BTreeMap::new(),
        inbound_resolver_by_id: std::collections::BTreeMap::new(),
        dns_resolver_by_id: std::collections::BTreeMap::new(),
        resolver_errors: std::collections::BTreeMap::new(),
        resolver_registry_enabled: false,
        geo_metadata: Vec::new(),
        geo: None,
        proxies: vec![config],
        nat: doradus_store::NatConfigRecord::default(),
    }
}

#[path = "outbound_tests/chains.rs"]
mod chains;
#[path = "outbound_tests/configuration.rs"]
mod configuration;
#[path = "outbound_tests/protocols.rs"]
mod protocols;
#[path = "outbound_tests/routing.rs"]
mod routing;
use routing::MappingResolver;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}
