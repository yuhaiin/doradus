//! Proxy construction from the shared runtime snapshot.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use yuhaiin_chain::ChainProxy;
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector};
use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use yuhaiin_core::{Error, ErrorKind, FlowContext, Result};
use yuhaiin_store::GoProxyRuntimeConfig;
use yuhaiin_trie::router::RuntimeRoutedProxySelector;

use crate::RuntimeSnapshot;

#[path = "proxy/common.rs"]
pub(crate) mod common;
#[path = "proxy/http.rs"]
pub(crate) mod http;
#[path = "proxy/socks4a.rs"]
pub(crate) mod socks4a;
#[path = "proxy/socks5.rs"]
pub(crate) mod socks5;
#[cfg(feature = "websocket")]
#[path = "proxy/websocket.rs"]
pub(crate) mod websocket;
#[path = "proxy/yuubinsya.rs"]
pub(crate) mod yuubinsya;

/// The selected runtime proxy plus its persisted public configuration.
/// Keeping both together makes future HTTP handlers able to expose stable
/// metadata without reconstructing or serializing protocol internals.
pub struct ProxyBuild {
    pub config: GoProxyRuntimeConfig,
    pub proxy: Arc<dyn AsyncProxy>,
}

impl RuntimeSnapshot {
    pub async fn build_proxy(&self, id: &str, timeout: Duration) -> Result<ProxyBuild> {
        let config = self.require_proxy_config(id)?.clone();
        if !config.enabled {
            return Err(Error::new(
                ErrorKind::Closed,
                format!("proxy runtime config {id:?} is disabled"),
            ));
        }

        let proxy = if is_chain_config(&config) {
            let json = std::str::from_utf8(&config.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("proxy {id:?} data_json is not UTF-8: {error}"),
                )
            })?;
            Arc::new(ChainProxy::from_go_json_with_resolver(
                json,
                self.resolver.clone(),
            )?) as Arc<dyn AsyncProxy>
        } else {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            base.build()?
        };

        Ok(ProxyBuild { config, proxy })
    }

    /// Build the four proxy slots consumed by the TUN dispatcher.
    ///
    /// The persisted records are reused directly; the method only assembles
    /// the already existing proxy implementations into the routing adapter.
    /// Empty direct/bypass/drop IDs use safe built-ins. An empty proxy ID is
    /// an error because silently falling back to direct would leak traffic.
    pub async fn build_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        RuntimeProxySelector::from_snapshot(self, direct_id, proxy_id, bypass_id, drop_id, timeout)
            .await
    }

    async fn build_routed_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeRoutedProxySelector> {
        let direct = self
            .build_proxy_slot(direct_id, timeout, BaseProxyKind::Direct)
            .await?;
        let proxy = self.build_proxy(proxy_id, timeout).await?.proxy;
        let bypass = self
            .build_proxy_slot(bypass_id, timeout, BaseProxyKind::Direct)
            .await?;
        let drop = self
            .build_proxy_slot(drop_id, timeout, BaseProxyKind::Drop)
            .await?;

        Ok(RuntimeRoutedProxySelector {
            router: self.router.clone(),
            direct,
            proxy,
            bypass,
            drop,
        })
    }

    async fn build_proxy_slot(
        &self,
        id: &str,
        timeout: Duration,
        fallback: BaseProxyKind,
    ) -> Result<Arc<dyn AsyncProxy>> {
        if id.trim().is_empty() {
            return BaseProxyConfig {
                kind: fallback,
                timeout,
            }
            .build();
        }
        Ok(self.build_proxy(id, timeout).await?.proxy)
    }
}

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    current: RwLock<RuntimeRoutedProxySelector>,
    direct_id: String,
    proxy_id: String,
    bypass_id: String,
    drop_id: String,
    timeout: Duration,
}

impl RuntimeProxySelector {
    async fn from_snapshot(
        snapshot: &RuntimeSnapshot,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let current = snapshot
            .build_routed_proxy_selector(direct_id, proxy_id, bypass_id, drop_id, timeout)
            .await?;
        Ok(Self {
            current: RwLock::new(current),
            direct_id: direct_id.to_owned(),
            proxy_id: proxy_id.to_owned(),
            bypass_id: bypass_id.to_owned(),
            drop_id: drop_id.to_owned(),
            timeout,
        })
    }

    pub(crate) async fn prepare(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<RuntimeRoutedProxySelector> {
        snapshot
            .build_routed_proxy_selector(
                &self.direct_id,
                &self.proxy_id,
                &self.bypass_id,
                &self.drop_id,
                self.timeout,
            )
            .await
    }

    pub(crate) fn replace(&self, next: RuntimeRoutedProxySelector) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = next;
    }
}

impl AsyncProxySelector for RuntimeProxySelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.select(context)
    }
}

fn is_chain_config(config: &GoProxyRuntimeConfig) -> bool {
    if config.chain_types.iter().any(|kind| {
        matches!(
            kind.to_ascii_lowercase().as_str(),
            "tls" | "http2" | "websocket"
        )
    }) {
        return true;
    }
    config.chain_types.iter().any(|kind| {
        kind.eq_ignore_ascii_case("yuubinsya")
            && config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                .and_then(|layer| layer.config.get("udp_over_stream"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeSnapshot;
    use std::sync::Arc;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::proxy::{AsyncProxySelector, YuubinsyaUdpServer};
    use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
    use yuhaiin_core::{FlowContext, RouteMode};
    use yuhaiin_store::GoProxyTransport;
    use yuhaiin_trie::router::{RouteDecision, Router, RouterRuntime};

    fn snapshot(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
        RuntimeSnapshot {
            resolver: Arc::new(SystemAsyncIpResolver),
            hosts: yuhaiin_core::dns_hosts::HostsTable::new(),
            fakeip: None,
            resolvers: Vec::new(),
            route: None,
            route_rules: Vec::new(),
            route_lists: crate::RouteListSnapshot::default(),
            router: RouterRuntime::new(
                Router::compile(
                    Vec::new(),
                    RouteDecision {
                        mode: yuhaiin_core::RouteMode::Direct,
                        resolver_policy: yuhaiin_core::ResolverPolicy::default(),
                        priority: 0,
                    },
                )
                .unwrap(),
            ),
            resolver_by_id: std::collections::BTreeMap::new(),
            resolver_errors: std::collections::BTreeMap::new(),
            resolver_registry_enabled: false,
            geo_metadata: Vec::new(),
            geo: None,
            proxies: vec![config],
            nat: yuhaiin_store::NatConfigRecord::default(),
        }
    }

    #[test]
    fn base_proxy_build_uses_shared_snapshot_config_without_a_dto() {
        let config = GoProxyRuntimeConfig {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let built =
            block_on(snapshot(config).build_proxy("direct", Duration::from_secs(1))).unwrap();
        assert_eq!(built.config.id, "direct");
        let _ = BaseProxyConfig {
            kind: BaseProxyKind::Direct,
            timeout: Duration::from_secs(1),
        };
    }

    #[test]
    fn proxy_selector_assembles_snapshot_proxies_and_safe_builtin_slots() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = block_on(snapshot(config).build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            Duration::from_secs(1),
        ))
        .unwrap();

        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        context.route_mode = RouteMode::Proxy;
        context.skip_route = true;
        let selected = selector.select(&context);
        context.route_mode = RouteMode::Direct;
        let direct = selector.select(&context);
        assert!(!Arc::ptr_eq(&selected, &direct));
    }

    #[test]
    fn runtime_builds_native_yuubinsya_udp_from_go_layers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let password_hash = yuhaiin_core::yuubinsya::derive_salt(b"password");
            let server =
                YuubinsyaUdpServer::bind("127.0.0.1:0".parse().unwrap(), password_hash, false)
                    .await
                    .unwrap();
            let server_address = server.local_addr().unwrap().addr().unwrap();
            let config = GoProxyRuntimeConfig {
                id: "yuubinsya-udp".to_owned(),
                name: "yuubinsya-udp".to_owned(),
                group_name: "default".to_owned(),
                origin: "go".to_owned(),
                enabled: true,
                chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
                layers: vec![
                    yuhaiin_store::GoProxyLayer {
                        kind: "fixedv2".to_owned(),
                        config: serde_json::json!({
                            "addresses": [{
                                "host": server_address.ip().to_string(),
                                "port": server_address.port()
                            }]
                        }),
                    },
                    yuhaiin_store::GoProxyLayer {
                        kind: "yuubinsya".to_owned(),
                        config: serde_json::json!({ "password": "password" }),
                    },
                ],
                transport: GoProxyTransport::Yuubinsya,
                data_json: Vec::new(),
            };
            let proxy = snapshot(config)
                .build_proxy("yuubinsya-udp", Duration::from_secs(3))
                .await
                .unwrap()
                .proxy;
            let target = yuhaiin_core::Endpoint::domain(
                yuhaiin_core::Network::Udp,
                yuhaiin_core::DomainName::new("example.com").unwrap(),
                53,
            );
            let context = FlowContext::new(target.clone());
            let datagram = proxy.open_datagram(&context).await.unwrap();
            datagram.send_to(b"query", target.clone()).await.unwrap();
            let mut buffer = [0; 64];
            let (length, decoded_target, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"query");
            assert_eq!(decoded_target, target);
            server
                .send_to(b"answer", decoded_target.clone(), peer)
                .await
                .unwrap();
            let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"answer");
            assert_eq!(response_target, decoded_target);
        });
    }

    #[test]
    fn runtime_builds_simple_go_yuubinsya_uot_chain_without_four_layer_assumption() {
        let config = GoProxyRuntimeConfig {
            id: "yuubinsya-uot".to_owned(),
            name: "yuubinsya-uot".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "yuubinsya".to_owned(),
                    config: serde_json::json!({
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }),
                },
            ],
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    { "type": "fixedv2", "fixedv2": {
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }},
                    { "type": "yuubinsya", "yuubinsya": {
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built = block_on(snapshot(config).build_proxy("yuubinsya-uot", Duration::from_secs(1)))
            .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let error = match block_on(built.proxy.connect(&context)) {
            Ok(_) => panic!("simple Yuubinsya UOT must reject TCP stream connect"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn runtime_routes_go_websocket_http2_chain_to_chain_builder() {
        let config = GoProxyRuntimeConfig {
            id: "websocket-chain".to_owned(),
            name: "websocket-chain".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "http2".to_owned(),
                "yuubinsya".to_owned(),
            ],
            layers: Vec::new(),
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    {"type": "fixedv2", "fixedv2": {
                        "addresses": [{"host": "127.0.0.1:40501"}]
                    }},
                    {"type": "websocket", "websocket": {
                        "host": "localhost", "path": "/proxy/ws"
                    }},
                    {"type": "http2", "http2": {"concurrency": 2}},
                    {"type": "yuubinsya", "yuubinsya": {
                        "password": "password"
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("websocket-chain", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "websocket-chain");
    }

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
}
