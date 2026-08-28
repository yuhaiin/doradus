//! Outbound proxy construction from the shared runtime snapshot.
//!
//! Wire codecs live in `doradus-protocol`; the sibling
//! `inbounds/adapters/` directory contains runtime adapters for accepted
//! inbound streams. This file owns runtime proxy selection and Go-layer
//! assembly, which depend on the immutable runtime snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use doradus_chain::ChainProxy;
use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::proxy::{
    AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream, stream_local_addr,
    stream_remote_addr, with_stream_local_addr, with_stream_socket_addrs,
};
use doradus_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, GeoLookup, IpSet, ResolveStrategy, Result,
    RouteMode,
};
use doradus_protocol::YuubinsyaUdpDatagram;
use doradus_protocol::proxy::{DelayedDropAsyncProxy, DirectAsyncProxy, DropAsyncProxy};
use doradus_protocol::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use doradus_store::fakeip::FakeIpViewStore;
use doradus_store::{FakeIpPools, GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
use doradus_trie::router::RuntimeRoutedProxySelector;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::RuntimeSnapshot;
use crate::loopback::LoopbackDetector;
use crate::route::RouteListSnapshot;

#[path = "proxy_adapters.rs"]
mod proxy_adapters;
pub use proxy_adapters::*;

#[path = "selector.rs"]
mod selector;
pub use selector::*;

#[path = "protocol_factory.rs"]
mod protocol_factory;
use protocol_factory::*;

#[path = "proxy_slots.rs"]
mod proxy_slots;
pub use proxy_slots::*;

/// Go's `network_split` point keeps one already-built parent proxy and
/// selects an independent wrapper for TCP and UDP.  The selection happens at
/// the common async boundary so every inbound (including TUN) gets the same
/// semantics.
impl RuntimeSnapshot {
    async fn build_network_split_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        timeout: Duration,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let (split_index, split) = config
            .layers
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.kind.eq_ignore_ascii_case("network_split"))
            .ok_or_else(|| Error::invalid("network_split protocol layer is missing"))?;
        let object = split
            .config
            .as_object()
            .ok_or_else(|| Error::invalid("network_split configuration must be an object"))?;
        let tcp = network_split_branch(object.get("tcp"))?;
        let udp = network_split_branch(object.get("udp"))?;
        if tcp.is_none() && udp.is_none() {
            return Err(Error::invalid("network_split protocols are empty"));
        }

        let parent_config = config.chain_prefix(split_index)?;
        let parent = if split_index == 0 {
            let proxy: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy { timeout });
            self.resolve_proxy(proxy)
        } else {
            let mut parent_snapshot = self.clone();
            parent_snapshot.proxies = vec![parent_config.clone()];
            Box::pin(parent_snapshot.build_proxy(&parent_config.id, timeout))
                .await?
                .proxy
        };
        let proxy_resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
        let udp_server = parent_config
            .resolved_fixed_endpoint(proxy_resolver.as_ref())
            .await?
            .map(|address| Endpoint::ip(doradus_core::Network::Udp, address));
        let tcp = match tcp {
            Some(layer) => {
                self.build_network_split_branch(
                    &layer,
                    Arc::clone(&parent),
                    timeout,
                    udp_server.clone(),
                )
                .await?
            }
            None => Arc::clone(&parent),
        };
        let udp = match udp {
            Some(layer) => {
                self.build_network_split_branch(&layer, Arc::clone(&parent), timeout, udp_server)
                    .await?
            }
            None => Arc::clone(&parent),
        };
        Ok(Arc::new(NetworkSplitProxy { tcp, udp, parent }))
    }

    async fn build_network_split_branch(
        &self,
        layer: &GoProxyLayer,
        parent: Arc<dyn AsyncProxy>,
        timeout: Duration,
        udp_server: Option<Endpoint>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let kind = layer.kind.to_ascii_lowercase();
        match kind.as_str() {
            // Go registers `none` and `proxy` as parent-preserving no-op
            // wrappers. Neither may replace the already-built prefix with a
            // fresh direct socket.
            "none" | "proxy" => Ok(parent),
            "direct" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Direct);
                let proxy: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy { timeout });
                let proxy = Arc::new(SocketPolicyProxy {
                    inner: proxy,
                    bind_addresses: self.socket_bind_addresses.clone(),
                    bind_interface: child.network_interface(),
                    global_bind_interface: self.socket_bind_interface.clone(),
                }) as Arc<dyn AsyncProxy>;
                Ok(self.resolve_proxy_with_route_resolvers(proxy)?)
            }
            "reject" | "block" => Ok(Arc::new(DropAsyncProxy)),
            "drop" => Ok(Arc::new(DelayedDropAsyncProxy::new())),
            "fixed" | "simple" | "fixedv2" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Fixed);
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                Ok(child
                    .to_base_proxy_config_with_resolver(timeout, resolver)
                    .await?
                    .build_with_metrics(Arc::clone(&self.metrics))?)
            }
            "http" | "http_proxy" => {
                let user = layer_string(layer, "user").unwrap_or_default();
                let password = layer_string(layer, "password").unwrap_or_default();
                Ok(Arc::new(doradus_protocol::http::HttpProxy::new(
                    parent, user, password,
                )))
            }
            "socks5" => {
                let user = layer_string(layer, "user").unwrap_or_default();
                let password = layer_string(layer, "password").unwrap_or_default();
                let hostname = layer_string(layer, "hostname").unwrap_or_default();
                let override_port = layer
                    .config
                    .get("override_port")
                    .or_else(|| layer.config.get("overridePort"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                let override_port = i32::try_from(override_port)
                    .map_err(|_| Error::invalid("SOCKS5 override_port is out of range"))?;
                Ok(Arc::new(doradus_protocol::socks5::Socks5Proxy::new(
                    parent,
                    user,
                    password,
                    hostname,
                    override_port,
                )?))
            }
            "http_mock" => Ok(Arc::new(doradus_protocol::http_mock::HttpMockProxy::new(
                parent,
            ))),
            "tls" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Tls);
                #[cfg(feature = "doh-tls")]
                {
                    build_protocol_tls_proxy(&child, parent)
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    let _ = child;
                    Err(Error::new(
                        ErrorKind::Unsupported,
                        "network_split TLS branch requires the doh-tls feature",
                    ))
                }
            }
            "websocket" => {
                let child = GoProxyRuntimeConfig::single_layer(
                    layer,
                    GoProxyTransport::Unknown {
                        name: "websocket".to_owned(),
                    },
                );
                build_protocol_websocket_proxy(&child, parent)
            }
            "shadowsocks" | "shadowsocksr" | "trojan" | "vless" | "vmess" => {
                let transport = match kind.as_str() {
                    "shadowsocks" => GoProxyTransport::Shadowsocks,
                    "shadowsocksr" => GoProxyTransport::Shadowsocksr,
                    "trojan" => GoProxyTransport::Trojan,
                    "vless" => GoProxyTransport::Vless,
                    "vmess" => GoProxyTransport::Vmess,
                    _ => unreachable!(),
                };
                let child = GoProxyRuntimeConfig::single_layer(layer, transport);
                build_protocol_proxy(&child, parent)
            }
            "aead" => {
                let password = layer_string(layer, "password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::invalid("AEAD password is empty"))?;
                let method = layer
                    .config
                    .get("cryptoMethod")
                    .or_else(|| layer.config.get("crypto_method"))
                    .and_then(serde_json::Value::as_str)
                    .map(doradus_protocol::aead::CryptoMethod::parse)
                    .unwrap_or(doradus_protocol::aead::CryptoMethod::Chacha20Poly1305);
                Ok(Arc::new(doradus_protocol::aead::AeadProxy::new(
                    parent, password, method, None,
                )))
            }
            "yuubinsya" => {
                let password = layer_string(layer, "password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::invalid("Yuubinsya password is empty"))?;
                Ok(Arc::new(NetworkSplitYuubinsyaProxy {
                    upstream: parent,
                    password_hash: doradus_protocol::yuubinsya::derive_salt(password.as_bytes()),
                    udp_over_stream: layer_bool(layer, "udp_over_stream", "udpOverStream"),
                    udp_coalesce: layer_bool(layer, "udp_coalesce", "udpCoalesce"),
                    udp_server,
                }))
            }
            // Go's bootstrap_dns_warp point currently only embeds and returns
            // its parent proxy. Keep that no-op behavior instead of treating
            // it as an unknown protocol or accidentally replacing the parent
            // with a direct socket.
            "bootstrap_dns_warp" | "bootstrapdnswarp" => Ok(parent),
            "http2" => {
                let concurrency = layer
                    .config
                    .get("concurrency")
                    .or_else(|| layer.config.get("max_concurrency"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| *value >= 7)
                    .unwrap_or(10);
                let max_streams = layer
                    .config
                    .get("max_streams")
                    .or_else(|| layer.config.get("maxStreams"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(128)
                    .max(1);
                Ok(Arc::new(NetworkSplitHttp2Proxy {
                    upstream: parent,
                    connections: tokio::sync::Mutex::new(Vec::new()),
                    connect_lock: tokio::sync::Mutex::new(()),
                    concurrency,
                    max_streams,
                }))
            }
            "wireguard" | "wire_guard" | "wg" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Wireguard);
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                build_wireguard_proxy(
                    layer,
                    timeout,
                    resolver,
                    child
                        .network_interface()
                        .or_else(|| self.socket_bind_interface.clone()),
                )
                .await
            }
            "warp_masque" | "warpmasque" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::WarpMasque);
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                build_warp_masque_proxy(
                    layer,
                    timeout,
                    resolver,
                    child
                        .network_interface()
                        .or_else(|| self.socket_bind_interface.clone()),
                )
                .await
            }
            "network_split" | "networksplit" => {
                Err(Error::invalid("nested network_split is not supported"))
            }
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("network_split branch protocol {other:?} is not supported"),
            )),
        }
    }

    pub async fn build_proxy(&self, id: &str, timeout: Duration) -> Result<ProxyBuild> {
        let config = self.require_proxy_config(id)?.clone();
        self.build_proxy_config(config, timeout).await
    }

    async fn build_proxy_config(
        &self,
        config: GoProxyRuntimeConfig,
        timeout: Duration,
    ) -> Result<ProxyBuild> {
        self.build_proxy_config_with_tls_marker(config, timeout, false)
            .await
    }

    async fn build_proxy_config_with_tls_marker(
        &self,
        config: GoProxyRuntimeConfig,
        timeout: Duration,
        tls_terminated: bool,
    ) -> Result<ProxyBuild> {
        if !config.enabled {
            return Err(Error::new(
                ErrorKind::Closed,
                format!("proxy runtime config {:?} is disabled", config.id),
            ));
        }
        // A proxy node's own fixed/transport endpoint must use the direct
        // bootstrap resolver. Using the proxy DoH resolver here would make a
        // DoH resolver recursively resolve the node it needs to reach.
        let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
        let plan = ProxyPlan::from_config(&config);

        let proxy = if plan.kind == ProxyPlanKind::NetworkSplit {
            self.build_network_split_proxy(&config, timeout).await?
        } else if plan.kind == ProxyPlanKind::ProtocolH2 {
            build_protocol_h2_proxy(
                &config,
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::VlessWebSocket {
            build_vless_transport_proxy(
                &config,
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::VmessTransport {
            build_vmess_transport_proxy(
                &config,
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::TrojanWebSocket {
            build_trojan_transport_proxy(
                &config,
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::Wireguard {
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("wireguard"))
                .ok_or_else(|| Error::invalid("WireGuard protocol layer is missing"))?;
            build_wireguard_proxy(
                layer,
                timeout,
                resolver.clone(),
                config
                    .network_interface()
                    .or_else(|| self.socket_bind_interface.clone()),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::WarpMasque {
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("warp_masque"))
                .ok_or_else(|| Error::invalid("WARP MASQUE protocol layer is missing"))?;
            build_warp_masque_proxy(
                layer,
                timeout,
                resolver.clone(),
                config
                    .network_interface()
                    .or_else(|| self.socket_bind_interface.clone()),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::HttpMock {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                .await?;
            Arc::new(doradus_protocol::http_mock::HttpMockProxy::new(
                base.build_with_metrics(Arc::clone(&self.metrics))?,
            )) as Arc<dyn AsyncProxy>
        } else if plan.kind == ProxyPlanKind::HttpTermination {
            let index = config
                .layers
                .iter()
                .rposition(|layer| layer.kind.eq_ignore_ascii_case("http_termination"))
                .ok_or_else(|| Error::invalid("HTTP termination layer is missing"))?;
            let parent = if index == 0 {
                self.resolve_proxy(Arc::new(DirectAsyncProxy { timeout }))
            } else {
                Box::pin(self.build_proxy_config(config.chain_prefix(index)?, timeout))
                    .await?
                    .proxy
            };
            #[cfg(feature = "http-termination")]
            {
                crate::proxy::http_termination::build(&config, parent, tls_terminated)?
            }
            #[cfg(not(feature = "http-termination"))]
            {
                let _ = parent;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP termination requires the http-termination feature",
                ));
            }
        } else if plan.kind == ProxyPlanKind::TlsTermination {
            let index = config
                .layers
                .iter()
                .rposition(|layer| layer.kind.eq_ignore_ascii_case("tls_termination"))
                .ok_or_else(|| Error::invalid("TLS termination layer is missing"))?;
            // The Go TLS unwrap point marks its parent HTTP-termination
            // connection before putting the TLS server on top. Propagate that
            // per-chain fact into the recursive prefix build so the reverse
            // proxy can choose the same upstream wire mode.
            let parent = if index == 0 {
                self.resolve_proxy(Arc::new(DirectAsyncProxy { timeout }))
            } else {
                Box::pin(self.build_proxy_config_with_tls_marker(
                    config.chain_prefix(index)?,
                    timeout,
                    true,
                ))
                .await?
                .proxy
            };
            #[cfg(feature = "doh-tls")]
            {
                build_tls_termination_proxy(&config, parent)?
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                let _ = parent;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS termination requires the doh-tls feature",
                ));
            }
        } else if plan.kind == ProxyPlanKind::Chain {
            let json = std::str::from_utf8(&config.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("proxy {:?} data_json is not UTF-8: {error}", config.id),
                )
            })?;
            Arc::new(ChainProxy::from_go_json_with_resolver_and_metrics(
                json,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )?) as Arc<dyn AsyncProxy>
        } else if plan.kind == ProxyPlanKind::Aead {
            build_aead_proxy(
                &config,
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if let ProxyPlanKind::Standard(protocol) = plan.kind {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                .await?;
            let mut upstream = base.build_with_metrics(Arc::clone(&self.metrics))?;
            if plan.has_protocol_tls {
                #[cfg(feature = "doh-tls")]
                {
                    upstream = build_protocol_tls_proxy(&config, upstream)?;
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "protocol TLS requires the doh-tls feature",
                    ));
                }
            }
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case(protocol.layer_name()))
                .ok_or_else(|| Error::invalid("proxy protocol layer is missing"))?;
            if config
                .layers
                .iter()
                .any(|layer| layer.kind.eq_ignore_ascii_case("obfs_http"))
            {
                if config.transport != doradus_store::GoProxyTransport::Shadowsocks {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "obfs_http is only supported around the Go Shadowsocks protocol",
                    ));
                }
                let obfs = config
                    .layers
                    .iter()
                    .find(|layer| layer.kind.eq_ignore_ascii_case("obfs_http"))
                    .expect("obfs_http layer was checked above");
                let host = obfs
                    .config
                    .get("host")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::invalid("obfs_http host is missing"))?;
                let port = obfs
                    .config
                    .get("port")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::invalid("obfs_http port is missing"))?;
                upstream = Arc::new(doradus_protocol::http_obfs::HttpObfsProxy::new(
                    upstream, host, port,
                )?);
            }
            match protocol {
                StandardProtocol::Shadowsocks => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    let method = layer
                        .config
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("Shadowsocks method is missing"))?;
                    Arc::new(doradus_protocol::shadowsocks::ShadowsocksProxy::new(
                        upstream, method, password,
                    )?) as Arc<dyn AsyncProxy>
                }
                StandardProtocol::Shadowsocksr => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let method = layer
                        .config
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("chacha20-ietf");
                    let protocol = layer
                        .config
                        .get("protocol")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("origin");
                    let protocol_param = layer
                        .config
                        .get("protoparam")
                        .or_else(|| layer.config.get("protocol_param"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let obfs = layer
                        .config
                        .get("obfs")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("plain");
                    let obfs_param = layer
                        .config
                        .get("obfsparam")
                        .or_else(|| layer.config.get("obfs_param"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    Arc::new(doradus_protocol::shadowsocksr::ShadowsocksrProxy::new(
                        upstream,
                        method,
                        password,
                        protocol,
                        protocol_param,
                        obfs,
                        obfs_param,
                    )?) as Arc<dyn AsyncProxy>
                }
                StandardProtocol::Trojan => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    Arc::new(doradus_protocol::trojan::TrojanProxy::new(
                        upstream, password,
                    )) as Arc<dyn AsyncProxy>
                }
                StandardProtocol::Vless => {
                    let uuid = layer
                        .config
                        .get("uuid")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
                    Arc::new(doradus_protocol::vless::VlessProxy::new(upstream, uuid)?)
                        as Arc<dyn AsyncProxy>
                }
                StandardProtocol::Vmess => {
                    let uuid = layer
                        .config
                        .get("id")
                        .or_else(|| layer.config.get("uuid"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VMess UUID is missing"))?;
                    let security = layer
                        .config
                        .get("security")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("auto");
                    let alter_id = vmess_alter_id(&layer.config)?;
                    Arc::new(doradus_protocol::vmess::VmessProxy::new(
                        upstream, uuid, security, alter_id,
                    )?) as Arc<dyn AsyncProxy>
                }
            }
        } else {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                .await?;
            let mut proxy = base.build_with_metrics(Arc::clone(&self.metrics))?;
            if config.transport == GoProxyTransport::Yuubinsya
                && config
                    .layers
                    .iter()
                    .any(|layer| layer.kind.eq_ignore_ascii_case("quic"))
            {
                let yuubinsya = config
                    .layers
                    .iter()
                    .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                    .ok_or_else(|| Error::invalid("Yuubinsya layer is missing"))?;
                let password = yuubinsya
                    .config
                    .get("password")
                    .and_then(serde_json::Value::as_str)
                    .filter(|password| !password.is_empty())
                    .ok_or_else(|| Error::invalid("Yuubinsya password is empty"))?;
                let server = config
                    .resolved_fixed_endpoint(resolver.as_ref())
                    .await?
                    .ok_or_else(|| Error::invalid("QUIC transport requires a server endpoint"))?;
                let socks5_prefix = yuubinsya
                    .config
                    .get("socks5_prefix")
                    .or_else(|| yuubinsya.config.get("socks5Prefix"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                proxy = Arc::new(doradus_protocol::YuubinsyaOverTransportProxy::new(
                    proxy,
                    doradus_protocol::yuubinsya::derive_salt(password.as_bytes()),
                    Endpoint::ip(doradus_core::Network::Udp, server),
                    socks5_prefix,
                )?);
            }
            proxy
        };

        let proxy = Arc::new(ConnectBudgetProxy {
            inner: Arc::new(SocketPolicyProxy {
                inner: proxy,
                bind_addresses: self.socket_bind_addresses.clone(),
                bind_interface: config.network_interface(),
                global_bind_interface: self.socket_bind_interface.clone(),
            }),
            semaphore: self.connect_semaphore.clone(),
        }) as Arc<dyn AsyncProxy>;
        let proxy = if matches!(
            config.transport,
            doradus_store::GoProxyTransport::Direct
                | doradus_store::GoProxyTransport::Wireguard
                | doradus_store::GoProxyTransport::WarpMasque
        ) {
            // Direct and the userspace WireGuard stack both require an IP
            // endpoint before opening their final socket. Keep their lookup
            // on the runtime resolver boundary so route resolver policy,
            // hosts and FakeIP are not silently replaced by getaddrinfo.
            self.resolve_proxy_with_route_resolvers(proxy)?
        } else {
            proxy
        };
        Ok(ProxyBuild {
            config,
            // `build_proxy` is also used by management operations such as
            // node latency and route-list refresh, which do not pass through
            // the routed selector. Direct is the one final transport that
            // requires an IP; HTTP/SOCKS5/protocol chains must retain the
            // original domain for their wire framing and proxy-side DNS.
            proxy,
        })
    }

    pub async fn build_proxy_for_management(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<Arc<dyn AsyncProxy>> {
        self.build_proxy_slot(id, timeout, BaseProxyKind::Direct)
            .await
    }

    /// Build the four proxy slots consumed by the TUN dispatcher.
    ///
    /// The persisted records are reused directly; the method only assembles
    /// the already existing proxy implementations into the routing adapter.
    /// Empty IDs use safe built-ins. The internal `direct` sentinel is also
    /// accepted for the selected-node fallback, but unknown non-empty proxy
    /// IDs remain errors so a missing configured node cannot leak traffic.
    pub async fn build_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        self.build_proxy_selector_with_udp(
            direct_id, proxy_id, proxy_id, bypass_id, drop_id, timeout,
        )
        .await
    }

    /// Build a selector with Go-compatible independent TCP and UDP selected
    /// nodes. Existing callers that only provide one node intentionally use
    /// [`Self::build_proxy_selector`] and retain the same node for both
    /// networks.
    pub async fn build_proxy_selector_with_udp(
        &self,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        RuntimeProxySelector::from_snapshot(
            self,
            direct_id,
            tcp_proxy_id,
            udp_proxy_id,
            bypass_id,
            drop_id,
            timeout,
        )
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
        // Go's empty selected-node state means the built-in direct transport;
        // it does not create a synthetic `direct` node row. Keep the proxy
        // slot fail-closed for non-empty unknown IDs while treating only an
        // empty ID as this explicit direct fallback.
        let proxy = self
            .build_proxy_slot(proxy_id, timeout, BaseProxyKind::Direct)
            .await?;
        let bypass = self
            .build_proxy_slot(bypass_id, timeout, BaseProxyKind::Direct)
            .await?;
        let drop = self
            .build_proxy_slot(drop_id, timeout, BaseProxyKind::Reject)
            .await?;

        Ok(RuntimeRoutedProxySelector {
            router: self.router.clone(),
            direct,
            proxy,
            bypass,
            drop,
        })
    }

    /// Wrap a proxy with the resolver used for final outbound sockets.
    ///
    /// `self.resolver` may include the FakeIP answer policy because it is also
    /// used for DNS responses.  A proxy that is already handling a restored
    /// FakeIP domain must never use that policy for its final dial, otherwise
    /// resolving `example.com` can produce the same synthetic address again.
    fn resolve_proxy_with_resolver(
        &self,
        proxy: Arc<dyn AsyncProxy>,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Arc<dyn AsyncProxy> {
        Arc::new(ResolvingProxy::new(proxy, resolver))
    }

    fn resolve_proxy_with_route_resolvers(
        &self,
        proxy: Arc<dyn AsyncProxy>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        // A tagged direct node does not change the flow's route mode. Keep
        // the resolver selection attached to that mode, as in Go: a direct
        // node selected by Proxy mode still uses the Proxy resolver.
        let direct_resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
        let proxy_resolver = self.dns_resolver_for_route_mode(RouteMode::Proxy)?;
        Ok(Arc::new(ResolvingProxy::with_route_resolvers(
            proxy,
            direct_resolver,
            proxy_resolver,
        )))
    }

    pub fn resolve_proxy(&self, proxy: Arc<dyn AsyncProxy>) -> Arc<dyn AsyncProxy> {
        self.resolve_proxy_with_resolver(proxy, self.dns_resolver.clone())
    }

    async fn build_proxy_slot(
        &self,
        id: &str,
        timeout: Duration,
        fallback: BaseProxyKind,
    ) -> Result<Arc<dyn AsyncProxy>> {
        if id.trim().is_empty() || (id == "direct" && matches!(fallback, BaseProxyKind::Direct)) {
            let is_direct = matches!(fallback, BaseProxyKind::Direct);
            let proxy = BaseProxyConfig {
                kind: fallback,
                timeout,
            }
            .build_with_metrics(Arc::clone(&self.metrics))?;
            let proxy = Arc::new(ConnectBudgetProxy {
                inner: Arc::new(SocketPolicyProxy {
                    inner: proxy,
                    bind_addresses: self.socket_bind_addresses.clone(),
                    bind_interface: None,
                    global_bind_interface: self.socket_bind_interface.clone(),
                }),
                semaphore: self.connect_semaphore.clone(),
            }) as Arc<dyn AsyncProxy>;
            return Ok(if is_direct {
                self.resolve_proxy_with_route_resolvers(proxy)?
            } else {
                proxy
            });
        }
        Ok(self.build_proxy(id, timeout).await?.proxy)
    }
}

#[cfg(test)]
#[path = "outbound_tests.rs"]
mod tests;
