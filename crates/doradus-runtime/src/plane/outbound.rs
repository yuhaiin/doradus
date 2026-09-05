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
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use doradus_chain::ChainProxy;
use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::network::TcpDialCandidate;
use doradus_core::proxy::{
    AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream, stream_local_addr,
    stream_remote_addr, with_stream_local_addr, with_stream_socket_addrs,
};
use doradus_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, GeoLookup, IpSet, ResolveStrategy, Result,
    RouteMode,
};
use doradus_protocol::YuubinsyaUdpDatagram;
use doradus_protocol::proxy::{DelayedDropAsyncProxy, DropAsyncProxy};
use doradus_protocol::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use doradus_store::fakeip::FakeIpViewStore;
use doradus_store::{
    FakeIpPools, GoBaseProxyConfig, GoBaseProxyEndpoint, GoBaseProxyKind, GoProxyLayer,
    GoProxyRuntimeConfig, GoProxyTransport,
};
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

#[path = "protocol_tls.rs"]
mod protocol_tls;
use protocol_tls::*;

#[path = "proxy_plan.rs"]
mod proxy_plan;
use proxy_plan::*;

#[path = "protocol_factory.rs"]
mod protocol_factory;
use protocol_factory::*;

#[path = "proxy_slots.rs"]
mod proxy_slots;
pub use proxy_slots::*;

#[path = "happy_eyeballs.rs"]
mod happy_eyeballs;
pub(crate) use happy_eyeballs::{
    HappyEyeballsDirectProxy, HappyEyeballsFixedProxy, new_dialer, reconfigure_dialer,
};

/// Go's `network_split` point keeps one already-built parent proxy and
/// selects an independent wrapper for TCP and UDP.  The selection happens at
/// the common async boundary so every inbound (including TUN) gets the same
/// semantics.
impl RuntimeSnapshot {
    fn happy_eyeballs_direct(&self, timeout: Duration) -> Result<Arc<dyn AsyncProxy>> {
        let direct_resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
        let proxy_resolver = self.dns_resolver_for_route_mode(RouteMode::Proxy)?;
        Ok(Arc::new(
            HappyEyeballsDirectProxy::new_with_route_resolvers(
                timeout,
                direct_resolver,
                proxy_resolver,
                Arc::clone(&self.happy_eyeballs),
            ),
        ))
    }

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
            self.happy_eyeballs_direct(timeout)?
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
                let proxy = self.happy_eyeballs_direct(timeout)?;
                let proxy = Arc::new(SocketPolicyProxy {
                    inner: proxy,
                    bind_addresses: self.socket_bind_addresses.clone(),
                    bind_interface: child.network_interface(),
                    global_bind_interface: self.socket_bind_interface.clone(),
                }) as Arc<dyn AsyncProxy>;
                Ok(proxy)
            }
            "reject" | "block" => Ok(Arc::new(DropAsyncProxy)),
            "drop" => Ok(Arc::new(DelayedDropAsyncProxy::new())),
            "fixed" | "simple" | "fixedv2" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Fixed);
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                Ok(protocol_base_proxy_config(
                    child
                        .to_base_proxy_config_with_resolver(timeout, resolver)
                        .await?,
                )?
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
                let plan = Socks5Plan::compile_layer(layer)?;
                Ok(Arc::new(doradus_protocol::socks5::Socks5Proxy::new(
                    parent,
                    plan.user,
                    plan.password,
                    plan.hostname,
                    plan.override_port,
                )?))
            }
            "http_mock" => Ok(Arc::new(doradus_protocol::http_mock::HttpMockProxy::new(
                parent,
            ))),
            "tls" => {
                let tls = ProtocolTlsPlan::compile_layer(layer)?;
                #[cfg(feature = "doh-tls")]
                {
                    build_protocol_tls_proxy(&tls, parent)
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    let _ = tls;
                    Err(Error::new(
                        ErrorKind::Unsupported,
                        "network_split TLS branch requires the doh-tls feature",
                    ))
                }
            }
            "websocket" => {
                let websocket = WebSocketPlan::compile_layer(layer)?;
                build_protocol_websocket_proxy(&websocket, parent)
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
                let plan = ProxyPlan::from_config(&child)?;
                build_protocol_proxy(
                    plan.standard
                        .as_ref()
                        .expect("standard network-split protocol must compile a typed plan"),
                    parent,
                )
            }
            "aead" => {
                let plan = AeadPlan::compile_layer(layer)?;
                let method = doradus_protocol::aead::CryptoMethod::parse(&plan.method);
                Ok(Arc::new(doradus_protocol::aead::AeadProxy::new(
                    parent,
                    &plan.password,
                    method,
                    None,
                )))
            }
            "yuubinsya" => {
                let plan = YuubinsyaPlan::compile_layer(layer)?;
                Ok(Arc::new(NetworkSplitYuubinsyaProxy {
                    upstream: parent,
                    password_hash: doradus_protocol::yuubinsya::derive_salt(
                        plan.password.as_bytes(),
                    ),
                    udp_over_stream: plan.udp_over_stream,
                    udp_coalesce: plan.udp_coalesce,
                    udp_server,
                }))
            }
            // Go's bootstrap_dns_warp point currently only embeds and returns
            // its parent proxy. Keep that no-op behavior instead of treating
            // it as an unknown protocol or accidentally replacing the parent
            // with a direct socket.
            "bootstrap_dns_warp" | "bootstrapdnswarp" => Ok(parent),
            "http2" => {
                let plan = Http2Plan::compile_layer(layer);
                Ok(Arc::new(NetworkSplitHttp2Proxy {
                    upstream: parent,
                    connections: tokio::sync::Mutex::new(Vec::new()),
                    connect_lock: tokio::sync::Mutex::new(()),
                    concurrency: plan.concurrency,
                    max_streams: plan.max_streams,
                }))
            }
            "wireguard" | "wire_guard" | "wg" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Wireguard);
                let wireguard = compile_wireguard_config(layer)?;
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                build_wireguard_proxy(
                    &wireguard,
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
                let warp = compile_warp_masque_config(layer)?;
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                build_warp_masque_proxy(
                    &warp,
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
        let plan = ProxyPlan::from_config(&config)?;

        let proxy = if plan.kind == ProxyPlanKind::NetworkSplit {
            self.build_network_split_proxy(&config, timeout).await?
        } else if plan.kind == ProxyPlanKind::ProtocolH2 {
            build_protocol_h2_proxy(
                plan.h2_transport_json
                    .as_deref()
                    .expect("HTTP/2 protocol must compile transport JSON"),
                plan.standard
                    .as_ref()
                    .expect("HTTP/2 protocol must compile a typed protocol plan"),
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
                Arc::clone(&self.happy_eyeballs),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::VlessWebSocket {
            build_vless_transport_proxy(
                &config,
                plan.standard
                    .as_ref()
                    .expect("VLESS transport must compile a typed protocol plan"),
                plan.protocol_tls.as_ref(),
                plan.websocket.as_ref(),
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::VmessTransport {
            build_vmess_transport_proxy(
                &config,
                plan.standard
                    .as_ref()
                    .expect("VMess transport must compile a typed protocol plan"),
                plan.protocol_tls.as_ref(),
                plan.websocket.as_ref(),
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::TrojanWebSocket {
            build_trojan_transport_proxy(
                &config,
                plan.standard
                    .as_ref()
                    .expect("Trojan transport must compile a typed protocol plan"),
                plan.protocol_tls.as_ref(),
                plan.websocket.as_ref(),
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::Wireguard {
            build_wireguard_proxy(
                plan.wireguard
                    .as_ref()
                    .expect("WireGuard must compile a typed config"),
                timeout,
                resolver.clone(),
                config
                    .network_interface()
                    .or_else(|| self.socket_bind_interface.clone()),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::WarpMasque {
            build_warp_masque_proxy(
                plan.warp_masque
                    .as_ref()
                    .expect("WARP MASQUE must compile a typed config"),
                timeout,
                resolver.clone(),
                config
                    .network_interface()
                    .or_else(|| self.socket_bind_interface.clone()),
            )
            .await?
        } else if plan.kind == ProxyPlanKind::HttpMock {
            let base = protocol_base_proxy_config(
                config
                    .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                    .await?,
            )?;
            let upstream = if let Some(endpoints) = fixed_tcp_candidates(&base.kind) {
                Arc::new(HappyEyeballsFixedProxy::new(
                    endpoints,
                    Arc::clone(&self.happy_eyeballs),
                    timeout,
                )?) as Arc<dyn AsyncProxy>
            } else {
                base.build_with_metrics(Arc::clone(&self.metrics))?
            };
            Arc::new(doradus_protocol::http_mock::HttpMockProxy::new(upstream))
                as Arc<dyn AsyncProxy>
        } else if plan.kind == ProxyPlanKind::HttpTermination {
            let index = config
                .layers
                .iter()
                .rposition(|layer| layer.kind.eq_ignore_ascii_case("http_termination"))
                .ok_or_else(|| Error::invalid("HTTP termination layer is missing"))?;
            let parent = if index == 0 {
                self.happy_eyeballs_direct(timeout)?
            } else {
                Box::pin(self.build_proxy_config(config.chain_prefix(index)?, timeout))
                    .await?
                    .proxy
            };
            #[cfg(feature = "http-termination")]
            {
                crate::proxy::http_termination::build(
                    plan.http_termination
                        .expect("HTTP termination plan must be compiled"),
                    parent,
                    tls_terminated,
                )?
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
                self.happy_eyeballs_direct(timeout)?
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
                build_tls_termination_proxy(
                    plan.tls_termination
                        .expect("TLS termination plan must be compiled"),
                    parent,
                )?
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
            Arc::new(
                ChainProxy::from_go_json_with_resolver_and_metrics_and_dialer(
                    json,
                    resolver.clone(),
                    Arc::clone(&self.metrics),
                    Arc::clone(&self.happy_eyeballs),
                )?,
            ) as Arc<dyn AsyncProxy>
        } else if plan.kind == ProxyPlanKind::Aead {
            build_aead_proxy(
                &config,
                plan.aead
                    .as_ref()
                    .expect("AEAD transport must compile a typed plan"),
                plan.protocol_tls.as_ref(),
                timeout,
                resolver.clone(),
                Arc::clone(&self.metrics),
                Arc::clone(&self.happy_eyeballs),
            )
            .await?
        } else if let ProxyPlanKind::Standard(_) = plan.kind {
            let base = protocol_base_proxy_config(
                config
                    .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                    .await?,
            )?;
            let mut upstream = if let Some(endpoints) = fixed_tcp_candidates(&base.kind) {
                Arc::new(HappyEyeballsFixedProxy::new(
                    endpoints,
                    Arc::clone(&self.happy_eyeballs),
                    timeout,
                )?) as Arc<dyn AsyncProxy>
            } else {
                base.build_with_metrics(Arc::clone(&self.metrics))?
            };
            if let Some(tls) = &plan.protocol_tls {
                #[cfg(feature = "doh-tls")]
                {
                    upstream = build_protocol_tls_proxy(tls, upstream)?;
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "protocol TLS requires the doh-tls feature",
                    ));
                }
            }
            if let Some(obfs) = &plan.http_obfs {
                upstream = Arc::new(doradus_protocol::http_obfs::HttpObfsProxy::new(
                    upstream, &obfs.host, &obfs.port,
                )?);
            }
            build_protocol_proxy(
                plan.standard
                    .as_ref()
                    .expect("standard protocol must compile a typed plan"),
                upstream,
            )?
        } else {
            let base = protocol_base_proxy_config(
                config
                    .to_base_proxy_config_with_resolver(timeout, resolver.clone())
                    .await?,
            )?;
            let mut proxy = if let Some(endpoints) = fixed_tcp_candidates(&base.kind) {
                Arc::new(HappyEyeballsFixedProxy::new(
                    endpoints,
                    Arc::clone(&self.happy_eyeballs),
                    timeout,
                )?) as Arc<dyn AsyncProxy>
            } else {
                base.build_with_metrics(Arc::clone(&self.metrics))?
            };
            if config.transport == GoProxyTransport::Yuubinsya
                && config
                    .layers
                    .iter()
                    .any(|layer| layer.kind.eq_ignore_ascii_case("quic"))
            {
                let yuubinsya = plan
                    .yuubinsya
                    .as_ref()
                    .expect("Yuubinsya transport must compile a typed plan");
                let server = config
                    .resolved_fixed_endpoint(resolver.as_ref())
                    .await?
                    .ok_or_else(|| Error::invalid("QUIC transport requires a server endpoint"))?;
                proxy = Arc::new(doradus_protocol::YuubinsyaOverTransportProxy::new(
                    proxy,
                    doradus_protocol::yuubinsya::derive_salt(yuubinsya.password.as_bytes()),
                    Endpoint::ip(doradus_core::Network::Udp, server),
                    yuubinsya.socks5_prefix,
                )?);
            }
            proxy
        };

        let proxy = if matches!(config.transport, doradus_store::GoProxyTransport::Direct) {
            let direct = self.happy_eyeballs_direct(timeout)?;
            Arc::new(SocketPolicyProxy {
                inner: direct,
                bind_addresses: self.socket_bind_addresses.clone(),
                bind_interface: config.network_interface(),
                global_bind_interface: self.socket_bind_interface.clone(),
            }) as Arc<dyn AsyncProxy>
        } else {
            Arc::new(SocketPolicyProxy {
                inner: proxy,
                bind_addresses: self.socket_bind_addresses.clone(),
                bind_interface: config.network_interface(),
                global_bind_interface: self.socket_bind_interface.clone(),
            }) as Arc<dyn AsyncProxy>
        };
        let proxy = if matches!(
            config.transport,
            doradus_store::GoProxyTransport::Wireguard
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
            let proxy = if is_direct {
                self.happy_eyeballs_direct(timeout)?
            } else {
                proxy
            };
            let proxy = Arc::new(SocketPolicyProxy {
                inner: proxy,
                bind_addresses: self.socket_bind_addresses.clone(),
                bind_interface: None,
                global_bind_interface: self.socket_bind_interface.clone(),
            }) as Arc<dyn AsyncProxy>;
            return Ok(proxy);
        }
        Ok(self.build_proxy(id, timeout).await?.proxy)
    }
}

fn fixed_tcp_candidates(kind: &BaseProxyKind) -> Option<Vec<TcpDialCandidate>> {
    match kind {
        BaseProxyKind::Fixed { address } => Some(vec![TcpDialCandidate::new(*address, None)]),
        BaseProxyKind::FixedMany { endpoints } => Some(
            endpoints
                .iter()
                .map(|endpoint| {
                    TcpDialCandidate::new(endpoint.address, endpoint.bind_interface.clone())
                })
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
#[path = "outbound_tests.rs"]
mod tests;
