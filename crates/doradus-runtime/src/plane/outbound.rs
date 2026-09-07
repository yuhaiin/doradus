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
use doradus_store::{FakeIpPools, GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
use doradus_trie::router::RuntimeRoutedProxySelector;
use doradus_types::AsyncIpResolver;
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

#[path = "base_proxy.rs"]
mod base_proxy;
use base_proxy::*;

#[path = "network_split.rs"]
mod network_split;

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

    async fn build_base_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        timeout: Duration,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let base = compile_base_proxy_config(config, timeout, resolver.as_ref()).await?;
        if let Some(endpoints) = fixed_tcp_candidates(&base.kind) {
            Ok(Arc::new(HappyEyeballsFixedProxy::new(
                endpoints,
                Arc::clone(&self.happy_eyeballs),
                timeout,
            )?))
        } else {
            base.build_with_metrics(Arc::clone(&self.metrics))
        }
    }

    async fn build_http_mock_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        timeout: Duration,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let upstream = self.build_base_proxy(config, timeout, resolver).await?;
        Ok(Arc::new(doradus_protocol::http_mock::HttpMockProxy::new(
            upstream,
        )))
    }

    async fn build_termination_parent(
        &self,
        config: &GoProxyRuntimeConfig,
        layer_kind: &str,
        timeout: Duration,
        tls_terminated: bool,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let index = config
            .layers
            .iter()
            .rposition(|layer| layer.kind.eq_ignore_ascii_case(layer_kind))
            .ok_or_else(|| Error::invalid(format!("{layer_kind} layer is missing")))?;
        if index == 0 {
            return self.happy_eyeballs_direct(timeout);
        }
        let prefix = config.chain_prefix(index)?;
        if tls_terminated {
            Ok(
                Box::pin(self.build_proxy_config_with_tls_marker(prefix, timeout, true))
                    .await?
                    .proxy,
            )
        } else {
            Ok(Box::pin(self.build_proxy_config(prefix, timeout))
                .await?
                .proxy)
        }
    }

    async fn build_standard_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        protocol: &StandardProxyPlan,
        tls: Option<&ProtocolTlsPlan>,
        http_obfs: Option<&HttpObfsPlan>,
        timeout: Duration,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let mut upstream = self.build_base_proxy(config, timeout, resolver).await?;
        if let Some(tls) = tls {
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
        if let Some(obfs) = http_obfs {
            upstream = Arc::new(doradus_protocol::http_obfs::HttpObfsProxy::new(
                upstream, &obfs.host, &obfs.port,
            )?);
        }
        build_protocol_proxy(protocol, upstream)
    }

    async fn build_generic_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        yuubinsya: Option<&YuubinsyaPlan>,
        timeout: Duration,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let mut proxy = self
            .build_base_proxy(config, timeout, resolver.clone())
            .await?;
        if config.transport == GoProxyTransport::Yuubinsya
            && config
                .layers
                .iter()
                .any(|layer| layer.kind.eq_ignore_ascii_case("quic"))
        {
            let yuubinsya = yuubinsya.ok_or_else(|| {
                Error::invalid("Yuubinsya transport did not compile a typed plan")
            })?;
            let server = resolve_fixed_endpoint(config, resolver.as_ref())
                .await?
                .ok_or_else(|| Error::invalid("QUIC transport requires a server endpoint"))?;
            proxy = Arc::new(doradus_protocol::YuubinsyaOverTransportProxy::new(
                proxy,
                doradus_protocol::yuubinsya::derive_salt(yuubinsya.password.as_bytes()),
                Endpoint::ip(doradus_core::Network::Udp, server),
                yuubinsya.socks5_prefix,
            )?);
        }
        Ok(proxy)
    }

    pub async fn build_proxy(&self, id: &str, timeout: Duration) -> Result<ProxyBuild> {
        let config = self.require_proxy_config(id)?.clone();
        // Keep the all-feature protocol assembly future off caller stacks.
        // TLS/termination plans make that future large enough to overflow the
        // default test-thread stack when selectors build several slots.
        Box::pin(self.build_proxy_config(config, timeout)).await
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

        let proxy = match plan {
            ProxyPlan::NetworkSplit => self.build_network_split_proxy(&config, timeout).await?,
            ProxyPlan::ProtocolH2 {
                transport_json,
                protocol,
            } => {
                build_protocol_h2_proxy(
                    &transport_json,
                    &protocol,
                    timeout,
                    resolver.clone(),
                    Arc::clone(&self.metrics),
                    Arc::clone(&self.happy_eyeballs),
                )
                .await?
            }
            ProxyPlan::StreamTransport {
                protocol,
                tls,
                websocket,
            } => {
                build_standard_transport_proxy(
                    &config,
                    &protocol,
                    tls.as_ref(),
                    Some(&websocket),
                    timeout,
                    resolver.clone(),
                    Arc::clone(&self.metrics),
                )
                .await?
            }
            ProxyPlan::Wireguard(wireguard) => {
                build_wireguard_proxy(
                    &wireguard,
                    timeout,
                    resolver.clone(),
                    config
                        .network_interface()
                        .or_else(|| self.socket_bind_interface.clone()),
                )
                .await?
            }
            ProxyPlan::Openvpn(openvpn) => {
                build_openvpn_proxy(
                    &openvpn,
                    timeout,
                    resolver.clone(),
                    config
                        .network_interface()
                        .or_else(|| self.socket_bind_interface.clone()),
                )
                .await?
            }
            ProxyPlan::WarpMasque(warp_masque) => {
                build_warp_masque_proxy(
                    &warp_masque,
                    timeout,
                    resolver.clone(),
                    config
                        .network_interface()
                        .or_else(|| self.socket_bind_interface.clone()),
                )
                .await?
            }
            ProxyPlan::HttpMock => {
                self.build_http_mock_proxy(&config, timeout, resolver.clone())
                    .await?
            }
            ProxyPlan::HttpTermination {
                #[cfg(feature = "http-termination")]
                plan,
            } => {
                let parent = self
                    .build_termination_parent(&config, "http_termination", timeout, false)
                    .await?;
                #[cfg(feature = "http-termination")]
                {
                    crate::proxy::http_termination::build(plan, parent, tls_terminated)?
                }
                #[cfg(not(feature = "http-termination"))]
                {
                    let _ = parent;
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "HTTP termination requires the http-termination feature",
                    ));
                }
            }
            ProxyPlan::TlsTermination {
                #[cfg(feature = "doh-tls")]
                plan,
            } => {
                let parent = self
                    .build_termination_parent(&config, "tls_termination", timeout, true)
                    .await?;
                #[cfg(feature = "doh-tls")]
                {
                    build_tls_termination_proxy(plan, parent)?
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    let _ = parent;
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "TLS termination requires the doh-tls feature",
                    ));
                }
            }
            ProxyPlan::Chain => {
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
            }
            ProxyPlan::Aead { plan, tls } => {
                build_aead_proxy(
                    &config,
                    &plan,
                    tls.as_ref(),
                    timeout,
                    resolver.clone(),
                    Arc::clone(&self.metrics),
                    Arc::clone(&self.happy_eyeballs),
                )
                .await?
            }
            ProxyPlan::Standard {
                protocol,
                tls,
                http_obfs,
            } => {
                self.build_standard_proxy(
                    &config,
                    &protocol,
                    tls.as_ref(),
                    http_obfs.as_ref(),
                    timeout,
                    resolver.clone(),
                )
                .await?
            }
            ProxyPlan::Generic { yuubinsya } => {
                self.build_generic_proxy(&config, yuubinsya.as_ref(), timeout, resolver.clone())
                    .await?
            }
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
        let proxy = if config.transport.is_stateful_tunnel() {
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
