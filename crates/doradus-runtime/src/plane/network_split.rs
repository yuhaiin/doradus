use super::*;

/// Go's `network_split` point keeps one already-built parent proxy and
/// selects an independent wrapper for TCP and UDP. The selection happens at
/// the common async seam so every inbound, including TUN, gets the same semantics.
impl RuntimeSnapshot {
    pub(super) async fn build_network_split_proxy(
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
        let udp_server = resolve_fixed_endpoint(&parent_config, proxy_resolver.as_ref())
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
                Ok(
                    compile_base_proxy_config(&child, timeout, resolver.as_ref())
                        .await?
                        .build_with_metrics(Arc::clone(&self.metrics))?,
                )
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
                let transport = GoProxyTransport::parse(&kind);
                let child = GoProxyRuntimeConfig::single_layer(layer, transport);
                let ProxyPlan::Standard { protocol, .. } = ProxyPlan::from_config(&child)? else {
                    return Err(Error::invalid(
                        "network_split protocol layer did not compile as a standard protocol",
                    ));
                };
                build_protocol_proxy(&protocol, parent)
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
            "openvpn" | "open_vpn" | "ovpn" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Openvpn);
                let openvpn = compile_openvpn_config(layer)?;
                let resolver = self.dns_resolver_for_route_mode(RouteMode::Direct)?;
                build_openvpn_proxy(
                    &openvpn,
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
}
