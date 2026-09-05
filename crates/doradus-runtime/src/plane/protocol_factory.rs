use super::*;

pub(super) fn hosts_context_value(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
}

pub(super) async fn build_stream_transport_upstream(
    config: &GoProxyRuntimeConfig,
    protocol_tls: Option<&ProtocolTlsPlan>,
    websocket: Option<&WebSocketPlan>,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    protocol_name: &str,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
) -> Result<Arc<dyn AsyncProxy>> {
    #[cfg(feature = "doh-tls")]
    let _ = protocol_name;

    let base = protocol_base_proxy_config(
        config
            .to_base_proxy_config_with_resolver(timeout, resolver)
            .await?,
    )?;
    let mut upstream: Arc<dyn AsyncProxy> = base.build_with_metrics(metrics)?;
    if let Some(tls) = protocol_tls {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(tls, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("{protocol_name} TLS transport requires the doh-tls feature"),
            ));
        }
    }
    if let Some(websocket) = websocket {
        upstream = build_protocol_websocket_proxy(websocket, upstream)?;
    }
    Ok(upstream)
}

pub(super) async fn build_wireguard_proxy(
    wireguard: &doradus_wireguard::WireGuardConfig,
    timeout: Duration,
    resolver: Arc<dyn AsyncIpResolver>,
    bind_interface: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    Ok(Arc::new(
        doradus_wireguard::build_proxy_with_interface_and_resolver(
            wireguard.clone(),
            timeout,
            bind_interface.as_deref(),
            Some(resolver),
        )
        .await?,
    ))
}

pub(super) async fn build_warp_masque_proxy(
    warp: &doradus_masque::WarpMasqueConfig,
    timeout: Duration,
    resolver: Arc<dyn AsyncIpResolver>,
    bind_interface: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    Ok(Arc::new(
        doradus_masque::build_proxy_with_interface_and_resolver(
            warp.clone(),
            timeout,
            bind_interface.as_deref(),
            Some(resolver),
        )
        .await?,
    ))
}

pub(super) async fn build_protocol_h2_proxy(
    transport_json: &str,
    protocol_plan: &StandardProxyPlan,
    _timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
    dialer: Arc<doradus_core::network::HappyEyeballsV2Dialer>,
) -> Result<Arc<dyn AsyncProxy>> {
    if !matches!(
        protocol_plan,
        StandardProxyPlan::Vless { .. }
            | StandardProxyPlan::Vmess { .. }
            | StandardProxyPlan::Trojan { .. }
    ) {
        return Err(Error::invalid(
            "HTTP/2 protocol transport requires VLESS, VMess, or Trojan",
        ));
    }
    let upstream = Arc::new(
        ChainProxy::from_go_json_transport_with_resolver_and_metrics_and_dialer(
            transport_json,
            resolver,
            metrics,
            dialer,
        )?,
    ) as Arc<dyn AsyncProxy>;
    build_protocol_proxy(protocol_plan, upstream)
}

pub(super) fn build_protocol_proxy(
    plan: &StandardProxyPlan,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    match plan {
        StandardProxyPlan::Shadowsocks { method, password } => Ok(Arc::new(
            doradus_protocol::shadowsocks::ShadowsocksProxy::new(upstream, method, password)?,
        )),
        StandardProxyPlan::Shadowsocksr {
            method,
            password,
            protocol,
            protocol_param,
            obfs,
            obfs_param,
        } => Ok(Arc::new(
            doradus_protocol::shadowsocksr::ShadowsocksrProxy::new(
                upstream,
                method,
                password,
                protocol,
                protocol_param,
                obfs,
                obfs_param,
            )?,
        )),
        StandardProxyPlan::Trojan { password } => Ok(Arc::new(
            doradus_protocol::trojan::TrojanProxy::new(upstream, password),
        )),
        StandardProxyPlan::Vless { uuid } => Ok(Arc::new(
            doradus_protocol::vless::VlessProxy::new(upstream, uuid)?,
        )),
        StandardProxyPlan::Vmess {
            uuid,
            security,
            alter_id,
        } => Ok(Arc::new(doradus_protocol::vmess::VmessProxy::new(
            upstream, uuid, security, *alter_id,
        )?)),
    }
}

pub(super) async fn build_vless_transport_proxy(
    config: &GoProxyRuntimeConfig,
    protocol_plan: &StandardProxyPlan,
    protocol_tls: Option<&ProtocolTlsPlan>,
    websocket: Option<&WebSocketPlan>,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(
        config,
        protocol_tls,
        websocket,
        timeout,
        resolver,
        "VLESS",
        metrics,
    )
    .await?;
    build_protocol_proxy(protocol_plan, upstream)
}

pub(super) async fn build_vmess_transport_proxy(
    config: &GoProxyRuntimeConfig,
    protocol_plan: &StandardProxyPlan,
    protocol_tls: Option<&ProtocolTlsPlan>,
    websocket: Option<&WebSocketPlan>,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(
        config,
        protocol_tls,
        websocket,
        timeout,
        resolver,
        "VMess",
        metrics,
    )
    .await?;
    build_protocol_proxy(protocol_plan, upstream)
}

pub(super) async fn build_trojan_transport_proxy(
    config: &GoProxyRuntimeConfig,
    protocol_plan: &StandardProxyPlan,
    protocol_tls: Option<&ProtocolTlsPlan>,
    websocket: Option<&WebSocketPlan>,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(
        config,
        protocol_tls,
        websocket,
        timeout,
        resolver,
        "Trojan",
        metrics,
    )
    .await?;
    build_protocol_proxy(protocol_plan, upstream)
}

#[cfg(feature = "websocket")]
pub(super) fn build_protocol_websocket_proxy(
    plan: &WebSocketPlan,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    Ok(Arc::new(doradus_protocol::websocket::WebSocketProxy::new(
        upstream, &plan.host, &plan.path,
    )?))
}

#[cfg(not(feature = "websocket"))]
pub(super) fn build_protocol_websocket_proxy(
    _plan: &WebSocketPlan,
    _upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "VLESS WebSocket transport requires the websocket feature",
    ))
}
