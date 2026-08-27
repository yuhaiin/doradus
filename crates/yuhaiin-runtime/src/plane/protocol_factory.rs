use super::*;

#[path = "protocol_tls.rs"]
mod protocol_tls;
pub(super) use protocol_tls::*;

pub(super) fn hosts_context_value(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
}

pub(super) fn network_split_branch(
    value: Option<&serde_json::Value>,
) -> Result<Option<GoProxyLayer>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| Error::invalid("network_split branch must be an object"))?;
    let kind = object
        .get("type")
        .or_else(|| object.get("protocol"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("network_split branch requires a protocol type"))?;
    let config = object
        .get(kind)
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(object.clone()));
    Ok(Some(GoProxyLayer {
        kind: kind.to_owned(),
        config,
    }))
}

pub(super) fn layer_string(layer: &GoProxyLayer, key: &str) -> Option<String> {
    layer
        .config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

pub(super) fn layer_bool(layer: &GoProxyLayer, snake: &str, camel: &str) -> bool {
    layer
        .config
        .get(snake)
        .or_else(|| layer.config.get(camel))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StandardProtocol {
    Shadowsocks,
    Shadowsocksr,
    Trojan,
    Vless,
    Vmess,
}

impl StandardProtocol {
    pub(super) const fn layer_name(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Shadowsocksr => "shadowsocksr",
            Self::Trojan => "trojan",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProxyPlanKind {
    NetworkSplit,
    ProtocolH2,
    VlessWebSocket,
    VmessTransport,
    TrojanWebSocket,
    Wireguard,
    WarpMasque,
    HttpMock,
    HttpTermination,
    TlsTermination,
    Chain,
    Aead,
    Standard(StandardProtocol),
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProxyPlan {
    pub(super) kind: ProxyPlanKind,
    pub(super) has_protocol_tls: bool,
}

impl ProxyPlan {
    /// Normalize the wire-layer facts once before the builder starts its
    /// dispatch.  The old builder independently scanned `chain_types` for
    /// every protocol branch, which made precedence changes easy to miss and
    /// let the factory and top-level builder drift apart.
    pub(super) fn from_config(config: &GoProxyRuntimeConfig) -> Self {
        let chain_kinds = config
            .chain_types
            .iter()
            .map(|kind| kind.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let standard_protocol = match config.transport {
            yuhaiin_store::GoProxyTransport::Shadowsocks => Some(StandardProtocol::Shadowsocks),
            yuhaiin_store::GoProxyTransport::Shadowsocksr => Some(StandardProtocol::Shadowsocksr),
            yuhaiin_store::GoProxyTransport::Trojan => Some(StandardProtocol::Trojan),
            yuhaiin_store::GoProxyTransport::Vless => Some(StandardProtocol::Vless),
            yuhaiin_store::GoProxyTransport::Vmess => Some(StandardProtocol::Vmess),
            _ => None,
        };
        let has_protocol_tls = chain_kinds.contains("tls");
        let is_chain = chain_kinds
            .iter()
            .any(|kind| matches!(kind.as_str(), "http2" | "websocket"))
            || (has_protocol_tls && standard_protocol.is_none())
            || (chain_kinds.contains("yuubinsya")
                && config
                    .layers
                    .iter()
                    .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                    .and_then(|layer| layer.config.get("udp_over_stream"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false));
        let protocol_h2 = matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Vless
                | yuhaiin_store::GoProxyTransport::Vmess
                | yuhaiin_store::GoProxyTransport::Trojan
        ) && chain_kinds.contains("http2")
            && standard_protocol
                .is_some_and(|protocol| chain_kinds.contains(protocol.layer_name()));
        let vless_websocket = matches!(config.transport, yuhaiin_store::GoProxyTransport::Vless)
            && chain_kinds.contains("websocket")
            && chain_kinds.contains("vless")
            && chain_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "fixed" | "fixedv2" | "tls" | "websocket" | "vless"
                )
            });
        let vmess_transport = matches!(config.transport, yuhaiin_store::GoProxyTransport::Vmess)
            && chain_kinds.contains("vmess")
            && chain_kinds
                .iter()
                .any(|kind| matches!(kind.as_str(), "tls" | "websocket"))
            && chain_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "fixed" | "fixedv2" | "tls" | "websocket" | "vmess"
                )
            });
        let trojan_websocket = matches!(config.transport, yuhaiin_store::GoProxyTransport::Trojan)
            && chain_kinds.contains("websocket")
            && chain_kinds.contains("trojan")
            && chain_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "fixed" | "fixedv2" | "tls" | "websocket" | "trojan"
                )
            });
        let kind = if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::NetworkSplit
        ) {
            ProxyPlanKind::NetworkSplit
        } else if protocol_h2 {
            ProxyPlanKind::ProtocolH2
        } else if vless_websocket {
            ProxyPlanKind::VlessWebSocket
        } else if vmess_transport {
            ProxyPlanKind::VmessTransport
        } else if trojan_websocket {
            ProxyPlanKind::TrojanWebSocket
        } else if matches!(config.transport, yuhaiin_store::GoProxyTransport::Wireguard) {
            ProxyPlanKind::Wireguard
        } else if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::WarpMasque
        ) {
            ProxyPlanKind::WarpMasque
        } else if matches!(config.transport, yuhaiin_store::GoProxyTransport::HttpMock) {
            ProxyPlanKind::HttpMock
        } else if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::HttpTermination
        ) {
            ProxyPlanKind::HttpTermination
        } else if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::TlsTermination
        ) {
            ProxyPlanKind::TlsTermination
        } else if is_chain {
            ProxyPlanKind::Chain
        } else if matches!(config.transport, yuhaiin_store::GoProxyTransport::Aead) {
            ProxyPlanKind::Aead
        } else if let Some(protocol) = standard_protocol {
            ProxyPlanKind::Standard(protocol)
        } else {
            ProxyPlanKind::Generic
        };
        Self {
            kind,
            has_protocol_tls,
        }
    }
}

pub(super) async fn build_stream_transport_upstream(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver::AsyncIpResolver>,
    protocol_name: &str,
) -> Result<Arc<dyn AsyncProxy>> {
    #[cfg(feature = "doh-tls")]
    let _ = protocol_name;

    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let mut upstream: Arc<dyn AsyncProxy> = base.build()?;
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
    {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(config, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("{protocol_name} TLS transport requires the doh-tls feature"),
            ));
        }
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"))
    {
        upstream = build_protocol_websocket_proxy(config, upstream)?;
    }
    Ok(upstream)
}

pub(super) async fn build_wireguard_proxy(
    layer: &GoProxyLayer,
    timeout: Duration,
    resolver: Arc<dyn AsyncIpResolver>,
    bind_interface: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    let wireguard: yuhaiin_wireguard::WireGuardConfig =
        serde_json::from_value(layer.config.clone()).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid WireGuard node configuration: {error}"),
            )
        })?;
    Ok(Arc::new(
        yuhaiin_wireguard::build_proxy_with_interface_and_resolver(
            wireguard,
            timeout,
            bind_interface.as_deref(),
            Some(resolver),
        )
        .await?,
    ))
}

pub(super) async fn build_warp_masque_proxy(
    layer: &GoProxyLayer,
    timeout: Duration,
    resolver: Arc<dyn AsyncIpResolver>,
    bind_interface: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    let warp: yuhaiin_masque::WarpMasqueConfig = serde_json::from_value(layer.config.clone())
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid WARP MASQUE node configuration: {error}"),
            )
        })?;
    Ok(Arc::new(
        yuhaiin_masque::build_proxy_with_interface_and_resolver(
            warp,
            timeout,
            bind_interface.as_deref(),
            Some(resolver),
        )
        .await?,
    ))
}

pub(super) async fn build_protocol_h2_proxy(
    config: &GoProxyRuntimeConfig,
    _timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let protocol = match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => "vless",
        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
        _ => {
            return Err(Error::invalid(
                "HTTP/2 protocol transport requires VLESS, VMess, or Trojan",
            ));
        }
    };
    let mut node: serde_json::Value =
        serde_json::from_slice(&config.data_json).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("proxy node chain JSON is invalid: {error}"),
            )
        })?;
    let chain = node
        .get_mut("chain")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| Error::invalid("HTTP/2 protocol node requires a chain array"))?;
    let original_len = chain.len();
    chain.retain(|layer| {
        !layer
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case(protocol))
    });
    if chain.len() == original_len {
        return Err(Error::invalid(format!(
            "HTTP/2 protocol node is missing its {protocol} chain layer"
        )));
    }

    let upstream = Arc::new(ChainProxy::from_go_json_transport_with_resolver(
        &node.to_string(),
        resolver,
    )?) as Arc<dyn AsyncProxy>;
    build_protocol_proxy(config, upstream)
}

pub(super) fn build_protocol_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    let protocol = match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => "vless",
        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
        _ => {
            return Err(Error::invalid(
                "protocol framing requires VLESS, VMess, or Trojan",
            ));
        }
    };
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case(protocol))
        .ok_or_else(|| Error::invalid(format!("{protocol} protocol layer is missing")))?;
    match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => {
            let uuid = layer
                .config
                .get("uuid")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
            Ok(Arc::new(yuhaiin_protocol::vless::VlessProxy::new(
                upstream, uuid,
            )?))
        }
        yuhaiin_store::GoProxyTransport::Vmess => {
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
            Ok(Arc::new(yuhaiin_protocol::vmess::VmessProxy::new(
                upstream, uuid, security, alter_id,
            )?))
        }
        yuhaiin_store::GoProxyTransport::Trojan => {
            let password = layer
                .config
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| !password.is_empty())
                .ok_or_else(|| Error::invalid("Trojan password is empty"))?;
            Ok(Arc::new(yuhaiin_protocol::trojan::TrojanProxy::new(
                upstream, password,
            )))
        }
        _ => unreachable!("protocol kind was validated above"),
    }
}

pub(super) async fn build_vless_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "VLESS").await?;
    build_protocol_proxy(config, upstream)
}

pub(super) async fn build_vmess_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "VMess").await?;
    build_protocol_proxy(config, upstream)
}

pub(super) async fn build_trojan_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "Trojan").await?;
    build_protocol_proxy(config, upstream)
}

pub(super) fn vmess_alter_id(config: &serde_json::Value) -> Result<u32> {
    let Some(value) = config.get("aid").or_else(|| config.get("alter_id")) else {
        return Ok(0);
    };
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).map_err(|_| Error::invalid("VMess alter_id is out of range"));
    }
    value
        .as_str()
        .ok_or_else(|| Error::invalid("VMess alter_id must be a string or integer"))?
        .parse::<u32>()
        .map_err(|error| Error::invalid(format!("VMess alter_id is invalid: {error}")))
}

#[cfg(feature = "websocket")]
pub(super) fn build_protocol_websocket_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("websocket"))
        .ok_or_else(|| Error::invalid("WebSocket transport layer is missing"))?;
    let host = layer
        .config
        .get("host")
        .or_else(|| layer.config.get("hostname"))
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| Error::invalid("WebSocket transport host is missing"))?;
    let path = layer
        .config
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("/");
    Ok(Arc::new(yuhaiin_protocol::websocket::WebSocketProxy::new(
        upstream, host, path,
    )?))
}

#[cfg(not(feature = "websocket"))]
pub(super) fn build_protocol_websocket_proxy(
    _config: &GoProxyRuntimeConfig,
    _upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "VLESS WebSocket transport requires the websocket feature",
    ))
}
