use super::*;

fn protocol_endpoint(
    endpoint: GoBaseProxyEndpoint,
) -> doradus_protocol::proxy_factory::BaseProxyEndpoint {
    doradus_protocol::proxy_factory::BaseProxyEndpoint {
        address: endpoint.address,
        bind_interface: endpoint.bind_interface,
    }
}

pub(super) fn protocol_base_proxy_config(config: GoBaseProxyConfig) -> Result<BaseProxyConfig> {
    let kind = match config.kind {
        GoBaseProxyKind::Direct => BaseProxyKind::Direct,
        GoBaseProxyKind::Reject => BaseProxyKind::Reject,
        GoBaseProxyKind::Drop => BaseProxyKind::Drop,
        GoBaseProxyKind::Fixed { address } => BaseProxyKind::Fixed { address },
        GoBaseProxyKind::FixedMany { endpoints } => BaseProxyKind::FixedMany {
            endpoints: endpoints.into_iter().map(protocol_endpoint).collect(),
        },
        GoBaseProxyKind::Http {
            proxy,
            username,
            password,
        } => BaseProxyKind::Http {
            proxy,
            username,
            password,
        },
        GoBaseProxyKind::HttpMany {
            endpoints,
            username,
            password,
        } => BaseProxyKind::HttpMany {
            endpoints: endpoints.into_iter().map(protocol_endpoint).collect(),
            username,
            password,
        },
        GoBaseProxyKind::Socks5 {
            proxy,
            username,
            password,
        } => BaseProxyKind::Socks5 {
            proxy,
            username,
            password,
        },
        GoBaseProxyKind::Socks5Many {
            endpoints,
            username,
            password,
        } => BaseProxyKind::Socks5Many {
            endpoints: endpoints.into_iter().map(protocol_endpoint).collect(),
            username,
            password,
        },
        GoBaseProxyKind::YuubinsyaUdp {
            server,
            password,
            socks5_prefix,
        } => BaseProxyKind::YuubinsyaUdp {
            server,
            password_hash: doradus_protocol::yuubinsya::derive_salt(password.as_bytes()),
            socks5_prefix,
        },
        GoBaseProxyKind::YuubinsyaUdpMany {
            endpoints,
            password,
            socks5_prefix,
        } => BaseProxyKind::YuubinsyaUdpMany {
            endpoints: endpoints.into_iter().map(protocol_endpoint).collect(),
            password_hash: doradus_protocol::yuubinsya::derive_salt(password.as_bytes()),
            socks5_prefix,
        },
        GoBaseProxyKind::Quic {
            server,
            server_name,
            ca_certificates,
            insecure_skip_verify,
        } => BaseProxyKind::Quic {
            server,
            server_name,
            ca_certificates,
            insecure_skip_verify,
        },
        GoBaseProxyKind::QuicMany {
            endpoints,
            server_name,
            ca_certificates,
            insecure_skip_verify,
        } => BaseProxyKind::QuicMany {
            endpoints: endpoints.into_iter().map(protocol_endpoint).collect(),
            server_name,
            ca_certificates,
            insecure_skip_verify,
        },
    };
    Ok(BaseProxyConfig {
        kind,
        timeout: config.timeout,
    })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StandardProxyPlan {
    Shadowsocks {
        method: String,
        password: String,
    },
    Shadowsocksr {
        method: String,
        password: String,
        protocol: String,
        protocol_param: String,
        obfs: String,
        obfs_param: String,
    },
    Trojan {
        password: String,
    },
    Vless {
        uuid: String,
    },
    Vmess {
        uuid: String,
        security: String,
        alter_id: u32,
    },
}

impl StandardProxyPlan {
    fn compile(config: &GoProxyRuntimeConfig, protocol: StandardProtocol) -> Result<Self> {
        let layer = config
            .layers
            .iter()
            .find(|layer| layer.kind.eq_ignore_ascii_case(protocol.layer_name()))
            .ok_or_else(|| Error::invalid("proxy protocol layer is missing"))?;
        Self::compile_layer(layer, protocol)
    }

    fn compile_layer(layer: &GoProxyLayer, protocol: StandardProtocol) -> Result<Self> {
        let string = |key: &str| {
            layer
                .config
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Ok(match protocol {
            StandardProtocol::Shadowsocks => Self::Shadowsocks {
                method: string("method")
                    .ok_or_else(|| Error::invalid("Shadowsocks method is missing"))?,
                password: string("password")
                    .filter(|password| !password.is_empty())
                    .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?,
            },
            StandardProtocol::Shadowsocksr => Self::Shadowsocksr {
                method: string("method").unwrap_or_else(|| "chacha20-ietf".to_owned()),
                password: string("password").unwrap_or_default(),
                protocol: string("protocol").unwrap_or_else(|| "origin".to_owned()),
                protocol_param: string("protoparam")
                    .or_else(|| string("protocol_param"))
                    .unwrap_or_default(),
                obfs: string("obfs").unwrap_or_else(|| "plain".to_owned()),
                obfs_param: string("obfsparam")
                    .or_else(|| string("obfs_param"))
                    .unwrap_or_default(),
            },
            StandardProtocol::Trojan => Self::Trojan {
                password: string("password")
                    .filter(|password| !password.is_empty())
                    .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?,
            },
            StandardProtocol::Vless => Self::Vless {
                uuid: string("uuid").ok_or_else(|| Error::invalid("VLESS UUID is missing"))?,
            },
            StandardProtocol::Vmess => Self::Vmess {
                uuid: string("id")
                    .or_else(|| string("uuid"))
                    .ok_or_else(|| Error::invalid("VMess UUID is missing"))?,
                security: string("security").unwrap_or_else(|| "auto".to_owned()),
                alter_id: vmess_alter_id(&layer.config)?,
            },
        })
    }

    pub(super) const fn protocol(&self) -> StandardProtocol {
        match self {
            Self::Shadowsocks { .. } => StandardProtocol::Shadowsocks,
            Self::Shadowsocksr { .. } => StandardProtocol::Shadowsocksr,
            Self::Trojan { .. } => StandardProtocol::Trojan,
            Self::Vless { .. } => StandardProtocol::Vless,
            Self::Vmess { .. } => StandardProtocol::Vmess,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HttpObfsPlan {
    pub(super) host: String,
    pub(super) port: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WebSocketPlan {
    pub(super) host: String,
    pub(super) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AeadPlan {
    pub(super) password: String,
    pub(super) method: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct YuubinsyaPlan {
    pub(super) password: String,
    pub(super) udp_over_stream: bool,
    pub(super) udp_coalesce: bool,
    pub(super) socks5_prefix: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Socks5Plan {
    pub(super) user: String,
    pub(super) password: String,
    pub(super) hostname: String,
    pub(super) override_port: i32,
}

impl Socks5Plan {
    pub(super) fn compile_layer(layer: &GoProxyLayer) -> Result<Self> {
        let override_port = layer
            .config
            .get("override_port")
            .or_else(|| layer.config.get("overridePort"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        Ok(Self {
            user: layer_string(layer, "user").unwrap_or_default(),
            password: layer_string(layer, "password").unwrap_or_default(),
            hostname: layer_string(layer, "hostname").unwrap_or_default(),
            override_port: i32::try_from(override_port)
                .map_err(|_| Error::invalid("SOCKS5 override_port is out of range"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Http2Plan {
    pub(super) concurrency: usize,
    pub(super) max_streams: usize,
}

impl Http2Plan {
    pub(super) fn compile_layer(layer: &GoProxyLayer) -> Self {
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
        Self {
            concurrency,
            max_streams,
        }
    }
}

impl YuubinsyaPlan {
    pub(super) fn compile_layer(layer: &GoProxyLayer) -> Result<Self> {
        let password = layer_string(layer, "password")
            .filter(|password| !password.is_empty())
            .ok_or_else(|| Error::invalid("Yuubinsya password is empty"))?;
        Ok(Self {
            password,
            udp_over_stream: layer_bool(layer, "udp_over_stream", "udpOverStream"),
            udp_coalesce: layer_bool(layer, "udp_coalesce", "udpCoalesce"),
            socks5_prefix: layer_bool(layer, "socks5_prefix", "socks5Prefix"),
        })
    }
}

impl AeadPlan {
    pub(super) fn compile(config: &GoProxyRuntimeConfig) -> Result<Self> {
        let layer = config
            .layers
            .iter()
            .find(|layer| layer.kind.eq_ignore_ascii_case("aead"))
            .ok_or_else(|| Error::invalid("AEAD transport layer is missing"))?;
        Self::compile_layer(layer)
    }

    pub(super) fn compile_layer(layer: &GoProxyLayer) -> Result<Self> {
        let password = layer_string(layer, "password")
            .filter(|password| !password.is_empty())
            .ok_or_else(|| Error::invalid("AEAD password is empty"))?;
        let method = layer
            .config
            .get("cryptoMethod")
            .or_else(|| layer.config.get("crypto_method"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("chacha20-poly1305")
            .to_owned();
        Ok(Self { password, method })
    }
}

impl WebSocketPlan {
    pub(super) fn compile(config: &GoProxyRuntimeConfig) -> Result<Self> {
        let layer = config
            .layers
            .iter()
            .find(|layer| layer.kind.eq_ignore_ascii_case("websocket"))
            .ok_or_else(|| Error::invalid("WebSocket transport layer is missing"))?;
        Self::compile_layer(layer)
    }

    pub(super) fn compile_layer(layer: &GoProxyLayer) -> Result<Self> {
        let host = layer
            .config
            .get("host")
            .or_else(|| layer.config.get("hostname"))
            .and_then(serde_json::Value::as_str)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::invalid("WebSocket transport host is missing"))?;
        let path = layer
            .config
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("/")
            .to_owned();
        Ok(Self { host, path })
    }
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

pub(super) struct ProxyPlan {
    pub(super) kind: ProxyPlanKind,
    pub(super) standard: Option<StandardProxyPlan>,
    pub(super) http_obfs: Option<HttpObfsPlan>,
    pub(super) protocol_tls: Option<ProtocolTlsPlan>,
    pub(super) websocket: Option<WebSocketPlan>,
    pub(super) aead: Option<AeadPlan>,
    pub(super) wireguard: Option<doradus_wireguard::WireGuardConfig>,
    pub(super) warp_masque: Option<doradus_masque::WarpMasqueConfig>,
    pub(super) yuubinsya: Option<YuubinsyaPlan>,
    pub(super) h2_transport_json: Option<String>,
    #[cfg(feature = "http-termination")]
    pub(super) http_termination: Option<crate::proxy::http_termination::HttpTerminationPlan>,
    #[cfg(feature = "doh-tls")]
    pub(super) tls_termination: Option<TlsTerminationPlan>,
}

impl ProxyPlan {
    /// Normalize the wire-layer facts once before the builder starts its
    /// dispatch.  The old builder independently scanned `chain_types` for
    /// every protocol branch, which made precedence changes easy to miss and
    /// let the factory and top-level builder drift apart.
    pub(super) fn from_config(config: &GoProxyRuntimeConfig) -> Result<Self> {
        let chain_kinds = config
            .chain_types
            .iter()
            .map(|kind| kind.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let standard_protocol = match config.transport {
            doradus_store::GoProxyTransport::Shadowsocks => Some(StandardProtocol::Shadowsocks),
            doradus_store::GoProxyTransport::Shadowsocksr => Some(StandardProtocol::Shadowsocksr),
            doradus_store::GoProxyTransport::Trojan => Some(StandardProtocol::Trojan),
            doradus_store::GoProxyTransport::Vless => Some(StandardProtocol::Vless),
            doradus_store::GoProxyTransport::Vmess => Some(StandardProtocol::Vmess),
            _ => None,
        };
        let yuubinsya = if matches!(config.transport, doradus_store::GoProxyTransport::Yuubinsya) {
            config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                .map(YuubinsyaPlan::compile_layer)
                .transpose()?
        } else {
            None
        };
        let has_protocol_tls = chain_kinds.contains("tls");
        let is_chain = chain_kinds
            .iter()
            .any(|kind| matches!(kind.as_str(), "http2" | "websocket"))
            || (has_protocol_tls && standard_protocol.is_none())
            || yuubinsya.as_ref().is_some_and(|plan| plan.udp_over_stream);
        let protocol_h2 = matches!(
            config.transport,
            doradus_store::GoProxyTransport::Vless
                | doradus_store::GoProxyTransport::Vmess
                | doradus_store::GoProxyTransport::Trojan
        ) && chain_kinds.contains("http2")
            && standard_protocol
                .is_some_and(|protocol| chain_kinds.contains(protocol.layer_name()));
        let vless_websocket = matches!(config.transport, doradus_store::GoProxyTransport::Vless)
            && chain_kinds.contains("websocket")
            && chain_kinds.contains("vless")
            && chain_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "fixed" | "fixedv2" | "tls" | "websocket" | "vless"
                )
            });
        let vmess_transport = matches!(config.transport, doradus_store::GoProxyTransport::Vmess)
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
        let trojan_websocket = matches!(config.transport, doradus_store::GoProxyTransport::Trojan)
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
            doradus_store::GoProxyTransport::NetworkSplit
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
        } else if matches!(config.transport, doradus_store::GoProxyTransport::Wireguard) {
            ProxyPlanKind::Wireguard
        } else if matches!(
            config.transport,
            doradus_store::GoProxyTransport::WarpMasque
        ) {
            ProxyPlanKind::WarpMasque
        } else if matches!(config.transport, doradus_store::GoProxyTransport::HttpMock) {
            ProxyPlanKind::HttpMock
        } else if matches!(
            config.transport,
            doradus_store::GoProxyTransport::HttpTermination
        ) {
            ProxyPlanKind::HttpTermination
        } else if matches!(
            config.transport,
            doradus_store::GoProxyTransport::TlsTermination
        ) {
            ProxyPlanKind::TlsTermination
        } else if is_chain {
            ProxyPlanKind::Chain
        } else if matches!(config.transport, doradus_store::GoProxyTransport::Aead) {
            ProxyPlanKind::Aead
        } else if let Some(protocol) = standard_protocol {
            ProxyPlanKind::Standard(protocol)
        } else {
            ProxyPlanKind::Generic
        };
        let compiled_protocol = match kind {
            ProxyPlanKind::Standard(protocol) => Some(protocol),
            ProxyPlanKind::ProtocolH2 => standard_protocol,
            ProxyPlanKind::VlessWebSocket => Some(StandardProtocol::Vless),
            ProxyPlanKind::VmessTransport => Some(StandardProtocol::Vmess),
            ProxyPlanKind::TrojanWebSocket => Some(StandardProtocol::Trojan),
            _ => None,
        };
        let standard = compiled_protocol
            .map(|protocol| StandardProxyPlan::compile(config, protocol))
            .transpose()?;
        let h2_transport_json = if matches!(kind, ProxyPlanKind::ProtocolH2) {
            let protocol = standard
                .as_ref()
                .expect("HTTP/2 protocol kind must compile a protocol plan")
                .protocol()
                .layer_name();
            Some(compile_protocol_h2_transport(config, protocol)?)
        } else {
            None
        };
        let http_obfs = if matches!(kind, ProxyPlanKind::Standard(StandardProtocol::Shadowsocks)) {
            config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("obfs_http"))
                .map(|layer| {
                    Ok(HttpObfsPlan {
                        host: layer
                            .config
                            .get("host")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                            .ok_or_else(|| Error::invalid("obfs_http host is missing"))?,
                        port: layer
                            .config
                            .get("port")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                            .ok_or_else(|| Error::invalid("obfs_http port is missing"))?,
                    })
                })
                .transpose()?
        } else {
            None
        };
        let uses_compiled_stream_transport = matches!(
            kind,
            ProxyPlanKind::VlessWebSocket
                | ProxyPlanKind::VmessTransport
                | ProxyPlanKind::TrojanWebSocket
                | ProxyPlanKind::Aead
                | ProxyPlanKind::Standard(_)
        );
        let protocol_tls = if uses_compiled_stream_transport && has_protocol_tls {
            Some(ProtocolTlsPlan::compile(config)?)
        } else {
            None
        };
        let websocket = if matches!(
            kind,
            ProxyPlanKind::VlessWebSocket
                | ProxyPlanKind::VmessTransport
                | ProxyPlanKind::TrojanWebSocket
        ) && chain_kinds.contains("websocket")
        {
            Some(WebSocketPlan::compile(config)?)
        } else {
            None
        };
        let aead = if matches!(kind, ProxyPlanKind::Aead) {
            Some(AeadPlan::compile(config)?)
        } else {
            None
        };
        let wireguard = if matches!(kind, ProxyPlanKind::Wireguard) {
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("wireguard"))
                .ok_or_else(|| Error::invalid("WireGuard protocol layer is missing"))?;
            Some(compile_wireguard_config(layer)?)
        } else {
            None
        };
        let warp_masque = if matches!(kind, ProxyPlanKind::WarpMasque) {
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("warp_masque"))
                .ok_or_else(|| Error::invalid("WARP MASQUE protocol layer is missing"))?;
            Some(compile_warp_masque_config(layer)?)
        } else {
            None
        };
        #[cfg(feature = "http-termination")]
        let http_termination = if matches!(kind, ProxyPlanKind::HttpTermination) {
            Some(crate::proxy::http_termination::HttpTerminationPlan::compile(config)?)
        } else {
            None
        };
        #[cfg(feature = "doh-tls")]
        let tls_termination = if matches!(kind, ProxyPlanKind::TlsTermination) {
            Some(TlsTerminationPlan::compile(config)?)
        } else {
            None
        };
        Ok(Self {
            kind,
            standard,
            http_obfs,
            protocol_tls,
            websocket,
            aead,
            wireguard,
            warp_masque,
            yuubinsya,
            h2_transport_json,
            #[cfg(feature = "http-termination")]
            http_termination,
            #[cfg(feature = "doh-tls")]
            tls_termination,
        })
    }
}

fn compile_protocol_h2_transport(config: &GoProxyRuntimeConfig, protocol: &str) -> Result<String> {
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
    Ok(node.to_string())
}

pub(super) fn compile_wireguard_config(
    layer: &GoProxyLayer,
) -> Result<doradus_wireguard::WireGuardConfig> {
    serde_json::from_value(layer.config.clone()).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard node configuration: {error}"),
        )
    })
}

pub(super) fn compile_warp_masque_config(
    layer: &GoProxyLayer,
) -> Result<doradus_masque::WarpMasqueConfig> {
    serde_json::from_value(layer.config.clone()).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WARP MASQUE node configuration: {error}"),
        )
    })
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
