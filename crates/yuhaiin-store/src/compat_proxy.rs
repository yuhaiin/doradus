//! Go `nodes_v2` protocol-chain compatibility and async runtime snapshots.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::{DomainName, Error, ErrorKind, Result};
use yuhaiin_protocol::proxy_factory::{BaseProxyConfig, BaseProxyEndpoint, BaseProxyKind};

use crate::GoNodeRecord;

/// One ordered Go protocol layer. The payload is the object stored under the
/// layer's tagged key (`fixed`, `socks5`, `yuubinsya`, ...), so an application
/// runtime can construct the layer without reparsing the whole node JSON.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoProxyLayer {
    pub kind: String,
    pub config: serde_json::Value,
}

impl Serialize for GoProxyLayer {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::json!({
            "kind": self.kind,
            "config": redact_config(&self.config),
        })
        .serialize(serializer)
    }
}

/// Transport kinds understood by the first Rust runtime builder. TLS and
/// HTTP/2 remain explicit layers; they are not mistaken for the base proxy
/// when a chain also contains fixed/socks5/yuubinsya.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoProxyTransport {
    Direct,
    Reject,
    Drop,
    Fixed,
    HttpMock,
    HttpProxy,
    Socks5,
    Shadowsocks,
    Shadowsocksr,
    Trojan,
    Vless,
    Vmess,
    Yuubinsya,
    Wireguard,
    Aead,
    NetworkSplit,
    Tls,
    TlsTermination,
    HttpTermination,
    Http2,
    Unknown { name: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoProxyRuntimeConfig {
    pub id: String,
    pub name: String,
    pub group_name: String,
    pub origin: String,
    pub enabled: bool,
    pub chain_types: Vec<String>,
    pub layers: Vec<GoProxyLayer>,
    pub transport: GoProxyTransport,
    /// The original bytes remain available internally for fields not yet
    /// modeled by the Rust runtime and for lossless write-back. They are not
    /// serialized into HTTP responses because the payload may contain secrets.
    #[serde(skip)]
    pub data_json: Vec<u8>,
}

impl GoProxyRuntimeConfig {
    /// Build an internal one-layer view for a protocol branch that wraps an
    /// already-constructed parent proxy.  It is not exposed through the HTTP
    /// API; the original node JSON remains the persisted source of truth.
    pub fn single_layer(layer: &GoProxyLayer, transport: GoProxyTransport) -> Self {
        let mut node = serde_json::Map::new();
        node.insert("type".to_owned(), Value::String(layer.kind.clone()));
        node.insert(layer.kind.clone(), layer.config.clone());
        Self {
            id: format!("network-split-{}", layer.kind),
            name: layer.kind.clone(),
            group_name: String::new(),
            origin: "runtime".to_owned(),
            enabled: true,
            chain_types: vec![layer.kind.clone()],
            layers: vec![layer.clone()],
            transport,
            data_json: serde_json::to_vec(&serde_json::json!({
                "chain": [Value::Object(node)]
            }))
            .unwrap_or_default(),
        }
    }

    /// Return the node-level interface requested by Go's Direct/Fixed
    /// contracts.  It is intentionally derived from the preserved layer JSON
    /// instead of being added to the HTTP-facing runtime struct: unknown Go
    /// fields remain lossless and the existing API shape stays unchanged.
    pub fn network_interface(&self) -> Option<String> {
        self.layers
            .iter()
            .filter(|layer| {
                matches!(
                    layer.kind.to_ascii_lowercase().as_str(),
                    "direct" | "fixed" | "simple" | "fixedv2"
                )
            })
            .find_map(|layer| network_interface_from_value(&layer.config))
            .or_else(|| {
                serde_json::from_slice::<Value>(&self.data_json)
                    .ok()
                    .and_then(|value| network_interface_from_value(&value))
            })
    }

    /// Return the chain prefix before a Go `network_split` point.
    ///
    /// Go folds protocol points from left to right and passes the already
    /// built proxy into the split point.  Keeping this operation in the
    /// compatibility layer prevents runtime builders from reimplementing
    /// chain JSON slicing and transport selection independently.
    pub fn chain_prefix(&self, prefix_len: usize) -> Result<Self> {
        if prefix_len > self.layers.len() {
            return Err(Error::invalid("proxy chain prefix exceeds layer count"));
        }
        let layers = self.layers[..prefix_len].to_vec();
        let chain_types: Vec<String> = layers.iter().map(|layer| layer.kind.clone()).collect();
        let data_json = chain_prefix_json(&self.data_json, &layers)?;
        let transport = select_proxy_transport(&chain_types, &layers);
        Ok(Self {
            id: self.id.clone(),
            name: self.name.clone(),
            group_name: self.group_name.clone(),
            origin: self.origin.clone(),
            enabled: self.enabled,
            chain_types,
            layers,
            transport,
            data_json,
        })
    }
}

fn chain_prefix_json(data_json: &[u8], layers: &[GoProxyLayer]) -> Result<Vec<u8>> {
    let mut value = if data_json.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(data_json).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("proxy chain JSON is invalid while slicing prefix: {error}"),
            )
        })?
    };
    let chain = layers
        .iter()
        .map(|layer| {
            let mut node = serde_json::Map::new();
            node.insert("type".to_owned(), Value::String(layer.kind.clone()));
            node.insert(layer.kind.clone(), layer.config.clone());
            Value::Object(node)
        })
        .collect();
    if let Some(object) = value.as_object_mut() {
        object.insert("chain".to_owned(), Value::Array(chain));
    } else {
        value = serde_json::json!({ "chain": chain });
    }
    serde_json::to_vec(&value).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("encode proxy chain prefix failed: {error}"),
        )
    })
}

impl GoNodeRecord {
    pub fn to_proxy_runtime_config(&self) -> Result<GoProxyRuntimeConfig> {
        let chain_types: Vec<String> =
            serde_json::from_slice(&self.chain_types_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("node {} has invalid chain_types_json: {error}", self.id),
                )
            })?;
        if chain_types.iter().any(|value| value.trim().is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("node {} has an empty chain protocol type", self.id),
            ));
        }

        let payload: serde_json::Value =
            serde_json::from_slice(&self.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("node {} has invalid data_json: {error}", self.id),
                )
            })?;
        let layers = protocol_layers_from_payload(&payload, &chain_types);
        let transport = select_proxy_transport(&chain_types, &layers);

        Ok(GoProxyRuntimeConfig {
            id: self.id.clone(),
            name: self.name.clone(),
            group_name: self.group_name.clone(),
            origin: self.origin.clone(),
            enabled: self.enabled,
            chain_types,
            layers,
            transport,
            data_json: self.data_json.clone(),
        })
    }
}

fn protocol_layers_from_payload(
    payload: &serde_json::Value,
    chain_types: &[String],
) -> Vec<GoProxyLayer> {
    if let Some(chain) = payload.get("chain").and_then(serde_json::Value::as_array) {
        return chain
            .iter()
            .filter_map(|node| {
                let kind = node.get("type")?.as_str()?.to_owned();
                let config = node.get(&kind).cloned().unwrap_or(serde_json::Value::Null);
                Some(GoProxyLayer { kind, config })
            })
            .collect();
    }

    let kind = payload
        .get("protocol")
        .or_else(|| payload.get("type"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| chain_types.first().map(String::as_str));
    kind.map(|kind| {
        vec![GoProxyLayer {
            kind: kind.to_owned(),
            config: payload.clone(),
        }]
    })
    .unwrap_or_default()
}

fn redact_config(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    let redacted = lower.contains("password")
                        || lower.contains("secret")
                        || lower.contains("token")
                        || lower.contains("private_key");
                    (
                        key.clone(),
                        if redacted {
                            Value::String("***".to_owned())
                        } else {
                            redact_config(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_config).collect()),
        value => value.clone(),
    }
}

pub(crate) fn network_interface_field(value: &Value) -> Option<String> {
    for key in ["network_interface", "networkInterface"] {
        if let Some(interface) = value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|interface| !interface.is_empty())
        {
            return Some(interface.to_owned());
        }
    }
    None
}

fn network_interface_from_value(value: &Value) -> Option<String> {
    if let Some(interface) = network_interface_field(value) {
        return Some(interface);
    }

    value
        .get("addresses")
        .and_then(Value::as_array)
        .and_then(|addresses| addresses.iter().find_map(network_interface_from_value))
}

fn parse_proxy_transport(value: &str) -> GoProxyTransport {
    match value.trim().to_ascii_lowercase().as_str() {
        "direct" => GoProxyTransport::Direct,
        "reject" | "block" => GoProxyTransport::Reject,
        "drop" => GoProxyTransport::Drop,
        "fixed" | "simple" | "fixedv2" => GoProxyTransport::Fixed,
        "http_mock" | "httpmock" => GoProxyTransport::HttpMock,
        "http" | "http_proxy" => GoProxyTransport::HttpProxy,
        "socks5" => GoProxyTransport::Socks5,
        "shadowsocks" => GoProxyTransport::Shadowsocks,
        "shadowsocksr" | "ssr" => GoProxyTransport::Shadowsocksr,
        "trojan" => GoProxyTransport::Trojan,
        "vless" => GoProxyTransport::Vless,
        "vmess" => GoProxyTransport::Vmess,
        "yuubinsya" => GoProxyTransport::Yuubinsya,
        "wireguard" | "wire_guard" | "wg" => GoProxyTransport::Wireguard,
        "aead" => GoProxyTransport::Aead,
        // Go registers bootstrap_dns_warp as a no-op wrapper around the
        // already-built proxy. At node level the zero/direct proxy is the
        // equivalent base; network_split handles the parent-preserving case
        // in the runtime builder.
        "bootstrap_dns_warp" | "bootstrapdnswarp" | "proxy" => GoProxyTransport::Direct,
        "network_split" | "networksplit" => GoProxyTransport::NetworkSplit,
        "tls" => GoProxyTransport::Tls,
        "tls_termination" | "tlstermination" => GoProxyTransport::TlsTermination,
        "http_termination" | "httptermination" => GoProxyTransport::HttpTermination,
        "http2" => GoProxyTransport::Http2,
        other => GoProxyTransport::Unknown {
            name: other.to_owned(),
        },
    }
}

fn select_proxy_transport(chain_types: &[String], layers: &[GoProxyLayer]) -> GoProxyTransport {
    let all_types = chain_types
        .iter()
        .map(String::as_str)
        .chain(layers.iter().map(|layer| layer.kind.as_str()))
        .collect::<Vec<_>>();
    // Go registers `none` as a no-op point. A node containing only that point
    // therefore starts from the zero/direct proxy instead of being rejected
    // as an unknown transport. Keep mixed future chains unknown so this
    // compatibility rule cannot silently discard a protocol we do not know.
    if !all_types.is_empty()
        && all_types
            .iter()
            .all(|kind| kind.eq_ignore_ascii_case("none"))
    {
        return GoProxyTransport::Direct;
    }
    // Prefer the last transparent termination layer. Go folds contract points
    // from left to right, so the last one is the outer wrapper when a node
    // combines TLS and HTTP termination.
    if let Some(layer) = layers.iter().rev().find(|layer| {
        layer.kind.eq_ignore_ascii_case("http_termination")
            || layer.kind.eq_ignore_ascii_case("tls_termination")
    }) {
        return parse_proxy_transport(&layer.kind);
    }
    // The outer protocol is the effective runtime proxy: HTTP/SOCKS5 wraps a
    // fixed dialer, and Yuubinsya wraps the full fixed/TLS/HTTP2 chain.
    for preferred in [
        "http_mock",
        "network_split",
        "tls_termination",
        "http_termination",
        "yuubinsya",
        "wireguard",
        "aead",
        "socks5",
        "vmess",
        "vless",
        "shadowsocksr",
        "shadowsocks",
        "trojan",
        "http",
        "http_proxy",
        "reject",
        "drop",
        "block",
        "fixed",
        "simple",
        "fixedv2",
        "direct",
    ] {
        if let Some(kind) = all_types
            .iter()
            .find(|kind| kind.eq_ignore_ascii_case(preferred))
        {
            return parse_proxy_transport(kind);
        }
    }
    all_types
        .iter()
        .filter(|kind| !kind.eq_ignore_ascii_case("none"))
        .map(|kind| parse_proxy_transport(kind))
        .find(|transport| !matches!(transport, GoProxyTransport::Unknown { .. }))
        .unwrap_or_else(|| GoProxyTransport::Unknown {
            name: all_types
                .iter()
                .find(|kind| !kind.eq_ignore_ascii_case("none"))
                .copied()
                .or_else(|| all_types.first().copied())
                .unwrap_or("unknown")
                .to_owned(),
        })
}
impl GoProxyRuntimeConfig {
    /// Resolve the first fixed endpoint used by this node, if it has one.
    ///
    /// Runtime observability uses this before opening a flow to determine the
    /// actual socket destination for fixed/proxy/chain nodes.  It deliberately
    /// shares the same endpoint parser and injected resolver as proxy build,
    /// instead of introducing a second JSON interpretation in the runtime.
    pub async fn resolved_fixed_endpoint(
        &self,
        resolver: &dyn AsyncIpResolver,
    ) -> Result<Option<SocketAddr>> {
        let Some(endpoint) = self.fixed_endpoints()?.into_iter().next() else {
            return Ok(None);
        };
        Ok(resolve_endpoints(&endpoint, resolver)
            .await?
            .into_iter()
            .next())
    }

    /// Convert a Go node whose base transport is implemented by core into the
    /// core factory input. Chain transports remain explicit unsupported values
    /// here and must go through `yuhaiin-chain::parse_go_node` instead.
    pub fn to_base_proxy_config(&self, timeout: Duration) -> Result<BaseProxyConfig> {
        self.ensure_base_transport()?;
        let endpoints = self
            .fixed_endpoints()?
            .into_iter()
            .map(|endpoint| {
                Ok(BaseProxyEndpoint {
                    address: resolve_socket_addr(&endpoint.text())?,
                    bind_interface: endpoint.bind_interface,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(BaseProxyConfig {
            kind: self.base_proxy_kind(endpoints)?,
            timeout,
        })
    }

    /// Build the same core proxy using the application's configured DNS
    /// policy instead of the process resolver. The returned config remains the
    /// existing core model; only endpoint resolution is injected here.
    pub async fn to_base_proxy_config_with_resolver(
        &self,
        timeout: Duration,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<BaseProxyConfig> {
        self.ensure_base_transport()?;
        let mut endpoints = Vec::new();
        for endpoint in self.fixed_endpoints()? {
            for address in resolve_endpoints(&endpoint, resolver.as_ref()).await? {
                endpoints.push(BaseProxyEndpoint {
                    address,
                    bind_interface: endpoint.bind_interface.clone(),
                });
            }
        }
        Ok(BaseProxyConfig {
            kind: self.base_proxy_kind(endpoints)?,
            timeout,
        })
    }

    fn ensure_base_transport(&self) -> Result<()> {
        if self.chain_types.iter().any(|kind| {
            matches!(kind.to_ascii_lowercase().as_str(), "http2")
                || (kind.eq_ignore_ascii_case("websocket")
                    && !matches!(
                        self.transport,
                        GoProxyTransport::Trojan
                            | GoProxyTransport::Vless
                            | GoProxyTransport::Vmess
                    ))
                || (kind.eq_ignore_ascii_case("tls")
                    && !matches!(
                        self.transport,
                        GoProxyTransport::Trojan
                            | GoProxyTransport::Shadowsocks
                            | GoProxyTransport::Shadowsocksr
                            | GoProxyTransport::Vless
                            | GoProxyTransport::Vmess
                    ))
                || kind.eq_ignore_ascii_case("http_termination")
                || kind.eq_ignore_ascii_case("tls_termination")
        }) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Go TLS/HTTP2/WebSocket chain requires yuhaiin-chain runtime construction",
            ));
        }
        if self
            .chain_types
            .iter()
            .any(|kind| kind.eq_ignore_ascii_case("yuubinsya"))
        {
            let config = layer_config(&self.layers, "yuubinsya")?;
            if config
                .get("udp_over_stream")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "Yuubinsya UDP-over-stream requires yuhaiin-chain runtime construction",
                ));
            }
        }
        Ok(())
    }

    fn fixed_endpoints(&self) -> Result<Vec<ProxyEndpoint>> {
        match &self.transport {
            GoProxyTransport::Fixed
            | GoProxyTransport::HttpMock
            | GoProxyTransport::HttpProxy
            | GoProxyTransport::Socks5
            | GoProxyTransport::Shadowsocks
            | GoProxyTransport::Shadowsocksr
            | GoProxyTransport::Trojan
            | GoProxyTransport::Vless
            | GoProxyTransport::Vmess
            | GoProxyTransport::Yuubinsya
            | GoProxyTransport::Aead => fixed_endpoints(&self.layers),
            GoProxyTransport::NetworkSplit => {
                // `network_split` wraps the proxy assembled from the chain
                // prefix.  The branch payload is a protocol point, not a
                // second node-level fixed endpoint, so observability must
                // resolve only the parent prefix just like the runtime
                // builder does.
                let Some(split_index) = self
                    .layers
                    .iter()
                    .position(|layer| layer.kind.eq_ignore_ascii_case("network_split"))
                else {
                    return Ok(Vec::new());
                };
                if split_index == 0 {
                    Ok(Vec::new())
                } else {
                    fixed_endpoints(&self.layers[..split_index])
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    fn base_proxy_kind(&self, endpoints: Vec<BaseProxyEndpoint>) -> Result<BaseProxyKind> {
        let single_address = || {
            (endpoints.len() == 1 && endpoints[0].bind_interface.is_none())
                .then(|| endpoints[0].address)
        };
        Ok(match &self.transport {
            GoProxyTransport::Direct => BaseProxyKind::Direct,
            GoProxyTransport::Reject => BaseProxyKind::Reject,
            GoProxyTransport::Drop => BaseProxyKind::Drop,
            GoProxyTransport::Fixed => match single_address() {
                Some(address) => BaseProxyKind::Fixed { address },
                None => BaseProxyKind::FixedMany { endpoints },
            },
            GoProxyTransport::HttpMock => match single_address() {
                Some(address) => BaseProxyKind::Fixed { address },
                None => BaseProxyKind::FixedMany { endpoints },
            },
            GoProxyTransport::HttpProxy => {
                let config = layer_config(&self.layers, "http")
                    .or_else(|_| layer_config(&self.layers, "http_proxy"))?;
                let username = optional_string(config, "user");
                let password = optional_string(config, "password");
                match single_address() {
                    Some(proxy) => BaseProxyKind::Http {
                        proxy,
                        username,
                        password,
                    },
                    None => BaseProxyKind::HttpMany {
                        endpoints,
                        username,
                        password,
                    },
                }
            }
            GoProxyTransport::Socks5 => {
                let config = layer_config(&self.layers, "socks5")?;
                let username = optional_string(config, "user");
                let password = optional_string(config, "password");
                match single_address() {
                    Some(proxy) => BaseProxyKind::Socks5 {
                        proxy,
                        username,
                        password,
                    },
                    None => BaseProxyKind::Socks5Many {
                        endpoints,
                        username,
                        password,
                    },
                }
            }
            GoProxyTransport::Shadowsocks
            | GoProxyTransport::Shadowsocksr
            | GoProxyTransport::Trojan
            | GoProxyTransport::Vless
            | GoProxyTransport::Vmess => match single_address() {
                Some(address) => BaseProxyKind::Fixed { address },
                None => BaseProxyKind::FixedMany { endpoints },
            },
            GoProxyTransport::Aead => match single_address() {
                Some(address) => BaseProxyKind::Fixed { address },
                None => BaseProxyKind::FixedMany { endpoints },
            },
            GoProxyTransport::Yuubinsya => {
                let config = layer_config(&self.layers, "yuubinsya")?;
                let password = required_string(config, "password")?;
                let password_hash = yuhaiin_protocol::yuubinsya::derive_salt(password.as_bytes());
                let socks5_prefix = config
                    .get("socks5_prefix")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                match single_address() {
                    Some(server) => BaseProxyKind::YuubinsyaUdp {
                        server,
                        password_hash,
                        socks5_prefix,
                    },
                    None => BaseProxyKind::YuubinsyaUdpMany {
                        endpoints,
                        password_hash,
                        socks5_prefix,
                    },
                }
            }
            GoProxyTransport::Wireguard => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "WireGuard is a stateful userspace tunnel and must be built by yuhaiin-runtime",
                ));
            }
            GoProxyTransport::NetworkSplit
            | GoProxyTransport::Tls
            | GoProxyTransport::TlsTermination
            | GoProxyTransport::HttpTermination
            | GoProxyTransport::Http2
            | GoProxyTransport::Unknown { .. } => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!(
                        "{} is a chain transport; use yuhaiin-chain runtime construction",
                        transport_name(&self.transport)
                    ),
                ));
            }
        })
    }
}

fn transport_name(transport: &GoProxyTransport) -> &str {
    match transport {
        GoProxyTransport::Direct => "direct",
        GoProxyTransport::Reject => "reject",
        GoProxyTransport::Drop => "drop",
        GoProxyTransport::Fixed => "fixed",
        GoProxyTransport::HttpMock => "http_mock",
        GoProxyTransport::HttpProxy => "http",
        GoProxyTransport::Socks5 => "socks5",
        GoProxyTransport::Shadowsocks => "shadowsocks",
        GoProxyTransport::Shadowsocksr => "shadowsocksr",
        GoProxyTransport::Trojan => "trojan",
        GoProxyTransport::Vless => "vless",
        GoProxyTransport::Vmess => "vmess",
        GoProxyTransport::Yuubinsya => "yuubinsya",
        GoProxyTransport::Wireguard => "wireguard",
        GoProxyTransport::Aead => "aead",
        GoProxyTransport::NetworkSplit => "network_split",
        GoProxyTransport::Tls => "tls",
        GoProxyTransport::TlsTermination => "tls_termination",
        GoProxyTransport::HttpTermination => "http_termination",
        GoProxyTransport::Http2 => "http2",
        GoProxyTransport::Unknown { name } => name,
    }
}

fn layer_config<'a>(layers: &'a [GoProxyLayer], kind: &str) -> Result<&'a serde_json::Value> {
    layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case(kind))
        .map(|layer| &layer.config)
        .ok_or_else(|| Error::invalid(format!("Go proxy chain has no {kind} layer")))
}

fn optional_string(config: &serde_json::Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn required_string(config: &serde_json::Value, key: &str) -> Result<String> {
    optional_string(config, key)
        .ok_or_else(|| Error::invalid(format!("Go Yuubinsya {key} is empty")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    host: String,
    port: u16,
    bind_interface: Option<String>,
}

impl ProxyEndpoint {
    fn text(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn fixed_endpoints(layers: &[GoProxyLayer]) -> Result<Vec<ProxyEndpoint>> {
    let config = layers
        .iter()
        .find(|layer| matches!(layer.kind.as_str(), "fixed" | "simple" | "fixedv2"))
        .map(|layer| &layer.config)
        .ok_or_else(|| Error::invalid("Go proxy chain has no fixed endpoint layer"))?;
    let default_interface = crate::compat_proxy::network_interface_field(config);
    if let Some(addresses) = config
        .get("addresses")
        .and_then(serde_json::Value::as_array)
    {
        if addresses.is_empty() {
            return Err(Error::invalid("Go fixed endpoint addresses is empty"));
        }
        return addresses
            .iter()
            .map(|value| {
                let mut endpoint = proxy_endpoint_value(value)?;
                if endpoint.bind_interface.is_none() {
                    endpoint.bind_interface = crate::compat_proxy::network_interface_field(value)
                        .or_else(|| default_interface.clone());
                }
                Ok(endpoint)
            })
            .collect();
    }
    let mut endpoints = Vec::new();
    if config.get("host").is_some() {
        endpoints.push(proxy_endpoint_value(config)?);
    }
    if let Some(alternates) = config
        .get("alternate_host")
        .and_then(serde_json::Value::as_array)
    {
        endpoints.extend(
            alternates
                .iter()
                .map(proxy_endpoint_value)
                .collect::<Result<Vec<_>>>()?,
        );
    }
    if endpoints.is_empty() {
        return Err(Error::invalid(
            "Go fixed node requires addresses or host/port",
        ));
    }
    for endpoint in &mut endpoints {
        if endpoint.bind_interface.is_none() {
            endpoint.bind_interface = default_interface.clone();
        }
    }
    Ok(endpoints)
}

fn proxy_endpoint_value(value: &serde_json::Value) -> Result<ProxyEndpoint> {
    if let Some(value) = value.as_str() {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(ProxyEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
                bind_interface: None,
            });
        }
        let (host, port) = split_endpoint_text(value)?;
        return Ok(ProxyEndpoint {
            host,
            port,
            bind_interface: None,
        });
    }
    let host = value
        .get("host")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("Go proxy endpoint requires host"))?;
    let port = value
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::invalid("Go proxy endpoint requires port"))?;
    if port == 0 || port > u64::from(u16::MAX) {
        return Err(Error::invalid("Go proxy endpoint port is out of range"));
    }
    Ok(ProxyEndpoint {
        host: host.to_owned(),
        port: u16::try_from(port)
            .map_err(|_| Error::invalid("Go proxy endpoint port is out of range"))?,
        bind_interface: crate::compat_proxy::network_interface_field(value),
    })
}

fn split_endpoint_text(value: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        value.split_once("]:").ok_or_else(|| {
            Error::invalid(format!("Go proxy endpoint {value:?} requires host:port"))
        })?
    } else {
        value.rsplit_once(':').ok_or_else(|| {
            Error::invalid(format!("Go proxy endpoint {value:?} requires host:port"))
        })?
    };
    let port = port.parse::<u16>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid proxy port: {error}"),
        )
    })?;
    if host.is_empty() {
        return Err(Error::invalid("Go proxy endpoint host cannot be empty"));
    }
    if host.parse::<std::net::IpAddr>().is_err() {
        DomainName::new(host)?;
    }
    Ok((host.to_owned(), port))
}

fn resolve_socket_addr(value: &str) -> Result<SocketAddr> {
    if let Ok(address) = value.parse() {
        return Ok(address);
    }
    value
        .to_socket_addrs()
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Go proxy endpoint {value:?} cannot be resolved: {error}"),
            )
        })?
        .next()
        .ok_or_else(|| {
            Error::invalid(format!(
                "Go proxy endpoint {value:?} resolved to no address"
            ))
        })
}

async fn resolve_endpoints(
    endpoint: &ProxyEndpoint,
    resolver: &dyn AsyncIpResolver,
) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = endpoint.text().parse() {
        return Ok(vec![address]);
    }
    let domain = DomainName::new(&endpoint.host)?;
    let addresses = resolver
        .resolve(&domain, yuhaiin_core::ResolveStrategy::Default)
        .await?;
    let addresses = addresses
        .iter()
        .map(|address| SocketAddr::new(address, endpoint.port))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(Error::invalid(format!(
            "proxy endpoint {} resolved to no address",
            domain
        )));
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use yuhaiin_core::{BoxFuture, IpSet};

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: yuhaiin_core::ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 44)],
                    v6: Vec::new(),
                })
            })
        }
    }

    #[test]
    fn resolves_domain_proxy_endpoint_before_building_base_config() {
        let address = proxy_endpoint_value(&serde_json::json!({
            "host": "localhost",
            "port": 18080
        }))
        .unwrap();
        assert_eq!(address.port, 18080);
    }

    #[test]
    fn extracts_node_interface_from_fixedv2_and_alternate_address() {
        let config = GoProxyRuntimeConfig {
            id: "fixed".to_owned(),
            name: "fixed".to_owned(),
            group_name: "default".to_owned(),
            origin: "local".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [
                        { "host": "proxy.example", "port": 443, "network_interface": "eth-proxy" }
                    ]
                }),
            }],
            transport: GoProxyTransport::Fixed,
            data_json: Vec::new(),
        };
        assert_eq!(config.network_interface().as_deref(), Some("eth-proxy"));
    }

    #[test]
    fn extracts_camel_case_interface_from_preserved_legacy_payload() {
        let config = GoProxyRuntimeConfig {
            id: "direct".to_owned(),
            name: "direct".to_owned(),
            group_name: "default".to_owned(),
            origin: "local".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: serde_json::to_vec(&serde_json::json!({
                "networkInterface": "wan0"
            }))
            .unwrap(),
        };
        assert_eq!(config.network_interface().as_deref(), Some("wan0"));
    }

    #[test]
    fn preserves_fixedv2_alternate_endpoints_and_interface_policy() {
        let config = GoProxyRuntimeConfig {
            id: "fixed".to_owned(),
            name: "fixed".to_owned(),
            group_name: "default".to_owned(),
            origin: "local".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "network_interface": "lo",
                    "addresses": [
                        { "host": "127.0.0.1", "port": 18080 },
                        { "host": "127.0.0.1", "port": 18081 }
                    ]
                }),
            }],
            transport: GoProxyTransport::Fixed,
            data_json: Vec::new(),
        };
        let built = config.to_base_proxy_config(Duration::from_secs(3)).unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::FixedMany {
                endpoints: vec![
                    BaseProxyEndpoint {
                        address: "127.0.0.1:18080".parse().unwrap(),
                        bind_interface: Some("lo".to_owned()),
                    },
                    BaseProxyEndpoint {
                        address: "127.0.0.1:18081".parse().unwrap(),
                        bind_interface: Some("lo".to_owned()),
                    },
                ],
            }
        );
    }

    #[test]
    fn injected_resolver_builds_domain_fixed_proxy_without_system_dns() {
        let config = GoProxyRuntimeConfig {
            id: "fixed".to_owned(),
            name: "fixed".to_owned(),
            group_name: "default".to_owned(),
            origin: "local".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{ "host": "proxy.example", "port": 443 }]
                }),
            }],
            transport: GoProxyTransport::Fixed,
            data_json: Vec::new(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let built = runtime
            .block_on(config.to_base_proxy_config_with_resolver(
                Duration::from_secs(3),
                Arc::new(StaticResolver),
            ))
            .unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::Fixed {
                address: "192.0.2.44:443".parse().unwrap()
            }
        );
    }

    #[test]
    fn native_yuubinsya_udp_reuses_fixed_endpoint_and_derives_password_hash() {
        let config = GoProxyRuntimeConfig {
            id: "yuubinsya-udp".to_owned(),
            name: "yuubinsya-udp".to_owned(),
            group_name: "default".to_owned(),
            origin: "local".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{ "host": "yuubinsya.example", "port": 40501 }]
                    }),
                },
                GoProxyLayer {
                    kind: "yuubinsya".to_owned(),
                    config: serde_json::json!({ "password": "password" }),
                },
            ],
            transport: GoProxyTransport::Yuubinsya,
            data_json: Vec::new(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let built = runtime
            .block_on(config.to_base_proxy_config_with_resolver(
                Duration::from_secs(3),
                Arc::new(StaticResolver),
            ))
            .unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::YuubinsyaUdp {
                server: "192.0.2.44:40501".parse().unwrap(),
                password_hash: yuhaiin_protocol::yuubinsya::derive_salt(b"password"),
                socks5_prefix: false,
            }
        );
    }
}
