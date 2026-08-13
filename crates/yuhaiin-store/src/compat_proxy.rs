//! Go `nodes_v2` protocol-chain compatibility and runtime snapshots.

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use yuhaiin_core::{Error, ErrorKind, Result};

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
    // The outer protocol is the effective runtime proxy: HTTP/SOCKS5 wraps a
    // fixed dialer, and Yuubinsya wraps the full fixed/TLS/HTTP2 chain.
    for preferred in [
        "http_mock",
        "network_split",
        "tls_termination",
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
