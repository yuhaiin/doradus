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
    Drop,
    Fixed,
    HttpProxy,
    Socks5,
    Shadowsocks,
    Trojan,
    Vless,
    Vmess,
    Yuubinsya,
    Tls,
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

fn parse_proxy_transport(value: &str) -> GoProxyTransport {
    match value.trim().to_ascii_lowercase().as_str() {
        "direct" => GoProxyTransport::Direct,
        "drop" | "block" => GoProxyTransport::Drop,
        "fixed" | "simple" | "fixedv2" => GoProxyTransport::Fixed,
        "http" | "http_proxy" => GoProxyTransport::HttpProxy,
        "socks5" => GoProxyTransport::Socks5,
        "shadowsocks" => GoProxyTransport::Shadowsocks,
        "trojan" => GoProxyTransport::Trojan,
        "vless" => GoProxyTransport::Vless,
        "vmess" => GoProxyTransport::Vmess,
        "yuubinsya" => GoProxyTransport::Yuubinsya,
        "tls" => GoProxyTransport::Tls,
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
    // The outer protocol is the effective runtime proxy: HTTP/SOCKS5 wraps a
    // fixed dialer, and Yuubinsya wraps the full fixed/TLS/HTTP2 chain.
    for preferred in [
        "yuubinsya",
        "socks5",
        "vmess",
        "vless",
        "shadowsocks",
        "trojan",
        "http",
        "http_proxy",
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
        .map(|kind| parse_proxy_transport(kind))
        .find(|transport| !matches!(transport, GoProxyTransport::Unknown { .. }))
        .unwrap_or_else(|| GoProxyTransport::Unknown {
            name: all_types.first().copied().unwrap_or("unknown").to_owned(),
        })
}
