use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use serde::Deserialize;
use yuhaiin_core::{DomainName, Error, ErrorKind, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub chain: Vec<ChainNode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainNode {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub fixedv2: Option<FixedV2Config>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub websocket: Option<WebSocketConfig>,
    #[serde(default)]
    pub http2: Option<Http2Config>,
    #[serde(default)]
    pub yuubinsya: Option<YuubinsyaConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixedV2Config {
    pub addresses: Vec<FixedAddress>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixedAddress {
    pub host: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub servernames: Vec<String>,
    #[serde(default)]
    pub ca_cert: Vec<String>,
    #[serde(default)]
    pub next_protos: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Http2Config {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_max_streams")]
    pub max_streams: usize,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct YuubinsyaConfig {
    pub password: String,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub udp_coalesce: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatedChain {
    pub id: Option<String>,
    pub name: Option<String>,
    pub fixed_addresses: Vec<ValidatedFixedAddress>,
    pub tls: ValidatedTls,
    pub websocket: Option<ValidatedWebSocket>,
    pub http2: ValidatedHttp2,
    pub yuubinsya: ValidatedYuubinsya,
}

/// A fixed upstream endpoint retained in its original host/port form.
///
/// Go accepts both IP literals and DNS names for fixed nodes. Keeping the
/// host instead of resolving during config parsing lets the runtime use its
/// async resolver and pick up DNS changes without rebuilding the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFixedAddress {
    pub host: String,
    pub port: u16,
}

impl ValidatedFixedAddress {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format_host_port(&self.host, self.port)
            .parse::<SocketAddr>()
            .ok()
    }

    pub fn domain(&self) -> Option<DomainName> {
        if self.socket_addr().is_some() {
            None
        } else {
            DomainName::new(&self.host).ok()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedTls {
    pub servernames: Vec<String>,
    pub ca_certificates: Vec<Vec<u8>>,
    pub next_protos: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWebSocket {
    pub host: String,
    pub path: String,
}

impl ValidatedWebSocket {
    pub fn request_uri(&self) -> String {
        format!("ws://{}{}", self.host, self.path)
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedHttp2 {
    pub concurrency: usize,
    pub max_streams: usize,
    pub idle_timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct ValidatedYuubinsya {
    pub password: String,
    pub udp_over_stream: bool,
    pub udp_coalesce: bool,
}

pub fn parse_config(json: &str) -> Result<ValidatedChain> {
    let config: ChainConfig = serde_json::from_str(json)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, format!("chain JSON: {error}")))?;
    config.validate()
}

impl ChainConfig {
    pub fn validate(self) -> Result<ValidatedChain> {
        if !(4..=5).contains(&self.chain.len()) {
            return Err(Error::invalid(
                "the first runnable chain supports fixedv2, optional tls/websocket, http2, yuubinsya",
            ));
        }
        let fixed = require_node(&self.chain[0], "fixedv2", |node| node.fixedv2.clone())?;
        let yuubinsya = require_node(
            self.chain.last().expect("chain length validated"),
            "yuubinsya",
            |node| node.yuubinsya.clone(),
        )?;

        let middle = &self.chain[1..self.chain.len() - 1];
        let mut tls = None;
        let mut websocket = None;
        let mut http2 = None;
        let mut saw_http2 = false;
        for node in middle {
            match node.kind.as_str() {
                "tls" if tls.is_none() && !saw_http2 => {
                    tls = Some(require_node(node, "tls", |node| node.tls.clone())?);
                }
                "websocket" if websocket.is_none() && !saw_http2 => {
                    websocket = Some(require_node(node, "websocket", |node| {
                        node.websocket.clone()
                    })?);
                }
                "http2" if !saw_http2 => {
                    http2 = Some(require_node(node, "http2", |node| node.http2.clone())?);
                    saw_http2 = true;
                }
                other => {
                    return Err(Error::invalid(format!(
                        "unsupported or reordered chain node {other:?}"
                    )));
                }
            }
        }
        let http2 = http2.ok_or_else(|| Error::invalid("chain requires an http2 node"))?;
        let has_websocket = websocket.is_some();

        if fixed.addresses.is_empty() {
            return Err(Error::invalid("fixedv2 requires at least one address"));
        }
        let mut fixed_addresses = Vec::with_capacity(fixed.addresses.len());
        for address in fixed.addresses {
            let (host, port) = split_host_port(&address.host)?;
            if host.parse::<IpAddr>().is_err() {
                DomainName::new(&host).map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "fixedv2 address {} has an invalid host: {error}",
                            address.host
                        ),
                    )
                })?;
            }
            fixed_addresses.push(ValidatedFixedAddress { host, port });
        }

        let tls = match tls {
            Some(tls) => {
                if !tls.enable {
                    return Err(Error::invalid("TLS node must have enable=true"));
                }
                if tls.servernames.is_empty() {
                    return Err(Error::invalid("TLS node requires servernames"));
                }
                let mut ca_certificates = Vec::with_capacity(tls.ca_cert.len());
                for (index, certificate) in tls.ca_cert.iter().enumerate() {
                    let certificate = base64::engine::general_purpose::STANDARD
                        .decode(certificate)
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                format!("TLS ca_cert[{index}] is not base64: {error}"),
                            )
                        })?;
                    if certificate.is_empty() {
                        return Err(Error::invalid("TLS CA certificate cannot be empty"));
                    }
                    ca_certificates.push(certificate);
                }
                if ca_certificates.is_empty() {
                    return Err(Error::invalid("TLS node requires at least one ca_cert"));
                }

                let next_protos = if tls.next_protos.is_empty() {
                    if has_websocket {
                        Vec::new()
                    } else {
                        vec!["h2".to_owned()]
                    }
                } else {
                    tls.next_protos
                };
                if !has_websocket && !next_protos.iter().any(|protocol| protocol == "h2") {
                    return Err(Error::invalid("HTTP/2 chain requires TLS ALPN h2"));
                }
                ValidatedTls {
                    servernames: tls
                        .servernames
                        .into_iter()
                        .map(|name| name.replace("&lt;", "<").replace("&gt;", ">"))
                        .collect(),
                    ca_certificates,
                    next_protos,
                }
            }
            None => ValidatedTls {
                servernames: Vec::new(),
                ca_certificates: Vec::new(),
                next_protos: Vec::new(),
            },
        };

        let websocket = websocket.map(|websocket| ValidatedWebSocket {
            host: if websocket.host.is_empty() {
                "localhost".to_owned()
            } else {
                websocket.host
            },
            path: normalize_websocket_path(&websocket.path),
        });

        let concurrency = http2.concurrency.max(1);
        let max_streams = http2.max_streams.max(1);
        let idle_timeout = std::time::Duration::from_secs(http2.idle_timeout_secs.max(1));
        if yuubinsya.password.is_empty() {
            return Err(Error::invalid("Yuubinsya password cannot be empty"));
        }
        Ok(ValidatedChain {
            id: self.id,
            name: self.name,
            fixed_addresses,
            tls,
            websocket,
            http2: ValidatedHttp2 {
                concurrency,
                max_streams,
                idle_timeout,
            },
            yuubinsya: ValidatedYuubinsya {
                password: yuubinsya.password,
                udp_over_stream: yuubinsya.udp_over_stream,
                udp_coalesce: yuubinsya.udp_coalesce,
            },
        })
    }
}

fn normalize_websocket_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

impl ValidatedTls {
    /// Stable identity for connection-pool coalescing.  Dynamic SNI patterns
    /// intentionally produce a fresh concrete name per TLS connection, but
    /// they still belong to the same configured TLS identity.  Include ALPN
    /// so a future shared pool cannot reuse an h2 connection for another
    /// protocol profile.
    pub fn pool_identity(&self) -> String {
        format!(
            "servernames:{}\0alpn:{}",
            self.servernames.join("\0"),
            self.next_protos.join("\0")
        )
    }

    pub fn server_name(&self) -> String {
        let configured = &self.servernames[0];
        if let Some(suffix) = configured.strip_prefix("<bilibili_mcdn>.") {
            let mut rng = rand::rng();
            let mut name = format!(
                "xy{}x{}x{}x{}xy",
                rand::RngExt::random_range(&mut rng, 0..255),
                rand::RngExt::random_range(&mut rng, 0..255),
                rand::RngExt::random_range(&mut rng, 0..255),
                rand::RngExt::random_range(&mut rng, 0..255),
            );
            if rand::RngExt::random_range(&mut rng, 0..2) == 0 {
                let mut bytes = [0u8; 16];
                rand::RngExt::fill(&mut rng, &mut bytes);
                bytes[8..14].fill(0);
                let ipv6 = std::net::Ipv6Addr::from(bytes)
                    .to_string()
                    .replace(':', "y");
                name.push_str(&format!("{ipv6}xy"));
            }
            format!("{name}.{suffix}")
        } else if let Some(suffix) = configured.strip_prefix("*.") {
            let mut rng = rand::rng();
            let mut bytes = [0u8; 16];
            rand::RngExt::fill(&mut rng, &mut bytes);
            let prefix = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("{prefix}.{suffix}")
        } else {
            configured.clone()
        }
    }
}

fn require_node<T>(
    node: &ChainNode,
    expected: &str,
    get: impl FnOnce(&ChainNode) -> Option<T>,
) -> Result<T> {
    if node.kind != expected {
        return Err(Error::invalid(format!(
            "chain node {} must be {expected}, got {}",
            expected, node.kind
        )));
    }
    get(node).ok_or_else(|| Error::invalid(format!("chain node {expected} has no config")))
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }

    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        let (host, port) = value.split_once("]:").ok_or_else(|| {
            Error::invalid(format!("fixedv2 address {value:?} requires host:port"))
        })?;
        (host, port)
    } else {
        value.rsplit_once(':').ok_or_else(|| {
            Error::invalid(format!("fixedv2 address {value:?} requires host:port"))
        })?
    };
    let port = port.parse::<u16>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid fixedv2 port: {error}"),
        )
    })?;
    if host.is_empty() {
        return Err(Error::invalid("fixedv2 address host cannot be empty"));
    }
    Ok((host.to_owned(), port))
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

const fn default_concurrency() -> usize {
    8
}

const fn default_max_streams() -> usize {
    128
}

const fn default_idle_timeout_secs() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
    {
      "chain": [
        {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:12103"}]}},
        {"type":"tls","tls":{"enable":true,"servernames":["<bilibili_mcdn>.mcdn.bilivideo.cn"],"ca_cert":["AQ=="],"next_protos":["h2"]}},
        {"type":"http2","http2":{"concurrency":8}},
        {"type":"yuubinsya","yuubinsya":{"password":"secret","udp_over_stream":true,"udp_coalesce":true}}
      ]
    }
    "#;

    #[test]
    fn parses_and_validates_the_requested_chain_shape() {
        let chain = parse_config(CONFIG).unwrap();
        assert_eq!(
            chain.fixed_addresses[0],
            ValidatedFixedAddress {
                host: "127.0.0.1".to_owned(),
                port: 12103,
            }
        );
        assert_eq!(chain.http2.concurrency, 8);
        assert_eq!(chain.http2.max_streams, 128);
        assert!(chain.yuubinsya.udp_over_stream);
        assert!(chain.tls.server_name().ends_with(".mcdn.bilivideo.cn"));
    }

    #[test]
    fn rejects_reordered_nodes_and_empty_password() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][0]["type"] = serde_json::Value::String("tls".to_owned());
        assert!(parse_config(&value.to_string()).is_err());
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][3]["yuubinsya"]["password"] = serde_json::Value::String(String::new());
        assert!(parse_config(&value.to_string()).is_err());
    }

    #[test]
    fn validates_websocket_chain_without_forcing_tls_h2_alpn() {
        let config = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"tls","tls":{"enable":true,"servernames":["proxy.example"],"ca_cert":["AQ=="]}},
            {"type":"websocket","websocket":{"host":"proxy.example","path":"proxy/ws"}},
            {"type":"http2","http2":{}},
            {"type":"yuubinsya","yuubinsya":{"password":"secret"}}
          ]
        }
        "#;
        let chain = parse_config(config).unwrap();
        assert!(chain.tls.next_protos.is_empty());
        assert_eq!(
            chain.websocket,
            Some(ValidatedWebSocket {
                host: "proxy.example".to_owned(),
                path: "/proxy/ws".to_owned(),
            })
        );
    }
}
