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
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub http_proxy: Option<HttpConfig>,
    #[serde(default)]
    pub socks5: Option<Socks5Config>,
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
    #[serde(default, alias = "networkInterface")]
    pub network_interface: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub insecure_skip_verify: bool,
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

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Socks5Config {
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub override_port: i32,
}

#[derive(Debug, Clone)]
pub struct ValidatedChain {
    pub id: Option<String>,
    pub name: Option<String>,
    pub fixed_addresses: Vec<ValidatedFixedAddress>,
    pub tls: ValidatedTls,
    pub websocket: Option<ValidatedWebSocket>,
    pub http2: ValidatedHttp2,
    /// The final protocol is optional for a standalone Go HTTP/2 transport.
    /// When absent, the chain only provides a raw CONNECT stream and must be
    /// wrapped by another protocol layer before it can be used as a final
    /// destination proxy.
    pub yuubinsya: Option<ValidatedYuubinsya>,
    /// Final stream protocol layered on top of HTTP/2.  `None` means this is
    /// a raw standalone HTTP/2 transport and still needs an outer protocol.
    pub http: Option<ValidatedHttp>,
    pub socks5: Option<ValidatedSocks5>,
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
    pub network_interface: Option<String>,
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
    pub insecure_skip_verify: bool,
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

#[derive(Debug, Clone)]
pub struct ValidatedHttp {
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedSocks5 {
    pub user: String,
    pub password: String,
    pub hostname: String,
    pub override_port: i32,
}

pub fn parse_config(json: &str) -> Result<ValidatedChain> {
    let config: ChainConfig = serde_json::from_str(json)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, format!("chain JSON: {error}")))?;
    config.validate()
}

impl ChainConfig {
    pub fn validate(self) -> Result<ValidatedChain> {
        let ChainConfig {
            id,
            name,
            chain: original_chain,
        } = self;
        // Go's `none`, `proxy` and `bootstrap_dns_warp` contract points are
        // no-op wrappers around the already-built parent. Remove them before
        // validating the runnable transport shape so persisted Go chains can
        // retain those layers without changing the wire path.
        let chain: Vec<ChainNode> = original_chain
            .into_iter()
            .filter(|node| {
                !matches!(
                    node.kind.to_ascii_lowercase().as_str(),
                    "none" | "proxy" | "bootstrap_dns_warp" | "bootstrapdnswarp"
                )
            })
            .collect();
        if !(2..=5).contains(&chain.len()) {
            return Err(Error::invalid(
                "the runnable chain supports fixedv2, optional tls/websocket, http2, and final yuubinsya/http/socks5",
            ));
        }
        let fixed = require_node(&chain[0], "fixedv2", |node| node.fixedv2.clone())?;
        let final_kind = chain
            .last()
            .map(|node| node.kind.to_ascii_lowercase())
            .ok_or_else(|| Error::invalid("chain has no final node"))?;
        let has_destination_protocol = matches!(
            final_kind.as_str(),
            "yuubinsya" | "http" | "http_proxy" | "socks5"
        );
        let yuubinsya = if final_kind == "yuubinsya" {
            Some(require_node(
                chain.last().expect("chain length validated"),
                "yuubinsya",
                |node| node.yuubinsya.clone(),
            )?)
        } else {
            None
        };
        let http = if matches!(final_kind.as_str(), "http" | "http_proxy") {
            let expected = if final_kind == "http_proxy" {
                "http_proxy"
            } else {
                "http"
            };
            Some(require_node(
                chain.last().expect("chain length validated"),
                expected,
                |node| node.http.clone().or_else(|| node.http_proxy.clone()),
            )?)
        } else {
            None
        };
        let socks5 = if final_kind == "socks5" {
            Some(require_node(
                chain.last().expect("chain length validated"),
                "socks5",
                |node| node.socks5.clone(),
            )?)
        } else {
            None
        };
        if !has_destination_protocol && final_kind != "http2" {
            return Err(Error::invalid(
                "standalone HTTP/2 chain must end with http2 or a supported destination protocol",
            ));
        }

        let middle_end = if has_destination_protocol {
            chain.len() - 1
        } else {
            chain.len()
        };
        let middle = &chain[1..middle_end];
        let mut tls = None;
        let mut websocket = None;
        let mut http2 = None;
        let mut saw_http2 = false;
        for node in middle {
            match node.kind.to_ascii_lowercase().as_str() {
                kind if kind == "tls" && tls.is_none() && !saw_http2 => {
                    tls = Some(require_node(node, "tls", |node| node.tls.clone())?);
                }
                kind if kind == "websocket" && websocket.is_none() && !saw_http2 => {
                    websocket = Some(require_node(node, "websocket", |node| {
                        node.websocket.clone()
                    })?);
                }
                kind if kind == "http2" && !saw_http2 => {
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
            let network_interface = address
                .network_interface
                .map(|interface| interface.trim().to_owned())
                .filter(|interface| !interface.is_empty());
            fixed_addresses.push(ValidatedFixedAddress {
                host,
                port,
                network_interface,
            });
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
                    insecure_skip_verify: tls.insecure_skip_verify,
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
                insecure_skip_verify: false,
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
        if yuubinsya
            .as_ref()
            .is_some_and(|yuubinsya| yuubinsya.password.is_empty())
        {
            return Err(Error::invalid("Yuubinsya password cannot be empty"));
        }
        if http.is_some() && socks5.is_some() {
            return Err(Error::invalid(
                "chain cannot contain both HTTP and SOCKS5 destination protocols",
            ));
        }
        if socks5
            .as_ref()
            .is_some_and(|socks5| !(0..=i32::from(u16::MAX)).contains(&socks5.override_port))
        {
            return Err(Error::invalid("SOCKS5 override_port is out of range"));
        }
        Ok(ValidatedChain {
            id,
            name,
            fixed_addresses,
            tls,
            websocket,
            http2: ValidatedHttp2 {
                concurrency,
                max_streams,
                idle_timeout,
            },
            yuubinsya: yuubinsya.map(|yuubinsya| ValidatedYuubinsya {
                password: yuubinsya.password,
                udp_over_stream: yuubinsya.udp_over_stream,
                udp_coalesce: yuubinsya.udp_coalesce,
            }),
            http: http.map(|http| ValidatedHttp {
                user: http.user,
                password: http.password,
            }),
            socks5: socks5.map(|socks5| ValidatedSocks5 {
                user: socks5.user,
                password: socks5.password,
                hostname: socks5.hostname,
                override_port: socks5.override_port,
            }),
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
            "insecure_skip_verify:{}\0servernames:{}\0alpn:{}",
            self.insecure_skip_verify,
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
                network_interface: None,
            }
        );
        assert_eq!(chain.http2.concurrency, 8);
        assert_eq!(chain.http2.max_streams, 128);
        assert!(chain.yuubinsya.as_ref().unwrap().udp_over_stream);
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
    fn accepts_public_ca_tls_without_custom_ca_certificates() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][1]["tls"]["ca_cert"] = serde_json::json!([]);
        let chain = parse_config(&value.to_string()).unwrap();
        assert!(chain.tls.ca_certificates.is_empty());
    }

    #[test]
    fn preserves_go_insecure_skip_verify_tls_option() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][1]["tls"]["ca_cert"] = serde_json::json!([]);
        value["chain"][1]["tls"]["insecure_skip_verify"] = serde_json::json!(true);
        let chain = parse_config(&value.to_string()).unwrap();
        assert!(chain.tls.insecure_skip_verify);
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

    #[test]
    fn accepts_http_and_socks5_as_final_protocols_after_http2() {
        let http = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"http2","http2":{}},
            {"type":"http","http":{"user":"user","password":"pass"}}
          ]
        }
        "#;
        let parsed = parse_config(http).unwrap();
        assert_eq!(parsed.http.as_ref().unwrap().user, "user");
        assert!(parsed.socks5.is_none());

        let http_proxy = http.replace(
            "\"type\":\"http\",\"http\"",
            "\"type\":\"http_proxy\",\"http_proxy\"",
        );
        let parsed = parse_config(&http_proxy).unwrap();
        assert_eq!(parsed.http.as_ref().unwrap().password, "pass");

        let socks5 = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"http2","http2":{}},
            {"type":"socks5","socks5":{"user":"user","password":"pass","hostname":"relay.example","override_port":8443}}
          ]
        }
        "#;
        let parsed = parse_config(socks5).unwrap();
        let socks5 = parsed.socks5.unwrap();
        assert_eq!(socks5.hostname, "relay.example");
        assert_eq!(socks5.override_port, 8443);
        assert!(parsed.http.is_none());
    }

    #[test]
    fn ignores_go_parent_preserving_contract_points() {
        let config = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"proxy","proxy":{}},
            {"type":"none","none":{}},
            {"type":"bootstrap_dns_warp","bootstrap_dns_warp":{}},
            {"type":"http2","http2":{}},
            {"type":"http","http":{}}
          ]
        }
        "#;
        let parsed = parse_config(config).unwrap();
        assert!(parsed.tls.servernames.is_empty());
        assert_eq!(parsed.http.as_ref().unwrap().user, "");
    }

    #[test]
    fn rejects_invalid_socks5_override_port() {
        let config = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"http2","http2":{}},
            {"type":"socks5","socks5":{"override_port":65536}}
          ]
        }
        "#;
        assert!(parse_config(config).is_err());
    }
}
