use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use doradus_core::{DomainName, Error, ErrorKind, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub chain: Vec<ChainNode>,
}

#[derive(Debug, Clone)]
pub enum ChainNode {
    Direct(DirectConfig),
    FixedV2(FixedV2Config),
    Tls(TlsConfig),
    WebSocket(WebSocketConfig),
    Http2(Http2Config),
    Yuubinsya(YuubinsyaConfig),
    Http(HttpConfig),
    HttpProxy(HttpConfig),
    Socks5(Socks5Config),
    None,
    Proxy,
    BootstrapDnsWarp,
}

impl<'de> Deserialize<'de> for ChainNode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        parse_chain_node(value).map_err(serde::de::Error::custom)
    }
}

fn parse_chain_node(value: Value) -> std::result::Result<ChainNode, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "chain node must be an object".to_owned())?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "chain node requires a string type".to_owned())?
        .to_ascii_lowercase();

    match kind.as_str() {
        "direct" => Ok(ChainNode::Direct(
            optional_payload(object, "direct", &kind)?.unwrap_or_default(),
        )),
        "fixed" | "simple" | "fixedv2" => Ok(ChainNode::FixedV2(payload_from_any(
            object,
            &["fixedv2", "fixed", "simple"],
            &kind,
        )?)),
        "tls" => Ok(ChainNode::Tls(payload(object, "tls", &kind)?)),
        "websocket" => Ok(ChainNode::WebSocket(payload(object, "websocket", &kind)?)),
        "http2" => Ok(ChainNode::Http2(payload(object, "http2", &kind)?)),
        "yuubinsya" => Ok(ChainNode::Yuubinsya(payload(object, "yuubinsya", &kind)?)),
        "http" => Ok(ChainNode::Http(payload_from_any(
            object,
            &["http", "http_proxy"],
            &kind,
        )?)),
        "http_proxy" => Ok(ChainNode::HttpProxy(payload_from_any(
            object,
            &["http_proxy", "http"],
            &kind,
        )?)),
        "socks5" => Ok(ChainNode::Socks5(payload(object, "socks5", &kind)?)),
        "none" => Ok(ChainNode::None),
        "proxy" => Ok(ChainNode::Proxy),
        "bootstrap_dns_warp" | "bootstrapdnswarp" => Ok(ChainNode::BootstrapDnsWarp),
        _ => Err(format!("unsupported chain node type {kind:?}")),
    }
}

fn payload<T: DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    field: &str,
    kind: &str,
) -> std::result::Result<T, String> {
    let value = object
        .get(field)
        .cloned()
        .ok_or_else(|| format!("chain node {kind} has no {field} config"))?;
    serde_json::from_value(value).map_err(|error| format!("chain node {kind}: {error}"))
}

fn optional_payload<T: DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    field: &str,
    kind: &str,
) -> std::result::Result<Option<T>, String> {
    object
        .get(field)
        .cloned()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| format!("chain node {kind}: {error}"))
        })
        .transpose()
}

fn payload_from_any<T: DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    kind: &str,
) -> std::result::Result<T, String> {
    for field in fields {
        if object.contains_key(*field) {
            return payload(object, field, kind);
        }
    }
    Err(format!("chain node {kind} has no config"))
}

impl ChainNode {
    fn is_noop(&self) -> bool {
        matches!(self, Self::None | Self::Proxy | Self::BootstrapDnsWarp)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DirectConfig {
    #[serde(default, alias = "networkInterface")]
    pub network_interface: Option<String>,
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
    pub nodes: Vec<ValidatedNode>,
}

#[derive(Debug, Clone)]
pub enum ValidatedNode {
    Direct(ValidatedDirect),
    Fixed(ValidatedFixedConfig),
    Tls(ValidatedTls),
    WebSocket(ValidatedWebSocket),
    Http2(ValidatedHttp2),
    Yuubinsya(ValidatedYuubinsya),
    Http(ValidatedHttp),
    HttpProxy(ValidatedHttp),
    Socks5(ValidatedSocks5),
    None,
    Proxy,
    BootstrapDnsWarp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDirect {
    pub network_interface: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedFixedConfig {
    pub addresses: Vec<ValidatedFixedAddress>,
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
        let ChainConfig { id, name, chain } = self;
        // Go's no-op contract points remain in the validated sequence. The
        // runtime skips their byte-level work, but retaining them keeps the
        // original chain order observable and compatible with Go's fold.
        let runnable = chain
            .iter()
            .enumerate()
            .filter(|(_, node)| !node.is_noop())
            .map(|(index, node)| (index, node.clone()))
            .collect::<Vec<_>>();
        if runnable.is_empty() {
            return Err(Error::invalid(
                "the chain requires at least one runnable node",
            ));
        }
        let last_index = runnable.last().expect("chain length validated").0;
        let mut validated = Vec::with_capacity(chain.len());
        for (index, node) in chain.into_iter().enumerate() {
            let next_kind = runnable
                .iter()
                .find(|(next_index, _)| *next_index > index)
                .map(|(_, next)| next);
            let validated_node = match node {
                ChainNode::Direct(config) => ValidatedNode::Direct(ValidatedDirect {
                    network_interface: config
                        .network_interface
                        .filter(|interface| !interface.trim().is_empty()),
                }),
                ChainNode::FixedV2(config) => ValidatedNode::Fixed(ValidatedFixedConfig {
                    addresses: validate_fixed_addresses(config)?,
                }),
                ChainNode::Tls(config) => ValidatedNode::Tls(validate_tls(config, next_kind)?),
                ChainNode::WebSocket(config) => ValidatedNode::WebSocket(ValidatedWebSocket {
                    host: if config.host.is_empty() {
                        "localhost".to_owned()
                    } else {
                        config.host
                    },
                    path: normalize_websocket_path(&config.path),
                }),
                ChainNode::Http2(config) => ValidatedNode::Http2(ValidatedHttp2 {
                    concurrency: config.concurrency.max(1),
                    max_streams: config.max_streams.max(1),
                    idle_timeout: std::time::Duration::from_secs(config.idle_timeout_secs.max(1)),
                }),
                ChainNode::Yuubinsya(config) => {
                    if index != last_index {
                        return Err(Error::invalid(
                            "yuubinsya must be the last runnable chain node",
                        ));
                    }
                    if config.password.is_empty() {
                        return Err(Error::invalid("Yuubinsya password cannot be empty"));
                    }
                    ValidatedNode::Yuubinsya(ValidatedYuubinsya {
                        password: config.password,
                        udp_over_stream: config.udp_over_stream,
                        udp_coalesce: config.udp_coalesce,
                    })
                }
                ChainNode::Http(config) => {
                    if index != last_index {
                        return Err(Error::invalid(
                            "HTTP destination protocol must be the last runnable chain node",
                        ));
                    }
                    ValidatedNode::Http(ValidatedHttp {
                        user: config.user,
                        password: config.password,
                    })
                }
                ChainNode::HttpProxy(config) => {
                    if index != last_index {
                        return Err(Error::invalid(
                            "HTTP destination protocol must be the last runnable chain node",
                        ));
                    }
                    ValidatedNode::HttpProxy(ValidatedHttp {
                        user: config.user,
                        password: config.password,
                    })
                }
                ChainNode::Socks5(config) => {
                    if index != last_index {
                        return Err(Error::invalid(
                            "socks5 must be the last runnable chain node",
                        ));
                    }
                    if !(0..=i32::from(u16::MAX)).contains(&config.override_port) {
                        return Err(Error::invalid("SOCKS5 override_port is out of range"));
                    }
                    ValidatedNode::Socks5(ValidatedSocks5 {
                        user: config.user,
                        password: config.password,
                        hostname: config.hostname,
                        override_port: config.override_port,
                    })
                }
                ChainNode::None => ValidatedNode::None,
                ChainNode::Proxy => ValidatedNode::Proxy,
                ChainNode::BootstrapDnsWarp => ValidatedNode::BootstrapDnsWarp,
            };
            validated.push(validated_node);
        }

        Ok(ValidatedChain {
            id,
            name,
            nodes: validated,
        })
    }
}

fn validate_fixed_addresses(config: FixedV2Config) -> Result<Vec<ValidatedFixedAddress>> {
    if config.addresses.is_empty() {
        return Err(Error::invalid("fixedv2 requires at least one address"));
    }
    config
        .addresses
        .into_iter()
        .map(|address| {
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
            Ok(ValidatedFixedAddress {
                host,
                port,
                network_interface,
            })
        })
        .collect()
}

fn validate_tls(config: TlsConfig, next: Option<&ChainNode>) -> Result<ValidatedTls> {
    if !config.enable {
        return Err(Error::invalid("TLS node must have enable=true"));
    }
    if config.servernames.is_empty() {
        return Err(Error::invalid("TLS node requires servernames"));
    }
    let mut ca_certificates = Vec::with_capacity(config.ca_cert.len());
    for (index, certificate) in config.ca_cert.iter().enumerate() {
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
    let next_protos = if config.next_protos.is_empty() {
        if matches!(next, Some(ChainNode::WebSocket(_))) {
            Vec::new()
        } else {
            vec!["h2".to_owned()]
        }
    } else {
        config.next_protos
    };
    if matches!(next, Some(ChainNode::Http2(_)))
        && !next_protos.iter().any(|protocol| protocol == "h2")
    {
        return Err(Error::invalid("HTTP/2 chain requires TLS ALPN h2"));
    }
    Ok(ValidatedTls {
        insecure_skip_verify: config.insecure_skip_verify,
        servernames: config
            .servernames
            .into_iter()
            .map(|name| name.replace("&lt;", "<").replace("&gt;", ">"))
            .collect(),
        ca_certificates,
        next_protos,
    })
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

    fn fixed(chain: &ValidatedChain) -> &ValidatedFixedConfig {
        chain
            .nodes
            .iter()
            .find_map(|node| match node {
                ValidatedNode::Fixed(config) => Some(config),
                _ => None,
            })
            .unwrap()
    }

    fn tls(chain: &ValidatedChain) -> &ValidatedTls {
        chain
            .nodes
            .iter()
            .find_map(|node| match node {
                ValidatedNode::Tls(config) => Some(config),
                _ => None,
            })
            .unwrap()
    }

    fn http2(chain: &ValidatedChain) -> &ValidatedHttp2 {
        chain
            .nodes
            .iter()
            .find_map(|node| match node {
                ValidatedNode::Http2(config) => Some(config),
                _ => None,
            })
            .unwrap()
    }

    fn yuubinsya(chain: &ValidatedChain) -> &ValidatedYuubinsya {
        chain
            .nodes
            .iter()
            .find_map(|node| match node {
                ValidatedNode::Yuubinsya(config) => Some(config),
                _ => None,
            })
            .unwrap()
    }

    fn final_http(chain: &ValidatedChain) -> Option<&ValidatedHttp> {
        chain.nodes.iter().rev().find_map(|node| match node {
            ValidatedNode::Http(config) | ValidatedNode::HttpProxy(config) => Some(config),
            _ => None,
        })
    }

    fn final_socks5(chain: &ValidatedChain) -> Option<&ValidatedSocks5> {
        chain.nodes.iter().rev().find_map(|node| match node {
            ValidatedNode::Socks5(config) => Some(config),
            _ => None,
        })
    }

    #[test]
    fn parses_and_validates_the_requested_chain_shape() {
        let chain = parse_config(CONFIG).unwrap();
        assert_eq!(
            fixed(&chain).addresses[0],
            ValidatedFixedAddress {
                host: "127.0.0.1".to_owned(),
                port: 12103,
                network_interface: None,
            }
        );
        assert_eq!(http2(&chain).concurrency, 8);
        assert_eq!(http2(&chain).max_streams, 128);
        assert!(yuubinsya(&chain).udp_over_stream);
        assert!(tls(&chain).server_name().ends_with(".mcdn.bilivideo.cn"));
    }

    #[test]
    fn preserves_repeated_transport_nodes_in_order() {
        let config = r#"
        {
          "chain": [
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"tls","tls":{"enable":true,"servernames":["inner.example"]}},
            {"type":"http2","http2":{"concurrency":2}},
            {"type":"tls","tls":{"enable":true,"servernames":["outer.example"]}},
            {"type":"http2","http2":{"concurrency":3}},
            {"type":"yuubinsya","yuubinsya":{"password":"secret"}}
          ]
        }
        "#;
        let chain = parse_config(config).unwrap();
        assert!(matches!(chain.nodes[0], ValidatedNode::Fixed(_)));
        assert!(matches!(chain.nodes[1], ValidatedNode::Tls(_)));
        assert!(matches!(
            chain.nodes[2],
            ValidatedNode::Http2(ValidatedHttp2 { concurrency: 2, .. })
        ));
        assert!(matches!(chain.nodes[3], ValidatedNode::Tls(_)));
        assert!(matches!(
            chain.nodes[4],
            ValidatedNode::Http2(ValidatedHttp2 { concurrency: 3, .. })
        ));
        assert!(matches!(chain.nodes[5], ValidatedNode::Yuubinsya(_)));
        crate::ChainClient::new(chain).unwrap();
    }

    #[test]
    fn accepts_direct_and_reordered_fixed_nodes() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        let fixed = value["chain"][0].clone();
        let tls = value["chain"][1].clone();
        value["chain"][0] = tls;
        value["chain"][1] = fixed;
        let chain = parse_config(&value.to_string()).unwrap();
        assert!(matches!(chain.nodes[0], ValidatedNode::Tls(_)));

        let direct = r#"
        {
          "chain": [
            {"type":"direct","direct":{}},
            {"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1:443"}]}},
            {"type":"tls","tls":{"enable":true,"servernames":["proxy.example"]}},
            {"type":"http2","http2":{}}
          ]
        }
        "#;
        let chain = parse_config(direct).unwrap();
        assert!(matches!(chain.nodes[0], ValidatedNode::Direct(_)));
        assert!(matches!(chain.nodes[1], ValidatedNode::Fixed(_)));
        crate::ChainClient::new(chain).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][3]["yuubinsya"]["password"] = serde_json::Value::String(String::new());
        assert!(parse_config(&value.to_string()).is_err());
    }

    #[test]
    fn accepts_public_ca_tls_without_custom_ca_certificates() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][1]["tls"]["ca_cert"] = serde_json::json!([]);
        let chain = parse_config(&value.to_string()).unwrap();
        assert!(tls(&chain).ca_certificates.is_empty());
    }

    #[test]
    fn preserves_go_insecure_skip_verify_tls_option() {
        let mut value: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        value["chain"][1]["tls"]["ca_cert"] = serde_json::json!([]);
        value["chain"][1]["tls"]["insecure_skip_verify"] = serde_json::json!(true);
        let chain = parse_config(&value.to_string()).unwrap();
        assert!(tls(&chain).insecure_skip_verify);
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
        assert!(tls(&chain).next_protos.is_empty());
        assert!(chain.nodes.iter().any(|node| matches!(
            node,
            ValidatedNode::WebSocket(ValidatedWebSocket {
                host,
                path
            }) if host == "proxy.example" && path == "/proxy/ws"
        )));
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
        assert_eq!(final_http(&parsed).unwrap().user, "user");
        assert!(final_socks5(&parsed).is_none());

        let http_proxy = http.replace(
            "\"type\":\"http\",\"http\"",
            "\"type\":\"http_proxy\",\"http_proxy\"",
        );
        let parsed = parse_config(&http_proxy).unwrap();
        assert_eq!(final_http(&parsed).unwrap().password, "pass");

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
        let socks5 = final_socks5(&parsed).unwrap();
        assert_eq!(socks5.hostname, "relay.example");
        assert_eq!(socks5.override_port, 8443);
        assert!(final_http(&parsed).is_none());
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
        assert!(
            !parsed
                .nodes
                .iter()
                .any(|node| matches!(node, ValidatedNode::Tls(_)))
        );
        assert_eq!(final_http(&parsed).unwrap().user, "");
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
