//! Async-core construction adapters for Go proxy runtime snapshots.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyEndpoint, BaseProxyKind};
use yuhaiin_core::{DomainName, Error, ErrorKind, Result};

use crate::{GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};

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
                let password_hash = yuhaiin_core::yuubinsya::derive_salt(password.as_bytes());
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
                password_hash: yuhaiin_core::yuubinsya::derive_salt(b"password"),
                socks5_prefix: false,
            }
        );
    }
}
