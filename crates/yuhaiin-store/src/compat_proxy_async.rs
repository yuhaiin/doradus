//! Async-core construction adapters for Go proxy runtime snapshots.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
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
        let Some(endpoint) = self.fixed_endpoint().transpose()? else {
            return Ok(None);
        };
        Ok(Some(resolve_endpoint(&endpoint, resolver).await?))
    }

    /// Convert a Go node whose base transport is implemented by core into the
    /// core factory input. Chain transports remain explicit unsupported values
    /// here and must go through `yuhaiin-chain::parse_go_node` instead.
    pub fn to_base_proxy_config(&self, timeout: Duration) -> Result<BaseProxyConfig> {
        self.ensure_base_transport()?;
        let address = self
            .fixed_endpoint()
            .transpose()?
            .map(|endpoint| resolve_socket_addr(&endpoint.text()))
            .transpose()?;
        Ok(BaseProxyConfig {
            kind: self.base_proxy_kind(address)?,
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
        let address = match self.fixed_endpoint().transpose()? {
            Some(endpoint) => Some(resolve_endpoint(&endpoint, resolver.as_ref()).await?),
            None => None,
        };
        Ok(BaseProxyConfig {
            kind: self.base_proxy_kind(address)?,
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

    fn fixed_endpoint(&self) -> Option<Result<ProxyEndpoint>> {
        match &self.transport {
            GoProxyTransport::Fixed
            | GoProxyTransport::HttpProxy
            | GoProxyTransport::Socks5
            | GoProxyTransport::Shadowsocks
            | GoProxyTransport::Shadowsocksr
            | GoProxyTransport::Trojan
            | GoProxyTransport::Vless
            | GoProxyTransport::Vmess
            | GoProxyTransport::Yuubinsya
            | GoProxyTransport::Aead => Some(fixed_endpoint(&self.layers)),
            _ => None,
        }
    }

    fn base_proxy_kind(&self, address: Option<SocketAddr>) -> Result<BaseProxyKind> {
        Ok(match &self.transport {
            GoProxyTransport::Direct => BaseProxyKind::Direct,
            GoProxyTransport::Drop => BaseProxyKind::Drop,
            GoProxyTransport::Fixed => BaseProxyKind::Fixed {
                address: address.ok_or_else(|| Error::invalid("fixed proxy has no endpoint"))?,
            },
            GoProxyTransport::HttpProxy => {
                let config = layer_config(&self.layers, "http")
                    .or_else(|_| layer_config(&self.layers, "http_proxy"))?;
                BaseProxyKind::Http {
                    proxy: address.ok_or_else(|| Error::invalid("HTTP proxy has no endpoint"))?,
                    username: optional_string(config, "user"),
                    password: optional_string(config, "password"),
                }
            }
            GoProxyTransport::Socks5 => {
                let config = layer_config(&self.layers, "socks5")?;
                BaseProxyKind::Socks5 {
                    proxy: address.ok_or_else(|| Error::invalid("SOCKS5 proxy has no endpoint"))?,
                    username: optional_string(config, "user"),
                    password: optional_string(config, "password"),
                }
            }
            GoProxyTransport::Shadowsocks
            | GoProxyTransport::Shadowsocksr
            | GoProxyTransport::Trojan
            | GoProxyTransport::Vless
            | GoProxyTransport::Vmess => BaseProxyKind::Fixed {
                address: address.ok_or_else(|| Error::invalid("proxy protocol has no endpoint"))?,
            },
            GoProxyTransport::Aead => BaseProxyKind::Fixed {
                address: address.ok_or_else(|| Error::invalid("AEAD proxy has no endpoint"))?,
            },
            GoProxyTransport::Yuubinsya => {
                let config = layer_config(&self.layers, "yuubinsya")?;
                let password = required_string(config, "password")?;
                BaseProxyKind::YuubinsyaUdp {
                    server: address
                        .ok_or_else(|| Error::invalid("Yuubinsya proxy has no endpoint"))?,
                    password_hash: yuhaiin_core::yuubinsya::derive_salt(password.as_bytes()),
                    socks5_prefix: config
                        .get("socks5_prefix")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                }
            }
            GoProxyTransport::Wireguard => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "WireGuard is a stateful userspace tunnel and must be built by yuhaiin-runtime",
                ));
            }
            GoProxyTransport::Tls | GoProxyTransport::Http2 | GoProxyTransport::Unknown { .. } => {
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
        GoProxyTransport::Drop => "drop",
        GoProxyTransport::Fixed => "fixed",
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
        GoProxyTransport::Tls => "tls",
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

fn fixed_endpoint(layers: &[GoProxyLayer]) -> Result<ProxyEndpoint> {
    let config = layers
        .iter()
        .find(|layer| matches!(layer.kind.as_str(), "fixed" | "simple" | "fixedv2"))
        .map(|layer| &layer.config)
        .ok_or_else(|| Error::invalid("Go proxy chain has no fixed endpoint layer"))?;
    if let Some(addresses) = config
        .get("addresses")
        .and_then(serde_json::Value::as_array)
    {
        return addresses
            .first()
            .ok_or_else(|| Error::invalid("Go fixed endpoint addresses is empty"))
            .and_then(proxy_endpoint_value);
    }
    proxy_endpoint_value(config)
}

fn proxy_endpoint_value(value: &serde_json::Value) -> Result<ProxyEndpoint> {
    if let Some(value) = value.as_str() {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(ProxyEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
            });
        }
        let (host, port) = split_endpoint_text(value)?;
        return Ok(ProxyEndpoint { host, port });
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

async fn resolve_endpoint(
    endpoint: &ProxyEndpoint,
    resolver: &dyn AsyncIpResolver,
) -> Result<SocketAddr> {
    if let Ok(address) = endpoint.text().parse() {
        return Ok(address);
    }
    let domain = DomainName::new(&endpoint.host)?;
    let addresses = resolver
        .resolve(&domain, yuhaiin_core::ResolveStrategy::Default)
        .await?;
    addresses
        .iter()
        .next()
        .map(|address| SocketAddr::new(address, endpoint.port))
        .ok_or_else(|| Error::invalid(format!("proxy endpoint {} resolved to no address", domain)))
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
