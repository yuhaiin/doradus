//! Runtime compilation of persisted Go base-proxy specifications.
//!
//! `doradus-store` parses the persisted endpoint shape without performing I/O.
//! This module owns DNS policy, protocol factory types and runtime-only
//! validation so storage remains independent from network construction.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use doradus_protocol::proxy_factory::{BaseProxyConfig, BaseProxyEndpoint, BaseProxyKind};
use doradus_store::{GoProxyEndpoint, GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
use doradus_types::{AsyncIpResolver, DomainName, Error, ErrorKind, ResolveStrategy, Result};

pub(super) async fn compile_base_proxy_config(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: &dyn AsyncIpResolver,
) -> Result<BaseProxyConfig> {
    ensure_base_transport(config)?;
    let endpoints = resolve_base_endpoints(config, resolver).await?;
    Ok(BaseProxyConfig {
        kind: compile_base_proxy_kind(config, endpoints)?,
        timeout,
    })
}

pub(super) async fn resolve_fixed_endpoint(
    config: &GoProxyRuntimeConfig,
    resolver: &dyn AsyncIpResolver,
) -> Result<Option<SocketAddr>> {
    let Some(endpoint) = config.base_proxy_endpoints()?.into_iter().next() else {
        return Ok(None);
    };
    Ok(resolve_endpoint(&endpoint, resolver)
        .await?
        .into_iter()
        .next())
}

async fn resolve_base_endpoints(
    config: &GoProxyRuntimeConfig,
    resolver: &dyn AsyncIpResolver,
) -> Result<Vec<BaseProxyEndpoint>> {
    let mut resolved = Vec::new();
    for endpoint in config.base_proxy_endpoints()? {
        for address in resolve_endpoint(&endpoint, resolver).await? {
            resolved.push(BaseProxyEndpoint {
                address,
                bind_interface: endpoint.bind_interface.clone(),
            });
        }
    }
    Ok(resolved)
}

async fn resolve_endpoint(
    endpoint: &GoProxyEndpoint,
    resolver: &dyn AsyncIpResolver,
) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = endpoint.socket_text().parse() {
        return Ok(vec![address]);
    }
    let domain = DomainName::new(&endpoint.host)?;
    let addresses = resolver.resolve(&domain, ResolveStrategy::Default).await?;
    let addresses = addresses
        .iter()
        .map(|address| SocketAddr::new(address, endpoint.port))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(Error::invalid(format!(
            "proxy endpoint {domain} resolved to no address"
        )));
    }
    Ok(addresses)
}

fn ensure_base_transport(config: &GoProxyRuntimeConfig) -> Result<()> {
    if config.chain_types.iter().any(|kind| {
        matches!(kind.to_ascii_lowercase().as_str(), "http2")
            || (kind.eq_ignore_ascii_case("websocket")
                && !matches!(
                    config.transport,
                    GoProxyTransport::Trojan | GoProxyTransport::Vless | GoProxyTransport::Vmess
                ))
            || (kind.eq_ignore_ascii_case("tls")
                && !matches!(
                    config.transport,
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
            "Go TLS/HTTP2/WebSocket chain requires doradus-chain runtime construction",
        ));
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("yuubinsya"))
    {
        let yuubinsya = layer_config(&config.layers, "yuubinsya")?;
        if yuubinsya
            .get("udp_over_stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya UDP-over-stream requires doradus-chain runtime construction",
            ));
        }
    }
    Ok(())
}

fn compile_base_proxy_kind(
    config: &GoProxyRuntimeConfig,
    endpoints: Vec<BaseProxyEndpoint>,
) -> Result<BaseProxyKind> {
    let single_address = || {
        (endpoints.len() == 1 && endpoints[0].bind_interface.is_none())
            .then(|| endpoints[0].address)
    };
    Ok(match &config.transport {
        GoProxyTransport::Direct => BaseProxyKind::Direct,
        GoProxyTransport::Reject => BaseProxyKind::Reject,
        GoProxyTransport::Drop => BaseProxyKind::Drop,
        GoProxyTransport::Fixed | GoProxyTransport::HttpMock => match single_address() {
            Some(address) => BaseProxyKind::Fixed { address },
            None => BaseProxyKind::FixedMany { endpoints },
        },
        GoProxyTransport::HttpProxy => {
            let http = layer_config(&config.layers, "http")
                .or_else(|_| layer_config(&config.layers, "http_proxy"))?;
            let username = optional_string(http, "user");
            let password = optional_string(http, "password");
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
            let socks5 = layer_config(&config.layers, "socks5")?;
            let username = optional_string(socks5, "user");
            let password = optional_string(socks5, "password");
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
        | GoProxyTransport::Vmess
        | GoProxyTransport::Aead => match single_address() {
            Some(address) => BaseProxyKind::Fixed { address },
            None => BaseProxyKind::FixedMany { endpoints },
        },
        GoProxyTransport::Yuubinsya => {
            if config
                .layers
                .iter()
                .any(|layer| layer.kind.eq_ignore_ascii_case("quic"))
            {
                let endpoint = endpoints
                    .first()
                    .ok_or_else(|| Error::invalid("QUIC transport requires a server endpoint"))?;
                let (server_name, ca_certificates, insecure_skip_verify) =
                    quic_settings(config, endpoint.address)?;
                return Ok(match single_address() {
                    Some(server) => BaseProxyKind::Quic {
                        server,
                        server_name,
                        ca_certificates,
                        insecure_skip_verify,
                    },
                    None => BaseProxyKind::QuicMany {
                        endpoints,
                        server_name,
                        ca_certificates,
                        insecure_skip_verify,
                    },
                });
            }
            let yuubinsya = layer_config(&config.layers, "yuubinsya")?;
            let password = required_string(yuubinsya, "password")?;
            let password_hash = doradus_protocol::yuubinsya::derive_salt(password.as_bytes());
            let socks5_prefix = yuubinsya
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
        GoProxyTransport::Quic => {
            let endpoint = endpoints
                .first()
                .ok_or_else(|| Error::invalid("QUIC transport requires a server endpoint"))?;
            let (server_name, ca_certificates, insecure_skip_verify) =
                quic_settings(config, endpoint.address)?;
            match single_address() {
                Some(server) => BaseProxyKind::Quic {
                    server,
                    server_name,
                    ca_certificates,
                    insecure_skip_verify,
                },
                None => BaseProxyKind::QuicMany {
                    endpoints,
                    server_name,
                    ca_certificates,
                    insecure_skip_verify,
                },
            }
        }
        GoProxyTransport::Wireguard => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "WireGuard is a stateful userspace tunnel and must be built by doradus-runtime",
            ));
        }
        GoProxyTransport::Openvpn => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "OpenVPN is a stateful userspace tunnel and must be built by doradus-runtime",
            ));
        }
        GoProxyTransport::WarpMasque => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "WARP MASQUE is a stateful userspace tunnel and must be built by doradus-runtime",
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
                    "{} is a chain transport; use doradus-chain runtime construction",
                    config.transport.as_str()
                ),
            ));
        }
    })
}

fn quic_settings(
    config: &GoProxyRuntimeConfig,
    server: SocketAddr,
) -> Result<(String, Vec<Vec<u8>>, bool)> {
    let layer = layer_config(&config.layers, "quic")?;
    let tls = layer.get("tls").unwrap_or(layer);
    let server_name = tls
        .get("servernames")
        .or_else(|| tls.get("serverNames"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.iter().find_map(serde_json::Value::as_str))
        .or_else(|| tls.get("server_name").and_then(serde_json::Value::as_str))
        .or_else(|| tls.get("serverName").and_then(serde_json::Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| server.ip().to_string());
    let mut ca_certificates = Vec::new();
    if let Some(certificates) = tls
        .get("ca_cert")
        .or_else(|| tls.get("caCert"))
        .and_then(serde_json::Value::as_array)
    {
        for (index, certificate) in certificates.iter().enumerate() {
            let encoded = certificate
                .as_str()
                .ok_or_else(|| Error::invalid(format!("QUIC ca_cert[{index}] must be a string")))?;
            let certificate = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("QUIC ca_cert[{index}] is not base64: {error}"),
                    )
                })?;
            if certificate.is_empty() {
                return Err(Error::invalid("QUIC CA certificate cannot be empty"));
            }
            ca_certificates.push(certificate);
        }
    }
    let insecure_skip_verify = tls
        .get("insecure_skip_verify")
        .or_else(|| tls.get("insecureSkipVerify"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok((server_name, ca_certificates, insecure_skip_verify))
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use doradus_types::{BoxFuture, IpSet};

    use super::*;

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 44)],
                    v6: Vec::new(),
                })
            })
        }
    }

    #[tokio::test]
    async fn compiles_domain_fixed_proxy_with_injected_resolver() {
        let config = test_config(
            GoProxyTransport::Fixed,
            vec![GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{ "host": "proxy.example", "port": 443 }]
                }),
            }],
        );
        let built = compile_base_proxy_config(&config, Duration::from_secs(3), &StaticResolver)
            .await
            .unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::Fixed {
                address: "192.0.2.44:443".parse().unwrap()
            }
        );
    }

    #[tokio::test]
    async fn compiles_quic_endpoint_and_tls_settings() {
        let config = test_config(
            GoProxyTransport::Quic,
            vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{ "host": "wrong.example", "port": 443 }]
                    }),
                },
                GoProxyLayer {
                    kind: "quic".to_owned(),
                    config: serde_json::json!({
                        "host": "quic.example:784",
                        "tls": {
                            "serverName": "edge.example",
                            "caCert": [base64::engine::general_purpose::STANDARD.encode(b"ca")]
                        }
                    }),
                },
            ],
        );
        let built = compile_base_proxy_config(&config, Duration::from_secs(3), &StaticResolver)
            .await
            .unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::Quic {
                server: "192.0.2.44:784".parse().unwrap(),
                server_name: "edge.example".to_owned(),
                ca_certificates: vec![b"ca".to_vec()],
                insecure_skip_verify: false,
            }
        );
    }

    #[tokio::test]
    async fn compiles_native_yuubinsya_udp_credentials() {
        let config = test_config(
            GoProxyTransport::Yuubinsya,
            vec![
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
        );
        let built = compile_base_proxy_config(&config, Duration::from_secs(3), &StaticResolver)
            .await
            .unwrap();
        assert_eq!(
            built.kind,
            BaseProxyKind::YuubinsyaUdp {
                server: "192.0.2.44:40501".parse().unwrap(),
                password_hash: doradus_protocol::yuubinsya::derive_salt(b"password"),
                socks5_prefix: false,
            }
        );
    }

    fn test_config(transport: GoProxyTransport, layers: Vec<GoProxyLayer>) -> GoProxyRuntimeConfig {
        GoProxyRuntimeConfig {
            id: "test".to_owned(),
            name: "test".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: layers.iter().map(|layer| layer.kind.clone()).collect(),
            layers,
            transport,
            data_json: Vec::new(),
        }
    }
}
