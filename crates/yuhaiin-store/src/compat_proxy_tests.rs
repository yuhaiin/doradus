//! Go compatibility proxy tests.

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
    let built =
        runtime
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
    let built =
        runtime
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
