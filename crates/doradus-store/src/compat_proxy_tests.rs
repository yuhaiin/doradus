//! Go compatibility proxy tests.

use super::*;

#[test]
fn proxy_transport_owns_aliases_names_and_lifecycle_classification() {
    assert_eq!(GoProxyTransport::parse("fixedv2"), GoProxyTransport::Fixed);
    assert_eq!(GoProxyTransport::parse("OVPN"), GoProxyTransport::Openvpn);
    assert_eq!(GoProxyTransport::Openvpn.as_str(), "openvpn");
    assert!(GoProxyTransport::Wireguard.is_stateful_tunnel());
    assert!(GoProxyTransport::Openvpn.is_stateful_tunnel());
    assert!(GoProxyTransport::WarpMasque.is_stateful_tunnel());
    assert!(!GoProxyTransport::Direct.is_stateful_tunnel());
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
    let endpoints = config.base_proxy_endpoints().unwrap();
    assert_eq!(
        endpoints,
        vec![
            GoProxyEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 18080,
                bind_interface: Some("lo".to_owned()),
            },
            GoProxyEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 18081,
                bind_interface: Some("lo".to_owned()),
            },
        ]
    );
}

#[test]
fn openvpn_layer_serialization_redacts_every_profile_alias() {
    for field in ["profile", "config", "content", "ovpn"] {
        let layer = GoProxyLayer {
            kind: "openvpn".to_owned(),
            config: serde_json::json!({
                field: "client\n<key>private</key>",
                "username": "alice",
                "password": "secret"
            }),
        };

        let serialized = serde_json::to_value(layer).unwrap();
        assert_eq!(serialized["config"][field], "***", "alias {field}");
        assert_eq!(serialized["config"]["username"], "alice");
        assert_eq!(serialized["config"]["password"], "***");
        assert!(!serialized.to_string().contains("private"));
        assert!(!serialized.to_string().contains("secret"));
    }
}
