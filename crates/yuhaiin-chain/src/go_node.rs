//! Adapter from the Go node contract to the first runnable Rust chain.

use std::net::SocketAddr;

use serde_json::{Value, json};
use yuhaiin_core::{Error, ErrorKind, Result};

use crate::config::{ChainConfig, ValidatedChain};

/// Parse a Go `contract/node.Node` JSON payload into the currently runnable
/// Rust chain. Go stores fixed endpoints as `{host, port}` objects while the
/// first Rust chain uses `SocketAddr` strings, so this adapter normalizes only
/// that representation and leaves TLS/HTTP2/Yuubinsya fields intact.
pub fn parse_go_node(json_text: &str) -> Result<ValidatedChain> {
    let mut node: Value = serde_json::from_str(json_text)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, format!("Go node JSON: {error}")))?;
    let chain = node
        .get_mut("chain")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::invalid("Go node requires a chain array"))?;
    let normalized = chain
        .iter()
        .map(normalize_chain_node)
        .collect::<Result<Vec<_>>>()?;
    *chain = normalized;

    let config: ChainConfig = serde_json::from_value(node).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("Go node chain config: {error}"),
        )
    })?;
    config.validate()
}

fn normalize_chain_node(node: &Value) -> Result<Value> {
    let kind = node
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("Go chain node requires a string type"))?;
    if !matches!(kind, "fixed" | "simple" | "fixedv2") {
        return Ok(node.clone());
    }

    let source = node
        .get(kind)
        .or_else(|| node.get("fixedv2"))
        .or_else(|| node.get("fixed"))
        .or_else(|| node.get("simple"))
        .ok_or_else(|| Error::invalid(format!("Go {kind} node has no config")))?;
    let addresses = fixed_addresses(source)?;
    Ok(json!({
        "type": "fixedv2",
        "fixedv2": { "addresses": addresses },
    }))
}

fn fixed_addresses(source: &Value) -> Result<Vec<Value>> {
    if let Some(addresses) = source.get("addresses").and_then(Value::as_array) {
        return addresses.iter().map(endpoint_value).collect();
    }

    let mut values = Vec::new();
    if source.get("host").is_some() {
        values.push(endpoint_value(source)?);
    }
    if let Some(alternates) = source.get("alternate_host").and_then(Value::as_array) {
        values.extend(
            alternates
                .iter()
                .map(endpoint_value)
                .collect::<Result<Vec<_>>>()?,
        );
    }
    if values.is_empty() {
        return Err(Error::invalid(
            "Go fixed node requires addresses or host/port",
        ));
    }
    Ok(values)
}

fn endpoint_value(value: &Value) -> Result<Value> {
    if let Some(endpoint) = value.as_str() {
        return Ok(json!({ "host": endpoint }));
    }
    let object = value
        .as_object()
        .ok_or_else(|| Error::invalid("Go fixed address must be a string or object"))?;
    let host = object
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("Go fixed address requires host"))?;
    let port = object.get("port").and_then(Value::as_u64).unwrap_or(0);
    let endpoint = if host.parse::<SocketAddr>().is_ok() {
        host.to_owned()
    } else {
        if port == 0 || port > u64::from(u16::MAX) {
            return Err(Error::invalid(format!(
                "Go fixed address {host:?} requires a valid port"
            )));
        }
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    };
    Ok(json!({ "host": endpoint }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(fixed: Value) -> String {
        json!({
            "id": "go-node",
            "chain": [
                fixed,
                { "type": "tls", "tls": {
                    "enable": true,
                    "servernames": ["example.com"],
                    "ca_cert": ["Y2E="],
                    "next_protos": ["h2"]
                }},
                { "type": "http2", "http2": {
                    "concurrency": 2,
                    "max_streams": 8,
                    "idle_timeout_secs": 30
                }},
                { "type": "yuubinsya", "yuubinsya": {
                    "password": "secret",
                    "udp_over_stream": true,
                    "udp_coalesce": true
                }}
            ]
        })
        .to_string()
    }

    #[test]
    fn parses_go_fixedv2_host_port_and_keeps_chain_layers() {
        let parsed = parse_go_node(&chain(json!({
            "type": "fixedv2",
            "fixedv2": { "addresses": [{ "host": "127.0.0.1", "port": 12103 }] }
        })))
        .unwrap();
        assert_eq!(
            parsed.fixed_addresses,
            vec![crate::config::ValidatedFixedAddress {
                host: "127.0.0.1".to_owned(),
                port: 12103,
            }]
        );
        assert_eq!(parsed.http2.max_streams, 8);
        assert!(parsed.yuubinsya.as_ref().unwrap().udp_over_stream);
    }

    #[test]
    fn parses_go_fixed_alias_with_alternate_addresses_and_ipv6() {
        let parsed = parse_go_node(&chain(json!({
            "type": "fixed",
            "fixed": {
                "host": "2001:db8::1",
                "port": 443,
                "alternate_host": [{ "host": "127.0.0.1", "port": 8443 }]
            }
        })))
        .unwrap();
        assert_eq!(parsed.fixed_addresses.len(), 2);
        assert_eq!(parsed.fixed_addresses[0].host, "2001:db8::1");
        assert_eq!(parsed.fixed_addresses[0].port, 443);
        assert_eq!(parsed.fixed_addresses[1].host, "127.0.0.1");
        assert_eq!(parsed.fixed_addresses[1].port, 8443);
    }

    #[test]
    fn parses_real_go_node_protocol_shape() {
        let parsed = parse_go_node(
            &json!({
                    "id": "go-node",
                    "name": "production",
                    "group": "default",
                    "origin": "remote",
                    "enabled": true,
                    "chain": [
                        { "type": "fixedv2", "fixedv2": {
                        "addresses": [{ "host": "proxy.example", "port": 443 }]
                        }},
                    { "type": "tls", "tls": {
                        "enable": true,
                        "servernames": ["proxy.example"],
                        "ca_cert": ["AQ=="],
                        "next_protos": ["h2"]
                    }},
                    { "type": "http2", "http2": { "concurrency": 10 } },
                    { "type": "yuubinsya", "yuubinsya": {
                        "password": "secret",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }}
                ]
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(parsed.fixed_addresses[0].host, "proxy.example");
        assert_eq!(parsed.fixed_addresses[0].port, 443);
        assert_eq!(parsed.http2.concurrency, 10);
        assert!(parsed.yuubinsya.as_ref().unwrap().udp_coalesce);
    }

    #[test]
    fn rejects_go_fixed_address_without_port() {
        let error = parse_go_node(&chain(json!({
            "type": "fixedv2",
            "fixedv2": { "addresses": [{ "host": "proxy.example" }] }
        })))
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }

    #[test]
    fn accepts_standalone_http2_transport_without_yuubinsya() {
        let parsed = parse_go_node(
            &json!({
                "id": "http2-transport",
                "chain": [
                    { "type": "fixedv2", "fixedv2": {
                        "addresses": [{ "host": "127.0.0.1", "port": 8080 }]
                    }},
                    { "type": "http2", "http2": { "concurrency": 1 } }
                ]
            })
            .to_string(),
        )
        .unwrap();

        assert!(parsed.yuubinsya.is_none());
        assert_eq!(parsed.http2.concurrency, 1);
    }
}
