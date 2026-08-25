use super::*;

pub fn node_json(record: GoNodeRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    if let Some(object) = value.as_object_mut() {
        // `hash` is the legacy node-store key. It is not part of Go's public
        // contract.Node even though old v1 migrations retain it in the raw
        // JSON used by the runtime.
        object.remove("hash");
    }
    strip_go_internal_node_fields(&mut value);
    normalize_go_node_optional_zero_fields(&mut value);
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_string(&mut value, "group", record.group_name);
    set_string(&mut value, "origin", record.origin);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

pub fn normalize_go_node_optional_zero_fields(value: &mut Value) {
    let Some(chain) = value.get_mut("chain").and_then(Value::as_array_mut) else {
        return;
    };
    for protocol in chain {
        let Some(protocol_object) = protocol.as_object_mut() else {
            continue;
        };
        let Some(kind) = protocol_object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(config) = protocol_object
            .get_mut(&kind)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let optional_fields: &[&str] = match kind.as_str() {
            "direct" => &["network_interface"],
            "simple" | "fixed" => &["port", "alternate_host", "network_interface"],
            "fixedv2" => &["addresses", "udp_happy_eyeballs"],
            "socks5" => &["override_port"],
            "yuubinsya" => &["udp_over_stream", "udp_coalesce"],
            "http2" | "mux" => &["concurrency"],
            "reality" => &["mldsa65_verify", "short_id", "debug"],
            "tls" => &[
                "servernames",
                "ca_cert",
                "insecure_skip_verify",
                "next_protos",
                "ech_config",
            ],
            "wireguard" => &["endpoint", "peers", "mtu", "reserved"],
            "tailscale" => &["debug"],
            "set" => &["nodes", "strategy"],
            "http_mock" => &["data"],
            "cloudflare_warp_masque" => &["local_addresses", "mtu"],
            _ => &[],
        };
        for field in optional_fields {
            if config.get(*field).is_some_and(json_value_is_go_zero) {
                config.remove(*field);
            }
        }
    }
}

pub fn strip_go_internal_node_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("userId");
            for child in object.values_mut() {
                strip_go_internal_node_fields(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_go_internal_node_fields(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

pub fn inbound_json(record: GoInboundRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    normalize_go_inbound_public_json(&mut value);
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

pub fn normalize_go_inbound_public_json(value: &mut Value) {
    if let Some(network) = value.get_mut("network").and_then(Value::as_object_mut)
        && let Some(tcp_udp) = network.get_mut("tcp_udp").and_then(Value::as_object_mut)
    {
        // These fields belong to the runtime/network adapter, not Go's
        // public contract.TCPUDPNetwork.
        tcp_udp.remove("control");
        tcp_udp.remove("udp_happy_eyeballs");
    }

    let Some(protocol) = value.get_mut("protocol").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(kind) = protocol
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    let Some(config) = protocol.get_mut(&kind).and_then(Value::as_object_mut) else {
        return;
    };

    for (legacy, public) in [
        ("force_fakeip", "forceFakeIp"),
        ("portal_v6", "portalV6"),
        ("post_up", "postUp"),
        ("post_down", "postDown"),
        ("skip_multicast", "skipMulticast"),
        ("udp_coalesce", "udpCoalesce"),
    ] {
        rename_json_field(config, legacy, public);
    }
    config.remove("platform");

    if kind == "tun" {
        if let Some(route) = config
            .remove("route")
            .and_then(|value| value.as_object().cloned())
        {
            if !config.contains_key("routes") {
                config.insert(
                    "routes".to_owned(),
                    route.get("routes").cloned().unwrap_or_else(|| json!([])),
                );
            }
            if !config.contains_key("excludes") {
                config.insert(
                    "excludes".to_owned(),
                    route.get("excludes").cloned().unwrap_or_else(|| json!([])),
                );
            }
        }
        for (field, default) in [
            ("forceFakeIp", json!(false)),
            ("skipMulticast", json!(false)),
            ("portalV6", json!("")),
            ("routes", json!([])),
            ("excludes", json!([])),
            ("postUp", json!([])),
            ("postDown", json!([])),
        ] {
            config.entry(field.to_owned()).or_insert(default);
        }
    } else if kind == "yuubinsya"
        && config
            .get("udpCoalesce")
            .is_none_or(|value| value.is_null())
    {
        config.insert("udpCoalesce".to_owned(), json!(false));
    }
}

pub fn resolver_json(record: GoResolverRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    if let Some(object) = value.as_object_mut() {
        // `tls_servername` is a legacy SQLite column spelling, not part of
        // Go's public resolver contract. The camel-case field is contract
        // data, but `omitzero` removes it (and subnet) when empty.
        object.remove("tls_servername");
        for field in ["subnet", "tlsServerName", "system"] {
            if object.get(field).is_some_and(json_value_is_go_zero) {
                object.remove(field);
            }
        }
    }
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "type", record.resolver_type);
    set_string(&mut value, "host", record.host);
    if value.get("id").and_then(Value::as_str) == Some("bootstrap") {
        set_bool(&mut value, "system", true);
    }
    value
}
