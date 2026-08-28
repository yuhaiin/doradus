//! Go-compatible connection JSON and telemetry projection.
//!
//! The monitor owns live flow state and persistence scheduling; this module
//! owns the public connection shape and the stable telemetry dimensions that
//! are derived from it.

use super::*;

pub(super) fn connection_value(id: &str, flow: TunFlow, context: &FlowContext) -> Value {
    let destination = endpoint_string(&context.effective_destination());
    let is_tun = context.component.as_deref() == Some("tun");
    // Socket-backed HTTP inbounds keep a placeholder packet tuple while the
    // parsed CONNECT authority lives in `original_domain`. Report that
    // authority as Go does. The same applies to SOCKS5 UDP after the resolver
    // has filled in the packet tuple: using `FlowKey::endpoint()` there leaks
    // `udp://` and the resolved IP instead of the user's original authority.
    // TUN keeps its packet-level endpoint contract, including the network
    // prefix, so this normalization is limited to socket-backed inbounds.
    let use_original_authority = context.original_domain.is_some()
        && ((!is_tun && context.inbound.is_some()) || flow.key.destination.ip().is_unspecified());
    let original = if use_original_authority {
        destination.clone()
    } else {
        flow.key.endpoint().to_string()
    };
    let source = endpoint_string(&flow.key.source_endpoint());
    let local_addr = context
        .outbound_local_addr
        .as_ref()
        .and_then(Endpoint::addr)
        .map(|address| address.to_string())
        .unwrap_or_default();
    let underlying_type = context
        .outbound_local_addr
        .as_ref()
        .map(|endpoint| endpoint.network().to_string())
        .unwrap_or_default();
    let domain = (is_tun || context.inbound.is_none())
        .then(|| context.original_domain.as_ref().map(ToString::to_string))
        .flatten()
        .unwrap_or_default();
    let inbound = context
        .inbound
        .as_deref()
        .or_else(|| is_tun.then_some("tun"))
        .unwrap_or_default();
    let inbound_name = context
        .inbound_name
        .as_deref()
        .or_else(|| is_tun.then_some("TUN"))
        .unwrap_or_default();
    let outbound = context
        .outbound_addr
        .as_ref()
        .and_then(Endpoint::addr)
        .map(|address| address.to_string())
        .unwrap_or_default();
    json!({
        "id": id,
        "addr": destination,
        "network": {"connType": flow.key.network.to_string(), "underlyingType": underlying_type},
        "source": source,
        "inbound": inbound,
        "inboundName": inbound_name,
        "inboundId": context.inbound_id.as_deref().unwrap_or_default(),
        "interface": context.interface.as_deref().unwrap_or_default(),
        "outbound": outbound,
        "localAddr": local_addr,
        "destination": original,
        "fakeIp": context.fake_ip.as_deref().unwrap_or_default(),
        "hosts": context.hosts.as_deref().unwrap_or_default(),
        "domain": domain,
        "ip": context
            .resolved_destination
            .as_ref()
            .and_then(Endpoint::addr)
            .or_else(|| {
                context
                    .fake_ip
                    .is_none()
                    .then(|| context.destination.addr())
                    .flatten()
            })
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default(),
        "tag": context.tag.as_deref().unwrap_or_default(),
        "nodeId": context.outbound.as_deref().unwrap_or_default(),
        "nodeName": context.outbound_name.as_deref().unwrap_or_default(),
        "protocol": context.protocol.as_deref().unwrap_or_default(),
        "process": context.process.as_deref().unwrap_or_default(),
        "pid": context.process_id.map(|value| value.to_string()).unwrap_or_default(),
        "uid": context.user_id.map(|value| value.to_string()).unwrap_or_default(),
        "tlsServerName": context.tls_server_name.as_deref().unwrap_or_default(),
        "httpHost": context.http_host.as_deref().unwrap_or_default(),
        "component": context.component.as_deref().unwrap_or_default(),
        "udpMigrateId": match context.udp_migrate_id.load(std::sync::atomic::Ordering::Relaxed) {
            0 => "".to_owned(),
            value => value.to_string(),
        },
        "mode": route_mode(context.route_mode),
        "matchHistory": context
            .match_history
            .iter()
            .map(|entry| json!({
                "ruleName": entry.rule_name,
                "history": entry.history.iter().map(|item| json!({
                    "listName": item.list_name,
                    "matched": item.matched,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "resolver": context.resolver.as_deref().unwrap_or_default(),
        "geo": context.geo.as_deref().unwrap_or_default(),
        "outboundGeo": context.outbound_geo.as_deref().unwrap_or_default(),
        "lists": context.lists,
    })
}

pub(super) fn merge_connection_metadata(target: &mut Value, update: Value) -> bool {
    fn merge_value(target: &mut Value, update: Value) -> bool {
        match (target, update) {
            (Value::Object(target), Value::Object(update)) => {
                let mut changed = false;
                for (key, value) in update {
                    if key == "id" || value_is_empty(&value) {
                        continue;
                    }
                    match target.get_mut(&key) {
                        Some(existing) => changed |= merge_value(existing, value),
                        None => {
                            target.insert(key, value);
                            changed = true;
                        }
                    }
                }
                changed
            }
            (target, update) if *target != update => {
                *target = update;
                true
            }
            _ => false,
        }
    }

    fn value_is_empty(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::String(value) => value.is_empty(),
            Value::Array(value) => value.is_empty(),
            Value::Object(value) => value.is_empty(),
            Value::Bool(_) | Value::Number(_) => false,
        }
    }

    merge_value(target, update)
}

pub(super) fn telemetry_dimensions(connection: &Value) -> Vec<(String, String)> {
    let protocol = connection
        .pointer("/network/connType")
        .and_then(Value::as_str)
        .or_else(|| connection.get("protocol").and_then(Value::as_str))
        .unwrap_or_default();
    let inbound = first_non_empty(&[
        string_field(connection, "inboundName"),
        string_field(connection, "inbound"),
    ]);
    let source = normalize_telemetry_source(&string_field(connection, "source"));
    let addr = telemetry_addr(connection);
    let outbound = first_non_empty(&[
        string_field(connection, "nodeName"),
        string_field(connection, "nodeId"),
        string_field(connection, "outbound"),
    ]);
    let process = string_field(connection, "process");
    let tag = string_field(connection, "tag");
    let destination = telemetry_destination(connection);

    let mut values = Vec::with_capacity(9);
    for (dimension, value) in [
        ("addr", addr),
        ("destination", destination),
        ("inbound", inbound),
        ("outbound", outbound),
        ("process", process),
        ("protocol", protocol.to_owned()),
        ("source", source),
        ("tag", tag),
    ] {
        if !value.is_empty() {
            values.push((dimension.to_owned(), value));
        }
    }
    if let Some(rule) = connection
        .get("matchHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|match_value| match_value.get("ruleName").and_then(Value::as_str))
        .rfind(|rule| !rule.is_empty())
    {
        let insert_at = values
            .iter()
            .position(|(dimension, _)| dimension.as_str() > "rule")
            .unwrap_or(values.len());
        values.insert(insert_at, ("rule".to_owned(), rule.to_owned()));
    }
    values
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn telemetry_addr(connection: &Value) -> String {
    let addr = string_field(connection, "addr");
    let fake_ip = string_field(connection, "fakeIp");
    if !fake_ip.is_empty() && telemetry_host(&addr) == telemetry_host(&fake_ip) {
        return first_non_empty(&[
            string_field(connection, "domain"),
            string_field(connection, "hosts"),
        ]);
    }
    addr
}

pub(super) fn telemetry_destination(connection: &Value) -> String {
    if !string_field(connection, "fakeIp").is_empty() {
        return String::new();
    }
    first_non_empty(&[
        string_field(connection, "domain"),
        string_field(connection, "hosts"),
        string_field(connection, "destination"),
        string_field(connection, "addr"),
    ])
}

fn telemetry_host(value: &str) -> String {
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return address.ip().to_string();
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && is_decimal(port)
    {
        return host.trim_matches(['[', ']']).to_owned();
    }
    value.trim_matches(&['[', ']'][..]).to_owned()
}

pub(super) fn normalize_telemetry_source(value: &str) -> String {
    let mut value = value.trim().to_owned();
    if let Some(rest) = value.strip_prefix("http2.h-")
        && let Some(marker) = rest.find("-2")
    {
        value = rest[marker + 2..].to_owned();
    }
    if let Some(left) = value.rfind('[')
        && let Some(right) = value[left + 1..].find(']')
    {
        return value[left + 1..left + 1 + right].to_owned();
    }
    if value.matches(':').count() == 1
        && let Some(colon) = value.rfind(':')
        && colon > 0
        && colon + 1 < value.len()
        && is_decimal(&value[colon + 1..])
    {
        return value[..colon].to_owned();
    }
    value
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn normalize_persisted_telemetry_value(dimension: &str, value: String) -> String {
    if dimension == "source" {
        normalize_telemetry_source(&value)
    } else {
        value
    }
}

fn endpoint_string(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
}

fn route_mode(mode: RouteMode) -> &'static str {
    match mode {
        RouteMode::Bypass => "bypass",
        RouteMode::Proxy => "proxy",
        RouteMode::Direct => "direct",
        RouteMode::Block => "block",
    }
}

pub(super) fn traffic_bucket_start(interval: &str, timestamp: i64) -> i64 {
    let datetime =
        OffsetDateTime::from_unix_timestamp(timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    match interval {
        "day" => datetime
            .date()
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
            .unix_timestamp(),
        "month" => time::Date::from_calendar_date(datetime.year(), datetime.month(), 1)
            .expect("a valid timestamp has a valid calendar date")
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
            .unix_timestamp(),
        _ => timestamp.div_euclid(3_600) * 3_600,
    }
}
