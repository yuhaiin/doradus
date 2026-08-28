//! Conversion from the persisted Go route-rule shape to the trie runtime.
//!
//! The store keeps the original JSON payload for forward compatibility.  This
//! module is deliberately strict at the runtime boundary: a rule that cannot
//! be represented by the current domain/CIDR router is reported instead of
//! silently becoming a different rule.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use doradus_core::GeoLookup;
use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::proxy::{AsyncProxy, BoxAsyncStream};
use doradus_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, ResolveStrategy,
    ResolverPolicy, Result,
};
use doradus_store::{GoRouteListRecord, GoRouteRuleRecord};
use doradus_trie::HostTrie;
use doradus_trie::router::{RouteDecision, RouteRule, Router, RouterRuntime, RuleAction};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[path = "route_lists.rs"]
mod route_lists;
pub use route_lists::*;

#[path = "route_expressions.rs"]
mod route_expressions;
use route_expressions::*;

pub fn compile_go_route_rules(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
) -> Result<RouterRuntime> {
    compile_go_route_rules_with_lists(records, &RouteListSnapshot::default(), fallback, None)
}

pub fn compile_go_route_rules_with_geo(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
) -> Result<RouterRuntime> {
    compile_go_route_rules_with_lists(records, &RouteListSnapshot::default(), fallback, geo)
}

pub fn compile_go_route_rules_with_lists(
    records: &[GoRouteRuleRecord],
    lists: &RouteListSnapshot,
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
) -> Result<RouterRuntime> {
    let mut rules = Vec::with_capacity(records.len());
    for record in records {
        rules.extend(expand_go_route_rule(record, lists)?);
    }
    let router = Router::compile(rules, fallback)?;
    let router = match geo {
        Some(geo) => router.with_geo_lookup(geo),
        None => router,
    };
    Ok(RouterRuntime::new(router))
}

pub fn expand_go_route_rule(
    record: &GoRouteRuleRecord,
    lists: &RouteListSnapshot,
) -> Result<Vec<RouteRule>> {
    if record.disabled {
        return Ok(Vec::new());
    }
    let root: Value = serde_json::from_slice(&record.data_json).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} has invalid data_json: {error}", record.id),
        )
    })?;
    let Some(expressions) = root.get("rules").and_then(Value::as_array) else {
        return Ok(route_rule_from_root(record, &root)?.into_iter().collect());
    };
    let action = parse_action(&record.action_mode, &root, record.id.as_str())?;
    let resolver_policy = parse_resolver_policy(&root, &root, action, record.id.as_str())?;
    let priority = i32::try_from(record.priority).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} priority is outside i32", record.id),
        )
    })?;
    let variants = if expressions.is_empty() {
        vec![RuleVariant::default()]
    } else {
        let mut variants = Vec::new();
        for expression in expressions {
            variants.extend(parse_rule_expression(
                expression,
                lists,
                record.id.as_str(),
            )?);
        }
        variants
    };
    if variants.is_empty() {
        // Go keeps a rule whose referenced list is unavailable and simply
        // makes that matcher return false until the list is refreshed.
        return Ok(Vec::new());
    }
    variants
        .into_iter()
        .map(|variant| {
            Ok(RouteRule {
                rule_name: record.name.clone(),
                tag: record.tag.clone(),
                list_names: variant.list_names,
                pattern: variant.pattern.clone().unwrap_or_default(),
                host_lists: variant.host_lists,
                required_patterns: compile_required_patterns(
                    variant.additional_patterns,
                    record.id.as_str(),
                )?,
                always_false: variant.always_false,
                action,
                network: variant.network,
                excluded_networks: variant.excluded_networks,
                port: variant.port,
                excluded_ports: variant.excluded_ports,
                geo_country: variant.geo_country,
                excluded_geo_countries: variant.excluded_geo_countries,
                inbound_names: variant.inbound_names.unwrap_or_default(),
                excluded_inbound_names: variant.excluded_inbound_names.unwrap_or_default(),
                process_names: variant.process_names.unwrap_or_default(),
                excluded_process_names: variant.excluded_process_names.unwrap_or_default(),
                excluded_patterns: compile_excluded_patterns(
                    variant.excluded_patterns,
                    record.id.as_str(),
                )?,
                excluded_host_lists: variant.excluded_host_lists,
                resolver_policy,
                priority,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn route_rule_from_root(record: &GoRouteRuleRecord, root: &Value) -> Result<Option<RouteRule>> {
    let matcher = root
        .get("match")
        .or_else(|| root.get("matcher"))
        .unwrap_or(root);
    let match_type = record.match_type.trim().to_ascii_lowercase();
    let pattern = match match_type.as_str() {
        "domain" | "host" => string_field(matcher, &["domain", "host", "pattern"]),
        "cidr" | "ip" | "network" => string_field(matcher, &["cidr", "ip", "network", "pattern"]),
        _ => string_field(
            matcher,
            &["domain", "host", "cidr", "ip", "network", "pattern"],
        ),
    }
    .ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            format!(
                "route rule {} has unsupported matcher type {:?}",
                record.id, record.match_type
            ),
        )
    })?;

    let action = parse_action(&record.action_mode, root, record.id.as_str())?;
    let network = parse_network(
        field(root, matcher, &["network", "protocol"]),
        record.id.as_str(),
    )?;
    let port = parse_port(field(root, matcher, &["port", "ports"]), record.id.as_str())?;
    let geo_country = string_field(root, &["geo_country", "geoCountry", "country"])
        .or_else(|| string_field(matcher, &["geo_country", "geoCountry", "country"]));
    let inbound_names = parse_inbound_names(root, matcher);
    let process_names = parse_process_names(root, matcher);
    let resolver_policy = parse_resolver_policy(root, matcher, action, record.id.as_str())?;
    let priority = i32::try_from(record.priority).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} priority is outside i32", record.id),
        )
    })?;

    Ok(Some(RouteRule {
        rule_name: record.name.clone(),
        tag: record.tag.clone(),
        list_names: Vec::new(),
        pattern,
        host_lists: Vec::new(),
        required_patterns: Vec::new(),
        always_false: false,
        action,
        network,
        excluded_networks: Vec::new(),
        port,
        excluded_ports: Vec::new(),
        geo_country,
        excluded_geo_countries: Vec::new(),
        inbound_names: inbound_names.unwrap_or_default(),
        excluded_inbound_names: Vec::new(),
        process_names: process_names.unwrap_or_default(),
        excluded_process_names: Vec::new(),
        excluded_patterns: HostTrie::new(),
        excluded_host_lists: Vec::new(),
        resolver_policy,
        priority,
    }))
}

pub fn route_rule_from_go_record(record: &GoRouteRuleRecord) -> Result<Option<RouteRule>> {
    if record.disabled {
        return Ok(None);
    }
    let root: Value = serde_json::from_slice(&record.data_json).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} has invalid data_json: {error}", record.id),
        )
    })?;
    route_rule_from_root(record, &root)
}

fn parse_inbound_names(root: &Value, matcher: &Value) -> Option<Vec<String>> {
    let value = root
        .get("inbound")
        .or_else(|| matcher.get("inbound"))
        .unwrap_or(&Value::Null);
    let mut names = value
        .get("names")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(name) = string_field(value, &["name"]) {
        names.push(name);
    }
    names.sort();
    names.dedup();
    (!names.is_empty()).then_some(names)
}

fn parse_process_names(root: &Value, matcher: &Value) -> Option<Vec<String>> {
    let value = root
        .get("process")
        .or_else(|| matcher.get("process"))
        .unwrap_or(&Value::Null);
    let names = value
        .get("names")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .or_else(|| string_field(value, &["name", "path"]).map(|value| vec![value]));
    names.filter(|names| !names.is_empty())
}

fn parse_action(mode: &str, root: &Value, id: &str) -> Result<RuleAction> {
    let mode = string_field(root, &["mode", "action"]).unwrap_or_else(|| mode.to_owned());
    match mode.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(RuleAction::Direct),
        "proxy" => Ok(RuleAction::Proxy),
        "bypass" => Ok(RuleAction::Bypass),
        "drop" | "block" => Ok(RuleAction::Drop),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported action {other:?}"),
        )),
    }
}

fn parse_network(value: Option<&Value>, id: &str) -> Result<Option<Network>> {
    let Some(value) = value else { return Ok(None) };
    let Some(value) = value.as_str() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {id} network must be a string"),
        ));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "all" => Ok(None),
        "tcp" => Ok(Some(Network::Tcp)),
        "udp" => Ok(Some(Network::Udp)),
        "icmp" => Ok(Some(Network::Icmp)),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported network {other:?}"),
        )),
    }
}

fn parse_port(value: Option<&Value>, id: &str) -> Result<Option<(u16, u16)>> {
    let Some(value) = value else { return Ok(None) };
    let (start, end) = if let Some(port) = value.as_u64() {
        let port = u16::try_from(port).map_err(|_| invalid_port(id))?;
        (port, port)
    } else if let Some(range) = value.as_str() {
        let mut values = range.split('-');
        let start = values.next().and_then(|value| value.trim().parse().ok());
        let end = values
            .next()
            .map(|value| value.trim().parse().ok())
            .unwrap_or(start);
        if values.next().is_some() || start.is_none() || end.is_none() {
            return Err(invalid_port(id));
        }
        (start.unwrap(), end.unwrap())
    } else if let Some(object) = value.as_object() {
        let start = object
            .get("start")
            .or_else(|| object.get("from"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok());
        let end = object
            .get("end")
            .or_else(|| object.get("to"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok());
        match (start, end) {
            (Some(start), Some(end)) => (start, end),
            _ => return Err(invalid_port(id)),
        }
    } else {
        return Err(invalid_port(id));
    };
    if start > end {
        return Err(invalid_port(id));
    }
    Ok(Some((start, end)))
}

fn parse_resolver_policy(
    root: &Value,
    matcher: &Value,
    action: RuleAction,
    id: &str,
) -> Result<ResolverPolicy> {
    let policy = root
        .get("resolverPolicy")
        .or_else(|| root.get("resolver_policy"))
        .unwrap_or(&Value::Null);
    let strategy_value = field(root, policy, &["resolve_strategy", "resolveStrategy"])
        .or_else(|| field(matcher, policy, &["resolve_strategy", "resolveStrategy"]));
    let strategy = match strategy_value {
        None => ResolveStrategy::Default,
        Some(value) => {
            let Some(value) = value.as_str() else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("route rule {id} resolve strategy must be a string"),
                ));
            };
            match value.trim().to_ascii_lowercase().as_str() {
                "" | "default" => ResolveStrategy::Default,
                "only_ipv4" | "onlyipv4" | "ipv4" => ResolveStrategy::OnlyIpv4,
                "prefer_ipv4" | "preferipv4" => ResolveStrategy::PreferIpv4,
                "only_ipv6" | "onlyipv6" | "ipv6" => ResolveStrategy::OnlyIpv6,
                "prefer_ipv6" | "preferipv6" => ResolveStrategy::PreferIpv6,
                other => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        format!("route rule {id} has unsupported resolve strategy {other:?}"),
                    ));
                }
            }
        }
    };
    let use_fake_ip = bool_field(root, policy, &["use_fake_ip", "useFakeIp"])
        .unwrap_or(action == RuleAction::Proxy);
    let fake_ip_skip_check_upstream = bool_field(
        root,
        policy,
        &[
            "fake_ip_skip_check_upstream",
            "fakeIpSkipCheckUpstream",
            "skip_check_upstream",
        ],
    )
    .unwrap_or(false);
    let udp_skip_resolve_target = bool_field(
        root,
        policy,
        &["udp_skip_resolve_target", "udpSkipResolveTarget"],
    )
    .unwrap_or(false);
    Ok(ResolverPolicy {
        strategy,
        use_fake_ip,
        fake_ip_skip_check_upstream,
        udp_skip_resolve_target,
    })
}

fn field<'a>(root: &'a Value, nested: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| root.get(*key).or_else(|| nested.get(*key)))
}

fn bool_field(root: &Value, nested: &Value, keys: &[&str]) -> Option<bool> {
    field(root, nested, keys).and_then(Value::as_bool)
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn geoip_countries(value: &Value) -> Vec<String> {
    fn strings(value: &Value) -> Vec<String> {
        match value {
            Value::String(value) => value
                .split([',', '|'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .flat_map(|value| {
                    value
                        .split([',', '|'])
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    if !value.is_object() {
        return strings(value);
    }
    for key in ["countries", "country", "country_codes", "countryCodes"] {
        if let Some(value) = value.get(key) {
            let countries = strings(value);
            if !countries.is_empty() {
                return countries;
            }
        }
    }
    Vec::new()
}

fn invalid_port(id: &str) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!("route rule {id} has an invalid port range"),
    )
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;
