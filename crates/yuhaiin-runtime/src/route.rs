//! Conversion from the persisted Go route-rule shape to the trie runtime.
//!
//! The store keeps the original JSON payload for forward compatibility.  This
//! module is deliberately strict at the runtime boundary: a rule that cannot
//! be represented by the current domain/CIDR router is reported instead of
//! silently becoming a different rule.

use std::sync::Arc;

use serde_json::Value;
use yuhaiin_core::GeoLookup;
use yuhaiin_core::{Error, ErrorKind, Network, ResolveStrategy, ResolverPolicy, Result};
use yuhaiin_store::GoRouteRuleRecord;
use yuhaiin_trie::router::{RouteDecision, RouteRule, Router, RouterRuntime, RuleAction};

pub fn compile_go_route_rules(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
) -> Result<RouterRuntime> {
    compile_go_route_rules_with_geo(records, fallback, None)
}

pub fn compile_go_route_rules_with_geo(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
) -> Result<RouterRuntime> {
    let mut rules = Vec::with_capacity(records.len());
    for record in records {
        if let Some(rule) = route_rule_from_go_record(record)? {
            rules.push(rule);
        }
    }
    let router = Router::compile(rules, fallback)?;
    let router = match geo {
        Some(geo) => router.with_geo_lookup(geo),
        None => router,
    };
    Ok(RouterRuntime::new(router))
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
    let matcher = root
        .get("match")
        .or_else(|| root.get("matcher"))
        .unwrap_or(&root);
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

    let action = parse_action(&record.action_mode, &root, record.id.as_str())?;
    let network = parse_network(
        field(&root, matcher, &["network", "protocol"]),
        record.id.as_str(),
    )?;
    let port = parse_port(
        field(&root, matcher, &["port", "ports"]),
        record.id.as_str(),
    )?;
    let geo_country = string_field(&root, &["geo_country", "geoCountry", "country"])
        .or_else(|| string_field(matcher, &["geo_country", "geoCountry", "country"]));
    let resolver_policy = parse_resolver_policy(&root, matcher, action, record.id.as_str())?;
    let priority = i32::try_from(record.priority).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} priority is outside i32", record.id),
        )
    })?;

    Ok(Some(RouteRule {
        pattern,
        action,
        network,
        port,
        geo_country,
        resolver_policy,
        priority,
    }))
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
        let end = values.next().and_then(|value| value.trim().parse().ok());
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

fn invalid_port(id: &str) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!("route rule {id} has an invalid port range"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::{Endpoint, Network};

    fn record(json: &str, mode: &str, match_type: &str) -> GoRouteRuleRecord {
        GoRouteRuleRecord {
            id: "rule-1".to_owned(),
            name: "rule-1".to_owned(),
            priority: 10,
            disabled: false,
            action_mode: mode.to_owned(),
            match_type: match_type.to_owned(),
            tag: String::new(),
            updated_at: 0,
            data_json: json.as_bytes().to_vec(),
        }
    }

    #[test]
    fn production_domain_shape_compiles_to_router() {
        let rule = route_rule_from_go_record(&record(
            r#"{"name":"production-domain","match":{"domain":"example.com"},"mode":"proxy"}"#,
            "proxy",
            "domain",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(rule.pattern, "example.com");
        assert_eq!(rule.action, RuleAction::Proxy);
        assert!(rule.resolver_policy.use_fake_ip);
        let router = Router::compile(
            vec![rule],
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap();
        let endpoint = Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("www.example.com").unwrap(),
            443,
        );
        assert_eq!(
            router.decide(&endpoint).mode,
            yuhaiin_core::RouteMode::Proxy
        );
    }

    #[test]
    fn disabled_and_cidr_policy_are_supported() {
        let mut disabled = record(
            r#"{"match":{"domain":"disabled.example"}}"#,
            "direct",
            "domain",
        );
        disabled.disabled = true;
        assert!(route_rule_from_go_record(&disabled).unwrap().is_none());

        let rule = route_rule_from_go_record(&record(
            r#"{"match":{"cidr":"192.0.2.0/24","network":"udp","port":"53-853"},"resolveStrategy":"only_ipv4","useFakeIp":false}"#,
            "direct",
            "cidr",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(rule.pattern, "192.0.2.0/24");
        assert_eq!(rule.network, Some(Network::Udp));
        assert_eq!(rule.port, Some((53, 853)));
        assert_eq!(rule.resolver_policy.strategy, ResolveStrategy::OnlyIpv4);
        assert!(!rule.resolver_policy.use_fake_ip);
    }

    #[test]
    fn unsupported_matcher_is_not_silently_dropped() {
        let error = route_rule_from_go_record(&record(
            r#"{"rules":[{"host":{"list":"domains"}}]}"#,
            "proxy",
            "all",
        ))
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }
}
