use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct RuleVariant {
    /// `None` means the expression has no host/CIDR constraint and is a
    /// global rule whose remaining network/port/geo predicates still apply.
    pub(super) pattern: Option<String>,
    pub(super) host_lists: Vec<Arc<HostTrie>>,
    /// Positive patterns beyond `pattern`, produced by nested `all`.
    pub(super) additional_patterns: Vec<String>,
    pub(super) network: Option<Network>,
    pub(super) excluded_networks: Vec<Network>,
    pub(super) port: Option<(u16, u16)>,
    pub(super) excluded_ports: Vec<(u16, u16)>,
    pub(super) geo_country: Option<String>,
    pub(super) excluded_geo_countries: Vec<String>,
    pub(super) inbound_names: Option<Vec<String>>,
    pub(super) excluded_inbound_names: Option<Vec<String>>,
    pub(super) process_names: Option<Vec<String>>,
    pub(super) excluded_process_names: Option<Vec<String>>,
    pub(super) excluded_patterns: Vec<String>,
    pub(super) excluded_host_lists: Vec<Arc<HostTrie>>,
    pub(super) list_names: Vec<String>,
    pub(super) always_false: bool,
}

#[derive(Debug)]
enum RuleExpressionKind {
    All,
    Any,
    Not,
    Host,
    Network,
    Port,
    Geoip,
    Inbound,
    Process,
    Pattern,
    Unsupported(String),
}

fn rule_expression_kind(value: &Value) -> RuleExpressionKind {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind == "all" || value.get("all").is_some() {
        return RuleExpressionKind::All;
    }
    if kind == "any" || value.get("any").is_some() {
        return RuleExpressionKind::Any;
    }
    if kind == "not" || value.get("not").is_some() {
        return RuleExpressionKind::Not;
    }
    match kind.as_str() {
        "host" => RuleExpressionKind::Host,
        "network" => RuleExpressionKind::Network,
        "port" => RuleExpressionKind::Port,
        "geoip" => RuleExpressionKind::Geoip,
        "inbound" => RuleExpressionKind::Inbound,
        "process" => RuleExpressionKind::Process,
        "domain" | "cidr" | "ip" => RuleExpressionKind::Pattern,
        other => RuleExpressionKind::Unsupported(other.to_owned()),
    }
}

pub(super) fn parse_rule_expression(
    value: &Value,
    lists: &RouteListSnapshot,
    id: &str,
) -> Result<Vec<RuleVariant>> {
    parse_rule_expression_inner(value, lists, id, false)
}

pub(super) fn parse_rule_expression_inner(
    value: &Value,
    lists: &RouteListSnapshot,
    id: &str,
    negated: bool,
) -> Result<Vec<RuleVariant>> {
    let kind = rule_expression_kind(value);
    if matches!(&kind, RuleExpressionKind::All) {
        let mut children = value
            .get("all")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        children.sort_by_key(route_expression_sort_key);
        if negated {
            let mut variants = Vec::new();
            for child in children {
                variants.extend(parse_rule_expression_inner(&child, lists, id, true)?);
            }
            return Ok(variants);
        }
        return combine_all(&children, lists, id, false);
    }
    if matches!(&kind, RuleExpressionKind::Any) {
        let children = value
            .get("any")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if negated {
            return combine_all(&children, lists, id, true);
        }
        let mut variants = Vec::new();
        for child in children {
            variants.extend(parse_rule_expression_inner(&child, lists, id, false)?);
        }
        return Ok(variants);
    }
    if matches!(&kind, RuleExpressionKind::Not) {
        let nested = value
            .get("not")
            .ok_or_else(|| unsupported_expression(id, "not expression value"))?;
        return parse_rule_expression_inner(nested, lists, id, !negated);
    }

    match kind {
        RuleExpressionKind::Host => {
            let host = value.get("host").unwrap_or(value);
            let name = string_field(host, &["list", "name"])
                .ok_or_else(|| unsupported_expression(id, "host list name"))?;
            let patterns = lists.values(&name).unwrap_or_default();
            if patterns.is_empty() {
                // A missing/empty route list must not turn a negated matcher
                // into an accidental global rule. Keep the same fail-closed
                // behavior as the positive list expansion.
                return Ok(vec![RuleVariant {
                    list_names: vec![name],
                    always_false: !negated,
                    ..RuleVariant::default()
                }]);
            }
            if negated {
                Ok(vec![match lists.host_index(&name) {
                    Some(index) => RuleVariant {
                        excluded_host_lists: vec![index],
                        list_names: vec![name],
                        ..RuleVariant::default()
                    },
                    None => RuleVariant {
                        list_names: vec![name],
                        ..RuleVariant::default()
                    },
                }])
            } else {
                Ok(vec![match lists.host_index(&name) {
                    Some(index) => RuleVariant {
                        host_lists: vec![index],
                        list_names: vec![name],
                        ..RuleVariant::default()
                    },
                    None => RuleVariant {
                        list_names: vec![name],
                        always_false: true,
                        ..RuleVariant::default()
                    },
                }])
            }
        }
        RuleExpressionKind::Network => {
            let nested = value.get("network").unwrap_or(value);
            let network = parse_network_text(
                string_field(nested, &["network", "protocol"]).as_deref(),
                id,
            )?;
            Ok(vec![if negated {
                RuleVariant {
                    excluded_networks: network.into_iter().collect(),
                    ..Default::default()
                }
            } else {
                RuleVariant {
                    network,
                    ..Default::default()
                }
            }])
        }
        RuleExpressionKind::Port => {
            let nested = value.get("port").unwrap_or(value);
            let value = nested
                .get("ports")
                .or_else(|| nested.get("port"))
                .unwrap_or(nested);
            let variants = parse_port_variants(value, id)?;
            if negated {
                Ok(vec![RuleVariant {
                    excluded_ports: variants
                        .into_iter()
                        .filter_map(|variant| variant.port)
                        .collect(),
                    ..Default::default()
                }])
            } else {
                Ok(variants)
            }
        }
        RuleExpressionKind::Geoip => {
            let nested = value.get("geoip").unwrap_or(value);
            let countries = geoip_countries(nested);
            if countries.is_empty() {
                return Err(unsupported_expression(id, "geoip countries"));
            }
            if negated {
                Ok(vec![RuleVariant {
                    excluded_geo_countries: countries,
                    ..Default::default()
                }])
            } else {
                Ok(countries
                    .into_iter()
                    .map(|country| RuleVariant {
                        geo_country: Some(country),
                        ..Default::default()
                    })
                    .collect())
            }
        }
        RuleExpressionKind::Inbound => {
            let nested = value.get("inbound").unwrap_or(value);
            let mut names = nested
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
            if let Some(name) = string_field(nested, &["name"]) {
                names.push(name);
            }
            names.sort();
            names.dedup();
            if names.is_empty() {
                return Ok(Vec::new());
            }
            Ok(vec![if negated {
                RuleVariant {
                    excluded_inbound_names: Some(names),
                    ..Default::default()
                }
            } else {
                RuleVariant {
                    inbound_names: Some(names),
                    ..Default::default()
                }
            }])
        }
        RuleExpressionKind::Process => {
            let nested = value.get("process").unwrap_or(value);
            let name = string_field(nested, &["list", "name"])
                .ok_or_else(|| unsupported_expression(id, "process list name"))?;
            let mut names = lists.values(&name).unwrap_or_default().to_vec();
            names.sort();
            names.dedup();
            if names.is_empty() {
                return Ok(Vec::new());
            }
            Ok(vec![if negated {
                RuleVariant {
                    excluded_process_names: Some(names),
                    list_names: vec![name],
                    ..Default::default()
                }
            } else {
                RuleVariant {
                    process_names: Some(names),
                    list_names: vec![name],
                    ..Default::default()
                }
            }])
        }
        RuleExpressionKind::Pattern => {
            let pattern = string_field(value, &["domain", "host", "cidr", "ip", "pattern"])
                .ok_or_else(|| unsupported_expression(id, "matcher pattern"))?;
            Ok(vec![if negated {
                RuleVariant {
                    excluded_patterns: vec![pattern],
                    ..Default::default()
                }
            } else {
                RuleVariant {
                    pattern: Some(pattern),
                    ..Default::default()
                }
            }])
        }
        RuleExpressionKind::Unsupported(other) => Err(unsupported_expression(
            id,
            format!("expression type {other:?}"),
        )),
        RuleExpressionKind::All | RuleExpressionKind::Any | RuleExpressionKind::Not => {
            unreachable!("composite route expression was handled above")
        }
    }
}

/// Match Go's `sortRule` before evaluating nested `all` expressions.  The
/// order is observable through short-circuit match history, not just an
/// optimization: a failed process matcher must prevent later host-list
/// history from being recorded.
pub(super) fn route_expression_sort_key(value: &Value) -> u8 {
    match value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "port" | "network" => 1,
        "process" => 2,
        "inbound" => 3,
        "geoip" => 4,
        "host" => 5,
        _ => u8::MAX,
    }
}

pub(super) fn combine_all(
    children: &[Value],
    lists: &RouteListSnapshot,
    id: &str,
    child_negated: bool,
) -> Result<Vec<RuleVariant>> {
    let mut variants = vec![RuleVariant::default()];
    for child in children {
        let child_variants = parse_rule_expression_inner(child, lists, id, child_negated)?;
        let mut combined = Vec::new();
        for left in &variants {
            for right in &child_variants {
                let network = match (left.network, right.network) {
                    (Some(left), Some(right)) if left != right => {
                        return Ok(Vec::new());
                    }
                    (Some(network), _) | (_, Some(network)) => Some(network),
                    (None, None) => None,
                };
                let port = intersect_ports(left.port, right.port);
                if left.port.is_some() && right.port.is_some() && port.is_none() {
                    continue;
                }
                let geo_country = match (&left.geo_country, &right.geo_country) {
                    (Some(left), Some(right)) if !left.eq_ignore_ascii_case(right) => continue,
                    (Some(country), _) | (_, Some(country)) => Some(country.clone()),
                    (None, None) => None,
                };
                let inbound_names =
                    match intersect_name_constraints(&left.inbound_names, &right.inbound_names) {
                        Some(names) => names,
                        None => continue,
                    };
                let process_names =
                    match intersect_name_constraints(&left.process_names, &right.process_names) {
                        Some(names) => names,
                        None => continue,
                    };
                let excluded_inbound_names = union_name_constraints(
                    &left.excluded_inbound_names,
                    &right.excluded_inbound_names,
                );
                let excluded_process_names = union_name_constraints(
                    &left.excluded_process_names,
                    &right.excluded_process_names,
                );
                let mut excluded_patterns = left.excluded_patterns.clone();
                excluded_patterns.extend(right.excluded_patterns.iter().cloned());
                let mut host_lists = left.host_lists.clone();
                host_lists.extend(right.host_lists.iter().cloned());
                let mut excluded_host_lists = left.excluded_host_lists.clone();
                excluded_host_lists.extend(right.excluded_host_lists.iter().cloned());
                let mut additional_patterns = left.additional_patterns.clone();
                if let Some(pattern) = right.pattern.clone()
                    && left.pattern.is_some()
                {
                    additional_patterns.push(pattern);
                }
                additional_patterns.extend(right.additional_patterns.iter().cloned());
                let mut excluded_networks = left.excluded_networks.clone();
                excluded_networks.extend(right.excluded_networks.iter().copied());
                excluded_networks.sort_by_key(|network| *network as u8);
                excluded_networks.dedup();
                let mut excluded_ports = left.excluded_ports.clone();
                excluded_ports.extend(right.excluded_ports.iter().copied());
                excluded_ports.sort_unstable();
                excluded_ports.dedup();
                let mut excluded_geo_countries = left.excluded_geo_countries.clone();
                excluded_geo_countries.extend(right.excluded_geo_countries.iter().cloned());
                excluded_geo_countries.sort_unstable_by_key(|country| country.to_ascii_lowercase());
                excluded_geo_countries.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
                let mut list_names = left.list_names.clone();
                for name in &right.list_names {
                    if !list_names.iter().any(|existing| existing == name) {
                        list_names.push(name.clone());
                    }
                }
                combined.push(RuleVariant {
                    pattern: left.pattern.clone().or_else(|| right.pattern.clone()),
                    host_lists,
                    additional_patterns,
                    network,
                    port,
                    geo_country,
                    inbound_names,
                    process_names,
                    excluded_networks,
                    excluded_ports,
                    excluded_geo_countries,
                    excluded_inbound_names,
                    excluded_process_names,
                    excluded_patterns,
                    excluded_host_lists,
                    list_names,
                    always_false: left.always_false || right.always_false,
                });
            }
        }
        variants = combined;
    }
    Ok(variants)
}

pub(super) fn union_name_constraints(
    left: &Option<Vec<String>>,
    right: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    let mut values = left.clone().unwrap_or_default();
    values.extend(right.clone().unwrap_or_default());
    values.sort();
    values.dedup();
    (!values.is_empty()).then_some(values)
}

pub(super) fn compile_excluded_patterns(patterns: Vec<String>, id: &str) -> Result<HostTrie> {
    HostTrie::from_patterns(patterns.iter()).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {id} has invalid excluded pattern set: {error}"),
        )
    })
}

pub(super) fn compile_required_patterns(patterns: Vec<String>, id: &str) -> Result<Vec<HostTrie>> {
    patterns
        .into_iter()
        .map(|pattern| {
            HostTrie::from_patterns([pattern.clone()]).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("route rule {id} has invalid required pattern {pattern:?}: {error}"),
                )
            })
        })
        .collect()
}

/// `Some(None)` means no constraint, `Some(Some(values))` means a constraint,
/// and `None` means two `all` children have no common value.
pub(super) fn intersect_name_constraints(
    left: &Option<Vec<String>>,
    right: &Option<Vec<String>>,
) -> Option<Option<Vec<String>>> {
    match (left, right) {
        (None, None) => Some(None),
        (Some(values), None) | (None, Some(values)) => Some(Some(values.clone())),
        (Some(left), Some(right)) => {
            let values = left
                .iter()
                .filter(|value| right.iter().any(|candidate| candidate == *value))
                .cloned()
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some(Some(values))
        }
    }
}

pub(super) fn intersect_ports(
    left: Option<(u16, u16)>,
    right: Option<(u16, u16)>,
) -> Option<(u16, u16)> {
    match (left, right) {
        (Some((left_start, left_end)), Some((right_start, right_end))) => {
            let start = left_start.max(right_start);
            let end = left_end.min(right_end);
            (start <= end).then_some((start, end))
        }
        (Some(port), None) | (None, Some(port)) => Some(port),
        (None, None) => None,
    }
}

pub(super) fn parse_port_variants(value: &Value, id: &str) -> Result<Vec<RuleVariant>> {
    if let Some(values) = value.as_array() {
        let mut variants = Vec::new();
        for value in values {
            let port = parse_port(Some(value), id)?;
            variants.push(RuleVariant {
                port,
                ..Default::default()
            });
        }
        return Ok(variants);
    }
    Ok(vec![RuleVariant {
        port: parse_port(Some(value), id)?,
        ..Default::default()
    }])
}

pub(super) fn parse_network_text(value: Option<&str>, id: &str) -> Result<Option<Network>> {
    let Some(value) = value else { return Ok(None) };
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

pub(super) fn unsupported_expression(id: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        format!("route rule {id} has unsupported {detail}"),
    )
}
