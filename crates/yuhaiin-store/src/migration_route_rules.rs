//! Legacy route-rule conversion and JSON compatibility helpers.

use super::*;

pub fn upgrade_go_v1_route_rules(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "go_legacy_route_rules",
        &[
            "id",
            "name",
            "priority",
            "disabled",
            "updated_at",
            "data_json",
        ],
    )?;
    if table_row_count(connection, "route_rules_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT id, name, priority, disabled, updated_at, data_json
             FROM go_legacy_route_rules ORDER BY priority, name",
        )
        .map_err(storage_error)?;
    for (index, row) in rows.iter().enumerate() {
        let fallback_name = row_text(row, 1, "go_legacy_route_rules.name")?;
        validate_id(&fallback_name)?;
        let mut object = legacy_json_object(
            &row_blob_or_text(row, 5, "go_legacy_route_rules.data_json")?,
            "go_legacy_route_rules.data_json",
        )?;
        let name = json_string(&object, &["name"])
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback_name);
        validate_id(&name)?;
        let mode = json_enum_string(
            &object,
            &["mode"],
            &["bypass", "direct", "proxy", "block"],
            0,
        )?;
        let tag = json_string(&object, &["tag"]).unwrap_or_default();
        let resolve_strategy = json_enum_string(
            &object,
            &["resolve_strategy", "resolveStrategy"],
            &[
                "default",
                "prefer_ipv4",
                "only_ipv4",
                "prefer_ipv6",
                "only_ipv6",
            ],
            0,
        )?;
        let udp_strategy = json_enum_string(
            &object,
            &[
                "udp_proxy_fqdn",
                "udp_proxy_fqdn_strategy",
                "udpProxyFqdnStrategy",
            ],
            &["udp_proxy_fqdn_strategy_default", "resolve", "skip_resolve"],
            0,
        )?;
        let resolver = json_string(&object, &["resolver"]).unwrap_or_default();
        let disabled = row_integer(row, 3, "go_legacy_route_rules.disabled")? != 0;
        let (rules, match_type) = convert_legacy_route_groups(&object)?;
        object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
        object.insert("mode".to_owned(), serde_json::Value::String(mode.clone()));
        object.insert("tag".to_owned(), serde_json::Value::String(tag.clone()));
        object.insert(
            "resolveStrategy".to_owned(),
            serde_json::Value::String(resolve_strategy),
        );
        object.insert(
            "udpProxyFqdnStrategy".to_owned(),
            serde_json::Value::String(udp_strategy),
        );
        object.insert("resolver".to_owned(), serde_json::Value::String(resolver));
        object.insert("rules".to_owned(), rules);
        object.insert("disabled".to_owned(), serde_json::Value::Bool(disabled));
        let data_json = json_object_bytes(object, "legacy route rule")?;
        let updated_at = row_integer(row, 4, "go_legacy_route_rules.updated_at")?;
        validate_go_timestamp(updated_at)?;
        connection
            .execute_with_params(
                "INSERT INTO route_rules_v2
                 (id, name, priority, disabled, action_mode, match_type, tag, updated_at, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    SqliteValue::from(name.clone()),
                    SqliteValue::from(name),
                    SqliteValue::from((index + 1) as i64),
                    SqliteValue::from(if disabled { 1i64 } else { 0 }),
                    SqliteValue::from(mode),
                    SqliteValue::from(match_type),
                    SqliteValue::from(tag),
                    SqliteValue::from(updated_at),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

pub fn legacy_json_object(
    data: &[u8],
    field: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("decode {field} failed: {error}"),
        )
    })?;
    value.as_object().cloned().ok_or_else(|| {
        Error::new(
            ErrorKind::Storage,
            format!("{field} must contain a JSON object"),
        )
    })
}

pub fn json_object_bytes(
    object: serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::Value::Object(object)).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("encode {field} failed: {error}"),
        )
    })
}

pub fn json_string(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| match value {
            serde_json::Value::String(value) => Some(value.clone()),
            _ => None,
        })
    })
}

fn json_enum_string(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    names: &[&str],
    default: usize,
) -> Result<String> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(names[default].to_owned());
    };
    if let Some(value) = value.as_str() {
        if let Some(name) = names.iter().find(|name| **name == value) {
            return Ok((*name).to_owned());
        }
        if let Some(name) = names.iter().find(|name| value.ends_with(*name)) {
            return Ok((*name).to_owned());
        }
        return Err(Error::new(
            ErrorKind::Storage,
            format!("unknown legacy enum value {value:?}"),
        ));
    }
    let Some(value) = value.as_i64() else {
        return Err(Error::new(
            ErrorKind::Storage,
            "legacy enum value must be a string or integer",
        ));
    };
    names
        .get(value as usize)
        .map(|name| (*name).to_owned())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Storage,
                format!("unknown legacy enum value {value}"),
            )
        })
}

fn convert_legacy_route_groups(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(serde_json::Value, &'static str)> {
    let Some(groups) = object.get("rules") else {
        return Ok((serde_json::Value::Array(Vec::new()), "empty"));
    };
    let Some(groups) = groups.as_array() else {
        return Err(Error::new(
            ErrorKind::Storage,
            "legacy route rule rules must be an array",
        ));
    };
    let mut converted = Vec::with_capacity(groups.len());
    for group in groups {
        let Some(group) = group.as_object() else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group must be an object",
            ));
        };
        let Some(leaves) = group.get("rules") else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group is missing rules",
            ));
        };
        let Some(leaves) = leaves.as_array() else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group rules must be an array",
            ));
        };
        let mut all = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let Some(leaf) = leaf.as_object() else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy route rule leaf must be an object",
                ));
            };
            let Some((kind, value)) = ["host", "process", "inbound", "network", "port", "geoip"]
                .iter()
                .find_map(|kind| leaf.get(*kind).map(|value| (*kind, value.clone())))
            else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy route rule leaf has no supported discriminator",
                ));
            };
            let mut expression = serde_json::Map::new();
            expression.insert(
                "type".to_owned(),
                serde_json::Value::String(kind.to_owned()),
            );
            expression.insert(kind.to_owned(), value);
            all.push(serde_json::Value::Object(expression));
        }
        let mut expression = serde_json::Map::new();
        expression.insert(
            "type".to_owned(),
            serde_json::Value::String("all".to_owned()),
        );
        expression.insert("all".to_owned(), serde_json::Value::Array(all));
        converted.push(serde_json::Value::Object(expression));
    }
    let match_type = if converted.is_empty() { "empty" } else { "all" };
    Ok((serde_json::Value::Array(converted), match_type))
}
