use super::*;

pub fn normalize_route_list_value(value: &Value, name: &str) -> Value {
    let mut normalized = value.clone();
    set_string(&mut normalized, "name", name.trim().to_owned());
    let list_type = string_or(&normalized, "type", "host");
    set_string(
        &mut normalized,
        "type",
        if list_type.trim().is_empty() {
            "host".to_owned()
        } else {
            list_type
        },
    );

    let source_value = normalized
        .get("source")
        .filter(|source| source.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut source = source_value;
    let source_type = string_or(&source, "type", "local");
    let source_type = if source_type.trim().is_empty() {
        "local"
    } else {
        source_type.as_str()
    };
    set_string(&mut source, "type", source_type);
    if let Some(object) = source.as_object_mut() {
        if source_type == "remote" {
            object.remove("local");
            object
                .entry("remote".to_owned())
                .or_insert_with(|| json!({}));
        } else {
            object.insert("type".to_owned(), Value::String("local".to_owned()));
            object.remove("remote");
            object
                .entry("local".to_owned())
                .or_insert_with(|| json!({}));
        }
    }
    if let Some(object) = normalized.as_object_mut() {
        object.insert("source".to_owned(), source);
    }
    normalized
}

pub fn normalize_route_rule_value(value: &Value, name: &str) -> Value {
    let mut normalized = value.clone();
    set_string(&mut normalized, "name", name.trim().to_owned());
    let mode = string_or(&normalized, "mode", "bypass");
    set_string(
        &mut normalized,
        "mode",
        if mode.trim().is_empty() {
            "bypass".to_owned()
        } else {
            mode
        },
    );
    normalized
}

pub fn route_list_detail_json(record: GoRouteListRecord) -> Value {
    normalize_route_list_value(
        &raw_json(&record.data_json, json!({"name": record.name})),
        &record.name,
    )
}

pub fn route_list_record_with_refresh_errors(
    record: &GoRouteListRecord,
    errors: &[String],
) -> Option<GoRouteListRecord> {
    let mut value = serde_json::from_slice::<Value>(&record.data_json).ok()?;
    let source = value.get("source").cloned().unwrap_or_default();
    let source_type = string_or(&source, "type", &record.source_type).to_ascii_lowercase();
    if source_type != "remote" {
        return None;
    }
    value
        .as_object_mut()?
        .insert("errorMsgs".to_owned(), json!(errors));
    Some(GoRouteListRecord {
        data_json: serde_json::to_vec(&value).ok()?,
        ..record.clone()
    })
}

pub fn route_rule_detail_json(record: GoRouteRuleRecord) -> Value {
    let mut value = normalize_route_rule_value(
        &raw_json(&record.data_json, json!({"name": record.name})),
        &record.name,
    );
    // `match` is an internal compatibility projection used by the Rust
    // route compiler. Go's public RouteRule contract exposes the equivalent
    // expression through `rules` and omits this storage-only field.
    if let Value::Object(object) = &mut value {
        object.remove("match");
    }
    value
}

pub fn route_list_item_json(record: GoRouteListRecord) -> Value {
    let value = raw_json(
        &record.data_json,
        json!({"name": record.name, "type": record.list_type}),
    );
    let name = string_or(&value, "name", &record.name);
    let source = value.get("source").cloned().unwrap_or_default();
    let source_type = string_or(&source, "type", &record.source_type);
    // The Go list-store contract reports the persisted source metadata here,
    // not the number of entries currently loaded into the runtime trie.  In
    // particular, an empty local list is valid and must not become an error
    // merely because it has no runtime values.
    let source_values = if source_type == "local" {
        source.get("local").and_then(|local| local.get("lists"))
    } else {
        source.get("remote").and_then(|remote| remote.get("urls"))
    };
    let item_count = source_values.and_then(Value::as_array).map_or(0, Vec::len);
    let preview = source_values
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .unwrap_or_default();
    let error_count = value
        .get("errorMsgs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    json!({
        "name": name,
        "type": string_or(&value, "type", &record.list_type),
        "source": source_type,
        "itemCount": item_count,
        "errorCount": error_count,
        "preview": preview,
    })
}

pub fn route_rule_item_json(record: GoRouteRuleRecord) -> Value {
    let value = raw_json(&record.data_json, json!({}));
    json!({"name": record.name, "disabled": record.disabled, "index": record.priority, "mode": string_or(&value, "mode", &record.action_mode), "tag": record.tag, "resolver": string_or(&value, "resolver", ""), "ruleCount": value.get("rules").and_then(Value::as_array).map_or(0, Vec::len)})
}

pub fn route_match(value: &Value) -> (String, String) {
    fn walk(value: &Value) -> Option<(String, String)> {
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if ["domain", "host", "cidr", "ip", "network", "pattern"].contains(&lower.as_str())
                    && let Some(value) = value.as_str()
                {
                    return Some((
                        if lower == "cidr" || lower == "ip" {
                            "cidr"
                        } else {
                            "domain"
                        }
                        .to_owned(),
                        value.to_owned(),
                    ));
                }
                if lower == "list"
                    && let Some(value) = value.as_str()
                {
                    return Some(("domain".to_owned(), value.to_owned()));
                }
                if let Some(found) = walk(value) {
                    return Some(found);
                }
            }
        } else if let Some(array) = value.as_array() {
            for value in array {
                if let Some(found) = walk(value) {
                    return Some(found);
                }
            }
        }
        None
    }
    walk(value).unwrap_or_else(|| ("domain".to_owned(), "".to_owned()))
}

pub fn node_chain_types(value: &Value) -> Vec<String> {
    if let Some(chain) = value
        .get("chainTypes")
        .or_else(|| value.get("chain_types"))
        .and_then(Value::as_array)
    {
        return chain
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(chain) = value.get("chain").and_then(Value::as_array) {
        let types = chain
            .iter()
            .filter_map(|item| item.get("type").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !types.is_empty() {
            return types;
        }
    }
    ["protocol", "type"]
        .iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .map(|value| vec![value.to_owned()])
        })
        .unwrap_or_default()
}

pub fn nested_type(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("empty")
        .to_owned()
}
