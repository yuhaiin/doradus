use super::*;

#[cfg(test)]
pub fn page(mut values: Vec<Value>, input: &Value) -> Value {
    if let Some(query) = input
        .get("query")
        .and_then(Value::as_str)
        .filter(|query| !query.trim().is_empty())
    {
        let query = query.to_ascii_lowercase();
        values.retain(|value| value.to_string().to_ascii_lowercase().contains(&query));
    }
    page_values(values, input)
}

pub fn page_with_filter<F>(mut values: Vec<Value>, input: &Value, matches: F) -> Value
where
    F: Fn(&Value, &str) -> bool,
{
    if let Some(query) = normalized_query(input) {
        values.retain(|value| matches(value, &query));
    }
    page_values(values, input)
}

pub fn normalized_query(input: &Value) -> Option<String> {
    input
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_ascii_lowercase)
}

pub fn page_values(values: Vec<Value>, input: &Value) -> Value {
    let total = values.len();
    let page = input
        .get("page")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1) as usize;
    let size = input
        .get("page_size")
        .or_else(|| input.get("pageSize"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let items = if size == 0 {
        values
    } else {
        values
            .into_iter()
            .skip((page - 1) * size)
            .take(size)
            .collect()
    };
    json!({"items": items, "page": {"page": page, "pageSize": size, "total": total}})
}

pub fn field_contains(value: &Value, key: &str, query: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|field| field.to_ascii_lowercase().contains(query))
}

pub fn nested_type_contains(value: &Value, key: &str, query: &str) -> bool {
    value
        .get(key)
        .and_then(|nested| nested.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|field| field.to_ascii_lowercase().contains(query))
}

pub fn node_chain_contains_query(value: &Value, query: &str) -> bool {
    value
        .get("chain")
        .and_then(Value::as_array)
        .is_some_and(|chain| {
            chain
                .iter()
                .any(|protocol| field_contains(protocol, "type", query))
        })
}

pub fn node_matches_query(value: &Value, query: &str) -> bool {
    ["id", "name", "group", "origin"]
        .iter()
        .any(|key| field_contains(value, key, query))
        || node_chain_contains_query(value, query)
}

pub fn inbound_matches_query(value: &Value, query: &str) -> bool {
    ["id", "name"]
        .iter()
        .any(|key| field_contains(value, key, query))
        || nested_type_contains(value, "network", query)
        || nested_type_contains(value, "protocol", query)
}

pub fn resolver_matches_query(value: &Value, query: &str) -> bool {
    ["id", "type", "host", "subnet", "tlsServerName"]
        .iter()
        .any(|key| field_contains(value, key, query))
}

pub fn route_list_matches_query(value: &Value, query: &str) -> bool {
    ["name", "type", "source", "preview"]
        .iter()
        .any(|key| field_contains(value, key, query))
}

pub fn route_rule_matches_query(value: &Value, query: &str) -> bool {
    ["name", "mode", "tag", "resolver"]
        .iter()
        .any(|key| field_contains(value, key, query))
}

pub fn tag_matches_query(value: &Value, query: &str) -> bool {
    field_contains(value, "name", query)
        || field_contains(value, "type", query)
        || value
            .get("hash")
            .and_then(Value::as_array)
            .is_some_and(|hashes| {
                hashes
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|hash| hash.to_ascii_lowercase().contains(query))
            })
}
