use super::*;
pub async fn subscriptions_get_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_subscription_links()
        .await?;
    if !records.is_empty() {
        return Ok(Json(json!({
            "items": records.into_iter().map(subscription_json).collect::<Vec<_>>()
        })));
    }
    // Read the pre-table compatibility key once so an in-progress Rust
    // migration does not make existing local links disappear from the UI.
    Ok(Json(json!({
        "items": config_items(state, "subscriptions.items").await?
    })))
}

pub async fn subscriptions_put_value(state: &ApiState, value: Value) -> ApiResult {
    let records = subscription_records(&value)?;
    state
        .controller
        .mutate_and_reload_blocking(move |store| {
            store.repository().put_go_subscription_links_sync(&records)
        })
        .await?;
    empty()
}

pub async fn subscriptions_delete_value(state: &ApiState, value: &Value) -> ApiResult {
    let names = subscription_names(value, "subscriptions delete")?;
    let delete_nodes = bool_or(value, "deleteNodes", false);
    let delete_users = bool_or(value, "deleteUsers", false);
    if delete_users {
        return Err(ApiError::unavailable(
            "subscription user deletion is not yet available",
        ));
    }
    let groups = names.clone();
    state
        .controller
        .mutate_and_reload_blocking(move |store| {
            store
                .repository()
                .delete_go_subscription_links_sync(&names)?;
            if delete_nodes {
                store.repository().delete_go_nodes_by_groups_sync(&groups)?;
            }
            Ok(())
        })
        .await?;
    empty()
}

pub async fn subscriptions_delete_preview_value(state: &ApiState, value: &Value) -> ApiResult {
    let names = subscription_names(value, "subscriptions delete preview")?;
    let nodes = state
        .controller
        .store()
        .repository()
        .count_go_nodes_by_groups(&names)
        .await?;
    Ok(Json(json!({"nodes": nodes, "users": 0})))
}

pub async fn subscriptions_update_value(_state: &ApiState, value: &Value) -> ApiResult {
    // The Go LinkNames decoder leaves Names nil when the request is `{}`;
    // that is the same "refresh all" request as an explicit empty array.
    let names = if value.get("names").is_none() {
        Vec::new()
    } else {
        subscription_names(value, "subscriptions update")?
    };
    if names.is_empty() {
        // Go treats an empty name list as "refresh all".  The Rust refresh
        // worker is intentionally deferred, but an empty store still has the
        // same observable no-op success as the Go implementation.
        return empty();
    }
    Err(ApiError::unavailable(format!(
        "subscription refresh is not implemented for: {}",
        names.join(", ")
    )))
}

pub fn subscription_records(value: &Value) -> Result<Vec<GoSubscriptionLinkRecord>, ApiError> {
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad("subscriptions requires an items array"))?;
    items
        .iter()
        .map(|item| {
            let object = item
                .as_object()
                .ok_or_else(|| ApiError::bad("subscription item must be an object"))?;
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned();
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned();
            let link_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("reserve")
                .trim()
                .to_owned();
            Ok(GoSubscriptionLinkRecord {
                name,
                url,
                link_type,
                updated_at: 0,
                data_json: serde_json::to_vec(item)?,
            })
        })
        .collect()
}

pub fn subscription_names(value: &Value, operation: &str) -> Result<Vec<String>, ApiError> {
    value
        .get("names")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad(format!("{operation} requires a names array")))?
        .iter()
        .map(|name| {
            name.as_str()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| ApiError::bad(format!("{operation} names must be strings")))
        })
        .collect()
}

pub fn subscription_json(record: GoSubscriptionLinkRecord) -> Value {
    let mut value = raw_json(&record.data_json, json!({}));
    set_string(&mut value, "name", record.name);
    set_string(&mut value, "url", record.url);
    set_string(&mut value, "type", record.link_type);
    value
}

pub async fn publishes_get_value(state: &ApiState) -> ApiResult {
    let items = state
        .controller
        .store()
        .repository()
        .list_go_publishes()
        .await?
        .into_iter()
        .map(decode_publish_record)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Json(json!({"items": items})))
}

pub async fn publish_put_value(state: &ApiState, value: Value) -> ApiResult {
    let mut publish = parse_publish_contract(&value)?;
    publish.name = publish.name.trim().to_owned();
    if publish.name.is_empty() {
        return Err(ApiError::bad("publish name is empty"));
    }
    let data_json = serde_json::to_vec(&publish)
        .map_err(|error| ApiError::bad(format!("encode publish failed: {error}")))?;
    state
        .controller
        .store()
        .repository()
        .put_go_publish(&GoPublishRecord {
            name: publish.name.clone(),
            updated_at: unix_seconds(),
            data_json,
        })
        .await?;
    empty()
}

pub async fn publish_delete_value(state: &ApiState, name: String) -> ApiResult {
    let deleted = state
        .controller
        .store()
        .repository()
        .delete_go_publish(&name)
        .await?;
    if !deleted {
        return Err(ApiError::not_found(format!(
            "publish {name:?} was not found"
        )));
    }
    empty()
}

pub async fn publish_resolve_value(state: &ApiState, value: &Value) -> ApiResult {
    let name = required_string(value, "name")?;
    let publish = state
        .controller
        .store()
        .repository()
        .list_go_publishes()
        .await?
        .into_iter()
        .find(|record| record.name == name)
        .map(decode_publish_contract)
        .transpose()?;
    let Some(publish) = publish else {
        return json_value(json!({"points": Value::Null}));
    };
    let requested_path = string_or(value, "path", "");
    let requested_password = string_or(value, "password", "");
    if publish.path != requested_path || publish.password != requested_password {
        return json_value(json!({"points": Value::Null}));
    }
    let points = publish
        .points
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let nodes = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?
        .into_iter()
        .filter(|node| points.contains(node.id.as_str()))
        .map(node_json)
        .collect::<Vec<_>>();
    json_value(json!({"points": nodes}))
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PublishContract {
    #[serde(default)]
    name: String,
    #[serde(default)]
    points: Vec<String>,
    #[serde(default)]
    path: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    insecure: bool,
}

pub fn parse_publish_contract(value: &Value) -> Result<PublishContract, ApiError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ApiError::bad(format!("invalid publish contract: {error}")))
}

pub fn decode_publish_record(record: GoPublishRecord) -> Result<Value, ApiError> {
    let publish = decode_publish_contract(record)?;
    serde_json::to_value(publish)
        .map_err(|error| ApiError::internal(format!("encode publish response: {error}")))
}

pub fn decode_publish_contract(record: GoPublishRecord) -> Result<PublishContract, ApiError> {
    let mut publish: PublishContract =
        serde_json::from_slice(&record.data_json).map_err(|error| {
            ApiError::internal(format!("decode publish {:?}: {error}", record.name))
        })?;
    publish.name = publish.name.trim().to_owned();
    if publish.name.is_empty() {
        publish.name = record.name;
    }
    if publish.name.is_empty() {
        return Err(ApiError::internal("stored publish name is empty"));
    }
    Ok(publish)
}
