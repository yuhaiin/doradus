use super::*;
pub async fn nodes_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    let values = records.into_iter().map(node_json).collect::<Vec<_>>();
    Ok(Json(page_with_filter(values, input, node_matches_query)))
}

pub async fn get_node_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    records
        .into_iter()
        .find(|record| record.id == id)
        .map(|record| Json(node_json(record)))
        .ok_or_else(|| ApiError::not_found(format!("node {id:?} was not found")))
}

pub async fn save_node_value(state: &ApiState, value: Value, _index: Option<usize>) -> ApiResult {
    let id = required_string(&value, "id")?;
    let chain_types = node_chain_types(&value);
    if chain_types.is_empty() {
        return Err(ApiError::bad("node chain/protocol is empty"));
    }
    let group_name = match string_or_any(&value, &["group", "groupName", "group_name"]).as_str() {
        // Go's contract.node.Node has no default for group. Preserve an
        // omitted/empty group in the public API; internal runtime-created
        // nodes may still use the explicit "default" group where needed.
        "" => String::new(),
        group => group.to_owned(),
    };
    // `nodes_v2.data_json` is also consumed directly by Go's plain-contract
    // reader. Keep the persisted JSON in the same canonical shape as the
    // response and the typed columns; otherwise a normal frontend request
    // without `origin` can be returned successfully by Rust but makes Go's
    // node decoder fail with `node origin is empty` after rollback.
    let node_name = string_or(&value, "name", &id);
    let enabled = bool_or(&value, "enabled", true);
    let mut persisted_value = value;
    set_string(&mut persisted_value, "id", id.clone());
    set_string(&mut persisted_value, "name", node_name);
    set_string(&mut persisted_value, "group", group_name.clone());
    set_string(&mut persisted_value, "origin", "manual");
    set_bool(&mut persisted_value, "enabled", enabled);
    let record = GoNodeRecord {
        id: id.clone(),
        name: string_or(&persisted_value, "name", &id),
        group_name,
        // NodeRuntime.Save in Go intentionally marks every API save as a
        // manually managed node, regardless of the request's origin.
        origin: "manual".to_owned(),
        enabled,
        chain_types_json: serde_json::to_vec(&chain_types)?,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    state
        .controller
        .mutate_and_reload_blocking(move |store| store.repository().put_go_node_sync(&record))
        .await?;
    get_node_value(state, id).await
}

pub async fn delete_node_value(state: &ApiState, id: String) -> ApiResult {
    if !state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?
        .iter()
        .any(|node| node.id == id)
    {
        return Err(ApiError::not_found(format!("node {id:?} was not found")));
    }
    state
        .controller
        .retarget_node_to_direct(&id)
        .await
        .map_err(ApiError::from)?;
    let removed = state
        .controller
        .mutate_and_reload_blocking(move |store| {
            let selected_fallback = br##"{"id":"direct"}"##.to_vec();
            for key in [
                SELECTED_TCP_NODE_KEY,
                SELECTED_UDP_NODE_KEY,
                LEGACY_SELECTED_NODE_KEY,
            ] {
                let selected = store
                    .get_config_sync(key)?
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
                if selected.as_deref() == Some(id.as_str()) {
                    store.put_config_sync(key, &selected_fallback)?;
                }
            }
            if store.repository().delete_go_node_sync(&id)? {
                Ok(())
            } else {
                Err(doradus_core::Error::new(
                    doradus_core::ErrorKind::NotFound,
                    "node not found",
                ))
            }
        })
        .await;
    removed.map(|_| empty_json()).map_err(|error| {
        if error.to_string().contains("not found") {
            ApiError::not_found(error.to_string())
        } else {
            error.into()
        }
    })
}

pub async fn selected_nodes_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    let tcp = selected_node_record(state, &records, SELECTED_TCP_NODE_KEY).await?;
    let udp = selected_node_record(state, &records, SELECTED_UDP_NODE_KEY).await?;
    let mut selection = Map::new();
    if let Some(record) = tcp {
        selection.insert("tcp".to_owned(), node_json(record));
    }
    if let Some(record) = udp {
        selection.insert("udp".to_owned(), node_json(record));
    }
    Ok(Json(Value::Object(selection)))
}

pub async fn selected_node_id(state: &ApiState, key: &str) -> Result<Option<String>, ApiError> {
    let selected = state
        .controller
        .store()
        .get_config(key)
        .await?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
    if selected.is_some() || key == LEGACY_SELECTED_NODE_KEY {
        return Ok(selected);
    }
    let legacy = state
        .controller
        .store()
        .get_config(LEGACY_SELECTED_NODE_KEY)
        .await?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
    if legacy.is_some() {
        return Ok(legacy);
    }
    Ok(state
        .controller
        .store()
        .repository()
        .get_go_selected_node_id(key)
        .await?)
}

pub async fn selected_node_record(
    state: &ApiState,
    records: &[GoNodeRecord],
    key: &str,
) -> Result<Option<GoNodeRecord>, ApiError> {
    let selected_id = selected_node_id(state, key).await?;
    Ok(selected_id
        .as_deref()
        .and_then(|id| records.iter().find(|record| record.id == id))
        .cloned())
}

pub async fn active_nodes_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    let active_ids = state.controller.active_proxy_ids();
    Ok(Json(
        json!({"items": records.into_iter().filter(|record| active_ids.binary_search(&record.id).is_ok()).map(node_json).collect::<Vec<_>>() }),
    ))
}

pub async fn select_node_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    if !records.iter().any(|record| record.id == id) {
        return Err(ApiError::not_found(format!("node {id:?} was not found")));
    }
    let selected_id = id.clone();
    let bytes = serde_json::to_vec(&json!({"id": id}))?;
    state
        .controller
        .mutate_and_reload_inbounds_blocking(move |store| {
            store.put_config_sync(SELECTED_TCP_NODE_KEY, &bytes)?;
            store.put_config_sync(SELECTED_UDP_NODE_KEY, &bytes)?;
            store.put_config_sync(LEGACY_SELECTED_NODE_KEY, &bytes)?;
            store
                .repository()
                .put_go_selected_node_ids_sync(&selected_id)
        })
        .await?;
    Ok(empty_json())
}
