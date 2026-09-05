use super::*;
pub async fn info(State(state): State<ApiState>) -> ApiResult {
    info_value(&state)
}

pub async fn update_check(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    update_check_value(&state, &value).await
}

pub async fn update_apply(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    update_apply_value(&state, &value).await
}

pub async fn update_status(State(state): State<ApiState>) -> ApiResult {
    update_status_value(&state).await
}

pub fn info_value(state: &ApiState) -> ApiResult {
    json_value(json!({
        "version": state.version,
        "commit": "",
        "buildTime": "",
        "goVersion": "",
        "arch": std::env::consts::ARCH,
        "platform": std::env::consts::FAMILY,
        "os": std::env::consts::OS,
        "compiler": "rustc",
        "build": ["rust", "lite"],
    }))
}

pub async fn settings_get(State(state): State<ApiState>) -> ApiResult {
    settings_get_value(&state).await
}

pub async fn settings_get_value(state: &ApiState) -> ApiResult {
    if let Some(bytes) = state.controller.store().get_config("settings").await? {
        return json_value(canonical_settings_value(&raw_json(
            &bytes,
            default_settings(),
        )));
    }
    let values = state
        .controller
        .store()
        .repository()
        .list_go_settings_kv()
        .await?;
    if !values.is_empty() {
        return json_value(settings_value_from_go_kv(&values));
    }
    json_value(default_settings())
}

pub async fn settings_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    write_config_json(&state, "settings", value).await
}

pub async fn backup_config_get(State(state): State<ApiState>) -> ApiResult {
    backup_config_get_value(&state).await
}

pub async fn backup_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    backup_config_put_value(&state, value).await
}

pub async fn backup_config_get_value(state: &ApiState) -> ApiResult {
    json_value(load_backup_config_value(state).await?)
}

pub async fn load_backup_config_value(state: &ApiState) -> Result<Value, ApiError> {
    let value = if let Some(record) = state
        .controller
        .store()
        .repository()
        .get_go_backup_settings()
        .await?
    {
        raw_json(&record.data_json, default_backup_config())
    } else {
        let value = state.controller.store().get_config("backup.config").await?;
        value
            .as_deref()
            .map(|bytes| raw_json(bytes, default_backup_config()))
            .unwrap_or_else(default_backup_config)
    };

    // Go's BackupStore.Get lazily assigns a stable v4 UUID when an older
    // snapshot has no instance name. Persist it through the same Go-shaped
    // row and Rust overlay so the next API read, backup object name, and a
    // later process restart all observe the same identity.
    if value
        .get("instanceName")
        .and_then(Value::as_str)
        .is_some_and(|instance| !instance.is_empty())
    {
        return Ok(value);
    }
    let mut value = value;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "instanceName".to_owned(),
            Value::String(uuid::Uuid::new_v4().to_string()),
        );
    } else {
        value = default_backup_config();
        value["instanceName"] = Value::String(uuid::Uuid::new_v4().to_string());
    }
    persist_backup_config_value(state, value.clone()).await?;
    Ok(value)
}

pub async fn backup_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let bytes = serde_json::to_vec(&value)?;
    let updated_at = unix_seconds();
    let record = GoBackupSettingsRecord {
        updated_at,
        data_json: bytes.clone(),
    };
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config("backup.config", &bytes).await?;
            store.repository().put_go_backup_settings(&record).await
        })
        .await?;
    json_value(value)
}

pub async fn backup_run(State(state): State<ApiState>) -> ApiResult {
    run_backup_value(&state).await
}

pub async fn backup_restore(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    restore_backup_value(&state, &value).await
}

pub async fn nodes_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    nodes_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn nodes_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_node_value(&state, value, None).await
}

pub async fn nodes_selected(State(state): State<ApiState>) -> ApiResult {
    selected_nodes_value(&state).await
}

pub async fn nodes_active(State(state): State<ApiState>) -> ApiResult {
    active_nodes_value(&state).await
}

pub async fn node_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_node_value(&state, id).await
}

pub async fn node_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_node_value(&state, value, None).await
}

pub async fn node_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_node_value(&state, id).await
}

pub async fn node_use(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    select_node_value(&state, id).await
}

pub async fn node_latency(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    node_latency_value(&state, &value).await
}

pub async fn node_close(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    node_close_value(&state, id).await
}

pub async fn node_close_value(state: &ApiState, id: String) -> ApiResult {
    if id.trim().is_empty() {
        return Err(ApiError::bad("node id is required"));
    }
    state
        .controller
        .close_node(&id)
        .await
        .map_err(ApiError::from)?;
    empty()
}

pub async fn connections_get(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().connections_value())
}

pub async fn connections_total(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().total_flow_value())
}

#[derive(Debug, Default, Deserialize)]
pub struct TrafficQuery {
    interval: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TelemetryQuery {
    from: Option<String>,
    to: Option<String>,
    limit: Option<u64>,
}

pub async fn connections_traffic(
    State(state): State<ApiState>,
    Query(query): Query<TrafficQuery>,
) -> ApiResult {
    let (from, to) = required_stats_range(query.from.as_deref(), query.to.as_deref())?;
    json_value(state.controller.monitor().traffic_value_range(
        query.interval.as_deref().unwrap_or("hour"),
        from,
        to,
    ))
}

pub async fn connections_telemetry(
    State(state): State<ApiState>,
    Query(query): Query<TelemetryQuery>,
) -> ApiResult {
    let (from, to) = required_stats_range(query.from.as_deref(), query.to.as_deref())?;
    let limit = query.limit.unwrap_or(8);
    if !(1..=50).contains(&limit) {
        return Err(ApiError::bad("limit must be between 1 and 50"));
    }
    json_value(
        state
            .controller
            .monitor()
            .telemetry_value_range(from, to, limit as usize),
    )
}

pub async fn connections_failed_history(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().failed_history_value())
}

pub async fn connections_history(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().all_history_value())
}

pub async fn connections_close(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    close_connections_value(&state, value).await
}

pub async fn close_connections_value(state: &ApiState, value: Value) -> ApiResult {
    let ids = match value.get("ids") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                let id = value
                    .as_str()
                    .ok_or_else(|| ApiError::bad("connection ids must be strings"))?;
                id.parse::<u64>()
                    .map_err(|_| ApiError::bad(format!("invalid connection id {id:?}")))?;
                Ok::<_, ApiError>(id.to_owned())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => return Err(ApiError::bad("connections close ids must be an array")),
    };
    state.controller.monitor().request_close(&ids);
    empty()
}

pub async fn connections_events(State(state): State<ApiState>) -> Response {
    let monitor = state.controller.monitor();
    let (initial, receiver) = monitor.initial_event_and_subscribe();
    let updates = BroadcastStream::new(receiver).filter_map(|event| {
        event.ok().map(|event| {
            SseEvent::default()
                .event(event.kind)
                .json_data(event.payload)
                .unwrap_or_else(|_| SseEvent::default())
        })
    });
    let stream = tokio_stream::iter(vec![Ok::<SseEvent, Infallible>(
        SseEvent::default()
            .event(initial.kind)
            .json_data(initial.payload)
            .unwrap_or_else(|_| SseEvent::default()),
    )])
    .chain(updates.map(Ok));
    sse_response(Sse::new(stream).keep_alive(KeepAlive::default()))
}

pub async fn tools_logs(State(state): State<ApiState>) -> Response {
    tools_logs_v2(State(state)).await
}

pub async fn tools_logs_v2(State(state): State<ApiState>) -> Response {
    let (snapshot, receiver) = state.controller.monitor().logs().snapshot_and_subscribe();
    let initial = SseEvent::default()
        .event("log")
        .json_data(log_batch_value(snapshot))
        .unwrap_or_else(|_| SseEvent::default());
    let updates = BroadcastStream::new(receiver).filter_map(|batch| {
        batch.ok().map(|lines| {
            SseEvent::default()
                .event("log")
                .json_data(log_batch_value(lines))
                .unwrap_or_else(|_| SseEvent::default())
        })
    });
    let stream =
        tokio_stream::iter(vec![Ok::<SseEvent, Infallible>(initial)]).chain(updates.map(Ok));
    sse_response(Sse::new(stream).keep_alive(KeepAlive::default()))
}

pub fn sse_response<T>(sse: Sse<T>) -> Response
where
    T: futures_util::Stream<Item = Result<SseEvent, Infallible>> + Send + 'static,
{
    let mut response = sse.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("keep-alive"),
    );
    response
}

pub async fn tools_interfaces() -> ApiResult {
    tools_interfaces_value()
}

pub async fn tools_licenses() -> ApiResult {
    tools_licenses_value()
}

pub async fn subscriptions_get(State(state): State<ApiState>) -> ApiResult {
    subscriptions_get_value(&state).await
}

pub async fn subscriptions_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_put_value(&state, value).await
}

pub async fn subscriptions_delete(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_delete_value(&state, &value).await
}

pub async fn subscriptions_delete_preview(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_delete_preview_value(&state, &value).await
}

pub async fn subscriptions_update(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_update_value(&state, &value).await
}

pub async fn publishes(State(state): State<ApiState>) -> ApiResult {
    publishes_get_value(&state).await
}

pub async fn publish_put(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    publish_put_value(&state, value).await
}

pub async fn publish_delete(State(state): State<ApiState>, Path(name): Path<String>) -> ApiResult {
    publish_delete_value(&state, name).await
}

pub async fn publish_resolve(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    publish_resolve_value(&state, &value).await
}

pub async fn inbounds_config_get(State(state): State<ApiState>) -> ApiResult {
    inbounds_config_get_value(&state).await
}

pub async fn inbounds_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    inbounds_config_put_value(&state, value).await
}

pub async fn inbounds_config_get_value(state: &ApiState) -> ApiResult {
    let settings = state
        .controller
        .store()
        .repository()
        .get_inbound_settings()
        .await?;
    json_value(serde_json::to_value(settings)?)
}

pub async fn inbounds_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let settings: InboundSettings = serde_json::from_value(value)
        .map_err(|error| ApiError::bad(format!("invalid inbound settings: {error}")))?;
    state
        .controller
        .mutate_and_reload_blocking(move |store| {
            store.repository().put_inbound_settings_sync(settings)
        })
        .await?;
    json_value(serde_json::to_value(settings)?)
}

pub async fn users_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    users_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn users_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    user_save_value(&state, value, None).await
}

pub async fn user_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    user_get_value(&state, id).await
}

pub async fn user_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id.clone());
    user_save_value(&state, value, Some(id)).await
}

pub async fn user_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    user_delete_value(&state, id).await
}

pub async fn inbounds_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    inbounds_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn inbounds_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_inbound_value(&state, value, None).await
}

pub async fn inbound_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_inbound_value(&state, id).await
}

pub async fn inbounds_status(State(state): State<ApiState>) -> ApiResult {
    inbounds_status_value(&state).await
}

pub async fn inbound_events(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    inbound_events_value(&state, id).await
}

pub async fn inbound_retry(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    retry_inbound_value(&state, id).await
}

pub async fn inbound_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_inbound_value(&state, value, None).await
}

pub async fn inbound_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_inbound_value(&state, id).await
}

pub async fn resolvers_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    resolvers_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn resolvers_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_resolver_value(&state, value, None).await
}

pub async fn resolver_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_resolver_value(&state, id).await
}

pub async fn resolver_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_resolver_value(&state, value, None).await
}

pub async fn resolver_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_resolver_value(&state, id).await
}

pub async fn route_config_get(State(state): State<ApiState>) -> ApiResult {
    route_config_get_value(&state).await
}

pub async fn route_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_config_put_value(&state, value).await
}

pub async fn route_lists_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    route_lists_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn route_lists_post(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    save_route_list_value(&state, value, None).await
}

pub async fn route_lists_config_get(State(state): State<ApiState>) -> ApiResult {
    route_lists_config_get_value(&state).await
}

pub async fn route_lists_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_lists_config_put_value(&state, value).await
}
