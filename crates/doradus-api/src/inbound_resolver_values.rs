use super::*;
pub async fn inbounds_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_inbounds()
        .await?;
    Ok(Json(page_with_filter(
        records.into_iter().map(inbound_json).collect(),
        input,
        inbound_matches_query,
    )))
}

pub async fn get_inbound_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_inbounds()
        .await?;
    records
        .into_iter()
        .find(|record| record.id == id)
        .map(|record| Json(inbound_json(record)))
        .ok_or_else(|| ApiError::not_found("inbound not found"))
}

pub async fn inbounds_status_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_inbounds()
        .await?;
    let runtime = state.controller.inbound_runtime().snapshot();
    let statistics = state.controller.monitor().inbound_statistics();
    let items = records
        .into_iter()
        .map(|record| {
            let status = runtime.iter().find(|status| status.id == record.id);
            let stat = statistics
                .iter()
                .find(|statistics| statistics.inbound_id == record.id);
            let status_name = status
                .map(|status| status.state.as_str())
                .unwrap_or(if record.enabled { "starting" } else { "disabled" });
            let listeners = status
                .map(|status| serde_json::to_value(&status.listeners).unwrap_or_else(|_| json!([])))
                .unwrap_or_else(|| json!([]));
            json!({
                "id": record.id,
                "name": record.name,
                "enabled": record.enabled,
                "status": status_name,
                "lastError": status.and_then(|status| status.last_error.clone()),
                "changedAt": status.map(|status| status.changed_at).unwrap_or_default(),
                "listeners": listeners,
                "statistics": {
                    "activeTcp": stat.map(|stat| stat.active_tcp).unwrap_or_default(),
                    "activeUdp": stat.map(|stat| stat.active_udp).unwrap_or_default(),
                    "totalTcpFlows": stat.map(|stat| stat.total_tcp_flows).unwrap_or_default(),
                    "totalUdpFlows": stat.map(|stat| stat.total_udp_flows).unwrap_or_default(),
                    "uploadBytes": stat.map(|stat| stat.upload_bytes).unwrap_or_default().to_string(),
                    "downloadBytes": stat.map(|stat| stat.download_bytes).unwrap_or_default().to_string(),
                },
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"items": items})))
}

pub async fn inbound_events_value(state: &ApiState, id: String) -> ApiResult {
    let events = state
        .controller
        .store()
        .list_inbound_runtime_events(&id, 100)?;
    let items = events
        .into_iter()
        .map(|event| {
            let detail = serde_json::from_slice(&event.detail_json).unwrap_or_else(|_| json!({}));
            json!({
                "id": event.id,
                "inboundId": event.inbound_id,
                "type": event.event_type,
                "state": event.state,
                "error": event.error,
                "detail": detail,
                "createdAt": event.created_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"items": items})))
}

pub async fn retry_inbound_value(state: &ApiState, id: String) -> ApiResult {
    state.controller.retry_inbound(id).await?;
    Ok(empty_json())
}

pub async fn save_inbound_value(
    state: &ApiState,
    value: Value,
    _index: Option<usize>,
) -> ApiResult {
    let mut value = value;
    doradus_runtime::inbound::fill_generated_fields(&mut value)?;
    let id = required_string(&value, "id")?;
    let record = GoInboundRecord {
        id: id.clone(),
        name: string_or(&value, "name", &id),
        enabled: bool_or(&value, "enabled", true),
        network_type: nested_type(&value, "network"),
        protocol_type: nested_type(&value, "protocol"),
        transport_types_json: serde_json::to_vec(
            &value
                .get("transports")
                .cloned()
                .unwrap_or_else(|| json!([])),
        )?,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
    };
    state
        .controller
        .mutate_and_reload_inbound_blocking(id.clone(), move |store| {
            store.repository().put_go_inbound_sync(&record)
        })
        .await?;
    // Go's saveInbound calls Inbounds.Get after Save, so the response is the
    // persisted contract (including any fields normalized by the store), not
    // the request JSON verbatim.
    get_inbound_value(state, id).await
}

pub async fn delete_inbound_value(state: &ApiState, id: String) -> ApiResult {
    let result = state
        .controller
        .mutate_and_reload_inbound_blocking(id.clone(), move |store| {
            if store.repository().delete_go_inbound_sync(&id)? {
                Ok(())
            } else {
                Err(doradus_core::Error::new(
                    doradus_core::ErrorKind::NotFound,
                    "inbound not found",
                ))
            }
        })
        .await;
    result.map(|_| empty_json()).map_err(|error| {
        if error.to_string().contains("not found") {
            ApiError::not_found(error.to_string())
        } else {
            error.into()
        }
    })
}

pub async fn resolvers_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_resolvers()
        .await?;
    Ok(Json(page_with_filter(
        records.into_iter().map(resolver_json).collect(),
        input,
        resolver_matches_query,
    )))
}

pub async fn get_resolver_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_resolvers()
        .await?;
    records
        .into_iter()
        .find(|record| record.id == id)
        .map(|record| Json(resolver_json(record)))
        .ok_or_else(|| ApiError::not_found("resolver not found"))
}

pub async fn save_resolver_value(
    state: &ApiState,
    value: Value,
    _index: Option<usize>,
) -> ApiResult {
    let id = required_string(&value, "id")?;
    let resolver_type = string_or(&value, "type", "udp");
    let mut host = string_or(
        &value,
        "host",
        if resolver_type == "system" {
            "system default"
        } else {
            ""
        },
    );
    if resolver_type == "system" && host.trim().is_empty() {
        host = "system default".to_owned();
    }
    if resolver_type != "system" && host.trim().is_empty() {
        return Err(ApiError::bad("resolver host is empty"));
    }
    let normalized_id = id.trim().to_owned();
    let mut persisted_value = value.clone();
    set_string(&mut persisted_value, "id", normalized_id.clone());
    set_string(&mut persisted_value, "type", resolver_type.clone());
    set_string(&mut persisted_value, "host", host.clone());
    if resolver_type == "system" {
        set_bool(&mut persisted_value, "system", true);
    }
    let record = GoResolverRecord {
        id: normalized_id,
        resolver_type,
        host,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload_blocking(move |store| store.repository().put_go_resolver_sync(&record))
        .await?;
    Ok(Json(returned))
}

pub async fn delete_resolver_value(state: &ApiState, id: String) -> ApiResult {
    let result = state
        .controller
        .mutate_and_reload_blocking(move |store| {
            if store.repository().delete_go_resolver_sync(&id)? {
                Ok(())
            } else {
                Err(doradus_core::Error::new(
                    doradus_core::ErrorKind::NotFound,
                    "resolver not found",
                ))
            }
        })
        .await;
    result.map(|_| empty_json()).map_err(|error| {
        if error.to_string().contains("not found") {
            ApiError::not_found(error.to_string())
        } else {
            error.into()
        }
    })
}
