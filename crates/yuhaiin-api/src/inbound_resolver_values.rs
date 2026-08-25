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

pub async fn save_inbound_value(
    state: &ApiState,
    value: Value,
    _index: Option<usize>,
) -> ApiResult {
    let mut value = value;
    yuhaiin_runtime::inbound::fill_generated_fields(&mut value)?;
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
        .mutate_and_reload_inbound(id.clone(), move |store| async move {
            store.repository().put_go_inbound(&record).await
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
        .mutate_and_reload_inbound(id.clone(), move |store| async move {
            if store.repository().delete_go_inbound(&id).await? {
                Ok(())
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
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
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_resolver(&record).await },
        )
        .await?;
    Ok(Json(returned))
}

pub async fn delete_resolver_value(state: &ApiState, id: String) -> ApiResult {
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            if store.repository().delete_go_resolver(&id).await? {
                Ok(())
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
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
