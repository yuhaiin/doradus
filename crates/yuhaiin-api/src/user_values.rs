use super::*;
pub async fn users_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let page = input
        .get("page")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1) as usize;
    let page_size = input
        .get("page_size")
        .or_else(|| input.get("pageSize"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let query = input.get("query").and_then(Value::as_str);
    let (items, total) = state
        .controller
        .store()
        .repository()
        .list_go_user_views(query, page, page_size)
        .await?;
    json_value(json!({
        "items": items,
        "page": {"page": page, "pageSize": page_size, "total": total}
    }))
}

pub async fn user_get_value(state: &ApiState, id: String) -> ApiResult {
    let user = state
        .controller
        .store()
        .repository()
        .get_go_user_view(&id)
        .await?;
    json_value(serde_json::to_value(user)?)
}

#[derive(Debug, Deserialize)]
pub struct GoUserPutRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    usage: String,
    #[serde(default)]
    credential: Option<yuhaiin_store::GoCredential>,
}

pub async fn user_save_value(state: &ApiState, value: Value, id: Option<String>) -> ApiResult {
    if let Some(id) = id {
        let request: GoUserPutRequest = serde_json::from_value(value)
            .map_err(|error| ApiError::bad(format!("invalid user update: {error}")))?;
        let reload_id = id.clone();
        state
            .controller
            .mutate_and_reload_inbounds(move |store| async move {
                let repository = store.repository();
                let mut user: GoUserRecord = repository.get_go_user(&reload_id).await?;
                user.name = request.name;
                user.enabled = request.enabled;
                user.usage = request.usage;
                if let Some(credential) = request.credential {
                    user.credential = credential;
                }
                user.updated_at = unix_seconds();
                repository.save_go_user(&user).await
            })
            .await?;
        let view = state
            .controller
            .store()
            .repository()
            .get_go_user_view(&id)
            .await?;
        json_value(serde_json::to_value(view)?)
    } else {
        let write: GoUserWrite = serde_json::from_value(value)
            .map_err(|error| ApiError::bad(format!("invalid user contract: {error}")))?;
        let record = GoUserRecord::from(write);
        let id = record.id.clone();
        state
            .controller
            .mutate_and_reload_inbounds(move |store| async move {
                store.repository().save_go_user(&record).await
            })
            .await?;
        let view = state
            .controller
            .store()
            .repository()
            .get_go_user_view(&id)
            .await?;
        json_value(serde_json::to_value(view)?)
    }
}

pub async fn user_delete_value(state: &ApiState, id: String) -> ApiResult {
    state
        .controller
        .mutate_and_reload_inbounds(move |store| async move {
            store.repository().delete_go_user(&id).await
        })
        .await?;
    empty()
}
