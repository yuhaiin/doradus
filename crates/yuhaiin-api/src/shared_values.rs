use super::*;
pub async fn tags_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let values = state
        .controller
        .store()
        .repository()
        .list_go_node_tags()
        .await?
        .into_iter()
        .map(|record| {
            let mut value = serde_json::from_slice::<Value>(&record.members_json)?;
            let object = value.as_object_mut().ok_or_else(|| {
                ApiError::internal(format!(
                    "stored route tag {:?} is not a JSON object",
                    record.name
                ))
            })?;
            if object
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|name| name.trim().is_empty())
            {
                object.insert("name".to_owned(), Value::String(record.name));
            }
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|tag_type| tag_type.trim().is_empty())
            {
                object.insert("type".to_owned(), Value::String("node".to_owned()));
            }
            let tag_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if tag_type != "node" && tag_type != "mirror" {
                return Err(ApiError::internal(format!(
                    "stored route tag type {tag_type:?} is invalid"
                )));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(page_with_filter(values, input, tag_matches_query)))
}

pub async fn tag_put_value(state: &ApiState, value: Value) -> ApiResult {
    let name = required_string(&value, "tag")?.trim().to_owned();
    let mut tag_type = string_or(&value, "type", "node");
    if tag_type.trim().is_empty() {
        tag_type = "node".to_owned();
    }
    if tag_type != "node" && tag_type != "mirror" {
        return Err(ApiError::bad(format!("unknown tag type {tag_type:?}")));
    }
    let hash = string_or(&value, "hash", "");
    let tag = json!({"name": name, "type": tag_type, "hash": [hash]});
    let record = yuhaiin_store::GoNodeTagRecord {
        id: name.clone(),
        name,
        members_json: serde_json::to_vec(&tag)?,
        updated_at: unix_seconds(),
    };
    state
        .controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_node_tag(&record).await },
        )
        .await?;
    Ok(empty_json())
}

pub async fn tag_delete_value(state: &ApiState, tag: String) -> ApiResult {
    let tag = tag.trim().to_owned();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            let deleted = store.repository().delete_go_node_tag_by_name(&tag).await?;
            if deleted {
                Ok(())
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
                    format!("tag {tag:?} was not found"),
                ))
            }
        })
        .await?;
    empty()
}

pub async fn update_check_value(state: &ApiState, body: &Value) -> ApiResult {
    let channel = string_or(body, "channel", "stable");
    match state.update.check(&channel).await {
        Ok(result) => json_value(serde_json::to_value(result).unwrap_or_else(|_| json!({}))),
        Err(error) => Err(ApiError::unavailable(error)),
    }
}

pub fn required_stats_range(from: Option<&str>, to: Option<&str>) -> Result<(i64, i64), ApiError> {
    let from = from.ok_or_else(|| ApiError::bad("from must be an RFC3339 timestamp"))?;
    let to = to.ok_or_else(|| ApiError::bad("to must be an RFC3339 timestamp"))?;
    let from = OffsetDateTime::parse(from, &Rfc3339)
        .map_err(|_| ApiError::bad("from must be an RFC3339 timestamp"))?;
    let to = OffsetDateTime::parse(to, &Rfc3339)
        .map_err(|_| ApiError::bad("to must be an RFC3339 timestamp"))?;
    if from >= to {
        return Err(ApiError::bad("from must be before to"));
    }
    Ok((from.unix_timestamp(), to.unix_timestamp()))
}

pub async fn update_apply_value(state: &ApiState, value: &Value) -> ApiResult {
    let channel = string_or(value, "channel", "stable");
    let target_tag = required_string(value, "targetTag")?;
    state
        .update
        .apply(&channel, &target_tag)
        .await
        .map_err(ApiError::unavailable)?;
    empty()
}

pub async fn update_status_value(state: &ApiState) -> ApiResult {
    json_value(serde_json::to_value(state.update.status()).unwrap_or_else(|_| json!({})))
}

pub fn latency_probe_outer_timeout(request: &LatencyRequest, timeout: Duration) -> Duration {
    let probe_type = request.probe_type.trim();
    if probe_type != "stun" && probe_type != "stun_tcp" {
        return timeout;
    }

    // Go gives each NAT-behavior request a five-second deadline. Mapping can
    // use three requests and Filtering can use another three, so the API
    // wrapper must not cancel a valid STUN classification after one ten-second
    // request budget has elapsed.
    if probe_type == "stun_tcp" || request.tcp {
        timeout.saturating_mul(3)
    } else {
        timeout.saturating_add(timeout.min(Duration::from_secs(5)).saturating_mul(6))
    }
}

pub async fn node_latency_value(state: &ApiState, value: &Value) -> ApiResult {
    let id = required_string(value, "id")?;
    let timeout = Duration::from_millis(
        value
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(10_000)
            .clamp(100, 120_000),
    );
    let snapshot = state.controller.handle().load();
    // Go's IP latency probe uses netapi.Bootstrap(), not the FakeDNS wrapper.
    // The direct-route resolver is the Rust public equivalent here; it is only
    // for the management probe target, while the node proxy handles the
    // actual connection.
    let resolver = snapshot
        .dns_resolver_for_route_mode(yuhaiin_core::RouteMode::Direct)
        .map_err(ApiError::from)?;
    let proxy = snapshot
        .build_proxy(&id, timeout)
        .await
        .map_err(ApiError::from)?
        .proxy;
    let request: LatencyRequest = serde_json::from_value(value.clone())?;
    let outer_timeout = latency_probe_outer_timeout(&request, timeout);
    match tokio::time::timeout(
        outer_timeout,
        yuhaiin_runtime::latency::probe_with_resolver(proxy, resolver, request, timeout),
    )
    .await
    {
        Ok(Ok(response)) => json_value(serde_json::to_value(response)?),
        Ok(Err(error)) => json_value(json!({"ok": false, "error": error.to_string()})),
        Err(_) => json_value(json!({"ok": false, "error": "latency probe timed out"})),
    }
}

pub async fn run_backup_value(state: &ApiState) -> ApiResult {
    let _backup_guard = state.backup_lock.lock().await;
    let config = load_backup_config_value(state).await?;
    let s3 = backup_s3_config(&config)?;
    if !s3.enabled {
        return Err(ApiError::bad("backup.run requires enabled S3 backup"));
    }
    let client = backup_s3_client(state, s3.clone()).await?;
    let object = backup_object_name(&config)?;
    let destination = backup_destination()?;
    let result = async {
        state
            .controller
            .store()
            .backup_to(&destination)
            .await
            .map_err(ApiError::from)?;
        let state_bytes = std::fs::read(&destination)
            .map_err(|error| ApiError::internal(format!("read SQLite backup: {error}")))?;
        let hash = backup_hash(&state_bytes, &s3)?;
        let previous = string_or(&config, "lastBackupHash", "");
        if previous != hash {
            client
                .put(&object, &state_bytes)
                .await
                .map_err(|error| ApiError::unavailable(format!("S3 backup upload: {error}")))?;
            let mut updated = config;
            set_string(&mut updated, "lastBackupHash", hash);
            persist_backup_config_value(state, updated).await?;
        }
        Ok::<(), ApiError>(())
    }
    .await;
    let _ = std::fs::remove_file(&destination);
    result.map(|()| Json(json!({})))
}

pub async fn restore_backup_value(state: &ApiState, value: &Value) -> ApiResult {
    let _backup_guard = state.backup_lock.lock().await;
    let source = string_or_any(value, &["path", "source", "file"]);
    let source = if source.trim().is_empty() {
        let config = load_backup_config_value(state).await?;
        let s3 = backup_s3_config(&config)?;
        if !s3.enabled {
            return Err(ApiError::bad(
                "backup restore requires path/source/file or enabled S3 backup",
            ));
        }
        let client = backup_s3_client(state, s3).await?;
        let object = backup_object_name(&config)?;
        let bytes = client
            .get(&object)
            .await
            .map_err(|error| ApiError::unavailable(format!("S3 backup download: {error}")))?;
        let destination = backup_download_destination()?;
        std::fs::write(&destination, bytes)
            .map_err(|error| ApiError::internal(format!("write downloaded backup: {error}")))?;
        destination
    } else {
        PathBuf::from(source)
    };
    if !source.is_file() {
        return Err(ApiError::not_found(format!(
            "backup does not exist: {}",
            source.display()
        )));
    }
    if !state.request_shutdown() {
        return Err(ApiError::unavailable(
            "database restore requires the managed Rust service lifecycle",
        ));
    }
    state.controller.request_restore(source);
    json_value(json!({"accepted": true, "restart": true}))
}

pub fn tools_interfaces_value() -> ApiResult {
    json_value(json!({"interfaces": discover_interfaces()}))
}

pub fn tools_licenses_value() -> ApiResult {
    // Keep the contract useful on every platform.  The Rust backend owns this
    // entry; dependency notices can be added to the same static list as the
    // workspace grows, without making the API shape platform-dependent.
    json_value(json!({
        "yuhaiin": [{
            "name": "yuhaiin-rust",
            "url": "https://github.com/Asutorufa/yuhaiin",
            "license": "GPL-3.0-or-later",
            "licenseUrl": "https://github.com/Asutorufa/yuhaiin/blob/main/LICENSE"
        }],
        "android": []
    }))
}
