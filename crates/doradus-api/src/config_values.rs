use super::*;
pub async fn config_items(state: &ApiState, key: &str) -> Result<Vec<Value>, ApiError> {
    let Some(bytes) = state.controller.store().get_config(key).await? else {
        return Ok(Vec::new());
    };
    let value = raw_json(&bytes, json!({"items": []}));
    Ok(value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

pub fn default_backup_config() -> Value {
    json!({
        "instanceName": "",
        "s3": {"enabled": false, "accessKey": "", "secretKey": "", "bucket": "", "region": "", "endpointUrl": "", "usePathStyle": false, "storageClass": ""},
        "interval": 0,
        "lastBackupHash": ""
    })
}

pub fn backup_s3_config(value: &Value) -> Result<S3Config, ApiError> {
    serde_json::from_value(value.get("s3").cloned().unwrap_or_else(|| json!({})))
        .map_err(|error| ApiError::bad(format!("invalid backup S3 configuration: {error}")))
}

pub async fn backup_s3_client(state: &ApiState, config: S3Config) -> Result<S3Client, ApiError> {
    let selected = doradus_runtime::inbound::selected_proxy_id(&state.controller)
        .await
        .map_err(|error| ApiError::unavailable(format!("select S3 outbound proxy: {error}")))?;
    let proxy = state
        .controller
        .build_management_proxy(&selected, Duration::from_secs(30))
        .await
        .map_err(|error| ApiError::unavailable(format!("build S3 outbound proxy: {error}")))?;
    S3Client::with_transport(
        config,
        Arc::new(ProxyS3Transport::new(proxy, Duration::from_secs(30))),
    )
    .map_err(|error| ApiError::bad(error.to_string()))
}

pub fn backup_object_name(value: &Value) -> Result<String, ApiError> {
    let instance = string_or(value, "instanceName", "").trim().to_owned();
    if instance.is_empty() {
        return Err(ApiError::bad(
            "backup instanceName is required for S3 backup",
        ));
    }
    Ok(format!("{instance}-state.db"))
}

pub fn backup_hash(bytes: &[u8], s3: &S3Config) -> Result<String, ApiError> {
    let s3_bytes = serde_json::to_vec(s3)
        .map_err(|error| ApiError::internal(format!("serialize backup S3 config: {error}")))?;
    let mut hash = Blake2bVar::new(32)
        .map_err(|error| ApiError::internal(format!("create backup hash: {error}")))?;
    BlakeUpdate::update(&mut hash, bytes);
    BlakeUpdate::update(&mut hash, &s3_bytes);
    let mut output = [0_u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|error| ApiError::internal(format!("finalize backup hash: {error}")))?;
    Ok(output.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub async fn persist_backup_config_value(state: &ApiState, value: Value) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(&value)?;
    let record = GoBackupSettingsRecord {
        updated_at: unix_seconds(),
        data_json: bytes.clone(),
    };
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config("backup.config", &bytes).await?;
            store.repository().put_go_backup_settings(&record).await
        })
        .await
        .map(|_| ())
        .map_err(ApiError::from)
}

pub fn backup_destination() -> Result<PathBuf, ApiError> {
    let directory = backup_directory()?;
    let unique = OffsetDateTime::now_utc().unix_timestamp_nanos();
    Ok(directory.join(format!("state-{unique}.sqlite")))
}

pub fn backup_download_destination() -> Result<PathBuf, ApiError> {
    Ok(backup_directory()?.join("remote-state.sqlite"))
}

pub fn backup_directory() -> Result<PathBuf, ApiError> {
    let root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let directory = root.join("doradus").join("backups");
    std::fs::create_dir_all(&directory)
        .map_err(|error| ApiError::internal(format!("create backup directory: {error}")))?;
    Ok(directory)
}

pub async fn route_lists_config_get_value(state: &ApiState) -> ApiResult {
    json_value(load_route_list_config_value(state).await?)
}

pub async fn route_lists_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let refresh_interval = required_string(&value, "refreshInterval")?
        .parse::<u64>()
        .map_err(|error| {
            ApiError::bad(format!(
                "refreshInterval must be an unsigned integer: {error}"
            ))
        })?;
    // Go's SaveContractConfig updates the interval/disk/url settings but
    // preserves runtime-owned lastRefreshTime. It also clears the top-level
    // error and only clears the GeoIP error when the download URL changes.
    let current = load_route_list_config_value(state).await?;
    let last_refresh_time = string_or(&current, "lastRefreshTime", "0")
        .parse::<u64>()
        .unwrap_or(0);
    let geo = value
        .get("maxMindDbGeoIp")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let current_geo = current
        .get("maxMindDbGeoIp")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let download_url = string_or(&geo, "downloadUrl", "");
    let current_download_url = string_or(&current_geo, "downloadUrl", "");
    let geo_error = if download_url == current_download_url {
        string_or(&current_geo, "error", "")
    } else {
        String::new()
    };
    let normalized = json!({
        "refreshInterval": refresh_interval.to_string(),
        "lastRefreshTime": last_refresh_time.to_string(),
        "error": "",
        "hostIndexDisk": bool_or(&value, "hostIndexDisk", false),
        "maxMindDbGeoIp": {
            "downloadUrl": download_url,
            "error": geo_error,
        },
    });
    let settings = route_list_config_settings(&normalized)?;
    let bytes = serde_json::to_vec(&normalized)?;
    state
        .controller
        .mutate_and_reload_blocking(move |store| {
            store.put_config_sync("route.lists.config", &bytes)?;
            store.repository().put_go_settings_kv_sync(&settings)
        })
        .await?;
    Ok(Json(normalized))
}

pub async fn load_route_list_config_value(
    state: &ApiState,
) -> std::result::Result<Value, doradus_core::Error> {
    let settings = state
        .controller
        .store()
        .repository()
        .list_go_settings_kv()
        .await?;
    if let Some(value) = route_list_config_from_go_settings(&settings) {
        return Ok(value);
    }
    Ok(state
        .controller
        .store()
        .get_config("route.lists.config")
        .await?
        .map(|bytes| raw_json(&bytes, default_route_list_config()))
        .unwrap_or_else(default_route_list_config))
}

pub fn route_list_config_from_go_settings(rows: &[GoSettingsKvRecord]) -> Option<Value> {
    let refresh = rows
        .iter()
        .find(|row| row.section == "route_extra" && row.key == "refresh_config")
        .map(|row| raw_json(row.value_json.as_bytes(), json!({})));
    let geo = rows
        .iter()
        .find(|row| row.section == "route_extra" && row.key == "maxminddb_geoip")
        .map(|row| raw_json(row.value_json.as_bytes(), json!({})));
    if refresh.is_none() && geo.is_none() {
        return None;
    }
    let refresh = refresh.unwrap_or_else(|| json!({}));
    let geo = geo.unwrap_or_else(|| json!({}));
    Some(json!({
        "refreshInterval": json_u64_string(&refresh, "refresh_interval"),
        "lastRefreshTime": json_u64_string(&refresh, "last_refresh_time"),
        "error": string_or(&refresh, "error", ""),
        "hostIndexDisk": bool_or(&refresh, "host_index_disk", true),
        "maxMindDbGeoIp": {
            "downloadUrl": string_or(&geo, "download_url", ""),
            "error": string_or(&geo, "error", ""),
        },
    }))
}

pub fn route_list_config_settings(
    value: &Value,
) -> std::result::Result<Vec<GoSettingsKvRecord>, doradus_core::Error> {
    let refresh_interval = value
        .get("refreshInterval")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|error| doradus_core::Error::invalid(format!("refreshInterval: {error}")))?;
    let last_refresh_time = value
        .get("lastRefreshTime")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap_or(0);
    let geo = value.get("maxMindDbGeoIp").unwrap_or(&Value::Null);
    let refresh_json = serde_json::to_string(&json!({
        "refresh_interval": refresh_interval,
        "last_refresh_time": last_refresh_time,
        "error": string_or(value, "error", ""),
        "host_index_disk": bool_or(value, "hostIndexDisk", false),
    }))
    .map_err(|error| {
        doradus_core::Error::invalid(format!("encode route refresh config: {error}"))
    })?;
    let geo_json = serde_json::to_string(&json!({
        "download_url": string_or(geo, "downloadUrl", ""),
        "error": string_or(geo, "error", ""),
    }))
    .map_err(|error| doradus_core::Error::invalid(format!("encode MaxMind config: {error}")))?;
    Ok(vec![
        GoSettingsKvRecord {
            section: "route_extra".to_owned(),
            key: "refresh_config".to_owned(),
            value_json: refresh_json,
        },
        GoSettingsKvRecord {
            section: "route_extra".to_owned(),
            key: "maxminddb_geoip".to_owned(),
            value_json: geo_json,
        },
    ])
}

pub fn json_u64_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0)
        .to_string()
}

pub async fn read_config_json(state: &ApiState, key: &str, default: Value) -> ApiResult {
    let value = state
        .controller
        .store()
        .get_config(key)
        .await?
        .map(|bytes| raw_json(&bytes, default.clone()))
        .unwrap_or(default);
    Ok(Json(value))
}

pub async fn write_config_json(state: &ApiState, key: &str, value: Value) -> ApiResult {
    let value = if key == "settings" {
        canonical_settings_value(&value)
    } else {
        value
    };
    let bytes = serde_json::to_vec(&value)?;
    let key = key.to_owned();
    let settings_kv = (key == "settings").then(|| settings_kv_from_contract(&value));
    state
        .controller
        .mutate_and_reload_blocking(move |store| {
            store.put_config_sync(&key, &bytes)?;
            if let Some(settings_kv) = settings_kv {
                store.repository().put_go_settings_kv_sync(&settings_kv)?;
            }
            Ok(())
        })
        .await?;
    Ok(Json(value))
}
