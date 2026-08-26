use super::*;
pub const ROUTE_LIST_ACTIVATION_KEY: &str = "route.lists.activation";
pub const ROUTE_ACTIVATION_KEY: &str = "route.activation";

pub async fn route_lists_refresh(State(state): State<ApiState>) -> ApiResult {
    route_lists_refresh_value(&state).await
}

pub struct RouteGeoDownloadTransport {
    route: Arc<dyn RouteListTransport>,
    timeout: Duration,
}

pub struct RouteListRefreshGuard {
    refreshing: Arc<AtomicBool>,
}

impl RouteListRefreshGuard {
    pub fn acquire(refreshing: &Arc<AtomicBool>) -> std::result::Result<Self, ApiError> {
        if refreshing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // RefreshContract returns a plain `refreshing` error. It is not a
            // user validation failure, so retain Go's generic RPC 500 shape.
            return Err(ApiError::internal("refreshing"));
        }
        Ok(Self {
            refreshing: Arc::clone(refreshing),
        })
    }
}

impl Drop for RouteListRefreshGuard {
    fn drop(&mut self) {
        self.refreshing.store(false, Ordering::Release);
    }
}

impl GeoDownloadTransport for RouteGeoDownloadTransport {
    fn download<'a>(&'a self, url: &'a str) -> BoxFuture<'a, yuhaiin_core::Result<Vec<u8>>> {
        let route = Arc::clone(&self.route);
        let timeout = self.timeout;
        let url = url.to_owned();
        Box::pin(async move {
            download_route_url_with_transport(&url, timeout, Some(route.as_ref())).await
        })
    }
}

pub fn geo_cache_path() -> PathBuf {
    let root = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    root.join("yuhaiin-rust").join("geo").join("Country.mmdb")
}

pub fn optional_sha256(value: &Value) -> Option<Vec<u8>> {
    let value = value.as_str()?.trim();
    if value.len() != 64 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

pub async fn refresh_geo_database(
    state: &ApiState,
    route: Arc<dyn RouteListTransport>,
    timeout: Duration,
) -> std::result::Result<Option<MaxMindMetadataRecord>, yuhaiin_core::Error> {
    let config = load_route_list_config_value(state).await?;
    let geo_config = config.get("maxMindDbGeoIp").unwrap_or(&Value::Null);
    let Some(url) = geo_config.get("downloadUrl").and_then(Value::as_str) else {
        return Ok(None);
    };
    if url.trim().is_empty() {
        return Ok(None);
    }
    let current = state
        .controller
        .store()
        .repository()
        .list_maxmind_metadata()
        .await?
        .into_iter()
        .next();
    let path = current
        .as_ref()
        .map(|metadata| PathBuf::from(&metadata.path))
        .unwrap_or_else(geo_cache_path);
    let expected_size = geo_config
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size != 0);
    let expected_sha256 = geo_config.get("sha256").and_then(optional_sha256);
    let manager = GeoDatabaseManager::new();
    let snapshot = manager
        .refresh(
            GeoRefreshRequest {
                id: current
                    .as_ref()
                    .map(|metadata| metadata.id.clone())
                    .unwrap_or_else(|| "geoip".to_owned()),
                path,
                url: url.to_owned(),
                expected_sha256,
                expected_size,
                updated_at: unix_millis(),
            },
            &RouteGeoDownloadTransport { route, timeout },
        )
        .await?;
    let metadata = snapshot.metadata();
    Ok(Some(MaxMindMetadataRecord {
        id: metadata.id.clone(),
        path: metadata.path.to_string_lossy().into_owned(),
        sha256: metadata.sha256.clone(),
        size: i64::try_from(metadata.size)
            .map_err(|_| yuhaiin_core::Error::invalid("GeoIP file is too large to persist"))?,
        updated_at: metadata.updated_at,
    }))
}

pub async fn route_lists_activation(State(state): State<ApiState>) -> ApiResult {
    route_lists_activation_value(&state).await
}

pub async fn route_lists_refresh_value(state: &ApiState) -> ApiResult {
    let _refresh_guard = RouteListRefreshGuard::acquire(&state.route_list_refreshing)?;
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    let timeout = Duration::from_secs(90);
    let proxy_id = yuhaiin_runtime::inbound::selected_proxy_id(&state.controller).await?;
    let snapshot = state.controller.handle().load();
    let proxy: Arc<dyn AsyncProxy> = match snapshot.build_proxy(&proxy_id, timeout).await {
        Ok(build) => build.proxy,
        Err(_error) if proxy_id.is_empty() || proxy_id == "direct" => {
            snapshot.resolve_proxy(Arc::new(DirectAsyncProxy { timeout }))
        }
        Err(error) => return Err(error.into()),
    };
    let resolver = snapshot
        .dns_resolver_for_route_mode(yuhaiin_core::RouteMode::Proxy)
        .map_err(ApiError::from)?;
    let transport = Arc::new(ProxyRouteListTransport::new(proxy, resolver));
    let report = refresh_route_list_caches_with_transport(
        &records,
        timeout,
        Arc::clone(&transport) as Arc<dyn RouteListTransport>,
    )
    .await;
    let (geo_metadata, geo_error) = match refresh_geo_database(
        state,
        Arc::clone(&transport) as Arc<dyn RouteListTransport>,
        timeout,
    )
    .await
    {
        Ok(metadata) => (metadata, None),
        Err(error) => (None, Some(error.to_string())),
    };
    // Go writes the result of every remote download back into the route-list
    // contract: successful refresh clears stale `errorMsgs`, while failed
    // URLs remain visible through both route.lists and route.list.get.  Keep
    // this update in the same reload transaction as the cache/config change
    // so a force-stop cannot expose a half-updated management snapshot.
    let refreshed_route_lists = records
        .iter()
        .filter_map(|record| {
            let errors = report
                .errors
                .get(&record.name)
                .map(Vec::as_slice)
                .unwrap_or_default();
            route_list_record_with_refresh_errors(record, errors)
        })
        .collect::<Vec<_>>();
    let refreshed_at = unix_millis();
    let last_refresh_time = unix_seconds();
    let host_index_refresh_at = refreshed_at.saturating_add(60_000);
    let activation = json!({
        "hostIndexRefreshAt": host_index_refresh_at,
        "lastRefreshAt": refreshed_at,
        "refreshed": report.refreshed,
        "errors": report.errors,
    });
    let bytes = serde_json::to_vec(&activation)?;
    let mut list_config = load_route_list_config_value(state).await?;
    if let Some(object) = list_config.as_object_mut() {
        object.insert(
            "lastRefreshTime".to_owned(),
            // Go's persisted RouteListSettings.LastRefreshTime is Unix
            // seconds (`time.Now().Unix()`), while activation timestamps are
            // Unix milliseconds for the UI's pending-apply countdown.
            Value::String(last_refresh_time.to_string()),
        );
        if let Some(geo) = object
            .entry("maxMindDbGeoIp".to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
        {
            geo.insert(
                "error".to_owned(),
                Value::String(geo_error.clone().unwrap_or_default()),
            );
        }
    }
    let list_config_bytes = serde_json::to_vec(&list_config)?;
    let list_settings = route_list_config_settings(&list_config)?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            if let Some(metadata) = geo_metadata {
                store.repository().put_maxmind_metadata(&metadata).await?;
            }
            for record in &refreshed_route_lists {
                store.repository().put_go_route_list(record).await?;
            }
            store
                .put_config("route.lists.config", &list_config_bytes)
                .await?;
            store
                .repository()
                .put_go_settings_kv(&list_settings)
                .await?;
            store.put_config(ROUTE_LIST_ACTIVATION_KEY, &bytes).await
        })
        .await?;
    state.controller.monitor().logs().info(format!(
        "route list refresh applied at {refreshed_at}, {} cache entries updated",
        report.refreshed
    ));
    empty()
}

pub async fn route_lists_activation_value(state: &ApiState) -> ApiResult {
    let mut value = state
        .controller
        .store()
        .get_config(ROUTE_LIST_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0}));
    let refresh_at = effective_activation_at(&value, "hostIndexRefreshAt");
    if let Some(object) = value.as_object_mut() {
        object.insert("hostIndexRefreshAt".to_owned(), json!(refresh_at));
    }
    json_value(value)
}

pub async fn route_list_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_route_list_value(&state, id).await
}

pub async fn route_list_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", id.clone());
    save_route_list_value(&state, value, Some(id)).await
}

pub async fn route_list_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_route_list_value(&state, id).await
}

pub async fn route_rules_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    route_rules_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn route_rules_post(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    save_route_rule_value(&state, value, None).await
}

pub async fn route_rule_get(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
) -> ApiResult {
    get_route_rule_value(&state, name, index).await
}

pub async fn route_rule_put(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    save_route_rule_value(&state, value, Some(index)).await
}

pub async fn route_rule_delete(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
) -> ApiResult {
    delete_route_rule_value(&state, name, index).await
}

pub async fn route_rules_priority(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_rules_priority_value(&state, &value).await
}

pub async fn route_rules_test(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_rules_test_value(&state, &value).await
}

pub async fn route_rules_block_history(State(state): State<ApiState>) -> ApiResult {
    route_rules_block_history_value(&state).await
}

pub async fn tags_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    tags_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

pub async fn tag_put(
    State(state): State<ApiState>,
    Path(tag): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "tag", tag);
    tag_put_value(&state, value).await
}

pub async fn tag_delete(State(state): State<ApiState>, Path(tag): Path<String>) -> ApiResult {
    tag_delete_value(&state, tag).await
}

pub async fn route_apply(State(state): State<ApiState>) -> ApiResult {
    route_apply_value(&state).await
}

pub async fn route_activation(State(state): State<ApiState>) -> ApiResult {
    route_activation_value(&state).await
}

pub async fn hosts_get(State(state): State<ApiState>) -> ApiResult {
    hosts_get_value(&state).await
}

pub async fn hosts_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    hosts_put_value(&state, value).await
}

pub async fn fakedns_get(State(state): State<ApiState>) -> ApiResult {
    fakedns_get_value(&state).await
}

pub async fn fakedns_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    fakedns_put_value(&state, value).await
}

pub async fn resolver_server_get(State(state): State<ApiState>) -> ApiResult {
    resolver_server_get_value(&state).await
}

pub async fn resolver_server_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    resolver_server_put_value(&state, value).await
}
