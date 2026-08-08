//! Management HTTP API used by `yuhaiin-react`.
//!
//! The Go UI uses one JSON-RPC-shaped POST endpoint for all v2 operations:
//! `/api/v2/rpc/<operation>`.  This module keeps that wire contract at the
//! application boundary while reusing the store's Go compatibility records.
//! Unknown fields stay in `data_json`, so the management plane does not become
//! a second, lossy configuration model.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::convert::Infallible;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;

use yuhaiin_store::{
    GoInboundRecord, GoNodeRecord, GoResolverRecord, GoRouteListRecord, GoRouteRuleRecord,
    GoRouteSettingsRecord,
};

use crate::RuntimeController;

#[derive(Clone)]
pub struct ApiState {
    pub controller: RuntimeController,
    pub version: String,
}

impl ApiState {
    pub fn new(controller: RuntimeController) -> Self {
        Self {
            controller,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

type ApiResult = std::result::Result<Json<Value>, ApiError>;

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "unavailable",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

impl From<yuhaiin_core::Error> for ApiError {
    fn from(error: yuhaiin_core::Error) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::bad(format!("invalid JSON: {error}"))
    }
}

#[derive(Debug, Default, Deserialize, serde::Serialize)]
struct ListQuery {
    page: Option<usize>,
    #[serde(alias = "pageSize")]
    page_size: Option<usize>,
    query: Option<String>,
}

/// Build the application router. CORS is intentionally permissive because the
/// management endpoint is normally bound to loopback and the existing web UI
/// may be served from a different local development port.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v2/info", get(info))
        .route("/api/v2/settings", get(settings_get).put(settings_put))
        .route("/api/v2/nodes", get(nodes_get).post(nodes_post))
        .route(
            "/api/v2/nodes/{id}",
            get(node_get).put(node_put).delete(node_delete),
        )
        .route("/api/v2/inbounds", get(inbounds_get).post(inbounds_post))
        .route(
            "/api/v2/inbounds/{id}",
            get(inbound_get).put(inbound_put).delete(inbound_delete),
        )
        .route("/api/v2/resolvers", get(resolvers_get).post(resolvers_post))
        .route(
            "/api/v2/resolvers/{id}",
            get(resolver_get).put(resolver_put).delete(resolver_delete),
        )
        .route("/api/v2/connections", get(connections_get))
        .route("/api/v2/connections/total", get(connections_total))
        .route("/api/v2/connections/traffic", get(connections_traffic))
        .route("/api/v2/connections/telemetry", get(connections_telemetry))
        .route("/api/v2/connections/events", get(connections_events))
        .route("/api/v2/connections/close", post(connections_close))
        .route(
            "/api/v2/connections/failed-history",
            get(connections_failed_history),
        )
        .route("/api/v2/connections/history", get(connections_history))
        .route(
            "/api/v2/route/config",
            get(route_config_get).put(route_config_put),
        )
        .route(
            "/api/v2/route/lists",
            get(route_lists_get).post(route_lists_post),
        )
        .route(
            "/api/v2/route/lists/{id}",
            get(route_list_get)
                .put(route_list_put)
                .delete(route_list_delete),
        )
        .route(
            "/api/v2/route/rules",
            get(route_rules_get).post(route_rules_post),
        )
        .route(
            "/api/v2/route/rules/{name}/{index}",
            get(route_rule_get)
                .put(route_rule_put)
                .delete(route_rule_delete),
        )
        .route("/api/v2/route/apply", post(route_apply))
        .route("/api/v2/route/activation", get(route_activation))
        .route("/api/v2/resolver/hosts", get(hosts_get).put(hosts_put))
        .route(
            "/api/v2/resolver/fakedns",
            get(fakedns_get).put(fakedns_put),
        )
        .route(
            "/api/v2/resolver/server",
            get(resolver_server_get).put(resolver_server_put),
        )
        .route("/api/v2/rpc/{operation}", post(rpc))
        .layer(CorsLayer::very_permissive())
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: ApiState) -> std::io::Result<()> {
    serve_until(listener, state, std::future::pending::<()>()).await
}

pub async fn serve_until<S>(
    listener: tokio::net::TcpListener,
    state: ApiState,
    shutdown: S,
) -> std::io::Result<()>
where
    S: std::future::Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(std::io::Error::other)
}

async fn rpc(
    State(state): State<ApiState>,
    Path(operation): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    let body = if body.is_object() {
        body
    } else {
        return Err(ApiError::bad("request must be a JSON object"));
    };
    match operation.as_str() {
        "info" => info_value(&state),
        "settings.get" => read_config_json(&state, "settings", default_settings()).await,
        "settings.put" => write_config_json(&state, "settings", body).await,
        "nodes.get" => nodes_get_value(&state, &body).await,
        "nodes.post" => save_node_value(&state, body, None).await,
        "nodes.selected" => selected_nodes_value(&state).await,
        "nodes.active" => active_nodes_value(&state).await,
        "node.get" => get_node_value(&state, required_string(&body, "id")?).await,
        "node.put" => save_node_value(&state, body, None).await,
        "node.delete" => delete_node_value(&state, required_string(&body, "id")?).await,
        "node.use" => select_node_value(&state, required_string(&body, "id")?).await,
        "node.close" => empty(),
        "node.latency" => unsupported("node latency is not implemented in the lite runtime"),
        "inbounds.config.get" => {
            read_config_json(&state, "inbounds.config", default_inbound_config()).await
        }
        "inbounds.config.put" => write_config_json(&state, "inbounds.config", body).await,
        "inbounds.get" => inbounds_get_value(&state, &body).await,
        "inbounds.post" => save_inbound_value(&state, body, None).await,
        "inbound.get" => get_inbound_value(&state, required_string(&body, "id")?).await,
        "inbound.put" => save_inbound_value(&state, body, None).await,
        "inbound.delete" => delete_inbound_value(&state, required_string(&body, "id")?).await,
        "resolvers.get" => resolvers_get_value(&state, &body).await,
        "resolvers.post" => save_resolver_value(&state, body, None).await,
        "resolver.get" => get_resolver_value(&state, required_string(&body, "id")?).await,
        "resolver.put" => save_resolver_value(&state, body, None).await,
        "resolver.delete" => delete_resolver_value(&state, required_string(&body, "id")?).await,
        "resolver.hosts.get" => hosts_get_value(&state).await,
        "resolver.hosts.put" => hosts_put_value(&state, body).await,
        "resolver.fakedns.get" => fakedns_get_value(&state).await,
        "resolver.fakedns.put" => fakedns_put_value(&state, body).await,
        "resolver.server.get" => resolver_server_get_value(&state).await,
        "resolver.server.put" => resolver_server_put_value(&state, body).await,
        "connections" => json_value(state.controller.monitor().connections_value()),
        "connections.total" => json_value(state.controller.monitor().total_flow_value()),
        "connections.traffic" => {
            let interval = string_or(&body, "interval", "hour");
            json_value(state.controller.monitor().traffic_value(
                &interval,
                body.get("from").and_then(Value::as_str),
                body.get("to").and_then(Value::as_str),
            ))
        }
        "connections.telemetry" => json_value(state.controller.monitor().telemetry_value()),
        "connections.close" => close_connections_value(&state, body).await,
        "connections.failed_history" => {
            json_value(state.controller.monitor().failed_history_value())
        }
        "connections.history" => json_value(state.controller.monitor().all_history_value()),
        "tun.config.get" => read_config_json(&state, "tun.runtime", default_tun_config()).await,
        "tun.config.put" => write_config_json(&state, "tun.runtime", body).await,
        "route.config.get" => route_config_get_value(&state).await,
        "route.config.put" => route_config_put_value(&state, body).await,
        "route.lists.get" => route_lists_get_value(&state, &body).await,
        "route.lists.post" => save_route_list_value(&state, body, None).await,
        "route.list.get" => get_route_list_value(&state, required_string(&body, "id")?).await,
        "route.list.put" => save_route_list_value(&state, body, None).await,
        "route.list.delete" => delete_route_list_value(&state, required_string(&body, "id")?).await,
        "route.lists.config.get" => {
            read_config_json(&state, "route.lists.config", default_route_list_config()).await
        }
        "route.lists.config.put" => write_config_json(&state, "route.lists.config", body).await,
        "route.lists.refresh" => empty(),
        "route.lists.activation" => json_value(json!({ "hostIndexRefreshAt": 0 })),
        "route.rules.get" => route_rules_get_value(&state, &body).await,
        "route.rules.post" => save_route_rule_value(&state, body, None).await,
        "route.rule.get" => {
            get_route_rule_value(
                &state,
                required_string(&body, "name")?,
                number(&body, "index")?,
            )
            .await
        }
        "route.rule.put" => {
            let index = number(&body, "index")?;
            save_route_rule_value(&state, body, Some(index)).await
        }
        "route.rule.delete" => {
            delete_route_rule_value(
                &state,
                required_string(&body, "name")?,
                number(&body, "index")?,
            )
            .await
        }
        "route.rules.priority" => empty(),
        "route.rules.test" => json_value(json!({ "match": false, "mode": "direct" })),
        "route.rules.block_history" => {
            json_value(json!({ "items": [], "dumpProcessEnabled": false }))
        }
        "route.apply" => route_apply_value(&state).await,
        "route.activation" => route_activation_value(&state).await,
        "route.tags.get" => tags_get_value(&state, &body).await,
        "route.tag.put" => tag_put_value(&state, body).await,
        "route.tag.delete" => tag_delete_value(&state, required_string(&body, "tag")?).await,
        _ => Err(ApiError::not_found(format!(
            "unknown RPC operation {operation:?}"
        ))),
    }
}

async fn info(State(state): State<ApiState>) -> ApiResult {
    info_value(&state)
}

fn info_value(state: &ApiState) -> ApiResult {
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

async fn settings_get(State(state): State<ApiState>) -> ApiResult {
    read_config_json(&state, "settings", default_settings()).await
}

async fn settings_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    write_config_json(&state, "settings", value).await
}

async fn nodes_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    nodes_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn nodes_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_node_value(&state, value, None).await
}

async fn node_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_node_value(&state, id).await
}

async fn node_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_node_value(&state, value, None).await
}

async fn node_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_node_value(&state, id).await
}

async fn connections_get(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().connections_value())
}

async fn connections_total(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().total_flow_value())
}

#[derive(Debug, Default, Deserialize)]
struct TrafficQuery {
    interval: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

async fn connections_traffic(
    State(state): State<ApiState>,
    Query(query): Query<TrafficQuery>,
) -> ApiResult {
    json_value(state.controller.monitor().traffic_value(
        query.interval.as_deref().unwrap_or("hour"),
        query.from.as_deref(),
        query.to.as_deref(),
    ))
}

async fn connections_telemetry(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().telemetry_value())
}

async fn connections_failed_history(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().failed_history_value())
}

async fn connections_history(State(state): State<ApiState>) -> ApiResult {
    json_value(state.controller.monitor().all_history_value())
}

async fn connections_close(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    close_connections_value(&state, value).await
}

async fn close_connections_value(state: &ApiState, value: Value) -> ApiResult {
    let ids = value
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad("connections close requires an ids array"))?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    state.controller.monitor().request_close(&ids);
    empty()
}

async fn connections_events(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let monitor = state.controller.monitor();
    let initial = monitor.initial_event();
    let updates = BroadcastStream::new(monitor.subscribe()).filter_map(|event| {
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
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn inbounds_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    inbounds_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn inbounds_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_inbound_value(&state, value, None).await
}

async fn inbound_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_inbound_value(&state, id).await
}

async fn inbound_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_inbound_value(&state, value, None).await
}

async fn inbound_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_inbound_value(&state, id).await
}

async fn resolvers_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    resolvers_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn resolvers_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_resolver_value(&state, value, None).await
}

async fn resolver_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_resolver_value(&state, id).await
}

async fn resolver_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    save_resolver_value(&state, value, None).await
}

async fn resolver_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_resolver_value(&state, id).await
}

async fn route_config_get(State(state): State<ApiState>) -> ApiResult {
    route_config_get_value(&state).await
}

async fn route_config_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    route_config_put_value(&state, value).await
}

async fn route_lists_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    route_lists_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn route_lists_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_route_list_value(&state, value, None).await
}

async fn route_list_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    get_route_list_value(&state, id).await
}

async fn route_list_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", id.clone());
    save_route_list_value(&state, value, Some(id)).await
}

async fn route_list_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    delete_route_list_value(&state, id).await
}

async fn route_rules_get(
    State(state): State<ApiState>,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    route_rules_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn route_rules_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_route_rule_value(&state, value, None).await
}

async fn route_rule_get(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
) -> ApiResult {
    get_route_rule_value(&state, name, index).await
}

async fn route_rule_put(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    save_route_rule_value(&state, value, Some(index)).await
}

async fn route_rule_delete(
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
) -> ApiResult {
    delete_route_rule_value(&state, name, index).await
}

async fn route_apply(State(state): State<ApiState>) -> ApiResult {
    route_apply_value(&state).await
}

async fn route_activation(State(state): State<ApiState>) -> ApiResult {
    route_activation_value(&state).await
}

async fn hosts_get(State(state): State<ApiState>) -> ApiResult {
    hosts_get_value(&state).await
}

async fn hosts_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    hosts_put_value(&state, value).await
}

async fn fakedns_get(State(state): State<ApiState>) -> ApiResult {
    fakedns_get_value(&state).await
}

async fn fakedns_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    fakedns_put_value(&state, value).await
}

async fn resolver_server_get(State(state): State<ApiState>) -> ApiResult {
    resolver_server_get_value(&state).await
}

async fn resolver_server_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    resolver_server_put_value(&state, value).await
}

async fn nodes_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    let values = records.into_iter().map(node_json).collect::<Vec<_>>();
    Ok(Json(page(values, input)))
}

async fn get_node_value(state: &ApiState, id: String) -> ApiResult {
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

async fn save_node_value(state: &ApiState, value: Value, _index: Option<usize>) -> ApiResult {
    let id = required_string(&value, "id")?;
    let chain_types = node_chain_types(&value);
    if chain_types.is_empty() {
        return Err(ApiError::bad("node chain/protocol is empty"));
    }
    let group_name = match string_or_any(&value, &["group", "groupName", "group_name"]).as_str() {
        "" => "default".to_owned(),
        group => group.to_owned(),
    };
    let record = GoNodeRecord {
        id: id.clone(),
        name: string_or(&value, "name", &id),
        group_name,
        origin: string_or(&value, "origin", "rust-api"),
        enabled: bool_or(&value, "enabled", true),
        chain_types_json: serde_json::to_vec(&chain_types)?,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
    };
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_node(&record).await },
        )
        .await?;
    Ok(Json(returned))
}

async fn delete_node_value(state: &ApiState, id: String) -> ApiResult {
    let removed = state
        .controller
        .mutate_and_reload(move |store| async move {
            if store.repository().delete_go_node(&id).await? {
                Ok(())
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
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

async fn selected_nodes_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    let selected_id = state
        .controller
        .store()
        .get_config("selected.node")
        .await?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
    let selected = selected_id
        .as_deref()
        .and_then(|id| records.iter().find(|record| record.id == id))
        .cloned()
        .or_else(|| records.into_iter().find(|record| record.enabled));
    Ok(Json(
        selected
            .map(|record| json!({"tcp": node_json(record), "udp": null}))
            .unwrap_or_else(|| json!({})),
    ))
}

async fn active_nodes_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    Ok(Json(
        json!({"items": records.into_iter().filter(|record| record.enabled).map(node_json).collect::<Vec<_>>() }),
    ))
}

async fn select_node_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?;
    if !records.iter().any(|record| record.id == id) {
        return Err(ApiError::not_found(format!("node {id:?} was not found")));
    }
    write_config_json(state, "selected.node", json!({"id": id})).await
}

async fn inbounds_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_inbounds()
        .await?;
    Ok(Json(page(
        records.into_iter().map(inbound_json).collect(),
        input,
    )))
}

async fn get_inbound_value(state: &ApiState, id: String) -> ApiResult {
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

async fn save_inbound_value(state: &ApiState, value: Value, _index: Option<usize>) -> ApiResult {
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
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_inbound(&record).await },
        )
        .await?;
    Ok(Json(returned))
}

async fn delete_inbound_value(state: &ApiState, id: String) -> ApiResult {
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
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

async fn resolvers_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_resolvers()
        .await?;
    Ok(Json(page(
        records.into_iter().map(resolver_json).collect(),
        input,
    )))
}

async fn get_resolver_value(state: &ApiState, id: String) -> ApiResult {
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

async fn save_resolver_value(state: &ApiState, value: Value, _index: Option<usize>) -> ApiResult {
    let id = required_string(&value, "id")?;
    let resolver_type = string_or(&value, "type", "udp");
    let host = string_or(
        &value,
        "host",
        if resolver_type == "system" {
            "system default"
        } else {
            ""
        },
    );
    if resolver_type != "system" && host.trim().is_empty() {
        return Err(ApiError::bad("resolver host is empty"));
    }
    let record = GoResolverRecord {
        id: id.clone(),
        resolver_type,
        host,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
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

async fn delete_resolver_value(state: &ApiState, id: String) -> ApiResult {
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

async fn route_config_get_value(state: &ApiState) -> ApiResult {
    let value = state.controller.store().repository().list_go_route_settings().await?.into_iter().next().map(|record| json!({
        "directResolver": record.direct_resolver,
        "proxyResolver": record.proxy_resolver,
        "resolveLocally": record.resolve_locally,
        "udpProxyFqdnStrategy": match record.udp_proxy_fqdn { 1 => "resolve", 2 => "skip_resolve", _ => "default" },
    })).unwrap_or_else(default_route_config);
    Ok(Json(value))
}

async fn route_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let record = GoRouteSettingsRecord {
        id: 0,
        direct_resolver: string_or_any(&value, &["directResolver", "direct_resolver"]),
        proxy_resolver: string_or_any(&value, &["proxyResolver", "proxy_resolver"]),
        resolve_locally: bool_or_any(&value, &["resolveLocally", "resolve_locally"], false),
        udp_proxy_fqdn: match string_or_any(&value, &["udpProxyFqdnStrategy", "udp_proxy_fqdn"])
            .as_str()
        {
            "resolve" => 1,
            "skip_resolve" | "skipResolve" => 2,
            _ => 0,
        },
    };
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_settings(&record).await
        })
        .await?;
    Ok(Json(returned))
}

async fn route_lists_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    let values = records
        .into_iter()
        .map(route_list_item_json)
        .collect::<Vec<_>>();
    Ok(Json(page(values, input)))
}

async fn get_route_list_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    records
        .into_iter()
        .find(|record| record.name == id)
        .map(|record| Json(raw_json(&record.data_json, json!({"name": record.name}))))
        .ok_or_else(|| ApiError::not_found("route list not found"))
}

async fn save_route_list_value(
    state: &ApiState,
    mut value: Value,
    name: Option<String>,
) -> ApiResult {
    let name = name.unwrap_or(required_string(&value, "name")?);
    set_string(&mut value, "name", name.clone());
    let source = value.get("source").cloned().unwrap_or_else(|| json!({}));
    let record = GoRouteListRecord {
        name: name.clone(),
        list_type: string_or(&value, "type", "host"),
        source_type: string_or(&source, "type", "local"),
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
    };
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_list(&record).await
        })
        .await?;
    Ok(Json(returned))
}

async fn delete_route_list_value(state: &ApiState, id: String) -> ApiResult {
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            if store.repository().delete_go_route_list(&id).await? {
                Ok(())
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
                    "route list not found",
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

async fn route_rules_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    let values = records
        .into_iter()
        .map(route_rule_item_json)
        .collect::<Vec<_>>();
    Ok(Json(page(values, input)))
}

async fn get_route_rule_value(state: &ApiState, name: String, index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    records
        .into_iter()
        .filter(|record| record.name == name)
        .nth(index)
        .map(|record| Json(raw_json(&record.data_json, json!({"name": record.name}))))
        .ok_or_else(|| ApiError::not_found("route rule not found"))
}

async fn save_route_rule_value(
    state: &ApiState,
    mut value: Value,
    index: Option<usize>,
) -> ApiResult {
    let name = required_string(&value, "name")?;
    let current = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    let index =
        index.unwrap_or_else(|| current.iter().filter(|record| record.name == name).count());
    set_string(&mut value, "name", name.clone());
    let returned = value.clone();
    let (match_type, pattern) = route_match(&value);
    if !pattern.is_empty() {
        if let Some(object) = value.as_object_mut() {
            let mut matcher = Map::new();
            matcher.insert(
                if match_type == "cidr" {
                    "cidr"
                } else {
                    "domain"
                }
                .to_owned(),
                Value::String(pattern),
            );
            object
                .entry("match".to_owned())
                .or_insert_with(|| Value::Object(matcher));
        }
    }
    let record = GoRouteRuleRecord {
        id: format!("{name}:{index}"),
        name: name.clone(),
        priority: index as i64,
        disabled: bool_or(&value, "disabled", false),
        action_mode: string_or(&value, "mode", "direct"),
        match_type,
        tag: match string_or(&value, "tag", "default").as_str() {
            "" => "default".to_owned(),
            tag => tag.to_owned(),
        },
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
    };
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_rule(&record).await
        })
        .await?;
    Ok(Json(returned))
}

async fn delete_route_rule_value(state: &ApiState, name: String, index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    let record = records
        .into_iter()
        .filter(|record| record.name == name)
        .nth(index)
        .ok_or_else(|| ApiError::not_found("route rule not found"))?;
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .delete_go_route_rule(&record.id)
                .await
                .map(|_| ())
        })
        .await;
    result.map(|_| empty_json()).map_err(Into::into)
}

async fn route_apply_value(state: &ApiState) -> ApiResult {
    state.controller.reload().await?;
    empty()
}

async fn route_activation_value(state: &ApiState) -> ApiResult {
    json_value(
        json!({"hostIndexRefreshAt": 0, "ruleApplyAt": state.controller.handle().revision()}),
    )
}

async fn hosts_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.hosts")
        .await?
    {
        return Ok(Json(raw_json(&value, json!({"hosts": {}}))));
    }
    let mut hosts = Map::new();
    for record in state
        .controller
        .store()
        .repository()
        .list_go_dns_hosts()
        .await?
    {
        hosts.insert(record.host, Value::String(record.target));
    }
    Ok(Json(json!({"hosts": hosts})))
}

async fn hosts_put_value(state: &ApiState, value: Value) -> ApiResult {
    let value = if value.get("hosts").is_some() {
        value
    } else {
        json!({"hosts": value})
    };
    write_config_json(state, "resolver.hosts", value).await
}

async fn fakedns_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.fakedns")
        .await?
    {
        return Ok(Json(raw_json(&value, default_fakedns())));
    }
    let value = state.controller.store().repository().list_go_dns_settings().await?.into_iter().next().map(|record| json!({"enabled": record.fakedns_enabled, "ipv4Range": record.fakedns_ipv4_range, "ipv6Range": record.fakedns_ipv6_range, "whitelist": [], "skipCheckList": []})).unwrap_or_else(default_fakedns);
    Ok(Json(value))
}

async fn fakedns_put_value(state: &ApiState, value: Value) -> ApiResult {
    write_config_json(state, "resolver.fakedns", value).await
}

async fn resolver_server_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.server")
        .await?
    {
        return Ok(Json(raw_json(&value, json!({"server": ""}))));
    }
    let server = state
        .controller
        .store()
        .repository()
        .list_go_dns_settings()
        .await?
        .into_iter()
        .next()
        .map(|r| r.server)
        .unwrap_or_default();
    Ok(Json(json!({"server": server})))
}

async fn resolver_server_put_value(state: &ApiState, value: Value) -> ApiResult {
    let server = string_or(&value, "server", "");
    write_config_json(state, "resolver.server", json!({"server": server})).await
}

async fn tags_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let values = state
        .controller
        .store()
        .list_config("route.tag.")
        .await?
        .into_iter()
        .filter_map(|(key, value)| {
            serde_json::from_slice::<Value>(&value)
                .ok()
                .or_else(|| Some(json!({"name": key.trim_start_matches("route.tag.")})))
        })
        .collect::<Vec<_>>();
    Ok(Json(page(values, input)))
}

async fn tag_put_value(state: &ApiState, value: Value) -> ApiResult {
    let tag = required_string(&value, "tag")?;
    write_config_json(state, &format!("route.tag.{tag}"), value).await
}

async fn tag_delete_value(state: &ApiState, tag: String) -> ApiResult {
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .delete_config(&format!("route.tag.{tag}"))
                .await
                .map(|_| ())
        })
        .await?;
    empty()
}

async fn read_config_json(state: &ApiState, key: &str, default: Value) -> ApiResult {
    let value = state
        .controller
        .store()
        .get_config(key)
        .await?
        .map(|bytes| raw_json(&bytes, default.clone()))
        .unwrap_or(default);
    Ok(Json(value))
}

async fn write_config_json(state: &ApiState, key: &str, value: Value) -> ApiResult {
    let bytes = serde_json::to_vec(&value)?;
    let key = key.to_owned();
    state
        .controller
        .mutate_and_reload(move |store| async move { store.put_config(&key, &bytes).await })
        .await?;
    Ok(Json(value))
}

fn node_json(record: GoNodeRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_string(&mut value, "group", record.group_name);
    set_string(&mut value, "origin", record.origin);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

fn inbound_json(record: GoInboundRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

fn resolver_json(record: GoResolverRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "type", record.resolver_type);
    set_string(&mut value, "host", record.host);
    value
}

fn route_list_item_json(record: GoRouteListRecord) -> Value {
    let value = raw_json(
        &record.data_json,
        json!({"name": record.name, "type": record.list_type}),
    );
    json!({"name": string_or(&value, "name", &record.name), "type": string_or(&value, "type", &record.list_type), "source": string_or(&value.get("source").cloned().unwrap_or_default(), "type", &record.source_type), "itemCount": 0, "errorCount": 0, "preview": ""})
}

fn route_rule_item_json(record: GoRouteRuleRecord) -> Value {
    let value = raw_json(&record.data_json, json!({}));
    json!({"name": record.name, "disabled": record.disabled, "index": record.priority, "mode": string_or(&value, "mode", &record.action_mode), "tag": record.tag, "resolver": string_or(&value, "resolver", ""), "ruleCount": value.get("rules").and_then(Value::as_array).map_or(0, Vec::len)})
}

fn route_match(value: &Value) -> (String, String) {
    fn walk(value: &Value) -> Option<(String, String)> {
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if ["domain", "host", "cidr", "ip", "network", "pattern"].contains(&lower.as_str())
                {
                    if let Some(value) = value.as_str() {
                        return Some((
                            if lower == "cidr" || lower == "ip" {
                                "cidr"
                            } else {
                                "domain"
                            }
                            .to_owned(),
                            value.to_owned(),
                        ));
                    }
                }
                if lower == "list" {
                    if let Some(value) = value.as_str() {
                        return Some(("domain".to_owned(), value.to_owned()));
                    }
                }
                if let Some(found) = walk(value) {
                    return Some(found);
                }
            }
        } else if let Some(array) = value.as_array() {
            for value in array {
                if let Some(found) = walk(value) {
                    return Some(found);
                }
            }
        }
        None
    }
    walk(value).unwrap_or_else(|| ("domain".to_owned(), "".to_owned()))
}

fn node_chain_types(value: &Value) -> Vec<String> {
    if let Some(chain) = value
        .get("chainTypes")
        .or_else(|| value.get("chain_types"))
        .and_then(Value::as_array)
    {
        return chain
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(chain) = value.get("chain").and_then(Value::as_array) {
        let types = chain
            .iter()
            .filter_map(|item| item.get("type").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !types.is_empty() {
            return types;
        }
    }
    ["protocol", "type"]
        .iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .map(|value| vec![value.to_owned()])
        })
        .unwrap_or_default()
}

fn nested_type(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("empty")
        .to_owned()
}

fn page(mut values: Vec<Value>, input: &Value) -> Value {
    if let Some(query) = input
        .get("query")
        .and_then(Value::as_str)
        .filter(|query| !query.trim().is_empty())
    {
        let query = query.to_ascii_lowercase();
        values.retain(|value| value.to_string().to_ascii_lowercase().contains(&query));
    }
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

fn required_string(value: &Value, key: &str) -> std::result::Result<String, ApiError> {
    string_or_opt(value, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad(format!("{key} is required")))
}
fn string_or(value: &Value, key: &str, default: &str) -> String {
    string_or_opt(value, key).unwrap_or_else(|| default.to_owned())
}
fn string_or_any(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| string_or_opt(value, key))
        .unwrap_or_default()
}
fn string_or_opt(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}
fn bool_or(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}
fn bool_or_any(value: &Value, keys: &[&str], default: bool) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
        .unwrap_or(default)
}
fn number(value: &Value, key: &str) -> std::result::Result<usize, ApiError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .ok_or_else(|| ApiError::bad(format!("{key} must be a non-negative integer")))
}
fn set_string(value: &mut Value, key: &str, text: impl Into<String>) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), Value::String(text.into()));
    }
}
fn set_bool(value: &mut Value, key: &str, flag: bool) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), Value::Bool(flag));
    }
}
fn object_or_fallback(bytes: &[u8], fallback: Value) -> Value {
    raw_json(bytes, fallback)
}
fn raw_json(bytes: &[u8], fallback: Value) -> Value {
    serde_json::from_slice(bytes).unwrap_or(fallback)
}
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}
fn json_value(value: Value) -> ApiResult {
    Ok(Json(value))
}
fn empty_json() -> Json<Value> {
    Json(json!({}))
}
fn empty() -> ApiResult {
    Ok(empty_json())
}
fn unsupported(message: impl Into<String>) -> ApiResult {
    Err(ApiError::unavailable(message))
}
fn default_route_config() -> Value {
    json!({"directResolver":"", "proxyResolver":"", "resolveLocally":false, "udpProxyFqdnStrategy":"default"})
}
fn default_settings() -> Value {
    json!({"ipv6":false,"useDefaultInterface":true,"netInterface":"","pprof":false,"systemProxy":{"http":false,"socks5":false},"logcat":{"level":"info","save":false,"ignoreTimeoutError":false,"ignoreDnsError":false},"advanced":{"udpBufferSize":2048,"relayBufferSize":4096,"udpRingbufferSize":250,"happyEyeballsSemaphore":250},"backup":{"instanceName":"","interval":0,"lastBackupHash":""}})
}
fn default_inbound_config() -> Value {
    json!({"port":0,"bind":"127.0.0.1"})
}
fn default_route_list_config() -> Value {
    json!({"refreshInterval":"0","lastRefreshTime":"0","error":"","hostIndexDisk":false,"maxMindDbGeoIp":{"downloadUrl":"","error":""}})
}
fn default_fakedns() -> Value {
    json!({"enabled":false,"ipv4Range":"198.18.0.0/15","ipv6Range":"fc00::/18","whitelist":[],"skipCheckList":[]})
}
fn default_tun_config() -> Value {
    json!({"enabled":false,"name":"yuhaiin0","mtu":1500,"queueCapacity":256,"channelCapacity":256,"directId":"","proxyId":"","bypassId":"","dropId":""})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeBuilder, RuntimeController};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_store::ConfigStore;

    async fn state() -> ApiState {
        let store = ConfigStore::open_memory().await.unwrap();
        let controller = RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        ApiState::new(controller)
    }

    #[tokio::test]
    async fn node_rpc_round_trips_frontend_shape_and_publishes_reload() {
        let state = state().await;
        let value = json!({"id":"direct","name":"Direct","group":"","origin":"rust","enabled":true,"chain":[{"type":"direct","direct":{}}]});
        let saved = save_node_value(&state, value.clone(), None).await.unwrap();
        assert_eq!(saved.0["id"], "direct");
        let listed = nodes_get_value(&state, &json!({"page":1,"page_size":0}))
            .await
            .unwrap();
        assert_eq!(listed.0["items"][0]["chain"][0]["type"], "direct");
        assert_eq!(state.controller.handle().revision(), 1);
    }

    #[tokio::test]
    async fn resolver_and_route_config_use_the_same_mutation_reload_boundary() {
        let state = state().await;
        let _ = save_resolver_value(
            &state,
            json!({"id":"lan","type":"udp","host":"127.0.0.1:5353"}),
            None,
        )
        .await
        .unwrap();
        let _ = route_config_put_value(&state, json!({"directResolver":"lan","proxyResolver":"lan","resolveLocally":true,"udpProxyFqdnStrategy":"resolve"})).await.unwrap();
        let route = route_config_get_value(&state).await.unwrap();
        assert_eq!(route.0["directResolver"], "lan");
        assert_eq!(state.controller.handle().revision(), 2);
    }

    #[test]
    fn frontend_page_query_is_camel_case_compatible() {
        let value = page(
            vec![json!({"id":"a"}), json!({"id":"b"})],
            &json!({"page":2,"pageSize":1}),
        );
        assert_eq!(value["items"][0]["id"], "b");
        assert_eq!(value["page"]["pageSize"], 1);
    }

    #[tokio::test]
    async fn rpc_router_accepts_the_real_frontend_request_shape() {
        let state = state().await;
        let response = router(state)
            .oneshot(
                Request::post("/api/v2/rpc/nodes.post")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"api-direct","name":"API Direct","group":"test","enabled":true,"chain":[{"type":"direct","direct":{}}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["id"], "api-direct");
    }
}
