//! Management HTTP API used by `yuhaiin-react`.
//!
//! The Go UI uses one JSON-RPC-shaped POST endpoint for all v2 operations:
//! `/api/v2/rpc/<operation>`.  This module keeps that wire contract at the
//! application boundary while reusing the store's Go compatibility records.
//! Unknown fields stay in `data_json`, so the management plane does not become
//! a second, lossy configuration model.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::watch;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use yuhaiin_core::proxy::{AsyncProxy, DirectAsyncProxy};
use yuhaiin_core::{BoxFuture, DomainName, Endpoint, FlowContext, Network};
use yuhaiin_geo::{GeoDatabaseManager, GeoDownloadTransport, GeoRefreshRequest};

use yuhaiin_store::{
    GoInboundRecord, GoNodeRecord, GoResolverRecord, GoRouteListRecord, GoRouteRuleRecord,
    GoRouteSettingsRecord, GoSubscriptionLinkRecord, InboundSettings, MaxMindMetadataRecord,
};

use crate::update::UpdateService;
use crate::{
    ProxyRouteListTransport, RouteListSnapshot, RouteListTransport, RuntimeController,
    RuntimeSettings, download_route_url_with_transport, expand_go_route_rule,
    interfaces::discover_interfaces, latency::LatencyRequest, log::log_batch_value,
    refresh_route_list_caches_with_transport,
};

// Go keeps TCP and UDP node selection independently in metadata.  Keep the
// same names in the Rust config overlay, while retaining the old single-key
// selection as a read fallback for databases written by earlier Rust builds.
const SELECTED_TCP_NODE_KEY: &str = "selected_tcp_node_v2";
const SELECTED_UDP_NODE_KEY: &str = "selected_udp_node_v2";
const LEGACY_SELECTED_NODE_KEY: &str = "selected.node";

#[derive(Clone)]
pub struct ApiState {
    pub controller: RuntimeController,
    pub version: String,
    pub update: Arc<UpdateService>,
    shutdown: Option<watch::Sender<bool>>,
    auth: Option<ApiAuth>,
    web_root: Option<PathBuf>,
}

/// Optional management API credentials. The stored values are SHA-256
/// digests, matching the Go server's constant-time comparison boundary while
/// avoiding keeping the clear-text credentials in the long-lived router state.
#[derive(Clone)]
pub struct ApiAuth {
    username: [u8; 32],
    password: [u8; 32],
}

impl ApiAuth {
    pub fn new(username: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Self {
        Self {
            username: digest(username.as_ref()),
            password: digest(password.as_ref()),
        }
    }

    fn accepts_basic_token(&self, token: &str) -> bool {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
            return false;
        };
        let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
            return false;
        };
        constant_time_equal(&self.username, &digest(&decoded[..separator]))
            && constant_time_equal(
                &self.password,
                &digest(&decoded[separator.saturating_add(1)..]),
            )
    }
}

impl ApiState {
    pub fn new(controller: RuntimeController) -> Self {
        #[cfg(test)]
        let update = Arc::new(UpdateService::test_stub());
        #[cfg(not(test))]
        let update = Arc::new(UpdateService::new());
        Self {
            controller,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            update,
            shutdown: None,
            auth: None,
            web_root: None,
        }
    }

    pub fn with_shutdown(mut self, shutdown: watch::Sender<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Serve a Go-compatible external frontend directory from the same HTTP
    /// listener. API routes remain registered before the fallback; unknown
    /// paths use `index.html` so React client-side routes keep working.
    pub fn with_external_web(mut self, root: impl Into<PathBuf>) -> Self {
        self.web_root = Some(root.into());
        self
    }

    pub fn with_auth(mut self, username: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Self {
        self.auth = Some(ApiAuth::new(username, password));
        self
    }

    pub fn with_optional_auth(self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        if username.as_ref().is_empty() && password.as_ref().is_empty() {
            self
        } else {
            self.with_auth(username.as_ref().as_bytes(), password.as_ref().as_bytes())
        }
    }

    fn request_shutdown(&self) -> bool {
        self.shutdown
            .as_ref()
            .is_some_and(|shutdown| shutdown.send(true).is_ok())
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
        // Go's rpcError exposes the underlying validation message without
        // prepending an internal Rust error-kind label.
        let message = error.message;
        match error.kind {
            // Match the Go v2 RPC boundary: validation and unsupported
            // configurations are client errors, not server failures.
            yuhaiin_core::ErrorKind::InvalidInput | yuhaiin_core::ErrorKind::Unsupported => {
                Self::bad(message)
            }
            yuhaiin_core::ErrorKind::NotFound => Self::not_found(message),
            // A closed/timeout runtime owner is equivalent to Go's
            // unavailable service dependency.
            yuhaiin_core::ErrorKind::Closed | yuhaiin_core::ErrorKind::Timeout => {
                Self::unavailable(message)
            }
            yuhaiin_core::ErrorKind::Io
            | yuhaiin_core::ErrorKind::Protocol
            | yuhaiin_core::ErrorKind::Storage => Self::internal(message),
        }
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
    let auth = state.auth.clone();
    let web_root = state.web_root.clone();
    let router = Router::new()
        .route("/api/v2/info", get(info))
        .route("/api/v2/update/check", post(update_check))
        .route("/api/v2/update/apply", post(update_apply))
        .route("/api/v2/update/status", get(update_status))
        .route("/api/v2/settings", get(settings_get).put(settings_put))
        .route(
            "/api/v2/backup/config",
            get(backup_config_get).put(backup_config_put),
        )
        .route("/api/v2/backup/run", post(backup_run))
        .route("/api/v2/backup/restore", post(backup_restore))
        .route("/api/v2/tools/logs", get(tools_logs))
        .route("/api/v2/nodes", get(nodes_get).post(nodes_post))
        .route("/api/v2/nodes/selected", get(nodes_selected))
        .route("/api/v2/nodes/active", get(nodes_active))
        .route(
            "/api/v2/nodes/{id}",
            get(node_get).put(node_put).delete(node_delete),
        )
        .route("/api/v2/nodes/{id}/use", post(node_use))
        .route("/api/v2/nodes/{id}/latency", post(node_latency))
        .route("/api/v2/nodes/{id}/close", post(node_close))
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
        .route("/api/v2/tools/interfaces", get(tools_interfaces))
        .route("/api/v2/tools/licenses", get(tools_licenses))
        .route("/api/v2/tools/logs/v2", get(tools_logs_v2))
        .route("/debug/pprof/", get(pprof_index))
        .route("/debug/pprof/profile", get(pprof_profile))
        .route(
            "/api/v2/subscriptions",
            get(subscriptions_get)
                .put(subscriptions_put)
                .delete(subscriptions_delete),
        )
        .route(
            "/api/v2/subscriptions/delete-preview",
            post(subscriptions_delete_preview),
        )
        .route("/api/v2/subscriptions/update", post(subscriptions_update))
        .route("/api/v2/publishes", get(publishes))
        .route(
            "/api/v2/publishes/{name}",
            put(publish_put).delete(publish_delete),
        )
        .route("/api/v2/publishes/{name}/resolve", post(publish_resolve))
        .route(
            "/api/v2/inbounds/config",
            get(inbounds_config_get).put(inbounds_config_put),
        )
        .route("/api/v2/users", get(users_get).post(users_post))
        .route(
            "/api/v2/users/{id}",
            get(user_get).put(user_put).delete(user_delete),
        )
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
            "/api/v2/route/lists/config",
            get(route_lists_config_get).put(route_lists_config_put),
        )
        .route("/api/v2/route/lists/refresh", post(route_lists_refresh))
        .route(
            "/api/v2/route/lists/activation",
            get(route_lists_activation),
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
        .route("/api/v2/route/rules/priority", post(route_rules_priority))
        .route("/api/v2/route/rules/test", post(route_rules_test))
        .route(
            "/api/v2/route/rules/block-history",
            get(route_rules_block_history),
        )
        .route("/api/v2/route/tags", get(tags_get))
        .route("/api/v2/route/tags/{tag}", put(tag_put).delete(tag_delete))
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
        .layer(middleware::from_fn(move |request, next| {
            let auth = auth.clone();
            async move { authenticate(auth, request, next).await }
        }))
        .with_state(state);
    if let Some(root) = web_root {
        let index = root.join("index.html");
        router.fallback_service(ServeDir::new(root).fallback(ServeFile::new(index)))
    } else {
        router
    }
}

async fn authenticate(auth: Option<ApiAuth>, request: Request<Body>, next: Next) -> Response {
    let Some(auth) = auth else {
        return next.run(request).await;
    };
    if request.method() == axum::http::Method::OPTIONS {
        return next.run(request).await;
    }
    let token = query_token(request.uri().query()).or_else(|| {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .map(str::to_owned)
    });
    if token
        .as_deref()
        .is_some_and(|token| auth.accepts_basic_token(token))
    {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

#[derive(Debug, Default, Deserialize)]
struct PprofQuery {
    seconds: Option<u64>,
}

/// Rust-native profiling endpoints.  The payload is the standard protobuf
/// pprof profile produced by `pprof-rs`; it is intentionally not coupled to
/// Go's runtime profiler implementation.
async fn pprof_index(State(state): State<ApiState>) -> Response {
    if !state.controller.handle().load().settings.pprof {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><title>yuhaiin Rust profiles</title>\n<ul><li><a href=\"/debug/pprof/profile?seconds=10\">CPU profile (protobuf)</a></li></ul>\n",
    )
        .into_response()
}

async fn pprof_profile(State(state): State<ApiState>, Query(query): Query<PprofQuery>) -> Response {
    if !state.controller.handle().load().settings.pprof {
        return StatusCode::NOT_FOUND.into_response();
    }
    let seconds = query.seconds.unwrap_or(10).clamp(1, 60);
    let guard = match pprof::ProfilerGuard::new(100) {
        Ok(guard) => guard,
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("cannot start Rust CPU profiler: {error}"),
            )
                .into_response();
        }
    };
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let report = match guard.report().build() {
        Ok(report) => report,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build Rust CPU profile: {error}"),
            )
                .into_response();
        }
    };
    let profile = match report.pprof() {
        Ok(profile) => profile,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot encode Rust CPU profile: {error}"),
            )
                .into_response();
        }
    };
    use pprof::protos::Message;
    let mut body = Vec::new();
    if let Err(error) = profile.encode(&mut body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot serialize Rust CPU profile: {error}"),
        )
            .into_response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"yuhaiin-rust-profile.pb\"",
        )
        .body(Body::from(body))
        .unwrap_or_else(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create profile response: {error}"),
            )
                .into_response()
        })
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn query_token(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "token").then(|| percent_decode(value))
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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
        "update.check" => update_check_value(&state, &body).await,
        "update.apply" => update_apply_value(&state, &body).await,
        "update.status" => update_status_value(&state).await,
        "settings.get" => settings_get_value(&state).await,
        "settings.put" => write_config_json(&state, "settings", body).await,
        "backup.config.get" => {
            read_config_json(&state, "backup.config", default_backup_config()).await
        }
        "backup.config.put" => write_config_json(&state, "backup.config", body).await,
        "backup.run" => run_backup_value(&state).await,
        "backup.restore" => restore_backup_value(&state, &body).await,
        "tools.interfaces" => tools_interfaces_value(),
        "tools.licenses" => tools_licenses_value(),
        "tools.logs" | "tools.logs.v2" => json_value(log_batch_value(
            state.controller.monitor().logs().snapshot(),
        )),
        "nodes.get" => nodes_get_value(&state, &body).await,
        "nodes.post" => save_node_value(&state, body, None).await,
        "nodes.selected" => selected_nodes_value(&state).await,
        "nodes.active" => active_nodes_value(&state).await,
        "node.get" => get_node_value(&state, required_string(&body, "id")?).await,
        "node.put" => save_node_value(&state, body, None).await,
        "node.delete" => delete_node_value(&state, required_string(&body, "id")?).await,
        "node.use" => select_node_value(&state, required_string(&body, "id")?).await,
        "node.close" => node_close_value(&state, required_string(&body, "id")?).await,
        "node.latency" => node_latency_value(&state, &body).await,
        "inbounds.config.get" => inbounds_config_get_value(&state).await,
        "inbounds.config.put" => inbounds_config_put_value(&state, body).await,
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
        "subscriptions.get" => subscriptions_get_value(&state).await,
        "subscriptions.put" => subscriptions_put_value(&state, body).await,
        "subscriptions.delete" => subscriptions_delete_value(&state, &body).await,
        "subscriptions.delete_preview" => subscriptions_delete_preview_value(&state, &body).await,
        "subscriptions.update" => subscriptions_update_value(&state, &body).await,
        "publishes" => publishes_get_value(&state).await,
        "publish.put" => publish_put_value(&state, body).await,
        "publish.delete" => publish_delete_value(&state, required_string(&body, "name")?).await,
        "publish.resolve" => publish_resolve_value(&state, &body).await,
        "users.get" => users_get_value(&state, &body).await,
        "users.post" => user_save_value(&state, body, None).await,
        "user.get" => user_get_value(&state, required_string(&body, "id")?).await,
        "user.put" => {
            user_save_value(&state, body.clone(), Some(required_string(&body, "id")?)).await
        }
        "user.delete" => user_delete_value(&state, required_string(&body, "id")?).await,
        "connections" => json_value(state.controller.monitor().connections_value()),
        "connections.total" => json_value(state.controller.monitor().total_flow_value()),
        "connections.traffic" => {
            let interval = string_or(&body, "interval", "hour");
            let (from, to) = required_stats_range(
                body.get("from").and_then(Value::as_str),
                body.get("to").and_then(Value::as_str),
            )?;
            json_value(
                state
                    .controller
                    .monitor()
                    .traffic_value_range(&interval, from, to),
            )
        }
        "connections.telemetry" => {
            let (from, to) = required_stats_range(
                body.get("from").and_then(Value::as_str),
                body.get("to").and_then(Value::as_str),
            )?;
            let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(8);
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
        "route.lists.refresh" => route_lists_refresh_value(&state).await,
        "route.lists.activation" => route_lists_activation_value(&state).await,
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
        "route.rules.priority" => route_rules_priority_value(&state, &body).await,
        "route.rules.test" => route_rules_test_value(&state, &body).await,
        "route.rules.block_history" => route_rules_block_history_value(&state).await,
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

async fn update_check(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    update_check_value(&state, &value).await
}

async fn update_apply(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    update_apply_value(&state, &value).await
}

async fn update_status(State(state): State<ApiState>) -> ApiResult {
    update_status_value(&state).await
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
    settings_get_value(&state).await
}

async fn settings_get_value(state: &ApiState) -> ApiResult {
    if state
        .controller
        .store()
        .get_config("settings")
        .await?
        .is_some()
    {
        return read_config_json(state, "settings", default_settings()).await;
    }
    json_value(state.controller.handle().load().settings.to_json())
}

async fn settings_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    write_config_json(&state, "settings", value).await
}

async fn backup_config_get(State(state): State<ApiState>) -> ApiResult {
    read_config_json(&state, "backup.config", default_backup_config()).await
}

async fn backup_config_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    write_config_json(&state, "backup.config", value).await
}

async fn backup_run(State(state): State<ApiState>) -> ApiResult {
    run_backup_value(&state).await
}

async fn backup_restore(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    restore_backup_value(&state, &value).await
}

async fn nodes_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    nodes_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn nodes_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    save_node_value(&state, value, None).await
}

async fn nodes_selected(State(state): State<ApiState>) -> ApiResult {
    selected_nodes_value(&state).await
}

async fn nodes_active(State(state): State<ApiState>) -> ApiResult {
    active_nodes_value(&state).await
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

async fn node_use(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    select_node_value(&state, id).await
}

async fn node_latency(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id);
    node_latency_value(&state, &value).await
}

async fn node_close(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    node_close_value(&state, id).await
}

async fn node_close_value(state: &ApiState, id: String) -> ApiResult {
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

#[derive(Debug, Default, Deserialize)]
struct TelemetryQuery {
    from: Option<String>,
    to: Option<String>,
    limit: Option<u64>,
}

async fn connections_traffic(
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

async fn connections_telemetry(
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
        .map(|value| {
            let id = value
                .as_str()
                .ok_or_else(|| ApiError::bad("connection ids must be strings"))?;
            id.parse::<u64>()
                .map_err(|_| ApiError::bad(format!("invalid connection id {id:?}")))?;
            Ok::<_, ApiError>(id.to_owned())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    state.controller.monitor().request_close(&ids);
    empty()
}

async fn connections_events(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
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
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn tools_logs(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    tools_logs_v2(State(state)).await
}

async fn tools_logs_v2(
    State(state): State<ApiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
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
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn tools_interfaces() -> ApiResult {
    tools_interfaces_value()
}

async fn tools_licenses() -> ApiResult {
    tools_licenses_value()
}

async fn subscriptions_get(State(state): State<ApiState>) -> ApiResult {
    subscriptions_get_value(&state).await
}

async fn subscriptions_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    subscriptions_put_value(&state, value).await
}

async fn subscriptions_delete(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_delete_value(&state, &value).await
}

async fn subscriptions_delete_preview(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_delete_preview_value(&state, &value).await
}

async fn subscriptions_update(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    subscriptions_update_value(&state, &value).await
}

async fn publishes(State(state): State<ApiState>) -> ApiResult {
    publishes_get_value(&state).await
}

async fn publish_put(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    publish_put_value(&state, value).await
}

async fn publish_delete(State(state): State<ApiState>, Path(name): Path<String>) -> ApiResult {
    publish_delete_value(&state, name).await
}

async fn publish_resolve(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "name", name);
    publish_resolve_value(&state, &value).await
}

async fn inbounds_config_get(State(state): State<ApiState>) -> ApiResult {
    inbounds_config_get_value(&state).await
}

async fn inbounds_config_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    inbounds_config_put_value(&state, value).await
}

async fn inbounds_config_get_value(state: &ApiState) -> ApiResult {
    let settings = state
        .controller
        .store()
        .repository()
        .get_inbound_settings()
        .await?;
    json_value(serde_json::to_value(settings)?)
}

async fn inbounds_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let settings: InboundSettings = serde_json::from_value(value)
        .map_err(|error| ApiError::bad(format!("invalid inbound settings: {error}")))?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_inbound_settings(settings).await
        })
        .await?;
    json_value(serde_json::to_value(settings)?)
}

async fn users_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    users_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn users_post(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    user_save_value(&state, value, None).await
}

async fn user_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    user_get_value(&state, id).await
}

async fn user_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "id", id.clone());
    user_save_value(&state, value, Some(id)).await
}

async fn user_delete(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    user_delete_value(&state, id).await
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

async fn route_lists_config_get(State(state): State<ApiState>) -> ApiResult {
    read_config_json(&state, "route.lists.config", default_route_list_config()).await
}

async fn route_lists_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    write_config_json(&state, "route.lists.config", value).await
}

const ROUTE_LIST_ACTIVATION_KEY: &str = "route.lists.activation";
const ROUTE_ACTIVATION_KEY: &str = "route.activation";

async fn route_lists_refresh(State(state): State<ApiState>) -> ApiResult {
    route_lists_refresh_value(&state).await
}

struct RouteGeoDownloadTransport {
    route: Arc<dyn RouteListTransport>,
    timeout: Duration,
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

fn geo_cache_path() -> PathBuf {
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    root.join("yuhaiin-rust").join("geo").join("Country.mmdb")
}

fn optional_sha256(value: &Value) -> Option<Vec<u8>> {
    let value = value.as_str()?.trim();
    if value.len() != 64 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

async fn refresh_geo_database(
    state: &ApiState,
    route: Arc<dyn RouteListTransport>,
    timeout: Duration,
) -> std::result::Result<Option<MaxMindMetadataRecord>, yuhaiin_core::Error> {
    let config = state
        .controller
        .store()
        .get_config("route.lists.config")
        .await?
        .map(|bytes| raw_json(&bytes, default_route_list_config()))
        .unwrap_or_else(default_route_list_config);
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

async fn route_lists_activation(State(state): State<ApiState>) -> ApiResult {
    route_lists_activation_value(&state).await
}

async fn route_lists_refresh_value(state: &ApiState) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    let timeout = Duration::from_secs(90);
    let proxy_id = crate::inbound::selected_proxy_id(&state.controller).await?;
    let snapshot = state.controller.handle().load();
    let proxy: Arc<dyn AsyncProxy> = match snapshot.build_proxy(&proxy_id, timeout).await {
        Ok(build) => build.proxy,
        Err(_error) if proxy_id == "direct" => Arc::new(DirectAsyncProxy { timeout }),
        Err(error) => return Err(error.into()),
    };
    let transport = Arc::new(ProxyRouteListTransport::new(
        proxy,
        snapshot.resolver.clone(),
    ));
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
    let refreshed_at = unix_millis();
    let activation = json!({
        "hostIndexRefreshAt": refreshed_at,
        "lastRefreshAt": refreshed_at,
        "refreshed": report.refreshed,
        "errors": report.errors,
    });
    let bytes = serde_json::to_vec(&activation)?;
    let mut list_config = state
        .controller
        .store()
        .get_config("route.lists.config")
        .await?
        .map(|bytes| raw_json(&bytes, default_route_list_config()))
        .unwrap_or_else(default_route_list_config);
    if let Some(object) = list_config.as_object_mut() {
        object.insert(
            "lastRefreshTime".to_owned(),
            Value::String(refreshed_at.to_string()),
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
    state
        .controller
        .mutate_and_reload(move |store| async move {
            if let Some(metadata) = geo_metadata {
                store.repository().put_maxmind_metadata(&metadata).await?;
            }
            store
                .put_config("route.lists.config", &list_config_bytes)
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

async fn route_lists_activation_value(state: &ApiState) -> ApiResult {
    let value = state
        .controller
        .store()
        .get_config(ROUTE_LIST_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0}));
    json_value(value)
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

async fn route_rules_priority(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_rules_priority_value(&state, &value).await
}

async fn route_rules_test(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    route_rules_test_value(&state, &value).await
}

async fn route_rules_block_history(State(state): State<ApiState>) -> ApiResult {
    route_rules_block_history_value(&state).await
}

async fn tags_get(State(state): State<ApiState>, Query(query): Query<ListQuery>) -> ApiResult {
    tags_get_value(&state, &serde_json::to_value(query).unwrap_or_default()).await
}

async fn tag_put(
    State(state): State<ApiState>,
    Path(tag): Path<String>,
    Json(mut value): Json<Value>,
) -> ApiResult {
    set_string(&mut value, "tag", tag);
    tag_put_value(&state, value).await
}

async fn tag_delete(State(state): State<ApiState>, Path(tag): Path<String>) -> ApiResult {
    tag_delete_value(&state, tag).await
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
    Ok(Json(page_with_filter(values, input, node_matches_query)))
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
        // NodeRuntime.Save in Go intentionally marks every API save as a
        // manually managed node, regardless of the request's origin.
        origin: "manual".to_owned(),
        enabled: bool_or(&value, "enabled", true),
        chain_types_json: serde_json::to_vec(&chain_types)?,
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&value)?,
    };
    state
        .controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_node(&record).await },
        )
        .await?;
    get_node_value(state, id).await
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

async fn selected_node_id(state: &ApiState, key: &str) -> Result<Option<String>, ApiError> {
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
    Ok(state
        .controller
        .store()
        .get_config(LEGACY_SELECTED_NODE_KEY)
        .await?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned)))
}

async fn selected_node_record(
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

async fn active_nodes_value(state: &ApiState) -> ApiResult {
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
    let bytes = serde_json::to_vec(&json!({"id": id}))?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(SELECTED_TCP_NODE_KEY, &bytes).await?;
            store.put_config(SELECTED_UDP_NODE_KEY, &bytes).await?;
            store.put_config(LEGACY_SELECTED_NODE_KEY, &bytes).await
        })
        .await?;
    Ok(empty_json())
}

async fn inbounds_get_value(state: &ApiState, input: &Value) -> ApiResult {
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
    state
        .controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_inbound(&record).await },
        )
        .await?;
    // Go's saveInbound calls Inbounds.Get after Save, so the response is the
    // persisted contract (including any fields normalized by the store), not
    // the request JSON verbatim.
    get_inbound_value(state, id).await
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
    Ok(Json(page_with_filter(
        records.into_iter().map(resolver_json).collect(),
        input,
        resolver_matches_query,
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
    let route_lists = state.controller.handle().load().route_lists.clone();
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    let values = records
        .into_iter()
        .map(|record| route_list_item_json(record, &route_lists))
        .collect::<Vec<_>>();
    Ok(Json(page_with_filter(
        values,
        input,
        route_list_matches_query,
    )))
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
    Ok(Json(page_with_filter(
        values,
        input,
        route_rule_matches_query,
    )))
}

async fn get_route_rule_value(state: &ApiState, name: String, _index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    records
        .into_iter()
        .find(|record| record.name == name)
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
    let existing = current.iter().find(|record| record.name == name);
    let replace_legacy_id = existing.is_some_and(|record| record.id != name);
    let priority = existing.map(|record| record.priority).unwrap_or_else(|| {
        let requested = index.map(|value| value as i64).unwrap_or_default();
        if requested > 0 {
            requested
        } else {
            current
                .iter()
                .map(|record| record.priority)
                .max()
                .unwrap_or_default()
                .saturating_add(1)
        }
    });
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
        // Go's v2 store uses the public rule name as the compatibility row
        // id.  The URL index is only a legacy routing parameter; making it
        // part of the id creates duplicate rules on every PUT.
        id: name.clone(),
        name: name.clone(),
        priority,
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
            if replace_legacy_id {
                store
                    .repository()
                    .delete_go_route_rule_by_name(&record.name)
                    .await?;
            }
            store.repository().put_go_route_rule(&record).await
        })
        .await?;
    Ok(Json(returned))
}

async fn delete_route_rule_value(state: &ApiState, name: String, _index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    if !records.iter().any(|record| record.name == name) {
        return Err(ApiError::not_found("route rule not found"));
    }
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .delete_go_route_rule_by_name(&name)
                .await
                .map(|_| ())
        })
        .await;
    result.map(|_| empty_json()).map_err(Into::into)
}

async fn route_rules_priority_value(state: &ApiState, value: &Value) -> ApiResult {
    let source = value
        .get("source")
        .ok_or_else(|| ApiError::bad("source is required"))?;
    let target = value
        .get("target")
        .ok_or_else(|| ApiError::bad("target is required"))?;
    let source_name = required_string(source, "name")?;
    let target_name = required_string(target, "name")?;
    let operate = string_or(value, "operate", "exchange");
    if !matches!(
        operate.as_str(),
        "" | "exchange" | "insert_before" | "insert_after"
    ) {
        return Err(ApiError::bad(format!(
            "unknown priority operate {operate:?}"
        )));
    }

    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .change_go_route_rule_priority(&source_name, &target_name, &operate)
                .await
        })
        .await;
    result
        .map(|_| empty_json())
        .map_err(|error| match error.kind {
            yuhaiin_core::ErrorKind::NotFound => ApiError::not_found(error.to_string()),
            yuhaiin_core::ErrorKind::InvalidInput => ApiError::bad(error.to_string()),
            _ => error.into(),
        })
}

async fn route_rules_test_value(state: &ApiState, value: &Value) -> ApiResult {
    let input = required_string(value, "host")?;
    let (host, port) = split_rule_test_target(&input)?;
    let destination = match host.parse() {
        Ok(address) => Endpoint::ip(Network::Tcp, std::net::SocketAddr::new(address, port)),
        Err(_) => Endpoint::domain(
            Network::Tcp,
            DomainName::new(&host).map_err(|error| ApiError::bad(error.to_string()))?,
            port,
        ),
    };
    let mut context = FlowContext::new(destination);
    let snapshot = state.controller.handle().load();
    let decision = snapshot.apply_route(&mut context);
    let mode = match decision.mode {
        yuhaiin_core::RouteMode::Direct => "direct",
        yuhaiin_core::RouteMode::Proxy => "proxy",
        yuhaiin_core::RouteMode::Bypass => "bypass",
        yuhaiin_core::RouteMode::Block => "drop",
    };
    let mut matched = Vec::new();
    let route_lists = &snapshot.route_lists;
    for record in &snapshot.route_rules {
        for rule in expand_go_route_rule(record, route_lists)? {
            let is_match = rule.matches(&context.effective_destination());
            if is_match {
                matched.push((record, rule));
            }
        }
    }
    let selected = matched
        .iter()
        .min_by_key(|(_, rule)| rule.priority)
        .map(|(record, _)| raw_json(&record.data_json, json!({})));
    let tag = context.tag.clone().unwrap_or_else(|| {
        selected
            .as_ref()
            .map(|value| string_or(value, "tag", ""))
            .unwrap_or_default()
    });
    let resolver = context.resolver.clone().unwrap_or_else(|| {
        selected
            .as_ref()
            .map(|value| string_or(value, "resolver", ""))
            .unwrap_or_default()
    });
    let match_result = context
        .match_history
        .iter()
        .flat_map(|entry| entry.history.iter())
        .map(|item| {
            json!({
                "listName": item.list_name,
                "matched": item.matched,
            })
        })
        .collect::<Vec<_>>();
    json_value(json!({
        "mode": mode,
        "tag": tag,
        "resolver": resolver,
        "afterAddr": context.destination.to_string(),
        "lists": context.lists,
        "ips": [],
        "matchResult": match_result,
    }))
}

fn split_rule_test_target(value: &str) -> std::result::Result<(String, u16), ApiError> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| ApiError::bad("host has an invalid IPv6 authority"))?;
        let port = suffix
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|error| ApiError::bad(format!("host port: {error}")))?
            .unwrap_or(0);
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok((host.to_owned(), port));
        }
    }
    Ok((value.to_owned(), 0))
}

async fn route_rules_block_history_value(state: &ApiState) -> ApiResult {
    json_value(state.controller.monitor().block_history_value())
}

async fn route_apply_value(state: &ApiState) -> ApiResult {
    let applied_at = unix_millis();
    let activation = json!({
        "hostIndexRefreshAt": 0,
        "ruleApplyAt": 0,
        "lastApplyAt": applied_at,
    });
    let bytes = serde_json::to_vec(&activation)?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(ROUTE_ACTIVATION_KEY, &bytes).await
        })
        .await?;
    state
        .controller
        .monitor()
        .logs()
        .info(format!("route rules applied at {applied_at}"));
    empty()
}

async fn route_activation_value(state: &ApiState) -> ApiResult {
    let value = state
        .controller
        .store()
        .get_config(ROUTE_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0}));
    json_value(value)
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
    let config = json!({"server": server});
    let bytes = serde_json::to_vec(&config)?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config("resolver.server", &bytes).await?;
            store.repository().put_go_dns_server(&server).await
        })
        .await?;
    Ok(Json(config))
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

async fn update_check_value(state: &ApiState, body: &Value) -> ApiResult {
    let channel = string_or(&body, "channel", "stable");
    match state.update.check(&channel).await {
        Ok(result) => json_value(serde_json::to_value(result).unwrap_or_else(|_| json!({}))),
        Err(error) => Err(ApiError::unavailable(error)),
    }
}

fn required_stats_range(from: Option<&str>, to: Option<&str>) -> Result<(i64, i64), ApiError> {
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

async fn update_apply_value(state: &ApiState, value: &Value) -> ApiResult {
    let channel = string_or(value, "channel", "stable");
    let target_tag = required_string(value, "targetTag")?;
    state
        .update
        .apply(&channel, &target_tag)
        .await
        .map_err(ApiError::unavailable)?;
    empty()
}

async fn update_status_value(state: &ApiState) -> ApiResult {
    json_value(serde_json::to_value(state.update.status()).unwrap_or_else(|_| json!({})))
}

async fn node_latency_value(state: &ApiState, value: &Value) -> ApiResult {
    let id = required_string(value, "id")?;
    let timeout = Duration::from_millis(
        value
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(10_000)
            .clamp(100, 120_000),
    );
    let snapshot = state.controller.handle().load();
    let resolver = snapshot.resolver.clone();
    let proxy = snapshot
        .build_proxy(&id, timeout)
        .await
        .map_err(ApiError::from)?
        .proxy;
    let request: LatencyRequest = serde_json::from_value(value.clone())?;
    match tokio::time::timeout(
        timeout,
        crate::latency::probe_with_resolver(proxy, resolver, request, timeout),
    )
    .await
    {
        Ok(Ok(response)) => json_value(serde_json::to_value(response)?),
        Ok(Err(error)) => json_value(json!({"ok": false, "error": error.to_string()})),
        Err(_) => json_value(json!({"ok": false, "error": "latency probe timed out"})),
    }
}

async fn run_backup_value(state: &ApiState) -> ApiResult {
    let destination = backup_destination()?;
    state
        .controller
        .store()
        .backup_to(&destination)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(json!({})))
}

async fn restore_backup_value(state: &ApiState, value: &Value) -> ApiResult {
    let source = string_or_any(value, &["path", "source", "file"]);
    if source.trim().is_empty() {
        return Err(ApiError::bad("backup restore requires path/source/file"));
    }
    let source = PathBuf::from(source);
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

fn tools_interfaces_value() -> ApiResult {
    json_value(json!({"interfaces": discover_interfaces()}))
}

fn tools_licenses_value() -> ApiResult {
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

async fn subscriptions_get_value(state: &ApiState) -> ApiResult {
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

async fn subscriptions_put_value(state: &ApiState, value: Value) -> ApiResult {
    let records = subscription_records(&value)?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_subscription_links(&records).await
        })
        .await?;
    empty()
}

async fn subscriptions_delete_value(state: &ApiState, value: &Value) -> ApiResult {
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
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .delete_go_subscription_links(&names)
                .await?;
            if delete_nodes {
                store
                    .repository()
                    .delete_go_nodes_by_groups(&groups)
                    .await?;
            }
            Ok(())
        })
        .await?;
    empty()
}

async fn subscriptions_delete_preview_value(state: &ApiState, value: &Value) -> ApiResult {
    let names = subscription_names(value, "subscriptions delete preview")?;
    let nodes = state
        .controller
        .store()
        .repository()
        .count_go_nodes_by_groups(&names)
        .await?;
    Ok(Json(json!({"nodes": nodes, "users": 0})))
}

async fn subscriptions_update_value(_state: &ApiState, value: &Value) -> ApiResult {
    let names = subscription_names(value, "subscriptions update")?;
    if names.is_empty() {
        return Err(ApiError::bad(
            "subscription update requires at least one link name or an implemented refresh worker",
        ));
    }
    Err(ApiError::unavailable(format!(
        "subscription refresh is not implemented for: {}",
        names.join(", ")
    )))
}

fn subscription_records(value: &Value) -> Result<Vec<GoSubscriptionLinkRecord>, ApiError> {
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

fn subscription_names(value: &Value, operation: &str) -> Result<Vec<String>, ApiError> {
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

fn subscription_json(record: GoSubscriptionLinkRecord) -> Value {
    let mut value = raw_json(&record.data_json, json!({}));
    set_string(&mut value, "name", record.name);
    set_string(&mut value, "url", record.url);
    set_string(&mut value, "type", record.link_type);
    value
}

async fn publishes_get_value(state: &ApiState) -> ApiResult {
    Ok(Json(
        json!({"items": config_items(state, "publishes.items").await?}),
    ))
}

async fn publish_put_value(state: &ApiState, mut value: Value) -> ApiResult {
    let name = required_string(&value, "name")?;
    set_string(&mut value, "name", name.clone());
    let mut items = config_items(state, "publishes.items").await?;
    items.retain(|item| item.get("name").and_then(Value::as_str) != Some(name.as_str()));
    items.push(value);
    let _ = write_config_json(state, "publishes.items", json!({"items": items})).await?;
    empty()
}

async fn publish_delete_value(state: &ApiState, name: String) -> ApiResult {
    let mut items = config_items(state, "publishes.items").await?;
    items.retain(|item| item.get("name").and_then(Value::as_str) != Some(name.as_str()));
    let _ = write_config_json(state, "publishes.items", json!({"items": items})).await?;
    empty()
}

async fn publish_resolve_value(state: &ApiState, value: &Value) -> ApiResult {
    let name = required_string(value, "name")?;
    let publish = config_items(state, "publishes.items")
        .await?
        .into_iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name.as_str()))
        .ok_or_else(|| ApiError::not_found(format!("publish {name:?} was not found")))?;
    let points = publish
        .get("points")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<std::collections::HashSet<_>>();
    let nodes = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?
        .into_iter()
        .filter(|node| points.is_empty() || points.contains(node.id.as_str()))
        .map(node_json)
        .collect::<Vec<_>>();
    json_value(json!({"points": nodes}))
}

async fn users_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let users = config_items(state, "users.items")
        .await?
        .into_iter()
        .map(user_view)
        .collect::<Vec<_>>();
    Ok(Json(page(users, input)))
}

async fn user_get_value(state: &ApiState, id: String) -> ApiResult {
    config_items(state, "users.items")
        .await?
        .into_iter()
        .find(|user| user.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .map(|user| Json(user_view(user)))
        .ok_or_else(|| ApiError::not_found(format!("user {id:?} was not found")))
}

async fn user_save_value(state: &ApiState, mut value: Value, id: Option<String>) -> ApiResult {
    let id = id
        .or_else(|| string_or_opt(&value, "id"))
        .unwrap_or_else(|| format!("rust-user-{}-{}", unix_seconds(), std::process::id()));
    let mut items = config_items(state, "users.items").await?;
    let previous = items
        .iter()
        .find(|user| user.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .cloned();
    set_string(&mut value, "id", id.clone());
    if value.get("credential").is_none() {
        if let Some(previous) = previous.as_ref().and_then(|user| user.get("credential")) {
            if let Some(object) = value.as_object_mut() {
                object.insert("credential".to_owned(), previous.clone());
            }
        }
    }
    items.retain(|user| user.get("id").and_then(Value::as_str) != Some(id.as_str()));
    items.push(value.clone());
    let _ = write_config_json(state, "users.items", json!({"items": items})).await?;
    json_value(user_view(value))
}

async fn user_delete_value(state: &ApiState, id: String) -> ApiResult {
    let mut items = config_items(state, "users.items").await?;
    let before = items.len();
    items.retain(|user| user.get("id").and_then(Value::as_str) != Some(id.as_str()));
    if items.len() == before {
        return Err(ApiError::not_found(format!("user {id:?} was not found")));
    }
    let _ = write_config_json(state, "users.items", json!({"items": items})).await?;
    empty()
}

async fn config_items(state: &ApiState, key: &str) -> Result<Vec<Value>, ApiError> {
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

fn user_view(mut value: Value) -> Value {
    let credential = value
        .get("credential")
        .cloned()
        .unwrap_or_else(|| json!({"type": "token", "token": ""}));
    let mut view = json!({
        "id": string_or(&value, "id", ""),
        "name": string_or(&value, "name", ""),
        "enabled": bool_or(&value, "enabled", true),
        "origin": string_or(&value, "origin", "rust-api"),
        "usage": string_or(&value, "usage", ""),
        "credential": credential_view(&credential),
    });
    if let Some(reference_count) = value.get("outboundReferences") {
        if let Some(object) = view.as_object_mut() {
            object.insert("outboundReferences".to_owned(), reference_count.clone());
        }
    }
    value = view;
    value
}

fn credential_view(value: &Value) -> Value {
    let kind = string_or(value, "type", "token");
    let section = value.get(&kind).unwrap_or(value);
    let username = string_or_opt(section, "username");
    let password = string_or_opt(section, "password");
    let uuid = string_or_opt(section, "uuid");
    let token = string_or_opt(section, "token");
    let secret = password.as_deref().or(uuid.as_deref()).or(token.as_deref());
    let mut result = json!({
        "type": kind,
        "hasUsername": username.is_some(),
        "hasSecret": secret.is_some_and(|secret| !secret.is_empty()),
    });
    if let Some(object) = result.as_object_mut() {
        if let Some(username) = username {
            object.insert("username".to_owned(), Value::String(username));
        }
        if let Some(password) = password {
            object.insert("password".to_owned(), Value::String(password));
        }
        if let Some(uuid) = uuid {
            object.insert("uuid".to_owned(), Value::String(uuid));
        }
        if let Some(token) = token {
            object.insert("token".to_owned(), Value::String(token));
        }
    }
    result
}

fn default_backup_config() -> Value {
    json!({
        "instanceName": "",
        "s3": {"enabled": false, "accessKey": "", "secretKey": "", "bucket": "", "region": "", "endpointUrl": "", "usePathStyle": false, "storageClass": ""},
        "interval": 0,
        "lastBackupHash": ""
    })
}

fn backup_destination() -> Result<PathBuf, ApiError> {
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let directory = root.join("yuhaiin-rust").join("backups");
    std::fs::create_dir_all(&directory)
        .map_err(|error| ApiError::internal(format!("create backup directory: {error}")))?;
    Ok(directory.join(format!("state-{}.sqlite", unix_seconds())))
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
    let settings_kv =
        (key == "settings").then(|| crate::RuntimeSettings::from_value(&value).to_go_settings_kv());
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(&key, &bytes).await?;
            if let Some(settings_kv) = settings_kv {
                store.repository().put_go_settings_kv(&settings_kv).await?;
            }
            Ok(())
        })
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

fn route_list_item_json(record: GoRouteListRecord, route_lists: &RouteListSnapshot) -> Value {
    let value = raw_json(
        &record.data_json,
        json!({"name": record.name, "type": record.list_type}),
    );
    let name = string_or(&value, "name", &record.name);
    let entries = route_lists.values(&name).unwrap_or_default();
    let preview = entries
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let error_count = u32::from(route_lists.error(&name).is_some());
    json!({
        "name": name,
        "type": string_or(&value, "type", &record.list_type),
        "source": string_or(&value.get("source").cloned().unwrap_or_default(), "type", &record.source_type),
        "itemCount": entries.len(),
        "errorCount": error_count,
        "preview": preview,
    })
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
    page_values(values, input)
}

fn page_with_filter<F>(mut values: Vec<Value>, input: &Value, matches: F) -> Value
where
    F: Fn(&Value, &str) -> bool,
{
    if let Some(query) = normalized_query(input) {
        values.retain(|value| matches(value, &query));
    }
    page_values(values, input)
}

fn normalized_query(input: &Value) -> Option<String> {
    input
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_ascii_lowercase)
}

fn page_values(values: Vec<Value>, input: &Value) -> Value {
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

fn field_contains(value: &Value, key: &str, query: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|field| field.to_ascii_lowercase().contains(query))
}

fn nested_type_contains(value: &Value, key: &str, query: &str) -> bool {
    value
        .get(key)
        .and_then(|nested| nested.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|field| field.to_ascii_lowercase().contains(query))
}

fn node_chain_contains_query(value: &Value, query: &str) -> bool {
    value
        .get("chain")
        .and_then(Value::as_array)
        .is_some_and(|chain| {
            chain
                .iter()
                .any(|protocol| field_contains(protocol, "type", query))
        })
}

fn node_matches_query(value: &Value, query: &str) -> bool {
    ["id", "name", "group", "origin"]
        .iter()
        .any(|key| field_contains(value, key, query))
        || node_chain_contains_query(value, query)
}

fn inbound_matches_query(value: &Value, query: &str) -> bool {
    ["id", "name"]
        .iter()
        .any(|key| field_contains(value, key, query))
        || nested_type_contains(value, "network", query)
        || nested_type_contains(value, "protocol", query)
}

fn resolver_matches_query(value: &Value, query: &str) -> bool {
    ["id", "type", "host", "subnet", "tlsServerName"]
        .iter()
        .any(|key| field_contains(value, key, query))
}

fn route_list_matches_query(value: &Value, query: &str) -> bool {
    ["name", "type", "source", "preview"]
        .iter()
        .any(|key| field_contains(value, key, query))
}

fn route_rule_matches_query(value: &Value, query: &str) -> bool {
    ["name", "mode", "tag", "resolver"]
        .iter()
        .any(|key| field_contains(value, key, query))
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
fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(i64::MAX as u128) as i64
        })
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
fn default_route_config() -> Value {
    json!({"directResolver":"", "proxyResolver":"", "resolveLocally":false, "udpProxyFqdnStrategy":"default"})
}
fn default_settings() -> Value {
    let mut value = RuntimeSettings::default().to_json();
    if let Some(object) = value.as_object_mut() {
        object.insert("backup".to_owned(), default_backup_config());
    }
    value
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
    use base64::Engine;
    use http_body_util::BodyExt;
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
    async fn external_web_root_serves_assets_and_react_fallback_without_hiding_api() {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("yuhaiin-rust")
            .join(format!("api-web-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "<html>rust-ui</html>").unwrap();
        std::fs::write(root.join("app.js"), "console.log('rust-ui');").unwrap();

        let app = router(state().await.with_external_web(&root));
        let asset = app
            .clone()
            .oneshot(Request::get("/app.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(asset.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .as_ref(),
            b"console.log('rust-ui');"
        );

        let fallback = app
            .clone()
            .oneshot(Request::get("/dashboard").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(fallback.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(fallback.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .as_ref(),
            b"<html>rust-ui</html>"
        );

        let api = app
            .oneshot(Request::get("/api/v2/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(api.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn node_rpc_round_trips_frontend_shape_and_publishes_reload() {
        let state = state().await;
        let value = json!({"id":"direct","name":"Direct","group":"","origin":"rust","enabled":true,"chain":[{"type":"direct","direct":{}}]});
        let saved = save_node_value(&state, value.clone(), None).await.unwrap();
        assert_eq!(saved.0["id"], "direct");
        assert_eq!(saved.0["origin"], "manual");
        let listed = nodes_get_value(&state, &json!({"page":1,"page_size":0}))
            .await
            .unwrap();
        assert_eq!(listed.0["items"][0]["chain"][0]["type"], "direct");
        assert_eq!(listed.0["items"][0]["origin"], "manual");
        assert_eq!(state.controller.handle().revision(), 1);
    }

    #[tokio::test]
    async fn inbound_save_returns_persisted_contract_and_resolver_storage_normalizes_system() {
        let state = state().await;
        let inbound = json!({
            "id": "api-tun",
            "name": "API TUN",
            "enabled": false,
            "network": {"type": "empty", "empty": {}},
            "transports": [],
            "protocol": {
                "type": "tun",
                "tun": {
                    "name": "tun://api-tun",
                    "mtu": 9000,
                    "portal": "198.18.0.1/15",
                    "portalV6": "fc00::1/18",
                    "skipMulticast": true,
                    "driver": "gvisor",
                    "routes": [],
                    "excludes": []
                }
            }
        });
        let saved = save_inbound_value(&state, inbound, None).await.unwrap();
        assert_eq!(saved.0["id"], "api-tun");
        assert_eq!(saved.0["name"], "API TUN");
        assert_eq!(saved.0["protocol"]["type"], "tun");

        let response = save_resolver_value(
            &state,
            json!({"id": " system ", "type": "system", "host": ""}),
            None,
        )
        .await
        .unwrap();
        // The Go controller returns the request contract from SaveContract;
        // normalization is observable through List/Get afterward.
        assert_eq!(response.0["id"], " system ");
        let listed = resolvers_get_value(&state, &json!({"page": 1, "page_size": 0}))
            .await
            .unwrap();
        let system = listed.0["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "system")
            .unwrap();
        assert_eq!(system["type"], "system");
        assert_eq!(system["host"], "system default");
        assert_eq!(system["system"], true);
    }

    #[tokio::test]
    async fn node_selection_keeps_go_tcp_udp_contract_and_use_updates_both() {
        let state = state().await;
        for id in ["tcp-node", "udp-node"] {
            let _ = save_node_value(
                &state,
                json!({
                    "id": id,
                    "name": id,
                    "enabled": true,
                    "chain": [{"type":"direct","direct":{}}]
                }),
                None,
            )
            .await
            .unwrap();
        }

        state
            .controller
            .store()
            .put_config(SELECTED_TCP_NODE_KEY, br#"{"id":"tcp-node"}"#)
            .await
            .unwrap();
        state
            .controller
            .store()
            .put_config(SELECTED_UDP_NODE_KEY, br#"{"id":"udp-node"}"#)
            .await
            .unwrap();

        let selected = selected_nodes_value(&state).await.unwrap();
        assert_eq!(selected.0["tcp"]["id"], "tcp-node");
        assert_eq!(selected.0["udp"]["id"], "udp-node");

        let used = select_node_value(&state, "udp-node".to_owned())
            .await
            .unwrap();
        assert_eq!(used.0, json!({}));
        let selected = selected_nodes_value(&state).await.unwrap();
        assert_eq!(selected.0["tcp"]["id"], "udp-node");
        assert_eq!(selected.0["udp"]["id"], "udp-node");
    }

    #[tokio::test]
    async fn active_nodes_reports_live_proxy_slots_not_all_enabled_rows() {
        let state = state().await;
        let _ = save_node_value(
            &state,
            json!({
                "id": "active-node",
                "name": "active-node",
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();
        let _ = save_node_value(
            &state,
            json!({
                "id": "idle-node",
                "name": "idle-node",
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();

        let initially_active = active_nodes_value(&state).await.unwrap();
        assert!(initially_active.0["items"].as_array().unwrap().is_empty());

        let selector = state
            .controller
            .build_proxy_selector("", "active-node", "", "", Duration::from_secs(1))
            .await
            .unwrap();
        let active = active_nodes_value(&state).await.unwrap();
        assert_eq!(active.0["items"].as_array().unwrap().len(), 1);
        assert_eq!(active.0["items"][0]["id"], "active-node");

        drop(selector);
        let after_drop = active_nodes_value(&state).await.unwrap();
        assert!(after_drop.0["items"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn inbound_config_uses_go_shape_and_reload_updates_sniff_policy() {
        let state = state().await;
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::get("/api/v2/inbounds/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let initial: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(initial["hijackDns"], true);
        assert_eq!(initial["hijackDnsFakeIp"], true);
        assert_eq!(initial["sniff"], true);

        let response = app
            .oneshot(
                Request::put("/api/v2/inbounds/config")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"hijackDns":false,"hijackDnsFakeIp":false,"sniff":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state.controller.handle().load().inbound_settings.hijack_dns);
        assert!(
            !state
                .controller
                .handle()
                .load()
                .inbound_settings
                .hijack_dns_fakeip
        );
        assert!(!state.controller.monitor().sniff_enabled());
        let saved = state
            .controller
            .store()
            .repository()
            .get_inbound_settings()
            .await
            .unwrap();
        assert_eq!(
            saved,
            InboundSettings {
                hijack_dns: false,
                hijack_dns_fakeip: false,
                sniff: false,
            }
        );
    }

    #[tokio::test]
    async fn rust_pprof_index_follows_runtime_setting() {
        let state = state().await;
        let app = router(state.clone());
        let enabled = app
            .clone()
            .oneshot(Request::get("/debug/pprof/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(enabled.status(), StatusCode::OK);
        assert_eq!(
            enabled.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let profile = app
            .oneshot(
                Request::get("/debug/pprof/profile?seconds=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(profile.status(), StatusCode::OK);
        assert_eq!(
            profile.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert!(
            !to_bytes(profile.into_body(), 16 * 1024 * 1024)
                .await
                .unwrap()
                .is_empty()
        );

        state
            .controller
            .store()
            .put_config("settings", br#"{"pprof":false}"#)
            .await
            .unwrap();
        state.controller.reload().await.unwrap();
        let disabled = router(state)
            .oneshot(Request::get("/debug/pprof/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn route_priority_and_test_endpoints_use_persisted_rules() {
        let state = state().await;
        let _ = save_route_rule_value(
            &state,
            json!({
                "name":"allow-example",
                "mode":"direct",
                "match":{"domain":"example.com"}
            }),
            None,
        )
        .await
        .unwrap();
        let _ = save_route_rule_value(
            &state,
            json!({
                "name":"drop-example",
                "mode":"drop",
                "match":{"domain":"example.com"}
            }),
            None,
        )
        .await
        .unwrap();

        let priority = router(state.clone())
            .oneshot(
                Request::post("/api/v2/route/rules/priority")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"source":{"name":"drop-example","index":1},"target":{"name":"allow-example","index":0},"operate":"insert_before"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(priority.status(), StatusCode::OK);

        let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
            .await
            .unwrap();
        assert_eq!(
            listed.0["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == "drop-example")
                .unwrap()["name"],
            "drop-example"
        );

        let tested = router(state)
            .oneshot(
                Request::post("/api/v2/route/rules/test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host":"example.com:443"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tested.status(), StatusCode::OK);
        let body = to_bytes(tested.into_body(), 1024 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["mode"], "drop");
        assert!(value.get("matchResult").is_some());
    }

    #[tokio::test]
    async fn route_rule_url_index_does_not_create_duplicate_rules() {
        let state = state().await;
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(
                Request::post("/api/v2/route/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"browser","mode":"direct","match":{"domain":"example.com"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);

        let updated = app
            .clone()
            .oneshot(
                Request::put("/api/v2/route/rules/browser/999")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"mode":"drop","match":{"domain":"example.com"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);

        let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
            .await
            .unwrap();
        let browser_rules = listed.0["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["name"] == "browser")
            .collect::<Vec<_>>();
        assert_eq!(browser_rules.len(), 1);
        assert_eq!(browser_rules[0]["index"], 1);

        let fetched = app
            .clone()
            .oneshot(
                Request::get("/api/v2/route/rules/browser/0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let fetched: Value =
            serde_json::from_slice(&to_bytes(fetched.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(fetched["mode"], "drop");

        let deleted = app
            .oneshot(
                Request::delete("/api/v2/route/rules/browser/123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);
        let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
            .await
            .unwrap();
        assert!(
            !listed.0["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["name"] == "browser")
        );
    }

    #[tokio::test]
    async fn route_list_api_reports_loaded_local_items_after_reload() {
        let state = state().await;
        let _ = save_route_list_value(
            &state,
            json!({
                "name":"local-domains",
                "type":"host",
                "source":{"type":"local","local":{"lists":["example.test","api.example.test"]}}
            }),
            None,
        )
        .await
        .unwrap();
        let listed = route_lists_get_value(&state, &json!({"page":1,"pageSize":20}))
            .await
            .unwrap();
        let local = listed.0["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "local-domains")
            .unwrap();
        assert_eq!(local["name"], "local-domains");
        assert_eq!(local["itemCount"], 2);
        assert_eq!(local["errorCount"], 0);
        assert!(local["preview"].as_str().unwrap().contains("example.test"));
    }

    #[tokio::test]
    async fn route_list_refresh_downloads_geoip_through_runtime_and_persists_metadata() {
        let state = state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture: &'static [u8] =
            include_bytes!("../../yuhaiin-geo/tests/fixtures/GeoLite2-Country-Test.mmdb");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
                .await
                .unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                fixture.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, fixture)
                .await
                .unwrap();
        });

        let unique_path = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("yuhaiin-rust")
            .join("geo-tests")
            .join(format!("api-{}.mmdb", std::process::id()));
        let _ = write_config_json(
            &state,
            "route.lists.config",
            json!({
                "refreshInterval":"0",
                "maxMindDbGeoIp":{"downloadUrl":format!("http://{address}/Country.mmdb"),"error":""}
            }),
        )
        .await
        .unwrap();
        state
            .controller
            .store()
            .repository()
            .put_maxmind_metadata(&MaxMindMetadataRecord {
                id: "geoip".to_owned(),
                path: unique_path.to_string_lossy().into_owned(),
                sha256: Vec::new(),
                size: 0,
                updated_at: 0,
            })
            .await
            .unwrap();

        let _ = route_lists_refresh_value(&state).await.unwrap();
        server.await.unwrap();

        let metadata = state
            .controller
            .store()
            .repository()
            .list_maxmind_metadata()
            .await
            .unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].size, fixture.len() as i64);
        assert_eq!(metadata[0].sha256.len(), 32);
        assert_eq!(
            state
                .controller
                .handle()
                .load()
                .geo
                .as_ref()
                .unwrap()
                .country_code("2.125.160.217".parse().unwrap())
                .unwrap(),
            Some("GB".to_owned())
        );
        let config = state
            .controller
            .store()
            .get_config("route.lists.config")
            .await
            .unwrap()
            .map(|bytes| raw_json(&bytes, default_route_list_config()))
            .unwrap();
        assert_eq!(config["maxMindDbGeoIp"]["error"], "");
        let _ = std::fs::remove_file(unique_path);
    }

    #[tokio::test]
    async fn direct_subscription_tools_and_node_close_routes_match_frontend_contracts() {
        let state = state().await;
        let app = router(state);

        let saved = app
            .clone()
            .oneshot(
                Request::put("/api/v2/subscriptions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"items":[{"name":"prod","url":"https://example.test/sub","type":"base64","future":true}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);

        let listed = app
            .clone()
            .oneshot(
                Request::get("/api/v2/subscriptions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(listed["items"][0]["name"], "prod");
        assert_eq!(listed["items"][0]["future"], true);

        let preview = app
            .clone()
            .oneshot(
                Request::post("/api/v2/subscriptions/delete-preview")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"names":["prod"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preview.status(), StatusCode::OK);
        let preview: Value =
            serde_json::from_slice(&to_bytes(preview.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(preview, json!({"nodes": 0, "users": 0}));

        let interfaces = app
            .clone()
            .oneshot(
                Request::get("/api/v2/tools/interfaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(interfaces.status(), StatusCode::OK);
        let interfaces: Value =
            serde_json::from_slice(&to_bytes(interfaces.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert!(interfaces["interfaces"].is_array());

        let closed = app
            .oneshot(
                Request::post("/api/v2/nodes/prod/close")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(closed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn connections_close_rejects_non_numeric_ids_like_go() {
        let state = state().await;
        let response = router(state)
            .oneshot(
                Request::post("/api/v2/connections/close")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"ids":["not-a-number"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn connection_statistics_require_go_compatible_ranges_and_limits() {
        let state = state().await;
        let app = router(state);

        let missing_range = app
            .clone()
            .oneshot(
                Request::get("/api/v2/connections/traffic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_range.status(), StatusCode::BAD_REQUEST);

        let invalid_range = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v2/connections/traffic?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_range.status(), StatusCode::BAD_REQUEST);

        let invalid_limit = app
            .oneshot(
                Request::get("/api/v2/connections/telemetry?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&limit=51")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_limit.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn direct_legacy_management_routes_are_wired_to_shared_value_handlers() {
        let state = state().await;
        let app = router(state);

        let request = |method: axum::http::Method, uri: &str, body: &'static str| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };

        let response = app
            .clone()
            .oneshot(request(
                axum::http::Method::POST,
                "/api/v2/nodes",
                r#"{"id":"direct","name":"Direct","chain":[{"type":"direct","direct":{}}]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for uri in [
            "/api/v2/nodes/selected",
            "/api/v2/nodes/active",
            "/api/v2/inbounds/config",
            "/api/v2/route/lists/config",
            "/api/v2/route/lists/activation",
            "/api/v2/publishes",
            "/api/v2/users",
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
        }

        let response = app
            .clone()
            .oneshot(request(
                axum::http::Method::POST,
                "/api/v2/nodes/direct/use",
                "{}",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for (uri, body) in [
            (
                "/api/v2/inbounds/config",
                r#"{"hijackDns":true,"hijackDnsFakeIp":true,"sniff":true}"#,
            ),
            ("/api/v2/route/lists/config", r#"{"refreshInterval":"1h"}"#),
            (
                "/api/v2/route/tags/mobile",
                r#"{"type":"node","hash":"abc"}"#,
            ),
            ("/api/v2/publishes/public", r#"{"points":["direct"]}"#),
            (
                "/api/v2/users",
                r#"{"name":"Alice","enabled":true,"credential":{"type":"token","token":"secret"}}"#,
            ),
        ] {
            let method = if uri == "/api/v2/users" {
                axum::http::Method::POST
            } else {
                axum::http::Method::PUT
            };
            let response = app
                .clone()
                .oneshot(request(method, uri, body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "PUT/POST {uri}");
        }

        let response = app
            .clone()
            .oneshot(request(
                axum::http::Method::POST,
                "/api/v2/publishes/public/resolve",
                r#"{"name":"public"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for uri in [
            "/api/v2/route/tags",
            "/api/v2/route/tags/mobile",
            "/api/v2/publishes/public",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(if uri.ends_with("mobile") || uri.ends_with("public") {
                            axum::http::Method::DELETE
                        } else {
                            axum::http::Method::GET
                        })
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "GET/DELETE {uri}");
        }

        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v2/route/lists/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::post("/api/v2/update/check")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"channel":"stable"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The route remains valid when the host has no release-service
        // connectivity; in that case the network error is intentionally
        // surfaced as 503 instead of returning a fabricated update result.
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[tokio::test]
    async fn logs_and_route_activation_are_live_management_state() {
        let state = state().await;
        let monitor = state.controller.monitor();
        state
            .controller
            .monitor()
            .logs()
            .push_raw("time=2026-01-01T00:00:00Z level=INFO msg=\"boot\"\n");
        let app = router(state);

        let logs = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/tools.logs")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logs.status(), StatusCode::OK);
        let logs: Value =
            serde_json::from_slice(&to_bytes(logs.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(
            logs["log"][0],
            "time=2026-01-01T00:00:00Z level=INFO msg=\"boot\""
        );

        let response = app
            .clone()
            .oneshot(
                Request::get("/api/v2/tools/logs/v2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(String::from_utf8_lossy(&first).contains("boot"));
        monitor.logs().push_raw("live-log\n");
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(String::from_utf8_lossy(&second).contains("live-log"));

        let refreshed = app
            .clone()
            .oneshot(
                Request::post("/api/v2/route/lists/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refreshed.status(), StatusCode::OK);
        let activation = app
            .oneshot(
                Request::get("/api/v2/route/lists/activation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let activation: Value =
            serde_json::from_slice(&to_bytes(activation.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert!(activation["lastRefreshAt"].as_i64().unwrap_or_default() > 0);
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

    #[test]
    fn list_query_filters_match_go_field_contracts() {
        assert!(node_matches_query(
            &json!({"id":"n1", "chain":[{"type":"tls"}]}),
            "tls"
        ));
        assert!(!node_matches_query(
            &json!({"id":"n1", "description":"tls"}),
            "tls"
        ));
        assert!(inbound_matches_query(
            &json!({"id":"i1", "network":{"type":"tcp"}, "protocol":{"type":"http"}}),
            "http"
        ));
        assert!(!inbound_matches_query(
            &json!({"id":"i1", "listen":"http://127.0.0.1"}),
            "http"
        ));
        assert!(resolver_matches_query(
            &json!({"id":"r1", "type":"doh", "host":"dns.example"}),
            "example"
        ));
        assert!(!resolver_matches_query(
            &json!({"id":"r1", "description":"doh"}),
            "doh"
        ));
        assert!(route_list_matches_query(
            &json!({"name":"blocklist", "preview":"ads.example"}),
            "ads"
        ));
        assert!(route_rule_matches_query(
            &json!({"name":"rule", "mode":"proxy", "tag":"work"}),
            "work"
        ));
        assert!(!route_rule_matches_query(
            &json!({"name":"rule", "comment":"proxy"}),
            "proxy"
        ));
    }

    #[test]
    fn list_query_filters_trim_and_paginate_after_filtering() {
        let value = page_with_filter(
            vec![
                json!({"name":"direct"}),
                json!({"name":"proxy"}),
                json!({"name":"proxy backup"}),
            ],
            &json!({"query":"  PROXY ", "page":2, "pageSize":1}),
            |value, query| field_contains(value, "name", query),
        );
        assert_eq!(value["page"]["total"], 2);
        assert_eq!(value["items"][0]["name"], "proxy backup");
    }

    #[test]
    fn core_errors_use_go_rpc_status_categories() {
        let cases = [
            (
                yuhaiin_core::ErrorKind::InvalidInput,
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                yuhaiin_core::ErrorKind::Unsupported,
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                yuhaiin_core::ErrorKind::NotFound,
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                yuhaiin_core::ErrorKind::Timeout,
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
            ),
            (
                yuhaiin_core::ErrorKind::Closed,
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
            ),
            (
                yuhaiin_core::ErrorKind::Storage,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];
        for (kind, status, code) in cases {
            let error = ApiError::from(yuhaiin_core::Error::new(kind, "contract error"));
            assert_eq!(error.status, status);
            assert_eq!(error.code, code);
            assert_eq!(error.message, "contract error");
        }
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

    #[tokio::test]
    async fn management_auth_matches_go_basic_and_eventsource_query_token() {
        let state = state().await.with_auth("alice", "secret");
        let app = router(state);

        let unauthorized = app
            .clone()
            .oneshot(Request::get("/api/v2/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let wrong = app
            .clone()
            .oneshot(
                Request::get("/api/v2/info")
                    .header("authorization", "Basic YWxpY2U6d3Jvbmc=")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let authorized = app
            .clone()
            .oneshot(
                Request::get("/api/v2/info")
                    .header("authorization", format!("Basic {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);

        let eventsource = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v2/info?token={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(eventsource.status(), StatusCode::OK);

        let preflight = app
            .oneshot(
                Request::options("/api/v2/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(preflight.status(), StatusCode::UNAUTHORIZED);
    }
}
