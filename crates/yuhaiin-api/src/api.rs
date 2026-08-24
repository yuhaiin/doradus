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
use blake2::{Blake2bVar, digest::Update as BlakeUpdate, digest::VariableOutput};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::watch;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use yuhaiin_backup::{S3Client, S3Config};
use yuhaiin_core::proxy::{AsyncProxy, DirectAsyncProxy};
use yuhaiin_core::{BoxFuture, DomainName, Endpoint, FlowContext, Network, ResolveStrategy};
use yuhaiin_geo::{GeoDatabaseManager, GeoDownloadTransport, GeoRefreshRequest};

use yuhaiin_store::{
    GoBackupSettingsRecord, GoInboundRecord, GoNodeRecord, GoPublishRecord, GoResolverRecord,
    GoRouteListRecord, GoRouteRuleRecord, GoRouteSettingsRecord, GoSettingsKvRecord,
    GoSubscriptionLinkRecord, GoUserRecord, GoUserWrite, InboundSettings, MaxMindMetadataRecord,
};

use crate::backup_transport::ProxyS3Transport;
use yuhaiin_runtime::update::UpdateService;
use yuhaiin_runtime::{
    ProxyRouteListTransport, RouteListTransport, RuntimeController,
    download_route_url_with_transport, interfaces::discover_interfaces, latency::LatencyRequest,
    log::log_batch_value, refresh_route_list_caches_with_transport,
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
    route_list_refreshing: Arc<AtomicBool>,
    backup_lock: Arc<tokio::sync::Mutex<()>>,
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
            route_list_refreshing: Arc::new(AtomicBool::new(false)),
            backup_lock: Arc::new(tokio::sync::Mutex::new(())),
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
        let requested = self
            .shutdown
            .as_ref()
            .is_some_and(|shutdown| shutdown.send(true).is_ok());
        if requested {
            self.controller
                .monitor()
                .logs()
                .warn("runtime shutdown requested by API (source=backup-restore)");
        }
        requested
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

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "user_referenced",
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
            yuhaiin_core::ErrorKind::Conflict => Self::conflict(message),
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
        .route("/health", get(health))
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
        }));
    #[cfg(all(not(windows), not(target_os = "android")))]
    let router = router
        .route("/debug/pprof/heap", get(pprof_heap))
        .route("/debug/pprof/allocs", get(pprof_heap));
    let router = router.with_state(state);
    if let Some(root) = web_root {
        let index = root.join("index.html");
        router.fallback_service(ServeDir::new(root).fallback(ServeFile::new(index)))
    } else {
        router
    }
}

async fn authenticate(auth: Option<ApiAuth>, request: Request<Body>, next: Next) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
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

/// Lightweight process health endpoint for systemd/container supervisors.
///
/// It deliberately has no dependency on the persisted configuration and is
/// reachable even when management API credentials are enabled.  A 204 means
/// the HTTP server and runtime task owner are alive; data-plane readiness is
/// still validated by the service manager's regular integration smoke.
async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Debug, Default, Deserialize)]
struct PprofQuery {
    #[cfg(all(unix, not(target_os = "android")))]
    seconds: Option<u64>,
}

/// Rust-native profiling endpoints.  The payload is the standard protobuf
/// pprof profile produced by `pprof-rs`; it is intentionally not coupled to
/// Go's runtime profiler implementation.
async fn pprof_index(State(state): State<ApiState>) -> Response {
    if !state.controller.handle().load().settings.pprof {
        return StatusCode::NOT_FOUND.into_response();
    }
    let heap_link = if cfg!(all(not(windows), not(target_os = "android"))) {
        "<li><a href=\"/debug/pprof/heap\">Heap profile (pprof)</a></li><li><a href=\"/debug/pprof/allocs\">Allocation profile (pprof)</a></li>"
    } else {
        ""
    };
    let body = format!(
        "<!doctype html><title>yuhaiin Rust profiles</title>\n<ul><li><a href=\"/debug/pprof/profile?seconds=10\">CPU profile (protobuf)</a></li>{heap_link}</ul>\n"
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Return the current sampled mimalloc allocation snapshot in gzipped
/// protobuf pprof format. The route is available in Debug and Release builds
/// on non-Windows targets.
#[cfg(all(not(windows), not(target_os = "android")))]
async fn pprof_heap(State(state): State<ApiState>) -> Response {
    if !state.controller.handle().load().settings.pprof {
        return StatusCode::NOT_FOUND.into_response();
    }
    let body = match pprof_alloc::generate_pprof() {
        Ok(body) => body,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build mimalloc heap profile: {error}"),
            )
                .into_response();
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"yuhaiin-rust-heap.pb.gz\"",
        )
        .body(Body::from(body))
        .unwrap_or_else(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create heap profile response: {error}"),
            )
                .into_response()
        })
}

#[cfg(all(unix, not(target_os = "android")))]
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

#[cfg(any(not(unix), target_os = "android"))]
async fn pprof_profile(
    State(state): State<ApiState>,
    Query(_query): Query<PprofQuery>,
) -> Response {
    if !state.controller.handle().load().settings.pprof {
        StatusCode::NOT_FOUND.into_response()
    } else {
        (
            StatusCode::NOT_IMPLEMENTED,
            "Rust CPU profiling is unavailable on this platform",
        )
            .into_response()
    }
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
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            output.push((high << 4) | low);
            index += 3;
            continue;
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

/// Keep remote route-list caches fresh while the runtime is alive.
///
/// Go stores this value as minutes and arms a timer whenever the route-list
/// contract is created or reloaded.  The Rust service owns the equivalent
/// task so API handlers, embedded hosts and the desktop binary all share the
/// same lifecycle.  A reload wakes the loop and re-reads the setting, while a
/// refresh-generated reload is drained before the next timer is armed to
/// avoid a self-triggered busy loop.
pub(crate) async fn run_route_list_refresh_loop(state: ApiState, shutdown: watch::Receiver<bool>) {
    run_route_list_refresh_loop_inner(state, shutdown, None).await;
}

async fn run_route_list_refresh_loop_inner(
    state: ApiState,
    mut shutdown: watch::Receiver<bool>,
    _test_interval: Option<Duration>,
) {
    let mut reloads = state.controller.subscribe_reload();
    loop {
        let interval = match load_route_list_config_value(&state).await {
            Ok(value) => {
                let interval = route_list_refresh_duration(&value);
                #[cfg(test)]
                let interval = match (interval, _test_interval) {
                    (Some(_), Some(test_interval)) => Some(test_interval),
                    (interval, None) => interval,
                    (None, Some(_)) => None,
                };
                interval
            }
            Err(error) => {
                state
                    .controller
                    .monitor()
                    .logs()
                    .error(format!("load route-list refresh interval: {error}"));
                None
            }
        };

        let Some(interval) = interval else {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                result = reloads.recv() => match result {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            }
            continue;
        };

        let sleep = tokio::time::sleep(interval);
        tokio::pin!(sleep);
        tokio::select! {
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            result = reloads.recv() => match result {
                Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            _ = &mut sleep => {
                if *shutdown.borrow() {
                    return;
                }
                if let Err(error) = route_lists_refresh_value(&state).await {
                    state
                        .controller
                        .monitor()
                        .logs()
                        .error(format!(
                            "scheduled route-list refresh failed: {}",
                            error.message
                        ));
                }
                // A successful refresh publishes a reload event itself. Do
                // not let that event immediately arm another zero-delay
                // iteration; the next refresh is due after the configured
                // interval, just like Go's resetRefreshInterval.
                while reloads.try_recv().is_ok() {}
            }
        }
    }
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
        "backup.config.get" => backup_config_get_value(&state).await,
        "backup.config.put" => backup_config_put_value(&state, body).await,
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
        // Go decodes these endpoints into typed request structs. A missing or
        // null string field therefore becomes the zero value and reaches the
        // store lookup, which returns 404; it is not rejected as a 400 here.
        "node.get" => get_node_value(&state, go_request_string(&body, "id")?).await,
        "node.put" => save_node_value(&state, body, None).await,
        "node.delete" => delete_node_value(&state, required_string(&body, "id")?).await,
        "node.use" => select_node_value(&state, required_string(&body, "id")?).await,
        "node.close" => node_close_value(&state, required_string(&body, "id")?).await,
        "node.latency" => node_latency_value(&state, &body).await,
        "inbounds.config.get" => inbounds_config_get_value(&state).await,
        "inbounds.config.put" => inbounds_config_put_value(&state, body).await,
        "inbounds.get" => inbounds_get_value(&state, &body).await,
        "inbounds.post" => save_inbound_value(&state, body, None).await,
        "inbound.get" => get_inbound_value(&state, go_request_string(&body, "id")?).await,
        "inbound.put" => save_inbound_value(&state, body, None).await,
        "inbound.delete" => delete_inbound_value(&state, required_string(&body, "id")?).await,
        "resolvers.get" => resolvers_get_value(&state, &body).await,
        "resolvers.post" => save_resolver_value(&state, body, None).await,
        "resolver.get" => get_resolver_value(&state, go_request_string(&body, "id")?).await,
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
        "user.get" => user_get_value(&state, go_request_string(&body, "id")?).await,
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
        "route.list.get" => get_route_list_value(&state, go_request_string(&body, "id")?).await,
        "route.list.put" => save_route_list_value(&state, body, None).await,
        "route.list.delete" => delete_route_list_value(&state, required_string(&body, "id")?).await,
        "route.lists.config.get" => route_lists_config_get_value(&state).await,
        "route.lists.config.put" => route_lists_config_put_value(&state, body).await,
        "route.lists.refresh" => route_lists_refresh_value(&state).await,
        "route.lists.activation" => route_lists_activation_value(&state).await,
        "route.rules.get" => route_rules_get_value(&state, &body).await,
        "route.rules.post" => save_route_rule_value(&state, body, None).await,
        "route.rule.get" => {
            get_route_rule_value(
                &state,
                go_request_string(&body, "name")?,
                go_request_number(&body, "index")?,
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

async fn settings_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    write_config_json(&state, "settings", value).await
}

async fn backup_config_get(State(state): State<ApiState>) -> ApiResult {
    backup_config_get_value(&state).await
}

async fn backup_config_put(State(state): State<ApiState>, Json(value): Json<Value>) -> ApiResult {
    backup_config_put_value(&state, value).await
}

async fn backup_config_get_value(state: &ApiState) -> ApiResult {
    json_value(load_backup_config_value(state).await?)
}

async fn load_backup_config_value(state: &ApiState) -> Result<Value, ApiError> {
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

async fn backup_config_put_value(state: &ApiState, value: Value) -> ApiResult {
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

async fn connections_events(State(state): State<ApiState>) -> Response {
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

async fn tools_logs(State(state): State<ApiState>) -> Response {
    tools_logs_v2(State(state)).await
}

async fn tools_logs_v2(State(state): State<ApiState>) -> Response {
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

fn sse_response<T>(sse: Sse<T>) -> Response
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
    route_lists_config_get_value(&state).await
}

async fn route_lists_config_put(
    State(state): State<ApiState>,
    Json(value): Json<Value>,
) -> ApiResult {
    route_lists_config_put_value(&state, value).await
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

struct RouteListRefreshGuard {
    refreshing: Arc<AtomicBool>,
}

impl RouteListRefreshGuard {
    fn acquire(refreshing: &Arc<AtomicBool>) -> std::result::Result<Self, ApiError> {
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

async fn route_lists_activation(State(state): State<ApiState>) -> ApiResult {
    route_lists_activation_value(&state).await
}

async fn route_lists_refresh_value(state: &ApiState) -> ApiResult {
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

async fn route_lists_activation_value(state: &ApiState) -> ApiResult {
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
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_node(&record).await },
        )
        .await?;
    get_node_value(state, id).await
}

async fn delete_node_value(state: &ApiState, id: String) -> ApiResult {
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
        .mutate_and_reload(move |store| async move {
            let selected_fallback = br##"{"id":"direct"}"##.to_vec();
            for key in [
                SELECTED_TCP_NODE_KEY,
                SELECTED_UDP_NODE_KEY,
                LEGACY_SELECTED_NODE_KEY,
            ] {
                let selected = store
                    .get_config(key)
                    .await?
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
                if selected.as_deref() == Some(id.as_str()) {
                    store.put_config(key, &selected_fallback).await?;
                }
            }
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
    let selected_id = id.clone();
    let bytes = serde_json::to_vec(&json!({"id": id}))?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(SELECTED_TCP_NODE_KEY, &bytes).await?;
            store.put_config(SELECTED_UDP_NODE_KEY, &bytes).await?;
            store.put_config(LEGACY_SELECTED_NODE_KEY, &bytes).await?;
            store
                .repository()
                .put_go_selected_node_ids(&selected_id)
                .await
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

async fn delete_inbound_value(state: &ApiState, id: String) -> ApiResult {
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
        // Go's route_settings compatibility table is a single-row table with
        // CHECK (id = 1). Keep the API mutation on that canonical row so a
        // Go snapshot can be edited and later reopened by either runtime.
        id: 1,
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
        .map(|record| Json(route_list_detail_json(record)))
        .ok_or_else(|| ApiError::not_found("route list not found"))
}

async fn save_route_list_value(
    state: &ApiState,
    mut value: Value,
    name: Option<String>,
) -> ApiResult {
    let request_name = name.unwrap_or(required_string(&value, "name")?);
    set_string(&mut value, "name", request_name.clone());
    let name = request_name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad("route list name is empty"));
    }
    let persisted_value = normalize_route_list_value(&value, &name);
    let source = persisted_value
        .get("source")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let record = GoRouteListRecord {
        name: name.clone(),
        list_type: string_or(&persisted_value, "type", "host"),
        source_type: string_or(&source, "type", "local"),
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    let activation = serde_json::to_vec(&pending_route_list_activation())?;
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_list(&record).await?;
            store
                .put_config(ROUTE_LIST_ACTIVATION_KEY, &activation)
                .await
        })
        .await?;
    Ok(Json(returned))
}

async fn delete_route_list_value(state: &ApiState, id: String) -> ApiResult {
    let activation = serde_json::to_vec(&pending_route_list_activation())?;
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            if store.repository().delete_go_route_list(&id).await? {
                store
                    .put_config(ROUTE_LIST_ACTIVATION_KEY, &activation)
                    .await
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
        .map(|record| Json(route_rule_detail_json(record)))
        .ok_or_else(|| ApiError::not_found("route rule not found"))
}

async fn save_route_rule_value(
    state: &ApiState,
    mut value: Value,
    index: Option<usize>,
) -> ApiResult {
    let request_name = required_string(&value, "name")?;
    let name = request_name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad("route rule name is empty"));
    }
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
    set_string(&mut value, "name", request_name);
    let returned = value.clone();
    let mut persisted_value = normalize_route_rule_value(&value, &name);
    let (match_type, pattern) = route_match(&persisted_value);
    if !pattern.is_empty()
        && let Some(object) = persisted_value.as_object_mut()
    {
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
    let record = GoRouteRuleRecord {
        // Go's v2 store uses the public rule name as the compatibility row
        // id.  The URL index is only a legacy routing parameter; making it
        // part of the id creates duplicate rules on every PUT.
        id: name.clone(),
        name: name.clone(),
        priority,
        disabled: bool_or(&persisted_value, "disabled", false),
        action_mode: string_or(&persisted_value, "mode", "direct"),
        match_type,
        tag: match string_or(&persisted_value, "tag", "default").as_str() {
            "" => "default".to_owned(),
            tag => tag.to_owned(),
        },
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            if replace_legacy_id {
                store
                    .repository()
                    .delete_go_route_rule_by_name(&record.name)
                    .await?;
            }
            store.repository().put_go_route_rule(&record).await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
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
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .delete_go_route_rule_by_name(&name)
                .await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
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
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;

    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .change_go_route_rule_priority(&source_name, &target_name, &operate)
                .await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
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
    let selected_rule_name = snapshot.router.selected_rule_name(&context);
    let selected = selected_rule_name.as_deref().and_then(|name| {
        snapshot
            .route_rules
            .iter()
            .find(|record| record.name == name)
            .map(|record| raw_json(&record.data_json, json!({})))
    });
    let tag = context.tag.clone().unwrap_or_else(|| {
        selected
            .as_ref()
            .map(|value| string_or(value, "tag", ""))
            .unwrap_or_default()
    });
    let resolver = selected
        .as_ref()
        .map(|value| string_or(value, "resolver", ""))
        .unwrap_or_default();
    let match_result = context
        .match_history
        .iter()
        .map(|entry| {
            json!({
                "ruleName": entry.rule_name,
                "history": entry
                    .history
                    .iter()
                    .map(|result| {
                        json!({
                            "listName": result.list_name,
                            "matched": result.matched,
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let ips = match &context.destination {
        Endpoint::Ip { addr, .. } => vec![addr.ip().to_string()],
        Endpoint::Domain { host, .. } => {
            let mut resolved = Vec::new();
            if let Ok(resolver) = snapshot.dns_resolver_for_route_mode(decision.mode)
                && let Ok(addresses) = resolver.resolve(host, ResolveStrategy::Default).await
            {
                resolved.extend(addresses.v4.into_iter().map(|address| address.to_string()));
                resolved.extend(addresses.v6.into_iter().map(|address| address.to_string()));
            }
            resolved
        }
    };
    json_value(json!({
        "mode": mode,
        "tag": tag,
        "resolver": resolver,
        "afterAddr": endpoint_authority(&context.destination),
        "lists": context.lists,
        "ips": ips,
        "matchResult": match_result,
    }))
}

fn endpoint_authority(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } if *port == 0 => host.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
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
    if let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Ok((host.to_owned(), port));
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
    let list_bytes = serde_json::to_vec(&json!({"hostIndexRefreshAt": 0}))?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(ROUTE_ACTIVATION_KEY, &bytes).await?;
            store
                .put_config(ROUTE_LIST_ACTIVATION_KEY, &list_bytes)
                .await
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
    let rule_value = state
        .controller
        .store()
        .get_config(ROUTE_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0}));
    let list_value = state
        .controller
        .store()
        .get_config(ROUTE_LIST_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0}));
    let value = json!({
        "hostIndexRefreshAt": effective_activation_at(&list_value, "hostIndexRefreshAt"),
        "ruleApplyAt": effective_activation_at(&rule_value, "ruleApplyAt"),
    });
    json_value(value)
}

fn effective_activation_at(value: &Value, field: &str) -> i64 {
    value
        .get(field)
        .and_then(Value::as_i64)
        .filter(|at| *at > unix_millis())
        .unwrap_or(0)
}

fn pending_route_list_activation() -> Value {
    json!({"hostIndexRefreshAt": unix_millis() + 60_000})
}

fn pending_route_rule_activation() -> Value {
    json!({"hostIndexRefreshAt": 0, "ruleApplyAt": unix_millis() + 60_000})
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
    let repository = state.controller.store().repository();
    let settings = repository.list_go_dns_settings().await?;
    let lists = repository.list_go_dns_fakedns_lists().await?;
    let mut value = settings
        .into_iter()
        .next()
        .map(|record| {
            json!({
                "enabled": record.fakedns_enabled,
                "ipv4Range": record.fakedns_ipv4_range,
                "ipv6Range": record.fakedns_ipv6_range,
                "whitelist": [],
                "skipCheckList": [],
            })
        })
        .unwrap_or_else(default_fakedns);
    let mut whitelist = Vec::new();
    let mut skip_check_list = Vec::new();
    for list in lists {
        match list.kind.as_str() {
            "whitelist" => whitelist.push(Value::String(list.value)),
            "skip_check" => skip_check_list.push(Value::String(list.value)),
            _ => {}
        }
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::internal("fake DNS settings must be an object"))?;
    object.insert("whitelist".to_owned(), Value::Array(whitelist));
    object.insert("skipCheckList".to_owned(), Value::Array(skip_check_list));
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
        .mutate_and_reload_dns(move |store| async move {
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

async fn tag_put_value(state: &ApiState, value: Value) -> ApiResult {
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

async fn tag_delete_value(state: &ApiState, tag: String) -> ApiResult {
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

async fn update_check_value(state: &ApiState, body: &Value) -> ApiResult {
    let channel = string_or(body, "channel", "stable");
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

fn latency_probe_outer_timeout(request: &LatencyRequest, timeout: Duration) -> Duration {
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

async fn run_backup_value(state: &ApiState) -> ApiResult {
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

async fn restore_backup_value(state: &ApiState, value: &Value) -> ApiResult {
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
    // The Go LinkNames decoder leaves Names nil when the request is `{}`;
    // that is the same "refresh all" request as an explicit empty array.
    let names = if value.get("names").is_none() {
        Vec::new()
    } else {
        subscription_names(value, "subscriptions update")?
    };
    if names.is_empty() {
        // Go treats an empty name list as "refresh all".  The Rust refresh
        // worker is intentionally deferred, but an empty store still has the
        // same observable no-op success as the Go implementation.
        return empty();
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
    let items = state
        .controller
        .store()
        .repository()
        .list_go_publishes()
        .await?
        .into_iter()
        .map(decode_publish_record)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Json(json!({"items": items})))
}

async fn publish_put_value(state: &ApiState, value: Value) -> ApiResult {
    let mut publish = parse_publish_contract(&value)?;
    publish.name = publish.name.trim().to_owned();
    if publish.name.is_empty() {
        return Err(ApiError::bad("publish name is empty"));
    }
    let data_json = serde_json::to_vec(&publish)
        .map_err(|error| ApiError::bad(format!("encode publish failed: {error}")))?;
    state
        .controller
        .store()
        .repository()
        .put_go_publish(&GoPublishRecord {
            name: publish.name.clone(),
            updated_at: unix_seconds(),
            data_json,
        })
        .await?;
    empty()
}

async fn publish_delete_value(state: &ApiState, name: String) -> ApiResult {
    let deleted = state
        .controller
        .store()
        .repository()
        .delete_go_publish(&name)
        .await?;
    if !deleted {
        return Err(ApiError::not_found(format!(
            "publish {name:?} was not found"
        )));
    }
    empty()
}

async fn publish_resolve_value(state: &ApiState, value: &Value) -> ApiResult {
    let name = required_string(value, "name")?;
    let publish = state
        .controller
        .store()
        .repository()
        .list_go_publishes()
        .await?
        .into_iter()
        .find(|record| record.name == name)
        .map(decode_publish_contract)
        .transpose()?;
    let Some(publish) = publish else {
        return json_value(json!({"points": Value::Null}));
    };
    let requested_path = string_or(value, "path", "");
    let requested_password = string_or(value, "password", "");
    if publish.path != requested_path || publish.password != requested_password {
        return json_value(json!({"points": Value::Null}));
    }
    let points = publish
        .points
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let nodes = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await?
        .into_iter()
        .filter(|node| points.contains(node.id.as_str()))
        .map(node_json)
        .collect::<Vec<_>>();
    json_value(json!({"points": nodes}))
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PublishContract {
    #[serde(default)]
    name: String,
    #[serde(default)]
    points: Vec<String>,
    #[serde(default)]
    path: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    insecure: bool,
}

fn parse_publish_contract(value: &Value) -> Result<PublishContract, ApiError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ApiError::bad(format!("invalid publish contract: {error}")))
}

fn decode_publish_record(record: GoPublishRecord) -> Result<Value, ApiError> {
    let publish = decode_publish_contract(record)?;
    serde_json::to_value(publish)
        .map_err(|error| ApiError::internal(format!("encode publish response: {error}")))
}

fn decode_publish_contract(record: GoPublishRecord) -> Result<PublishContract, ApiError> {
    let mut publish: PublishContract =
        serde_json::from_slice(&record.data_json).map_err(|error| {
            ApiError::internal(format!("decode publish {:?}: {error}", record.name))
        })?;
    publish.name = publish.name.trim().to_owned();
    if publish.name.is_empty() {
        publish.name = record.name;
    }
    if publish.name.is_empty() {
        return Err(ApiError::internal("stored publish name is empty"));
    }
    Ok(publish)
}

async fn users_get_value(state: &ApiState, input: &Value) -> ApiResult {
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

async fn user_get_value(state: &ApiState, id: String) -> ApiResult {
    let user = state
        .controller
        .store()
        .repository()
        .get_go_user_view(&id)
        .await?;
    json_value(serde_json::to_value(user)?)
}

#[derive(Debug, Deserialize)]
struct GoUserPutRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    usage: String,
    #[serde(default)]
    credential: Option<yuhaiin_store::GoCredential>,
}

async fn user_save_value(state: &ApiState, value: Value, id: Option<String>) -> ApiResult {
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

async fn user_delete_value(state: &ApiState, id: String) -> ApiResult {
    state
        .controller
        .mutate_and_reload_inbounds(move |store| async move {
            store.repository().delete_go_user(&id).await
        })
        .await?;
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

fn default_backup_config() -> Value {
    json!({
        "instanceName": "",
        "s3": {"enabled": false, "accessKey": "", "secretKey": "", "bucket": "", "region": "", "endpointUrl": "", "usePathStyle": false, "storageClass": ""},
        "interval": 0,
        "lastBackupHash": ""
    })
}

fn backup_s3_config(value: &Value) -> Result<S3Config, ApiError> {
    serde_json::from_value(value.get("s3").cloned().unwrap_or_else(|| json!({})))
        .map_err(|error| ApiError::bad(format!("invalid backup S3 configuration: {error}")))
}

async fn backup_s3_client(state: &ApiState, config: S3Config) -> Result<S3Client, ApiError> {
    let selected = yuhaiin_runtime::inbound::selected_proxy_id(&state.controller)
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

fn backup_object_name(value: &Value) -> Result<String, ApiError> {
    let instance = string_or(value, "instanceName", "").trim().to_owned();
    if instance.is_empty() {
        return Err(ApiError::bad(
            "backup instanceName is required for S3 backup",
        ));
    }
    Ok(format!("{instance}-state.db"))
}

fn backup_hash(bytes: &[u8], s3: &S3Config) -> Result<String, ApiError> {
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

async fn persist_backup_config_value(state: &ApiState, value: Value) -> Result<(), ApiError> {
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

fn backup_destination() -> Result<PathBuf, ApiError> {
    let directory = backup_directory()?;
    let unique = OffsetDateTime::now_utc().unix_timestamp_nanos();
    Ok(directory.join(format!("state-{unique}.sqlite")))
}

fn backup_download_destination() -> Result<PathBuf, ApiError> {
    Ok(backup_directory()?.join("remote-state.sqlite"))
}

fn backup_directory() -> Result<PathBuf, ApiError> {
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let directory = root.join("yuhaiin-rust").join("backups");
    std::fs::create_dir_all(&directory)
        .map_err(|error| ApiError::internal(format!("create backup directory: {error}")))?;
    Ok(directory)
}

async fn route_lists_config_get_value(state: &ApiState) -> ApiResult {
    json_value(load_route_list_config_value(state).await?)
}

async fn route_lists_config_put_value(state: &ApiState, value: Value) -> ApiResult {
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
        .mutate_and_reload(move |store| async move {
            store.put_config("route.lists.config", &bytes).await?;
            store.repository().put_go_settings_kv(&settings).await
        })
        .await?;
    Ok(Json(normalized))
}

async fn load_route_list_config_value(
    state: &ApiState,
) -> std::result::Result<Value, yuhaiin_core::Error> {
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

fn route_list_config_from_go_settings(rows: &[GoSettingsKvRecord]) -> Option<Value> {
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

fn route_list_config_settings(
    value: &Value,
) -> std::result::Result<Vec<GoSettingsKvRecord>, yuhaiin_core::Error> {
    let refresh_interval = value
        .get("refreshInterval")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|error| yuhaiin_core::Error::invalid(format!("refreshInterval: {error}")))?;
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
        yuhaiin_core::Error::invalid(format!("encode route refresh config: {error}"))
    })?;
    let geo_json = serde_json::to_string(&json!({
        "download_url": string_or(geo, "downloadUrl", ""),
        "error": string_or(geo, "error", ""),
    }))
    .map_err(|error| yuhaiin_core::Error::invalid(format!("encode MaxMind config: {error}")))?;
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

fn json_u64_string(value: &Value, key: &str) -> String {
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
    if let Some(object) = value.as_object_mut() {
        // `hash` is the legacy node-store key. It is not part of Go's public
        // contract.Node even though old v1 migrations retain it in the raw
        // JSON used by the runtime.
        object.remove("hash");
    }
    strip_go_internal_node_fields(&mut value);
    normalize_go_node_optional_zero_fields(&mut value);
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_string(&mut value, "group", record.group_name);
    set_string(&mut value, "origin", record.origin);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

fn normalize_go_node_optional_zero_fields(value: &mut Value) {
    let Some(chain) = value.get_mut("chain").and_then(Value::as_array_mut) else {
        return;
    };
    for protocol in chain {
        let Some(protocol_object) = protocol.as_object_mut() else {
            continue;
        };
        let Some(kind) = protocol_object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(config) = protocol_object
            .get_mut(&kind)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let optional_fields: &[&str] = match kind.as_str() {
            "direct" => &["network_interface"],
            "simple" | "fixed" => &["port", "alternate_host", "network_interface"],
            "fixedv2" => &["addresses", "udp_happy_eyeballs"],
            "socks5" => &["override_port"],
            "yuubinsya" => &["udp_over_stream", "udp_coalesce"],
            "http2" | "mux" => &["concurrency"],
            "reality" => &["mldsa65_verify", "short_id", "debug"],
            "tls" => &[
                "servernames",
                "ca_cert",
                "insecure_skip_verify",
                "next_protos",
                "ech_config",
            ],
            "wireguard" => &["endpoint", "peers", "mtu", "reserved"],
            "tailscale" => &["debug"],
            "set" => &["nodes", "strategy"],
            "http_mock" => &["data"],
            "cloudflare_warp_masque" => &["local_addresses", "mtu"],
            _ => &[],
        };
        for field in optional_fields {
            if config.get(*field).is_some_and(json_value_is_go_zero) {
                config.remove(*field);
            }
        }
    }
}

fn json_value_is_go_zero(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(value) => !value,
        Value::Number(value) => {
            value.as_i64() == Some(0) || value.as_u64() == Some(0) || value.as_f64() == Some(0.0)
        }
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
    }
}

/// The persisted Go node JSON contains runtime-only `userId` fields for some
/// protocol layers. Go's public `contract.node.Node` does not expose those
/// fields, but the raw JSON must remain intact in SQLite so the runtime can
/// still use it and a later Go process can read it back. Keep this filtering
/// at the HTTP projection boundary rather than mutating the compatibility
/// record or rewriting the stored node.
fn strip_go_internal_node_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("userId");
            for child in object.values_mut() {
                strip_go_internal_node_fields(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_go_internal_node_fields(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn inbound_json(record: GoInboundRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    normalize_go_inbound_public_json(&mut value);
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "name", record.name);
    set_bool(&mut value, "enabled", record.enabled);
    value
}

fn normalize_go_inbound_public_json(value: &mut Value) {
    if let Some(network) = value.get_mut("network").and_then(Value::as_object_mut)
        && let Some(tcp_udp) = network.get_mut("tcp_udp").and_then(Value::as_object_mut)
    {
        // These fields belong to the runtime/network adapter, not Go's
        // public contract.TCPUDPNetwork.
        tcp_udp.remove("control");
        tcp_udp.remove("udp_happy_eyeballs");
    }

    let Some(protocol) = value.get_mut("protocol").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(kind) = protocol
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    let Some(config) = protocol.get_mut(&kind).and_then(Value::as_object_mut) else {
        return;
    };

    for (legacy, public) in [
        ("force_fakeip", "forceFakeIp"),
        ("portal_v6", "portalV6"),
        ("post_up", "postUp"),
        ("post_down", "postDown"),
        ("skip_multicast", "skipMulticast"),
        ("udp_coalesce", "udpCoalesce"),
    ] {
        rename_json_field(config, legacy, public);
    }
    config.remove("platform");

    if kind == "tun" {
        if let Some(route) = config
            .remove("route")
            .and_then(|value| value.as_object().cloned())
        {
            if !config.contains_key("routes") {
                config.insert(
                    "routes".to_owned(),
                    route.get("routes").cloned().unwrap_or_else(|| json!([])),
                );
            }
            if !config.contains_key("excludes") {
                config.insert(
                    "excludes".to_owned(),
                    route.get("excludes").cloned().unwrap_or_else(|| json!([])),
                );
            }
        }
        for (field, default) in [
            ("forceFakeIp", json!(false)),
            ("skipMulticast", json!(false)),
            ("portalV6", json!("")),
            ("routes", json!([])),
            ("excludes", json!([])),
            ("postUp", json!([])),
            ("postDown", json!([])),
        ] {
            config.entry(field.to_owned()).or_insert(default);
        }
    } else if kind == "yuubinsya"
        && config
            .get("udpCoalesce")
            .is_none_or(|value| value.is_null())
    {
        config.insert("udpCoalesce".to_owned(), json!(false));
    }
}

fn rename_json_field(object: &mut serde_json::Map<String, Value>, legacy: &str, public: &str) {
    if object.contains_key(public) {
        object.remove(legacy);
    } else if let Some(value) = object.remove(legacy) {
        object.insert(public.to_owned(), value);
    }
}

fn resolver_json(record: GoResolverRecord) -> Value {
    let mut value = object_or_fallback(&record.data_json, json!({}));
    if let Some(object) = value.as_object_mut() {
        // `tls_servername` is a legacy SQLite column spelling, not part of
        // Go's public resolver contract. The camel-case field is contract
        // data, but `omitzero` removes it (and subnet) when empty.
        object.remove("tls_servername");
        for field in ["subnet", "tlsServerName", "system"] {
            if object.get(field).is_some_and(json_value_is_go_zero) {
                object.remove(field);
            }
        }
    }
    set_string(&mut value, "id", record.id);
    set_string(&mut value, "type", record.resolver_type);
    set_string(&mut value, "host", record.host);
    if value.get("id").and_then(Value::as_str) == Some("bootstrap") {
        set_bool(&mut value, "system", true);
    }
    value
}

fn normalize_route_list_value(value: &Value, name: &str) -> Value {
    let mut normalized = value.clone();
    set_string(&mut normalized, "name", name.trim().to_owned());
    let list_type = string_or(&normalized, "type", "host");
    set_string(
        &mut normalized,
        "type",
        if list_type.trim().is_empty() {
            "host".to_owned()
        } else {
            list_type
        },
    );

    let source_value = normalized
        .get("source")
        .filter(|source| source.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut source = source_value;
    let source_type = string_or(&source, "type", "local");
    let source_type = if source_type.trim().is_empty() {
        "local"
    } else {
        source_type.as_str()
    };
    set_string(&mut source, "type", source_type);
    if let Some(object) = source.as_object_mut() {
        if source_type == "remote" {
            object.remove("local");
            object
                .entry("remote".to_owned())
                .or_insert_with(|| json!({}));
        } else {
            object.insert("type".to_owned(), Value::String("local".to_owned()));
            object.remove("remote");
            object
                .entry("local".to_owned())
                .or_insert_with(|| json!({}));
        }
    }
    if let Some(object) = normalized.as_object_mut() {
        object.insert("source".to_owned(), source);
    }
    normalized
}

fn normalize_route_rule_value(value: &Value, name: &str) -> Value {
    let mut normalized = value.clone();
    set_string(&mut normalized, "name", name.trim().to_owned());
    let mode = string_or(&normalized, "mode", "bypass");
    set_string(
        &mut normalized,
        "mode",
        if mode.trim().is_empty() {
            "bypass".to_owned()
        } else {
            mode
        },
    );
    normalized
}

fn route_list_detail_json(record: GoRouteListRecord) -> Value {
    normalize_route_list_value(
        &raw_json(&record.data_json, json!({"name": record.name})),
        &record.name,
    )
}

fn route_list_record_with_refresh_errors(
    record: &GoRouteListRecord,
    errors: &[String],
) -> Option<GoRouteListRecord> {
    let mut value = serde_json::from_slice::<Value>(&record.data_json).ok()?;
    let source = value.get("source").cloned().unwrap_or_default();
    let source_type = string_or(&source, "type", &record.source_type).to_ascii_lowercase();
    if source_type != "remote" {
        return None;
    }
    value
        .as_object_mut()?
        .insert("errorMsgs".to_owned(), json!(errors));
    Some(GoRouteListRecord {
        data_json: serde_json::to_vec(&value).ok()?,
        ..record.clone()
    })
}

fn route_rule_detail_json(record: GoRouteRuleRecord) -> Value {
    let mut value = normalize_route_rule_value(
        &raw_json(&record.data_json, json!({"name": record.name})),
        &record.name,
    );
    // `match` is an internal compatibility projection used by the Rust
    // route compiler. Go's public RouteRule contract exposes the equivalent
    // expression through `rules` and omits this storage-only field.
    if let Value::Object(object) = &mut value {
        object.remove("match");
    }
    value
}

fn route_list_item_json(record: GoRouteListRecord) -> Value {
    let value = raw_json(
        &record.data_json,
        json!({"name": record.name, "type": record.list_type}),
    );
    let name = string_or(&value, "name", &record.name);
    let source = value.get("source").cloned().unwrap_or_default();
    let source_type = string_or(&source, "type", &record.source_type);
    // The Go list-store contract reports the persisted source metadata here,
    // not the number of entries currently loaded into the runtime trie.  In
    // particular, an empty local list is valid and must not become an error
    // merely because it has no runtime values.
    let source_values = if source_type == "local" {
        source.get("local").and_then(|local| local.get("lists"))
    } else {
        source.get("remote").and_then(|remote| remote.get("urls"))
    };
    let item_count = source_values.and_then(Value::as_array).map_or(0, Vec::len);
    let preview = source_values
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .unwrap_or_default();
    let error_count = value
        .get("errorMsgs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    json!({
        "name": name,
        "type": string_or(&value, "type", &record.list_type),
        "source": source_type,
        "itemCount": item_count,
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
                    && let Some(value) = value.as_str()
                {
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
                if lower == "list"
                    && let Some(value) = value.as_str()
                {
                    return Some(("domain".to_owned(), value.to_owned()));
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

#[cfg(test)]
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

fn tag_matches_query(value: &Value, query: &str) -> bool {
    field_contains(value, "name", query)
        || field_contains(value, "type", query)
        || value
            .get("hash")
            .and_then(Value::as_array)
            .is_some_and(|hashes| {
                hashes
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|hash| hash.to_ascii_lowercase().contains(query))
            })
}

fn required_string(value: &Value, key: &str) -> std::result::Result<String, ApiError> {
    string_or_opt(value, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad(format!("{key} is required")))
}
fn go_request_string(value: &Value, key: &str) -> std::result::Result<String, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ApiError::bad(format!("{key} must be a string"))),
    }
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
fn go_request_number(value: &Value, key: &str) -> std::result::Result<usize, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(|value| value as usize)
            .ok_or_else(|| ApiError::bad(format!("{key} must be a non-negative integer"))),
        Some(_) => Err(ApiError::bad(format!(
            "{key} must be a non-negative integer"
        ))),
    }
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
    // This is the HTTP contract default from Go's SettingsStore.Load. It is
    // deliberately separate from RuntimeSettings::default: the runtime uses
    // conservative operational defaults, while the Go management contract
    // returns zero values for unset scalar settings (except pprof).
    json!({
        "ipv6": false,
        "useDefaultInterface": false,
        "netInterface": "",
        "pprof": true,
        "systemProxy": {"http": false, "socks5": false},
        "logcat": {
            "level": "verbose",
            "save": false,
            "ignoreTimeoutError": false,
            "ignoreDnsError": false
        },
        "advanced": {
            "udpBufferSize": 0,
            "relayBufferSize": 0,
            "udpRingbufferSize": 0,
            "happyEyeballsSemaphore": 0
        },
        "backup": {
            "instanceName": "",
            "interval": 0,
            "lastBackupHash": ""
        }
    })
}

fn canonical_settings_value(value: &Value) -> Value {
    let mut result = default_settings();
    for (path, predicate) in [
        ("/ipv6", Value::is_boolean as fn(&Value) -> bool),
        ("/useDefaultInterface", Value::is_boolean),
        ("/netInterface", Value::is_string),
        ("/pprof", Value::is_boolean),
        ("/systemProxy/http", Value::is_boolean),
        ("/systemProxy/socks5", Value::is_boolean),
        ("/logcat/level", Value::is_string),
        ("/logcat/save", Value::is_boolean),
        ("/logcat/ignoreTimeoutError", Value::is_boolean),
        ("/logcat/ignoreDnsError", Value::is_boolean),
        ("/advanced/udpBufferSize", Value::is_number),
        ("/advanced/relayBufferSize", Value::is_number),
        ("/advanced/udpRingbufferSize", Value::is_number),
        ("/advanced/happyEyeballsSemaphore", Value::is_number),
    ] {
        if let (Some(source), Some(destination)) = (value.pointer(path), result.pointer_mut(path))
            && predicate(source)
        {
            *destination = source.clone();
        }
    }
    result
}

fn settings_value_from_go_kv(values: &[GoSettingsKvRecord]) -> Value {
    let mut result = default_settings();
    for record in values {
        let Ok(value) = serde_json::from_str::<Value>(&record.value_json) else {
            continue;
        };
        let path = match (record.section.as_str(), record.key.as_str()) {
            ("general", "ipv6") => "/ipv6",
            ("general", "use_default_interface") => "/useDefaultInterface",
            ("general", "net_interface") => "/netInterface",
            ("general", "pprof") => "/pprof",
            ("system_proxy", "http") => "/systemProxy/http",
            ("system_proxy", "socks5") => "/systemProxy/socks5",
            ("logcat", "save") => "/logcat/save",
            ("logcat", "ignore_dns_error") => "/logcat/ignoreDnsError",
            ("logcat", "ignore_timeout_error") => "/logcat/ignoreTimeoutError",
            ("advanced", "udp_buffer_size") => "/advanced/udpBufferSize",
            ("advanced", "relay_buffer_size") => "/advanced/relayBufferSize",
            ("advanced", "udp_ringbuffer_size") => "/advanced/udpRingbufferSize",
            ("advanced", "happyeyeballs_semaphore") => "/advanced/happyEyeballsSemaphore",
            ("logcat", "level") => {
                if let Some(destination) = result.pointer_mut("/logcat/level") {
                    *destination = Value::String(log_level_from_json(&value));
                }
                continue;
            }
            _ => continue,
        };
        let accepts = if path == "/netInterface" {
            value.is_string()
        } else if path.starts_with("/advanced/") {
            value.is_number()
        } else {
            value.is_boolean()
        };
        if accepts && let Some(destination) = result.pointer_mut(path) {
            *destination = value;
        }
    }
    result
}

fn settings_kv_from_contract(value: &Value) -> Vec<GoSettingsKvRecord> {
    let entries = [
        ("general", "ipv6", "/ipv6"),
        ("general", "use_default_interface", "/useDefaultInterface"),
        ("general", "net_interface", "/netInterface"),
        ("general", "pprof", "/pprof"),
        ("system_proxy", "http", "/systemProxy/http"),
        ("system_proxy", "socks5", "/systemProxy/socks5"),
        ("logcat", "save", "/logcat/save"),
        ("logcat", "ignore_dns_error", "/logcat/ignoreDnsError"),
        (
            "logcat",
            "ignore_timeout_error",
            "/logcat/ignoreTimeoutError",
        ),
        ("advanced", "udp_buffer_size", "/advanced/udpBufferSize"),
        ("advanced", "relay_buffer_size", "/advanced/relayBufferSize"),
        (
            "advanced",
            "udp_ringbuffer_size",
            "/advanced/udpRingbufferSize",
        ),
        (
            "advanced",
            "happyeyeballs_semaphore",
            "/advanced/happyEyeballsSemaphore",
        ),
    ];
    let mut result = entries
        .into_iter()
        .filter_map(|(section, key, path)| {
            let value = value.pointer(path)?;
            Some(GoSettingsKvRecord {
                section: section.to_owned(),
                key: key.to_owned(),
                value_json: serde_json::to_string(value).ok()?,
            })
        })
        .collect::<Vec<_>>();
    let level = value
        .pointer("/logcat/level")
        .and_then(Value::as_str)
        .map(log_level_code)
        .unwrap_or(0);
    result.push(GoSettingsKvRecord {
        section: "logcat".to_owned(),
        key: "level".to_owned(),
        value_json: level.to_string(),
    });
    result
}

fn log_level_code(level: &str) -> i64 {
    match level {
        "verbose" => 0,
        "debug" => 1,
        "info" => 2,
        "warning" => 3,
        "error" => 4,
        "fatal" => 5,
        _ => 2,
    }
}

fn log_level_from_json(value: &Value) -> String {
    let code = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .unwrap_or(0);
    match code {
        0 => "verbose",
        1 => "debug",
        2 => "info",
        3 => "warning",
        4 => "error",
        5 => "fatal",
        _ => "info",
    }
    .to_owned()
}
fn default_route_list_config() -> Value {
    json!({"refreshInterval":"0","lastRefreshTime":"0","error":"","hostIndexDisk":false,"maxMindDbGeoIp":{"downloadUrl":"","error":""}})
}

/// Go's route-extra contract expresses refresh intervals in minutes. Zero
/// disables the timer; malformed or overflowing legacy values are treated as
/// disabled until the user saves a valid configuration.
fn route_list_refresh_duration(value: &Value) -> Option<Duration> {
    let minutes = match value.get("refreshInterval") {
        Some(Value::String(value)) => value.parse::<u64>().ok(),
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    };
    let minutes = minutes.filter(|minutes| *minutes != 0)?;
    Some(Duration::from_secs(minutes.checked_mul(60)?))
}
fn default_fakedns() -> Value {
    json!({
        "enabled": false,
        "ipv4Range": "10.2.0.1/24",
        "ipv6Range": "fc00::/64",
        "whitelist": [
            "*.msftncsi.com",
            "*.msftconnecttest.com",
            "ping.archlinux.org",
            "mask.icloud.com",
            "mask-h2.icloud.com",
            "mask.apple-dns.net"
        ],
        "skipCheckList": []
    })
}
fn default_tun_config() -> Value {
    json!({"enabled":false,"name":"yuhaiin0","mtu":1500,"queueCapacity":256,"channelCapacity":256,"directId":"","proxyId":"","bypassId":"","dropId":""})
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::net::UdpSocket;
    use tower::ServiceExt;
    use yuhaiin_core::dns::{DnsResponse, encode_response};
    use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
    use yuhaiin_runtime::{RuntimeBuilder, RuntimeController};
    use yuhaiin_store::ConfigStore;

    #[test]
    fn stun_latency_outer_timeout_covers_nat_behavior_requests() {
        let udp = LatencyRequest {
            probe_type: "stun".to_owned(),
            ..LatencyRequest::default()
        };
        assert_eq!(
            latency_probe_outer_timeout(&udp, Duration::from_secs(10)),
            Duration::from_secs(40)
        );

        let tcp = LatencyRequest {
            probe_type: "stun".to_owned(),
            tcp: true,
            ..LatencyRequest::default()
        };
        assert_eq!(
            latency_probe_outer_timeout(&tcp, Duration::from_secs(10)),
            Duration::from_secs(30)
        );

        let http = LatencyRequest {
            probe_type: "http".to_owned(),
            ..LatencyRequest::default()
        };
        assert_eq!(
            latency_probe_outer_timeout(&http, Duration::from_secs(10)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn node_public_json_hides_go_internal_user_ids_without_mutating_unknown_json() {
        let value = node_json(yuhaiin_store::GoNodeRecord {
            id: "node-1".to_owned(),
            name: "Node 1".to_owned(),
            group_name: "group".to_owned(),
            origin: "manual".to_owned(),
            enabled: true,
            chain_types_json: b"[\"yuubinsya\"]".to_vec(),
            updated_at: 0,
            data_json: br#"{
                "hash":"legacy-hash",
                "id":"raw-id",
                "futureField":"preserve-for-compatibility",
                "chain":[
                    {"type":"simple","simple":{"host":"127.0.0.1","port":1080,"alternate_host":[],"network_interface":""}},
                    {"type":"socks5","socks5":{"hostname":"127.0.0.1","user":"","password":"","override_port":0}},
                    {"type":"yuubinsya","yuubinsya":{"userId":"runtime-only"}}
                ]
            }"#
            .to_vec(),
        });
        assert_eq!(value["id"], "node-1");
        assert_eq!(value["name"], "Node 1");
        assert_eq!(value["futureField"], "preserve-for-compatibility");
        assert!(value.get("hash").is_none());
        assert!(value["chain"][0]["simple"].get("alternate_host").is_none());
        assert!(
            value["chain"][0]["simple"]
                .get("network_interface")
                .is_none()
        );
        assert!(value["chain"][1]["socks5"].get("override_port").is_none());
        assert!(value["chain"][2]["yuubinsya"].get("userId").is_none());
    }

    #[test]
    fn resolver_public_json_uses_go_omitzero_shape() {
        let value = resolver_json(yuhaiin_store::GoResolverRecord {
            id: "direct".to_owned(),
            resolver_type: "doh".to_owned(),
            host: "223.5.5.5".to_owned(),
            updated_at: 0,
            data_json: br#"{
                "id":"legacy-id",
                "type":"doh",
                "host":"223.5.5.5",
                "subnet":"",
                "tlsServerName":"",
                "tls_servername":""
            }"#
            .to_vec(),
        });
        assert_eq!(value["id"], "direct");
        assert_eq!(value["type"], "doh");
        assert_eq!(value["host"], "223.5.5.5");
        assert!(value.get("subnet").is_none());
        assert!(value.get("tlsServerName").is_none());
        assert!(value.get("tls_servername").is_none());
    }

    #[test]
    fn settings_contract_uses_go_defaults_and_ignores_backup_payload() {
        let value = canonical_settings_value(&json!({
            "ipv6": true,
            "pprof": false,
            "logcat": {"level": "info"},
            "advanced": {"udpBufferSize": 65536},
            "backup": {"instanceName": "must-not-be-in-settings"},
            "unknown": true,
        }));
        assert_eq!(value["ipv6"], true);
        assert_eq!(value["pprof"], false);
        assert_eq!(value["advanced"]["udpBufferSize"], 65536);
        assert_eq!(value["backup"]["instanceName"], "");
        assert!(value.get("unknown").is_none());

        let rows = settings_kv_from_contract(&value);
        assert!(rows.iter().any(|row| {
            row.section == "advanced" && row.key == "udp_buffer_size" && row.value_json == "65536"
        }));
        assert_eq!(settings_value_from_go_kv(&rows)["logcat"]["level"], "info");
    }

    #[tokio::test]
    async fn settings_and_backup_rpc_round_trip_go_storage_shapes() {
        let app = router(state().await);
        let settings_response = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/settings.put")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"ipv6":true,"advanced":{"udpBufferSize":65536},"backup":{"instanceName":"ignored"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(settings_response.status(), StatusCode::OK);
        let settings: Value = serde_json::from_slice(
            &to_bytes(settings_response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(settings["advanced"]["udpBufferSize"], 65536);
        assert_eq!(settings["backup"]["instanceName"], "");

        let generated = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/backup.config.get")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(generated.status(), StatusCode::OK);
        let generated: Value =
            serde_json::from_slice(&to_bytes(generated.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        let generated_id = generated["instanceName"].as_str().unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(generated_id)
                .unwrap()
                .get_version_num(),
            4
        );

        let second_read = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/backup.config.get")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_read: Value = serde_json::from_slice(
            &to_bytes(second_read.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second_read["instanceName"], generated_id);

        let backup = json!({
            "instanceName":"rust-instance",
            "s3":{"enabled":true,"bucket":"bucket"},
            "interval":3600,
            "lastBackupHash":"hash"
        });
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/backup.config.put")
                    .header("content-type", "application/json")
                    .body(Body::from(backup.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::post("/api/v2/rpc/backup.config.get")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let persisted: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(persisted["instanceName"], "rust-instance");
        assert_eq!(persisted["s3"]["bucket"], "bucket");
    }

    async fn read_s3_test_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let length = stream.read(&mut chunk).await.unwrap();
            assert!(length > 0);
            bytes.extend_from_slice(&chunk[..length]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let mut chunk = [0_u8; 1024];
            let length = stream.read(&mut chunk).await.unwrap();
            assert!(length > 0);
            bytes.extend_from_slice(&chunk[..length]);
        }
        bytes
    }

    #[tokio::test]
    async fn backup_run_rejects_disabled_s3_before_creating_a_snapshot() {
        let error = run_backup_value(&state().await)
            .await
            .expect_err("disabled S3 backup must not report success");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "bad_request");
        assert_eq!(error.message, "backup.run requires enabled S3 backup");
    }

    #[tokio::test]
    async fn backup_run_and_empty_restore_use_the_go_s3_object_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let uploaded = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let uploaded_server = Arc::clone(&uploaded);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_s3_test_request(&mut stream).await;
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let is_put = request.starts_with(b"PUT ");
                let body = if is_put {
                    request[header_end..].to_vec()
                } else {
                    uploaded_server.lock().await.clone()
                };
                if is_put {
                    *uploaded_server.lock().await = body.clone();
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if is_put { 0 } else { body.len() }
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                if !is_put {
                    stream.write_all(&body).await.unwrap();
                }
            }
        });

        let (shutdown, _shutdown_rx) = watch::channel(false);
        let state = state().await.with_shutdown(shutdown);
        let _ = backup_config_put_value(
            &state,
            json!({
                "instanceName":"api-test",
                "s3":{
                    "enabled":true,
                    "accessKey":"access",
                    "secretKey":"secret",
                    "bucket":"bucket",
                    "region":"us-east-1",
                    "endpointUrl":endpoint,
                    "usePathStyle":true,
                    "storageClass":"STANDARD"
                },
                "interval":0,
                "lastBackupHash":""
            }),
        )
        .await
        .unwrap();

        let _ = run_backup_value(&state).await.unwrap();
        let config = load_backup_config_value(&state).await.unwrap();
        assert!(string_or(&config, "lastBackupHash", "").len() == 64);
        assert!(!uploaded.lock().await.is_empty());

        let response = restore_backup_value(&state, &json!({})).await.unwrap();
        assert_eq!(response.0["accepted"], true);
        assert_eq!(response.0["restart"], true);
        server.await.unwrap();
    }

    #[test]
    fn backup_hash_matches_go_blake2b_and_object_name_contract() {
        let s3 = S3Config {
            enabled: true,
            access_key: "a".to_owned(),
            secret_key: "b".to_owned(),
            bucket: "bucket".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint_url: String::new(),
            use_path_style: false,
            storage_class: String::new(),
        };
        assert_eq!(
            backup_hash(b"state", &s3).unwrap(),
            "47a09b4d4dcab1042d455793b5ea98a8cc8a4175ee526ae276b5e63ce2b3dc1d"
        );
        assert_eq!(
            backup_object_name(&json!({"instanceName":"desktop"})).unwrap(),
            "desktop-state.db"
        );
        assert!(backup_object_name(&json!({"instanceName":""})).is_err());
    }

    #[tokio::test]
    async fn health_endpoint_is_public_even_when_management_api_is_authenticated() {
        let app = router(state().await.with_auth("alice", "secret"));
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

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
        let value = json!({"id":"direct","name":"Direct","group":"","enabled":true,"chain":[{"type":"direct","direct":{}}]});
        let saved = save_node_value(&state, value.clone(), None).await.unwrap();
        assert_eq!(saved.0["id"], "direct");
        assert_eq!(saved.0["group"], "");
        assert_eq!(saved.0["origin"], "manual");
        let listed = nodes_get_value(&state, &json!({"page":1,"page_size":0}))
            .await
            .unwrap();
        assert_eq!(listed.0["items"][0]["chain"][0]["type"], "direct");
        assert_eq!(listed.0["items"][0]["origin"], "manual");
        let stored = state
            .controller
            .store()
            .repository()
            .list_go_nodes()
            .await
            .unwrap()
            .into_iter()
            .find(|node| node.id == "direct")
            .unwrap();
        let stored_json: Value = serde_json::from_slice(&stored.data_json).unwrap();
        assert_eq!(stored_json["origin"], "manual");
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
    async fn node_selection_reads_and_updates_go_metadata_strings() {
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
            .repository()
            .put_go_selected_node_ids("tcp-node")
            .await
            .unwrap();
        let selected = selected_nodes_value(&state).await.unwrap();
        assert_eq!(selected.0["tcp"]["id"], "tcp-node");
        assert_eq!(selected.0["udp"]["id"], "tcp-node");

        let _ = select_node_value(&state, "udp-node".to_owned())
            .await
            .unwrap();
        let repository = state.controller.store().repository();
        assert_eq!(
            repository
                .get_go_selected_node_id(SELECTED_TCP_NODE_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("udp-node")
        );
        assert_eq!(
            repository
                .get_go_selected_node_id(SELECTED_UDP_NODE_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("udp-node")
        );
    }

    #[tokio::test]
    async fn direct_node_latency_resolves_domain_before_async_socket_connect() {
        let state = state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte)
                    .await
                    .unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
            tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let _ = save_node_value(
            &state,
            json!({
                "id": "direct-latency",
                "name": "Direct latency",
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();

        let response = node_latency_value(
            &state,
            &json!({
                "id": "direct-latency",
                "type": "tcp",
                "url": format!("http://localhost:{}/health", address.port())
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            response.0["ok"], true,
            "direct latency response: {}",
            response.0
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_node_latency_dns_uses_the_selected_proxy_datagram() {
        let state = state().await;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut query = [0u8; 4096];
            let (length, peer) = server.recv_from(&mut query).await.unwrap();
            let response = encode_response(
                &query[..length],
                &DnsResponse {
                    addresses: yuhaiin_core::IpSet {
                        v4: vec!["192.0.2.77".parse().unwrap()],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
            .unwrap();
            server.send_to(&response, peer).await.unwrap();
        });

        let _ = save_node_value(
            &state,
            json!({
                "id": "direct-dns-latency",
                "name": "Direct DNS latency",
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();

        let response = node_latency_value(
            &state,
            &json!({
                "id": "direct-dns-latency",
                "type": "dns",
                "host": address.to_string(),
                "targetDomain": "example.com"
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            response.0["ok"], true,
            "DNS latency response: {}",
            response.0
        );
        server_task.await.unwrap();
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

    #[cfg(unix)]
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
            .clone()
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

        #[cfg(not(windows))]
        {
            let heap = app
                .clone()
                .oneshot(
                    Request::get("/debug/pprof/heap")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(heap.status(), StatusCode::OK);
            assert_eq!(
                heap.headers()[header::CONTENT_TYPE],
                "application/octet-stream"
            );
            assert!(
                !to_bytes(heap.into_body(), 16 * 1024 * 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

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
        let pending = route_activation_value(&state).await.unwrap();
        assert!(pending.0["ruleApplyAt"].as_i64().unwrap_or_default() > unix_millis());

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

        let tested = router(state.clone())
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
        assert_eq!(value["afterAddr"], "example.com:443");
        let match_result = value["matchResult"].as_array().unwrap();
        let selected = match_result
            .iter()
            .find(|entry| entry["ruleName"] == "drop-example")
            .expect("selected route rule must be present in match history");
        assert!(selected["history"].is_array());

        let _ = route_apply_value(&state).await.unwrap();
        let applied = route_activation_value(&state).await.unwrap();
        assert_eq!(applied.0["hostIndexRefreshAt"], 0);
        assert_eq!(applied.0["ruleApplyAt"], 0);
    }

    #[tokio::test]
    async fn route_activation_expiry_matches_go_timer_lifecycle() {
        let state = state().await;
        state
            .controller
            .store()
            .put_config(
                ROUTE_ACTIVATION_KEY,
                &serde_json::to_vec(&json!({
                    "hostIndexRefreshAt": 0,
                    "ruleApplyAt": unix_millis() - 1,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        state
            .controller
            .store()
            .put_config(
                ROUTE_LIST_ACTIVATION_KEY,
                &serde_json::to_vec(&json!({
                    "hostIndexRefreshAt": unix_millis() - 1,
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let expired_rules = route_activation_value(&state).await.unwrap();
        assert_eq!(expired_rules.0["hostIndexRefreshAt"], 0);
        assert_eq!(expired_rules.0["ruleApplyAt"], 0);
        let expired_lists = route_lists_activation_value(&state).await.unwrap();
        assert_eq!(expired_lists.0["hostIndexRefreshAt"], 0);

        state
            .controller
            .store()
            .put_config(
                ROUTE_ACTIVATION_KEY,
                &serde_json::to_vec(&pending_route_rule_activation()).unwrap(),
            )
            .await
            .unwrap();
        let pending = route_activation_value(&state).await.unwrap();
        assert!(pending.0["ruleApplyAt"].as_i64().unwrap() > unix_millis());
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
        assert_eq!(browser_rules[0]["index"], 2);

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
        let list_pending = route_lists_activation_value(&state).await.unwrap();
        assert!(
            list_pending.0["hostIndexRefreshAt"]
                .as_i64()
                .unwrap_or_default()
                > unix_millis()
        );
        let combined_pending = route_activation_value(&state).await.unwrap();
        assert!(
            combined_pending.0["hostIndexRefreshAt"]
                .as_i64()
                .unwrap_or_default()
                > unix_millis()
        );
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
    async fn route_list_refresh_downloads_remote_content_and_reloads_runtime_snapshot() {
        let state = state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/rules.txt");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
                .await
                .unwrap();
            let body = b"remote.example\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, body)
                .await
                .unwrap();
        });

        let list_name = format!("remote-http-{}", std::process::id());
        let _ = save_route_list_value(
            &state,
            json!({
                "name":list_name,
                "type":"host",
                "source":{"type":"remote","remote":{"urls":[url]}}
            }),
            None,
        )
        .await
        .unwrap();
        let _ = route_lists_refresh_value(&state).await.unwrap();
        server.await.unwrap();
        let report = route_lists_activation_value(&state).await.unwrap();
        assert_eq!(report.0["refreshed"], 1);
        assert_eq!(report.0["errors"], json!({}));

        let snapshot = state.controller.handle().load();
        assert_eq!(
            snapshot.route_lists.values(&list_name).unwrap(),
            &["remote.example".to_owned()][..]
        );
        let detail = get_route_list_value(&state, list_name.clone())
            .await
            .unwrap();
        assert_eq!(detail.0["errorMsgs"], json!([]));

        let cache_path = yuhaiin_runtime::route_list_cache_path(&url);
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn route_list_refresh_interval_matches_go_minutes_and_zero_disables() {
        assert_eq!(
            route_list_refresh_duration(&json!({"refreshInterval":"3600"})),
            Some(Duration::from_secs(3600 * 60))
        );
        assert_eq!(
            route_list_refresh_duration(&json!({"refreshInterval":0})),
            None
        );
        assert_eq!(
            route_list_refresh_duration(&json!({"refreshInterval":"not-a-number"})),
            None
        );
    }

    #[test]
    fn route_list_refresh_guard_matches_go_single_flight_error_and_release() {
        let refreshing = Arc::new(AtomicBool::new(false));
        let guard = RouteListRefreshGuard::acquire(&refreshing).unwrap();
        let error = match RouteListRefreshGuard::acquire(&refreshing) {
            Ok(_) => panic!("a second route-list refresh must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "internal_error");
        assert_eq!(error.message, "refreshing");
        drop(guard);
        assert!(RouteListRefreshGuard::acquire(&refreshing).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scheduled_route_list_refresh_reloads_and_stops_with_service() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let state = state().await;
                let _ = route_lists_config_put_value(
                    &state,
                    json!({
                        "refreshInterval":"1",
                        "hostIndexDisk":false,
                        "maxMindDbGeoIp":{"downloadUrl":""}
                    }),
                )
                .await
                .unwrap();
                let (shutdown, receiver) = watch::channel(false);
                let task = tokio::task::spawn_local(run_route_list_refresh_loop_inner(
                    state.clone(),
                    receiver,
                    Some(Duration::from_millis(1)),
                ));

                tokio::time::sleep(Duration::from_millis(20)).await;
                let config = state
                    .controller
                    .store()
                    .get_config("route.lists.config")
                    .await
                    .unwrap()
                    .map(|bytes| raw_json(&bytes, Value::Null))
                    .unwrap();
                let last_refresh_time = config["lastRefreshTime"]
                    .as_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();
                let now = unix_seconds();
                assert!(last_refresh_time >= now.saturating_sub(2));
                assert!(last_refresh_time <= now.saturating_add(2));

                shutdown.send(true).unwrap();
                task.await.unwrap();
            })
            .await;
    }

    #[tokio::test]
    async fn route_detail_gets_return_go_store_normalized_contracts() {
        let state = state().await;
        let _ = save_route_list_value(&state, json!({"name":"normalized-list", "source":{}}), None)
            .await
            .unwrap();
        let list = get_route_list_value(&state, "normalized-list".to_owned())
            .await
            .unwrap();
        assert_eq!(list.0["name"], "normalized-list");
        assert_eq!(list.0["type"], "host");
        assert_eq!(list.0["source"]["type"], "local");
        assert!(list.0["source"]["local"].is_object());
        assert!(list.0["source"].get("remote").is_none());

        let _ = save_route_rule_value(
            &state,
            json!({
                "name":"normalized-rule",
                "mode":"",
                "match":{"domain":"normalized.example"}
            }),
            None,
        )
        .await
        .unwrap();
        let rule = get_route_rule_value(&state, "normalized-rule".to_owned(), 999)
            .await
            .unwrap();
        assert_eq!(rule.0["name"], "normalized-rule");
        assert_eq!(rule.0["mode"], "bypass");
        assert!(rule.0.get("match").is_none());
    }

    #[test]
    fn route_list_refresh_errors_are_persisted_only_for_remote_lists() {
        let remote = GoRouteListRecord {
            name: "remote".to_owned(),
            list_type: "host".to_owned(),
            source_type: "remote".to_owned(),
            updated_at: 7,
            data_json: serde_json::to_vec(&json!({
                "name":"remote",
                "type":"host",
                "source":{"type":"remote","remote":{"urls":["https://rules.example/list"]}},
                "errorMsgs":["stale"]
            }))
            .unwrap(),
        };
        let local = GoRouteListRecord {
            name: "local".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 8,
            data_json: serde_json::to_vec(&json!({
                "name":"local",
                "type":"host",
                "source":{"type":"local","local":{"lists":["local.example"]}}
            }))
            .unwrap(),
        };

        let updated = route_list_record_with_refresh_errors(
            &remote,
            &["https://rules.example/list: timeout".to_owned()],
        )
        .unwrap();
        assert_eq!(updated.name, remote.name);
        assert_eq!(updated.updated_at, remote.updated_at);
        assert_eq!(
            raw_json(&updated.data_json, Value::Null)["errorMsgs"][0],
            "https://rules.example/list: timeout"
        );
        assert!(route_list_record_with_refresh_errors(&local, &[]).is_none());
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
        let _ = route_lists_config_put_value(
            &state,
            json!({
                "refreshInterval":"0",
                "lastRefreshTime":"0",
                "error":"",
                "hostIndexDisk":true,
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

        let activation = route_lists_activation_value(&state).await.unwrap();
        assert!(
            activation.0["hostIndexRefreshAt"]
                .as_i64()
                .unwrap_or_default()
                > unix_millis()
        );

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
    async fn route_list_config_matches_go_canonical_settings_and_contract() {
        let state = state().await;
        let canonical = route_list_config_from_go_settings(&[
            GoSettingsKvRecord {
                section: "route_extra".to_owned(),
                key: "refresh_config".to_owned(),
                value_json: r#"{"refresh_interval":3600,"last_refresh_time":42,"error":"old","host_index_disk":true}"#.to_owned(),
            },
            GoSettingsKvRecord {
                section: "route_extra".to_owned(),
                key: "maxminddb_geoip".to_owned(),
                value_json: r#"{"download_url":"https://geo.example/Country.mmdb","error":""}"#.to_owned(),
            },
        ])
        .unwrap();
        assert_eq!(canonical["refreshInterval"], "3600");
        assert_eq!(canonical["lastRefreshTime"], "42");
        assert_eq!(canonical["hostIndexDisk"], true);
        assert_eq!(
            canonical["maxMindDbGeoIp"]["downloadUrl"],
            "https://geo.example/Country.mmdb"
        );

        state
            .controller
            .store()
            .repository()
            .put_go_settings_kv(&[
                GoSettingsKvRecord {
                    section: "route_extra".to_owned(),
                    key: "refresh_config".to_owned(),
                    value_json: r#"{"refresh_interval":3600,"last_refresh_time":42,"error":"old","host_index_disk":false}"#.to_owned(),
                },
                GoSettingsKvRecord {
                    section: "route_extra".to_owned(),
                    key: "maxminddb_geoip".to_owned(),
                    value_json: r#"{"download_url":"https://geo.example/Country.mmdb","error":"geo-old"}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

        let saved = route_lists_config_put_value(
            &state,
            json!({
                "refreshInterval":"7200",
                "lastRefreshTime":"not-a-number",
                "error":"",
                "hostIndexDisk":true,
                "maxMindDbGeoIp":{"downloadUrl":"https://geo.example/Country.mmdb","error":""},
                "unknown":"discarded"
            }),
        )
        .await
        .unwrap();
        assert_eq!(saved.0["refreshInterval"], "7200");
        assert_eq!(saved.0["lastRefreshTime"], "42");
        assert_eq!(saved.0["error"], "");
        assert_eq!(saved.0["maxMindDbGeoIp"]["error"], "geo-old");
        assert!(saved.0.get("unknown").is_none());
        assert_eq!(
            route_lists_config_get_value(&state).await.unwrap().0,
            saved.0
        );

        let changed_url = route_lists_config_put_value(
            &state,
            json!({
                "refreshInterval":"7200",
                "hostIndexDisk":true,
                "maxMindDbGeoIp":{"downloadUrl":"https://geo.example/new.mmdb","error":"client-error-is-discarded"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(changed_url.0["lastRefreshTime"], "42");
        assert_eq!(changed_url.0["maxMindDbGeoIp"]["error"], "");
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

        let refresh_all = app
            .clone()
            .oneshot(
                Request::post("/api/v2/subscriptions/update")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refresh_all.status(), StatusCode::OK);

        let refresh_named = app
            .clone()
            .oneshot(
                Request::post("/api/v2/subscriptions/update")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"names":["prod"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refresh_named.status(), StatusCode::SERVICE_UNAVAILABLE);

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
    async fn publishes_read_native_go_rows_and_preserve_resolve_semantics() {
        let state = state().await;
        state
            .controller
            .store()
            .repository()
            .put_go_publish(&GoPublishRecord {
                name: "public".to_owned(),
                updated_at: 1,
                data_json: br#"{"points":[],"path":"feed","password":"secret"}"#.to_vec(),
            })
            .await
            .unwrap();
        let app = router(state);

        let list = app
            .clone()
            .oneshot(
                Request::get("/api/v2/publishes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let list: Value =
            serde_json::from_slice(&to_bytes(list.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(list["items"][0]["name"], "public");
        assert_eq!(list["items"][0]["points"], json!([]));

        let resolved = app
            .clone()
            .oneshot(
                Request::post("/api/v2/publishes/public/resolve")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"path":"feed","password":"secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.status(), StatusCode::OK);
        let resolved: Value =
            serde_json::from_slice(&to_bytes(resolved.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(resolved["points"], json!([]));

        let mismatch = app
            .clone()
            .oneshot(
                Request::post("/api/v2/publishes/public/resolve")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"path":"wrong","password":"secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::OK);
        let mismatch: Value =
            serde_json::from_slice(&to_bytes(mismatch.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert!(mismatch["points"].is_null());
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
            (
                "/api/v2/route/lists/config",
                r#"{"refreshInterval":"3600"}"#,
            ),
            (
                "/api/v2/route/tags/mobile",
                r#"{"type":"node","hash":"abc"}"#,
            ),
            ("/api/v2/publishes/public", r#"{"points":["direct"]}"#),
            (
                "/api/v2/users",
                r#"{"name":"Alice","enabled":true,"usage":"outbound","credential":{"type":"token","token":{"token":"secret"}}}"#,
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
    async fn route_tags_use_go_node_tags_contract_and_filter_fields() {
        let state = state().await;

        let response = tag_put_value(&state, json!({"tag":" mobile ","type":"","hash":"abc"}))
            .await
            .unwrap();
        assert_eq!(response.0, json!({}));

        let listed = tags_get_value(&state, &json!({"page":1,"page_size":20}))
            .await
            .unwrap();
        assert_eq!(listed.0["items"][0]["name"], "mobile");
        assert_eq!(listed.0["items"][0]["type"], "node");
        assert_eq!(listed.0["items"][0]["hash"], json!(["abc"]));
        assert_eq!(listed.0["page"]["total"], 1);

        let filtered = tags_get_value(&state, &json!({"query":"abc"}))
            .await
            .unwrap();
        assert_eq!(filtered.0["page"]["total"], 1);
        let unmatched = tags_get_value(&state, &json!({"query":"mirror"}))
            .await
            .unwrap();
        assert_eq!(unmatched.0["page"]["total"], 0);

        let _ = tag_delete_value(&state, "mobile".to_owned()).await.unwrap();
        let empty = tags_get_value(&state, &json!({})).await.unwrap();
        assert_eq!(empty.0["page"]["total"], 0);
        assert!(tag_delete_value(&state, "mobile".to_owned()).await.is_err());
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
        let records = state
            .controller
            .store()
            .repository()
            .list_go_route_settings()
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 1);
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
                yuhaiin_core::ErrorKind::Conflict,
                StatusCode::CONFLICT,
                "user_referenced",
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

    #[test]
    fn go_typed_request_zero_values_preserve_missing_fields_but_reject_wrong_types() {
        assert_eq!(go_request_string(&json!({}), "id").unwrap(), "");
        assert_eq!(go_request_string(&json!({"id": null}), "id").unwrap(), "");
        assert_eq!(
            go_request_string(&json!({"id": "node-1"}), "id").unwrap(),
            "node-1"
        );
        assert!(go_request_string(&json!({"id": 1}), "id").is_err());

        assert_eq!(go_request_number(&json!({}), "index").unwrap(), 0);
        assert_eq!(
            go_request_number(&json!({"index": null}), "index").unwrap(),
            0
        );
        assert_eq!(go_request_number(&json!({"index": 3}), "index").unwrap(), 3);
        assert!(go_request_number(&json!({"index": -1}), "index").is_err());
        assert!(go_request_number(&json!({"index": "0"}), "index").is_err());
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
    async fn every_generated_frontend_rpc_operation_has_a_route() {
        // Keep this inventory synchronized with yuhaiin-react/src/api/generated.ts.
        // The generated operation inventory also contains connections.events;
        // its useful transport is GET/SSE, but the JSON-RPC route must still
        // remain registered so the frontend operation set has one boundary.
        const OPERATIONS: &[&str] = &[
            "backup.config.get",
            "backup.config.put",
            "backup.restore",
            "backup.run",
            "connections",
            "connections.close",
            "connections.events",
            "connections.failed_history",
            "connections.history",
            "connections.telemetry",
            "connections.total",
            "connections.traffic",
            "inbound.delete",
            "inbound.get",
            "inbound.put",
            "inbounds.config.get",
            "inbounds.config.put",
            "inbounds.get",
            "inbounds.post",
            "info",
            "node.close",
            "node.delete",
            "node.get",
            "node.latency",
            "node.put",
            "node.use",
            "nodes.active",
            "nodes.get",
            "nodes.post",
            "nodes.selected",
            "publish.delete",
            "publish.put",
            "publish.resolve",
            "publishes",
            "resolver.delete",
            "resolver.fakedns.get",
            "resolver.fakedns.put",
            "resolver.get",
            "resolver.hosts.get",
            "resolver.hosts.put",
            "resolver.put",
            "resolver.server.get",
            "resolver.server.put",
            "resolvers.get",
            "resolvers.post",
            "route.activation",
            "route.apply",
            "route.config.get",
            "route.config.put",
            "route.list.delete",
            "route.list.get",
            "route.list.put",
            "route.lists.activation",
            "route.lists.config.get",
            "route.lists.config.put",
            "route.lists.get",
            "route.lists.post",
            "route.lists.refresh",
            "route.rule.delete",
            "route.rule.get",
            "route.rule.put",
            "route.rules.block_history",
            "route.rules.get",
            "route.rules.post",
            "route.rules.priority",
            "route.rules.test",
            "route.tag.delete",
            "route.tag.put",
            "route.tags.get",
            "settings.get",
            "settings.put",
            "subscriptions.delete",
            "subscriptions.delete_preview",
            "subscriptions.get",
            "subscriptions.put",
            "subscriptions.update",
            "tools.interfaces",
            "tools.licenses",
            "tools.logs",
            "tools.logs.v2",
            "update.apply",
            "update.check",
            "update.status",
            "user.delete",
            "user.get",
            "user.put",
            "users.get",
            "users.post",
        ];
        assert_eq!(OPERATIONS.len(), 88);

        let app = router(state().await);
        for operation in OPERATIONS {
            if *operation == "connections.events" {
                let response = app
                    .clone()
                    .oneshot(
                        Request::get("/api/v2/connections/events")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "generated frontend streaming operation {operation} is not routed",
                );
                continue;
            }
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v2/rpc/{operation}"))
                        .header("content-type", "application/json")
                        // Use a non-object probe so registered handlers
                        // stop at the shared request-shape check with
                        // 400. `{}` would legitimately reach 404 for Go
                        // typed detail requests whose zero-value ID is
                        // not present in the store.
                        .body(Body::from("[]"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "generated frontend operation {operation} is not routed",
            );
        }

        for (path, expected_content_type) in [
            ("/api/v2/connections/events", "text/event-stream"),
            ("/api/v2/tools/logs", "text/event-stream"),
            ("/api/v2/tools/logs/v2", "text/event-stream"),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "SSE route {path}");
            assert_eq!(response.headers()["content-type"], expected_content_type);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
            assert_eq!(response.headers()[header::CONNECTION], "keep-alive");
        }
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

    #[tokio::test]
    async fn connections_event_stream_starts_with_go_snapshot_event() {
        let app = router(state().await);
        let response = app
            .oneshot(
                Request::get("/api/v2/connections/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");

        let mut body = response.into_body();
        let first = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let first = String::from_utf8_lossy(&first);
        assert!(first.contains("event: connections_added"));
        assert!(first.contains(r#""connections":[]"#));
    }

    #[tokio::test]
    async fn connections_event_stream_delivers_live_add_and_remove_events() {
        let state = state().await;
        let monitor = state.controller.monitor();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/api/v2/connections/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let first = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(String::from_utf8_lossy(&first).contains("event: connections_added"));

        let flow = yuhaiin_core::flow::Flow {
            key: yuhaiin_core::flow::FlowKey {
                network: Network::Tcp,
                source: "127.0.0.1:41000".parse().unwrap(),
                destination: "127.0.0.1:443".parse().unwrap(),
            },
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.key.destination));
        yuhaiin_core::flow::FlowObserver::opened(monitor.as_ref(), flow, context);
        let added = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let added = String::from_utf8_lossy(&added);
        assert!(added.contains("event: connections_added"));
        assert!(added.contains(r#""id":"1""#));

        yuhaiin_core::flow::FlowObserver::closed(monitor.as_ref(), flow.key);
        let removed = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let removed = String::from_utf8_lossy(&removed);
        assert!(removed.contains("event: connections_removed"));
        assert!(removed.contains(r#""ids":["1"]"#));
    }
}
