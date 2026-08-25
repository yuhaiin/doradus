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
use axum::middleware::Next;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
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
#[path = "routes.rs"]
mod routes;

pub fn router(state: ApiState) -> Router {
    routes::build(state)
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

#[path = "rpc_dispatch.rs"]
mod rpc_dispatch;

async fn rpc(
    State(state): State<ApiState>,
    Path(operation): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    rpc_dispatch::dispatch(State(state), Path(operation), Json(body)).await
}

#[path = "operations.rs"]
mod operations;
use operations::*;
#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
