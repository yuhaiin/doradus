//! Runtime-owned connection and traffic monitor.
//!
//! The monitor is intentionally independent from SQLite. Active flows are
//! process state, while totals and time buckets are cheap in-memory counters;
//! the existing store remains responsible for configuration and durable
//! migration state. All callbacks are synchronous so packet processing never
//! waits for an HTTP/SSE consumer.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex as AsyncMutex, broadcast, watch};

use doradus_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver,
};
use doradus_core::{BoxFuture, Endpoint, FlowContext, RouteMode};
use doradus_metrics::{FailureStage, RuntimeMetrics};
use doradus_store::{
    ConfigStore, GoConnectionHistoryRecord, GoFailedHistoryRecord, GoStatisticsDelta,
    GoStatisticsSnapshot, GoTelemetryBucketRecord, GoTrafficBucketRecord, InboundStatisticsRecord,
    TELEMETRY_DAILY_BUCKET_SECONDS, TELEMETRY_HOURLY_BUCKET_SECONDS,
};

use crate::RuntimeLog;

#[path = "monitor_persistence.rs"]
mod monitor_persistence;
#[path = "monitor_projection.rs"]
mod monitor_projection;
#[path = "monitor_runtime.rs"]
mod monitor_runtime;
#[path = "monitor_statistics.rs"]
mod monitor_statistics;
use monitor_projection::{
    connection_value, merge_connection_metadata, normalize_persisted_telemetry_value,
    telemetry_dimensions, traffic_bucket_start,
};
#[cfg(test)]
use monitor_projection::{normalize_telemetry_source, telemetry_destination};
use monitor_statistics::*;

const HISTORY_LIMIT: usize = 2048;
const GO_HISTORY_SIZE: usize = 1000;
const BUCKET_LIMIT: usize = 90 * 24 * 60;
const PERSISTENCE_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
const PERSISTENCE_KEY: &str = "statistics.runtime";
const PERSISTENCE_VERSION: u32 = 1;
// Go stores the history key's protocol in a separate SQLite column, while
// the public history JSON may only contain the network metadata. Keep the
// exact storage value across a Rust checkpoint without changing that JSON.
const INTERNAL_GO_PROTOCOL_KEY: &str = "__doradus_go_protocol";
// The Go API always returns this complete, stable dimension list. Empty
// groups are part of the public response contract even though new telemetry
// entries are only recorded for non-empty dimensions.
const GO_TELEMETRY_DIMENSIONS: [&str; 9] = [
    "protocol",
    "inbound",
    "source",
    "addr",
    "outbound",
    "process",
    "rule",
    "tag",
    "destination",
];

fn default_telemetry_bucket_span_seconds() -> i64 {
    TELEMETRY_HOURLY_BUCKET_SECONDS
}

fn normalize_telemetry_bucket_span_seconds(span_seconds: i64) -> i64 {
    if span_seconds <= 0 {
        TELEMETRY_HOURLY_BUCKET_SECONDS
    } else {
        span_seconds
    }
}

/// Socket inbound tasks are spawned on Tokio's multithread executor. This
/// runtime-local boundary deliberately requires a Send future while the core
/// TUN API keeps its more permissive LocalBoxFuture contract.
pub(crate) trait SocketDnsHandler: Send + Sync {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, doradus_core::Result<Vec<u8>>>;
}

#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub kind: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
struct ConnectionEntry {
    id: String,
    value: Value,
    telemetry: Arc<[(String, String)]>,
    upload: u64,
    download: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct InboundStatistics {
    pub active_tcp: u64,
    pub active_udp: u64,
    pub total_tcp_flows: u64,
    pub total_udp_flows: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl InboundStatistics {
    fn record(&self, inbound_id: String) -> InboundStatisticsRecord {
        InboundStatisticsRecord {
            inbound_id,
            active_tcp: self.active_tcp,
            active_udp: self.active_udp,
            total_tcp_flows: self.total_tcp_flows,
            total_udp_flows: self.total_udp_flows,
            upload_bytes: self.upload_bytes,
            download_bytes: self.download_bytes,
            updated_at: unix_seconds(),
        }
    }
}

type TelemetryBucketKey = (i64, i64, String, String);
type TelemetryBucketValue = (u64, u64, u64);

struct PersistenceState {
    store: ConfigStore,
    dirty: AtomicBool,
    shutdown: watch::Sender<bool>,
    worker: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct MonitorState {
    next_id: u64,
    total_upload: u64,
    total_download: u64,
    connections: HashMap<TunFlowKey, ConnectionEntry>,
    ids: HashMap<String, TunFlowKey>,
    counters: BTreeMap<String, (u64, u64)>,
    inbound_statistics: BTreeMap<String, InboundStatistics>,
    buckets: BTreeMap<i64, (u64, u64)>,
    telemetry: BTreeMap<(String, String), (u64, u64, u64)>,
    telemetry_buckets: BTreeMap<TelemetryBucketKey, TelemetryBucketValue>,
    history: Vec<Value>,
    failed_history: BTreeMap<(String, String, String), FailedEntry>,
    block_history: BTreeMap<(String, String, String), BlockEntry>,
    // These are short-lived observations waiting for the SQLite writer. The
    // durable history/traffic/telemetry tables are queried on demand when a
    // persistent monitor serves an API request, matching Go's memory boundary.
    pending_traffic: BTreeMap<i64, (u64, u64)>,
    pending_telemetry: BTreeMap<TelemetryBucketKey, TelemetryBucketValue>,
    pending_history: Vec<GoConnectionHistoryRecord>,
    pending_failed_history: BTreeMap<(String, String, String), GoFailedHistoryRecord>,
    close_requests: Vec<TunFlowKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FailedEntry {
    protocol: String,
    host: String,
    process: String,
    error: String,
    time: i64,
    count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockEntry {
    protocol: String,
    host: String,
    process: String,
    time: i64,
    count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTelemetry {
    dimension: String,
    value: String,
    download: u64,
    upload: u64,
    failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTelemetryBucket {
    bucket: i64,
    #[serde(default = "default_telemetry_bucket_span_seconds")]
    span_seconds: i64,
    dimension: String,
    value: String,
    download: u64,
    upload: u64,
    failures: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedMonitor {
    version: u32,
    next_id: u64,
    total_upload: u64,
    total_download: u64,
    counters: BTreeMap<String, (u64, u64)>,
    buckets: BTreeMap<i64, (u64, u64)>,
    telemetry: Vec<PersistedTelemetry>,
    #[serde(default)]
    telemetry_buckets: Vec<PersistedTelemetryBucket>,
    history: Vec<Value>,
    failed_history: Vec<FailedEntry>,
    #[serde(default)]
    block_history: Vec<BlockEntry>,
}

#[derive(Clone)]
pub struct ConnectionMonitor {
    state: Arc<Mutex<MonitorState>>,
    sniff_enabled: Arc<AtomicBool>,
    dns_handler: Arc<RwLock<Option<Arc<dyn SocketDnsHandler>>>>,
    events: broadcast::Sender<MonitorEvent>,
    close_events: broadcast::Sender<TunFlowKey>,
    logs: RuntimeLog,
    persistence: Option<Arc<PersistenceState>>,
    metrics: Arc<RuntimeMetrics>,
}

impl Default for ConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TunFlowObserver for ConnectionMonitor {
    fn opened(&self, flow: TunFlow, context: FlowContext) {
        self.open(flow, context);
    }

    fn bytes(&self, flow: TunFlowKey, direction: TunFlowDirection, bytes: usize) {
        let tun = self
            .lock()
            .connections
            .get(&flow)
            .and_then(|entry| entry.value.get("component"))
            .and_then(Value::as_str)
            == Some("tun");
        if tun {
            let direction = match direction {
                TunFlowDirection::Upload => doradus_metrics::Direction::Upload,
                TunFlowDirection::Download => doradus_metrics::Direction::Download,
            };
            self.metrics.tun_packet(direction);
            match flow.network {
                doradus_core::Network::Tcp => {
                    self.metrics
                        .add_packet(direction, doradus_metrics::MetricNetwork::Tcp);
                }
                doradus_core::Network::Udp => {
                    self.metrics
                        .add_packet(direction, doradus_metrics::MetricNetwork::Udp);
                }
                doradus_core::Network::Icmp | doradus_core::Network::Any => {}
            }
        }
        self.add_bytes(flow, direction, bytes);
    }

    fn closed(&self, flow: TunFlowKey) {
        self.close(flow);
    }

    fn failed(&self, flow: TunFlowKey, stage: &str, error: &str) {
        self.metrics.connection_failed(failure_stage(stage));
        let metadata = self.lock().connections.get(&flow).map(|entry| {
            (
                entry.value["nodeId"].as_str().unwrap_or("-").to_owned(),
                entry.value["protocol"].as_str().unwrap_or("-").to_owned(),
                entry.value["inbound"].as_str().unwrap_or("-").to_owned(),
            )
        });
        let (node, protocol, inbound) =
            metadata.unwrap_or_else(|| ("-".to_owned(), "-".to_owned(), "-".to_owned()));
        self.error(format!(
            "TUN flow failed stage={stage} src={} dst={} node={node} protocol={protocol} inbound={inbound} error={error}",
            flow.source, flow.destination,
        ));
    }

    fn close_requested(&self, flow: TunFlowKey) -> bool {
        self.close_requested(flow)
    }
}

fn failure_stage(value: &str) -> FailureStage {
    match value.trim().to_ascii_lowercase().as_str() {
        "listener" => FailureStage::Listener,
        "dns" | "resolve" | "resolver" => FailureStage::Dns,
        "route" => FailureStage::Route,
        "dial" | "connect" => FailureStage::Dial,
        "handshake" | "auth" => FailureStage::Handshake,
        "stream" | "relay" => FailureStage::Stream,
        _ => FailureStage::Other,
    }
}

#[cfg(test)]
#[path = "monitor_tests.rs"]
mod tests;
