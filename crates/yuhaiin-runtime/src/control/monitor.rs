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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex as AsyncMutex, broadcast, watch};

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver,
};
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, RouteMode};
use yuhaiin_store::{
    ConfigStore, GoConnectionHistoryRecord, GoFailedHistoryRecord, GoStatisticsDelta,
    GoStatisticsSnapshot, GoTelemetryBucketRecord, GoTrafficBucketRecord,
    TELEMETRY_DAILY_BUCKET_SECONDS, TELEMETRY_HOURLY_BUCKET_SECONDS,
};

use crate::RuntimeLog;

const HISTORY_LIMIT: usize = 2048;
const GO_HISTORY_SIZE: usize = 1000;
const BUCKET_LIMIT: usize = 90 * 24 * 60;
const PERSISTENCE_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
const PERSISTENCE_KEY: &str = "statistics.runtime";
const PERSISTENCE_VERSION: u32 = 1;
// Go stores the history key's protocol in a separate SQLite column, while
// the public history JSON may only contain the network metadata. Keep the
// exact storage value across a Rust checkpoint without changing that JSON.
const INTERNAL_GO_PROTOCOL_KEY: &str = "__yuhaiin_go_protocol";
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
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, yuhaiin_core::Result<Vec<u8>>>;
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
}

impl Default for ConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMonitor {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        let (close_events, _) = broadcast::channel(256);
        Self {
            state: Arc::new(Mutex::new(MonitorState::default())),
            sniff_enabled: Arc::new(AtomicBool::new(true)),
            dns_handler: Arc::new(RwLock::new(None)),
            events,
            close_events,
            logs: RuntimeLog::new(),
            persistence: None,
        }
    }

    /// Whether generic stream relays should spend a bounded read waiting for
    /// TLS/HTTP metadata. Explicit protocol handlers may still attach their
    /// own metadata; this switch controls only the common inbound path.
    pub fn sniff_enabled(&self) -> bool {
        self.sniff_enabled.load(Ordering::Acquire)
    }

    pub fn set_sniff_enabled(&self, enabled: bool) {
        self.sniff_enabled.store(enabled, Ordering::Release);
    }

    /// Install the current inbound DNS handler for socket and TUN adapters.
    /// The handler is swapped atomically with the published runtime snapshot;
    /// in-flight packets keep the cloned handler they already started with.
    pub(crate) fn set_dns_handler(&self, handler: Option<Arc<dyn SocketDnsHandler>>) {
        *self
            .dns_handler
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handler;
    }

    pub(crate) fn dns_hijack_enabled(&self) -> bool {
        self.dns_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    pub(crate) async fn answer_dns(&self, packet: &[u8]) -> Option<yuhaiin_core::Result<Vec<u8>>> {
        let handler = self
            .dns_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()?;
        let target = yuhaiin_core::dns::decode_query(packet)
            .map(|query| format!("{} {:?}", query.domain, query.record_type))
            .unwrap_or_else(|_| format!("packet_len={}", packet.len()));
        let result = handler.answer(packet).await;
        if let Err(error) = &result {
            self.error(format!("DNS query failed target={target}: {error}"));
        }
        Some(result)
    }

    /// Load only the live totals from SQLite. Historical rows remain in the
    /// store and are read on demand, like Go's statistics package. The old
    /// `statistics.runtime` blob is imported once for upgrade compatibility
    /// and then removed.
    pub async fn load_with_store(store: ConfigStore) -> yuhaiin_core::Result<Self> {
        let monitor = Self::new();
        if let Some(bytes) = store.get_config(PERSISTENCE_KEY).await? {
            let persisted: PersistedMonitor = serde_json::from_slice(&bytes).map_err(|error| {
                yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::Storage,
                    format!("statistics state is invalid JSON: {error}"),
                )
            })?;
            if persisted.version != PERSISTENCE_VERSION {
                return Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::Storage,
                    format!("unsupported statistics state version {}", persisted.version),
                ));
            }
            let existing = store.load_go_statistics()?;
            let migrated = merge_statistics_snapshots(existing, persisted_snapshot(&persisted)?);
            store.replace_go_statistics(&migrated)?;
            monitor.restore_persisted_runtime(persisted);
            store.delete_config(PERSISTENCE_KEY).await?;
        } else {
            let (total_download, total_upload) = store.load_go_totals()?;
            let mut state = monitor.lock();
            state.total_download = total_download;
            state.total_upload = total_upload;
        }

        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let persistence = Arc::new(PersistenceState {
            store,
            dirty: AtomicBool::new(false),
            shutdown,
            worker: AsyncMutex::new(None),
        });
        let mut persistent = monitor.clone();
        persistent.persistence = Some(persistence.clone());
        let writer_monitor = persistent.clone();
        let worker_persistence = persistence.clone();
        let worker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(PERSISTENCE_CHECKPOINT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {},
                }
                if !worker_persistence.dirty.swap(false, Ordering::AcqRel) {
                    continue;
                }
                let delta = writer_monitor.take_statistics_delta();
                let store = worker_persistence.store.clone();
                let write_delta = delta.clone();
                let result = match tokio::task::spawn_blocking(move || {
                    store.try_apply_go_statistics_delta(&write_delta)
                })
                .await
                {
                    Ok(result) => result,
                    Err(error) => Err(yuhaiin_core::Error::new(
                        yuhaiin_core::ErrorKind::Storage,
                        format!("statistics persistence task: {error}"),
                    )),
                };
                if result.is_err() {
                    writer_monitor.merge_statistics_delta(delta);
                    worker_persistence.dirty.store(true, Ordering::Release);
                }
            }
        });
        *persistence.worker.lock().await = Some(worker);
        Ok(persistent)
    }

    /// Flush the current counters/history and stop the owned persistence task.
    ///
    /// The runtime calls this after inbound/DNS owners have stopped and before
    /// a backup restore can replace the database. This closes the low-traffic
    /// window where the old periodic-only writer could lose the final flow.
    pub async fn shutdown(&self) -> yuhaiin_core::Result<()> {
        let Some(persistence) = self.persistence.clone() else {
            return Ok(());
        };
        let worker = persistence.worker.lock().await.take();
        let _ = persistence.shutdown.send(true);
        let worker_error = if let Some(worker) = worker {
            worker.await.err().map(|error| {
                yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::Storage,
                    format!("statistics persistence task: {error}"),
                )
            })
        } else {
            None
        };
        self.persist_now().await?;
        if let Some(error) = worker_error {
            return Err(error);
        }
        Ok(())
    }

    async fn persist_now(&self) -> yuhaiin_core::Result<()> {
        let Some(persistence) = self.persistence.clone() else {
            return Ok(());
        };
        let delta = self.take_statistics_delta();
        let store = persistence.store.clone();
        let write_delta = delta.clone();
        let result = match tokio::task::spawn_blocking(move || {
            store.try_apply_go_statistics_delta(&write_delta)
        })
        .await
        {
            Ok(result) => result,
            Err(error) => {
                self.merge_statistics_delta(delta);
                return Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::Storage,
                    format!("statistics persistence task: {error}"),
                ));
            }
        };
        if let Err(error) = result {
            self.merge_statistics_delta(delta);
            return Err(error);
        }
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
    }

    pub fn logs(&self) -> RuntimeLog {
        self.logs.clone()
    }

    pub fn info(&self, message: impl AsRef<str>) {
        self.logs.info(message);
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        self.logs.warn(message);
    }

    pub fn error(&self, message: impl AsRef<str>) {
        self.logs.error(message);
    }

    pub fn connections_value(&self) -> Value {
        let state = self.lock();
        let mut values = state
            .connections
            .values()
            .map(|entry| entry.value.clone())
            .collect::<Vec<_>>();
        values.sort_by_key(|value| {
            value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        });
        json!({"connections": values})
    }

    pub fn total_flow_value(&self) -> Value {
        let state = self.lock();
        let counters = state
            .counters
            .iter()
            .map(|(id, (download, upload))| {
                (
                    id.clone(),
                    json!({
                        "download": download.to_string(),
                        "upload": upload.to_string(),
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        json!({
            "download": state.total_download.to_string(),
            "upload": state.total_upload.to_string(),
            "counters": counters,
        })
    }

    pub fn traffic_value(&self, interval: &str, from: Option<&str>, to: Option<&str>) -> Value {
        let now = unix_seconds();
        let end = parse_time(to).unwrap_or(now);
        let start = parse_time(from).unwrap_or(end.saturating_sub(86_400));
        self.traffic_value_range(interval, start, end)
    }

    pub fn traffic_value_range(&self, interval: &str, start: i64, end: i64) -> Value {
        let interval = match interval {
            "day" => "day",
            "month" => "month",
            _ => "hour",
        };
        let start = start.min(end);
        let end = end.max(start);
        let mut buckets = BTreeMap::<i64, (u64, u64)>::new();
        if let Some(snapshot) = self.durable_snapshot() {
            for item in snapshot.traffic {
                if item.bucket < start || item.bucket >= end {
                    continue;
                }
                let group = traffic_bucket_start(interval, item.bucket);
                let entry = buckets.entry(group).or_default();
                entry.0 = entry.0.saturating_add(item.download);
                entry.1 = entry.1.saturating_add(item.upload);
            }
        } else {
            let state = self.lock();
            for (bucket, (download, upload)) in &state.buckets {
                if *bucket < start || *bucket >= end {
                    continue;
                }
                let group = traffic_bucket_start(interval, *bucket);
                let entry = buckets.entry(group).or_default();
                entry.0 = entry.0.saturating_add(*download);
                entry.1 = entry.1.saturating_add(*upload);
            }
        }
        let items = buckets
            .into_iter()
            .take(10_000)
            .map(|(bucket, (download, upload))| {
                json!({
                "start": format_time_utc(bucket),
                "download": download.to_string(),
                "upload": upload.to_string(),
                })
            })
            .collect::<Vec<_>>();
        json!({"interval": interval, "items": items})
    }

    pub fn telemetry_value(&self) -> Value {
        self.telemetry_value_range(0, i64::MAX, usize::MAX)
    }

    pub fn telemetry_value_range(&self, from: i64, to: i64, limit: usize) -> Value {
        let mut dimensions: BTreeMap<String, BTreeMap<String, (u64, u64, u64)>> = BTreeMap::new();
        let telemetry = if let Some(snapshot) = self.durable_snapshot() {
            snapshot.telemetry
        } else {
            let state = self.lock();
            state
                .telemetry_buckets
                .iter()
                .map(
                    |((bucket, span_seconds, dimension, value), (download, upload, failures))| {
                        GoTelemetryBucketRecord {
                            bucket: *bucket,
                            span_seconds: *span_seconds,
                            dimension: dimension.clone(),
                            value: value.clone(),
                            download: *download,
                            upload: *upload,
                            failures: *failures,
                        }
                    },
                )
                .collect()
        };
        for item in telemetry {
            let span_seconds = normalize_telemetry_bucket_span_seconds(item.span_seconds);
            let in_range = if span_seconds == TELEMETRY_DAILY_BUCKET_SECONDS {
                let bucket_end = item.bucket.saturating_add(span_seconds);
                item.bucket < to && bucket_end > from
            } else {
                item.bucket >= from && item.bucket < to
            };
            if !in_range {
                continue;
            }
            let entry = dimensions
                .entry(item.dimension)
                .or_default()
                .entry(item.value)
                .or_default();
            entry.0 = entry.0.saturating_add(item.download);
            entry.1 = entry.1.saturating_add(item.upload);
            entry.2 = entry.2.saturating_add(item.failures);
        }
        let telemetry_group = |dimension: String, items: BTreeMap<String, (u64, u64, u64)>| {
            let mut items = items.into_iter().collect::<Vec<_>>();
            items.sort_by(|(left_value, left), (right_value, right)| {
                right
                    .0
                    .saturating_add(right.1)
                    .cmp(&left.0.saturating_add(left.1))
                    .then_with(|| right.2.cmp(&left.2))
                    .then_with(|| left_value.cmp(right_value))
            });
            items.truncate(limit);
            json!({
                "dimension": dimension,
                "items": items.into_iter().map(|(value, (download, upload, failures))| json!({
                    "value": value,
                    "download": download.to_string(),
                    "upload": upload.to_string(),
                    "failures": failures.to_string(),
                })).collect::<Vec<_>>(),
            })
        };
        let mut groups = GO_TELEMETRY_DIMENSIONS
            .into_iter()
            .map(|dimension| {
                telemetry_group(
                    dimension.to_owned(),
                    dimensions.remove(dimension).unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        // Preserve forward compatibility if a newer persisted store contains
        // a dimension unknown to this version. Known Go dimensions retain
        // their canonical order above.
        groups.extend(
            dimensions
                .into_iter()
                .map(|(dimension, items)| telemetry_group(dimension, items)),
        );
        json!({"groups": groups})
    }

    pub fn failed_history_value(&self) -> Value {
        let (mut items, dump_process_enabled) = if let Some(snapshot) = self.durable_snapshot() {
            let items = snapshot
                .failed_history
                .into_iter()
                .map(|entry| {
                    json!({
                        "protocol": entry.protocol,
                        "host": entry.host,
                        "error": entry.error,
                        "process": entry.process,
                        "time": format_time(entry.last_seen),
                        "failedCount": entry.count.to_string(),
                    })
                })
                .collect::<Vec<_>>();
            let dump = items.iter().any(|item| {
                item.get("process")
                    .and_then(Value::as_str)
                    .is_some_and(|process| !process.is_empty())
            });
            (items, dump)
        } else {
            let state = self.lock();
            let items = state
                .failed_history
                .values()
                .map(|entry| {
                    json!({
                        "protocol": entry.protocol,
                        "host": entry.host,
                        "error": entry.error,
                        "process": entry.process,
                        "time": format_time(entry.time),
                        "failedCount": entry.count.to_string(),
                    })
                })
                .collect::<Vec<_>>();
            let dump = state
                .failed_history
                .values()
                .any(|entry| !entry.process.is_empty());
            (items, dump)
        };
        items.sort_by(|left, right| {
            right
                .get("time")
                .and_then(Value::as_str)
                .cmp(&left.get("time").and_then(Value::as_str))
        });
        items.truncate(GO_HISTORY_SIZE);
        json!({
            "items": items,
            "dumpProcessEnabled": dump_process_enabled,
        })
    }

    pub fn all_history_value(&self) -> Value {
        let (mut items, dump_process_enabled) = if let Some(snapshot) = self.durable_snapshot() {
            let items = snapshot
                .history
                .into_iter()
                .filter_map(history_record_value)
                .collect::<Vec<_>>();
            let dump = items.iter().any(|item| {
                item.get("connection")
                    .and_then(|connection| connection.get("process"))
                    .and_then(Value::as_str)
                    .is_some_and(|process| !process.is_empty())
            });
            (coalesce_history(items), dump)
        } else {
            let state = self.lock();
            let items = coalesce_history(state.history.clone());
            let dump = items.iter().any(|item| {
                item.get("connection")
                    .and_then(|connection| connection.get("process"))
                    .and_then(Value::as_str)
                    .is_some_and(|process| !process.is_empty())
            });
            (items, dump)
        };
        items.sort_by(|left, right| {
            history_time(right)
                .cmp(&history_time(left))
                .then_with(|| history_key(left).cmp(&history_key(right)))
        });
        items.truncate(GO_HISTORY_SIZE);
        let public_items = items.iter().map(public_history_item).collect::<Vec<_>>();
        json!({
            "items": public_items,
            "dumpProcessEnabled": dump_process_enabled,
        })
    }

    pub fn block_history_value(&self) -> Value {
        let state = self.lock();
        let mut items = state
            .block_history
            .values()
            .map(|entry| {
                json!({
                    "protocol": entry.protocol,
                    "host": entry.host,
                    "process": entry.process,
                    "time": format_time(entry.time),
                    "blockCount": entry.count.to_string(),
                })
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .get("time")
                .and_then(Value::as_str)
                .cmp(&left.get("time").and_then(Value::as_str))
        });
        json!({
            "items": items,
            "dumpProcessEnabled": state.block_history.values().any(|entry| !entry.process.is_empty()),
        })
    }

    pub fn initial_event(&self) -> MonitorEvent {
        MonitorEvent {
            kind: "connections_added".to_owned(),
            payload: self.connections_value(),
        }
    }

    /// Subscribe before taking the active snapshot so an SSE reconnect cannot
    /// miss a connection opened during the initial HTTP response.
    pub fn initial_event_and_subscribe(&self) -> (MonitorEvent, broadcast::Receiver<MonitorEvent>) {
        let state = self.lock();
        let receiver = self.events.subscribe();
        let mut values = state
            .connections
            .values()
            .map(|entry| entry.value.clone())
            .collect::<Vec<_>>();
        values.sort_by_key(|value| {
            value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        });
        (
            MonitorEvent {
                kind: "connections_added".to_owned(),
                payload: json!({"connections": values}),
            },
            receiver,
        )
    }

    pub fn request_close(&self, ids: &[String]) -> usize {
        let mut state = self.lock();
        let mut requested = Vec::new();
        let mut count = 0;
        for id in ids {
            let Some(flow) = state.ids.get(id).copied() else {
                continue;
            };
            if !state.close_requests.contains(&flow) {
                state.close_requests.push(flow);
                requested.push(flow);
                count += 1;
            }
        }
        drop(state);
        for flow in requested {
            let _ = self.close_events.send(flow);
        }
        count
    }

    pub(crate) fn subscribe_close_requests(&self) -> broadcast::Receiver<TunFlowKey> {
        self.close_events.subscribe()
    }

    /// Wait until the management API requests this flow to close.
    ///
    /// The subscription is created before checking the state so a request
    /// cannot be lost between the state check and the first await. The state
    /// check also covers a request that arrived before this relay subscribed.
    pub(crate) async fn wait_for_close(&self, flow: TunFlowKey) {
        let mut events = self.subscribe_close_requests();
        loop {
            if self.close_requested(flow) {
                return;
            }
            match events.recv().await {
                Ok(requested) if requested == flow => return,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    }

    pub fn record_failure(&self, protocol: &str, host: &str, error: &str) {
        self.record_failure_with_process(protocol, host, error, None);
    }

    /// Record a failed dial with the same process dimension as Go's
    /// `failed_connection_history` table.  The short compatibility wrapper
    /// above is kept for failures that happen before an inbound context has
    /// been built (for example malformed protocol input).
    pub fn record_failure_with_process(
        &self,
        protocol: &str,
        host: &str,
        error: &str,
        process: Option<&str>,
    ) {
        self.error(format!(
            "outbound connection failed protocol={protocol} target={host} process={} error={error}",
            process.unwrap_or("-")
        ));
        let persistent = self.persistence.is_some();
        let mut state = self.lock();
        let process = process.unwrap_or_default().to_owned();
        let last_seen = unix_seconds();
        let key = (protocol.to_owned(), host.to_owned(), process.clone());
        let bucket = last_seen.div_euclid(3_600) * 3_600;
        if persistent {
            let entry =
                state
                    .pending_failed_history
                    .entry(key)
                    .or_insert_with(|| GoFailedHistoryRecord {
                        protocol: protocol.to_owned(),
                        host: host.to_owned(),
                        process: process.clone(),
                        error: error.to_owned(),
                        last_seen,
                        count: 0,
                    });
            entry.count = entry.count.saturating_add(1);
            entry.error = error.to_owned();
            entry.last_seen = last_seen;
        } else {
            let entry = state
                .failed_history
                .entry(key)
                .or_insert_with(|| FailedEntry {
                    protocol: protocol.to_owned(),
                    host: host.to_owned(),
                    process: process.clone(),
                    error: error.to_owned(),
                    time: last_seen,
                    count: 0,
                });
            entry.count = entry.count.saturating_add(1);
            entry.error = error.to_owned();
            entry.time = last_seen;
        }
        let connection = json!({
            "network": {"connType": protocol},
            "addr": host,
            "destination": host,
            "process": process,
        });
        for (dimension, value) in telemetry_dimensions(&connection) {
            if persistent {
                let item = state
                    .pending_telemetry
                    .entry((bucket, TELEMETRY_HOURLY_BUCKET_SECONDS, dimension, value))
                    .or_default();
                item.2 = item.2.saturating_add(1);
            } else {
                let item = state
                    .telemetry
                    .entry((dimension.clone(), value.clone()))
                    .or_default();
                item.2 = item.2.saturating_add(1);
                let key = (bucket, TELEMETRY_HOURLY_BUCKET_SECONDS, dimension, value);
                let item = state.telemetry_buckets.entry(key).or_default();
                item.2 = item.2.saturating_add(1);
            }
        }
        drop(state);
        self.mark_dirty();
    }

    pub fn take_close_requests(&self) -> Vec<TunFlowKey> {
        std::mem::take(&mut self.lock().close_requests)
    }

    pub fn close_requested(&self, flow: TunFlowKey) -> bool {
        self.lock().close_requests.contains(&flow)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MonitorState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn durable_snapshot(&self) -> Option<GoStatisticsSnapshot> {
        let store = self.persistence.as_ref()?.store.clone();
        let mut snapshot = store.load_go_statistics().ok()?;
        let delta = {
            let state = self.lock();
            pending_delta_from_state(&state)
        };
        apply_delta_to_snapshot(&mut snapshot, delta);
        Some(snapshot)
    }

    fn emit(&self, kind: &str, payload: Value) {
        let _ = self.events.send(MonitorEvent {
            kind: kind.to_owned(),
            payload,
        });
    }

    fn open(&self, flow: TunFlow, context: FlowContext) {
        let mut state = self.lock();
        if let Some(entry) = state.connections.get_mut(&flow.key) {
            let update = connection_value(&entry.id, flow, &context);
            let changed = merge_connection_metadata(&mut entry.value, update);
            if changed {
                entry.telemetry = Arc::from(telemetry_dimensions(&entry.value));
            }
            let value = entry.value.clone();
            drop(state);
            if changed {
                self.mark_dirty();
                // The React contract keys connections by id, so reusing the
                // existing `connections_added` event updates metadata in
                // place while remaining compatible with Go's two-event SSE
                // surface (`connections_added`/`connections_removed`).
                self.emit("connections_added", json!({"connections": [value]}));
            }
            return;
        }
        state.next_id = state.next_id.saturating_add(1);
        let id = state.next_id.to_string();
        let value = connection_value(&id, flow, &context);
        let telemetry = Arc::from(telemetry_dimensions(&value));
        state.ids.insert(id.clone(), flow.key);
        state.counters.entry(id.clone()).or_default();
        state.connections.insert(
            flow.key,
            ConnectionEntry {
                id,
                value: value.clone(),
                telemetry,
                upload: 0,
                download: 0,
            },
        );
        drop(state);
        self.mark_dirty();
        self.emit("connections_added", json!({"connections": [value]}));
    }

    fn add_bytes(&self, flow: TunFlowKey, direction: TunFlowDirection, bytes: usize) {
        let persistent = self.persistence.is_some();
        let mut state = self.lock();
        let bytes = bytes as u64;
        match direction {
            TunFlowDirection::Upload => {
                state.total_upload = state.total_upload.saturating_add(bytes)
            }
            TunFlowDirection::Download => {
                state.total_download = state.total_download.saturating_add(bytes)
            }
        }
        let now = unix_seconds();
        let bucket =
            now.div_euclid(TELEMETRY_HOURLY_BUCKET_SECONDS) * TELEMETRY_HOURLY_BUCKET_SECONDS;
        if persistent {
            let item = state.pending_traffic.entry(bucket).or_default();
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
        } else {
            let item = state.buckets.entry(now.div_euclid(60) * 60).or_default();
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
            while state.buckets.len() > BUCKET_LIMIT {
                let Some(first) = state.buckets.first_key_value().map(|(key, _)| *key) else {
                    break;
                };
                state.buckets.remove(&first);
            }
        }
        let Some(id) = state.connections.get(&flow).map(|entry| entry.id.clone()) else {
            drop(state);
            self.mark_dirty();
            return;
        };
        let telemetry = {
            let Some(entry) = state.connections.get_mut(&flow) else {
                drop(state);
                self.mark_dirty();
                return;
            };
            match direction {
                TunFlowDirection::Upload => {
                    entry.upload = entry.upload.saturating_add(bytes);
                }
                TunFlowDirection::Download => {
                    entry.download = entry.download.saturating_add(bytes);
                }
            }
            Arc::clone(&entry.telemetry)
        };
        let counter = state.counters.entry(id).or_default();
        match direction {
            TunFlowDirection::Upload => counter.1 = counter.1.saturating_add(bytes),
            TunFlowDirection::Download => counter.0 = counter.0.saturating_add(bytes),
        }
        for (dimension, value) in telemetry.iter() {
            let item = if persistent {
                state
                    .pending_telemetry
                    .entry((
                        bucket,
                        TELEMETRY_HOURLY_BUCKET_SECONDS,
                        dimension.clone(),
                        value.clone(),
                    ))
                    .or_default()
            } else {
                let item = state
                    .telemetry
                    .entry((dimension.clone(), value.clone()))
                    .or_default();
                match direction {
                    TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                    TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
                }
                state
                    .telemetry_buckets
                    .entry((
                        bucket,
                        TELEMETRY_HOURLY_BUCKET_SECONDS,
                        dimension.clone(),
                        value.clone(),
                    ))
                    .or_default()
            };
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
        }
        if !persistent {
            let telemetry_cutoff = now.saturating_sub(90 * 86_400);
            while state
                .telemetry_buckets
                .first_key_value()
                .is_some_and(|((bucket, _, _, _), _)| *bucket < telemetry_cutoff)
            {
                let Some(key) = state
                    .telemetry_buckets
                    .first_key_value()
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                state.telemetry_buckets.remove(&key);
            }
        }
        drop(state);
        self.mark_dirty();
    }

    fn close(&self, flow: TunFlowKey) {
        let persistent = self.persistence.is_some();
        let mut state = self.lock();
        let Some(entry) = state.connections.remove(&flow) else {
            return;
        };
        // Go's `connections.total.counters` is a live-flow view.  The
        // per-connection counter is removed together with the connection;
        // durable totals and history are maintained separately below.
        state.counters.remove(&entry.id);
        if entry.value.get("mode").and_then(Value::as_str) == Some("block") {
            let protocol = entry
                .value
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let host = entry
                .value
                .get("domain")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .or_else(|| entry.value.get("addr").and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned();
            let process = entry
                .value
                .get("process")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let key = (protocol.clone(), host.clone(), process.clone());
            {
                let blocked = state.block_history.entry(key).or_insert(BlockEntry {
                    protocol,
                    host,
                    process,
                    time: unix_seconds(),
                    count: 0,
                });
                blocked.time = unix_seconds();
                blocked.count = blocked.count.saturating_add(1);
            }
            while state.block_history.len() > GO_HISTORY_SIZE {
                let Some(key) = state
                    .block_history
                    .iter()
                    .min_by_key(|(_, entry)| entry.time)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                state.block_history.remove(&key);
            }
        }
        state.ids.remove(&entry.id);
        state.close_requests.retain(|pending| *pending != flow);
        let now = unix_seconds();
        if persistent {
            if let Some(record) = connection_history_record(&entry.value, now) {
                merge_pending_history(&mut state.pending_history, record);
            }
        } else {
            let key = connection_history_key(&entry.value);
            if let Some(existing) = state
                .history
                .iter_mut()
                .find(|item| history_key(item) == key)
            {
                let count = history_count(existing).saturating_add(1);
                existing["connection"] = entry.value;
                existing["count"] = Value::String(count.to_string());
                existing["time"] = Value::String(format_time(now));
            } else {
                state.history.push(json!({
                    "connection": entry.value,
                    "count": "1",
                    "time": format_time(now),
                }));
            }
            if state.history.len() > HISTORY_LIMIT {
                state.history.sort_by_key(history_time);
                let excess = state.history.len() - HISTORY_LIMIT;
                state.history.drain(..excess);
            }
        }
        let id = entry.id;
        drop(state);
        self.mark_dirty();
        self.emit("connections_removed", json!({"ids": [id]}));
    }

    fn mark_dirty(&self) {
        if let Some(persistence) = self.persistence.as_ref() {
            persistence.dirty.store(true, Ordering::Release);
        }
    }

    fn take_statistics_delta(&self) -> GoStatisticsDelta {
        let mut state = self.lock();
        GoStatisticsDelta {
            total_download: state.total_download,
            total_upload: state.total_upload,
            traffic: std::mem::take(&mut state.pending_traffic)
                .into_iter()
                .map(|(bucket, (download, upload))| GoTrafficBucketRecord {
                    bucket,
                    upload,
                    download,
                })
                .collect(),
            history: std::mem::take(&mut state.pending_history),
            failed_history: std::mem::take(&mut state.pending_failed_history)
                .into_values()
                .collect(),
            telemetry: std::mem::take(&mut state.pending_telemetry)
                .into_iter()
                .map(
                    |((bucket, span_seconds, dimension, value), (download, upload, failures))| {
                        GoTelemetryBucketRecord {
                            bucket,
                            span_seconds,
                            dimension,
                            value,
                            download,
                            upload,
                            failures,
                        }
                    },
                )
                .collect(),
        }
    }

    fn merge_statistics_delta(&self, delta: GoStatisticsDelta) {
        let mut state = self.lock();
        for traffic in delta.traffic {
            let item = state.pending_traffic.entry(traffic.bucket).or_default();
            item.0 = item.0.saturating_add(traffic.download);
            item.1 = item.1.saturating_add(traffic.upload);
        }
        for history in delta.history {
            merge_pending_history(&mut state.pending_history, history);
        }
        for failure in delta.failed_history {
            let key = (
                failure.protocol.clone(),
                failure.host.clone(),
                failure.process.clone(),
            );
            let item =
                state
                    .pending_failed_history
                    .entry(key)
                    .or_insert_with(|| GoFailedHistoryRecord {
                        protocol: failure.protocol.clone(),
                        host: failure.host.clone(),
                        process: failure.process.clone(),
                        ..GoFailedHistoryRecord::default()
                    });
            item.count = item.count.saturating_add(failure.count);
            if failure.last_seen >= item.last_seen {
                item.last_seen = failure.last_seen;
                item.error = failure.error;
            }
        }
        for telemetry in delta.telemetry {
            let item = state
                .pending_telemetry
                .entry((
                    telemetry.bucket,
                    telemetry.span_seconds,
                    telemetry.dimension,
                    telemetry.value,
                ))
                .or_default();
            item.0 = item.0.saturating_add(telemetry.download);
            item.1 = item.1.saturating_add(telemetry.upload);
            item.2 = item.2.saturating_add(telemetry.failures);
        }
    }

    fn restore_persisted_runtime(&self, persisted: PersistedMonitor) {
        let mut state = self.lock();
        state.next_id = persisted.next_id;
        state.total_upload = persisted.total_upload;
        state.total_download = persisted.total_download;
        // Active sockets and historical tables are intentionally not restored
        // into the monitor. The latter now live in SQLite, as in Go.
        state.counters.clear();
        state.block_history = persisted
            .block_history
            .into_iter()
            .map(|entry| {
                (
                    (
                        entry.protocol.clone(),
                        entry.host.clone(),
                        entry.process.clone(),
                    ),
                    entry,
                )
            })
            .collect();
        while state.block_history.len() > GO_HISTORY_SIZE {
            let Some(key) = state
                .block_history
                .iter()
                .min_by_key(|(_, entry)| entry.time)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            state.block_history.remove(&key);
        }
    }
}

impl TunFlowObserver for ConnectionMonitor {
    fn opened(&self, flow: TunFlow, context: FlowContext) {
        self.open(flow, context);
    }

    fn bytes(&self, flow: TunFlowKey, direction: TunFlowDirection, bytes: usize) {
        self.add_bytes(flow, direction, bytes);
    }

    fn closed(&self, flow: TunFlowKey) {
        self.close(flow);
    }

    fn failed(&self, flow: TunFlowKey, stage: &str, error: &str) {
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

fn connection_value(id: &str, flow: TunFlow, context: &FlowContext) -> Value {
    let destination = endpoint_string(&context.effective_destination());
    // Socket-backed HTTP inbounds keep a placeholder packet tuple while the
    // parsed CONNECT authority lives in `original_domain`.  Report that
    // authority as Go does; otherwise the API leaks `0.0.0.0:0` even though
    // routing and the proxy handshake used the real host and port.
    let original =
        if context.original_domain.is_some() && flow.key.destination.ip().is_unspecified() {
            destination.clone()
        } else {
            flow.key.endpoint().to_string()
        };
    let source = endpoint_string(&flow.key.source_endpoint());
    let local_addr = context
        .outbound_local_addr
        .as_ref()
        .and_then(Endpoint::addr)
        .map(|address| address.to_string())
        .unwrap_or_default();
    let underlying_type = context
        .outbound_local_addr
        .as_ref()
        .map(|endpoint| endpoint.network().to_string())
        .unwrap_or_default();
    let is_tun = context.component.as_deref() == Some("tun");
    // Go only fills Domain after resolver/FakeIP or route processing. Socket
    // proxy requests retain their hostname for routing but do not expose it
    // as Domain merely because the request used a domain endpoint.
    let domain = (is_tun || context.inbound.is_none())
        .then(|| context.original_domain.as_ref().map(ToString::to_string))
        .flatten()
        .unwrap_or_default();
    let inbound = context
        .inbound
        .as_deref()
        .or_else(|| is_tun.then_some("tun"))
        .unwrap_or_default();
    let inbound_name = context
        .inbound_name
        .as_deref()
        .or_else(|| is_tun.then_some("TUN"))
        .unwrap_or_default();
    let outbound = context
        .outbound_addr
        .as_ref()
        .and_then(Endpoint::addr)
        .map(|address| address.to_string())
        .unwrap_or_default();
    json!({
        "id": id,
        "addr": destination,
        "network": {"connType": flow.key.network.to_string(), "underlyingType": underlying_type},
        "source": source,
        "inbound": inbound,
        "inboundName": inbound_name,
        "interface": context.interface.as_deref().unwrap_or_default(),
        "outbound": outbound,
        "localAddr": local_addr,
        "destination": original,
        "fakeIp": context.fake_ip.as_deref().unwrap_or_default(),
        "hosts": context.hosts.as_deref().unwrap_or_default(),
        "domain": domain,
        // TUN's packet tuple is the synthetic FakeIP. Once a direct/bypass
        // socket has connected, `resolved_destination` contains the real
        // resolver-selected peer; keep `fakeIp` as the synthetic address for
        // diagnostics, but expose the real IP in the Go-compatible `ip`
        // field. Before that socket exists, Go leaves `IP` empty rather than
        // reporting the synthetic address as if it were real.
        "ip": context
            .resolved_destination
            .as_ref()
            .and_then(Endpoint::addr)
            .or_else(|| {
                context
                    .fake_ip
                    .is_none()
                    .then(|| context.destination.addr())
                    .flatten()
            })
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default(),
        "tag": context.tag.as_deref().unwrap_or_default(),
        "nodeId": context.outbound.as_deref().unwrap_or_default(),
        "nodeName": context.outbound_name.as_deref().unwrap_or_default(),
        "protocol": context.protocol.as_deref().unwrap_or_default(),
        "process": context.process.as_deref().unwrap_or_default(),
        "pid": context.process_id.map(|value| value.to_string()).unwrap_or_default(),
        "uid": context.user_id.map(|value| value.to_string()).unwrap_or_default(),
        "tlsServerName": context.tls_server_name.as_deref().unwrap_or_default(),
        "httpHost": context.http_host.as_deref().unwrap_or_default(),
        "component": context.component.as_deref().unwrap_or_default(),
        "udpMigrateId": match context.udp_migrate_id.load(std::sync::atomic::Ordering::Relaxed) {
            0 => "".to_owned(),
            value => value.to_string(),
        },
        "mode": route_mode(context.route_mode),
        "matchHistory": context
            .match_history
            .iter()
            .map(|entry| json!({
                "ruleName": entry.rule_name,
                "history": entry.history.iter().map(|item| json!({
                    "listName": item.list_name,
                    "matched": item.matched,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "resolver": context.resolver.as_deref().unwrap_or_default(),
        "geo": context.geo.as_deref().unwrap_or_default(),
        "outboundGeo": context.outbound_geo.as_deref().unwrap_or_default(),
        "lists": context.lists,
    })
}

/// Merge metadata discovered after a flow was first published. TUN can expose
/// a flow to the management plane before its asynchronous outbound socket has
/// finished connecting, while Go creates the public record after that dial.
/// Empty values from the early snapshot must not erase route/process metadata
/// when the later snapshot only contains socket fields.
fn merge_connection_metadata(target: &mut Value, update: Value) -> bool {
    fn merge_value(target: &mut Value, update: Value) -> bool {
        match (target, update) {
            (Value::Object(target), Value::Object(update)) => {
                let mut changed = false;
                for (key, value) in update {
                    if key == "id" || value_is_empty(&value) {
                        continue;
                    }
                    match target.get_mut(&key) {
                        Some(existing) => changed |= merge_value(existing, value),
                        None => {
                            target.insert(key, value);
                            changed = true;
                        }
                    }
                }
                changed
            }
            (target, update) if *target != update => {
                *target = update;
                true
            }
            _ => false,
        }
    }

    fn value_is_empty(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::String(value) => value.is_empty(),
            Value::Array(value) => value.is_empty(),
            Value::Object(value) => value.is_empty(),
            Value::Bool(_) | Value::Number(_) => false,
        }
    }

    merge_value(target, update)
}

/// Build the same telemetry dimensions as Go's `statistics.dimensionsForConnection`.
///
/// This is intentionally derived from the public connection contract instead of
/// the internal flow/router structs. It keeps the persisted telemetry stable
/// when a protocol adds metadata and makes FakeIP/domain handling identical for
/// TUN and socket inbound flows.
fn telemetry_dimensions(connection: &Value) -> Vec<(String, String)> {
    let protocol = connection
        .pointer("/network/connType")
        .and_then(Value::as_str)
        .or_else(|| connection.get("protocol").and_then(Value::as_str))
        .unwrap_or_default();
    let inbound = first_non_empty(&[
        string_field(connection, "inboundName"),
        string_field(connection, "inbound"),
    ]);
    let source = normalize_telemetry_source(&string_field(connection, "source"));
    let addr = telemetry_addr(connection);
    let outbound = first_non_empty(&[
        string_field(connection, "nodeName"),
        string_field(connection, "nodeId"),
        string_field(connection, "outbound"),
    ]);
    let process = string_field(connection, "process");
    let tag = string_field(connection, "tag");
    let destination = telemetry_destination(connection);

    let mut values = Vec::with_capacity(9);
    // Keep the same lexicographic order previously supplied by BTreeMap while
    // using a flat Vec, since these dimensions are already unique by name.
    for (dimension, value) in [
        ("addr", addr),
        ("destination", destination),
        ("inbound", inbound),
        ("outbound", outbound),
        ("process", process),
        ("protocol", protocol.to_owned()),
        ("source", source),
        ("tag", tag),
    ] {
        if !value.is_empty() {
            values.push((dimension.to_owned(), value));
        }
    }
    if let Some(rule) = connection
        .get("matchHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|match_value| match_value.get("ruleName").and_then(Value::as_str))
        .rfind(|rule| !rule.is_empty())
    {
        let insert_at = values
            .iter()
            .position(|(dimension, _)| dimension.as_str() > "rule")
            .unwrap_or(values.len());
        values.insert(insert_at, ("rule".to_owned(), rule.to_owned()));
    }
    values
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn telemetry_addr(connection: &Value) -> String {
    let addr = string_field(connection, "addr");
    let fake_ip = string_field(connection, "fakeIp");
    if !fake_ip.is_empty() && telemetry_host(&addr) == telemetry_host(&fake_ip) {
        return first_non_empty(&[
            string_field(connection, "domain"),
            string_field(connection, "hosts"),
        ]);
    }
    addr
}

fn telemetry_destination(connection: &Value) -> String {
    if !string_field(connection, "fakeIp").is_empty() {
        return String::new();
    }
    first_non_empty(&[
        string_field(connection, "domain"),
        string_field(connection, "hosts"),
        string_field(connection, "destination"),
        string_field(connection, "addr"),
    ])
}

fn telemetry_host(value: &str) -> String {
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return address.ip().to_string();
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && is_decimal(port)
    {
        return host.trim_matches(['[', ']']).to_owned();
    }
    value.trim_matches(&['[', ']'][..]).to_owned()
}

fn normalize_telemetry_source(value: &str) -> String {
    let mut value = value.trim().to_owned();
    if let Some(rest) = value.strip_prefix("http2.h-")
        && let Some(marker) = rest.find("-2")
    {
        value = rest[marker + 2..].to_owned();
    }
    if let Some(left) = value.rfind('[')
        && let Some(right) = value[left + 1..].find(']')
    {
        return value[left + 1..left + 1 + right].to_owned();
    }
    if value.matches(':').count() == 1
        && let Some(colon) = value.rfind(':')
        && colon > 0
        && colon + 1 < value.len()
        && is_decimal(&value[colon + 1..])
    {
        return value[..colon].to_owned();
    }
    value
}

fn normalize_persisted_telemetry_value(dimension: &str, value: String) -> String {
    if dimension == "source" {
        normalize_telemetry_source(&value)
    } else {
        value
    }
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn endpoint_string(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
}

fn traffic_bucket_start(interval: &str, timestamp: i64) -> i64 {
    let datetime =
        OffsetDateTime::from_unix_timestamp(timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    match interval {
        "day" => datetime
            .date()
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
            .unix_timestamp(),
        "month" => time::Date::from_calendar_date(datetime.year(), datetime.month(), 1)
            .expect("a valid timestamp has a valid calendar date")
            .with_time(time::Time::MIDNIGHT)
            .assume_utc()
            .unix_timestamp(),
        _ => timestamp.div_euclid(3_600) * 3_600,
    }
}

fn route_mode(mode: RouteMode) -> &'static str {
    match mode {
        RouteMode::Bypass => "bypass",
        RouteMode::Proxy => "proxy",
        RouteMode::Direct => "direct",
        RouteMode::Block => "block",
    }
}

fn persisted_snapshot(persisted: &PersistedMonitor) -> yuhaiin_core::Result<GoStatisticsSnapshot> {
    let mut traffic = BTreeMap::<i64, (u64, u64)>::new();
    for (bucket, (download, upload)) in &persisted.buckets {
        let hour = bucket.div_euclid(3_600) * 3_600;
        let item = traffic.entry(hour).or_default();
        item.0 = item.0.saturating_add(*download);
        item.1 = item.1.saturating_add(*upload);
    }
    let history = persisted
        .history
        .iter()
        .filter_map(|item| {
            let connection = item.get("connection")?;
            let mut public_connection = connection.clone();
            public_connection
                .as_object_mut()?
                .remove(INTERNAL_GO_PROTOCOL_KEY);
            Some(GoConnectionHistoryRecord {
                protocol: history_protocol(connection),
                addr: connection
                    .get("addr")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                process: connection
                    .get("process")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                count: history_count(item),
                last_seen: history_time(item),
                connection_json: serde_json::to_vec(&public_connection).ok()?,
            })
        })
        .collect();
    let telemetry = if persisted.telemetry_buckets.is_empty() {
        let bucket = unix_seconds().div_euclid(TELEMETRY_HOURLY_BUCKET_SECONDS)
            * TELEMETRY_HOURLY_BUCKET_SECONDS;
        persisted
            .telemetry
            .iter()
            .map(|entry| GoTelemetryBucketRecord {
                bucket,
                span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
                dimension: entry.dimension.clone(),
                value: normalize_persisted_telemetry_value(&entry.dimension, entry.value.clone()),
                download: entry.download,
                upload: entry.upload,
                failures: entry.failures,
            })
            .collect()
    } else {
        persisted
            .telemetry_buckets
            .iter()
            .map(|entry| GoTelemetryBucketRecord {
                bucket: entry.bucket,
                span_seconds: normalize_telemetry_bucket_span_seconds(entry.span_seconds),
                dimension: entry.dimension.clone(),
                value: normalize_persisted_telemetry_value(&entry.dimension, entry.value.clone()),
                download: entry.download,
                upload: entry.upload,
                failures: entry.failures,
            })
            .collect()
    };
    Ok(GoStatisticsSnapshot {
        total_download: persisted.total_download,
        total_upload: persisted.total_upload,
        traffic: traffic
            .into_iter()
            .map(|(bucket, (download, upload))| GoTrafficBucketRecord {
                bucket,
                upload,
                download,
            })
            .collect(),
        history,
        failed_history: persisted
            .failed_history
            .iter()
            .map(|entry| GoFailedHistoryRecord {
                protocol: entry.protocol.clone(),
                host: entry.host.clone(),
                process: entry.process.clone(),
                count: entry.count,
                last_seen: entry.time,
                error: entry.error.clone(),
            })
            .collect(),
        telemetry,
    })
}

fn pending_delta_from_state(state: &MonitorState) -> GoStatisticsDelta {
    GoStatisticsDelta {
        total_download: state.total_download,
        total_upload: state.total_upload,
        traffic: state
            .pending_traffic
            .iter()
            .map(|(bucket, (download, upload))| GoTrafficBucketRecord {
                bucket: *bucket,
                upload: *upload,
                download: *download,
            })
            .collect(),
        history: state.pending_history.clone(),
        failed_history: state.pending_failed_history.values().cloned().collect(),
        telemetry: state
            .pending_telemetry
            .iter()
            .map(
                |((bucket, span_seconds, dimension, value), (download, upload, failures))| {
                    GoTelemetryBucketRecord {
                        bucket: *bucket,
                        span_seconds: *span_seconds,
                        dimension: dimension.clone(),
                        value: value.clone(),
                        download: *download,
                        upload: *upload,
                        failures: *failures,
                    }
                },
            )
            .collect(),
    }
}

fn apply_delta_to_snapshot(snapshot: &mut GoStatisticsSnapshot, delta: GoStatisticsDelta) {
    snapshot.total_download = delta.total_download;
    snapshot.total_upload = delta.total_upload;
    for item in delta.traffic {
        if let Some(existing) = snapshot
            .traffic
            .iter_mut()
            .find(|existing| existing.bucket == item.bucket)
        {
            existing.download = existing.download.saturating_add(item.download);
            existing.upload = existing.upload.saturating_add(item.upload);
        } else {
            snapshot.traffic.push(item);
        }
    }
    for item in delta.history {
        if let Some(existing) = snapshot.history.iter_mut().find(|existing| {
            existing.protocol == item.protocol
                && existing.addr == item.addr
                && existing.process == item.process
        }) {
            existing.count = existing.count.saturating_add(item.count);
            if item.last_seen >= existing.last_seen {
                existing.last_seen = item.last_seen;
                existing.connection_json = item.connection_json;
            }
        } else {
            snapshot.history.push(item);
        }
    }
    for item in delta.failed_history {
        if let Some(existing) = snapshot.failed_history.iter_mut().find(|existing| {
            existing.protocol == item.protocol
                && existing.host == item.host
                && existing.process == item.process
        }) {
            existing.count = existing.count.saturating_add(item.count);
            if item.last_seen >= existing.last_seen {
                existing.last_seen = item.last_seen;
                existing.error = item.error;
            }
        } else {
            snapshot.failed_history.push(item);
        }
    }
    for item in delta.telemetry {
        if let Some(existing) = snapshot.telemetry.iter_mut().find(|existing| {
            existing.bucket == item.bucket
                && existing.span_seconds == item.span_seconds
                && existing.dimension == item.dimension
                && existing.value == item.value
        }) {
            existing.download = existing.download.saturating_add(item.download);
            existing.upload = existing.upload.saturating_add(item.upload);
            existing.failures = existing.failures.saturating_add(item.failures);
        } else {
            snapshot.telemetry.push(item);
        }
    }
}

fn merge_statistics_snapshots(
    mut base: GoStatisticsSnapshot,
    overlay: GoStatisticsSnapshot,
) -> GoStatisticsSnapshot {
    base.total_download = base.total_download.max(overlay.total_download);
    base.total_upload = base.total_upload.max(overlay.total_upload);

    let mut traffic = base
        .traffic
        .into_iter()
        .map(|item| (item.bucket, item))
        .collect::<BTreeMap<_, _>>();
    for item in overlay.traffic {
        traffic
            .entry(item.bucket)
            .and_modify(|current| {
                current.upload = current.upload.max(item.upload);
                current.download = current.download.max(item.download);
            })
            .or_insert(item);
    }
    base.traffic = traffic.into_values().collect();

    let mut history = base
        .history
        .into_iter()
        .map(|item| history_record_key(&item).map(|key| (key, item)))
        .flatten()
        .collect::<BTreeMap<_, _>>();
    for item in overlay.history {
        let key = (
            item.protocol.clone(),
            item.addr.clone(),
            item.process.clone(),
        );
        if let Some(current) = history.get_mut(&key) {
            if item.count > current.count || item.last_seen >= current.last_seen {
                *current = item;
            }
        } else {
            history.insert(key, item);
        }
    }
    base.history = history.into_values().collect();

    let mut failed = base
        .failed_history
        .into_iter()
        .map(|item| {
            (
                (
                    item.protocol.clone(),
                    item.host.clone(),
                    item.process.clone(),
                ),
                item,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for item in overlay.failed_history {
        let key = (
            item.protocol.clone(),
            item.host.clone(),
            item.process.clone(),
        );
        if let Some(current) = failed.get_mut(&key) {
            if item.count > current.count || item.last_seen >= current.last_seen {
                *current = item;
            }
        } else {
            failed.insert(key, item);
        }
    }
    base.failed_history = failed.into_values().collect();

    let mut telemetry = base
        .telemetry
        .into_iter()
        .map(|item| {
            (
                (
                    item.bucket,
                    item.span_seconds,
                    item.dimension.clone(),
                    item.value.clone(),
                ),
                item,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for item in overlay.telemetry {
        let key = (
            item.bucket,
            item.span_seconds,
            item.dimension.clone(),
            item.value.clone(),
        );
        if let Some(current) = telemetry.get_mut(&key) {
            current.download = current.download.max(item.download);
            current.upload = current.upload.max(item.upload);
            current.failures = current.failures.max(item.failures);
        } else {
            telemetry.insert(key, item);
        }
    }
    base.telemetry = telemetry.into_values().collect();
    base
}

fn history_record_key(item: &GoConnectionHistoryRecord) -> Option<(String, String, String)> {
    Some((
        item.protocol.clone(),
        item.addr.clone(),
        item.process.clone(),
    ))
}

fn history_record_value(item: GoConnectionHistoryRecord) -> Option<Value> {
    let mut connection = serde_json::from_slice::<Value>(&item.connection_json).ok()?;
    connection.as_object_mut()?.insert(
        INTERNAL_GO_PROTOCOL_KEY.to_owned(),
        Value::String(item.protocol),
    );
    Some(json!({
        "connection": connection,
        "count": item.count.to_string(),
        "time": format_time(item.last_seen),
    }))
}

fn connection_history_record(
    connection: &Value,
    last_seen: i64,
) -> Option<GoConnectionHistoryRecord> {
    let mut public_connection = connection.clone();
    public_connection
        .as_object_mut()?
        .remove(INTERNAL_GO_PROTOCOL_KEY);
    Some(GoConnectionHistoryRecord {
        protocol: history_protocol(connection),
        addr: connection
            .get("addr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        process: connection
            .get("process")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        count: 1,
        last_seen,
        connection_json: serde_json::to_vec(&public_connection).ok()?,
    })
}

fn merge_pending_history(
    pending: &mut Vec<GoConnectionHistoryRecord>,
    record: GoConnectionHistoryRecord,
) {
    if let Some(existing) = pending.iter_mut().find(|existing| {
        existing.protocol == record.protocol
            && existing.addr == record.addr
            && existing.process == record.process
    }) {
        existing.count = existing.count.saturating_add(record.count);
        if record.last_seen >= existing.last_seen {
            existing.last_seen = record.last_seen;
            existing.connection_json = record.connection_json;
        }
    } else {
        pending.push(record);
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn format_time(seconds: i64) -> String {
    // Go's `time.Unix` JSON representation is emitted in UTC by the service
    // contract. Do not let the host timezone leak into frontend responses.
    format_time_utc(seconds)
}

fn format_time_utc(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

fn parse_time(value: Option<&str>) -> Option<i64> {
    value
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map(|time| time.unix_timestamp())
}

fn history_key(item: &Value) -> (String, String, String) {
    let connection = item.get("connection").unwrap_or(item);
    connection_history_key(connection)
}

fn connection_history_key(connection: &Value) -> (String, String, String) {
    (
        history_protocol(connection),
        connection
            .get("addr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        connection
            .get("process")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

fn history_protocol(connection: &Value) -> String {
    connection
        .get(INTERNAL_GO_PROTOCOL_KEY)
        .and_then(Value::as_str)
        .or_else(|| connection.get("protocol").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

fn public_history_item(item: &Value) -> Value {
    let mut item = item.clone();
    if let Some(connection) = item.get_mut("connection").and_then(Value::as_object_mut) {
        connection.remove(INTERNAL_GO_PROTOCOL_KEY);
    }
    item
}

fn history_count(item: &Value) -> u64 {
    item.get("count")
        .and_then(Value::as_u64)
        .or_else(|| {
            item.get("count")
                .and_then(Value::as_str)
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(1)
}

/// Older Rust checkpoints can contain duplicate history rows after taking
/// over a Go database. Go's SQLite projection keys history by
/// `(protocol, addr, process_name)`, so normalize that key before exposing
/// the API or writing the projection back.
fn coalesce_history(items: Vec<Value>) -> Vec<Value> {
    let mut merged = BTreeMap::<(String, String, String), Value>::new();
    for item in items.into_iter().map(normalize_history_time) {
        let key = history_key(&item);
        if let Some(existing) = merged.get_mut(&key) {
            let count = history_count(existing).saturating_add(history_count(&item));
            if history_time(&item) >= history_time(existing) {
                *existing = item;
            }
            existing["count"] = Value::String(count.to_string());
        } else {
            merged.insert(key, item);
        }
    }
    let mut items = merged.into_values().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        history_time(right)
            .cmp(&history_time(left))
            .then_with(|| history_key(left).cmp(&history_key(right)))
    });
    items
}

fn normalize_history_time(mut item: Value) -> Value {
    let timestamp = item
        .get("time")
        .and_then(Value::as_str)
        .and_then(|value| parse_time(Some(value)));
    if let Some(timestamp) = timestamp {
        item["time"] = Value::String(format_time(timestamp));
    }
    item
}

fn history_time(item: &Value) -> i64 {
    item.get("time")
        .and_then(Value::as_str)
        .and_then(|value| parse_time(Some(value)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::SystemTime;

    use super::*;
    use yuhaiin_core::{Endpoint, Network};
    use yuhaiin_store::ConfigStore;

    fn flow() -> (TunFlow, FlowContext) {
        let key = TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:1234".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
        };
        let flow = TunFlow { key };
        (
            flow,
            FlowContext::new(Endpoint::ip(key.network, key.destination)),
        )
    }

    fn monitor_test_database_path() -> PathBuf {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .expect("a cache directory is required for the monitor test");
        let directory = cache.join("yuhaiin-rust-monitor-tests");
        fs::create_dir_all(&directory).unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        directory.join(format!("go-projection-{}-{nonce}.db", std::process::id()))
    }

    fn remove_monitor_test_database(path: &Path) {
        for suffix in ["", "-journal", "-wal", "-shm", "-yuhaiin-write-lock"] {
            let target = if suffix.is_empty() {
                path.to_path_buf()
            } else {
                PathBuf::from(format!("{}{}", path.display(), suffix))
            };
            let _ = fs::remove_file(target);
        }
    }

    #[test]
    fn monitor_tracks_live_connections_and_precise_string_counters() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 7);
        monitor.bytes(flow.key, TunFlowDirection::Download, 11);
        assert_eq!(monitor.connections_value()["connections"][0]["id"], "1");
        assert_eq!(monitor.total_flow_value()["upload"], "7");
        assert_eq!(monitor.total_flow_value()["download"], "11");
        assert_eq!(monitor.total_flow_value()["counters"]["1"]["upload"], "7");
        monitor.closed(flow.key);
        assert_eq!(
            monitor.connections_value()["connections"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            monitor.total_flow_value()["counters"]
                .as_object()
                .unwrap()
                .get("1"),
            None
        );
        assert_eq!(
            monitor.telemetry_value()["groups"]
                .as_array()
                .unwrap()
                .len(),
            GO_TELEMETRY_DIMENSIONS.len()
        );
        assert_eq!(
            monitor.telemetry_value()["groups"]
                .as_array()
                .unwrap()
                .iter()
                .map(|group| group["dimension"].as_str().unwrap())
                .collect::<Vec<_>>(),
            GO_TELEMETRY_DIMENSIONS.to_vec()
        );
    }

    #[test]
    fn history_times_are_serialized_in_utc() {
        assert_eq!(format_time(1_752_883_200), "2025-07-19T00:00:00Z");
    }

    #[test]
    fn telemetry_dimensions_match_go_fakeip_and_route_projection() {
        let connection = json!({
            "network": {"connType": "tcp"},
            "inbound": "socks5",
            "inboundName": "Desktop SOCKS",
            "source": "[2001:db8::2]:1234",
            "addr": "198.18.0.1:443",
            "fakeIp": "198.18.0.1",
            "domain": "example.com",
            "hosts": "hosts.example",
            "destination": "203.0.113.10:443",
            "outbound": "proxy",
            "nodeId": "node-1",
            "nodeName": "Tokyo",
            "process": "/usr/bin/browser",
            "tag": "streaming",
            "matchHistory": [
                {"ruleName": "first-rule"},
                {"ruleName": "last-rule"}
            ]
        });

        assert_eq!(
            telemetry_dimensions(&connection),
            vec![
                ("addr".to_owned(), "example.com".to_owned()),
                ("inbound".to_owned(), "Desktop SOCKS".to_owned()),
                ("outbound".to_owned(), "Tokyo".to_owned()),
                ("process".to_owned(), "/usr/bin/browser".to_owned()),
                ("protocol".to_owned(), "tcp".to_owned()),
                ("rule".to_owned(), "last-rule".to_owned()),
                ("source".to_owned(), "2001:db8::2".to_owned()),
                ("tag".to_owned(), "streaming".to_owned()),
            ]
        );
        assert_eq!(telemetry_destination(&connection), "");
    }

    #[test]
    fn telemetry_source_normalization_matches_go_http2_and_socket_forms() {
        assert_eq!(
            normalize_telemetry_source(" http2.h-ignored-2[2001:db8::4]:443 "),
            "2001:db8::4"
        );
        assert_eq!(normalize_telemetry_source("192.0.2.4:1234"), "192.0.2.4");
        assert_eq!(
            normalize_telemetry_source("[2001:db8::4]:1234"),
            "2001:db8::4"
        );
        assert_eq!(normalize_telemetry_source("unix-client"), "unix-client");
        assert_eq!(
            normalize_persisted_telemetry_value("source", "192.0.2.4:1234".to_owned()),
            "192.0.2.4"
        );
        assert_eq!(
            normalize_persisted_telemetry_value("addr", "example.com:443".to_owned()),
            "example.com:443"
        );
    }

    #[test]
    fn monitor_preserves_inbound_and_process_metadata_in_connections() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.inbound = Some("socks5".to_owned());
        context.inbound_name = Some("desktop-socks".to_owned());
        context.process = Some("/usr/bin/example-app".to_owned());
        context.process_id = Some(42);
        context.user_id = Some(1000);
        context.fake_ip = Some("198.18.0.1".to_owned());
        monitor.opened(flow, context);
        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["inbound"], "socks5");
        assert_eq!(connection["inboundName"], "desktop-socks");
        assert_eq!(connection["process"], "/usr/bin/example-app");
        assert_eq!(connection["pid"], "42");
        assert_eq!(connection["uid"], "1000");
        assert_eq!(connection["fakeIp"], "198.18.0.1");
        assert_eq!(connection["component"], "");
    }

    #[test]
    fn monitor_reports_resolved_ip_separately_from_fakeip() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        let fake_ip = "fc00::1".parse().unwrap();
        let real_ip = "142.250.72.4".parse().unwrap();
        context.destination = Endpoint::ip(Network::Tcp, std::net::SocketAddr::new(fake_ip, 443));
        context.original_domain = Some(yuhaiin_core::DomainName::new("www.google.com").unwrap());
        context.fake_ip = Some(fake_ip.to_string());

        monitor.opened(flow, context.clone());
        let pending = &monitor.connections_value()["connections"][0];
        assert_eq!(pending["ip"], "");

        context.resolved_destination = Some(Endpoint::ip(
            Network::Tcp,
            std::net::SocketAddr::new(real_ip, 443),
        ));

        monitor.opened(flow, context);

        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["domain"], "www.google.com");
        assert_eq!(connection["fakeIp"], "fc00::1");
        assert_eq!(connection["ip"], "142.250.72.4");
    }

    #[test]
    fn monitor_preserves_route_explainability_metadata_in_connections() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.tag = Some("streaming".to_owned());
        context.resolver = Some("secure-dns".to_owned());
        context.geo = Some("CN".to_owned());
        context.lists = vec!["media-hosts".to_owned()];
        context.match_history = vec![yuhaiin_core::MatchHistoryEntry {
            rule_name: "media-rule".to_owned(),
            history: vec![yuhaiin_core::MatchResult {
                list_name: "media-hosts".to_owned(),
                matched: true,
            }],
        }];
        monitor.opened(flow, context);

        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["tag"], "streaming");
        assert_eq!(connection["resolver"], "secure-dns");
        assert_eq!(connection["geo"], "CN");
        assert_eq!(connection["lists"][0], "media-hosts");
        assert_eq!(connection["matchHistory"][0]["ruleName"], "media-rule");
        assert_eq!(
            connection["matchHistory"][0]["history"][0]["listName"],
            "media-hosts"
        );
        assert_eq!(connection["matchHistory"][0]["history"][0]["matched"], true);
    }

    #[test]
    fn monitor_preserves_protocol_and_socket_metadata_in_connections() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.local_addr = Some(Endpoint::ip(
            Network::Tcp,
            "127.0.0.1:1080".parse().unwrap(),
        ));
        context.outbound_local_addr = Some(Endpoint::ip(
            Network::Tcp,
            "192.0.2.20:52000".parse().unwrap(),
        ));
        context.outbound = Some("node-id".to_owned());
        context.outbound_addr = Some(Endpoint::ip(
            Network::Tcp,
            "192.0.2.10:8443".parse().unwrap(),
        ));
        context.hosts = Some("hosts".to_owned());
        context.protocol = Some("http".to_owned());
        context.tls_server_name = Some("example.com".to_owned());
        context.http_host = Some("example.com:443".to_owned());
        context.interface = Some("eth0".to_owned());
        context.outbound_geo = Some("US".to_owned());
        monitor.opened(flow, context);
        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["hosts"], "hosts");
        assert_eq!(connection["tlsServerName"], "example.com");
        assert_eq!(connection["httpHost"], "example.com:443");
        assert_eq!(connection["interface"], "eth0");
        assert_eq!(connection["outboundGeo"], "US");
        assert_eq!(connection["localAddr"], "192.0.2.20:52000");
        assert_eq!(connection["network"]["underlyingType"], "tcp");
        assert_eq!(connection["protocol"], "http");
        assert_eq!(connection["outbound"], "192.0.2.10:8443");
        assert_eq!(connection["nodeId"], "node-id");
    }

    #[test]
    fn monitor_keeps_socket_local_metadata_empty_without_outbound_socket() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.local_addr = Some(Endpoint::ip(
            Network::Tcp,
            "127.0.0.1:1080".parse().unwrap(),
        ));
        context.udp_migrate_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        monitor.opened(flow, context);

        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["localAddr"], "");
        assert_eq!(connection["network"]["underlyingType"], "");
        assert_eq!(connection["udpMigrateId"], "");
    }

    #[test]
    fn monitor_merges_late_socket_metadata_without_allocating_a_new_connection() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut initial) = flow();
        initial.inbound = Some("tun".to_owned());
        initial.inbound_name = Some("TUN".to_owned());
        initial.process = Some("/usr/bin/browser".to_owned());
        monitor.opened(flow, initial);
        let mut late = FlowContext::new(Endpoint::ip(flow.key.network, flow.key.destination));
        late.outbound_local_addr = Some(Endpoint::ip(
            Network::Tcp,
            "192.0.2.20:52000".parse().unwrap(),
        ));
        late.protocol = Some("tls".to_owned());
        monitor.opened(flow, late);

        let connections = monitor.connections_value()["connections"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0]["id"], "1");
        assert_eq!(connections[0]["inbound"], "tun");
        assert_eq!(connections[0]["process"], "/usr/bin/browser");
        assert_eq!(connections[0]["localAddr"], "192.0.2.20:52000");
        assert_eq!(connections[0]["network"]["underlyingType"], "tcp");
        assert_eq!(connections[0]["protocol"], "tls");
    }

    #[test]
    fn monitor_preserves_tun_component_and_defaults() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.component = Some("tun".to_owned());
        monitor.opened(flow, context);
        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["component"], "tun");
        assert_eq!(connection["inbound"], "tun");
        assert_eq!(connection["inboundName"], "TUN");
    }

    #[test]
    fn monitor_traffic_uses_utc_calendar_buckets_and_skips_empty_ranges() {
        let monitor = ConnectionMonitor::new();
        let january = OffsetDateTime::parse("2024-01-31T23:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        let february = OffsetDateTime::parse("2024-02-01T01:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        let march = OffsetDateTime::parse("2024-03-01T01:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        {
            let mut state = monitor.lock();
            state.buckets.insert(january, (11, 7));
            state.buckets.insert(february, (13, 17));
            state.buckets.insert(march, (19, 23));
        }

        let value = monitor.traffic_value_range("month", january, march + 3_600);
        assert_eq!(value["interval"], "month");
        assert_eq!(value["items"].as_array().unwrap().len(), 3);
        assert_eq!(value["items"][0]["start"], "2024-01-01T00:00:00Z");
        assert_eq!(value["items"][0]["download"], "11");
        assert_eq!(value["items"][1]["start"], "2024-02-01T00:00:00Z");
        assert_eq!(value["items"][1]["upload"], "17");
        assert_eq!(value["items"][2]["start"], "2024-03-01T00:00:00Z");
    }

    #[test]
    fn monitor_emits_snapshot_add_and_remove_events() {
        let monitor = ConnectionMonitor::new();
        let mut receiver = monitor.subscribe();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        assert_eq!(receiver.try_recv().unwrap().kind, "connections_added");
        assert_eq!(monitor.initial_event().kind, "connections_added");
        monitor.closed(flow.key);
        let event = receiver.try_recv().unwrap();
        assert_eq!(event.kind, "connections_removed");
        assert_eq!(event.payload["ids"][0], "1");
    }

    #[test]
    fn monitor_coalesces_connection_history_by_go_key() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context.clone());
        monitor.closed(flow.key);
        monitor.opened(flow, context);
        monitor.closed(flow.key);

        let history = monitor.all_history_value();
        assert_eq!(history["items"].as_array().unwrap().len(), 1);
        assert_eq!(history["items"][0]["count"], "2");
    }

    #[tokio::test]
    async fn monitor_does_not_restore_live_counters_without_live_connections() {
        let store = ConfigStore::open_memory().await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store.clone())
            .await
            .unwrap();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 11);
        monitor.shutdown().await.unwrap();

        let reloaded = ConnectionMonitor::load_with_store(store).await.unwrap();
        assert!(
            reloaded.connections_value()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            reloaded.total_flow_value()["counters"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        assert_eq!(reloaded.total_flow_value()["upload"], "11");
        reloaded.shutdown().await.unwrap();
    }

    #[test]
    fn monitor_preserves_close_requests_until_data_plane_consumes_them() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        assert_eq!(monitor.request_close(&["1".to_owned()]), 1);
        assert_eq!(monitor.take_close_requests(), vec![flow.key]);
        assert!(monitor.take_close_requests().is_empty());
    }

    #[tokio::test]
    async fn monitor_wakes_non_tun_relays_for_close_requests() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        let waiter = {
            let monitor = monitor.clone();
            tokio::spawn(async move { monitor.wait_for_close(flow.key).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(monitor.request_close(&["1".to_owned()]), 1);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("close waiter should wake")
            .expect("close waiter should not panic");
    }

    #[test]
    fn monitor_records_coalesced_failed_history() {
        let monitor = ConnectionMonitor::new();
        monitor.record_failure("http", "example.com:443", "connection refused");
        monitor.record_failure("http", "example.com:443", "timeout");
        let history = monitor.failed_history_value();
        assert_eq!(history["items"][0]["failedCount"], "2");
        assert_eq!(history["items"][0]["error"], "timeout");
    }

    #[test]
    fn monitor_surfaces_transport_failures_without_packet_logs() {
        let monitor = ConnectionMonitor::new();
        monitor.record_failure("http2", "proxy.example:443", "connection lost");
        let (flow, _) = flow();
        monitor.failed(flow.key, "tcp-connect", "timeout after 30s");

        let logs = monitor.logs().snapshot();
        assert!(
            logs.iter()
                .any(|line| line.contains("outbound connection failed")
                    && line.contains("proxy.example:443"))
        );
        assert!(
            logs.iter()
                .any(|line| line.contains("TUN flow failed") && line.contains("tcp-connect"))
        );
        assert!(logs.iter().all(|line| !line.contains("packet")));
    }

    #[test]
    fn monitor_telemetry_respects_time_range_limit_and_failures() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 7);
        monitor.bytes(flow.key, TunFlowDirection::Download, 11);
        monitor.record_failure("http", "example.com:443", "timeout");

        let now = unix_seconds();
        let value = monitor.telemetry_value_range(now - 3_600, now + 3_600, 1);
        let protocol = value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "protocol")
            .unwrap();
        assert_eq!(protocol["items"].as_array().unwrap().len(), 1);
        assert_eq!(protocol["items"][0]["value"], "tcp");
        assert_eq!(protocol["items"][0]["download"], "11");
        assert_eq!(protocol["items"][0]["upload"], "7");

        let failures = monitor.telemetry_value_range(now - 3_600, now + 3_600, 10);
        let failure_protocol = failures["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "protocol")
            .unwrap();
        assert!(
            failure_protocol["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["value"] == "http" && item["failures"] == "1")
        );
        let failure_process = failures["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "process")
            .unwrap();
        assert!(
            failure_process["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["failures"] == "0")
        );
        monitor.record_failure_with_process(
            "http",
            "example.com:443",
            "timeout",
            Some("/usr/bin/browser"),
        );
        let failures = monitor.telemetry_value_range(now - 3_600, now + 3_600, 10);
        let failure_process = failures["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "process")
            .unwrap();
        assert!(
            failure_process["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| { item["value"] == "/usr/bin/browser" && item["failures"] == "1" })
        );
    }

    #[test]
    fn monitor_telemetry_includes_daily_buckets_that_overlap_a_partial_day() {
        let monitor = ConnectionMonitor::new();
        let day = 1_704_067_200_i64; // 2024-01-01T00:00:00Z
        {
            let mut state = monitor.lock();
            state.telemetry_buckets.insert(
                (
                    day,
                    TELEMETRY_DAILY_BUCKET_SECONDS,
                    "protocol".to_owned(),
                    "tcp".to_owned(),
                ),
                (100, 50, 2),
            );
            state.telemetry_buckets.insert(
                (
                    day + TELEMETRY_DAILY_BUCKET_SECONDS,
                    TELEMETRY_HOURLY_BUCKET_SECONDS,
                    "protocol".to_owned(),
                    "tcp".to_owned(),
                ),
                (3, 4, 1),
            );
            state.telemetry_buckets.insert(
                (
                    day + 11 * 3_600,
                    TELEMETRY_HOURLY_BUCKET_SECONDS,
                    "protocol".to_owned(),
                    "tcp".to_owned(),
                ),
                (70, 80, 9),
            );
        }

        let value = monitor.telemetry_value_range(
            day + 12 * 3_600,
            day + TELEMETRY_DAILY_BUCKET_SECONDS + 12 * 3_600,
            8,
        );
        let protocol = value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "protocol")
            .unwrap();
        assert_eq!(protocol["items"][0]["value"], "tcp");
        assert_eq!(protocol["items"][0]["download"], "103");
        assert_eq!(protocol["items"][0]["upload"], "54");
        assert_eq!(protocol["items"][0]["failures"], "3");

        let after_daily = monitor.telemetry_value_range(
            day + TELEMETRY_DAILY_BUCKET_SECONDS + 12 * 3_600,
            day + 2 * TELEMETRY_DAILY_BUCKET_SECONDS,
            8,
        );
        let protocol = after_daily["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["dimension"] == "protocol")
            .unwrap();
        assert!(protocol["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn monitor_exposes_block_history_in_the_route_contract_shape() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.route_mode = RouteMode::Block;
        context.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
        context.process = Some("/usr/bin/browser".to_owned());
        monitor.opened(flow, context);
        monitor.closed(flow.key);

        let mut second = FlowContext::new(Endpoint::ip(flow.key.network, flow.key.destination));
        second.route_mode = RouteMode::Block;
        second.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
        second.process = Some("/usr/bin/browser".to_owned());
        monitor.opened(flow, second);
        monitor.closed(flow.key);

        let value = monitor.block_history_value();
        // History uses the same application-protocol field as connections;
        // an un-sniffed blocked flow must not fall back to its TCP transport.
        assert_eq!(value["items"][0]["protocol"], "");
        assert_eq!(value["items"][0]["host"], "blocked.example");
        assert_eq!(value["items"][0]["blockCount"], "2");
        assert_eq!(value["dumpProcessEnabled"], true);
    }

    #[test]
    fn monitor_keeps_failed_history_processes_separate_and_exposes_the_flag() {
        let monitor = ConnectionMonitor::new();
        monitor.record_failure_with_process(
            "http",
            "example.com:443",
            "timeout",
            Some("/usr/bin/browser"),
        );
        monitor.record_failure("http", "example.com:443", "connection refused");

        let value = monitor.failed_history_value();
        assert_eq!(value["items"].as_array().unwrap().len(), 2);
        assert_eq!(value["dumpProcessEnabled"], true);
        assert!(
            value["items"].as_array().unwrap().iter().any(|item| {
                item["process"] == "/usr/bin/browser" && item["failedCount"] == "1"
            })
        );
    }

    #[test]
    fn monitor_bounds_block_history_to_the_go_public_window() {
        let monitor = ConnectionMonitor::new();
        for index in 0..=GO_HISTORY_SIZE {
            let (flow, mut context) = flow();
            context.route_mode = RouteMode::Block;
            context.original_domain =
                Some(yuhaiin_core::DomainName::new(&format!("blocked-{index}.example")).unwrap());
            context.process = Some(format!("process-{index}"));
            monitor.opened(flow, context);
            monitor.closed(flow.key);
        }
        assert_eq!(
            monitor.block_history_value()["items"]
                .as_array()
                .unwrap()
                .len(),
            GO_HISTORY_SIZE
        );
    }

    #[test]
    fn monitor_connection_uses_http_authority_for_placeholder_socket_tuple() {
        let monitor = ConnectionMonitor::new();
        let key = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:40000".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
        };
        let flow = TunFlow { key };
        let mut context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:443".parse().unwrap()));
        context.original_domain = Some(yuhaiin_core::DomainName::new("example.test").unwrap());
        monitor.opened(flow, context);

        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["addr"], "example.test:443");
        assert_eq!(connection["destination"], "example.test:443");
    }

    #[test]
    fn monitor_persists_totals_and_history_through_the_config_store() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = ConfigStore::open_memory().await.unwrap();
            let monitor = ConnectionMonitor::load_with_store(store.clone())
                .await
                .unwrap();
            let (flow, context) = flow();
            monitor.opened(flow, context);
            monitor.bytes(flow.key, TunFlowDirection::Upload, 13);
            monitor.closed(flow.key);
            monitor.shutdown().await.unwrap();

            let reloaded = ConnectionMonitor::load_with_store(store).await.unwrap();
            assert_eq!(reloaded.total_flow_value()["upload"], "13");
            let now = unix_seconds();
            assert_eq!(
                reloaded.telemetry_value_range(now - 3_600, now + 3_600, 10)["groups"]
                    .as_array()
                    .unwrap()
                    .len(),
                GO_TELEMETRY_DIMENSIONS.len()
            );
            assert_eq!(
                reloaded.all_history_value()["items"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            reloaded.shutdown().await.unwrap();
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_history_callback_does_not_wait_for_the_store_lock() {
        let path = monitor_test_database_path();
        remove_monitor_test_database(&path);
        let store = ConfigStore::open(&path).await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
        monitor.shutdown().await.unwrap();

        let lock_path = PathBuf::from(format!("{}-yuhaiin-write-lock", path.display()));
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        lock.lock().unwrap();

        let callback_monitor = monitor.clone();
        let callback = std::thread::spawn(move || {
            callback_monitor.record_failure("http", "example.com:443", "database busy");
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            callback.is_finished(),
            "failure callback must not synchronously wait for SQLite"
        );
        drop(lock);
        callback.join().unwrap();
        remove_monitor_test_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn monitor_shutdown_does_not_wait_for_the_store_lock() {
        let path = monitor_test_database_path();
        remove_monitor_test_database(&path);
        let store = ConfigStore::open(&path).await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
        let lock_path = PathBuf::from(format!("{}-yuhaiin-write-lock", path.display()));
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        lock.lock().unwrap();

        monitor.record_failure("http", "example.com:443", "database busy");
        let result = tokio::time::timeout(Duration::from_secs(1), monitor.shutdown())
            .await
            .expect("monitor shutdown must not wait for SQLite lock");
        assert!(result.is_err());
        drop(lock);
        remove_monitor_test_database(&path);
    }

    #[tokio::test]
    async fn failed_history_checkpoint_keeps_all_failures() {
        let store = ConfigStore::open_memory().await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store.clone())
            .await
            .unwrap();
        let expected = 1_280;
        for _ in 0..expected {
            monitor.record_failure("http", "example.com:443", "connection refused");
        }

        monitor.shutdown().await.unwrap();
        let statistics = store.load_go_statistics().unwrap();
        assert_eq!(statistics.failed_history.len(), 1);
        assert_eq!(statistics.failed_history[0].count, expected as u64);
    }

    #[tokio::test]
    async fn monitor_projects_go_statistics_for_an_independent_reader_before_shutdown() {
        let path = monitor_test_database_path();
        remove_monitor_test_database(&path);
        let writer_store = ConfigStore::open(&path).await.unwrap();
        let reader_store = ConfigStore::open(&path).await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(writer_store)
            .await
            .unwrap();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 23);
        monitor.closed(flow.key);

        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let statistics = reader_store.load_go_statistics().unwrap();
                if statistics.total_upload == 23 && statistics.history.len() == 1 {
                    break statistics;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("independent reader should observe the runtime Go projection");
        assert_eq!(observed.total_upload, 23);
        assert_eq!(observed.history[0].count, 1);

        monitor.shutdown().await.unwrap();
        drop(reader_store);
        remove_monitor_test_database(&path);
    }

    #[tokio::test]
    async fn monitor_flushes_incremental_statistics_on_the_next_interval() {
        let store = ConfigStore::open_memory().await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store.clone())
            .await
            .unwrap();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 13);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store.load_go_statistics().unwrap().total_upload == 13 {
                    if store.get_config(PERSISTENCE_KEY).await.unwrap().is_none() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initial checkpoint should be written");

        monitor.bytes(flow.key, TunFlowDirection::Upload, 17);
        tokio::time::timeout(
            PERSISTENCE_CHECKPOINT_INTERVAL + Duration::from_secs(1),
            async {
                loop {
                    if store.load_go_statistics().unwrap().total_upload == 30 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            },
        )
        .await
        .expect("dirty update should be persisted on the next interval");
        monitor.shutdown().await.unwrap();
    }

    #[test]
    fn monitor_force_abort_child() {
        let Some(path) = std::env::var_os("YUHAIIN_RUNTIME_MONITOR_CRASH_CHILD_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = ConfigStore::open(&path).await.unwrap();
            let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
            let (flow, context) = flow();
            monitor.opened(flow, context);
            monitor.bytes(flow.key, TunFlowDirection::Upload, 29);
            monitor.closed(flow.key);
            monitor.record_failure("tcp", "resolver.example:443", "selected tcp node not found");

            // Keep the process alive so the parent can kill it before any
            // graceful monitor shutdown or Drop-based cleanup can run.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
    }

    #[test]
    fn monitor_recovers_checkpoint_after_force_abort() {
        let path = monitor_test_database_path();
        remove_monitor_test_database(&path);
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("monitor::tests::monitor_force_abort_child")
            .arg("--nocapture")
            .env("YUHAIIN_RUNTIME_MONITOR_CRASH_CHILD_PATH", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        // The persistence worker's first interval tick is immediate; this
        // leaves enough time for the checkpoint write while still ensuring
        // the child is terminated far before its ten-second sleep ends.
        std::thread::sleep(Duration::from_millis(700));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success(), "crash child must not exit gracefully");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = ConfigStore::open(&path).await.unwrap();
            let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
            assert_eq!(monitor.total_flow_value()["upload"], "29");
            assert_eq!(monitor.all_history_value()["items"][0]["count"], "1");
            let go_statistics = monitor
                .persistence
                .as_ref()
                .unwrap()
                .store
                .load_go_statistics()
                .unwrap();
            assert_eq!(go_statistics.total_upload, 29);
            assert_eq!(go_statistics.history[0].count, 1);
            assert_eq!(go_statistics.failed_history[0].count, 1);
            assert_eq!(go_statistics.failed_history[0].host, "resolver.example:443");
            monitor.shutdown().await.unwrap();
        });
        remove_monitor_test_database(&path);
    }

    #[test]
    fn monitor_takes_over_go_statistics_when_runtime_checkpoint_is_absent() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = ConfigStore::open_memory().await.unwrap();
            let observed_store = store.clone();
            store
                .replace_go_statistics(&GoStatisticsSnapshot {
                    total_download: 23,
                    total_upload: 19,
                    history: vec![GoConnectionHistoryRecord {
                        protocol: "tcp".to_owned(),
                        addr: "203.0.113.10:443".to_owned(),
                        process: "/usr/bin/browser".to_owned(),
                        count: 4,
                        last_seen: 1_700_000_000,
                        connection_json: br#"{
                            "network":{"connType":"tcp"},
                            "addr":"203.0.113.10:443",
                            "process":"/usr/bin/browser"
                        }"#
                        .to_vec(),
                    }],
                    ..GoStatisticsSnapshot::default()
                })
                .unwrap();

            let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
            assert_eq!(monitor.total_flow_value()["download"], "23");
            assert_eq!(monitor.total_flow_value()["upload"], "19");
            assert_eq!(monitor.all_history_value()["items"][0]["count"], "4");
            assert_eq!(monitor.all_history_value()["dumpProcessEnabled"], true);
            assert!(
                monitor.all_history_value()["items"][0]["connection"]
                    .get(INTERNAL_GO_PROTOCOL_KEY)
                    .is_none()
            );
            assert!(
                monitor.all_history_value()["items"][0]["connection"]
                    .get("protocol")
                    .is_none()
            );
            monitor.shutdown().await.unwrap();
            assert_eq!(
                observed_store.load_go_statistics().unwrap().history[0].protocol,
                "tcp"
            );
        });
    }

    #[tokio::test]
    async fn monitor_migrates_legacy_runtime_blob_into_go_tables_once() {
        let store = ConfigStore::open_memory().await.unwrap();
        let bucket = 1_700_000_000;
        let persisted = PersistedMonitor {
            version: PERSISTENCE_VERSION,
            next_id: 9,
            total_upload: 7,
            total_download: 11,
            counters: BTreeMap::new(),
            buckets: BTreeMap::from([(bucket, (11, 7))]),
            telemetry: vec![],
            telemetry_buckets: vec![PersistedTelemetryBucket {
                bucket,
                span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
                dimension: "protocol".to_owned(),
                value: "tcp".to_owned(),
                download: 11,
                upload: 7,
                failures: 0,
            }],
            history: vec![json!({
                "connection": {"protocol": "tcp", "addr": "example.com:443"},
                "count": "2",
                "time": "2024-01-01T00:00:00Z"
            })],
            failed_history: vec![],
            block_history: vec![],
        };
        store
            .put_config(PERSISTENCE_KEY, &serde_json::to_vec(&persisted).unwrap())
            .await
            .unwrap();

        let monitor = ConnectionMonitor::load_with_store(store.clone())
            .await
            .unwrap();
        assert_eq!(monitor.total_flow_value()["upload"], "7");
        assert_eq!(monitor.all_history_value()["items"][0]["count"], "2");
        assert!(store.get_config(PERSISTENCE_KEY).await.unwrap().is_none());
        let statistics = store.load_go_statistics().unwrap();
        assert_eq!(statistics.total_upload, 7);
        assert_eq!(statistics.history[0].count, 2);
        monitor.shutdown().await.unwrap();
    }
}
