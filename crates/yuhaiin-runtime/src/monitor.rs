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
use tokio::sync::{Mutex as AsyncMutex, Notify, broadcast, watch};

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver,
};
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, RouteMode};
use yuhaiin_store::{
    ConfigStore, GoConnectionHistoryRecord, GoFailedHistoryRecord, GoStatisticsSnapshot,
    GoTelemetryBucketRecord, GoTrafficBucketRecord,
};

use crate::RuntimeLog;

const HISTORY_LIMIT: usize = 2048;
const BUCKET_LIMIT: usize = 90 * 24 * 60;
const GO_STATISTICS_PROJECTION_INTERVAL: Duration = Duration::from_secs(30);
const GO_STATISTICS_PROJECTION_RETRY_INITIAL: Duration = Duration::from_secs(2);
const GO_STATISTICS_PROJECTION_RETRY_MAX: Duration = Duration::from_secs(60);
const PERSISTENCE_KEY: &str = "statistics.runtime";
const PERSISTENCE_VERSION: u32 = 1;

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
    upload: u64,
    download: u64,
}

struct PersistenceState {
    store: ConfigStore,
    dirty: Arc<Notify>,
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
    telemetry_buckets: BTreeMap<(i64, String, String), (u64, u64, u64)>,
    history: Vec<Value>,
    failed_history: BTreeMap<(String, String, String), FailedEntry>,
    block_history: BTreeMap<(String, String, String), BlockEntry>,
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
    dimension: String,
    value: String,
    download: u64,
    upload: u64,
    failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub(crate) fn socket_dns_handler(&self) -> Option<Arc<dyn SocketDnsHandler>> {
        self.dns_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) async fn answer_dns(&self, packet: &[u8]) -> Option<yuhaiin_core::Result<Vec<u8>>> {
        let handler = self
            .dns_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()?;
        Some(handler.answer(packet).await)
    }

    /// Load durable totals/history from the same SQLite store as the
    /// configuration and periodically flush the in-memory counters back to
    /// it. Active connections are deliberately not restored: a process
    /// restart cannot prove that those sockets still exist.
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
            monitor.restore_persisted(persisted);
        } else {
            let statistics = store.load_go_statistics()?;
            monitor.restore_go_statistics(statistics)?;
        }

        let dirty = Arc::new(Notify::new());
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let persistence = Arc::new(PersistenceState {
            store,
            dirty,
            shutdown,
            worker: AsyncMutex::new(None),
        });
        let mut persistent = monitor.clone();
        persistent.persistence = Some(persistence.clone());
        let writer_monitor = persistent.clone();
        let worker_persistence = persistence.clone();
        let worker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            let mut last_go_projection = Instant::now();
            let mut project_go_statistics = true;
            let mut next_go_projection = Instant::now();
            let mut projection_backoff = GO_STATISTICS_PROJECTION_RETRY_INITIAL;
            loop {
                tokio::select! {
                    _ = worker_persistence.dirty.notified() => {},
                    _ = interval.tick() => {},
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
                let value = writer_monitor.persisted_json();
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    let checkpoint_written = worker_persistence
                        .store
                        .put_config(PERSISTENCE_KEY, &bytes)
                        .await
                        .is_ok();
                    let projection_due =
                        project_go_statistics && Instant::now() >= next_go_projection;
                    if checkpoint_written
                        && (projection_due
                            || last_go_projection.elapsed() >= GO_STATISTICS_PROJECTION_INTERVAL)
                    {
                        // Keep the compact checkpoint as the crash-recovery
                        // path, but refresh Go's public tables infrequently so
                        // another Go/Rust management process can observe
                        // recent totals without rewriting the tables per flow.
                        if worker_persistence
                            .store
                            .replace_go_statistics(&writer_monitor.go_statistics_snapshot())
                            .is_ok()
                        {
                            last_go_projection = Instant::now();
                            project_go_statistics = false;
                            next_go_projection =
                                last_go_projection + GO_STATISTICS_PROJECTION_INTERVAL;
                            projection_backoff = GO_STATISTICS_PROJECTION_RETRY_INITIAL;
                        } else {
                            project_go_statistics = true;
                            next_go_projection = Instant::now() + projection_backoff;
                            projection_backoff = next_projection_backoff(projection_backoff);
                        }
                    }
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
        let bytes = serde_json::to_vec(&self.persisted_json()).map_err(|error| {
            yuhaiin_core::Error::new(
                yuhaiin_core::ErrorKind::Storage,
                format!("statistics state serialization: {error}"),
            )
        })?;
        persistence
            .store
            .put_config(PERSISTENCE_KEY, &bytes)
            .await?;
        persistence
            .store
            .replace_go_statistics(&self.go_statistics_snapshot())
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
        let state = self.lock();
        let mut buckets = BTreeMap::<i64, (u64, u64)>::new();
        for (bucket, (download, upload)) in &state.buckets {
            if *bucket < start || *bucket >= end {
                continue;
            }
            let group = traffic_bucket_start(interval, *bucket);
            let entry = buckets.entry(group).or_default();
            entry.0 = entry.0.saturating_add(*download);
            entry.1 = entry.1.saturating_add(*upload);
        }
        let items = buckets
            .into_iter()
            .take(10_000)
            .map(|(bucket, (download, upload))| {
                json!({
                "start": format_time(bucket),
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
        let state = self.lock();
        let mut dimensions: BTreeMap<String, BTreeMap<String, (u64, u64, u64)>> = BTreeMap::new();
        if state.telemetry_buckets.is_empty() {
            for ((dimension, value), (download, upload, failures)) in &state.telemetry {
                dimensions
                    .entry(dimension.clone())
                    .or_default()
                    .insert(value.clone(), (*download, *upload, *failures));
            }
        } else {
            for ((bucket, dimension, value), (download, upload, failures)) in
                &state.telemetry_buckets
            {
                if *bucket < from || *bucket >= to {
                    continue;
                }
                let item = dimensions
                    .entry(dimension.clone())
                    .or_default()
                    .entry(value.clone())
                    .or_default();
                item.0 = item.0.saturating_add(*download);
                item.1 = item.1.saturating_add(*upload);
                item.2 = item.2.saturating_add(*failures);
            }
        }
        let groups = dimensions
            .into_iter()
            .map(|(dimension, items)| {
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
            })
            .collect::<Vec<_>>();
        json!({"groups": groups})
    }

    pub fn failed_history_value(&self) -> Value {
        let state = self.lock();
        let mut items = state
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
        items.sort_by(|left, right| {
            right
                .get("time")
                .and_then(Value::as_str)
                .cmp(&left.get("time").and_then(Value::as_str))
        });
        json!({
            "items": items,
            "dumpProcessEnabled": state.failed_history.values().any(|entry| !entry.process.is_empty()),
        })
    }

    pub fn all_history_value(&self) -> Value {
        let state = self.lock();
        let mut items = coalesce_history(state.history.clone());
        items.sort_by(|left, right| {
            history_time(right)
                .cmp(&history_time(left))
                .then_with(|| history_key(left).cmp(&history_key(right)))
        });
        json!({
            "items": items,
            "dumpProcessEnabled": items.iter().any(|item| {
                item.get("connection")
                    .and_then(|connection| connection.get("process"))
                    .and_then(Value::as_str)
                    .is_some_and(|process| !process.is_empty())
            }),
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
        json!({"items": items, "dumpProcessEnabled": false})
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
        let mut state = self.lock();
        let key = (protocol.to_owned(), host.to_owned(), String::new());
        let entry = state
            .failed_history
            .entry(key)
            .or_insert_with(|| FailedEntry {
                protocol: protocol.to_owned(),
                host: host.to_owned(),
                process: String::new(),
                error: error.to_owned(),
                time: unix_seconds(),
                count: 0,
            });
        entry.count = entry.count.saturating_add(1);
        entry.error = error.to_owned();
        entry.time = unix_seconds();
        let bucket = entry.time.div_euclid(3600) * 3600;
        let connection = json!({
            "network": {"connType": protocol},
            "addr": host,
            "destination": host,
        });
        for (dimension, value) in telemetry_dimensions(&connection) {
            let item = state
                .telemetry
                .entry((dimension.clone(), value.clone()))
                .or_default();
            item.2 = item.2.saturating_add(1);
            let item = state
                .telemetry_buckets
                .entry((bucket, dimension, value))
                .or_default();
            item.2 = item.2.saturating_add(1);
        }
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

    fn emit(&self, kind: &str, payload: Value) {
        let _ = self.events.send(MonitorEvent {
            kind: kind.to_owned(),
            payload,
        });
    }

    fn open(&self, flow: TunFlow, context: FlowContext) {
        let mut state = self.lock();
        if state.connections.contains_key(&flow.key) {
            return;
        }
        state.next_id = state.next_id.saturating_add(1);
        let id = state.next_id.to_string();
        let value = connection_value(&id, flow, &context);
        state.ids.insert(id.clone(), flow.key);
        state.counters.entry(id.clone()).or_default();
        state.connections.insert(
            flow.key,
            ConnectionEntry {
                id,
                value: value.clone(),
                upload: 0,
                download: 0,
            },
        );
        drop(state);
        self.mark_dirty();
        self.emit("connections_added", json!({"connections": [value]}));
    }

    fn add_bytes(&self, flow: TunFlowKey, direction: TunFlowDirection, bytes: usize) {
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
        let now = unix_seconds().div_euclid(60) * 60;
        let bucket = state.buckets.entry(now).or_default();
        match direction {
            TunFlowDirection::Upload => bucket.1 = bucket.1.saturating_add(bytes),
            TunFlowDirection::Download => bucket.0 = bucket.0.saturating_add(bytes),
        }
        while state.buckets.len() > BUCKET_LIMIT {
            let Some(first) = state.buckets.first_key_value().map(|(key, _)| *key) else {
                break;
            };
            state.buckets.remove(&first);
        }
        let Some(id) = state.connections.get(&flow).map(|entry| entry.id.clone()) else {
            drop(state);
            self.mark_dirty();
            return;
        };
        let object = state
            .connections
            .get(&flow)
            .and_then(|entry| entry.value.as_object())
            .cloned();
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
        let counter = state.counters.entry(id).or_default();
        match direction {
            TunFlowDirection::Upload => counter.1 = counter.1.saturating_add(bytes),
            TunFlowDirection::Download => counter.0 = counter.0.saturating_add(bytes),
        }
        let Some(object) = object else {
            drop(state);
            self.mark_dirty();
            return;
        };
        for (dimension, value) in telemetry_dimensions(&Value::Object(object)) {
            let item = state
                .telemetry
                .entry((dimension.clone(), value.clone()))
                .or_default();
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
            let item = state
                .telemetry_buckets
                .entry((now.div_euclid(3600) * 3600, dimension, value))
                .or_default();
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
        }
        let telemetry_cutoff = now.saturating_sub(90 * 86_400);
        while state
            .telemetry_buckets
            .first_key_value()
            .is_some_and(|((bucket, _, _), _)| *bucket < telemetry_cutoff)
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
        drop(state);
        self.mark_dirty();
    }

    fn close(&self, flow: TunFlowKey) {
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
        state.ids.remove(&entry.id);
        state.close_requests.retain(|pending| *pending != flow);
        let now = unix_seconds();
        let key = history_key(&json!({"connection": entry.value.clone()}));
        if let Some(existing) = state
            .history
            .iter_mut()
            .find(|item| history_key(item) == key)
        {
            let count = existing
                .get("count")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_add(1);
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
        let id = entry.id;
        drop(state);
        self.mark_dirty();
        self.emit("connections_removed", json!({"ids": [id]}));
    }

    fn mark_dirty(&self) {
        if let Some(persistence) = self.persistence.as_ref() {
            persistence.dirty.notify_one();
        }
    }

    fn restore_persisted(&self, persisted: PersistedMonitor) {
        let mut state = self.lock();
        state.next_id = persisted.next_id;
        state.total_upload = persisted.total_upload;
        state.total_download = persisted.total_download;
        // Active sockets are intentionally not restored after a process
        // restart, so counters from an older checkpoint cannot describe a
        // live connection. Keep deserializing the legacy field for v1 file
        // compatibility, but start the live counter map empty like Go.
        state.counters.clear();
        state.buckets = persisted.buckets;
        state.history = coalesce_history(persisted.history);
        state.failed_history = persisted
            .failed_history
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
        state.telemetry = persisted
            .telemetry
            .into_iter()
            .map(|entry| {
                let value = normalize_persisted_telemetry_value(&entry.dimension, entry.value);
                (
                    (entry.dimension, value),
                    (entry.download, entry.upload, entry.failures),
                )
            })
            .collect();
        state.telemetry_buckets = persisted
            .telemetry_buckets
            .into_iter()
            .map(|entry| {
                let value = normalize_persisted_telemetry_value(&entry.dimension, entry.value);
                (
                    (entry.bucket, entry.dimension, value),
                    (entry.download, entry.upload, entry.failures),
                )
            })
            .collect();
    }

    fn restore_go_statistics(&self, persisted: GoStatisticsSnapshot) -> yuhaiin_core::Result<()> {
        let mut state = self.lock();
        state.total_upload = persisted.total_upload;
        state.total_download = persisted.total_download;
        for bucket in persisted.traffic {
            let entry = state.buckets.entry(bucket.bucket).or_default();
            entry.0 = entry.0.saturating_add(bucket.download);
            entry.1 = entry.1.saturating_add(bucket.upload);
        }
        let history = persisted
            .history
            .into_iter()
            .filter_map(|history| {
                let connection = serde_json::from_slice::<Value>(&history.connection_json).ok()?;
                Some(json!({
                    "connection": connection,
                    "count": history.count.to_string(),
                    "time": format_time(history.last_seen),
                }))
            })
            .collect();
        state.history = coalesce_history(history);
        state.history.sort_by_key(history_time);
        if state.history.len() > HISTORY_LIMIT {
            let excess = state.history.len() - HISTORY_LIMIT;
            state.history.drain(..excess);
        }
        for failure in persisted.failed_history {
            state.failed_history.insert(
                (
                    failure.protocol.clone(),
                    failure.host.clone(),
                    failure.process.clone(),
                ),
                FailedEntry {
                    protocol: failure.protocol,
                    host: failure.host,
                    process: failure.process,
                    error: failure.error,
                    time: failure.last_seen,
                    count: failure.count,
                },
            );
        }
        for item in persisted.telemetry {
            let value = normalize_persisted_telemetry_value(&item.dimension, item.value);
            let aggregate = state
                .telemetry
                .entry((item.dimension.clone(), value.clone()))
                .or_default();
            aggregate.0 = aggregate.0.saturating_add(item.download);
            aggregate.1 = aggregate.1.saturating_add(item.upload);
            aggregate.2 = aggregate.2.saturating_add(item.failures);
            let bucket = state
                .telemetry_buckets
                .entry((item.bucket, item.dimension, value))
                .or_default();
            bucket.0 = bucket.0.saturating_add(item.download);
            bucket.1 = bucket.1.saturating_add(item.upload);
            bucket.2 = bucket.2.saturating_add(item.failures);
        }
        Ok(())
    }

    fn go_statistics_snapshot(&self) -> GoStatisticsSnapshot {
        let state = self.lock();
        let mut traffic = BTreeMap::<i64, (u64, u64)>::new();
        for (bucket, (download, upload)) in &state.buckets {
            let hour = bucket.div_euclid(3_600) * 3_600;
            let entry = traffic.entry(hour).or_default();
            entry.0 = entry.0.saturating_add(*upload);
            entry.1 = entry.1.saturating_add(*download);
        }
        GoStatisticsSnapshot {
            total_download: state.total_download,
            total_upload: state.total_upload,
            traffic: traffic
                .into_iter()
                .map(|(bucket, (upload, download))| GoTrafficBucketRecord {
                    bucket,
                    upload,
                    download,
                })
                .collect(),
            history: coalesce_history(state.history.clone())
                .iter()
                .filter_map(|item| {
                    let connection = item.get("connection")?;
                    Some(GoConnectionHistoryRecord {
                        protocol: connection
                            .get("protocol")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
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
                        connection_json: serde_json::to_vec(connection).ok()?,
                    })
                })
                .collect(),
            failed_history: state
                .failed_history
                .values()
                .map(|entry| GoFailedHistoryRecord {
                    protocol: entry.protocol.clone(),
                    host: entry.host.clone(),
                    process: entry.process.clone(),
                    count: entry.count,
                    last_seen: entry.time,
                    error: entry.error.clone(),
                })
                .collect(),
            telemetry: state
                .telemetry_buckets
                .iter()
                .map(
                    |((bucket, dimension, value), (download, upload, failures))| {
                        GoTelemetryBucketRecord {
                            bucket: *bucket,
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

    fn persisted_json(&self) -> PersistedMonitor {
        let state = self.lock();
        PersistedMonitor {
            version: PERSISTENCE_VERSION,
            next_id: state.next_id,
            total_upload: state.total_upload,
            total_download: state.total_download,
            counters: state.counters.clone(),
            buckets: state.buckets.clone(),
            telemetry: state
                .telemetry
                .iter()
                .map(
                    |((dimension, value), (download, upload, failures))| PersistedTelemetry {
                        dimension: dimension.clone(),
                        value: value.clone(),
                        download: *download,
                        upload: *upload,
                        failures: *failures,
                    },
                )
                .collect(),
            telemetry_buckets: state
                .telemetry_buckets
                .iter()
                .map(
                    |((bucket, dimension, value), (download, upload, failures))| {
                        PersistedTelemetryBucket {
                            bucket: *bucket,
                            dimension: dimension.clone(),
                            value: value.clone(),
                            download: *download,
                            upload: *upload,
                            failures: *failures,
                        }
                    },
                )
                .collect(),
            history: coalesce_history(state.history.clone()),
            failed_history: state.failed_history.values().cloned().collect(),
            block_history: state.block_history.values().cloned().collect(),
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

    fn close_requested(&self, flow: TunFlowKey) -> bool {
        self.close_requested(flow)
    }
}

fn connection_value(id: &str, flow: TunFlow, context: &FlowContext) -> Value {
    let destination = endpoint_string(&context.effective_destination());
    let original = endpoint_string(&flow.key.endpoint());
    let source = endpoint_string(&flow.key.source_endpoint());
    let domain = context
        .original_domain
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let is_tun = context.component.as_deref() == Some("tun");
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
        .outbound
        .as_deref()
        .unwrap_or_else(|| route_mode(context.route_mode));
    json!({
        "id": id,
        "addr": destination,
        "network": {"connType": flow.key.network.to_string(), "underlyingType": ""},
        "source": source,
        "inbound": inbound,
        "inboundName": inbound_name,
        "interface": context.interface.as_deref().unwrap_or_default(),
        "outbound": outbound,
        "localAddr": source,
        "destination": original,
        "fakeIp": context.fake_ip.as_deref().unwrap_or_default(),
        "hosts": context.hosts.as_deref().unwrap_or_default(),
        "domain": domain,
        "ip": context.destination.addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
        "tag": context.tag.as_deref().unwrap_or_default(),
        "nodeId": context.outbound.as_deref().unwrap_or_default(),
        "nodeName": context.outbound_name.as_deref().unwrap_or_default(),
        "protocol": flow.key.network.to_string(),
        "process": context.process.as_deref().unwrap_or_default(),
        "pid": context.process_id.map(|value| value.to_string()).unwrap_or_default(),
        "uid": context.user_id.map(|value| value.to_string()).unwrap_or_default(),
        "tlsServerName": context.tls_server_name.as_deref().unwrap_or_default(),
        "httpHost": context.http_host.as_deref().unwrap_or_default(),
        "component": context.component.as_deref().unwrap_or_default(),
        "udpMigrateId": context.udp_migrate_id.load(std::sync::atomic::Ordering::Relaxed).to_string(),
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

    let mut values = BTreeMap::new();
    for (dimension, value) in [
        ("protocol", protocol.to_owned()),
        ("inbound", inbound),
        ("source", source),
        ("addr", addr),
        ("outbound", outbound),
        ("process", process),
        ("tag", tag),
        ("destination", destination),
    ] {
        if !value.is_empty() {
            values.insert(dimension.to_owned(), value);
        }
    }
    if let Some(rule) = connection
        .get("matchHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|match_value| match_value.get("ruleName").and_then(Value::as_str))
        .filter(|rule| !rule.is_empty())
        .last()
    {
        values.insert("rule".to_owned(), rule.to_owned());
    }
    values.into_iter().collect()
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
    endpoint.to_string()
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

fn next_projection_backoff(current: Duration) -> Duration {
    current
        .saturating_mul(2)
        .min(GO_STATISTICS_PROJECTION_RETRY_MAX)
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn format_time(seconds: i64) -> String {
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
    (
        connection
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
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
    for item in items {
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
            5
        );
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
        context.hosts = Some("hosts".to_owned());
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
    fn go_statistics_projection_backoff_is_bounded_and_doubles() {
        assert_eq!(
            next_projection_backoff(GO_STATISTICS_PROJECTION_RETRY_INITIAL),
            Duration::from_secs(4)
        );
        assert_eq!(
            next_projection_backoff(Duration::from_secs(32)),
            GO_STATISTICS_PROJECTION_RETRY_MAX
        );
        assert_eq!(
            next_projection_backoff(GO_STATISTICS_PROJECTION_RETRY_MAX),
            GO_STATISTICS_PROJECTION_RETRY_MAX
        );
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

    #[test]
    fn monitor_coalesces_duplicate_checkpoint_history_before_go_projection() {
        let monitor = ConnectionMonitor::new();
        {
            let mut state = monitor.lock();
            state.history = vec![
                json!({
                    "connection": {
                        "protocol": "",
                        "addr": "example.com:443",
                        "process": "browser"
                    },
                    "count": "2",
                    "time": "2024-01-01T00:00:00Z"
                }),
                json!({
                    "connection": {
                        "protocol": "",
                        "addr": "example.com:443",
                        "process": "browser"
                    },
                    "count": "3",
                    "time": "2024-01-02T00:00:00Z"
                }),
            ];
        }

        let snapshot = monitor.go_statistics_snapshot();
        assert_eq!(snapshot.history.len(), 1);
        assert_eq!(snapshot.history[0].count, 5);
        assert_eq!(
            monitor.all_history_value()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
    }

    #[test]
    fn monitor_exposes_block_history_in_the_route_contract_shape() {
        let monitor = ConnectionMonitor::new();
        let (flow, mut context) = flow();
        context.route_mode = RouteMode::Block;
        context.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
        monitor.opened(flow, context);
        monitor.closed(flow.key);

        let mut second = FlowContext::new(Endpoint::ip(flow.key.network, flow.key.destination));
        second.route_mode = RouteMode::Block;
        second.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
        monitor.opened(flow, second);
        monitor.closed(flow.key);

        let value = monitor.block_history_value();
        assert_eq!(value["items"][0]["protocol"], "tcp");
        assert_eq!(value["items"][0]["host"], "blocked.example");
        assert_eq!(value["items"][0]["blockCount"], "2");
        assert_eq!(value["dumpProcessEnabled"], false);
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
                5
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
                            "protocol":"tcp",
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
            monitor.shutdown().await.unwrap();
        });
    }
}
