//! Runtime-owned connection and traffic monitor.
//!
//! The monitor is intentionally independent from SQLite. Active flows are
//! process state, while totals and time buckets are cheap in-memory counters;
//! the existing store remains responsible for configuration and durable
//! migration state. All callbacks are synchronous so packet processing never
//! waits for an HTTP/SSE consumer.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Notify, broadcast};

use yuhaiin_core::tun::{TunFlow, TunFlowDirection, TunFlowKey, TunFlowObserver};
use yuhaiin_core::{Endpoint, FlowContext, RouteMode};
use yuhaiin_store::ConfigStore;

const HISTORY_LIMIT: usize = 2048;
const BUCKET_LIMIT: usize = 90 * 24 * 60;
const PERSISTENCE_KEY: &str = "statistics.runtime";
const PERSISTENCE_VERSION: u32 = 1;

const TELEMETRY_DIMENSIONS: [&str; 9] = [
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
    history: Vec<Value>,
    failed_history: BTreeMap<(String, String, String), FailedEntry>,
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
struct PersistedTelemetry {
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
    history: Vec<Value>,
    failed_history: Vec<FailedEntry>,
}

#[derive(Clone)]
pub struct ConnectionMonitor {
    state: Arc<Mutex<MonitorState>>,
    events: broadcast::Sender<MonitorEvent>,
    persistence: Option<Arc<Notify>>,
}

impl Default for ConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMonitor {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            state: Arc::new(Mutex::new(MonitorState::default())),
            events,
            persistence: None,
        }
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
        }

        let notify = Arc::new(Notify::new());
        let mut persistent = monitor.clone();
        persistent.persistence = Some(notify.clone());
        let writer_monitor = persistent.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = notify.notified() => {},
                    _ = interval.tick() => {},
                }
                let value = writer_monitor.persisted_json();
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    let _ = store.put_config(PERSISTENCE_KEY, &bytes).await;
                }
            }
        });
        Ok(persistent)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
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
        let interval = match interval {
            "day" => "day",
            "month" => "month",
            _ => "hour",
        };
        let step = match interval {
            "day" => 86_400,
            "month" => 2_592_000,
            _ => 3_600,
        };
        let now = unix_seconds();
        let end = parse_time(to).unwrap_or(now);
        let start = parse_time(from).unwrap_or(end.saturating_sub(step * 24));
        let start = start.min(end);
        let first = start.div_euclid(step) * step;
        let last = end.div_euclid(step) * step;
        let state = self.lock();
        let mut items = Vec::new();
        let mut cursor = first;
        while cursor <= last && items.len() < 10_000 {
            let (download, upload) = state
                .buckets
                .iter()
                .filter(|(bucket, _)| **bucket >= cursor && **bucket < cursor + step)
                .fold((0_u64, 0_u64), |(download, upload), (_, (down, up))| {
                    (download.saturating_add(*down), upload.saturating_add(*up))
                });
            items.push(json!({
                "start": format_time(cursor),
                "download": download.to_string(),
                "upload": upload.to_string(),
            }));
            cursor = cursor.saturating_add(step);
            if cursor == i64::MAX {
                break;
            }
        }
        json!({"interval": interval, "items": items})
    }

    pub fn telemetry_value(&self) -> Value {
        let state = self.lock();
        let mut dimensions: BTreeMap<&str, BTreeMap<String, (u64, u64, u64)>> = BTreeMap::new();
        for ((dimension, value), (download, upload, failures)) in &state.telemetry {
            let item = dimensions
                .entry(dimension.as_str())
                .or_default()
                .entry(value.clone())
                .or_default();
            item.0 = item.0.saturating_add(*download);
            item.1 = item.1.saturating_add(*upload);
            item.2 = item.2.saturating_add(*failures);
        }
        let groups = dimensions
            .into_iter()
            .map(|(dimension, items)| {
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
        json!({"items": state.history, "dumpProcessEnabled": false})
    }

    pub fn initial_event(&self) -> MonitorEvent {
        MonitorEvent {
            kind: "connections_added".to_owned(),
            payload: self.connections_value(),
        }
    }

    pub fn request_close(&self, ids: &[String]) -> usize {
        let mut state = self.lock();
        let mut count = 0;
        for id in ids {
            let Some(flow) = state.ids.get(id).copied() else {
                continue;
            };
            if !state.close_requests.contains(&flow) {
                state.close_requests.push(flow);
                count += 1;
            }
        }
        count
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
        for dimension in TELEMETRY_DIMENSIONS {
            let value = object
                .get(dimension)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("unknown")
                .to_owned();
            let item = state
                .telemetry
                .entry((dimension.to_owned(), value))
                .or_default();
            match direction {
                TunFlowDirection::Upload => item.1 = item.1.saturating_add(bytes),
                TunFlowDirection::Download => item.0 = item.0.saturating_add(bytes),
            }
        }
        drop(state);
        self.mark_dirty();
    }

    fn close(&self, flow: TunFlowKey) {
        let mut state = self.lock();
        let Some(entry) = state.connections.remove(&flow) else {
            return;
        };
        state.ids.remove(&entry.id);
        state.close_requests.retain(|pending| *pending != flow);
        state.history.push(json!({
            "connection": entry.value,
            "count": "1",
            "time": format_time(unix_seconds()),
        }));
        if state.history.len() > HISTORY_LIMIT {
            let excess = state.history.len() - HISTORY_LIMIT;
            state.history.drain(..excess);
        }
        let id = entry.id;
        drop(state);
        self.mark_dirty();
        self.emit("connections_removed", json!({"ids": [id]}));
    }

    fn mark_dirty(&self) {
        if let Some(notify) = self.persistence.as_ref() {
            notify.notify_one();
        }
    }

    fn restore_persisted(&self, persisted: PersistedMonitor) {
        let mut state = self.lock();
        state.next_id = persisted.next_id;
        state.total_upload = persisted.total_upload;
        state.total_download = persisted.total_download;
        state.counters = persisted.counters;
        state.buckets = persisted.buckets;
        state.history = persisted.history;
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
        state.telemetry = persisted
            .telemetry
            .into_iter()
            .map(|entry| {
                (
                    (entry.dimension, entry.value),
                    (entry.download, entry.upload, entry.failures),
                )
            })
            .collect();
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
            history: state.history.clone(),
            failed_history: state.failed_history.values().cloned().collect(),
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
    let inbound = context.inbound.as_deref().unwrap_or("tun");
    let inbound_name = context.inbound_name.as_deref().unwrap_or("TUN");
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
        "interface": "",
        "outbound": outbound,
        "localAddr": source,
        "destination": original,
        "fakeIp": "",
        "hosts": "",
        "domain": domain,
        "ip": context.destination.addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
        "tag": "",
        "nodeId": context.outbound.as_deref().unwrap_or_default(),
        "nodeName": context.outbound_name.as_deref().unwrap_or_default(),
        "protocol": flow.key.network.to_string(),
        "process": "",
        "pid": "",
        "uid": "",
        "tlsServerName": "",
        "httpHost": "",
        "component": "tun",
        "udpMigrateId": context.udp_migrate_id.load(std::sync::atomic::Ordering::Relaxed).to_string(),
        "mode": route_mode(context.route_mode),
        "matchHistory": [],
        "resolver": "",
        "geo": "",
        "outboundGeo": "",
        "lists": [],
    })
}

fn endpoint_string(endpoint: &Endpoint) -> String {
    endpoint.to_string()
}

fn route_mode(mode: RouteMode) -> &'static str {
    match mode {
        RouteMode::Bypass => "bypass",
        RouteMode::Proxy => "proxy",
        RouteMode::Direct => "direct",
        RouteMode::Block => "block",
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::{Endpoint, Network};

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
            monitor.total_flow_value()["counters"]["1"]["download"],
            "11"
        );
        assert_eq!(
            monitor.telemetry_value()["groups"]
                .as_array()
                .unwrap()
                .len(),
            9
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
    fn monitor_preserves_close_requests_until_data_plane_consumes_them() {
        let monitor = ConnectionMonitor::new();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        assert_eq!(monitor.request_close(&["1".to_owned()]), 1);
        assert_eq!(monitor.take_close_requests(), vec![flow.key]);
        assert!(monitor.take_close_requests().is_empty());
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
            tokio::time::sleep(Duration::from_millis(20)).await;

            let reloaded = ConnectionMonitor::load_with_store(store).await.unwrap();
            assert_eq!(reloaded.total_flow_value()["upload"], "13");
            assert_eq!(
                reloaded.all_history_value()["items"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        });
    }
}
