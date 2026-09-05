//! Runtime flow state, persistence scheduling, and monitor-facing operations.

use super::*;

impl ConnectionMonitor {
    pub fn new() -> Self {
        Self::new_with_metrics(Arc::new(doradus_metrics::RuntimeMetrics::new()))
    }

    pub(crate) fn new_with_metrics(metrics: Arc<doradus_metrics::RuntimeMetrics>) -> Self {
        let (events, _) = broadcast::channel(256);
        let (close_events, _) = broadcast::channel(256);
        Self {
            state: Arc::new(Mutex::new(MonitorState::default())),
            traffic: Arc::new(MonitorTraffic::default()),
            sniff_enabled: Arc::new(AtomicBool::new(true)),
            dns_handler: Arc::new(RwLock::new(None)),
            events,
            close_events,
            logs: RuntimeLog::new(),
            persistence: None,
            metrics,
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

    pub(crate) async fn answer_dns(&self, packet: &[u8]) -> Option<doradus_core::Result<Vec<u8>>> {
        let handler = self
            .dns_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()?;
        let target = doradus_core::dns::decode_query(packet)
            .map(|query| format!("{} {:?}", query.domain, query.record_type))
            .unwrap_or_else(|_| format!("packet_len={}", packet.len()));
        let started = Instant::now();
        let result = handler.answer(packet).await;
        self.metrics.dns_query(if result.is_ok() {
            doradus_metrics::ResultKind::Success
        } else {
            doradus_metrics::ResultKind::Failure
        });
        self.metrics
            .dns_query_duration(started.elapsed().as_secs_f64());
        if let Err(error) = &result {
            self.error(format!("DNS query failed target={target}: {error}"));
        }
        Some(result)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
    }

    pub fn logs(&self) -> RuntimeLog {
        self.logs.clone()
    }

    pub(crate) fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.metrics)
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
        let mut total_download = state.total_download;
        let mut total_upload = state.total_upload;
        let mut counters = serde_json::Map::new();
        for shard in self.traffic.shards.iter() {
            let traffic = shard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            total_download = total_download.saturating_add(traffic.total_download);
            total_upload = total_upload.saturating_add(traffic.total_upload);
            counters.extend(traffic.counters.iter().map(|(id, (download, upload))| {
                (
                    id.clone(),
                    json!({
                        "download": download.to_string(),
                        "upload": upload.to_string(),
                    }),
                )
            }));
        }
        json!({
            "download": total_download.to_string(),
            "upload": total_upload.to_string(),
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
            drop(state);
            for shard in self.traffic.shards.iter() {
                let traffic = shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for (bucket, (download, upload)) in &traffic.buckets {
                    if *bucket < start || *bucket >= end {
                        continue;
                    }
                    let group = traffic_bucket_start(interval, *bucket);
                    let entry = buckets.entry(group).or_default();
                    entry.0 = entry.0.saturating_add(*download);
                    entry.1 = entry.1.saturating_add(*upload);
                }
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
            let mut telemetry = state
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
                .collect::<Vec<_>>();
            drop(state);
            for shard in self.traffic.shards.iter() {
                let traffic = shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                telemetry.extend(traffic.telemetry_buckets.iter().map(
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
                ));
            }
            telemetry
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
        self.metrics.connection_failed(FailureStage::Dial);
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

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, MonitorState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn traffic_shard_index(flow: TunFlowKey) -> usize {
        let source = usize::from(flow.source.port());
        let destination = usize::from(flow.destination.port());
        source
            .wrapping_mul(0x9e37)
            .wrapping_add(destination.rotate_left(7))
            % TRAFFIC_SHARD_COUNT
    }

    fn traffic_lock(&self, flow: TunFlowKey) -> std::sync::MutexGuard<'_, MonitorTrafficState> {
        self.traffic.shards[Self::traffic_shard_index(flow)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn durable_snapshot(&self) -> Option<GoStatisticsSnapshot> {
        let store = self.persistence.as_ref()?.store.clone();
        let mut snapshot = store.load_go_statistics().ok()?;
        let delta = {
            let state = self.lock();
            let mut delta = pending_delta_from_state(&state);
            delta.total_download = state.total_download;
            delta.total_upload = state.total_upload;
            for shard in self.traffic.shards.iter() {
                let traffic = shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                delta.total_download = delta.total_download.saturating_add(traffic.total_download);
                delta.total_upload = delta.total_upload.saturating_add(traffic.total_upload);
                delta.traffic.extend(traffic.pending_traffic.iter().map(
                    |(bucket, (download, upload))| GoTrafficBucketRecord {
                        bucket: *bucket,
                        upload: *upload,
                        download: *download,
                    },
                ));
                delta.telemetry.extend(traffic.pending_telemetry.iter().map(
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
                ));
            }
            delta
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

    pub(super) fn open(&self, flow: TunFlow, context: FlowContext) {
        let mut state = self.lock();
        if let Some(entry) = state.connections.get_mut(&flow.key) {
            let update = connection_value(&entry.id, flow, &context);
            let changed = merge_connection_metadata(&mut entry.value, update);
            if changed {
                entry.telemetry = Arc::from(telemetry_dimensions(&entry.value));
                entry.inbound_id = context
                    .inbound_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .map(Arc::<str>::from);
                entry.is_tun = context.component.as_deref() == Some("tun");
                let mut traffic = self.traffic_lock(flow.key);
                if let Some(flow_entry) = traffic.flows.get_mut(&flow.key) {
                    flow_entry.telemetry = Arc::clone(&entry.telemetry);
                    flow_entry.inbound_id = entry.inbound_id.clone();
                    flow_entry.is_tun = entry.is_tun;
                }
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
        let inbound_id = context
            .inbound_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .map(Arc::<str>::from);
        let is_tun = context.component.as_deref() == Some("tun");
        if let Some(inbound_id) = context.inbound_id.clone() {
            let statistics = state.inbound_statistics.entry(inbound_id).or_default();
            match flow.key.network {
                doradus_core::Network::Tcp => {
                    statistics.active_tcp = statistics.active_tcp.saturating_add(1);
                    statistics.total_tcp_flows = statistics.total_tcp_flows.saturating_add(1);
                }
                doradus_core::Network::Udp => {
                    statistics.active_udp = statistics.active_udp.saturating_add(1);
                    statistics.total_udp_flows = statistics.total_udp_flows.saturating_add(1);
                }
                doradus_core::Network::Icmp | doradus_core::Network::Any => {}
            }
        }
        state.ids.insert(id.clone(), flow.key);
        let traffic_entry = TrafficFlowEntry {
            id: id.clone(),
            telemetry: Arc::clone(&telemetry),
            inbound_id: inbound_id.clone(),
            is_tun,
            upload: 0,
            download: 0,
        };
        state.connections.insert(
            flow.key,
            ConnectionEntry {
                id,
                value: value.clone(),
                telemetry,
                inbound_id,
                is_tun,
            },
        );
        drop(state);
        {
            let mut traffic = self.traffic_lock(flow.key);
            traffic
                .counters
                .entry(traffic_entry.id.clone())
                .or_default();
            traffic.flows.insert(flow.key, traffic_entry);
        }
        self.metrics.connection_opened();
        self.mark_dirty();
        self.emit("connections_added", json!({"connections": [value]}));
    }

    pub(super) fn add_bytes(
        &self,
        flow: TunFlowKey,
        direction: TunFlowDirection,
        bytes: usize,
    ) -> bool {
        let persistent = self.persistence.is_some();
        self.metrics.add_traffic(
            match direction {
                TunFlowDirection::Upload => doradus_metrics::Direction::Upload,
                TunFlowDirection::Download => doradus_metrics::Direction::Download,
            },
            bytes as u64,
        );
        let mut state = self.traffic_lock(flow);
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
        let Some((id, inbound_id, is_tun)) = state
            .flows
            .get(&flow)
            .map(|entry| (entry.id.clone(), entry.inbound_id.clone(), entry.is_tun))
        else {
            drop(state);
            self.mark_dirty();
            return false;
        };
        let telemetry = {
            let Some(entry) = state.flows.get_mut(&flow) else {
                drop(state);
                self.mark_dirty();
                return false;
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
        if let Some(inbound_id) = inbound_id {
            let statistics = state
                .inbound_bytes
                .entry(inbound_id.to_string())
                .or_default();
            match direction {
                TunFlowDirection::Upload => {
                    statistics.1 = statistics.1.saturating_add(bytes);
                }
                TunFlowDirection::Download => {
                    statistics.0 = statistics.0.saturating_add(bytes);
                }
            }
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
        is_tun
    }

    pub(super) fn close(&self, flow: TunFlowKey) {
        let persistent = self.persistence.is_some();
        let mut state = self.lock();
        let Some(entry) = state.connections.remove(&flow) else {
            return;
        };
        {
            let mut traffic = self.traffic_lock(flow);
            traffic.flows.remove(&flow);
            traffic.counters.remove(&entry.id);
        }
        self.metrics.connection_closed();
        if let Some(inbound_id) = entry
            .value
            .get("inboundId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            let statistics = state
                .inbound_statistics
                .entry(inbound_id.to_owned())
                .or_default();
            match flow.network {
                doradus_core::Network::Tcp => {
                    statistics.active_tcp = statistics.active_tcp.saturating_sub(1);
                }
                doradus_core::Network::Udp => {
                    statistics.active_udp = statistics.active_udp.saturating_sub(1);
                }
                doradus_core::Network::Icmp | doradus_core::Network::Any => {}
            }
        }
        // Go's `connections.total.counters` is a live-flow view.  The
        // per-connection counter is removed together with the connection;
        // durable totals and history are maintained separately below.
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

    pub(super) fn take_statistics_delta(&self) -> GoStatisticsDelta {
        let mut state = self.lock();
        let mut telemetry = std::mem::take(&mut state.pending_telemetry)
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
            .collect::<Vec<_>>();
        let mut total_download = state.total_download;
        let mut total_upload = state.total_upload;
        let mut traffic_records = Vec::new();
        for shard in self.traffic.shards.iter() {
            let mut traffic_state = shard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            total_download = total_download.saturating_add(traffic_state.total_download);
            total_upload = total_upload.saturating_add(traffic_state.total_upload);
            traffic_records.extend(
                std::mem::take(&mut traffic_state.pending_traffic)
                    .into_iter()
                    .map(|(bucket, (download, upload))| GoTrafficBucketRecord {
                        bucket,
                        upload,
                        download,
                    }),
            );
            telemetry.extend(
                std::mem::take(&mut traffic_state.pending_telemetry)
                    .into_iter()
                    .map(
                        |(
                            (bucket, span_seconds, dimension, value),
                            (download, upload, failures),
                        )| {
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
                    ),
            );
        }
        GoStatisticsDelta {
            total_download,
            total_upload,
            traffic: traffic_records,
            history: std::mem::take(&mut state.pending_history),
            failed_history: std::mem::take(&mut state.pending_failed_history)
                .into_values()
                .collect(),
            telemetry,
        }
    }

    pub(super) fn merge_statistics_delta(&self, delta: GoStatisticsDelta) {
        let mut state = self.lock();
        let mut traffic_state = self.traffic.shards[0]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for traffic in delta.traffic {
            let item = traffic_state
                .pending_traffic
                .entry(traffic.bucket)
                .or_default();
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
            let item = traffic_state
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

    pub fn inbound_statistics(&self) -> Vec<InboundStatisticsRecord> {
        let state = self.lock();
        let mut inbound_bytes = BTreeMap::<String, (u64, u64)>::new();
        for shard in self.traffic.shards.iter() {
            let traffic = shard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (id, (download, upload)) in &traffic.inbound_bytes {
                let entry = inbound_bytes.entry(id.clone()).or_default();
                entry.0 = entry.0.saturating_add(*download);
                entry.1 = entry.1.saturating_add(*upload);
            }
        }
        state
            .inbound_statistics
            .iter()
            .map(|(id, statistics)| {
                let mut statistics = statistics.clone();
                if let Some((download, upload)) = inbound_bytes.get(id) {
                    statistics.download_bytes = statistics.download_bytes.saturating_add(*download);
                    statistics.upload_bytes = statistics.upload_bytes.saturating_add(*upload);
                }
                statistics.record(id.clone())
            })
            .collect()
    }

    pub(super) fn restore_persisted_runtime(&self, persisted: PersistedMonitor) {
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

    pub(super) fn restore_inbound_statistics(&self, records: Vec<InboundStatisticsRecord>) {
        let mut state = self.lock();
        for record in records {
            state.inbound_statistics.insert(
                record.inbound_id,
                InboundStatistics {
                    total_tcp_flows: record.total_tcp_flows,
                    total_udp_flows: record.total_udp_flows,
                    upload_bytes: record.upload_bytes,
                    download_bytes: record.download_bytes,
                    ..InboundStatistics::default()
                },
            );
        }
    }
}
