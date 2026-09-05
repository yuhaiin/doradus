//! Connection monitor runtime responsibilities split from the core type.

use super::*;

impl ConnectionMonitor {
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
            let mut projection = entry.record.projection.clone();
            let changed = merge_connection_metadata(&mut projection, update);
            if changed {
                entry.telemetry = Arc::from(telemetry_dimensions(&projection));
                entry.record.refresh_projection(projection, &context);
                let mut traffic = self.traffic_lock(flow.key);
                if let Some(flow_entry) = traffic.flows.get_mut(&flow.key) {
                    flow_entry.telemetry = Arc::clone(&entry.telemetry);
                    flow_entry.inbound_id = entry.record.inbound_id.clone();
                    flow_entry.is_tun = entry.record.is_tun;
                }
            }
            let value = entry.record.projection.clone();
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
        let record = ConnectionRecord::from_projection(value.clone(), &context);
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
            inbound_id: record.inbound_id.clone(),
            is_tun: record.is_tun,
            upload: 0,
            download: 0,
        };
        state.connections.insert(
            flow.key,
            ConnectionEntry {
                id,
                record,
                telemetry,
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
        if let Some(inbound_id) = entry.record.inbound_id.as_deref() {
            let statistics = state
                .inbound_statistics
                .entry(inbound_id.to_string())
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
        if entry.record.mode == RouteMode::Block {
            let protocol = entry.record.protocol.to_string();
            let host = entry.record.host.to_string();
            let process = entry.record.process.to_string();
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
        let value = entry.record.projection;
        if persistent {
            if let Some(record) = connection_history_record(&value, now) {
                merge_pending_history(&mut state.pending_history, record);
            }
        } else {
            let key = connection_history_key(&value);
            if let Some(existing) = state
                .history
                .iter_mut()
                .find(|item| history_key(item) == key)
            {
                let count = history_count(existing).saturating_add(1);
                existing["connection"] = value;
                existing["count"] = Value::String(count.to_string());
                existing["time"] = Value::String(format_time(now));
            } else {
                state.history.push(json!({
                    "connection": value,
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
}
