//! Connection monitor runtime responsibilities split from the core type.

use super::*;

impl ConnectionMonitor {
    pub fn connections_value(&self) -> Value {
        let state = self.lock();
        let mut values = state
            .connections
            .values()
            .map(|entry| entry.record.projection.clone())
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
            .map(|entry| entry.record.projection.clone())
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
}
