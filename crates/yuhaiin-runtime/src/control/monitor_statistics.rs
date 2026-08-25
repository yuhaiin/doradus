//! Durable statistics and history projection helpers for the runtime monitor.

use super::*;

pub(super) fn persisted_snapshot(
    persisted: &PersistedMonitor,
) -> yuhaiin_core::Result<GoStatisticsSnapshot> {
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

pub(super) fn pending_delta_from_state(state: &MonitorState) -> GoStatisticsDelta {
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

pub(super) fn apply_delta_to_snapshot(
    snapshot: &mut GoStatisticsSnapshot,
    delta: GoStatisticsDelta,
) {
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

pub(super) fn merge_statistics_snapshots(
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
        .filter_map(|item| history_record_key(&item).map(|key| (key, item)))
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

pub(super) fn history_record_key(
    item: &GoConnectionHistoryRecord,
) -> Option<(String, String, String)> {
    Some((
        item.protocol.clone(),
        item.addr.clone(),
        item.process.clone(),
    ))
}

pub(super) fn history_record_value(item: GoConnectionHistoryRecord) -> Option<Value> {
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

pub(super) fn connection_history_record(
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

pub(super) fn merge_pending_history(
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

pub(super) fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

pub(super) fn format_time(seconds: i64) -> String {
    // Go's `time.Unix` JSON representation is emitted in UTC by the service
    // contract. Do not let the host timezone leak into frontend responses.
    format_time_utc(seconds)
}

pub(super) fn format_time_utc(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

pub(super) fn parse_time(value: Option<&str>) -> Option<i64> {
    value
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map(|time| time.unix_timestamp())
}

pub(super) fn history_key(item: &Value) -> (String, String, String) {
    let connection = item.get("connection").unwrap_or(item);
    connection_history_key(connection)
}

pub(super) fn connection_history_key(connection: &Value) -> (String, String, String) {
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

pub(super) fn history_protocol(connection: &Value) -> String {
    connection
        .get(INTERNAL_GO_PROTOCOL_KEY)
        .and_then(Value::as_str)
        .or_else(|| connection.get("protocol").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn public_history_item(item: &Value) -> Value {
    let mut item = item.clone();
    if let Some(connection) = item.get_mut("connection").and_then(Value::as_object_mut) {
        connection.remove(INTERNAL_GO_PROTOCOL_KEY);
    }
    item
}

pub(super) fn history_count(item: &Value) -> u64 {
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
pub(super) fn coalesce_history(items: Vec<Value>) -> Vec<Value> {
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

pub(super) fn normalize_history_time(mut item: Value) -> Value {
    let timestamp = item
        .get("time")
        .and_then(Value::as_str)
        .and_then(|value| parse_time(Some(value)));
    if let Some(timestamp) = timestamp {
        item["time"] = Value::String(format_time(timestamp));
    }
    item
}

pub(super) fn history_time(item: &Value) -> i64 {
    item.get("time")
        .and_then(Value::as_str)
        .and_then(|value| parse_time(Some(value)))
        .unwrap_or_default()
}
