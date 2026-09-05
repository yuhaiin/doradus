//! Connection monitor runtime responsibilities split from the core type.

use super::*;

impl ConnectionMonitor {
    pub(super) fn durable_snapshot(&self) -> Option<GoStatisticsSnapshot> {
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
    pub(super) fn mark_dirty(&self) {
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
