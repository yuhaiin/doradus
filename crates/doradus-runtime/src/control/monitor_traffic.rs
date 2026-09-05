//! Connection monitor runtime responsibilities split from the core type.

use super::*;

impl ConnectionMonitor {
    fn traffic_shard_index(flow: TunFlowKey) -> usize {
        let source = usize::from(flow.source.port());
        let destination = usize::from(flow.destination.port());
        source
            .wrapping_mul(0x9e37)
            .wrapping_add(destination.rotate_left(7))
            % TRAFFIC_SHARD_COUNT
    }
    pub(super) fn traffic_lock(
        &self,
        flow: TunFlowKey,
    ) -> std::sync::MutexGuard<'_, MonitorTrafficState> {
        self.traffic.shards[Self::traffic_shard_index(flow)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
}
