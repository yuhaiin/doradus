//! Persistence lifecycle for the runtime connection monitor.

use super::*;

impl ConnectionMonitor {
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
}
