//! Runtime status and durable lifecycle events for inbound owners.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::json;

use doradus_store::{ConfigStore, InboundRuntimeEventInput};

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundListenerStatus {
    pub kind: String,
    pub state: String,
    pub listen: Option<String>,
    pub last_error: Option<String>,
    pub changed_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundRuntimeStatus {
    pub id: String,
    pub state: String,
    pub last_error: Option<String>,
    pub changed_at: i64,
    pub listeners: Vec<InboundListenerStatus>,
}

#[derive(Debug, Default)]
struct RuntimeEntry {
    state: String,
    last_error: Option<String>,
    changed_at: i64,
    listeners: BTreeMap<String, InboundListenerStatus>,
}

#[derive(Clone)]
pub struct InboundRuntimeState {
    entries: Arc<Mutex<BTreeMap<String, RuntimeEntry>>>,
    store: ConfigStore,
}

impl InboundRuntimeState {
    pub(crate) fn new(store: ConfigStore) -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            store,
        }
    }

    pub(crate) fn mark_disabled(&self, id: &str) {
        let now = unix_seconds();
        let changed = {
            let mut entries = self.lock();
            let entry = entries.entry(id.to_owned()).or_default();
            entry.state = "disabled".to_owned();
            entry.last_error = None;
            entry.changed_at = now;
            entry.listeners.clear();
            true
        };
        if changed {
            self.record_event(id, "stop", "disabled", None, json!({}));
        }
    }

    pub(crate) fn mark_starting(&self, id: &str, retry: bool) {
        let now = unix_seconds();
        {
            let mut entries = self.lock();
            let entry = entries.entry(id.to_owned()).or_default();
            entry.state = "starting".to_owned();
            entry.last_error = None;
            entry.changed_at = now;
            entry.listeners.clear();
        }
        self.record_event(
            id,
            if retry { "retry" } else { "start" },
            "starting",
            None,
            json!({}),
        );
    }

    pub(crate) fn mark_stopping(&self, id: &str) {
        let now = unix_seconds();
        {
            let mut entries = self.lock();
            let entry = entries.entry(id.to_owned()).or_default();
            entry.state = "stopping".to_owned();
            entry.changed_at = now;
            for listener in entry.listeners.values_mut() {
                listener.state = "stopping".to_owned();
                listener.changed_at = now;
            }
        }
        self.record_event(id, "stop", "stopping", None, json!({}));
    }

    pub(crate) fn is_stopping(&self, id: &str) -> bool {
        self.lock()
            .get(id)
            .is_some_and(|entry| entry.state == "stopping")
    }

    pub(crate) fn has_failed_listener(&self, id: &str) -> bool {
        self.lock().get(id).is_some_and(|entry| {
            entry
                .listeners
                .values()
                .any(|listener| listener.state == "failed")
        })
    }

    pub(crate) fn mark_reload(&self, id: &str) {
        let state = self
            .lock()
            .get(id)
            .map(|entry| entry.state.clone())
            .unwrap_or_else(|| "starting".to_owned());
        self.record_event(id, "reload", &state, None, json!({}));
    }

    pub(crate) fn listener_ready(&self, id: &str, kind: &str, listen: Option<String>) {
        let now = unix_seconds();
        let state =
            {
                let mut entries = self.lock();
                let entry = entries.entry(id.to_owned()).or_default();
                let listener = entry.listeners.entry(kind.to_owned()).or_insert_with(|| {
                    InboundListenerStatus {
                        kind: kind.to_owned(),
                        state: "starting".to_owned(),
                        listen: listen.clone(),
                        last_error: None,
                        changed_at: now,
                    }
                });
                listener.state = "running".to_owned();
                listener.listen = listen.clone().or_else(|| listener.listen.clone());
                listener.last_error = None;
                listener.changed_at = now;
                let has_failed_listener = entry
                    .listeners
                    .values()
                    .any(|listener| listener.state == "failed");
                entry.state = if has_failed_listener {
                    "degraded"
                } else {
                    "running"
                }
                .to_owned();
                if !has_failed_listener {
                    entry.last_error = None;
                }
                entry.changed_at = now;
                entry.state.clone()
            };
        self.record_event(
            id,
            "ready",
            &state,
            None,
            json!({"listener": kind, "listen": listen}),
        );
    }

    pub(crate) fn owner_started(&self, id: &str) {
        let starting = self
            .lock()
            .get(id)
            .is_some_and(|entry| entry.state == "starting");
        if starting {
            self.listener_ready(id, "listener", None);
        }
    }

    pub(crate) fn listener_failed(
        &self,
        id: &str,
        kind: &str,
        listen: Option<String>,
        error: &str,
    ) {
        let now = unix_seconds();
        let error = error.to_owned();
        {
            let mut entries = self.lock();
            let entry = entries.entry(id.to_owned()).or_default();
            let listener =
                entry
                    .listeners
                    .entry(kind.to_owned())
                    .or_insert_with(|| InboundListenerStatus {
                        kind: kind.to_owned(),
                        state: "starting".to_owned(),
                        listen: listen.clone(),
                        last_error: None,
                        changed_at: now,
                    });
            listener.state = "failed".to_owned();
            listener.listen = listen.clone().or_else(|| listener.listen.clone());
            listener.last_error = Some(error.clone());
            listener.changed_at = now;
            let any_running = entry
                .listeners
                .values()
                .any(|listener| listener.state == "running");
            entry.state = if any_running { "degraded" } else { "failed" }.to_owned();
            entry.last_error = Some(error.clone());
            entry.changed_at = now;
        }
        self.record_event(
            id,
            "fail",
            if self.is_degraded(id) {
                "degraded"
            } else {
                "failed"
            },
            Some(error),
            json!({"listener": kind, "listen": listen}),
        );
    }

    pub(crate) fn mark_no_listener(&self, id: &str, error: &str) {
        self.listener_failed(id, "inbound", None, error);
    }

    pub fn snapshot(&self) -> Vec<InboundRuntimeStatus> {
        self.lock()
            .iter()
            .map(|(id, entry)| InboundRuntimeStatus {
                id: id.clone(),
                state: entry.state.clone(),
                last_error: entry.last_error.clone(),
                changed_at: entry.changed_at,
                listeners: entry.listeners.values().cloned().collect(),
            })
            .collect()
    }

    fn is_degraded(&self, id: &str) -> bool {
        self.lock()
            .get(id)
            .is_some_and(|entry| entry.state == "degraded")
    }

    fn record_event(
        &self,
        id: &str,
        event_type: &str,
        state: &str,
        error: Option<String>,
        detail: serde_json::Value,
    ) {
        let input = InboundRuntimeEventInput {
            inbound_id: id.to_owned(),
            event_type: event_type.to_owned(),
            state: state.to_owned(),
            error,
            detail_json: serde_json::to_vec(&detail).unwrap_or_else(|_| b"{}".to_vec()),
            created_at: unix_seconds(),
        };
        let _ = self.store.append_inbound_runtime_event(&input);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, RuntimeEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_ready_listener_does_not_hide_another_failed_listener() {
        let store = ConfigStore::open_memory().await.unwrap();
        let runtime = InboundRuntimeState::new(store);
        runtime.mark_starting("entry", false);
        runtime.listener_ready("entry", "tcp", Some("127.0.0.1:9000".to_owned()));
        runtime.listener_failed(
            "entry",
            "udp",
            Some("127.0.0.1:9000".to_owned()),
            "address already in use",
        );
        runtime.listener_ready("entry", "tcp", Some("127.0.0.1:9000".to_owned()));

        let status = runtime.snapshot().pop().unwrap();
        assert_eq!(status.state, "degraded");
        assert_eq!(status.last_error.as_deref(), Some("address already in use"));
        assert_eq!(status.listeners.len(), 2);
        assert_eq!(
            status
                .listeners
                .iter()
                .find(|listener| listener.kind == "udp")
                .unwrap()
                .state,
            "failed"
        );
    }
}
