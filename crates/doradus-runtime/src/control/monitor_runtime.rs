//! Core connection-monitor construction, logging, and shared locking.

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
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, MonitorState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
