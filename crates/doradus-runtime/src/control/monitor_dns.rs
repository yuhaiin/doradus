//! Connection monitor runtime responsibilities split from the core type.

use super::*;

impl ConnectionMonitor {
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
}
