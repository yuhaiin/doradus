//! Transport-independent flow metadata and lifecycle observation.

use std::net::SocketAddr;
#[cfg(feature = "async-proxy")]
use std::sync::Arc;

use crate::{Endpoint, Network};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl FlowKey {
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::ip(self.network, self.destination)
    }

    pub fn source_endpoint(&self) -> Endpoint {
        Endpoint::ip(self.network, self.source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub key: FlowKey,
}

impl Flow {
    pub fn context(&self) -> crate::FlowContext {
        let mut context = crate::FlowContext::new(self.key.endpoint());
        context.source = Some(self.key.source_endpoint());
        context.network = self.key.network;
        context
    }
}

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    Upload,
    Download,
}

#[cfg(feature = "async-proxy")]
pub trait FlowObserver: Send + Sync {
    fn opened(&self, flow: Flow, context: crate::FlowContext);
    fn bytes(&self, flow: FlowKey, direction: FlowDirection, bytes: usize);
    fn closed(&self, flow: FlowKey);

    fn close_requested(&self, _flow: FlowKey) -> bool {
        false
    }
}

/// RAII lifecycle guard for observed flows.
///
/// Relays are frequently owned by a listener task and can be cancelled by a
/// reload or shutdown.  Relying on a statement after the relay future leaves
/// a live connection in the monitor when Tokio aborts that future.  Keeping
/// this guard beside the relay makes normal completion, force cancellation
/// and task abort all publish exactly one effective close event.
#[cfg(feature = "async-proxy")]
pub struct FlowObserverGuard {
    observer: Arc<dyn FlowObserver>,
    flow: FlowKey,
}

#[cfg(feature = "async-proxy")]
impl FlowObserverGuard {
    pub fn open(observer: Arc<dyn FlowObserver>, flow: Flow, context: crate::FlowContext) -> Self {
        observer.opened(flow, context);
        Self {
            observer,
            flow: flow.key,
        }
    }
}

#[cfg(feature = "async-proxy")]
impl Drop for FlowObserverGuard {
    fn drop(&mut self) {
        self.observer.closed(self.flow);
    }
}
