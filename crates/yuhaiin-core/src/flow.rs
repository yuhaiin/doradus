//! Transport-independent flow metadata and lifecycle observation.

use std::net::SocketAddr;

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
