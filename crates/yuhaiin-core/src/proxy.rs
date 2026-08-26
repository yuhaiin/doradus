//! Asynchronous stream and datagram proxy primitives.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use crate::{BoxFuture, FlowContext};
use crate::{Endpoint, Error, ErrorKind, Result};

use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T> AsyncStream for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Any,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub type BoxAsyncStream = Box<dyn AsyncStream>;

pub trait AsyncDatagram: Send + Sync {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>>;
    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>>;
    fn local_addr(&self) -> Result<Endpoint>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

pub trait AsyncProxy: Send + Sync {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>>;
    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>>;
    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "proxy does not provide ping",
            ))
        })
    }
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

pub trait AsyncProxySelector: Send + Sync {
    /// Annotate a mutable flow with the route snapshot used for selection.
    /// Static selectors intentionally leave this as a no-op; runtime-backed
    /// selectors use it to keep management metadata and proxy choice aligned.
    fn route_context(&self, _context: &mut FlowContext) {}

    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy>;
}

pub struct StaticProxySelector {
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for StaticProxySelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        match context.route_mode {
            crate::RouteMode::Direct => Arc::clone(&self.direct),
            crate::RouteMode::Proxy => Arc::clone(&self.proxy),
            crate::RouteMode::Bypass => Arc::clone(&self.bypass),
            crate::RouteMode::Block => Arc::clone(&self.drop),
        }
    }
}

pub use crate::stream_metadata::{
    LocalAddrStream, stream_local_addr, stream_remote_addr, with_stream_local_addr,
    with_stream_socket_addrs,
};
