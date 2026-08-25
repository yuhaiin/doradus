//! Asynchronous stream and datagram proxy primitives.

use std::any::Any;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::DomainName;
use crate::{BoxFuture, FlowContext, Network};
use crate::{Endpoint, Error, ErrorKind, Result};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;
use tokio::time::Sleep;

/// Internal marker used by the runtime for Go's `useDefaultInterface` mode.
/// It is resolved to the current physical default-route interface immediately
/// before each outbound socket is bound, rather than when a runtime snapshot
/// is built.
pub const DEFAULT_INTERFACE: &str = "__yuhaiin_default_interface__";

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

#[path = "proxy_datagrams.rs"]
mod datagrams;
#[path = "proxy_direct.rs"]
mod direct;
#[path = "proxy_drop.rs"]
mod drop;
#[path = "proxy_socket.rs"]
mod socket;
#[path = "proxy_socks5.rs"]
mod socks5;
#[path = "proxy_stream.rs"]
mod stream_metadata;
#[path = "proxy_wrappers.rs"]
mod wrappers;

pub use direct::DirectAsyncProxy;
pub use drop::{DelayedDropAsyncProxy, DropAsyncProxy};
pub use socket::{
    bind_socket_to_interface, bind_tokio_udp_socket_for_target, connect_tokio_tcp,
    connect_tokio_tcp_with_interface,
};
pub use socks5::Socks5AsyncProxy;
pub use stream_metadata::{
    LocalAddrStream, stream_local_addr, stream_remote_addr, with_stream_local_addr,
    with_stream_socket_addrs,
};
pub use wrappers::{BindInterfaceProxy, FallbackAsyncProxy, FixedAsyncProxy};

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
