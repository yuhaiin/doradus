//! Generic observability wrappers for connections entering the proxy chain.
//!
//! Inbound and TUN relays already own a `FlowObserverGuard`.  Resolver and
//! other runtime-owned transports enter the same chain without a relay, so
//! they use these wrappers at that boundary.  Keeping the wrapper here avoids
//! logging every nested proxy hop and mirrors Go's outer statistics proxy.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection, FlowKey as TunFlowKey, FlowObserver, FlowObserverGuard,
};
use yuhaiin_core::proxy::{AsyncDatagram, BoxAsyncStream, stream_local_addr};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Result};

fn connection_aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection closed by monitor",
    )
}

fn destination_addr(context: &FlowContext, source: SocketAddr) -> SocketAddr {
    context.destination.addr().unwrap_or_else(|| {
        let ip = if source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        SocketAddr::new(ip, context.destination.port().unwrap_or_default())
    })
}

fn flow_for_stream(stream: &BoxAsyncStream, context: &FlowContext) -> Option<TunFlowKey> {
    let source = stream_local_addr(&**stream)?;
    Some(TunFlowKey {
        network: context.network,
        source,
        destination: destination_addr(context, source),
    })
}

/// Observe a stream returned by an outbound proxy.
pub(crate) fn observe_stream(
    observer: Arc<dyn FlowObserver>,
    stream: BoxAsyncStream,
    mut context: FlowContext,
) -> BoxAsyncStream {
    let Some(flow) = flow_for_stream(&stream, &context) else {
        return stream;
    };
    context.outbound_local_addr = Some(Endpoint::ip(context.network, flow.source));
    let guard = FlowObserverGuard::open(observer.clone(), TunFlow { key: flow }, context);
    Box::new(ObservedStream {
        inner: stream,
        observer,
        flow,
        _guard: guard,
    })
}

struct ObservedStream {
    inner: BoxAsyncStream,
    observer: Arc<dyn FlowObserver>,
    flow: TunFlowKey,
    _guard: FlowObserverGuard,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.observer.close_requested(self.flow) {
            return Poll::Ready(Err(connection_aborted()));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut *self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let bytes = buffer.filled().len().saturating_sub(before);
                if bytes != 0 {
                    self.observer
                        .bytes(self.flow, FlowDirection::Download, bytes);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.observer.close_requested(self.flow) {
            return Poll::Ready(Err(connection_aborted()));
        }
        match Pin::new(&mut *self.inner).poll_write(cx, data) {
            Poll::Ready(Ok(bytes)) => {
                if bytes != 0 {
                    self.observer.bytes(self.flow, FlowDirection::Upload, bytes);
                }
                Poll::Ready(Ok(bytes))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Observe a datagram socket returned by an outbound proxy.
pub(crate) fn observe_datagram(
    observer: Arc<dyn FlowObserver>,
    datagram: Box<dyn AsyncDatagram>,
    mut context: FlowContext,
) -> Box<dyn AsyncDatagram> {
    let Some(source) = datagram
        .local_addr()
        .ok()
        .and_then(|endpoint| endpoint.addr())
    else {
        return datagram;
    };
    context.outbound_local_addr = Some(Endpoint::ip(context.network, source));
    let flow = TunFlowKey {
        network: context.network,
        source,
        destination: destination_addr(&context, source),
    };
    let guard = FlowObserverGuard::open(observer.clone(), TunFlow { key: flow }, context);
    Box::new(ObservedDatagram {
        inner: datagram,
        observer,
        flow,
        guard: Mutex::new(Some(guard)),
    })
}

struct ObservedDatagram {
    inner: Box<dyn AsyncDatagram>,
    observer: Arc<dyn FlowObserver>,
    flow: TunFlowKey,
    guard: Mutex<Option<FlowObserverGuard>>,
}

impl AsyncDatagram for ObservedDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let observer = self.observer.clone();
        let flow = self.flow;
        Box::pin(async move {
            if observer.close_requested(flow) {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "connection closed by monitor",
                ));
            }
            let result = self.inner.send_to(payload, target).await;
            if let Ok(bytes) = result
                && bytes != 0
            {
                observer.bytes(flow, FlowDirection::Upload, bytes);
            }
            result
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        let observer = self.observer.clone();
        let flow = self.flow;
        Box::pin(async move {
            if observer.close_requested(flow) {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "connection closed by monitor",
                ));
            }
            let result = self.inner.recv_from(buffer).await;
            if let Ok((bytes, _)) = result
                && bytes != 0
            {
                observer.bytes(flow, FlowDirection::Download, bytes);
            }
            result
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let result = self.inner.close().await;
            self.guard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            result
        })
    }
}
