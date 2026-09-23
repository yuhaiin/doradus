use super::*;

/// Keep a selected outbound proxy's socket in the loopback registry for the
/// exact lifetime of the returned stream. Protocol layers may replace the
/// concrete stream type, so the core transport carries the local endpoint as
/// optional metadata and this adapter owns the runtime-only guard.
pub struct LoopbackTrackingProxy {
    inner: Arc<dyn AsyncProxy>,
    detector: LoopbackDetector,
}

pub struct LoopbackTrackedStream {
    inner: BoxAsyncStream,
    _connection: crate::loopback::TrackedConnection,
}

impl AsyncRead for LoopbackTrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LoopbackTrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub fn track_stream(detector: &LoopbackDetector, stream: BoxAsyncStream) -> BoxAsyncStream {
    let Some(local_addr) = stream_local_addr(&*stream) else {
        return stream;
    };
    let remote_addr = stream_remote_addr(&*stream);
    with_stream_socket_addrs(
        Box::new(LoopbackTrackedStream {
            inner: stream,
            _connection: detector.track_connection(local_addr),
        }),
        Some(local_addr),
        remote_addr,
    )
}

pub struct LoopbackTrackedDatagram {
    inner: Box<dyn AsyncDatagram>,
    connection: Mutex<Option<crate::loopback::TrackedConnection>>,
}

impl AsyncDatagram for LoopbackTrackedDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        self.inner.send_to(payload, target)
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let result = self.inner.close().await;
            self.connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            result
        })
    }
}

pub fn track_datagram(
    detector: &LoopbackDetector,
    datagram: Box<dyn AsyncDatagram>,
) -> Box<dyn AsyncDatagram> {
    let connection = datagram
        .local_addr()
        .ok()
        .and_then(|endpoint| endpoint.addr())
        .map(|local_addr| detector.track_connection(local_addr));
    Box::new(LoopbackTrackedDatagram {
        inner: datagram,
        connection: Mutex::new(connection),
    })
}

pub fn track_tagged_proxies(
    proxies: BTreeMap<String, Arc<dyn AsyncProxy>>,
    detector: &LoopbackDetector,
) -> BTreeMap<String, Arc<dyn AsyncProxy>> {
    proxies
        .into_iter()
        .map(|(tag, proxy)| {
            (
                tag,
                Arc::new(LoopbackTrackingProxy {
                    inner: proxy,
                    detector: detector.clone(),
                }) as Arc<dyn AsyncProxy>,
            )
        })
        .collect()
}

pub fn track_selector(
    selector: RuntimeRoutedProxySelector,
    detector: &LoopbackDetector,
) -> RuntimeRoutedProxySelector {
    let wrap = |inner: Arc<dyn AsyncProxy>| {
        Arc::new(LoopbackTrackingProxy {
            inner,
            detector: detector.clone(),
        }) as Arc<dyn AsyncProxy>
    };
    RuntimeRoutedProxySelector {
        router: selector.router,
        direct: wrap(selector.direct),
        proxy: wrap(selector.proxy),
        bypass: wrap(selector.bypass),
        drop: wrap(selector.drop),
    }
}

impl AsyncProxy for LoopbackTrackingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.inner.connect(context).await?;
            Ok(track_stream(&self.detector, stream))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let datagram = self.inner.open_datagram(context).await?;
            Ok(track_datagram(&self.detector, datagram))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.inner.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

#[cfg(feature = "http-termination")]
#[path = "../outbound_layers/http_termination.rs"]
pub(crate) mod http_termination;
