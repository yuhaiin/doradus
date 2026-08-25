//! Stream endpoint metadata.

use super::*;

/// Preserve the socket's local endpoint while protocol layers replace the
/// concrete stream type (TLS, HTTP/2, Yuubinsya, and WebSocket all do this).
/// The runtime uses this metadata for loopback protection; it is deliberately
/// optional because in-memory test streams do not have a socket endpoint.
pub struct LocalAddrStream {
    inner: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

impl LocalAddrStream {
    pub fn new(inner: BoxAsyncStream, local_addr: SocketAddr) -> Self {
        Self {
            inner,
            local_addr: Some(local_addr),
            remote_addr: None,
        }
    }

    fn with_socket_addrs(
        inner: BoxAsyncStream,
        local_addr: Option<SocketAddr>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            local_addr,
            remote_addr,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

impl AsyncRead for LocalAddrStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LocalAddrStream {
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

pub fn stream_local_addr(stream: &dyn AsyncStream) -> Option<SocketAddr> {
    stream
        .as_any()
        .downcast_ref::<LocalAddrStream>()
        .and_then(LocalAddrStream::local_addr)
}

pub fn stream_remote_addr(stream: &dyn AsyncStream) -> Option<SocketAddr> {
    stream
        .as_any()
        .downcast_ref::<LocalAddrStream>()
        .and_then(LocalAddrStream::remote_addr)
}

pub fn with_stream_local_addr(
    stream: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
) -> BoxAsyncStream {
    with_stream_socket_addrs(stream, local_addr, None)
}

pub fn with_stream_socket_addrs(
    stream: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
) -> BoxAsyncStream {
    if (local_addr.is_none() || stream_local_addr(&*stream).is_some())
        && (remote_addr.is_none() || stream_remote_addr(&*stream).is_some())
    {
        return stream;
    }
    Box::new(LocalAddrStream::with_socket_addrs(
        stream,
        local_addr,
        remote_addr,
    ))
}
