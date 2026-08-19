//! Reverse inbound protocols.
//!
//! Go's reverse listeners are still ordinary inbounds: an accepted stream is
//! enriched with the configured destination and then enters the same router
//! and outbound selector as SOCKS5, HTTP and TUN flows.  Keeping that bridge
//! here prevents reverse listeners from growing a second direct-connect path.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_protocol::reverse_http;

use super::common::io_error;
use crate::inbound::{InboundHandler, InboundStream, ReverseHttpConfig};

const HTTP_SNIFF_TIMEOUT: Duration = Duration::from_millis(55);

/// Serve a Go `reverse_tcp` inbound through the shared outbound selector.
pub(crate) async fn handle_tcp(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let target = inbound.spec().reverse_target.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "reverse_tcp inbound target is missing",
        )
    })?;
    relay_to_target(stream, peer, target, inbound, &[], "reverse_tcp").await
}

/// Serve a Go `reverse_http` inbound. HTTP requests are rewritten to the
/// configured URL; non-HTTP bytes retain the raw reverse-TCP behavior used by
/// the Go implementation and are sent to the URL authority.
pub(crate) async fn handle_http(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let config = inbound.spec().reverse_http.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "reverse_http inbound URL is missing",
        )
    })?;
    let (prefix, is_http) = reverse_http::read_http_prefix(&mut stream, HTTP_SNIFF_TIMEOUT).await?;
    if !is_http {
        let stream = BufferedIo::new(prefix, stream);
        return relay_to_target(
            Box::new(stream),
            peer,
            config.target,
            inbound,
            &[],
            "reverse_http",
        )
        .await;
    }

    let headers = std::str::from_utf8(&prefix).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("reverse HTTP headers: {error}"),
        )
    })?;
    let rewritten = reverse_http::rewrite_request(headers, &config.path, &config.authority)?;
    let destination = config.target.clone();
    let mut context = inbound.context(peer, Network::Tcp, destination.clone());
    context.http_host = reverse_http::request_host(headers);
    let connection = inbound.connect("reverse_http", context).await?;
    let connection = InboundStream {
        outbound: wrap_https_if_needed(connection.outbound, &config).await?,
        context: connection.context,
    };
    inbound
        .relay_with_prefix(
            BufferedIo::new(Vec::new(), stream),
            connection,
            peer,
            rewritten.as_bytes(),
        )
        .await
        .map_err(io_error)
}

async fn relay_to_target(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    target: Endpoint,
    inbound: Arc<InboundHandler>,
    prefix: &[u8],
    protocol: &str,
) -> Result<()> {
    inbound
        .serve_stream_with_prefix(stream, peer, protocol, target, prefix)
        .await
}

#[cfg(feature = "doh-tls")]
async fn wrap_https_if_needed(
    stream: BoxAsyncStream,
    config: &ReverseHttpConfig,
) -> Result<BoxAsyncStream> {
    if !config.https {
        return Ok(stream);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let connector = tokio_rustls::TlsConnector::from(crate::tls::client_config(roots)?);
    let name = config
        .target
        .host()
        .map(|host| host.as_str().to_owned())
        .or_else(|| config.target.addr().map(|addr| addr.ip().to_string()))
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "reverse_http target has no host"))?;
    let server_name = crate::tls::tls_server_name(&name)?;
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("reverse HTTP TLS handshake: {error}"),
            )
        })?;
    Ok(Box::new(stream))
}

#[cfg(not(feature = "doh-tls"))]
async fn wrap_https_if_needed(
    stream: BoxAsyncStream,
    config: &ReverseHttpConfig,
) -> Result<BoxAsyncStream> {
    if config.https {
        let _ = stream;
        Err(Error::new(
            ErrorKind::Unsupported,
            "reverse_http HTTPS target requires the doh-tls feature",
        ))
    } else {
        Ok(stream)
    }
}

struct BufferedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> BufferedIo<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BufferedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() > 0 {
            let count = (self.prefix.len() - self.offset).min(buffer.remaining());
            buffer.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BufferedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
