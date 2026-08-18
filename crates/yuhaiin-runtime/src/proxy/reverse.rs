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

use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::{AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_protocol::reverse_http;

use super::common::{io_error, record_outbound_stream, relay_counted_with_prefix_and_buffer};
use crate::inbound::{InboundSpec, ReverseHttpConfig};
use crate::{ConnectionMonitor, RuntimeProxySelector};

const HTTP_SNIFF_TIMEOUT: Duration = Duration::from_millis(55);

/// Serve a Go `reverse_tcp` inbound through the shared outbound selector.
pub(crate) async fn serve_tcp<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = spec.reverse_target.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "reverse_tcp inbound target is missing",
        )
    })?;
    relay_to_target(
        stream,
        peer,
        spec,
        target,
        selector,
        monitor,
        &[],
        "reverse_tcp",
    )
    .await
}

/// Serve a Go `reverse_http` inbound. HTTP requests are rewritten to the
/// configured URL; non-HTTP bytes retain the raw reverse-TCP behavior used by
/// the Go implementation and are sent to the URL authority.
pub(crate) async fn serve_http<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = spec.reverse_http.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "reverse_http inbound URL is missing",
        )
    })?;
    let (prefix, is_http) = reverse_http::read_http_prefix(&mut stream, HTTP_SNIFF_TIMEOUT).await?;
    if !is_http {
        let stream = BufferedIo::new(prefix, stream);
        return relay_to_target(
            stream,
            peer,
            spec,
            config.target,
            selector,
            monitor,
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
    let mut context = new_context(&destination, peer, &spec);
    context.http_host = reverse_http::request_host(headers);
    selector.route_context(&mut context);
    let process = context.process.clone();
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .inspect_err(|error| {
            monitor.record_failure_with_process(
                "reverse_http",
                &destination.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
        })?;
    record_outbound_stream(&mut context, &outbound);
    let outbound = wrap_https_if_needed(outbound, &config).await?;
    let flow = flow_key(peer, &destination);
    relay_counted_with_prefix_and_buffer(
        BufferedIo::new(Vec::new(), stream),
        outbound,
        flow,
        context,
        monitor,
        rewritten.as_bytes(),
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

#[allow(clippy::too_many_arguments)]
async fn relay_to_target<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    target: Endpoint,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    prefix: &[u8],
    protocol: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut context = new_context(&target, peer, &spec);
    selector.route_context(&mut context);
    let process = context.process.clone();
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .inspect_err(|error| {
            monitor.record_failure_with_process(
                protocol,
                &target.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
        })?;
    record_outbound_stream(&mut context, &outbound);
    let flow = flow_key(peer, &target);
    relay_counted_with_prefix_and_buffer(
        stream,
        outbound,
        flow,
        context,
        monitor,
        prefix,
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

fn new_context(target: &Endpoint, peer: SocketAddr, spec: &InboundSpec) -> FlowContext {
    let mut context = FlowContext::new(target.clone());
    context.source = Some(Endpoint::ip(Network::Tcp, peer));
    context.original_domain = target.host().cloned();
    spec.annotate_context(&mut context);
    context
}

fn flow_key(peer: SocketAddr, target: &Endpoint) -> TunFlowKey {
    TunFlowKey {
        network: Network::Tcp,
        source: peer,
        destination: target
            .addr()
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback address")),
    }
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
