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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::{AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{io_error, relay_counted_with_prefix_and_buffer};
use crate::inbound::{InboundSpec, ReverseHttpConfig};
use crate::{ConnectionMonitor, RuntimeProxySelector};

const MAX_HTTP_HEADERS: usize = 64 * 1024;
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
    let (prefix, is_http) = read_http_prefix(&mut stream).await?;
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
    let rewritten = rewrite_request(headers, &config)?;
    let destination = config.target.clone();
    let mut context = new_context(&destination, peer, &spec);
    context.http_host = request_host(headers);
    selector.route_context(&mut context);
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .inspect_err(|error| {
            monitor.record_failure("reverse_http", &destination.to_string(), &error.to_string());
        })?;
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
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .inspect_err(|error| {
            monitor.record_failure(protocol, &target.to_string(), &error.to_string());
        })?;
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
    let connector = tokio_rustls::TlsConnector::from(crate::doh_tls::client_config(roots)?);
    let name = config
        .target
        .host()
        .map(|host| host.as_str().to_owned())
        .or_else(|| config.target.addr().map(|addr| addr.ip().to_string()))
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "reverse_http target has no host"))?;
    let server_name = crate::doh_tls::tls_server_name(&name)?;
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

async fn read_http_prefix<S>(stream: &mut S) -> Result<(Vec<u8>, bool)>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::new();
    let result = tokio::time::timeout(HTTP_SNIFF_TIMEOUT, async {
        loop {
            if prefix.len() >= MAX_HTTP_HEADERS {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "reverse HTTP headers exceed limit",
                ));
            }
            let mut byte = [0u8; 1];
            let length = stream.read(&mut byte).await.map_err(io_error)?;
            if length == 0 {
                break;
            }
            prefix.push(byte[0]);
            if prefix.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok((prefix.clone(), looks_like_http_request(&prefix))),
        Ok(Err(error)) => Err(error),
        Err(_) => Ok((prefix, false)),
    }
}

fn looks_like_http_request(headers: &[u8]) -> bool {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let Some(line) = headers.split_once("\r\n").map(|(line, _)| line) else {
        return false;
    };
    let fields = line.split_whitespace().collect::<Vec<_>>();
    fields.len() == 3
        && fields[0].bytes().all(|byte| byte.is_ascii_alphabetic())
        && fields[2].starts_with("HTTP/")
}

fn rewrite_request(headers: &str, config: &ReverseHttpConfig) -> Result<String> {
    let (first, rest) = headers
        .split_once("\r\n")
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "reverse HTTP request line is missing"))?;
    let mut fields = first.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let requested = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or("HTTP/1.1");
    if method.is_empty() || requested.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "reverse HTTP request line is invalid",
        ));
    }
    let request_path = origin_path(requested);
    let target_path = join_path(&config.path, &request_path);
    let mut output = format!("{method} {target_path} {version}\r\n");
    let mut has_host = false;
    for line in rest.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            output.push_str("Host: ");
            output.push_str(&config.authority);
            output.push_str("\r\n");
            has_host = true;
        } else {
            output.push_str(line);
            output.push_str("\r\n");
        }
    }
    if !has_host {
        output.push_str("Host: ");
        output.push_str(&config.authority);
        output.push_str("\r\n");
    }
    output.push_str("\r\n");
    Ok(output)
}

fn origin_path(value: &str) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest
                .find('/')
                .map(|offset| rest[offset..].to_owned())
                .unwrap_or_else(|| "/".to_owned());
        }
    }
    if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    }
}

fn join_path(base: &str, requested: &str) -> String {
    if base == "/" {
        return requested.to_owned();
    }
    if requested == "/" {
        return base.to_owned();
    }
    format!("{}{}", base.trim_end_matches('/'), requested)
}

fn request_host(headers: &str) -> Option<String> {
    headers
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().split(':').next().unwrap_or_default())
        })
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
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
