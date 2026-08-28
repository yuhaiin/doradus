//! Runtime HTTP proxy adapter.
//!
//! HTTP/1.x framing and header rewriting live in `doradus-protocol`; this
//! module applies runtime authentication, routing, TLS and flow accounting.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::inbound::InboundHandler;
use doradus_core::flow::FlowObserver;
use doradus_core::flow::{Flow as TunFlow, FlowDirection as TunFlowDirection, FlowObserverGuard};
use doradus_core::proxy::BoxAsyncStream;
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};
use doradus_types::InboundStreamHandler;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct HttpInboundHandler {
    pub(crate) inbound: Arc<InboundHandler>,
}

/// Concrete stream type for the HTTP protocol boundary. Keeping the erased
/// runtime stream behind a named type avoids leaking an object-lifetime
/// parameter into the protocol handler's generic `S` contract.
pub(crate) struct HttpInboundStream(pub(crate) BoxAsyncStream);

impl AsyncRead for HttpInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for HttpInboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub(crate) struct HttpForwardConnection {
    outbound: BoxAsyncStream,
    flow: doradus_core::flow::FlowKey,
    _observation: FlowObserverGuard,
}

impl InboundStreamHandler<HttpInboundStream> for HttpInboundHandler {
    fn handle_stream<'a>(
        &'a self,
        stream: HttpInboundStream,
        peer: SocketAddr,
        destination: Endpoint,
        protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>> {
        self.inbound
            .handle_stream(stream.0, peer, destination, protocol)
    }
}

impl doradus_protocol::http_server::HttpForwardHandler<HttpInboundStream> for HttpInboundHandler {
    type Outbound = HttpForwardConnection;

    fn open_forward<'a>(
        &'a self,
        peer: SocketAddr,
        destination: Endpoint,
        http_host: Option<String>,
        https: bool,
    ) -> BoxFuture<'a, Result<Self::Outbound>> {
        Box::pin(async move {
            let monitor = Arc::clone(self.inbound.monitor());
            let mut context = self
                .inbound
                .context(peer, Network::Tcp, destination.clone());
            context.http_host = http_host;
            let connection = self.inbound.connect("http", context).await?;
            let outbound = if https {
                #[cfg(feature = "doh-tls")]
                {
                    let server_name = destination
                        .host()
                        .map(|host| host.as_str().to_owned())
                        .or_else(|| destination.addr().map(|addr| addr.ip().to_string()))
                        .ok_or_else(|| {
                            Error::new(ErrorKind::InvalidInput, "HTTPS target has no host")
                        })?;
                    crate::tls::wrap_system_tls_stream(&server_name, connection.outbound).await?
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "HTTP proxy HTTPS requests require the doh-tls feature",
                    ));
                }
            } else {
                connection.outbound
            };
            let flow = self.inbound.flow_key(&connection.context, peer);
            let observation =
                FlowObserverGuard::open(monitor, TunFlow { key: flow }, connection.context);
            Ok(HttpForwardConnection {
                outbound,
                flow,
                _observation: observation,
            })
        })
    }

    fn record_bytes(
        &self,
        connection: &Self::Outbound,
        direction: doradus_protocol::http_server::HttpTrafficDirection,
        bytes: usize,
    ) {
        let direction = match direction {
            doradus_protocol::http_server::HttpTrafficDirection::Upload => TunFlowDirection::Upload,
            doradus_protocol::http_server::HttpTrafficDirection::Download => {
                TunFlowDirection::Download
            }
        };
        self.inbound
            .monitor()
            .bytes(connection.flow, direction, bytes);
    }
}

impl tokio::io::AsyncRead for HttpForwardConnection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().outbound).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HttpForwardConnection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().outbound).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().outbound).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().outbound).poll_shutdown(cx)
    }
}
