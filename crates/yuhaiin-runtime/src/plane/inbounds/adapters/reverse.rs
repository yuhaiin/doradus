//! Reverse inbound protocols.
//!
//! Go's reverse listeners are still ordinary inbounds: an accepted stream is
//! enriched with the configured destination and then enters the same router
//! and outbound selector as SOCKS5, HTTP and TUN flows.  Keeping that bridge
//! here prevents reverse listeners from growing a second direct-connect path.

use std::net::SocketAddr;
use std::sync::Arc;

use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_protocol::reverse_http;

use super::common::io_error;
use crate::inbound::{InboundHandler, InboundStream, ReverseHttpConfig};

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

/// Serve a Go `reverse_http` inbound through the protocol-owned sniff and
/// rewrite loop.
pub(crate) async fn handle_http(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let config = inbound.spec().reverse_http.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "reverse_http inbound URL is missing",
        )
    })?;
    let forward_handler = ReverseHttpForwardHandler { inbound, config };
    reverse_http::handle(
        stream,
        peer,
        reverse_http::ReverseHttpOptions {
            target: forward_handler.config.target.clone(),
            path: &forward_handler.config.path,
            authority: &forward_handler.config.authority,
            https: forward_handler.config.https,
        },
        forward_handler.inbound.as_ref(),
        &forward_handler,
    )
    .await
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

struct ReverseHttpForwardHandler {
    inbound: Arc<InboundHandler>,
    config: ReverseHttpConfig,
}

impl reverse_http::ReverseHttpForwardHandler<BoxAsyncStream> for ReverseHttpForwardHandler {
    fn handle_forward<'a>(
        &'a self,
        stream: BoxAsyncStream,
        peer: SocketAddr,
        destination: Endpoint,
        http_host: Option<String>,
        https: bool,
        rewritten_request: Vec<u8>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            debug_assert_eq!(https, self.config.https);
            let mut context = self.inbound.context(peer, Network::Tcp, destination);
            context.http_host = http_host;
            let connection = self.inbound.connect("reverse_http", context).await?;
            let connection = InboundStream {
                outbound: wrap_https_if_needed(connection.outbound, &self.config).await?,
                context: connection.context,
            };
            self.inbound
                .relay_with_prefix(stream, connection, peer, &rewritten_request)
                .await
                .map_err(io_error)
        })
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
