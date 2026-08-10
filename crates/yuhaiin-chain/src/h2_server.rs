//! Server-side TLS + HTTP/2 transport for the Yuubinsya dispatcher.
//!
//! The transport owns only listener, TLS, HTTP/2 and stream-flow-control
//! concerns.  [`YuubinsyaServerProxy`](crate::YuubinsyaServerProxy) remains
//! responsible for authenticating and dispatching the protocol carried inside
//! each CONNECT stream.

use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use yuhaiin_core::{Error, ErrorKind, Result};

use crate::YuubinsyaServerProxy;
use crate::h2_tunnel::send_h2_data;

const H2_RELAY_CAPACITY: usize = 16 * 1024;

/// A TLS-enabled HTTP/2 server that dispatches each CONNECT body to a shared
/// Yuubinsya server proxy.
#[derive(Clone)]
pub struct YuubinsyaH2Server {
    acceptor: TlsAcceptor,
    proxy: Arc<YuubinsyaServerProxy>,
}

impl YuubinsyaH2Server {
    /// Build a server from a caller-owned rustls configuration.
    ///
    /// The configuration must advertise `h2` in ALPN.  Requiring this at the
    /// boundary prevents silently accepting HTTP/1.1 on a listener that is
    /// expected to carry H2 CONNECT streams.
    pub fn new(config: Arc<ServerConfig>, proxy: Arc<YuubinsyaServerProxy>) -> Result<Self> {
        if !config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol == b"h2")
        {
            return Err(Error::invalid(
                "Yuubinsya H2 server TLS config must advertise ALPN h2",
            ));
        }
        Ok(Self {
            acceptor: TlsAcceptor::from(config),
            proxy,
        })
    }

    /// Accept and serve TCP connections until the listener returns an error.
    pub async fn serve_listener(&self, listener: TcpListener) -> Result<()> {
        self.serve_listener_until(listener, std::future::pending::<()>())
            .await
    }

    /// Accept and serve TCP connections until `shutdown` resolves.
    ///
    /// Existing connections are aborted after shutdown and the shared
    /// Yuubinsya proxy is closed, which releases retained migrated UDP
    /// sessions and their full-cone NAT-facing upstream datagrams.
    pub async fn serve_listener_until<F>(&self, listener: TcpListener, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut shutdown = Box::pin(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.map_err(io_error)?;
                    let server = self.clone();
                    connections.spawn(async move { server.serve_tcp(stream).await });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    let _ = result;
                }
                _ = &mut shutdown => break,
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        self.proxy.close().await;
        Ok(())
    }

    /// Serve one accepted TCP connection through TLS and HTTP/2.
    pub async fn serve_tcp(&self, stream: TcpStream) -> Result<()> {
        let stream = self.acceptor.accept(stream).await.map_err(tls_error)?;
        let negotiated = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|protocol| protocol.to_vec());
        if negotiated.as_deref() != Some(b"h2") {
            return Err(Error::new(
                ErrorKind::Protocol,
                "Yuubinsya H2 server did not negotiate ALPN h2",
            ));
        }
        self.serve_h2(stream).await
    }

    /// Serve an already TLS-negotiated HTTP/2 I/O stream.
    ///
    /// This is public for platform listeners that obtain an accepted stream
    /// through a different pure-Rust transport, and makes the H2 boundary
    /// independently testable without weakening the production TLS check.
    pub async fn serve_h2<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mut connection = h2::server::handshake(stream)
            .await
            .map_err(|error| protocol_error(format!("HTTP/2 server handshake: {error}")))?;
        let mut streams = JoinSet::new();

        loop {
            tokio::select! {
                result = connection.accept() => {
                    let Some(result) = result else { break };
                    let (request, respond) = result
                        .map_err(|error| protocol_error(format!("HTTP/2 request: {error}")))?;
                    let proxy = Arc::clone(&self.proxy);
                    streams.spawn(async move { serve_connect(request, respond, proxy).await });
                }
                Some(result) = streams.join_next(), if !streams.is_empty() => {
                    // A single CONNECT failing must not tear down unrelated
                    // streams on the same H2 connection. The H2 connection
                    // itself remains driven by the accept future above.
                    let _ = result;
                }
            }
        }

        streams.abort_all();
        while streams.join_next().await.is_some() {}
        Ok(())
    }

    /// Close retained server-side migrated UDP sessions without needing to
    /// own the listener task itself.
    pub async fn close(&self) {
        self.proxy.close().await;
    }
}

async fn serve_connect(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    proxy: Arc<YuubinsyaServerProxy>,
) -> Result<()> {
    if request.method() != http::Method::CONNECT {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .map_err(|error| protocol_error(format!("HTTP/2 error response: {error}")))?;
        respond
            .send_response(response, true)
            .map_err(|error| protocol_error(format!("HTTP/2 error response send: {error}")))?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|error| protocol_error(format!("HTTP/2 CONNECT response: {error}")))?;
    let send = respond
        .send_response(response, false)
        .map_err(|error| protocol_error(format!("HTTP/2 CONNECT response send: {error}")))?;
    let (proxy_io, bridge_io) = tokio::io::duplex(H2_RELAY_CAPACITY);
    let bridge = tokio::spawn(bridge_h2_stream(request.into_body(), send, bridge_io));

    let result = proxy.serve(proxy_io).await;
    let _ = bridge.await;
    result
}

async fn bridge_h2_stream(
    mut body: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    relay_side: DuplexStream,
) -> Result<()> {
    let (mut reader, mut writer) = split(relay_side);
    let mut request_done = false;

    // The response sender may wait for the client's H2 flow-control window.
    // It must not block this task from consuming request data, otherwise a
    // full-duplex Yuubinsya stream can deadlock while both directions wait
    // for capacity updates.
    let mut send_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; H2_RELAY_CAPACITY];
        loop {
            let length = reader.read(&mut buffer).await.map_err(io_error)?;
            if length == 0 {
                send.send_data(Bytes::new(), true)
                    .map_err(|error| protocol_error(format!("HTTP/2 response end: {error}")))?;
                return Ok::<(), Error>(());
            }
            send_h2_data(&mut send, &buffer[..length]).await?;
        }
    });

    loop {
        tokio::select! {
            result = &mut send_task => {
                return match result {
                    Ok(result) => result,
                    Err(error) => Err(protocol_error(format!("HTTP/2 response task: {error}"))),
                };
            }
            result = body.data(), if !request_done => {
                let Some(result) = result else {
                    writer.shutdown().await.map_err(io_error)?;
                    request_done = true;
                    continue;
                };
                let data = result
                    .map_err(|error| protocol_error(format!("HTTP/2 request body: {error}")))?;
                body.flow_control()
                    .release_capacity(data.len())
                    .map_err(|error| protocol_error(format!("HTTP/2 request capacity: {error}")))?;
                writer.write_all(&data).await.map_err(io_error)?;
            }
        }
    }
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS accept: {error}"))
}

fn protocol_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, message.into())
}
