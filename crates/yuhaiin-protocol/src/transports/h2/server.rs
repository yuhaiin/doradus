//! Server-side TLS + HTTP/2 transport for the Yuubinsya dispatcher.
//!
//! The transport owns only listener, TLS, HTTP/2 and stream-flow-control
//! concerns.  [`YuubinsyaServerProxy`](crate::YuubinsyaServerProxy) remains
//! responsible for authenticating and dispatching the protocol carried inside
//! each CONNECT stream.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder;
use hyper::service::service_fn;
use hyper::upgrade::on;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use yuhaiin_core::{Error, ErrorKind, Result};

use crate::session::YuubinsyaServerProxy;

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
        let streams = Arc::new(Mutex::new(JoinSet::new()));
        let proxy = Arc::clone(&self.proxy);
        let active_streams = Arc::clone(&streams);
        let service = service_fn(move |request: Request<Incoming>| {
            serve_connect(request, Arc::clone(&proxy), Arc::clone(&active_streams))
        });
        let result = Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .map_err(|error| protocol_error(format!("HTTP/2 connection: {error}")));

        let mut streams = streams.lock().await;
        streams.abort_all();
        while streams.join_next().await.is_some() {}
        result
    }

    /// Close retained server-side migrated UDP sessions without needing to
    /// own the listener task itself.
    pub async fn close(&self) {
        self.proxy.close().await;
    }
}

async fn serve_connect(
    request: Request<Incoming>,
    proxy: Arc<YuubinsyaServerProxy>,
    streams: Arc<Mutex<JoinSet<()>>>,
) -> std::result::Result<Response<H2Body>, Infallible> {
    if request.method() != http::Method::CONNECT {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(empty_body())
            .expect("static HTTP/2 method response cannot fail"));
    }

    let upgrade = on(request);
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Empty::new())
        .expect("static HTTP/2 CONNECT response cannot fail");
    streams.lock().await.spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            let _ = proxy.serve(TokioIo::new(upgraded)).await;
        }
    });
    Ok(response)
}

type H2Body = Empty<Bytes>;

fn empty_body() -> H2Body {
    Empty::new()
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
