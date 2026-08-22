use futures_util::stream::{FuturesUnordered, StreamExt};
use http::Request;
use http_body_util::Empty;
use hyper::client::conn::http2::SendRequest;
use hyper::upgrade::Upgraded;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

use yuhaiin_core::{Error, ErrorKind, Result};

const DEFAULT_MAX_CONNECTIONS_PER_ENDPOINT: usize = 4;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(650);
type H2Body = Empty<bytes::Bytes>;

/// One HTTP/2 connection that can own multiple independent CONNECT streams.
/// The sender mutex is held only while opening a stream; data transfer is
/// handled by each stream's bounded relay and never serializes other flows.
pub struct H2Connection {
    sender: Mutex<SendRequest<H2Body>>,
    connection_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    relay_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    drain_lock: Mutex<()>,
    closed: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
    shutdown: watch::Sender<bool>,
    active_streams: Arc<AtomicUsize>,
    max_streams: usize,
    last_used_millis: AtomicU64,
    local_addr: Option<SocketAddr>,
}

/// Monotonic operational counters for the HTTP/2 pool.
///
/// The pool deliberately coalesces only streams targeting the same fixed
/// `SocketAddr` inside one `ChainClient`. It never merges DNS names, TLS
/// identities, or independently configured proxy chains. These counters make
/// that policy and its backpressure behavior observable without exposing the
/// internal h2 handles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H2PoolStats {
    pub connection_attempts: u64,
    pub connection_failures: u64,
    pub stream_capacity_rejections: u64,
    pub stream_open_failures: u64,
}

#[derive(Default)]
struct H2PoolMetrics {
    connection_attempts: AtomicU64,
    connection_failures: AtomicU64,
    stream_capacity_rejections: AtomicU64,
    stream_open_failures: AtomicU64,
}

impl H2PoolMetrics {
    fn snapshot(&self) -> H2PoolStats {
        H2PoolStats {
            connection_attempts: self.connection_attempts.load(Ordering::Relaxed),
            connection_failures: self.connection_failures.load(Ordering::Relaxed),
            stream_capacity_rejections: self.stream_capacity_rejections.load(Ordering::Relaxed),
            stream_open_failures: self.stream_open_failures.load(Ordering::Relaxed),
        }
    }
}

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

fn monotonic_millis() -> u64 {
    PROCESS_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

impl H2Connection {
    #[cfg(test)]
    pub async fn handshake_with_limits<S>(tls_stream: S, max_streams: usize) -> Result<Arc<Self>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::handshake_with_limits_and_local_addr(tls_stream, max_streams, None).await
    }

    pub async fn handshake_with_limits_and_local_addr<S>(
        tls_stream: S,
        max_streams: usize,
        local_addr: Option<SocketAddr>,
    ) -> Result<Arc<Self>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = hyper::client::conn::http2::handshake::<_, _, H2Body>(
            TokioExecutor::new(),
            TokioIo::new(tls_stream),
        )
        .await
        .map_err(|error| protocol_error(format!("HTTP/2 handshake: {error}")))?;
        let result = Arc::new(Self {
            sender: Mutex::new(sender),
            connection_task: Mutex::new(None),
            relay_tasks: Mutex::new(Vec::new()),
            drain_lock: Mutex::new(()),
            closed: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
            shutdown: watch::channel(false).0,
            active_streams: Arc::new(AtomicUsize::new(0)),
            max_streams: max_streams.max(1),
            last_used_millis: AtomicU64::new(monotonic_millis()),
            local_addr,
        });
        let closed = result.closed.clone();
        let shutdown = result.shutdown.clone();
        let task = tokio::spawn(async move {
            let _ = connection.await;
            closed.store(true, Ordering::Release);
            // The h2 driver can finish before every response body has
            // observed EOF (for example after a peer GOAWAY or transport
            // error). Wake all application relays explicitly so they cannot
            // retain a stream slot or wait forever on the local duplex side.
            let _ = shutdown.send(true);
        });
        *result.connection_task.lock().await = Some(task);
        Ok(result)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn at_capacity(&self) -> bool {
        self.active_streams() >= self.max_streams
    }

    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub async fn open_connect_stream(&self, concurrency: usize) -> Result<DuplexStream> {
        Ok(self
            .open_connect_stream_with_local_addr(concurrency)
            .await?
            .0)
    }

    pub async fn open_connect_stream_with_local_addr(
        &self,
        concurrency: usize,
    ) -> Result<(DuplexStream, Option<SocketAddr>)> {
        if self.is_closed() || self.is_draining() {
            return Err(protocol_error("HTTP/2 connection is closed"));
        }
        let mut active = self.active_streams.load(Ordering::Acquire);
        loop {
            if self.is_closed() || self.is_draining() {
                return Err(protocol_error("HTTP/2 connection is closed"));
            }
            if active >= self.max_streams {
                return Err(protocol_error("HTTP/2 connection is at stream capacity"));
            }
            match self.active_streams.compare_exchange(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }
        self.last_used_millis
            .store(monotonic_millis(), Ordering::Release);
        let request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("http://localhost")
            .body(Empty::new())
            .map_err(|error| {
                self.release_stream();
                Error::new(ErrorKind::InvalidInput, error.to_string())
            })?;
        let mut sender = self.sender.lock().await.clone();
        match timeout(Duration::from_secs(15), sender.ready()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.release_stream();
                return Err(protocol_error(format!("HTTP/2 stream readiness: {error}")));
            }
            Err(_) => {
                self.release_stream();
                return Err(protocol_error("HTTP/2 stream readiness timed out"));
            }
        }
        let response = match timeout(Duration::from_secs(15), sender.send_request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                self.release_stream();
                return Err(protocol_error(format!("HTTP/2 CONNECT request: {error}")));
            }
            Err(_) => {
                self.release_stream();
                return Err(protocol_error("HTTP/2 CONNECT response timed out"));
            }
        };
        if response.status() != http::StatusCode::OK {
            self.release_stream();
            return Err(protocol_error(format!(
                "HTTP/2 CONNECT returned {}",
                response.status()
            )));
        }

        let upgraded = match timeout(Duration::from_secs(15), hyper::upgrade::on(response)).await {
            Ok(Ok(upgraded)) => upgraded,
            Ok(Err(error)) => {
                self.release_stream();
                return Err(protocol_error(format!("HTTP/2 CONNECT upgrade: {error}")));
            }
            Err(_) => {
                self.release_stream();
                return Err(protocol_error("HTTP/2 CONNECT upgrade timed out"));
            }
        };
        let (application, relay_side) = tokio::io::duplex(16 * 1024 * concurrency.clamp(1, 64));
        let relay_task = tokio::spawn(relay(
            TokioIo::new(upgraded),
            relay_side,
            self.active_streams.clone(),
            self.shutdown.subscribe(),
        ));
        {
            let mut relay_tasks = self.relay_tasks.lock().await;
            relay_tasks.retain(|task| !task.is_finished());
        }
        self.relay_tasks.lock().await.push(relay_task);
        Ok((application, self.local_addr))
    }

    fn release_stream(&self) {
        self.active_streams.fetch_sub(1, Ordering::AcqRel);
    }

    fn is_idle(&self, idle_timeout: Duration) -> bool {
        let idle_millis =
            monotonic_millis().saturating_sub(self.last_used_millis.load(Ordering::Acquire));
        self.active_streams() == 0 && idle_millis >= idle_timeout.as_millis() as u64
    }

    /// Stop accepting new streams and wait for existing relays up to the
    /// deadline. Hyper drives peer GOAWAY and connection errors through the
    /// connection task; this method adds the application-level drain deadline
    /// for active CONNECT upgrades before closing the shared connection.
    pub async fn drain(&self, deadline: Duration) {
        let _drain_guard = self.drain_lock.lock().await;
        self.draining.store(true, Ordering::Release);
        let end = tokio::time::Instant::now() + deadline;
        while self.active_streams() != 0 && tokio::time::Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.closed.store(true, Ordering::Release);
        let _ = self.shutdown.send(true);
        let connection_task = self.connection_task.lock().await.take();
        if let Some(task) = connection_task {
            task.abort();
            let _ = task.await;
        }
        let relay_tasks = self.relay_tasks.lock().await.drain(..).collect::<Vec<_>>();
        for mut task in relay_tasks {
            let remaining = end.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                task.abort();
                let _ = task.await;
                continue;
            }
            if timeout(remaining, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }

    pub async fn close(&self) {
        self.drain(DEFAULT_DRAIN_TIMEOUT).await;
    }
}

impl Drop for H2Connection {
    fn drop(&mut self) {
        if let Some(task) = self.connection_task.get_mut().take() {
            task.abort();
        }
        for task in self.relay_tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct H2PoolKey {
    address: SocketAddr,
    bind_interface: Option<String>,
    tls_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2PoolEndpoint {
    pub address: SocketAddr,
    pub bind_interface: Option<String>,
}

/// A small endpoint, interface-policy, and TLS-identity keyed HTTP/2 pool.
/// Each fixed address/interface policy and configured TLS identity gets at
/// most the configured number of live h2 connections, while each connection
/// carries many CONNECT streams. This prevents a future caller that shares a
/// pool across TLS identities or network interfaces from accidentally
/// coalescing them.
pub struct H2Pool {
    connections: Mutex<HashMap<H2PoolKey, Vec<Arc<H2Connection>>>>,
    connect_lock: Mutex<()>,
    next: AtomicUsize,
    max_connections_per_endpoint: usize,
    idle_timeout: Duration,
    metrics: Arc<H2PoolMetrics>,
}

impl Default for H2Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl H2Pool {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_CONNECTIONS_PER_ENDPOINT, DEFAULT_IDLE_TIMEOUT)
    }

    pub fn with_limits(max_connections_per_endpoint: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            connect_lock: Mutex::new(()),
            next: AtomicUsize::new(0),
            max_connections_per_endpoint: max_connections_per_endpoint.max(1),
            idle_timeout,
            metrics: Arc::new(H2PoolMetrics::default()),
        }
    }

    pub fn stats(&self) -> H2PoolStats {
        self.metrics.snapshot()
    }

    #[cfg(test)]
    pub async fn open<F, Fut>(
        &self,
        addresses: &[SocketAddr],
        concurrency: usize,
        connect: F,
    ) -> Result<DuplexStream>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = Result<Arc<H2Connection>>>,
    {
        self.open_with_identity(addresses, "", concurrency, connect)
            .await
    }

    #[cfg(test)]
    pub async fn open_with_identity<F, Fut>(
        &self,
        addresses: &[SocketAddr],
        tls_identity: &str,
        concurrency: usize,
        connect: F,
    ) -> Result<DuplexStream>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = Result<Arc<H2Connection>>>,
    {
        Ok(self
            .open_with_identity_and_local_addr(addresses, tls_identity, concurrency, connect)
            .await?
            .0)
    }

    #[cfg(test)]
    pub async fn open_with_identity_and_local_addr<F, Fut>(
        &self,
        addresses: &[SocketAddr],
        tls_identity: &str,
        concurrency: usize,
        connect: F,
    ) -> Result<(DuplexStream, Option<SocketAddr>)>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = Result<Arc<H2Connection>>>,
    {
        let endpoints = addresses
            .iter()
            .copied()
            .map(|address| H2PoolEndpoint {
                address,
                bind_interface: None,
            })
            .collect::<Vec<_>>();
        self.open_with_endpoints_and_local_addr(&endpoints, tls_identity, concurrency, |endpoint| {
            connect(endpoint.address)
        })
        .await
    }

    pub async fn open_with_endpoints_and_local_addr<F, Fut>(
        &self,
        endpoints: &[H2PoolEndpoint],
        tls_identity: &str,
        concurrency: usize,
        connect: F,
    ) -> Result<(DuplexStream, Option<SocketAddr>)>
    where
        F: Fn(H2PoolEndpoint) -> Fut,
        Fut: Future<Output = Result<Arc<H2Connection>>>,
    {
        if endpoints.is_empty() {
            return Err(Error::invalid("HTTP/2 pool has no fixed endpoint"));
        }
        let mut last_error = None;
        self.reap_idle().await;
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..endpoints.len() {
            let endpoint = endpoints[(start + offset) % endpoints.len()].clone();
            let key = H2PoolKey {
                address: endpoint.address,
                bind_interface: endpoint.bind_interface.clone(),
                tls_identity: tls_identity.to_owned(),
            };
            let connections = self
                .connections
                .lock()
                .await
                .get(&key)
                .cloned()
                .unwrap_or_default();
            for connection in connections {
                match connection
                    .open_connect_stream_with_local_addr(concurrency)
                    .await
                {
                    Ok(stream) => return Ok(stream),
                    Err(_) if connection.is_closed() => {
                        self.remove_connection(&key, &connection).await;
                    }
                    Err(error) if connection.at_capacity() => {
                        self.metrics
                            .stream_capacity_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        let _ = error;
                    }
                    Err(error) => {
                        self.metrics
                            .stream_open_failures
                            .fetch_add(1, Ordering::Relaxed);
                        last_error = Some(error);
                        self.remove_connection(&key, &connection).await;
                        connection.close().await;
                    }
                }
            }
        }

        let _guard = self.connect_lock.lock().await;
        let mut candidates = Vec::new();
        for endpoint in endpoints {
            let key = H2PoolKey {
                address: endpoint.address,
                bind_interface: endpoint.bind_interface.clone(),
                tls_identity: tls_identity.to_owned(),
            };
            let connections = self
                .connections
                .lock()
                .await
                .get(&key)
                .cloned()
                .unwrap_or_default();
            for connection in connections {
                match connection
                    .open_connect_stream_with_local_addr(concurrency)
                    .await
                {
                    Ok(stream) => return Ok(stream),
                    Err(_) if connection.is_closed() => {
                        self.remove_connection(&key, &connection).await;
                    }
                    // The first scan already records a capacity rejection;
                    // this second scan is only the race-safe retry after the
                    // connect lock and must not double-count it.
                    Err(_) if connection.at_capacity() => {}
                    Err(error) => {
                        self.metrics
                            .stream_open_failures
                            .fetch_add(1, Ordering::Relaxed);
                        last_error = Some(error);
                        self.remove_connection(&key, &connection).await;
                        connection.close().await;
                    }
                }
            }
            let connection_count = self.connections.lock().await.get(&key).map_or(0, Vec::len);
            if connection_count >= self.max_connections_per_endpoint {
                continue;
            }
            candidates.push(endpoint.clone());
        }
        if candidates.is_empty() {
            return Err(last_error
                .unwrap_or_else(|| protocol_error("HTTP/2 pool could not open a connection")));
        }

        let (endpoint, connection, stream) = self
            .open_new_connection_happy_eyeballs(candidates, concurrency, &connect)
            .await?;
        let key = H2PoolKey {
            address: endpoint.address,
            bind_interface: endpoint.bind_interface,
            tls_identity: tls_identity.to_owned(),
        };
        self.connections
            .lock()
            .await
            .entry(key)
            .or_default()
            .push(connection);
        Ok(stream)
    }

    async fn open_new_connection_happy_eyeballs<F, Fut>(
        &self,
        endpoints: Vec<H2PoolEndpoint>,
        concurrency: usize,
        connect: &F,
    ) -> Result<(
        H2PoolEndpoint,
        Arc<H2Connection>,
        (DuplexStream, Option<SocketAddr>),
    )>
    where
        F: Fn(H2PoolEndpoint) -> Fut,
        Fut: Future<Output = Result<Arc<H2Connection>>>,
    {
        let mut attempts = FuturesUnordered::new();
        for (index, endpoint) in endpoints.into_iter().enumerate() {
            let metrics = Arc::clone(&self.metrics);
            attempts.push(async move {
                if index > 0 {
                    tokio::time::sleep(HAPPY_EYEBALLS_DELAY * index as u32).await;
                }
                metrics.connection_attempts.fetch_add(1, Ordering::Relaxed);
                let connection = match connect(endpoint.clone()).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        metrics.connection_failures.fetch_add(1, Ordering::Relaxed);
                        return Err(error);
                    }
                };
                let stream = match connection
                    .open_connect_stream_with_local_addr(concurrency)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        metrics.stream_open_failures.fetch_add(1, Ordering::Relaxed);
                        return Err(error);
                    }
                };
                Ok((endpoint, connection, stream))
            });
        }

        let mut last_error = None;
        while let Some(result) = attempts.next().await {
            match result {
                Ok(success) => return Ok(success),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| protocol_error("HTTP/2 pool could not open a connection")))
    }

    async fn remove_connection(&self, key: &H2PoolKey, target: &Arc<H2Connection>) {
        let mut connections = self.connections.lock().await;
        if let Some(current) = connections.get_mut(key) {
            current.retain(|connection| !Arc::ptr_eq(connection, target));
            if current.is_empty() {
                connections.remove(key);
            }
        }
    }

    pub async fn reap_idle(&self) {
        let mut idle = Vec::new();
        {
            let mut connections = self.connections.lock().await;
            for current in connections.values_mut() {
                let mut keep = Vec::with_capacity(current.len());
                for connection in current.drain(..) {
                    let remove = connection.is_closed() || connection.is_idle(self.idle_timeout);
                    if remove {
                        idle.push(connection);
                    } else {
                        keep.push(connection);
                    }
                }
                *current = keep;
            }
            connections.retain(|_, current| !current.is_empty());
        }
        for connection in idle {
            connection.close().await;
        }
    }

    pub async fn close(&self) {
        let connections = self
            .connections
            .lock()
            .await
            .drain()
            .flat_map(|(_, connections)| connections)
            .collect::<Vec<_>>();
        let mut closers = JoinSet::new();
        for connection in connections {
            closers.spawn(async move {
                connection.close().await;
            });
        }
        while closers.join_next().await.is_some() {}
    }

    pub async fn len(&self) -> usize {
        self.connections.lock().await.values().map(Vec::len).sum()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn active_streams(&self) -> usize {
        let connections = self.connections.lock().await;
        connections
            .values()
            .flat_map(|connections| connections.iter())
            .map(|connection| connection.active_streams())
            .sum()
    }
}

async fn relay(
    mut upgraded: TokioIo<Upgraded>,
    relay_side: DuplexStream,
    active_streams: Arc<AtomicUsize>,
    mut shutdown: watch::Receiver<bool>,
) {
    struct ActiveGuard<'a>(&'a AtomicUsize);
    impl Drop for ActiveGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let _active = ActiveGuard(&active_streams);
    if *shutdown.borrow() {
        return;
    }
    let mut relay_side = relay_side;
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut upgraded, &mut relay_side) => {}
        _ = shutdown.changed() => {
            let _ = relay_side.shutdown().await;
        }
    }
}

fn protocol_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Response;
    use std::collections::VecDeque;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "current_thread")]
    async fn h2_connect_stream_preserves_underlying_local_endpoint() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), true).unwrap();
            while connection.accept().await.is_some() {}
        });

        let local = "192.0.2.10:45678".parse().unwrap();
        let connection =
            H2Connection::handshake_with_limits_and_local_addr(client_io, 1, Some(local))
                .await
                .unwrap();
        let (_stream, observed) = connection
            .open_connect_stream_with_local_addr(1)
            .await
            .unwrap();
        assert_eq!(observed, Some(local));
        connection.close().await;
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connect_stream_relays_bytes_in_both_directions() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let request = connection.accept().await.unwrap().unwrap();
            let (request, mut respond) = request;
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut body = request.into_body();
            let send = respond.send_response(Response::new(()), false).unwrap();
            let echo = tokio::spawn(async move {
                let mut send = send;
                while let Some(data) = body.data().await {
                    let Ok(data) = data else { break };
                    if body.flow_control().release_capacity(data.len()).is_err() {
                        break;
                    }
                    if send.send_data(data, false).is_err() {
                        break;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
            });
            // The h2 connection itself must keep being polled while the
            // request/response stream handles are active.
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
            let _ = echo.await;
        });

        let connection = H2Connection::handshake_with_limits(client_io, 128)
            .await
            .unwrap();
        let mut tunnel = connection.open_connect_stream(8).await.unwrap();
        tunnel.write_all(b"hello over h2").await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut response = vec![0; 13];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello over h2");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hyper_connect_upgrade_respects_peer_flow_control() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let request = connection.accept().await.unwrap().unwrap();
            let (request, mut respond) = request;
            let _ = respond.send_response(Response::new(()), false).unwrap();
            let mut body = request.into_body();
            // Keep the connection driver active while the application body
            // is deliberately not released. Hyper's CONNECT upgrade must
            // stop at the peer's flow-control window instead of buffering
            // the entire application payload.
            let _ = connection.accept().await;
            let _ = body.data().await;
        });

        let connection = H2Connection::handshake_with_limits(client_io, 1)
            .await
            .unwrap();
        let mut stream = connection.open_connect_stream(1).await.unwrap();
        let payload = vec![0x5a; 128 * 1024];
        let send = tokio::spawn(async move { stream.write_all(&payload).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !send.is_finished(),
            "CONNECT upgrade buffered past peer window"
        );

        connection.close().await;
        let _ = send.await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn random_peer_bytes_do_not_panic_or_hang_h2_handshake() {
        // The peer side deliberately is not an h2 implementation.  This is
        // a small deterministic wire-fuzz regression: malformed prefaces,
        // truncated settings, and arbitrary frame headers must become an
        // error (or a bounded timeout), never a task panic or an unbounded
        // wait in the client handshake.
        let mut state = 0x9e37_79b9_u32;
        for case in 0..96 {
            let (client_io, mut peer_io) = tokio::io::duplex(4096);
            let length = (next_random(&mut state) as usize % 1537).min(2048);
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                *byte = next_random(&mut state) as u8;
            }
            let peer = tokio::spawn(async move {
                let _ = peer_io.write_all(&bytes).await;
                let _ = peer_io.shutdown().await;
            });

            let result = timeout(
                Duration::from_millis(250),
                H2Connection::handshake_with_limits(client_io, 1),
            )
            .await;
            if let Ok(Ok(connection)) = result {
                connection.close().await;
            }
            timeout(Duration::from_millis(250), peer)
                .await
                .unwrap_or_else(|_| panic!("random h2 peer case {case} did not finish"))
                .unwrap_or_else(|error| panic!("random h2 peer case {case} panicked: {error}"));
        }
    }

    fn next_random(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *state
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_h2_frames_after_settings_are_bounded() {
        // A valid server SETTINGS frame lets the client handshake complete;
        // each following frame is intentionally invalid at the connection or
        // stream level.  This exercises the live h2 driver rather than only
        // the preface error path above.
        let malformed_frames = [
            frame_header(0, 0x0, 0, 0),           // DATA on stream 0
            frame_header(0, 0x1, 0, 0),           // HEADERS on stream 0
            frame_header(0, 0x4, 0, 1),           // SETTINGS on stream 1
            frame_header(0, 0x6, 0, 1),           // PING on stream 1
            frame_header(0, 0x9, 0, 1),           // CONTINUATION without HEADERS
            frame_header(0, 0x0, 0, 0x8000_0001), // reserved stream-id bit
            frame_header(0x00ff_ffff, 0x0, 0, 1), // truncated oversized DATA
        ];
        for (case, malformed) in malformed_frames.into_iter().enumerate() {
            let (client_io, mut peer_io) = tokio::io::duplex(4096);
            let mut wire = Vec::with_capacity(9 + malformed.len());
            wire.extend_from_slice(&frame_header(0, 0x4, 0, 0)); // SETTINGS
            wire.extend_from_slice(&malformed);
            let peer = tokio::spawn(async move {
                let _ = peer_io.write_all(&wire).await;
                let _ = peer_io.shutdown().await;
            });

            let result = timeout(
                Duration::from_millis(250),
                H2Connection::handshake_with_limits(client_io, 1),
            )
            .await;
            if let Ok(Ok(connection)) = result {
                let _ = timeout(Duration::from_millis(250), async {
                    while !connection.is_closed() {
                        tokio::task::yield_now().await;
                    }
                })
                .await;
                connection.close().await;
            }
            timeout(Duration::from_millis(250), peer)
                .await
                .unwrap_or_else(|_| panic!("malformed h2 frame case {case} did not finish"))
                .unwrap_or_else(|error| panic!("malformed h2 frame case {case} panicked: {error}"));
        }
    }

    fn frame_header(length: u32, kind: u8, flags: u8, stream_id: u32) -> Vec<u8> {
        vec![
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            kind,
            flags,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ]
    }

    #[test]
    fn h2_pool_key_keeps_interface_binding_isolated() {
        let address = "127.0.0.1:443".parse().unwrap();
        let without_interface = H2PoolKey {
            address,
            bind_interface: None,
            tls_identity: "identity".to_owned(),
        };
        let with_interface = H2PoolKey {
            address,
            bind_interface: Some("eth0".to_owned()),
            tls_identity: "identity".to_owned(),
        };
        assert_ne!(without_interface, with_interface);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_does_not_coalesce_different_tls_identities() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let server = |io| async move {
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while connection.accept().await.is_some() {}
        };
        let server_one = tokio::spawn(server(server_one));
        let server_two = tokio::spawn(server(server_two));
        let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::with_limits(2, Duration::from_secs(300));

        let first = pool
            .open_with_identity(&[address], "tls-identity-a", 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let transport = io.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "first TLS identity transport missing")
                        })?;
                        H2Connection::handshake_with_limits(transport, 128).await
                    }
                }
            })
            .await
            .unwrap();
        let second = pool
            .open_with_identity(&[address], "tls-identity-b", 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let transport = io.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "second TLS identity transport missing")
                        })?;
                        H2Connection::handshake_with_limits(transport, 128).await
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(pool.len().await, 2);
        assert_eq!(pool.active_streams().await, 2);
        assert_eq!(pool.stats().connection_attempts, 2);

        drop(first);
        drop(second);
        pool.close().await;
        server_one.abort();
        server_two.abort();
        let _ = server_one.await;
        let _ = server_two.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_reuses_one_connection_for_multiple_connect_streams() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(2);
            for _ in 0..2 {
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::CONNECT);
                let mut body = request.into_body();
                let mut send = respond.send_response(Response::new(()), false).unwrap();
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    while let Some(data) = body.data().await {
                        let Ok(data) = data else { break };
                        if body.flow_control().release_capacity(data.len()).is_err() {
                            break;
                        }
                        if send.send_data(data, false).is_err() {
                            break;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                    let _ = done_tx.send(()).await;
                });
            }
            drop(done_tx);
            let mut completed = 0;
            while completed < 2 {
                tokio::select! {
                    _ = done_rx.recv() => completed += 1,
                    result = connection.accept() => {
                        if result.is_none() {
                            break;
                        }
                    }
                }
            }
        });

        let io = Arc::new(Mutex::new(Some(client_io)));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::new();
        let mut first = pool
            .open(&[address], 4, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let io = io.lock().await.take().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "test h2 transport already taken")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            })
            .await
            .unwrap();
        let mut second = pool
            .open(&[address], 4, |_| async {
                Err(Error::new(
                    ErrorKind::Closed,
                    "pool should not create a second connection",
                ))
            })
            .await
            .unwrap();
        assert_eq!(pool.len().await, 1);
        assert_eq!(pool.active_streams().await, 2);

        first.write_all(b"first").await.unwrap();
        second.write_all(b"second").await.unwrap();
        let mut first_response = [0u8; 5];
        let mut second_response = [0u8; 6];
        first.read_exact(&mut first_response).await.unwrap();
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&first_response, b"first");
        assert_eq!(&second_response, b"second");

        pool.close().await;
        assert_eq!(pool.len().await, 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_falls_back_to_next_endpoint_after_connection_failure() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while connection.accept().await.is_some() {}
        });

        let unreachable_v6 = "[2001:db8::1]:443".parse().unwrap();
        let reachable_v4 = "127.0.0.1:443".parse().unwrap();
        let io = Arc::new(Mutex::new(Some(client_io)));
        let pool = H2Pool::new();
        let stream = tokio::time::timeout(
            Duration::from_secs(2),
            pool.open(&[unreachable_v6, reachable_v4], 1, {
                let io = Arc::clone(&io);
                move |address| {
                    let io = Arc::clone(&io);
                    async move {
                        if address == unreachable_v6 {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            return Err(Error::new(
                                ErrorKind::Io,
                                "simulated unreachable IPv6 endpoint",
                            ));
                        }
                        let io = io.lock().await.take().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "test transport missing")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            }),
        )
        .await
        .expect("IPv4 fallback did not race the stalled IPv6 endpoint")
        .unwrap();
        assert_eq!(pool.stats().connection_attempts, 2);
        drop(stream);
        pool.close().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_rebuilds_after_the_underlying_h2_connection_ends() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let server_one = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_one).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), true).unwrap();
            connection.graceful_shutdown();
            while connection.accept().await.is_some() {}
        });
        let server_two = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_two).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), true).unwrap();
            connection.graceful_shutdown();
            while connection.accept().await.is_some() {}
        });

        let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::new();
        let first = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let io = io.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "test h2 transports exhausted")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            })
            .await
            .unwrap();
        drop(first);
        server_one.await.unwrap();

        let second = tokio::time::timeout(
            Duration::from_secs(1),
            pool.open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let io = io.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "pool did not rebuild h2 connection")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            }),
        )
        .await
        .expect("h2 pool reconnect timed out")
        .unwrap();
        drop(second);
        assert_eq!(pool.len().await, 1);
        pool.close().await;
        server_two.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_rebuilds_after_a_stream_error_on_a_live_connection() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let server_one = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_one).await.unwrap();
            for status in [http::StatusCode::OK, http::StatusCode::BAD_GATEWAY] {
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::CONNECT);
                respond
                    .send_response(Response::builder().status(status).body(()).unwrap(), true)
                    .unwrap();
            }
            while connection.accept().await.is_some() {}
        });
        let server_two = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_two).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), true).unwrap();
            connection.graceful_shutdown();
            while connection.accept().await.is_some() {}
        });

        let transports = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
        let connection_attempts = Arc::new(AtomicUsize::new(0));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::with_limits(1, Duration::from_secs(300));
        let first = pool
            .open(&[address], 1, {
                let transports = Arc::clone(&transports);
                let connection_attempts = Arc::clone(&connection_attempts);
                move |_| {
                    let transports = Arc::clone(&transports);
                    let connection_attempts = Arc::clone(&connection_attempts);
                    async move {
                        connection_attempts.fetch_add(1, Ordering::Relaxed);
                        let io = transports.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "test h2 transports exhausted")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            })
            .await
            .unwrap();
        drop(first);
        let second = pool
            .open(&[address], 1, {
                let transports = Arc::clone(&transports);
                let connection_attempts = Arc::clone(&connection_attempts);
                move |_| {
                    let transports = Arc::clone(&transports);
                    let connection_attempts = Arc::clone(&connection_attempts);
                    async move {
                        connection_attempts.fetch_add(1, Ordering::Relaxed);
                        let io = transports.lock().await.pop_front().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "pool did not rebuild h2 connection")
                        })?;
                        H2Connection::handshake_with_limits(io, 128).await
                    }
                }
            })
            .await
            .expect("pool should rebuild after a live connection rejects a stream");

        assert_eq!(connection_attempts.load(Ordering::Relaxed), 2);
        drop(second);
        pool.close().await;
        server_one.abort();
        let _ = server_one.await;
        server_two.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_goaway_closes_active_stream_and_rejects_new_streams() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (goaway_tx, goaway_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            tokio::select! {
                _ = goaway_rx => {
                    connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                    while connection.accept().await.is_some() {}
                }
                result = async {
                    while connection.accept().await.is_some() {}
                } => result,
            }
        });
        let connection = H2Connection::handshake_with_limits(client_io, 128)
            .await
            .unwrap();
        let mut stream = connection.open_connect_stream(1).await.unwrap();
        goaway_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client did not observe peer GOAWAY");
        assert!(connection.open_connect_stream(1).await.is_err());
        let mut buffer = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .expect("peer GOAWAY did not close the active relay");
        assert!(matches!(result, Ok(0) | Err(_)));
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.active_streams() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer GOAWAY left an active stream slot behind");
        server.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_opens_a_second_connection_when_one_reaches_stream_capacity() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let server = |io| async move {
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while connection.accept().await.is_some() {}
        };
        let server_one = tokio::spawn(server(server_one));
        let server_two = tokio::spawn(server(server_two));
        let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::with_limits(2, Duration::from_secs(300));
        let mut first = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let io = io.lock().await.pop_front().unwrap();
                        H2Connection::handshake_with_limits(io, 1).await
                    }
                }
            })
            .await
            .unwrap();
        let mut second = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        let io = io.lock().await.pop_front().unwrap();
                        H2Connection::handshake_with_limits(io, 1).await
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(pool.len().await, 2);
        assert_eq!(pool.active_streams().await, 2);
        let stats = pool.stats();
        assert_eq!(stats.connection_attempts, 2);
        assert_eq!(stats.connection_failures, 0);
        assert_eq!(stats.stream_capacity_rejections, 1);
        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        pool.close().await;
        server_one.abort();
        server_two.abort();
        let _ = server_one.await;
        let _ = server_two.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_close_drains_multiple_connections_in_parallel() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let server = |io| async move {
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while connection.accept().await.is_some() {}
        };
        let server_one = tokio::spawn(server(server_one));
        let server_two = tokio::spawn(server(server_two));
        let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::with_limits(2, Duration::from_secs(300));
        let first = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        H2Connection::handshake_with_limits(io.lock().await.pop_front().unwrap(), 1)
                            .await
                    }
                }
            })
            .await
            .unwrap();
        let second = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        H2Connection::handshake_with_limits(io.lock().await.pop_front().unwrap(), 1)
                            .await
                    }
                }
            })
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        pool.close().await;
        assert!(
            started.elapsed() < Duration::from_millis(1_800),
            "pool close exceeded one shared drain deadline: {:?}",
            started.elapsed()
        );
        assert_eq!(pool.len().await, 0);
        assert_eq!(pool.active_streams().await, 0);
        drop(first);
        drop(second);
        server_one.abort();
        server_two.abort();
        let _ = server_one.await;
        let _ = server_two.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_reaps_only_idle_connections() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let io = Arc::new(Mutex::new(Some(client_io)));
        let address = "127.0.0.1:443".parse().unwrap();
        let pool = H2Pool::with_limits(1, Duration::from_millis(10));
        let stream = pool
            .open(&[address], 1, {
                let io = Arc::clone(&io);
                move |_| {
                    let io = Arc::clone(&io);
                    async move {
                        H2Connection::handshake_with_limits(io.lock().await.take().unwrap(), 128)
                            .await
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(pool.active_streams().await, 1);
        pool.reap_idle().await;
        assert_eq!(pool.len().await, 1);
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        pool.reap_idle().await;
        assert_eq!(pool.len().await, 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_drain_rejects_new_streams_and_has_a_deadline() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while connection.accept().await.is_some() {}
        });
        let connection = H2Connection::handshake_with_limits(client_io, 128)
            .await
            .unwrap();
        let mut stream = connection.open_connect_stream(1).await.unwrap();
        let started = Instant::now();
        connection.drain(Duration::from_millis(20)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(connection.is_closed());
        assert!(connection.connection_task.lock().await.is_none());
        assert!(connection.relay_tasks.lock().await.is_empty());
        assert!(connection.open_connect_stream(1).await.is_err());
        let mut eof = [0u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_tcp_connection_drain_releases_socket_and_server_task() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (server_io, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond.send_response(Response::new(()), false).unwrap();
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });

        let client_io = tokio::net::TcpStream::connect(address).await.unwrap();
        let connection = H2Connection::handshake_with_limits(client_io, 1)
            .await
            .unwrap();
        let mut stream = connection.open_connect_stream(1).await.unwrap();
        connection.drain(Duration::from_millis(20)).await;

        assert!(connection.is_closed());
        assert_eq!(connection.active_streams(), 0);
        assert!(connection.connection_task.lock().await.is_none());
        assert!(connection.relay_tasks.lock().await.is_empty());
        let mut eof = [0u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
        timeout(Duration::from_secs(1), server)
            .await
            .expect("real h2 server did not observe client teardown")
            .expect("real h2 server task panicked");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_connect_response_releases_the_reserved_stream_slot() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond
                .send_response(
                    Response::builder()
                        .status(http::StatusCode::BAD_GATEWAY)
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
        });
        let connection = H2Connection::handshake_with_limits(client_io, 1)
            .await
            .unwrap();
        assert!(connection.open_connect_stream(1).await.is_err());
        assert_eq!(connection.active_streams(), 0);
        connection.close().await;
        server.await.unwrap();
    }
}
