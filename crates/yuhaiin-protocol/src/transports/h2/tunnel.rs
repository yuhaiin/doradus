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
#[path = "tunnel_tests.rs"]
mod tests;
