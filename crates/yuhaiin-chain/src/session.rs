use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use yuhaiin_core::flow::{Flow, FlowDirection, FlowKey, FlowObserver, FlowObserverGuard};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy};
use yuhaiin_core::yuubinsya::{
    YuubinsyaHeader, YuubinsyaProtocol, decode_header, decode_header_any, decode_uot_frame,
    encode_header, encode_uot_frame,
};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Result};

pub(crate) const MAX_UOT_COALESCE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_UOT_COALESCE_FRAMES: usize = 32;
const SERVER_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SERVER_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Optional DNS boundary for the Yuubinsya inbound session. The chain crate
/// owns Yuubinsya framing; the embedding runtime owns resolver policy.
pub trait YuubinsyaDnsHandler: Send + Sync {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>>;
}

/// A Yuubinsya TCP stream after the authenticated destination header has been
/// sent. The remaining bytes are transparent TCP payload.
pub struct AsyncYuubinsyaTcpSession<S> {
    stream: S,
    password_hash: [u8; 32],
    write_shutdown: bool,
}

/// Persistent Yuubinsya ping session.  The first response is produced after
/// the Ping header; later requests are eight-byte probes on the same stream.
pub struct AsyncYuubinsyaPingSession<S> {
    stream: S,
    write_shutdown: bool,
}

/// Server-side Ping boundary.  The actual dial/latency probe is injected by
/// the caller; this type only owns authentication, header validation and the
/// persistent probe wire format.
pub struct AsyncYuubinsyaPingServerSession<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaPingSession<S> {
    pub async fn connect(
        mut stream: S,
        password_hash: [u8; 32],
        destination: Endpoint,
    ) -> Result<(Self, Duration)> {
        let started = std::time::Instant::now();
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::Ping,
                migrate_id: None,
                destination: Some(destination),
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.map_err(io_error)?;
        if response == [0xff; 8] {
            return Err(Error::new(ErrorKind::Closed, "Yuubinsya ping failed"));
        }
        Ok((
            Self {
                stream,
                write_shutdown: false,
            },
            started.elapsed(),
        ))
    }

    pub async fn ping(&mut self) -> Result<Duration> {
        let started = std::time::Instant::now();
        self.stream
            .write_all(&0u64.to_be_bytes())
            .await
            .map_err(io_error)?;
        self.stream.flush().await.map_err(io_error)?;
        let mut response = [0u8; 8];
        self.stream
            .read_exact(&mut response)
            .await
            .map_err(io_error)?;
        if response == [0xff; 8] {
            return Err(Error::new(ErrorKind::Closed, "Yuubinsya ping failed"));
        }
        Ok(started.elapsed())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.write_shutdown {
            return Ok(());
        }
        self.stream.shutdown().await.map_err(io_error)?;
        self.write_shutdown = true;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaPingServerSession<S> {
    pub async fn accept(mut stream: S, password_hash: [u8; 32]) -> Result<(Self, Endpoint)> {
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _) = decode_header(&password_hash, &header_bytes)?;
        if header.protocol != YuubinsyaProtocol::Ping {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya Ping server received a non-Ping protocol",
            ));
        }
        let destination = header.destination.ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "Yuubinsya Ping header has no destination",
            )
        })?;
        Ok((Self { stream }, destination))
    }

    /// Reply to the initial Ping and exactly one follow-up probe.  A failed
    /// probe is represented by the protocol's all-ones sentinel; the caller
    /// decides how to measure the destination.
    pub async fn serve_one_probe(
        &mut self,
        initial: Result<Duration>,
        follow_up: Result<Duration>,
    ) -> Result<()> {
        write_ping_reply(&mut self.stream, initial).await?;
        let mut probe = [0u8; 8];
        self.stream.read_exact(&mut probe).await.map_err(io_error)?;
        if probe != [0; 8] {
            return Err(Error::new(
                ErrorKind::Protocol,
                "Yuubinsya Ping probe is not zero",
            ));
        }
        write_ping_reply(&mut self.stream, follow_up).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncYuubinsyaTcpSession<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncYuubinsyaTcpSession<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaTcpSession<S> {
    pub async fn connect(
        mut stream: S,
        password_hash: [u8; 32],
        destination: Endpoint,
    ) -> Result<Self> {
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::Tcp,
                migrate_id: None,
                destination: Some(destination),
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
            write_shutdown: false,
        })
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.stream.read(buffer).await.map_err(io_error)
    }

    pub async fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        self.stream.read_exact(buffer).await.map_err(io_error)?;
        Ok(())
    }

    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        self.stream.write_all(buffer).await.map_err(io_error)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.write_shutdown {
            return Ok(());
        }
        self.stream.shutdown().await.map_err(io_error)?;
        self.write_shutdown = true;
        Ok(())
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// Yuubinsya UDP-over-TCP session. A session starts with the migrate-ID
/// handshake and then carries `[address][u16 length][payload]` frames.
pub struct AsyncYuubinsyaUotSession<S> {
    stream: S,
    password_hash: [u8; 32],
    pub migrate_id: u64,
    pub udp_coalesce: bool,
    pending: Vec<u8>,
    pending_frames: usize,
    write_shutdown: bool,
}

/// Server-side UOT session.  It owns only the authenticated migration
/// handshake and frame codec; destination dispatch remains injected by the
/// caller.
pub struct AsyncYuubinsyaUotServerSession<S> {
    stream: S,
    password_hash: [u8; 32],
    pub migrate_id: u64,
}

enum ServerUdpMessage {
    Data { source: Endpoint, payload: Vec<u8> },
    Closed,
}

struct ServerUdpSession {
    datagram: Arc<dyn AsyncDatagram>,
    routes: Mutex<HashMap<Endpoint, mpsc::Sender<ServerUdpMessage>>>,
    last_sender: Mutex<Option<mpsc::Sender<ServerUdpMessage>>>,
    last_used: StdMutex<Instant>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ServerUdpSession {
    async fn spawn(datagram: Box<dyn AsyncDatagram>) -> Arc<Self> {
        let session = Arc::new(Self {
            datagram: Arc::from(datagram),
            routes: Mutex::new(HashMap::new()),
            last_sender: Mutex::new(None),
            last_used: StdMutex::new(Instant::now()),
            worker: Mutex::new(None),
        });
        let worker_session = Arc::clone(&session);
        let worker = tokio::spawn(async move {
            worker_session.run_reader().await;
        });
        *session.worker.lock().await = Some(worker);
        session
    }

    async fn run_reader(self: Arc<Self>) {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let result = tokio::time::timeout(
                SERVER_UDP_RESPONSE_TIMEOUT,
                self.datagram.recv_from(&mut buffer),
            )
            .await;
            let Ok(Ok((length, source))) = result else {
                self.notify_closed().await;
                return;
            };
            self.touch();
            let sender = {
                let routes = self.routes.lock().await;
                routes.get(&source).cloned()
            };
            let sender = match sender {
                Some(sender) => Some(sender),
                None => self.last_sender.lock().await.clone(),
            };
            let Some(sender) = sender else {
                continue;
            };
            if sender
                .send(ServerUdpMessage::Data {
                    source,
                    payload: buffer[..length].to_vec(),
                })
                .await
                .is_err()
            {
                self.unregister_sender(&sender).await;
            }
        }
    }

    fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = Instant::now();
        }
    }

    fn is_idle(&self, now: Instant) -> bool {
        self.last_used
            .lock()
            .map(|last_used| now.duration_since(*last_used) >= SERVER_UDP_IDLE_TIMEOUT)
            .unwrap_or(false)
    }

    async fn register(
        &self,
        destination: Endpoint,
    ) -> (
        mpsc::Sender<ServerUdpMessage>,
        mpsc::Receiver<ServerUdpMessage>,
    ) {
        let (sender, receiver) = mpsc::channel(64);
        self.routes.lock().await.insert(destination, sender.clone());
        *self.last_sender.lock().await = Some(sender.clone());
        self.touch();
        (sender, receiver)
    }

    async fn route(&self, destination: Endpoint, sender: &mpsc::Sender<ServerUdpMessage>) {
        self.routes.lock().await.insert(destination, sender.clone());
        *self.last_sender.lock().await = Some(sender.clone());
        self.touch();
    }

    async fn unregister_sender(&self, sender: &mpsc::Sender<ServerUdpMessage>) {
        let remaining = {
            let mut routes = self.routes.lock().await;
            routes.retain(|_, current| !current.same_channel(sender));
            routes.values().next().cloned()
        };
        let mut last_sender = self.last_sender.lock().await;
        if last_sender
            .as_ref()
            .is_some_and(|current| current.same_channel(sender))
        {
            *last_sender = remaining;
        }
    }

    async fn notify_closed(&self) {
        let senders = self
            .routes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for sender in senders {
            let _ = sender.send(ServerUdpMessage::Closed).await;
        }
    }

    async fn send_to(&self, payload: &[u8], target: Endpoint) -> Result<usize> {
        self.touch();
        self.datagram.send_to(payload, target).await
    }

    async fn close(&self) {
        let _ = self.datagram.close().await;
        self.notify_closed().await;
        if let Some(worker) = self.worker.lock().await.take() {
            worker.abort();
            let _ = worker.await;
        }
    }
}

/// Server-side Yuubinsya protocol dispatcher.
///
/// The transport listener and HTTP/2 server remain outside this type. The
/// caller hands each authenticated stream to [`serve`], while the injected
/// `AsyncProxy` owns the actual outbound TCP/UDP routing policy. UOT sessions
/// are keyed by migrate id, so a new HTTP/2 stream can continue an existing
/// UDP flow instead of creating a second upstream datagram.
pub struct YuubinsyaServerProxy {
    password_hashes: Arc<[[u8; 32]]>,
    upstream: Arc<dyn AsyncProxy>,
    next_migrate_id: AtomicU64,
    udp_sessions: Mutex<HashMap<u64, Arc<ServerUdpSession>>>,
    udp_open_lock: Mutex<()>,
}

struct ObservedInbound {
    source: SocketAddr,
    observer: Arc<dyn FlowObserver>,
    annotate: Arc<dyn Fn(&mut FlowContext) + Send + Sync>,
}

struct ObservedFlow {
    flow: FlowKey,
    _observation: FlowObserverGuard,
}

impl YuubinsyaServerProxy {
    pub fn new(password_hash: [u8; 32], upstream: Arc<dyn AsyncProxy>) -> Self {
        Self::new_with_password_hashes(vec![password_hash], upstream)
    }

    pub fn new_with_password_hashes(
        password_hashes: Vec<[u8; 32]>,
        upstream: Arc<dyn AsyncProxy>,
    ) -> Self {
        let password_hashes = if password_hashes.is_empty() {
            vec![[0u8; 32]]
        } else {
            password_hashes
        };
        Self {
            password_hashes: password_hashes.into(),
            upstream,
            next_migrate_id: AtomicU64::new(1),
            udp_sessions: Mutex::new(HashMap::new()),
            udp_open_lock: Mutex::new(()),
        }
    }

    /// Serve one Yuubinsya stream. A closed stream returns its underlying I/O
    /// error; the listener may treat that as normal per-stream cleanup.
    pub async fn serve<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_inner(&mut stream, None, None).await
    }

    /// Serve an inbound stream while publishing the same lifecycle and byte
    /// callbacks used by the TUN monitor. The chain crate owns protocol
    /// framing; the application only supplies the source endpoint and a
    /// context annotator for inbound/outbound metadata.
    pub async fn serve_observed<S, F>(
        &self,
        stream: S,
        source: SocketAddr,
        observer: Arc<dyn FlowObserver>,
        annotate: F,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(&mut FlowContext) + Send + Sync + 'static,
    {
        self.serve_observed_with_dns(stream, source, observer, annotate, None)
            .await
    }

    pub async fn serve_observed_with_dns<S, F>(
        &self,
        mut stream: S,
        source: SocketAddr,
        observer: Arc<dyn FlowObserver>,
        annotate: F,
        dns_handler: Option<Arc<dyn YuubinsyaDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(&mut FlowContext) + Send + Sync + 'static,
    {
        self.serve_inner(
            &mut stream,
            Some(ObservedInbound {
                source,
                observer,
                annotate: Arc::new(annotate),
            }),
            dns_handler,
        )
        .await
    }

    async fn serve_inner<S>(
        &self,
        stream: &mut S,
        observed: Option<ObservedInbound>,
        dns_handler: Option<Arc<dyn YuubinsyaDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let header_bytes = read_header_bytes(&mut *stream).await?;
        let (header, _, password_hash) = decode_header_any(&self.password_hashes, &header_bytes)?;
        match header.protocol {
            YuubinsyaProtocol::Tcp => {
                let destination = header.destination.ok_or_else(|| {
                    Error::new(
                        ErrorKind::Protocol,
                        "Yuubinsya TCP header has no destination",
                    )
                })?;
                let mut inbound = AsyncYuubinsyaTcpSession {
                    stream: stream,
                    password_hash,
                    write_shutdown: false,
                };
                let mut context = FlowContext::new(destination.clone());
                let flow = observed.as_ref().map(|observed| {
                    context.source =
                        Some(Endpoint::ip(yuhaiin_core::Network::Tcp, observed.source));
                    (observed.annotate)(&mut context);
                    FlowKey {
                        network: yuhaiin_core::Network::Tcp,
                        source: observed.source,
                        destination: endpoint_socket_addr(&destination, observed.source),
                    }
                });
                let mut prefix = Vec::new();
                if destination.port() == Some(53) {
                    if let Some(handler) = dns_handler.as_deref() {
                        match intercept_dns_tcp(&mut inbound, handler).await? {
                            DnsTcpDecision::Answered { upload, download } => {
                                if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                                    let _observation = FlowObserverGuard::open(
                                        Arc::clone(&observed.observer),
                                        Flow { key: flow },
                                        context,
                                    );
                                    observed.observer.bytes(flow, FlowDirection::Upload, upload);
                                    observed.observer.bytes(
                                        flow,
                                        FlowDirection::Download,
                                        download,
                                    );
                                }
                                return Ok(());
                            }
                            DnsTcpDecision::Forward(bytes) => prefix = bytes,
                        }
                    }
                }
                let mut outbound = self.upstream.connect(&context).await?;
                if !prefix.is_empty() {
                    outbound.write_all(&prefix).await.map_err(io_error)?;
                    if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                        observed
                            .observer
                            .bytes(flow, FlowDirection::Upload, prefix.len());
                    }
                }
                if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                    let _observation = FlowObserverGuard::open(
                        Arc::clone(&observed.observer),
                        Flow { key: flow },
                        context,
                    );
                    let result = copy_bidirectional_observed(
                        &mut inbound,
                        &mut outbound,
                        Arc::clone(&observed.observer),
                        flow,
                    )
                    .await
                    .map_err(io_error);
                    result?;
                } else {
                    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                        .await
                        .map_err(io_error)?;
                }
                Ok(())
            }
            YuubinsyaProtocol::Ping => {
                let destination = header.destination.ok_or_else(|| {
                    Error::new(
                        ErrorKind::Protocol,
                        "Yuubinsya Ping header has no destination",
                    )
                })?;
                let mut session = AsyncYuubinsyaPingServerSession { stream };
                let context = FlowContext::new(destination);
                let initial = self.upstream.ping(&context).await;
                let follow_up = self.upstream.ping(&context).await;
                session.serve_one_probe(initial, follow_up).await
            }
            YuubinsyaProtocol::UdpWithMigrateId => {
                let requested = header.migrate_id.unwrap_or(0);
                let migrate_id = if requested == 0 {
                    self.allocate_migrate_id()
                } else {
                    requested
                };
                let mut session = AsyncYuubinsyaUotServerSession {
                    stream,
                    password_hash,
                    migrate_id,
                };
                session
                    .stream
                    .write_all(&migrate_id.to_be_bytes())
                    .await
                    .map_err(io_error)?;
                session.stream.flush().await.map_err(io_error)?;
                self.serve_uot(&mut session, observed.as_ref(), dns_handler.as_deref())
                    .await
            }
            YuubinsyaProtocol::Udp => Err(Error::new(
                ErrorKind::Unsupported,
                "native Yuubinsya UDP must use its datagram socket boundary",
            )),
        }
    }

    fn allocate_migrate_id(&self) -> u64 {
        loop {
            let id = self.next_migrate_id.fetch_add(1, Ordering::AcqRel);
            if id != 0 {
                return id;
            }
        }
    }

    async fn serve_uot<S>(
        &self,
        session: &mut AsyncYuubinsyaUotServerSession<S>,
        observed: Option<&ObservedInbound>,
        dns_handler: Option<&dyn YuubinsyaDnsHandler>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut destination, mut payload) = session.recv_from().await?;
        while destination.port() == Some(53) {
            let Some(handler) = dns_handler else {
                break;
            };
            let Some(response) = answer_dns_packet(handler, &payload).await? else {
                break;
            };
            session.send_to(&destination, &response).await?;
            (destination, payload) = session.recv_from().await?;
        }
        let shared = self
            .udp_session(session.migrate_id, destination.clone())
            .await?;
        let (sender, mut responses) = shared.register(destination.clone()).await;
        let mut observed_flows = HashMap::<Endpoint, ObservedFlow>::new();
        let result: Result<()> = async {
            if let Some(observed) = observed {
                let mut context = FlowContext::new(destination.clone());
                context.source = Some(Endpoint::ip(yuhaiin_core::Network::Udp, observed.source));
                context.udp_migrate_id.store(session.migrate_id, Ordering::Release);
                (observed.annotate)(&mut context);
                let flow = FlowKey {
                    network: yuhaiin_core::Network::Udp,
                    source: observed.source,
                    destination: endpoint_socket_addr(&destination, observed.source),
                };
                let observation = FlowObserverGuard::open(
                    Arc::clone(&observed.observer),
                    Flow { key: flow },
                    context,
                );
                observed_flows.insert(
                    destination.clone(),
                    ObservedFlow {
                        flow,
                        _observation: observation,
                    },
                );
                observed.observer.bytes(flow, FlowDirection::Upload, payload.len());
            }
            shared.send_to(&payload, destination).await?;
            loop {
                tokio::select! {
                    incoming = session.recv_from() => {
                        let (destination, payload) = incoming?;
                        if destination.port() == Some(53) {
                            if let Some(handler) = dns_handler {
                                if let Some(response) = answer_dns_packet(handler, &payload).await? {
                                    session.send_to(&destination, &response).await?;
                                    continue;
                                }
                            }
                        }
                        if let Some(observed) = observed {
                            let flow = if let Some(flow) = observed_flows.get(&destination) {
                                flow.flow
                            } else {
                                let mut context = FlowContext::new(destination.clone());
                                context.source = Some(Endpoint::ip(yuhaiin_core::Network::Udp, observed.source));
                                context.udp_migrate_id.store(session.migrate_id, Ordering::Release);
                                (observed.annotate)(&mut context);
                                let flow = FlowKey {
                                    network: yuhaiin_core::Network::Udp,
                                    source: observed.source,
                                    destination: endpoint_socket_addr(&destination, observed.source),
                                };
                                let observation = FlowObserverGuard::open(
                                    Arc::clone(&observed.observer),
                                    Flow { key: flow },
                                    context,
                                );
                                observed_flows.insert(
                                    destination.clone(),
                                    ObservedFlow {
                                        flow,
                                        _observation: observation,
                                    },
                                );
                                flow
                            };
                            observed.observer.bytes(flow, FlowDirection::Upload, payload.len());
                        }
                        shared.route(destination.clone(), &sender).await;
                        shared.send_to(&payload, destination).await?;
                    }
                    response = responses.recv() => {
                        match response {
                            Some(ServerUdpMessage::Data { source, payload }) => {
                                shared.touch();
                                session.send_to(&source, &payload).await?;
                                if let Some(observed) = observed {
                                    if let Some(flow) = observed_flows.get(&source) {
                                        observed.observer.bytes(
                                            flow.flow,
                                            FlowDirection::Download,
                                            payload.len(),
                                        );
                                    }
                                }
                            }
                            Some(ServerUdpMessage::Closed) | None => {
                                return Err(Error::new(
                                    ErrorKind::Closed,
                                    "Yuubinsya upstream UDP session closed",
                                ));
                            }
                        }
                    }
                }
            }
        }
        .await;
        drop(observed_flows);
        shared.unregister_sender(&sender).await;
        result
    }

    async fn udp_session(
        &self,
        migrate_id: u64,
        destination: Endpoint,
    ) -> Result<Arc<ServerUdpSession>> {
        let _open_guard = self.udp_open_lock.lock().await;
        let now = Instant::now();
        let stale = {
            let mut sessions = self.udp_sessions.lock().await;
            let mut stale = Vec::new();
            sessions.retain(|_, session| {
                if session.is_idle(now) {
                    stale.push(Arc::clone(session));
                    false
                } else {
                    true
                }
            });
            stale
        };
        for session in stale {
            let _ = session.close().await;
        }
        if let Some(session) = self.udp_sessions.lock().await.get(&migrate_id) {
            session.touch();
            return Ok(Arc::clone(session));
        }
        let context = FlowContext::new(destination);
        context.udp_migrate_id.store(migrate_id, Ordering::Release);
        let datagram = self.upstream.open_datagram(&context).await?;
        let session = ServerUdpSession::spawn(datagram).await;
        self.udp_sessions
            .lock()
            .await
            .insert(migrate_id, Arc::clone(&session));
        Ok(session)
    }

    /// Close all retained migrated UDP sessions when the owning listener
    /// stops.
    pub async fn close(&self) {
        let sessions = self
            .udp_sessions
            .lock()
            .await
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>();
        for session in sessions {
            let _ = session.close().await;
        }
    }
}

enum DnsTcpDecision {
    Forward(Vec<u8>),
    Answered { upload: usize, download: usize },
}

async fn intercept_dns_tcp<S>(
    stream: &mut S,
    handler: &dyn YuubinsyaDnsHandler,
) -> Result<DnsTcpDecision>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut length = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut length))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "Yuubinsya DNS over TCP query timed out"))?
        .map_err(io_error)?;
    let length = usize::from(u16::from_be_bytes(length));
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await.map_err(io_error)?;
    let mut framed = Vec::with_capacity(length + 2);
    framed.extend_from_slice(&(length as u16).to_be_bytes());
    framed.extend_from_slice(&packet);
    if yuhaiin_core::dns::decode_query(&packet).is_err() {
        return Ok(DnsTcpDecision::Forward(framed));
    }
    let response = handler.answer(&packet).await?;
    if response.len() > usize::from(u16::MAX) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya DNS over TCP response is too large",
        ));
    }
    stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.write_all(&response).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)?;
    Ok(DnsTcpDecision::Answered {
        upload: framed.len(),
        download: response.len() + 2,
    })
}

async fn answer_dns_packet(
    handler: &dyn YuubinsyaDnsHandler,
    packet: &[u8],
) -> Result<Option<Vec<u8>>> {
    if yuhaiin_core::dns::decode_query(packet).is_err() {
        return Ok(None);
    }
    Ok(Some(handler.answer(packet).await?))
}

fn endpoint_socket_addr(endpoint: &Endpoint, source: SocketAddr) -> SocketAddr {
    endpoint.addr().unwrap_or_else(|| {
        SocketAddr::new(
            match source.ip() {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            endpoint.port().unwrap_or(0),
        )
    })
}

async fn copy_bidirectional_observed<A, B>(
    left: &mut A,
    right: &mut B,
    observer: Arc<dyn FlowObserver>,
    flow: FlowKey,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let upload = copy_observed(
        &mut left_read,
        &mut right_write,
        Arc::clone(&observer),
        flow,
        FlowDirection::Upload,
    );
    let download = copy_observed(
        &mut right_read,
        &mut left_write,
        observer,
        flow,
        FlowDirection::Download,
    );
    tokio::try_join!(upload, download).map(|_| ())
}

async fn copy_observed<R, W>(
    reader: &mut R,
    writer: &mut W,
    observer: Arc<dyn FlowObserver>,
    flow: FlowKey,
    direction: FlowDirection,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..length]).await?;
        observer.bytes(flow, direction, length);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaUotSession<S> {
    pub async fn connect(
        mut stream: S,
        password_hash: [u8; 32],
        migrate_id: u64,
        udp_coalesce: bool,
    ) -> Result<Self> {
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::UdpWithMigrateId,
                migrate_id: Some(migrate_id),
                destination: None,
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        let mut assigned = [0u8; 8];
        stream.read_exact(&mut assigned).await.map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
            migrate_id: u64::from_be_bytes(assigned),
            udp_coalesce,
            pending: Vec::new(),
            pending_frames: 0,
            write_shutdown: false,
        })
    }

    pub async fn send_to(&mut self, destination: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = encode_uot_frame(destination, payload)?;
        if !self.udp_coalesce {
            self.stream.write_all(&frame).await.map_err(io_error)?;
            return self.stream.flush().await.map_err(io_error);
        }
        if frame.len() > MAX_UOT_COALESCE_BYTES
            || self.pending.len() + frame.len() > MAX_UOT_COALESCE_BYTES
            || self.pending_frames >= MAX_UOT_COALESCE_FRAMES
        {
            self.flush().await?;
        }
        self.pending.extend_from_slice(&frame);
        self.pending_frames += 1;
        if self.pending_frames >= MAX_UOT_COALESCE_FRAMES {
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn recv_from(&mut self) -> Result<(Endpoint, Vec<u8>)> {
        self.flush().await?;
        let frame = read_uot_frame(&mut self.stream).await?;
        let (destination, payload, _) = decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    /// Flush all queued UOT frames as one bounded byte batch.
    pub async fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.stream
            .write_all(&self.pending)
            .await
            .map_err(io_error)?;
        self.stream.flush().await.map_err(io_error)?;
        self.pending.clear();
        self.pending_frames = 0;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.write_shutdown {
            return Ok(());
        }
        self.flush().await?;
        self.stream.shutdown().await.map_err(io_error)?;
        self.write_shutdown = true;
        Ok(())
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaUotServerSession<S> {
    pub async fn accept(
        mut stream: S,
        password_hash: [u8; 32],
        assigned_migrate_id: u64,
    ) -> Result<Self> {
        if assigned_migrate_id == 0 {
            return Err(Error::invalid(
                "Yuubinsya server migrate id must be non-zero",
            ));
        }
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _) = decode_header(&password_hash, &header_bytes)?;
        if header.protocol != YuubinsyaProtocol::UdpWithMigrateId {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya UOT server received a non-UOT protocol",
            ));
        }
        let migrate_id = header.migrate_id.unwrap_or(0);
        let migrate_id = if migrate_id == 0 {
            assigned_migrate_id
        } else {
            migrate_id
        };
        stream
            .write_all(&migrate_id.to_be_bytes())
            .await
            .map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
            migrate_id,
        })
    }

    pub async fn recv_from(&mut self) -> Result<(Endpoint, Vec<u8>)> {
        let frame = read_uot_frame(&mut self.stream).await?;
        let (destination, payload, _) = decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    pub async fn send_to(&mut self, destination: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = encode_uot_frame(destination, payload)?;
        self.stream.write_all(&frame).await.map_err(io_error)?;
        self.stream.flush().await.map_err(io_error)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await.map_err(io_error)
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }
}

pub(crate) async fn read_uot_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut endpoint = read_endpoint_bytes(stream).await?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.map_err(io_error)?;
    let payload_length = usize::from(u16::from_be_bytes(length));
    let mut payload = vec![0u8; payload_length];
    stream.read_exact(&mut payload).await.map_err(io_error)?;
    endpoint.extend_from_slice(&length);
    endpoint.extend_from_slice(&payload);
    Ok(endpoint)
}

async fn read_header_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(io_error)?;
    let protocol = YuubinsyaProtocol::from_byte(first[0])?;
    let mut packet = vec![first[0]];
    if protocol == YuubinsyaProtocol::UdpWithMigrateId {
        let mut migrate_id = [0u8; 8];
        stream.read_exact(&mut migrate_id).await.map_err(io_error)?;
        packet.extend_from_slice(&migrate_id);
    }
    let mut password = [0u8; 32];
    stream.read_exact(&mut password).await.map_err(io_error)?;
    packet.extend_from_slice(&password);
    if matches!(protocol, YuubinsyaProtocol::Tcp | YuubinsyaProtocol::Ping) {
        packet.extend_from_slice(&read_endpoint_bytes(stream).await?);
    }
    Ok(packet)
}

async fn write_ping_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    result: Result<Duration>,
) -> Result<()> {
    let value = result
        .map(|elapsed| elapsed.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(u64::MAX);
    stream
        .write_all(&value.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.flush().await.map_err(io_error)
}

async fn read_endpoint_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(io_error)?;
    let mut output = vec![first[0]];
    match first[0] {
        1 => {
            output.resize(1 + 4 + 2, 0);
            stream
                .read_exact(&mut output[1..])
                .await
                .map_err(io_error)?;
        }
        4 => {
            output.resize(1 + 16 + 2, 0);
            stream
                .read_exact(&mut output[1..])
                .await
                .map_err(io_error)?;
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            let domain_length = usize::from(length[0]);
            output.push(length[0]);
            output.resize(output.len() + domain_length + 2, 0);
            stream
                .read_exact(&mut output[2..])
                .await
                .map_err(io_error)?;
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown Yuubinsya UOT address type",
            ));
        }
    }
    Ok(output)
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use yuhaiin_core::flow::{FlowDirection, FlowObserver};
    use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
    use yuhaiin_core::{BoxFuture, DomainName, Network};

    struct EchoDnsHandler;

    impl YuubinsyaDnsHandler for EchoDnsHandler {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            let response = packet.to_vec();
            Box::pin(async move { Ok(response) })
        }
    }

    #[derive(Clone)]
    struct EchoUpstream {
        opens: Arc<AtomicUsize>,
        tcp_echo: bool,
        ping_ok: bool,
    }

    struct EchoDatagram {
        received: StdMutex<VecDeque<(Vec<u8>, Endpoint)>>,
        notify: Arc<Notify>,
    }

    impl AsyncDatagram for EchoDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.received
                    .lock()
                    .unwrap()
                    .push_back((payload.to_vec(), target));
                self.notify.notify_one();
                Ok(payload.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async move {
                loop {
                    if let Some((payload, source)) = self.received.lock().unwrap().pop_front() {
                        if buffer.len() < payload.len() {
                            return Err(Error::invalid("echo datagram buffer is too small"));
                        }
                        buffer[..payload.len()].copy_from_slice(&payload);
                        return Ok((payload.len(), source));
                    }
                    self.notify.notified().await;
                }
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone, Default)]
    struct RecordingObserver {
        events: Arc<StdMutex<Vec<&'static str>>>,
        bytes: Arc<AtomicUsize>,
    }

    impl FlowObserver for RecordingObserver {
        fn opened(&self, _flow: Flow, _context: FlowContext) {
            self.events.lock().unwrap().push("open");
        }

        fn bytes(&self, _flow: FlowKey, _direction: FlowDirection, bytes: usize) {
            self.bytes.fetch_add(bytes, Ordering::AcqRel);
        }

        fn closed(&self, _flow: FlowKey) {
            self.events.lock().unwrap().push("close");
        }
    }

    impl AsyncProxy for EchoUpstream {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async move {
                if !self.tcp_echo {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "echo upstream has no TCP test path",
                    ));
                }
                let (client, mut peer) = duplex(4096);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(length) = peer.read(&mut buffer).await {
                        if length == 0 || peer.write_all(&buffer[..length]).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Box::new(client) as BoxAsyncStream)
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async move {
                self.opens.fetch_add(1, Ordering::AcqRel);
                Ok(Box::new(EchoDatagram {
                    received: StdMutex::new(VecDeque::new()),
                    notify: Arc::new(Notify::new()),
                }) as Box<dyn AsyncDatagram>)
            })
        }

        fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
            Box::pin(async move {
                if self.ping_ok {
                    Ok(Duration::from_nanos(1))
                } else {
                    Err(Error::new(ErrorKind::Unsupported, "ping not used"))
                }
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    async fn real_loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (client.await.unwrap(), server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_header_and_payload_round_trip() {
        let (client, mut server) = duplex(4096);
        let destination = Endpoint::ip(
            Network::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        );
        let password = [7u8; 32];
        let client_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaTcpSession::connect(client, password, destination)
                .await
                .unwrap();
            session.write_all(b"hello").await.unwrap();
            session
        });
        let mut header = vec![0u8; 1 + 32 + 1 + 4 + 2];
        server.read_exact(&mut header).await.unwrap();
        let (decoded, consumed) =
            yuhaiin_core::yuubinsya::decode_header(&password, &header).unwrap();
        assert_eq!(decoded.protocol, YuubinsyaProtocol::Tcp);
        assert_eq!(consumed, header.len());
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        let _ = client_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_loopback_tcp_session_preserves_half_close_and_idempotent_shutdown() {
        let (client_io, mut server_io) = real_loopback_pair().await;
        let password = [31u8; 32];
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.31:443".parse().unwrap());
        let server_task = tokio::spawn(async move {
            let header = read_header_bytes(&mut server_io).await?;
            let (header, _) = decode_header(&password, &header)?;
            assert_eq!(header.protocol, YuubinsyaProtocol::Tcp);
            let mut request = [0u8; 10];
            server_io.read_exact(&mut request).await.map_err(io_error)?;
            assert_eq!(&request, b"half-close");
            server_io.write_all(b"response").await.map_err(io_error)?;
            server_io.flush().await.map_err(io_error)?;
            server_io.shutdown().await.map_err(io_error)?;
            let mut after_eof = [0u8; 1];
            let length = server_io.read(&mut after_eof).await.map_err(io_error)?;
            assert_eq!(length, 0, "client did not send a TCP half-close");
            Result::<()>::Ok(())
        });

        let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
            .await
            .unwrap();
        client.write_all(b"half-close").await.unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        let mut eof = [0u8; 1];
        assert_eq!(client.read(&mut eof).await.unwrap(), 0);
        client.shutdown().await.unwrap();
        client
            .shutdown()
            .await
            .expect("repeated TCP shutdown must be idempotent");
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("real TCP half-close server task did not exit")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_loopback_uot_peer_exit_wakes_recv_and_shutdown_is_idempotent() {
        let (client_io, server_io) = real_loopback_pair().await;
        let password = [32u8; 32];
        let server_task = tokio::spawn(async move {
            let session = AsyncYuubinsyaUotServerSession::accept(server_io, password, 7331).await?;
            drop(session);
            Result::<()>::Ok(())
        });
        let mut client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("real TCP peer-exit task did not finish")
            .unwrap()
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), client.recv_from())
            .await
            .expect("UOT recv remained pending after peer exit")
            .unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Io | ErrorKind::Closed));
        client.shutdown().await.unwrap();
        client
            .shutdown()
            .await
            .expect("repeated UOT shutdown must be idempotent");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_proxy_reuses_one_upstream_datagram_across_migrated_streams() {
        let password = [11u8; 32];
        let opens = Arc::new(AtomicUsize::new(0));
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::clone(&opens),
            tcp_echo: false,
            ping_ok: false,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let destination =
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);

        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(server_io).await })
        };
        let mut first = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
            .await
            .unwrap();
        first.send_to(&destination, b"first").await.unwrap();
        let (_, first_payload) = first.recv_from().await.unwrap();
        assert_eq!(first_payload, b"first");
        let migrate_id = first.migrate_id;
        first.shutdown().await.unwrap();
        let _ = server_task.await.unwrap();

        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(server_io).await })
        };
        let mut second = AsyncYuubinsyaUotSession::connect(client_io, password, migrate_id, false)
            .await
            .unwrap();
        assert_eq!(second.migrate_id, migrate_id);
        second.send_to(&destination, b"second").await.unwrap();
        let (_, second_payload) = second.recv_from().await.unwrap();
        assert_eq!(second_payload, b"second");
        second.shutdown().await.unwrap();
        let _ = server_task.await.unwrap();
        assert_eq!(opens.load(Ordering::Acquire), 1);
        server.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_close_wakes_a_pending_migrated_uot_stream() {
        struct StallDatagram;

        impl AsyncDatagram for StallDatagram {
            fn send_to<'a>(
                &'a self,
                payload: &'a [u8],
                _target: Endpoint,
            ) -> BoxFuture<'a, Result<usize>> {
                Box::pin(async move { Ok(payload.len()) })
            }

            fn recv_from<'a>(
                &'a self,
                _buffer: &'a mut [u8],
            ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
                Box::pin(async { std::future::pending().await })
            }

            fn local_addr(&self) -> Result<Endpoint> {
                Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
            }

            fn close(&self) -> BoxFuture<'_, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        struct StallUpstream {
            opened: Arc<Notify>,
        }

        impl AsyncProxy for StallUpstream {
            fn connect<'a>(
                &'a self,
                _context: &'a FlowContext,
            ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
                Box::pin(async {
                    Err(Error::new(
                        ErrorKind::Unsupported,
                        "stall upstream has no TCP path",
                    ))
                })
            }

            fn open_datagram<'a>(
                &'a self,
                _context: &'a FlowContext,
            ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
                let opened = Arc::clone(&self.opened);
                Box::pin(async move {
                    opened.notify_one();
                    Ok(Box::new(StallDatagram) as Box<dyn AsyncDatagram>)
                })
            }

            fn close(&self) -> BoxFuture<'_, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let password = [17u8; 32];
        let opened = Arc::new(Notify::new());
        let upstream: Arc<dyn AsyncProxy> = Arc::new(StallUpstream {
            opened: Arc::clone(&opened),
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(server_io).await })
        };
        let mut client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
            .await
            .unwrap();
        let destination = Endpoint::ip(Network::Udp, "192.0.2.17:5353".parse().unwrap());
        client
            .send_to(&destination, b"pending-close")
            .await
            .unwrap();
        opened.notified().await;

        let pending = tokio::spawn(async move { client.recv_from().await });
        tokio::task::yield_now().await;
        server.close().await;
        let result = tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .expect("server close did not wake pending UOT recv")
            .unwrap();
        assert!(
            matches!(result, Err(error) if matches!(error.kind, ErrorKind::Io | ErrorKind::Closed))
        );

        let server_result = tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server UOT task did not exit after close")
            .unwrap();
        assert!(server_result.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_proxy_routes_concurrent_migrated_streams_to_their_endpoints() {
        let password = [13u8; 32];
        let opens = Arc::new(AtomicUsize::new(0));
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::clone(&opens),
            tcp_echo: false,
            ping_ok: false,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let first_destination = Endpoint::ip(Network::Udp, "192.0.2.11:5300".parse().unwrap());
        let second_destination = Endpoint::ip(Network::Udp, "192.0.2.12:5300".parse().unwrap());

        let (first_client_io, first_server_io) = duplex(4096);
        let first_server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(first_server_io).await })
        };
        let mut first = AsyncYuubinsyaUotSession::connect(first_client_io, password, 0, false)
            .await
            .unwrap();
        let migrate_id = first.migrate_id;

        let (second_client_io, second_server_io) = duplex(4096);
        let second_server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(second_server_io).await })
        };
        let mut second =
            AsyncYuubinsyaUotSession::connect(second_client_io, password, migrate_id, false)
                .await
                .unwrap();

        first
            .send_to(&first_destination, b"first-concurrent")
            .await
            .unwrap();
        second
            .send_to(&second_destination, b"second-concurrent")
            .await
            .unwrap();

        let (first_source, first_payload) = first.recv_from().await.unwrap();
        let (second_source, second_payload) = second.recv_from().await.unwrap();
        assert_eq!(first_source, first_destination);
        assert_eq!(first_payload, b"first-concurrent");
        assert_eq!(second_source, second_destination);
        assert_eq!(second_payload, b"second-concurrent");
        assert_eq!(opens.load(Ordering::Acquire), 1);

        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        let _ = first_server_task.await;
        let _ = second_server_task.await;
        server.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_proxy_dispatches_tcp_and_ping_to_the_injected_upstream() {
        let password = [12u8; 32];
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::new(AtomicUsize::new(0)),
            tcp_echo: true,
            ping_ok: true,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());

        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(server_io).await })
        };
        let mut client =
            AsyncYuubinsyaTcpSession::connect(client_io, password, destination.clone())
                .await
                .unwrap();
        client.write_all(b"tcp").await.unwrap();
        let mut response = [0u8; 3];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"tcp");
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();

        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.serve(server_io).await })
        };
        let (mut client, initial) =
            AsyncYuubinsyaPingSession::connect(client_io, password, destination)
                .await
                .unwrap();
        assert!(initial >= Duration::ZERO);
        assert!(client.ping().await.unwrap() >= Duration::ZERO);
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
        server.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observed_server_proxy_publishes_tcp_lifecycle_and_payload_bytes() {
        let password = [19u8; 32];
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::new(AtomicUsize::new(0)),
            tcp_echo: true,
            ping_ok: true,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let observer = Arc::new(RecordingObserver::default());
        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            let observer = Arc::clone(&observer);
            tokio::spawn(async move {
                server
                    .serve_observed(
                        server_io,
                        "10.0.0.2:12345".parse().unwrap(),
                        observer,
                        |context| {
                            context.inbound = Some("yuubinsya".to_owned());
                            context.inbound_name = Some("test".to_owned());
                        },
                    )
                    .await
            })
        };
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
        let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
            .await
            .unwrap();
        client.write_all(b"observed").await.unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"observed");
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
        assert_eq!(&*observer.events.lock().unwrap(), &["open", "close"]);
        assert_eq!(observer.bytes.load(Ordering::Acquire), 16);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observed_yuubinsya_tcp_hijacks_dns_before_upstream_connect() {
        let password = [21u8; 32];
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::new(AtomicUsize::new(0)),
            tcp_echo: false,
            ping_ok: false,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let observer = Arc::new(RecordingObserver::default());
        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            let observer = Arc::clone(&observer);
            tokio::spawn(async move {
                server
                    .serve_observed_with_dns(
                        server_io,
                        "10.0.0.2:12346".parse().unwrap(),
                        observer,
                        |_| {},
                        Some(Arc::new(EchoDnsHandler)),
                    )
                    .await
            })
        };
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:53".parse().unwrap());
        let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
            .await
            .unwrap();
        let query = yuhaiin_core::dns::encode_query(
            19,
            &DomainName::new("example.com").unwrap(),
            yuhaiin_core::dns::DnsRecordType::A,
        )
        .unwrap();
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&query).await.unwrap();
        let mut length = [0u8; 2];
        client.read_exact(&mut length).await.unwrap();
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, query);
        assert!(server_task.await.unwrap().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observed_yuubinsya_uot_hijacks_dns_without_opening_datagram() {
        let password = [22u8; 32];
        let opens = Arc::new(AtomicUsize::new(0));
        let upstream = Arc::new(EchoUpstream {
            opens: Arc::clone(&opens),
            tcp_echo: false,
            ping_ok: false,
        });
        let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
        let observer = Arc::new(RecordingObserver::default());
        let (client_io, server_io) = duplex(4096);
        let server_task = {
            let server = Arc::clone(&server);
            let observer = Arc::clone(&observer);
            tokio::spawn(async move {
                server
                    .serve_observed_with_dns(
                        server_io,
                        "10.0.0.2:12347".parse().unwrap(),
                        observer,
                        |_| {},
                        Some(Arc::new(EchoDnsHandler)),
                    )
                    .await
            })
        };
        let mut client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
            .await
            .unwrap();
        let destination = Endpoint::ip(Network::Udp, "192.0.2.10:53".parse().unwrap());
        let query = yuhaiin_core::dns::encode_query(
            20,
            &DomainName::new("example.com").unwrap(),
            yuhaiin_core::dns::DnsRecordType::A,
        )
        .unwrap();
        client.send_to(&destination, &query).await.unwrap();
        let (response_target, response) = client.recv_from().await.unwrap();
        assert_eq!(response_target, destination);
        assert_eq!(response, query);
        assert_eq!(opens.load(Ordering::Acquire), 0);
        client.shutdown().await.unwrap();
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ping_session_reuses_stream_for_follow_up_probe() {
        let (client, mut server) = duplex(4096);
        let password = [6u8; 32];
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
        let server_task = tokio::spawn(async move {
            let mut header = vec![0u8; 1 + 32 + 1 + 4 + 2];
            server.read_exact(&mut header).await.unwrap();
            let (header, _) = yuhaiin_core::yuubinsya::decode_header(&password, &header).unwrap();
            assert_eq!(header.protocol, YuubinsyaProtocol::Ping);
            server.write_all(&1u64.to_be_bytes()).await.unwrap();
            let mut probe = [0u8; 8];
            server.read_exact(&mut probe).await.unwrap();
            assert_eq!(probe, [0; 8]);
            server.write_all(&2u64.to_be_bytes()).await.unwrap();
        });
        let (mut session, first_elapsed) =
            AsyncYuubinsyaPingSession::connect(client, password, destination)
                .await
                .unwrap();
        assert!(first_elapsed >= Duration::ZERO);
        assert!(session.ping().await.unwrap() >= Duration::ZERO);
        server_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ping_server_accepts_header_and_serves_follow_up_probe() {
        let (client, server) = duplex(4096);
        let password = [8u8; 32];
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.20:443".parse().unwrap());
        let expected_destination = destination.clone();
        let server_task = tokio::spawn(async move {
            let (mut session, decoded_destination) =
                AsyncYuubinsyaPingServerSession::accept(server, password)
                    .await
                    .unwrap();
            assert_eq!(decoded_destination, expected_destination);
            session
                .serve_one_probe(Ok(Duration::from_nanos(1)), Ok(Duration::from_nanos(2)))
                .await
                .unwrap();
        });
        let (mut session, _) = AsyncYuubinsyaPingSession::connect(client, password, destination)
            .await
            .unwrap();
        assert!(session.ping().await.unwrap() >= Duration::ZERO);
        server_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_handshake_and_frame_round_trip() {
        let (client, mut server) = duplex(4096);
        let password = [9u8; 32];
        let client_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaUotSession::connect(client, password, 12, true)
                .await
                .unwrap();
            assert_eq!(session.migrate_id, 99);
            let destination =
                Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
            session.send_to(&destination, b"query").await.unwrap();
            session.flush().await.unwrap();
            session
        });
        let mut header = vec![0u8; 1 + 8 + 32];
        server.read_exact(&mut header).await.unwrap();
        let (decoded, _) = yuhaiin_core::yuubinsya::decode_header(&password, &header).unwrap();
        assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
        server.write_all(&99u64.to_be_bytes()).await.unwrap();
        let mut endpoint = [0u8; 1 + 1 + 11 + 2 + 2 + 5];
        server.read_exact(&mut endpoint).await.unwrap();
        let (_, payload, _) = decode_uot_frame(&endpoint).unwrap();
        assert_eq!(payload, b"query");
        let _ = client_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_server_assigns_zero_migration_and_round_trips_frames() {
        let (client, server) = duplex(4096);
        let password = [5u8; 32];
        let destination =
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        let expected_destination = destination.clone();
        let server_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 99)
                .await
                .unwrap();
            assert_eq!(session.migrate_id, 99);
            let (decoded_destination, payload) = session.recv_from().await.unwrap();
            assert_eq!(decoded_destination, expected_destination);
            assert_eq!(payload, b"query");
            session
                .send_to(&expected_destination, b"answer")
                .await
                .unwrap();
        });
        let mut client = AsyncYuubinsyaUotSession::connect(client, password, 0, false)
            .await
            .unwrap();
        assert_eq!(client.migrate_id, 99);
        client.send_to(&destination, b"query").await.unwrap();
        let (decoded_destination, payload) = client.recv_from().await.unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(payload, b"answer");
        server_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_server_handles_fragmented_max_payload_and_truncated_frame() {
        let password = [8u8; 32];
        let destination = Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap());
        let payload = vec![0x5a; u16::MAX as usize];
        let header = encode_header(
            &password,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::UdpWithMigrateId,
                migrate_id: Some(0),
                destination: None,
            },
        )
        .unwrap();
        let frame = encode_uot_frame(&destination, &payload).unwrap();

        let (mut client, server) = duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 123)
                .await
                .unwrap();
            let (decoded_destination, decoded_payload) = session.recv_from().await.unwrap();
            assert_eq!(decoded_destination, destination);
            assert_eq!(decoded_payload, payload);
        });
        for chunk in header.chunks(3) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut assigned = [0u8; 8];
        client.read_exact(&mut assigned).await.unwrap();
        assert_eq!(u64::from_be_bytes(assigned), 123);
        for chunk in frame.chunks(257) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        server_task.await.unwrap();

        let (mut client, server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 123)
                .await
                .unwrap();
            assert!(session.recv_from().await.is_err());
        });
        client.write_all(&header).await.unwrap();
        client.read_exact(&mut assigned).await.unwrap();
        client.write_all(&frame[..frame.len() - 1]).await.unwrap();
        client.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_frame_reader_rejects_bounded_random_wire_without_hanging() {
        for length in 0..512 {
            let (mut writer, mut reader) = duplex(4096);
            let mut state = 0x9e37_79b9_u32 ^ length as u32;
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
            let result =
                tokio::time::timeout(Duration::from_millis(50), read_uot_frame(&mut reader))
                    .await
                    .expect("random UOT wire input left the frame reader pending");
            assert!(result.is_err());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_reconnect_can_roll_over_to_a_new_h2_stream_with_the_same_migration() {
        let password = [6u8; 32];
        let (first_client, first_server) = duplex(4096);
        let first_server_task = tokio::spawn(async move {
            let session = AsyncYuubinsyaUotServerSession::accept(first_server, password, 77)
                .await
                .unwrap();
            assert_eq!(session.migrate_id, 77);
        });
        let first_client = AsyncYuubinsyaUotSession::connect(first_client, password, 0, false)
            .await
            .unwrap();
        assert_eq!(first_client.migrate_id, 77);
        drop(first_client);
        first_server_task.await.unwrap();

        let (second_client, second_server) = duplex(4096);
        let second_server_task = tokio::spawn(async move {
            let session = AsyncYuubinsyaUotServerSession::accept(second_server, password, 99)
                .await
                .unwrap();
            assert_eq!(session.migrate_id, 77);
        });
        let second_client = AsyncYuubinsyaUotSession::connect(second_client, password, 77, false)
            .await
            .unwrap();
        assert_eq!(second_client.migrate_id, 77);
        second_server_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uot_coalesce_flushes_multiple_bounded_frames() {
        let (client, mut server) = duplex(4096);
        let password = [4u8; 32];
        let first_destination =
            Endpoint::domain(Network::Udp, DomainName::new("one.example").unwrap(), 53);
        let second_destination = Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap());
        let first = encode_uot_frame(&first_destination, b"one").unwrap();
        let second = encode_uot_frame(&second_destination, b"two").unwrap();
        let client_task = tokio::spawn(async move {
            let mut session = AsyncYuubinsyaUotSession::connect(client, password, 12, true)
                .await
                .unwrap();
            session.send_to(&first_destination, b"one").await.unwrap();
            session.send_to(&second_destination, b"two").await.unwrap();
            assert_eq!(session.pending_frames, 2);
            session.flush().await.unwrap();
        });
        let mut header = vec![0u8; 1 + 8 + 32];
        server.read_exact(&mut header).await.unwrap();
        server.write_all(&99u64.to_be_bytes()).await.unwrap();
        client_task.await.unwrap();
        let mut frames = vec![0u8; first.len() + second.len()];
        server.read_exact(&mut frames).await.unwrap();
        let (_, first_payload, consumed) = decode_uot_frame(&frames).unwrap();
        assert_eq!(first_payload, b"one");
        let (_, second_payload, second_consumed) = decode_uot_frame(&frames[consumed..]).unwrap();
        assert_eq!(second_payload, b"two");
        assert_eq!(consumed + second_consumed, frames.len());
    }
}
