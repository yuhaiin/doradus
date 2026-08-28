//! QUIC transport for the raw async proxy boundary.
//!
//! QUIC streams carry the upper proxy protocol byte-for-byte. UDP packets use
//! QUIC DATAGRAM and a small association/fragments envelope. The envelope has
//! no address or authentication fields: those belong to the upper protocol
//! (Yuubinsya, for example), which keeps full-cone NAT semantics at the right
//! layer.

mod codec;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use doradus_core::network::bind_tokio_udp_socket_for_target;
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};

pub use codec::{
    DecodeError, EncodeError, EncodedDatagrams, FRAGMENT_HEADER_LEN, FRAGMENT_REASSEMBLY_TIMEOUT,
    FragmentReassembler, Frame, MAX_ASSOCIATION_ID, MAX_FRAGMENT_COUNT,
    MAX_INCOMPLETE_BYTES_PER_ASSOCIATION, MAX_REASSEMBLED_PAYLOAD, decode_frame, encode_datagrams,
    varint_len,
};

pub const ALPN: &[u8] = b"doradus-quic-v1";
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
pub const DEFAULT_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub const DEFAULT_MAX_ASSOCIATIONS: usize = 4096;
pub const DEFAULT_RX_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_RX_MEMORY_BUDGET: usize = 16 * 1024 * 1024;
const MAX_STREAMS: u32 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicStats {
    pub datagrams_sent: usize,
    pub datagrams_received: usize,
    pub datagrams_dropped: usize,
    pub fragments_expired: usize,
}

#[derive(Debug, Default)]
struct StatsInner {
    datagrams_sent: AtomicUsize,
    datagrams_received: AtomicUsize,
    datagrams_dropped: AtomicUsize,
    fragments_expired: AtomicUsize,
}

impl StatsInner {
    fn snapshot(&self) -> QuicStats {
        QuicStats {
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_dropped: self.datagrams_dropped.load(Ordering::Relaxed),
            fragments_expired: self.fragments_expired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub server: SocketAddr,
    pub server_name: String,
    pub ca_certificates: Vec<Vec<u8>>,
    pub insecure_skip_verify: bool,
    pub timeout: Duration,
    pub idle_timeout: Duration,
    pub association_idle_timeout: Duration,
    pub max_associations: usize,
    pub rx_queue_capacity: usize,
    pub rx_memory_budget: usize,
}

impl QuicConfig {
    pub fn new(server: SocketAddr, server_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            server,
            server_name: server_name.into(),
            ca_certificates: Vec::new(),
            insecure_skip_verify: false,
            timeout,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            association_idle_timeout: DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
            rx_queue_capacity: DEFAULT_RX_QUEUE_CAPACITY,
            rx_memory_budget: DEFAULT_RX_MEMORY_BUDGET,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.server.port() == 0 {
            return Err(Error::invalid("QUIC server port must be non-zero"));
        }
        if self.server_name.trim().is_empty() {
            return Err(Error::invalid("QUIC server name must not be empty"));
        }
        if self.timeout.is_zero() || self.idle_timeout.is_zero() {
            return Err(Error::invalid("QUIC timeout must be greater than zero"));
        }
        if self.association_idle_timeout.is_zero()
            || self.max_associations == 0
            || self.rx_queue_capacity == 0
            || self.rx_memory_budget == 0
        {
            return Err(Error::invalid("QUIC resource limits must be non-zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct QuicServerConfig {
    pub idle_timeout: Duration,
    pub association_idle_timeout: Duration,
    pub max_associations: usize,
    pub rx_queue_capacity: usize,
    pub rx_memory_budget: usize,
}

impl Default for QuicServerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            association_idle_timeout: DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
            rx_queue_capacity: DEFAULT_RX_QUEUE_CAPACITY,
            rx_memory_budget: DEFAULT_RX_MEMORY_BUDGET,
        }
    }
}

impl QuicServerConfig {
    fn validate(&self) -> Result<()> {
        if self.idle_timeout.is_zero()
            || self.association_idle_timeout.is_zero()
            || self.max_associations == 0
            || self.rx_queue_capacity == 0
            || self.rx_memory_budget == 0
        {
            return Err(Error::invalid(
                "QUIC server resource limits must be non-zero",
            ));
        }
        Ok(())
    }
}

pub struct QuicProxy {
    config: Arc<QuicConfig>,
    client_config: Arc<rustls::ClientConfig>,
    session: Mutex<Option<Arc<ClientSession>>>,
}

impl QuicProxy {
    pub fn new(config: QuicConfig) -> Result<Self> {
        config.validate()?;
        let client_config = build_client_tls_config(&config)?;
        Ok(Self {
            config: Arc::new(config),
            client_config,
            session: Mutex::const_new(None),
        })
    }

    pub fn with_client_config(
        config: QuicConfig,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            client_config: force_alpn(client_config),
            session: Mutex::const_new(None),
        })
    }

    pub async fn stats(&self) -> Option<QuicStats> {
        self.session
            .lock()
            .await
            .as_ref()
            .map(|session| session.stats.snapshot())
    }

    async fn session(&self, context: &FlowContext) -> Result<Arc<ClientSession>> {
        let mut stored = self.session.lock().await;
        if let Some(session) = stored.as_ref()
            && session.connection.close_reason().is_none()
        {
            return Ok(session.clone());
        }
        if let Some(session) = stored.take() {
            session.close();
        }

        let bind = context
            .local_bind_for(self.config.server)
            .unwrap_or_else(|| wildcard_for(self.config.server));
        let socket = bind_tokio_udp_socket_for_target(
            bind,
            self.config.server,
            context.bind_interface.as_deref(),
            "QUIC",
        )
        .await?;
        let socket = socket
            .into_std()
            .map_err(|error| Error::new(ErrorKind::Io, format!("create QUIC socket: {error}")))?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| Error::new(ErrorKind::Io, format!("create QUIC endpoint: {error}")))?;
        endpoint.set_default_client_config(build_quinn_client_config(
            self.client_config.clone(),
            &self.config,
        )?);
        let connecting = endpoint
            .connect(self.config.server, &self.config.server_name)
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("start QUIC connection: {error}"))
            })?;
        let connection = tokio::time::timeout(self.config.timeout, connecting)
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "QUIC connection timed out"))?
            .map_err(|error| Error::new(ErrorKind::Io, format!("connect QUIC server: {error}")))?;
        let local_addr = endpoint.local_addr().map_err(|error| {
            Error::new(ErrorKind::Io, format!("read QUIC local address: {error}"))
        })?;
        let session = Arc::new(ClientSession::new(
            endpoint,
            connection,
            local_addr,
            &self.config,
        ));
        tokio::spawn(run_client_dispatcher(session.clone()));
        *stored = Some(session.clone());
        Ok(session)
    }
}

impl AsyncProxy for QuicProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let session = self.session(context).await?;
            let (send, recv) =
                tokio::time::timeout(self.config.timeout, session.connection.open_bi())
                    .await
                    .map_err(|_| Error::new(ErrorKind::Timeout, "QUIC stream open timed out"))?
                    .map_err(|error| {
                        Error::new(ErrorKind::Io, format!("open QUIC stream: {error}"))
                    })?;
            Ok(Box::new(QuicStream { send, recv }) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let session = self.session(context).await?;
            Ok(Box::new(session.open_association().await?) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if let Some(session) = self.session.lock().await.take() {
                session.close();
            }
            Ok(())
        })
    }
}

pub struct QuicServer {
    endpoint: quinn::Endpoint,
    config: QuicServerConfig,
}

impl QuicServer {
    pub fn new(
        bind: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        config: QuicServerConfig,
    ) -> Result<Self> {
        config.validate()?;
        let server_config = build_quinn_server_config(tls_config, &config)?;
        let endpoint = quinn::Endpoint::server(server_config, bind)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind QUIC server: {error}")))?;
        Ok(Self { endpoint, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|error| {
            Error::new(ErrorKind::Io, format!("read QUIC server address: {error}"))
        })
    }

    pub async fn accept(&self) -> Result<QuicServerConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::new(ErrorKind::Closed, "QUIC server endpoint is closed"))?;
        let connection = incoming.await.map_err(|error| {
            Error::new(ErrorKind::Io, format!("accept QUIC connection: {error}"))
        })?;
        let local_addr = self.local_addr()?;
        Ok(QuicServerConnection::new(
            connection,
            local_addr,
            self.config.clone(),
        ))
    }

    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"server closed");
    }
}

pub struct QuicServerConnection {
    connection: quinn::Connection,
    dispatcher: Arc<ServerDispatcher>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl QuicServerConnection {
    fn new(
        connection: quinn::Connection,
        local_addr: SocketAddr,
        config: QuicServerConfig,
    ) -> Self {
        let dispatcher = ServerDispatcher::new(connection.clone(), local_addr, config);
        tokio::spawn(run_server_dispatcher(dispatcher.clone()));
        Self {
            remote_addr: connection.remote_address(),
            connection,
            dispatcher,
            local_addr,
        }
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub async fn accept_datagram(&self) -> Result<QuicDatagram> {
        let mut receiver = self.dispatcher.accept_rx.lock().await;
        let association = receiver.recv().await.ok_or_else(|| {
            Error::new(
                ErrorKind::Closed,
                "QUIC connection has no datagram associations",
            )
        })?;
        Ok(QuicDatagram { association })
    }

    pub async fn accept_stream(&self) -> Result<BoxAsyncStream> {
        let (send, recv) =
            self.connection.accept_bi().await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("accept QUIC stream: {error}"))
            })?;
        Ok(Box::new(QuicStream { send, recv }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> QuicStats {
        self.dispatcher.stats.snapshot()
    }

    pub fn close(&self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"connection closed");
    }
}

#[derive(Clone)]
pub struct QuicDatagram {
    association: Arc<Association>,
}

impl QuicDatagram {
    pub fn association_id(&self) -> u32 {
        self.association.id
    }
}

impl AsyncDatagram for QuicDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { self.association.send(payload).await })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move { self.association.recv(buffer).await })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(Network::Udp, self.association.local_addr))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.association.close().await;
            Ok(())
        })
    }
}

struct ClientSession {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    local_addr: SocketAddr,
    next_association_id: AtomicU32,
    associations: Mutex<HashMap<u32, Arc<Association>>>,
    config: QuicServerConfig,
    stats: Arc<StatsInner>,
    queued_bytes: Arc<AtomicUsize>,
}

impl ClientSession {
    fn new(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        local_addr: SocketAddr,
        config: &QuicConfig,
    ) -> Self {
        Self {
            endpoint,
            connection,
            local_addr,
            next_association_id: AtomicU32::new(1),
            associations: Mutex::const_new(HashMap::new()),
            config: server_config_from_client(config),
            stats: Arc::new(StatsInner::default()),
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn close(&self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"client closed");
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"client closed");
    }

    async fn open_association(self: &Arc<Self>) -> Result<QuicDatagram> {
        let id = self.next_association_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id > MAX_ASSOCIATION_ID {
            return Err(Error::new(
                ErrorKind::Closed,
                "QUIC association ID space exhausted",
            ));
        }
        let association = Arc::new(Association::new(
            id,
            self.connection.clone(),
            self.local_addr,
            self.connection.remote_address(),
            AssociationOwner::Client(Arc::downgrade(self)),
            self.config.rx_queue_capacity,
            self.config.association_idle_timeout,
            self.stats.clone(),
            self.queued_bytes.clone(),
            self.config.rx_memory_budget,
        ));
        let mut map = self.associations.lock().await;
        if map.len() >= self.config.max_associations {
            return Err(Error::new(
                ErrorKind::Closed,
                "QUIC association limit reached",
            ));
        }
        map.insert(id, association.clone());
        Ok(QuicDatagram { association })
    }

    async fn remove_association(&self, id: u32) {
        if let Some(association) = self.associations.lock().await.remove(&id) {
            association.close_sender().await;
        }
    }

    async fn expire_associations(&self, now: Instant) {
        let associations: Vec<Arc<Association>> = {
            let map = self.associations.lock().await;
            map.values().cloned().collect()
        };
        for association in &associations {
            association.expire_fragments(now).await;
        }
        let expired: Vec<u32> = associations
            .into_iter()
            .filter(|association| association.is_expired(now))
            .map(|association| association.id)
            .collect();
        for id in expired {
            self.remove_association(id).await;
        }
    }
}

fn server_config_from_client(config: &QuicConfig) -> QuicServerConfig {
    QuicServerConfig {
        idle_timeout: config.idle_timeout,
        association_idle_timeout: config.association_idle_timeout,
        max_associations: config.max_associations,
        rx_queue_capacity: config.rx_queue_capacity,
        rx_memory_budget: config.rx_memory_budget,
    }
}

struct ServerDispatcher {
    connection: quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    associations: Mutex<HashMap<u32, Arc<Association>>>,
    accept_tx: mpsc::Sender<Arc<Association>>,
    accept_rx: Mutex<mpsc::Receiver<Arc<Association>>>,
    config: QuicServerConfig,
    queued_bytes: Arc<AtomicUsize>,
    stats: Arc<StatsInner>,
}

impl ServerDispatcher {
    fn new(
        connection: quinn::Connection,
        local_addr: SocketAddr,
        config: QuicServerConfig,
    ) -> Arc<Self> {
        let (accept_tx, accept_rx) = mpsc::channel(config.max_associations);
        Arc::new(Self {
            remote_addr: connection.remote_address(),
            connection,
            local_addr,
            associations: Mutex::const_new(HashMap::new()),
            accept_tx,
            accept_rx: Mutex::const_new(accept_rx),
            config,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            stats: Arc::new(StatsInner::default()),
        })
    }

    async fn association(self: &Arc<Self>, id: u32) -> Option<Arc<Association>> {
        let mut map = self.associations.lock().await;
        if let Some(existing) = map.get(&id) {
            return Some(existing.clone());
        }
        if map.len() >= self.config.max_associations {
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let association = Arc::new(Association::new(
            id,
            self.connection.clone(),
            self.local_addr,
            self.remote_addr,
            AssociationOwner::Server(Arc::downgrade(self)),
            self.config.rx_queue_capacity,
            self.config.association_idle_timeout,
            self.stats.clone(),
            self.queued_bytes.clone(),
            self.config.rx_memory_budget,
        ));
        if self.accept_tx.try_send(association.clone()).is_err() {
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        map.insert(id, association.clone());
        Some(association)
    }

    async fn remove_association(&self, id: u32) {
        if let Some(association) = self.associations.lock().await.remove(&id) {
            association.close_sender().await;
        }
    }

    async fn expire_associations(&self, now: Instant) {
        let associations: Vec<Arc<Association>> = {
            let map = self.associations.lock().await;
            map.values().cloned().collect()
        };
        for association in &associations {
            association.expire_fragments(now).await;
        }
        let expired: Vec<u32> = associations
            .into_iter()
            .filter(|association| association.is_expired(now))
            .map(|association| association.id)
            .collect();
        for id in expired {
            self.remove_association(id).await;
        }
    }
}

enum AssociationOwner {
    Client(Weak<ClientSession>),
    Server(Weak<ServerDispatcher>),
}

struct Association {
    id: u32,
    connection: quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    owner: AssociationOwner,
    sender: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    reassembler: Mutex<FragmentReassembler>,
    message_id: AtomicU32,
    last_activity: Mutex<Instant>,
    idle_timeout: Duration,
    closed: AtomicBool,
    stats: Arc<StatsInner>,
    queued_bytes: Arc<AtomicUsize>,
    queue_budget: usize,
}

impl Association {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u32,
        connection: quinn::Connection,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        owner: AssociationOwner,
        queue_capacity: usize,
        idle_timeout: Duration,
        stats: Arc<StatsInner>,
        queued_bytes: Arc<AtomicUsize>,
        queue_budget: usize,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(queue_capacity);
        Self {
            id,
            connection,
            local_addr,
            remote_addr,
            owner,
            sender: Mutex::const_new(Some(sender)),
            receiver: Mutex::const_new(receiver),
            reassembler: Mutex::const_new(FragmentReassembler::new(
                FRAGMENT_REASSEMBLY_TIMEOUT,
                MAX_INCOMPLETE_BYTES_PER_ASSOCIATION,
            )),
            message_id: AtomicU32::new(1),
            last_activity: Mutex::const_new(Instant::now()),
            idle_timeout,
            closed: AtomicBool::new(false),
            stats,
            queued_bytes,
            queue_budget,
        }
    }

    async fn send(&self, payload: &[u8]) -> Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "QUIC datagram association is closed",
            ));
        }
        let max_size = self.connection.max_datagram_size();
        let Some(max_size) = max_size else {
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(payload.len());
        };
        let message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        let frames = match encode_datagrams(self.id, message_id, payload, max_size) {
            Ok(frames) => frames,
            Err(_) => {
                self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(payload.len());
            }
        };
        for frame in frames {
            match self.connection.send_datagram(Bytes::from(frame)) {
                Ok(()) => {}
                Err(quinn::SendDatagramError::TooLarge)
                | Err(quinn::SendDatagramError::UnsupportedByPeer)
                | Err(quinn::SendDatagramError::Disabled) => {
                    self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(payload.len());
                }
                Err(quinn::SendDatagramError::ConnectionLost(error)) => {
                    return Err(Error::new(
                        ErrorKind::Closed,
                        format!("send QUIC datagram: {error}"),
                    ));
                }
            }
        }
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        *self.last_activity.lock().await = Instant::now();
        Ok(payload.len())
    }

    async fn receive_frame(&self, frame: Frame<'_>, now: Instant) {
        let payload = {
            let mut reassembler = self.reassembler.lock().await;
            reassembler.push(frame, now)
        };
        let Some(payload) = payload else {
            return;
        };
        *self.last_activity.lock().await = now;
        let Some(sender) = self.sender.lock().await.as_ref().cloned() else {
            return;
        };
        let size = payload.len();
        let queued = self.queued_bytes.fetch_add(size, Ordering::AcqRel);
        if queued.saturating_add(size) > self.queue_budget {
            self.queued_bytes.fetch_sub(size, Ordering::AcqRel);
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if sender.try_send(payload).is_err() {
            self.queued_bytes.fetch_sub(size, Ordering::AcqRel);
            self.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, Endpoint)> {
        let mut receiver = self.receiver.lock().await;
        let payload = receiver
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::Closed, "QUIC datagram association closed"))?;
        self.queued_bytes.fetch_sub(payload.len(), Ordering::AcqRel);
        if payload.len() > buffer.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "QUIC datagram receive buffer is too small",
            ));
        }
        buffer[..payload.len()].copy_from_slice(&payload);
        Ok((payload.len(), Endpoint::ip(Network::Udp, self.remote_addr)))
    }

    async fn expire_fragments(&self, now: Instant) {
        let expired = self.reassembler.lock().await.expire(now);
        self.stats
            .fragments_expired
            .fetch_add(expired, Ordering::Relaxed);
    }

    async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        match &self.owner {
            AssociationOwner::Client(session) => {
                if let Some(session) = session.upgrade() {
                    session.remove_association(self.id).await;
                }
            }
            AssociationOwner::Server(dispatcher) => {
                if let Some(dispatcher) = dispatcher.upgrade() {
                    dispatcher.remove_association(self.id).await;
                }
            }
        }
        self.close_sender().await;
    }

    async fn close_sender(&self) {
        self.closed.store(true, Ordering::Release);
        self.sender.lock().await.take();
        let mut receiver = self.receiver.lock().await;
        while let Ok(payload) = receiver.try_recv() {
            self.queued_bytes.fetch_sub(payload.len(), Ordering::AcqRel);
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.closed.load(Ordering::Acquire)
            || self
                .last_activity
                .try_lock()
                .map(|last| now.saturating_duration_since(*last) >= self.idle_timeout)
                .unwrap_or(false)
    }
}

async fn run_client_dispatcher(session: Arc<ClientSession>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            datagram = session.connection.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                session.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                let Ok(frame) = decode_frame(&datagram) else {
                    session.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let id = match frame {
                    Frame::Single { association_id, .. } | Frame::Fragment { association_id, .. } => association_id,
                };
                let association = session.associations.lock().await.get(&id).cloned();
                if let Some(association) = association {
                    association.receive_frame(frame, Instant::now()).await;
                } else {
                    session.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = ticker.tick() => {
                session.expire_associations(Instant::now()).await;
                if session.connection.close_reason().is_some() { break; }
            }
        }
    }
    let associations = session
        .associations
        .lock()
        .await
        .drain()
        .map(|(_, association)| association)
        .collect::<Vec<_>>();
    for association in associations {
        association.close_sender().await;
    }
}

async fn run_server_dispatcher(dispatcher: Arc<ServerDispatcher>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            datagram = dispatcher.connection.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                dispatcher.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                let Ok(frame) = decode_frame(&datagram) else {
                    dispatcher.stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let id = match frame {
                    Frame::Single { association_id, .. } | Frame::Fragment { association_id, .. } => association_id,
                };
                let Some(association) = dispatcher.association(id).await else { continue };
                association.receive_frame(frame, Instant::now()).await;
            }
            _ = ticker.tick() => {
                dispatcher.expire_associations(Instant::now()).await;
                if dispatcher.connection.close_reason().is_some() { break; }
            }
        }
    }
    let associations = dispatcher
        .associations
        .lock()
        .await
        .drain()
        .map(|(_, association)| association)
        .collect::<Vec<_>>();
    for association in associations {
        association.close_sender().await;
    }
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

fn build_client_tls_config(config: &QuicConfig) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in &config.ca_certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
            .map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("QUIC CA certificate: {error}"))
            })?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = if config.insecure_skip_verify {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("QUIC TLS: {error}")))?
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new(provider))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("QUIC TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(tls))
}

fn build_quinn_client_config(
    tls: Arc<rustls::ClientConfig>,
    config: &QuicConfig,
) -> Result<quinn::ClientConfig> {
    let tls = force_alpn(tls);
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("configure QUIC TLS: {error}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(
        config.idle_timeout,
        config.rx_memory_budget,
    )?));
    Ok(client)
}

fn force_alpn(mut tls: Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    let config = Arc::make_mut(&mut tls);
    config.alpn_protocols = vec![ALPN.to_vec()];
    tls
}

fn build_quinn_server_config(
    tls: Arc<rustls::ServerConfig>,
    config: &QuicServerConfig,
) -> Result<quinn::ServerConfig> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("configure QUIC server TLS: {error}"),
            )
        })?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport_config(
        config.idle_timeout,
        config.rx_memory_budget,
    )?));
    Ok(server)
}

fn transport_config(
    idle_timeout: Duration,
    memory_budget: usize,
) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = idle_timeout
        .try_into()
        .map_err(|_| Error::invalid("QUIC idle timeout is too large"))?;
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(Some(memory_budget))
        .datagram_send_buffer_size(memory_budget)
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_STREAMS));
    Ok(transport)
}

fn wildcard_for(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    }
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
    const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

    fn server_tls() -> Arc<rustls::ServerConfig> {
        let cert = rustls_pemfile::certs(&mut Cursor::new(CERTIFICATE_PEM))
            .next()
            .unwrap()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
            .unwrap()
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        Arc::new(config)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quic_raw_stream_and_datagram_share_one_connection() {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig::default(),
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let config = QuicConfig {
            insecure_skip_verify: true,
            ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
        };
        let proxy = Arc::new(QuicProxy::new(config).unwrap());
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, server_address));
        let mut stream = proxy.connect(&context).await.unwrap();
        let datagram = proxy
            .open_datagram(&FlowContext::new(Endpoint::ip(
                Network::Udp,
                server_address,
            )))
            .await
            .unwrap();

        let connection = accepting.await.unwrap();
        stream.write_all(b"stream").await.unwrap();
        let mut server_stream = connection.accept_stream().await.unwrap();
        let mut stream_buffer = [0; 6];
        server_stream.read_exact(&mut stream_buffer).await.unwrap();
        assert_eq!(&stream_buffer, b"stream");

        datagram
            .send_to(b"udp", Endpoint::ip(Network::Udp, server_address))
            .await
            .unwrap();
        let server_datagram = connection.accept_datagram().await.unwrap();
        let mut udp_buffer = [0; 8];
        let (length, peer) = server_datagram.recv_from(&mut udp_buffer).await.unwrap();
        assert_eq!(&udp_buffer[..length], b"udp");
        assert_eq!(peer.addr().unwrap().ip(), server_address.ip());
        assert_ne!(peer.addr().unwrap().port(), server_address.port());
        server_datagram.send_to(b"reply", peer).await.unwrap();
        let (length, _) = datagram.recv_from(&mut udp_buffer).await.unwrap();
        assert_eq!(&udp_buffer[..length], b"reply");
        proxy.close().await.unwrap();
        server.close();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragmented_udp_round_trips_without_retransmission_state() {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig::default(),
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let config = QuicConfig {
            insecure_skip_verify: true,
            ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
        };
        let proxy = QuicProxy::new(config).unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let datagram = proxy
            .open_datagram(&FlowContext::new(Endpoint::ip(
                Network::Udp,
                server_address,
            )))
            .await
            .unwrap();
        let connection = accepting.await.unwrap();
        let payload = vec![0x5a; 32 * 1024];
        datagram
            .send_to(&payload, Endpoint::ip(Network::Udp, server_address))
            .await
            .unwrap();
        let server_datagram = connection.accept_datagram().await.unwrap();
        let mut received = vec![0; payload.len()];
        let (length, _) = server_datagram.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..length], payload.as_slice());
        assert!(connection.stats().datagrams_received > 0);
        proxy.close().await.unwrap();
        server.close();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multiple_udp_associations_share_the_same_quic_connection() {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig::default(),
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let proxy = QuicProxy::new(QuicConfig {
            max_associations: 2,
            insecure_skip_verify: true,
            ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
        })
        .unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let context = FlowContext::new(Endpoint::ip(Network::Udp, server_address));
        let first = proxy.open_datagram(&context).await.unwrap();
        let second = proxy.open_datagram(&context).await.unwrap();
        assert!(proxy.open_datagram(&context).await.is_err());

        let connection = accepting.await.unwrap();
        first
            .send_to(b"first", context.destination.clone())
            .await
            .unwrap();
        second
            .send_to(b"second", context.destination.clone())
            .await
            .unwrap();
        let server_first = connection.accept_datagram().await.unwrap();
        let server_second = connection.accept_datagram().await.unwrap();
        assert_ne!(
            server_first.association_id(),
            server_second.association_id()
        );
        let mut first_buffer = [0; 16];
        let mut second_buffer = [0; 16];
        let mut values = [
            server_first.recv_from(&mut first_buffer).await.unwrap().0,
            server_second.recv_from(&mut second_buffer).await.unwrap().0,
        ];
        values.sort_unstable();
        assert_eq!(values, [5, 6]);
        proxy.close().await.unwrap();
        server.close();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_receive_queue_drops_newest_udp_packet() {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig {
                    rx_queue_capacity: 1,
                    ..QuicServerConfig::default()
                },
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let proxy = QuicProxy::new(QuicConfig {
            rx_queue_capacity: 1,
            insecure_skip_verify: true,
            ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
        })
        .unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let context = FlowContext::new(Endpoint::ip(Network::Udp, server_address));
        let datagram = proxy.open_datagram(&context).await.unwrap();
        let connection = accepting.await.unwrap();
        datagram
            .send_to(b"first", context.destination.clone())
            .await
            .unwrap();
        let server_datagram = connection.accept_datagram().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        datagram
            .send_to(b"second", context.destination.clone())
            .await
            .unwrap();

        for _ in 0..20 {
            if connection.stats().datagrams_dropped > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(connection.stats().datagrams_dropped > 0);
        let mut buffer = [0; 16];
        let (length, _) = server_datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"first");
        proxy.close().await.unwrap();
        server.close();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn yuubinsya_keeps_logical_targets_above_raw_quic() {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig::default(),
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let config = QuicConfig {
            insecure_skip_verify: true,
            ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
        };
        let proxy = QuicProxy::new(config).unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let raw = proxy
            .open_datagram(&FlowContext::new(Endpoint::ip(
                Network::Udp,
                server_address,
            )))
            .await
            .unwrap();
        let connection = accepting.await.unwrap();
        let target_a = Endpoint::ip(Network::Udp, "192.0.2.10:5300".parse().unwrap());
        let target_b = Endpoint::domain(
            Network::Udp,
            doradus_core::DomainName::new("target.example").unwrap(),
            5353,
        );
        let password_hash = crate::yuubinsya::derive_salt(b"quic-test-password");
        let client = crate::YuubinsyaUdpDatagram::new(
            raw,
            password_hash,
            Endpoint::ip(Network::Udp, server_address),
            false,
        )
        .unwrap();
        client.send_to(b"one", target_a.clone()).await.unwrap();
        let raw_server = connection.accept_datagram().await.unwrap();
        let server_protocol =
            crate::YuubinsyaUdpServer::new(Box::new(raw_server), password_hash, false);
        let mut buffer = [0; 128];
        let (length, decoded_target, _peer) = server_protocol.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"one");
        assert_eq!(decoded_target, target_a);
        client.send_to(b"two", target_b.clone()).await.unwrap();
        let (length, decoded_target, peer) = server_protocol.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"two");
        assert_eq!(decoded_target, target_b);
        server_protocol
            .send_to(b"reply", decoded_target, peer)
            .await
            .unwrap();
        let (length, decoded_target) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"reply");
        assert_eq!(decoded_target, target_b);
        proxy.close().await.unwrap();
        server.close();
    }
}
