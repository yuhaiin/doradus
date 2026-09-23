//! Server endpoint, accepted connections, and server datagram dispatch.

use super::association::{Association, AssociationOwner, QuicDatagram};
use super::*;

pub struct QuicServer {
    endpoint: quinn::Endpoint,
    config: QuicServerConfig,
    metrics: Arc<RuntimeMetrics>,
}

impl QuicServer {
    pub fn new(
        bind: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        config: QuicServerConfig,
    ) -> Result<Self> {
        Self::new_with_metrics(bind, tls_config, config, Arc::new(RuntimeMetrics::new()))
    }

    pub fn new_with_metrics(
        bind: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        config: QuicServerConfig,
        metrics: Arc<RuntimeMetrics>,
    ) -> Result<Self> {
        config.validate()?;
        let server_config = build_quinn_server_config(tls_config, &config)?;
        let endpoint = quinn::Endpoint::server(server_config, bind)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind QUIC server: {error}")))?;
        Ok(Self {
            endpoint,
            config,
            metrics,
        })
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
            Arc::clone(&self.metrics),
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
        metrics: Arc<RuntimeMetrics>,
    ) -> Self {
        let dispatcher = ServerDispatcher::new(connection.clone(), local_addr, config, metrics);
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

pub(super) struct ServerDispatcher {
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
        metrics: Arc<RuntimeMetrics>,
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
            stats: Arc::new(StatsInner::new(Some(metrics))),
        })
    }

    async fn association(self: &Arc<Self>, id: u32) -> Option<Arc<Association>> {
        let mut map = self.associations.lock().await;
        if let Some(existing) = map.get(&id) {
            return Some(existing.clone());
        }
        if map.len() >= self.config.max_associations {
            self.stats.datagram_dropped();
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
            self.stats.datagram_dropped();
            return None;
        }
        map.insert(id, association.clone());
        Some(association)
    }

    pub(super) async fn remove_association(&self, id: u32) {
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

async fn run_server_dispatcher(dispatcher: Arc<ServerDispatcher>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            datagram = dispatcher.connection.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                dispatcher.stats.datagram_received();
                let Ok(frame) = decode_frame(&datagram) else {
                    dispatcher.stats.datagram_dropped();
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
