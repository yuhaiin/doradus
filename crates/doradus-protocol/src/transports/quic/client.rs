//! Client endpoint, session reuse, and datagram dispatch.

use super::association::{Association, AssociationOwner, QuicDatagram};
use super::*;

pub struct QuicProxy {
    config: Arc<QuicConfig>,
    client_config: Arc<rustls::ClientConfig>,
    session: Mutex<Option<Arc<ClientSession>>>,
    metrics: Arc<RuntimeMetrics>,
}

impl QuicProxy {
    pub fn new(config: QuicConfig) -> Result<Self> {
        Self::new_with_metrics(config, Arc::new(RuntimeMetrics::new()))
    }

    pub fn new_with_metrics(config: QuicConfig, metrics: Arc<RuntimeMetrics>) -> Result<Self> {
        config.validate()?;
        let client_config = build_client_tls_config(&config)?;
        Ok(Self {
            config: Arc::new(config),
            client_config,
            session: Mutex::const_new(None),
            metrics,
        })
    }

    pub fn with_client_config(
        config: QuicConfig,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        Self::with_client_config_and_metrics(config, client_config, Arc::new(RuntimeMetrics::new()))
    }

    pub fn with_client_config_and_metrics(
        config: QuicConfig,
        client_config: Arc<rustls::ClientConfig>,
        metrics: Arc<RuntimeMetrics>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            client_config: force_alpn(client_config),
            session: Mutex::const_new(None),
            metrics,
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
            Arc::clone(&self.metrics),
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

pub(super) struct ClientSession {
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
        metrics: Arc<RuntimeMetrics>,
    ) -> Self {
        Self {
            endpoint,
            connection,
            local_addr,
            next_association_id: AtomicU32::new(1),
            associations: Mutex::const_new(HashMap::new()),
            config: server_config_from_client(config),
            stats: Arc::new(StatsInner::new(Some(metrics))),
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

fn server_config_from_client(config: &QuicConfig) -> QuicServerConfig {
    QuicServerConfig {
        idle_timeout: config.idle_timeout,
        association_idle_timeout: config.association_idle_timeout,
        max_associations: config.max_associations,
        rx_queue_capacity: config.rx_queue_capacity,
        rx_memory_budget: config.rx_memory_budget,
    }
}

async fn run_client_dispatcher(session: Arc<ClientSession>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            datagram = session.connection.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                session.stats.datagram_received();
                let Ok(frame) = decode_frame(&datagram) else {
                    session.stats.datagram_dropped();
                    continue;
                };
                let id = match frame {
                    Frame::Single { association_id, .. } | Frame::Fragment { association_id, .. } => association_id,
                };
                let association = session.associations.lock().await.get(&id).cloned();
                if let Some(association) = association {
                    association.receive_frame(frame, Instant::now()).await;
                } else {
                    session.stats.datagram_dropped();
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

fn wildcard_for(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    }
}
