//! QUIC datagram association framing, queues, and fragment lifecycle.

use super::client::ClientSession;
use super::server::ServerDispatcher;
use super::*;

#[derive(Clone)]
pub struct QuicDatagram {
    pub(super) association: Arc<Association>,
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

pub(super) enum AssociationOwner {
    Client(Weak<ClientSession>),
    Server(Weak<ServerDispatcher>),
}

pub(super) struct Association {
    pub(super) id: u32,
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
    pub(super) fn new(
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
            self.stats.datagram_dropped();
            return Ok(payload.len());
        };
        let message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        let frames = match encode_datagrams(self.id, message_id, payload, max_size) {
            Ok(frames) => frames,
            Err(_) => {
                self.stats.datagram_dropped();
                return Ok(payload.len());
            }
        };
        for frame in frames {
            match self.connection.send_datagram(Bytes::from(frame)) {
                Ok(()) => {}
                Err(quinn::SendDatagramError::TooLarge)
                | Err(quinn::SendDatagramError::UnsupportedByPeer)
                | Err(quinn::SendDatagramError::Disabled) => {
                    self.stats.datagram_dropped();
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
        self.stats.datagram_sent();
        *self.last_activity.lock().await = Instant::now();
        Ok(payload.len())
    }

    pub(super) async fn receive_frame(&self, frame: Frame<'_>, now: Instant) {
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
        self.stats.queued_bytes_changed(size as i64);
        if queued.saturating_add(size) > self.queue_budget {
            self.queued_bytes.fetch_sub(size, Ordering::AcqRel);
            self.stats.queued_bytes_changed(-(size as i64));
            self.stats.datagram_dropped();
            return;
        }
        if sender.try_send(payload).is_err() {
            self.queued_bytes.fetch_sub(size, Ordering::AcqRel);
            self.stats.queued_bytes_changed(-(size as i64));
            self.stats.datagram_dropped();
        }
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, Endpoint)> {
        let mut receiver = self.receiver.lock().await;
        let payload = receiver
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::Closed, "QUIC datagram association closed"))?;
        self.queued_bytes.fetch_sub(payload.len(), Ordering::AcqRel);
        self.stats.queued_bytes_changed(-(payload.len() as i64));
        if payload.len() > buffer.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "QUIC datagram receive buffer is too small",
            ));
        }
        buffer[..payload.len()].copy_from_slice(&payload);
        Ok((payload.len(), Endpoint::ip(Network::Udp, self.remote_addr)))
    }

    pub(super) async fn expire_fragments(&self, now: Instant) {
        let expired = self.reassembler.lock().await.expire(now);
        self.stats.fragments_expired(expired);
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

    pub(super) async fn close_sender(&self) {
        self.closed.store(true, Ordering::Release);
        self.sender.lock().await.take();
        let mut receiver = self.receiver.lock().await;
        while let Ok(payload) = receiver.try_recv() {
            self.queued_bytes.fetch_sub(payload.len(), Ordering::AcqRel);
            self.stats.queued_bytes_changed(-(payload.len() as i64));
        }
    }

    pub(super) fn is_expired(&self, now: Instant) -> bool {
        self.closed.load(Ordering::Acquire)
            || self
                .last_activity
                .try_lock()
                .map(|last| now.saturating_duration_since(*last) >= self.idle_timeout)
                .unwrap_or(false)
    }
}
