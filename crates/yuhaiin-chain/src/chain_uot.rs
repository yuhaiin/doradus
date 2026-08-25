//! UDP-over-TCP datagram lifecycle, batching, and bounded retries.

use super::chain_client::ChainClient;
use super::*;

pub(super) struct ChainDatagram {
    pub(super) client: ChainClient,
    pub(super) migrate_id: Arc<std::sync::atomic::AtomicU64>,
    pub(super) session: Mutex<Option<Arc<ChainUotSession>>>,
    pub(super) reconnect_lock: Mutex<()>,
    pub(super) generation: std::sync::atomic::AtomicU64,
    pub(super) closed: std::sync::atomic::AtomicBool,
    pub(super) shutdown: watch::Sender<bool>,
    pub(super) next_retry_id: std::sync::atomic::AtomicU64,
    pub(super) retry: Mutex<RetryQueue>,
    pub(super) local_bind_addresses: Arc<Vec<std::net::IpAddr>>,
    pub(super) bind_interface: Option<String>,
    pub(super) local_addr: StdMutex<Option<SocketAddr>>,
}

pub(super) struct PendingUotDatagram {
    pub(super) id: u64,
    pub(super) target: Endpoint,
    pub(super) payload: Vec<u8>,
}

pub(super) struct RetryQueue {
    frames: VecDeque<PendingUotDatagram>,
    bytes: usize,
}

impl RetryQueue {
    pub(super) fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
        }
    }

    pub(super) fn push(&mut self, frame: PendingUotDatagram) -> Result<()> {
        if frame.payload.len() > MAX_UOT_RETRY_BYTES
            || self.frames.len() >= MAX_UOT_RETRY_FRAMES
            || self.bytes.saturating_add(frame.payload.len()) > MAX_UOT_RETRY_BYTES
        {
            return Err(Error::new(
                ErrorKind::Timeout,
                "Yuubinsya UOT retry queue is full",
            ));
        }
        self.bytes += frame.payload.len();
        self.frames.push_back(frame);
        Ok(())
    }

    pub(super) fn remove_id(&mut self, id: u64) {
        if let Some(index) = self.frames.iter().position(|frame| frame.id == id)
            && let Some(frame) = self.frames.remove(index)
        {
            self.bytes = self.bytes.saturating_sub(frame.payload.len());
        }
    }

    pub(super) fn acknowledge(&mut self, source: &Endpoint, payload: &[u8]) {
        let exact = self
            .frames
            .iter()
            .position(|frame| &frame.target == source && frame.payload == payload);
        let index = exact.or_else(|| {
            self.frames
                .iter()
                .position(|frame| frame.payload == payload)
        });
        if let Some(index) = index
            && let Some(frame) = self.frames.remove(index)
        {
            self.bytes = self.bytes.saturating_sub(frame.payload.len());
        }
    }

    pub(super) fn snapshot(&self) -> Vec<(Endpoint, Vec<u8>)> {
        self.frames
            .iter()
            .map(|frame| (frame.target.clone(), frame.payload.clone()))
            .collect()
    }

    pub(super) fn clear(&mut self) {
        self.frames.clear();
        self.bytes = 0;
    }
}

struct ChainUotWriter {
    stream: WriteHalf<BoxAsyncStream>,
    udp_coalesce: bool,
    pending: Vec<u8>,
    pending_frames: usize,
}

pub(super) struct ChainUotSession {
    reader: Mutex<ReadHalf<BoxAsyncStream>>,
    writer: Mutex<ChainUotWriter>,
    coalescer: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    coalesce_notify: Arc<Notify>,
}

impl ChainUotSession {
    pub(super) fn new(
        reader: ReadHalf<BoxAsyncStream>,
        writer: WriteHalf<BoxAsyncStream>,
        udp_coalesce: bool,
    ) -> Arc<Self> {
        let session = Arc::new(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(ChainUotWriter {
                stream: writer,
                udp_coalesce,
                pending: Vec::new(),
                pending_frames: 0,
            }),
            coalescer: StdMutex::new(None),
            coalesce_notify: Arc::new(Notify::new()),
        });
        if udp_coalesce {
            let weak = Arc::downgrade(&session);
            let notify = Arc::clone(&session.coalesce_notify);
            let task = tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    tokio::task::yield_now().await;
                    let Some(session) = weak.upgrade() else {
                        return;
                    };
                    if session.flush().await.is_err() {
                        return;
                    }
                }
            });
            if let Ok(mut coalescer) = session.coalescer.lock() {
                *coalescer = Some(task);
            } else {
                task.abort();
            }
        }
        session
    }

    pub(super) async fn send_to(&self, target: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = yuhaiin_protocol::yuubinsya::encode_uot_frame(target, payload)?;
        let mut writer = self.writer.lock().await;
        if !writer.udp_coalesce {
            writer.stream.write_all(&frame).await.map_err(io_error)?;
            return writer.stream.flush().await.map_err(io_error);
        }
        if frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending.len() + frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending_frames >= MAX_UOT_COALESCE_FRAMES
        {
            flush_uot_writer(&mut writer).await?;
        }
        writer.pending.extend_from_slice(&frame);
        writer.pending_frames += 1;
        if writer.pending_frames >= MAX_UOT_COALESCE_FRAMES {
            flush_uot_writer(&mut writer).await?;
        }
        drop(writer);
        // Match the Go packet-conn policy: one producer enqueue wakes an
        // owner flush loop, which gets one scheduler turn to batch concurrent
        // producers before writing.  Threshold and explicit recv/close
        // flushes remain the hard upper bounds for the batch size.
        self.coalesce_notify.notify_one();
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Endpoint, Vec<u8>)> {
        self.flush().await?;
        let mut reader = self.reader.lock().await;
        let frame = read_uot_frame(&mut *reader).await?;
        let (destination, payload, _) = yuhaiin_protocol::yuubinsya::decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        flush_uot_writer(&mut writer).await
    }

    pub(super) async fn shutdown(&self) -> Result<()> {
        self.flush().await?;
        let task = self
            .coalescer
            .lock()
            .ok()
            .and_then(|mut coalescer| coalescer.take());
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        let mut writer = self.writer.lock().await;
        writer.stream.shutdown().await.map_err(io_error)
    }
}

impl Drop for ChainUotSession {
    fn drop(&mut self) {
        if let Ok(mut coalescer) = self.coalescer.lock()
            && let Some(task) = coalescer.take()
        {
            task.abort();
        }
    }
}

async fn flush_uot_writer(writer: &mut ChainUotWriter) -> Result<()> {
    if writer.pending.is_empty() {
        return Ok(());
    }
    writer
        .stream
        .write_all(&writer.pending)
        .await
        .map_err(io_error)?;
    writer.stream.flush().await.map_err(io_error)?;
    writer.pending.clear();
    writer.pending_frames = 0;
    Ok(())
}

impl AsyncDatagram for ChainDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let retry_id = self.queue_retry(target.clone(), payload).await?;
            let generation = self.generation.load(Ordering::Acquire);
            let mut shutdown = self.shutdown.subscribe();
            let send_result = tokio::select! {
                result = self.send_once(&target, payload) => result,
                changed = shutdown.changed() => match changed {
                    Ok(()) | Err(_) => Err(closed_error()),
                },
            };
            if let Err(mut error) = send_result {
                if !is_recoverable_uot_error(&error) {
                    self.drop_retry(retry_id).await;
                    return Err(error);
                }

                // A write can fail before the peer has observed the frame, or
                // after it has already reached the peer. `reconnect()`
                // replays every still-unacknowledged frame from the bounded
                // retry queue, so retrying the connection is safe with the
                // duplicate-tolerant semantics required by UDP callers. Keep
                // the original frame queued when the reconnect budget is
                // exhausted; a concurrent/follow-up recv can still recover it.
                let mut reconnect_attempts = 0;
                loop {
                    if reconnect_attempts >= MAX_UOT_RECONNECT_ATTEMPTS {
                        return Err(error);
                    }
                    reconnect_attempts += 1;
                    let reconnect = tokio::select! {
                        result = self.reconnect(generation) => result,
                        changed = shutdown.changed() => match changed {
                            Ok(()) | Err(_) => Err(closed_error()),
                        },
                    };
                    match reconnect {
                        Ok(()) => break,
                        Err(reconnect_error) if reconnect_error.kind == ErrorKind::Closed => {
                            self.drop_retry(retry_id).await;
                            return Err(reconnect_error);
                        }
                        Err(reconnect_error) => error = reconnect_error,
                    }
                }
            }
            if self.closed.load(Ordering::Acquire) {
                self.drop_retry(retry_id).await;
                return Err(closed_error());
            }
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let generation = self.generation.load(Ordering::Acquire);
            let mut shutdown = self.shutdown.subscribe();
            let mut generation = generation;
            let mut reconnect_attempts = 0;
            let (source, payload) = loop {
                let result = tokio::select! {
                    result = self.recv_once() => result,
                    changed = shutdown.changed() => match changed {
                        Ok(()) | Err(_) => Err(closed_error()),
                    },
                };
                match result {
                    Ok(value) => break value,
                    Err(error)
                        if is_recoverable_uot_error(&error)
                            && reconnect_attempts < MAX_UOT_RECONNECT_ATTEMPTS =>
                    {
                        let reconnect = tokio::select! {
                            result = self.reconnect(generation) => result,
                            changed = shutdown.changed() => match changed {
                                Ok(()) | Err(_) => Err(closed_error()),
                            },
                        };
                        reconnect?;
                        generation = self.generation.load(Ordering::Acquire);
                        reconnect_attempts += 1;
                    }
                    Err(error) => return Err(error),
                }
            };
            if self.closed.load(Ordering::Acquire) {
                return Err(closed_error());
            }
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Yuubinsya UDP payload exceeds receive buffer",
                ));
            }
            self.acknowledge_retry(&source, &payload).await;
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), source))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        let local_addr = self
            .local_addr
            .lock()
            .ok()
            .and_then(|address| *address)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "Yuubinsya UOT has no observable local endpoint",
                )
            })?;
        Ok(Endpoint::ip(Network::Tcp, local_addr))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Release);
            let _ = self.shutdown.send(true);
            let session = self.session.lock().await.take();
            let result = if let Some(session) = session {
                session.shutdown().await
            } else {
                Ok(())
            };
            self.retry.lock().await.clear();
            result
        })
    }
}

pub(super) fn closed_error() -> Error {
    Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed")
}

impl ChainDatagram {
    async fn send_once(&self, target: &Endpoint, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let session = self.session.lock().await.clone();
        let session = session
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed"))?;
        session.send_to(target, payload).await
    }

    async fn recv_once(&self) -> Result<(Endpoint, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let session = self.session.lock().await.clone();
        let session = session
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed"))?;
        session.recv_from().await
    }

    async fn reconnect(&self, failed_generation: u64) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let _guard = self.reconnect_lock.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        if self.generation.load(Ordering::Acquire) != failed_generation {
            return Ok(());
        }
        let migrate_id = self.migrate_id.load(Ordering::Acquire);
        // A failed write may have reached the peer before reporting an error;
        // retrying one UDP datagram can therefore duplicate it. UDP callers
        // already need duplicate-tolerant semantics, while a bounded retry
        // prevents a dead H2 stream from permanently wedging the flow.
        let replacement = self
            .client
            .connect_uot_with_bind_and_interface(
                migrate_id,
                self.local_bind_addresses.as_slice(),
                self.bind_interface.as_deref(),
            )
            .await?;
        let replacement_id = replacement.migrate_id;
        let udp_coalesce = replacement.udp_coalesce;
        let local_addr = replacement.local_addr();
        let (reader, writer) = replacement.into_split().await;
        let replacement = ChainUotSession::new(reader, writer, udp_coalesce);
        let retry = self.retry.lock().await.snapshot();
        for (target, payload) in &retry {
            replacement.send_to(target, payload).await?;
        }
        replacement.flush().await?;
        if self.closed.load(Ordering::Acquire) {
            replacement.shutdown().await?;
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        self.migrate_id.store(replacement_id, Ordering::Release);
        if let Ok(mut current) = self.local_addr.lock() {
            *current = local_addr;
        }
        let mut session = self.session.lock().await;
        if self.closed.load(Ordering::Acquire) {
            replacement.shutdown().await?;
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let _ = session.take();
        *session = Some(replacement);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn queue_retry(&self, target: Endpoint, payload: &[u8]) -> Result<u64> {
        let id = self.next_retry_id.fetch_add(1, Ordering::AcqRel);
        self.retry.lock().await.push(PendingUotDatagram {
            id,
            target,
            payload: payload.to_vec(),
        })?;
        Ok(id)
    }

    async fn drop_retry(&self, id: u64) {
        self.retry.lock().await.remove_id(id);
    }

    async fn acknowledge_retry(&self, source: &Endpoint, payload: &[u8]) {
        self.retry.lock().await.acknowledge(source, payload);
    }
}

fn is_recoverable_uot_error(error: &Error) -> bool {
    matches!(
        error.kind,
        ErrorKind::Io | ErrorKind::Closed | ErrorKind::Protocol | ErrorKind::Timeout
    )
}
