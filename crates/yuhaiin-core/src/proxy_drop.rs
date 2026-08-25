//! Drop proxies.

use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct DropAsyncProxy;

impl AsyncProxy for DropAsyncProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "connection dropped by route policy",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "datagram dropped by route policy",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Go's `drop` proxy accepts a flow, acknowledges writes, and silently waits
/// before ending reads.  The wait grows per destination so repeated blocked
/// attempts do not immediately consume CPU or create observable connection
/// errors.  This is deliberately separate from [`DropAsyncProxy`], which is
/// the internal fail-closed placeholder used while a runtime slot is closed.
pub struct DelayedDropAsyncProxy {
    state: Arc<DelayedDropState>,
}

impl Default for DelayedDropAsyncProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayedDropAsyncProxy {
    pub fn new() -> Self {
        Self {
            state: Arc::new(DelayedDropState::default()),
        }
    }
}

const DROP_CACHE_CAPACITY: usize = 512;

const DROP_CACHE_EXPIRY: Duration = Duration::from_secs(5);

const DROP_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct DelayedDropEntry {
    delay: Duration,
    last_seen: std::time::Instant,
}

#[derive(Default)]
pub(super) struct DelayedDropState {
    entries: Mutex<HashMap<u64, DelayedDropEntry>>,
}

impl DelayedDropState {
    pub(super) fn next_delay(&self, destination: &Endpoint) -> Duration {
        let key = destination.comparable_key();
        let now = std::time::Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        match entries.get_mut(&key) {
            Some(entry) if now.duration_since(entry.last_seen) <= DROP_CACHE_EXPIRY => {
                entry.delay = if entry.delay.is_zero() {
                    Duration::from_secs(1)
                } else {
                    (entry.delay * 2).min(DROP_MAX_DELAY)
                };
                entry.last_seen = now;
                entry.delay
            }
            Some(entry) => {
                entry.delay = Duration::ZERO;
                entry.last_seen = now;
                Duration::ZERO
            }
            None => {
                if entries.len() >= DROP_CACHE_CAPACITY
                    && let Some(oldest_key) = entries
                        .iter()
                        .min_by_key(|(_, entry)| entry.last_seen)
                        .map(|(key, _)| *key)
                {
                    entries.remove(&oldest_key);
                }
                entries.insert(
                    key,
                    DelayedDropEntry {
                        delay: Duration::ZERO,
                        last_seen: now,
                    },
                );
                Duration::ZERO
            }
        }
    }
}

struct DelayedDropStream {
    sleep: Option<Pin<Box<Sleep>>>,
}

impl DelayedDropStream {
    fn new(delay: Duration) -> Self {
        Self {
            sleep: (!delay.is_zero()).then(|| Box::pin(tokio::time::sleep(delay))),
        }
    }
}

impl AsyncRead for DelayedDropStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(sleep) = self.sleep.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DelayedDropStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.sleep = None;
        Poll::Ready(Ok(()))
    }
}

struct DelayedDropDatagram {
    delay: Duration,
    closed: Arc<DelayedDropDatagramState>,
}

struct DelayedDropDatagramState {
    closed: AtomicBool,
    notify: Notify,
}

impl DelayedDropDatagramState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }
}

impl AsyncDatagram for DelayedDropDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { Ok(payload.len()) })
    }

    fn recv_from<'a>(&'a self, _buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        let closed = Arc::clone(&self.closed);
        let delay = self.delay;
        Box::pin(async move {
            if closed.closed.load(Ordering::Acquire) {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                ));
            }
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                )),
                _ = closed.notify.notified() => Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                )),
            }
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            SocketAddr::from(([0, 0, 0, 0], 0)),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.closed.closed.store(true, Ordering::Release);
        self.closed.notify.notify_waiters();
        Box::pin(async { Ok(()) })
    }
}

impl AsyncProxy for DelayedDropAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let delay = self.state.next_delay(&context.effective_destination());
        Box::pin(async move { Ok(Box::new(DelayedDropStream::new(delay)) as BoxAsyncStream) })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let delay = self.state.next_delay(&context.effective_destination());
        Box::pin(async move {
            Ok(Box::new(DelayedDropDatagram {
                delay,
                closed: Arc::new(DelayedDropDatagramState::new()),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "drop proxy does not support ping",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
