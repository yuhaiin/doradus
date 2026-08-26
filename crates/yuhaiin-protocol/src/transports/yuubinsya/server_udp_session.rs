use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

use super::common::{SERVER_UDP_IDLE_TIMEOUT, SERVER_UDP_RESPONSE_TIMEOUT};
use tokio::sync::{Mutex, mpsc};
use yuhaiin_core::proxy::AsyncDatagram;
use yuhaiin_core::{Endpoint, Result};

pub(super) enum ServerUdpMessage {
    Data { source: Endpoint, payload: Vec<u8> },
    Closed,
}

pub(super) struct ServerUdpSession {
    datagram: Arc<dyn AsyncDatagram>,
    routes: Mutex<HashMap<Endpoint, mpsc::Sender<ServerUdpMessage>>>,
    last_sender: Mutex<Option<mpsc::Sender<ServerUdpMessage>>>,
    last_used: StdMutex<Instant>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ServerUdpSession {
    pub(super) async fn spawn(
        datagram: Box<dyn AsyncDatagram>,
        udp_buffer_size: usize,
    ) -> Arc<Self> {
        let session = Arc::new(Self {
            datagram: Arc::from(datagram),
            routes: Mutex::new(HashMap::new()),
            last_sender: Mutex::new(None),
            last_used: StdMutex::new(Instant::now()),
            worker: Mutex::new(None),
        });
        let worker_session = Arc::clone(&session);
        let worker = tokio::spawn(async move {
            worker_session.run_reader(udp_buffer_size).await;
        });
        *session.worker.lock().await = Some(worker);
        session
    }

    async fn run_reader(self: Arc<Self>, udp_buffer_size: usize) {
        let mut buffer = vec![0u8; udp_buffer_size];
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

    pub(super) fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = Instant::now();
        }
    }

    pub(super) fn is_idle(&self, now: Instant) -> bool {
        self.last_used
            .lock()
            .map(|last_used| now.duration_since(*last_used) >= SERVER_UDP_IDLE_TIMEOUT)
            .unwrap_or(false)
    }

    pub(super) async fn register(
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

    pub(super) async fn route(
        &self,
        destination: Endpoint,
        sender: &mpsc::Sender<ServerUdpMessage>,
    ) {
        self.routes.lock().await.insert(destination, sender.clone());
        *self.last_sender.lock().await = Some(sender.clone());
        self.touch();
    }

    pub(super) async fn unregister_sender(&self, sender: &mpsc::Sender<ServerUdpMessage>) {
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

    pub(super) async fn send_to(&self, payload: &[u8], target: Endpoint) -> Result<usize> {
        self.touch();
        self.datagram.send_to(payload, target).await
    }

    pub(super) fn local_addr(&self) -> Result<Endpoint> {
        self.datagram.local_addr()
    }

    pub(super) async fn close(&self) {
        let _ = self.datagram.close().await;
        self.notify_closed().await;
        if let Some(worker) = self.worker.lock().await.take() {
            worker.abort();
            let _ = worker.await;
        }
    }
}
