//! UDP socket adapters used by the DoQ client's Quinn endpoint.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::dns_datagram::AsyncDnsDatagram;
use crate::transport::bind_udp_socket;
use crate::{BoxFuture, Error, ErrorKind, Result};
use futures_util::task::AtomicWaker;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

const MAX_QUIC_DATAGRAM: usize = 65_535;
pub(super) const QUINN_DATAGRAM_QUEUE_CAPACITY: usize = 256;

pub(super) struct DirectDatagram {
    socket: Arc<UdpSocket>,
}

impl DirectDatagram {
    pub(super) async fn bind(
        server: SocketAddr,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<Self> {
        let bind_address = local_bind_addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == server.is_ipv4())
            .map(|address| SocketAddr::new(address, 0))
            .unwrap_or_else(|| {
                if server.is_ipv4() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                }
            });
        let socket = bind_udp_socket(bind_address, server, bind_interface, "DoQ").await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }
}

impl AsyncDnsDatagram for DirectDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.socket
                .send_to(payload, target)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("send DoQ UDP packet: {error}")))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (length, address) = self.socket.recv_from(buffer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("receive DoQ UDP packet: {error}"))
            })?;
            Ok((length, address))
        })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, format!("DoQ UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
struct InboundDatagram {
    payload: Vec<u8>,
    source: SocketAddr,
}

#[derive(Debug)]
struct OutboundDatagram {
    payload: Vec<u8>,
    target: SocketAddr,
}

pub(super) struct QuinnDatagram {
    local_addr: SocketAddr,
    send: mpsc::Sender<OutboundDatagram>,
    recv: Mutex<mpsc::Receiver<InboundDatagram>>,
    send_waker: Arc<AtomicWaker>,
    send_closed: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    closed: Arc<AtomicBool>,
}

impl fmt::Debug for QuinnDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuinnDatagram")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl QuinnDatagram {
    pub(super) fn new(datagram: Box<dyn AsyncDnsDatagram>) -> Result<Self> {
        let datagram: Arc<dyn AsyncDnsDatagram> = Arc::from(datagram);
        let local_addr = datagram.local_addr()?;
        let (send, mut send_rx) = mpsc::channel::<OutboundDatagram>(QUINN_DATAGRAM_QUEUE_CAPACITY);
        let (recv_tx, recv) = mpsc::channel::<InboundDatagram>(QUINN_DATAGRAM_QUEUE_CAPACITY);
        let send_waker = Arc::new(AtomicWaker::new());
        let send_closed = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let sender_datagram = datagram.clone();
        let sender_shutdown = shutdown.clone();
        let sender_closed = closed.clone();
        let sender_send_closed = send_closed.clone();
        let sender_send_waker = send_waker.clone();
        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = sender_shutdown.notified() => break,
                    packet = send_rx.recv() => packet,
                };
                let Some(packet) = packet else {
                    break;
                };
                // Receiving from the bounded queue frees at least one slot.
                // Wake Quinn if it previously observed WouldBlock.
                sender_send_waker.wake();
                if sender_datagram
                    .send_to(&packet.payload, packet.target)
                    .await
                    .is_err()
                {
                    sender_send_closed.store(true, Ordering::Release);
                    break;
                }
            }
            let _ = sender_datagram.close().await;
            sender_closed.store(true, Ordering::Release);
            sender_send_waker.wake();
        });

        let receiver_datagram = datagram;
        let receiver_shutdown = shutdown.clone();
        let receiver_closed = closed.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_QUIC_DATAGRAM];
            loop {
                if receiver_closed.load(Ordering::Acquire) {
                    break;
                };
                let received = tokio::select! {
                    _ = receiver_shutdown.notified() => break,
                    received = receiver_datagram.recv_from(&mut buffer) => received,
                };
                let Ok((length, source)) = received else {
                    break;
                };
                if recv_tx
                    .send(InboundDatagram {
                        payload: buffer[..length].to_vec(),
                        source,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Self {
            local_addr,
            send,
            recv: Mutex::new(recv),
            send_waker,
            send_closed,
            shutdown,
            closed,
        })
    }
}

impl Drop for QuinnDatagram {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
    }
}

impl quinn::AsyncUdpSocket for QuinnDatagram {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(QuinnDatagramPoller {
            send: self.send.clone(),
            send_waker: self.send_waker.clone(),
            send_closed: self.send_closed.clone(),
            closed: self.closed.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        if self.send_closed.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP sender closed",
            ));
        }
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 {
            return Ok(());
        }
        for payload in transmit.contents.chunks(segment_size) {
            self.send
                .try_send(OutboundDatagram {
                    payload: payload.to_vec(),
                    target: transmit.destination,
                })
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        io::Error::new(io::ErrorKind::WouldBlock, "DoQ UDP send queue is full")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "DoQ UDP sender closed")
                    }
                })?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(metadata) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut recv = match self.recv.lock() {
            Ok(recv) => recv,
            Err(_) => return Poll::Ready(Err(io::Error::other("DoQ UDP receive lock poisoned"))),
        };
        match Pin::new(&mut *recv).poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let length = packet.payload.len().min(buffer.len());
                buffer[..length].copy_from_slice(&packet.payload[..length]);
                *metadata = quinn::udp::RecvMeta {
                    addr: packet.source,
                    len: length,
                    stride: length,
                    ..Default::default()
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP receiver closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct QuinnDatagramPoller {
    send: mpsc::Sender<OutboundDatagram>,
    send_waker: Arc<AtomicWaker>,
    send_closed: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
}

impl quinn::UdpPoller for QuinnDatagramPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.send_closed.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
            || self.send.is_closed()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP sender closed",
            )));
        }
        if self.send.capacity() > 0 {
            return Poll::Ready(Ok(()));
        }

        self.send_waker.register(cx.waker());

        // Check again after registering to close the race where the worker
        // freed capacity immediately before the waker became visible.
        if self.send_closed.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
            || self.send.is_closed()
        {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DoQ UDP sender closed",
            )))
        } else if self.send.capacity() > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
