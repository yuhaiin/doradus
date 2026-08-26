use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot};

use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::network::{DEFAULT_INTERFACE, bind_socket_to_interface};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use crate::config::{
    ParsedConfig, ParsedPeer, WireGuardConfig, core_endpoint, decode_key, error_io,
    error_unsupported,
};
use crate::driver::{DatagramCommand, Driver, DriverCommand, StreamCommand};

/// Construct the running WireGuard proxy. The returned proxy owns one
/// userspace IP stack and one UDP underlay; individual yuhaiin flows become
/// smoltcp TCP or UDP sockets on that stack.
pub async fn build_proxy(config: WireGuardConfig, timeout: Duration) -> Result<WireGuardProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, None, None).await
}

/// Construct a WireGuard proxy while constraining its UDP underlay to an
/// operating-system interface when the platform supports that operation.
/// Keeping this option at the underlay boundary is important: the BoringTun
/// virtual stack does not create the socket used by the outer proxy wrapper.
pub async fn build_proxy_with_interface(
    config: WireGuardConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
) -> Result<WireGuardProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, bind_interface, None).await
}

/// Construct a WireGuard proxy using the runtime's resolver for peer endpoint
/// hostnames. This keeps hosts/FakeIP/DNS policy consistent with the rest of
/// the proxy graph; the no-resolver wrappers retain the standalone API and
/// use the system resolver for compatibility.
pub async fn build_proxy_with_interface_and_resolver(
    config: WireGuardConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
) -> Result<WireGuardProxy> {
    let private_key = decode_key(&config.secret_key, "secretKey")?;
    let mut parsed_peers = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        parsed_peers.push(peer.parse(timeout, resolver.as_deref()).await?);
    }
    let parsed = config.parse(parsed_peers)?;
    WireGuardProxy::start(ParsedConfig { ..parsed }, private_key, bind_interface).await
}

pub struct WireGuardProxy {
    pub(crate) command_tx: mpsc::Sender<DriverCommand>,
    pub(crate) closed: Arc<AtomicBool>,
}

impl WireGuardProxy {
    pub(crate) async fn start(
        config: ParsedConfig,
        private_key: [u8; 32],
        bind_interface: Option<&str>,
    ) -> Result<Self> {
        let bind_address = if config.peers.iter().any(|peer| peer.endpoint.is_ipv6()) {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let bind_interface = underlay_interface_for_peers(bind_interface, &config.peers);
        let underlay = bind_udp_underlay(bind_address, bind_interface).await?;
        let (command_tx, command_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            Driver::new(config, private_key, underlay, command_rx, task_closed)
                .run(Some(ready_tx))
                .await;
        });
        ready_rx.await.map_err(|_| {
            Error::new(
                ErrorKind::Closed,
                "WireGuard driver exited before it became ready",
            )
        })??;
        Ok(Self { command_tx, closed })
    }
}

pub(crate) fn underlay_interface_for_peers<'a>(
    bind_interface: Option<&'a str>,
    peers: &[ParsedPeer],
) -> Option<&'a str> {
    if bind_interface == Some(DEFAULT_INTERFACE)
        && peers.iter().any(|peer| peer.endpoint.ip().is_loopback())
    {
        return None;
    }
    bind_interface
}

pub(crate) async fn bind_udp_underlay(
    bind_address: &str,
    bind_interface: Option<&str>,
) -> Result<TokioUdpSocket> {
    let Some(interface) = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return TokioUdpSocket::bind(bind_address).await.map_err(error_io);
    };
    let address: SocketAddr = bind_address.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard bind address: {error}"),
        )
    })?;
    let socket = socket2::Socket::new(
        if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(error_io)?;
    bind_socket_to_interface(&socket, Some(interface))?;
    socket.bind(&address.into()).map_err(error_io)?;
    socket.set_nonblocking(true).map_err(error_io)?;
    TokioUdpSocket::from_std(socket.into()).map_err(error_io)
}

impl AsyncProxy for WireGuardProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            if context.network != Network::Tcp {
                return Err(error_unsupported(
                    "WireGuard TCP proxy received a non-TCP flow",
                ));
            }
            let destination = resolve_flow_destination(context).await?;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenTcp {
                    destination,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard driver dropped TCP request")
            })??) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            if context.network != Network::Udp && context.network != Network::Any {
                return Err(error_unsupported(
                    "WireGuard UDP proxy received a non-UDP flow",
                ));
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenUdp { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard driver dropped UDP request")
            })??) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.command_tx.try_send(DriverCommand::Close);
        }
        Box::pin(async { Ok(()) })
    }
}

async fn resolve_flow_destination(context: &FlowContext) -> Result<SocketAddr> {
    let endpoint = context
        .resolved_destination
        .as_ref()
        .unwrap_or(&context.destination);
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WireGuard destination has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WireGuard destination has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(error_io)?
        .next()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Io,
                format!("WireGuard destination {host}:{port} resolved to no address"),
            )
        })
}

pub(crate) type StreamWriteFuture = Pin<
    Box<dyn Future<Output = std::result::Result<(), mpsc::error::SendError<StreamCommand>>> + Send>,
>;
pub(crate) type DatagramReceiveReply = oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>;

pub(crate) struct WireGuardStream {
    pub(crate) command_tx: mpsc::Sender<StreamCommand>,
    pub(crate) output_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) pending_read: VecDeque<u8>,
    pub(crate) pending_write: Option<StreamWriteFuture>,
    pub(crate) shutdown_sent: bool,
}

impl AsyncRead for WireGuardStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending_read.is_empty() {
            let amount = buffer.remaining().min(self.pending_read.len());
            let mut data = self.pending_read.drain(..amount).collect::<Vec<_>>();
            buffer.put_slice(&data);
            data.clear();
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.output_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let amount = buffer.remaining().min(data.len());
                buffer.put_slice(&data[..amount]);
                self.pending_read.extend(data.into_iter().skip(amount));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WireGuardStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            let sender = self.command_tx.clone();
            let payload = data.to_vec();
            self.pending_write = Some(Box::pin(async move {
                sender.send(StreamCommand::Write(payload)).await
            }));
        }
        match self
            .pending_write
            .as_mut()
            .expect("write future was installed")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(Ok(())) => {
                self.pending_write = None;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(_)) => {
                self.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard TCP session is closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.shutdown_sent = true;
            let _ = self.command_tx.try_send(StreamCommand::Close);
        }
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct WireGuardDatagram {
    pub(crate) command_tx: mpsc::Sender<DatagramCommand>,
    pub(crate) local_addr: Endpoint,
}

impl AsyncDatagram for WireGuardDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("WireGuard UDP target has wrong network"));
            }
            let target = resolve_endpoint_value(&target).await?;
            let length = payload.len();
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DatagramCommand::Send {
                    payload: payload.to_vec(),
                    target,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard UDP session is closed"))?;
            reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard UDP driver dropped send")
            })??;
            Ok(length)
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DatagramCommand::Recv { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard UDP session is closed"))?;
            let (payload, target) = reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard UDP driver dropped receive")
            })??;
            if buffer.len() < payload.len() {
                return Err(Error::invalid(
                    "WireGuard UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), core_endpoint(Network::Udp, target)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(self.local_addr.clone())
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let _ = self.command_tx.try_send(DatagramCommand::Close);
        Box::pin(async { Ok(()) })
    }
}

async fn resolve_endpoint_value(endpoint: &Endpoint) -> Result<SocketAddr> {
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WireGuard UDP target has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WireGuard UDP target has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(error_io)?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "WireGuard UDP target resolved to no address"))
}
