use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot};

use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::network::{DEFAULT_INTERFACE, bind_socket_to_interface};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Network, Result};

use crate::config::{
    ParsedConfig, ParsedPeer, WireGuardConfig, decode_key, error_io, error_unsupported,
};
use crate::driver::{Driver, DriverCommand};

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
