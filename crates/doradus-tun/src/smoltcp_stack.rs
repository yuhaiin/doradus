//! Shared userspace IP stack for stateful outbound adapters.
//!
//! The stack owns smoltcp's TCP/UDP sockets and exposes them through the
//! project's `AsyncProxy` stream/datagram shapes.  A transport-specific
//! adapter (WireGuard, MASQUE, or a future tunnel) only has to feed complete
//! IP packets into [`SmoltcpStack::enqueue_ip_packet`] and send the packets
//! returned by [`SmoltcpStack::poll`].

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant as StdInstant;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    UdpMetadata,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use doradus_core::proxy::AsyncDatagram;
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};

use crate::{
    DEFAULT_QUEUE_CAPACITY, Ipv6FragmentReassembler, SmoltcpTunDevice, fragment_ip_packet,
    normalize_ipv6_extension_headers,
};

const SOCKET_BUFFER_SIZE: usize = 64 * 1024;
const MAX_STREAM_OUTPUT_BYTES: usize = SOCKET_BUFFER_SIZE * 4;
const PORT_MIN: u16 = 32_768;
const PORT_MAX: u16 = 60_000;

/// Configuration for the shared smoltcp flow stack.
#[derive(Debug, Clone)]
pub struct SmoltcpStackConfig {
    /// Addresses assigned to the virtual IP interface.  An IPv4 address is
    /// normally configured as `/32` and an IPv6 address as `/128`.
    pub local_addresses: Vec<IpCidr>,
    /// Maximum packet size used by the virtual interface and by outbound IP
    /// fragmentation before packets cross the tunnel transport.
    pub mtu: usize,
    /// Capacity of each bounded packet queue.
    pub queue_capacity: usize,
}

impl SmoltcpStackConfig {
    pub fn new(local_addresses: Vec<IpCidr>, mtu: usize) -> Self {
        Self {
            local_addresses,
            mtu,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

pub(crate) enum StackCommand {
    Write(Vec<u8>),
    Close,
}

pub(crate) enum DatagramCommand {
    Send {
        payload: Vec<u8>,
        target: SocketAddr,
        reply: oneshot::Sender<Result<()>>,
    },
    Recv {
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
    Close,
}

type StreamWriteFuture = Pin<
    Box<dyn Future<Output = std::result::Result<(), mpsc::error::SendError<StackCommand>>> + Send>,
>;

type DatagramReceiveReply = oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>;

struct TcpSession {
    command_rx: mpsc::Receiver<StackCommand>,
    output_tx: mpsc::Sender<Vec<u8>>,
    pending_writes: VecDeque<Vec<u8>>,
    pending_output: VecDeque<Vec<u8>>,
    pending_output_bytes: usize,
    close_requested: bool,
}

struct UdpSession {
    command_rx: mpsc::Receiver<DatagramCommand>,
    pending_recv: Option<DatagramReceiveReply>,
    queued_recv: VecDeque<(Vec<u8>, SocketAddr)>,
}

/// A TCP stream backed by one smoltcp TCP socket.
pub struct SmoltcpStream {
    command_tx: mpsc::Sender<StackCommand>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    pending_read: VecDeque<u8>,
    pending_write: Option<StreamWriteFuture>,
    shutdown_sent: bool,
}

impl AsyncRead for SmoltcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending_read.is_empty() {
            let amount = buffer.remaining().min(self.pending_read.len());
            let data: Vec<_> = self.pending_read.drain(..amount).collect();
            buffer.put_slice(&data);
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

impl AsyncWrite for SmoltcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            let sender = self.command_tx.clone();
            let payload = data.to_vec();
            self.pending_write = Some(Box::pin(async move {
                sender.send(StackCommand::Write(payload)).await
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
                    "smoltcp TCP session is closed",
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
            let _ = self.command_tx.try_send(StackCommand::Close);
        }
        Poll::Ready(Ok(()))
    }
}

/// A UDP datagram endpoint backed by one smoltcp UDP socket.
pub struct SmoltcpDatagram {
    command_tx: mpsc::Sender<DatagramCommand>,
    local_addr: Endpoint,
}

impl AsyncDatagram for SmoltcpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("smoltcp UDP target has wrong network"));
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
                .map_err(|_| Error::new(ErrorKind::Closed, "smoltcp UDP session is closed"))?;
            reply_rx
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "smoltcp UDP driver dropped send"))??;
            Ok(length)
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DatagramCommand::Recv { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "smoltcp UDP session is closed"))?;
            let (payload, target) = reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "smoltcp UDP driver dropped receive")
            })??;
            if buffer.len() < payload.len() {
                return Err(Error::invalid("smoltcp UDP payload exceeds receive buffer"));
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

/// The shared smoltcp flow engine.
pub struct SmoltcpStack {
    config: SmoltcpStackConfig,
    device: SmoltcpTunDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    ipv6_fragments: Ipv6FragmentReassembler,
    fragment_identification: u32,
    next_port: u16,
    tcp_sessions: HashMap<SocketHandle, TcpSession>,
    udp_sessions: HashMap<SocketHandle, UdpSession>,
}

impl SmoltcpStack {
    pub fn new(config: SmoltcpStackConfig) -> Result<Self> {
        let mut device = SmoltcpTunDevice::new(config.mtu, config.queue_capacity)?;
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            for address in &config.local_addresses {
                let _ = addresses.push(*address);
            }
        });
        if config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv4(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0));
        }
        if config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv6(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);
        }
        Ok(Self {
            config,
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            fragment_identification: 0,
            next_port: PORT_MIN,
            tcp_sessions: HashMap::new(),
            udp_sessions: HashMap::new(),
        })
    }

    pub fn open_tcp(&mut self, destination: SocketAddr) -> Result<SmoltcpStream> {
        let local_port = self.allocate_port();
        let socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
            TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
        );
        let handle = self.sockets.add(socket);
        if let Err(error) = self.sockets.get_mut::<TcpSocket>(handle).connect(
            self.interface.context(),
            ip_endpoint(destination),
            listen_endpoint(local_port),
        ) {
            let _ = self.sockets.remove(handle);
            return Err(error_protocol(error));
        }
        let (command_tx, command_rx) = mpsc::channel(64);
        let (output_tx, output_rx) = mpsc::channel(64);
        self.tcp_sessions.insert(
            handle,
            TcpSession {
                command_rx,
                output_tx,
                pending_writes: VecDeque::new(),
                pending_output: VecDeque::new(),
                pending_output_bytes: 0,
                close_requested: false,
            },
        );
        Ok(SmoltcpStream {
            command_tx,
            output_rx,
            pending_read: VecDeque::new(),
            pending_write: None,
            shutdown_sent: false,
        })
    }

    pub fn open_udp(&mut self) -> Result<SmoltcpDatagram> {
        let local_port = self.allocate_port();
        let mut socket = UdpSocket::new(
            UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; 64],
                vec![0; SOCKET_BUFFER_SIZE],
            ),
            UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; 64],
                vec![0; SOCKET_BUFFER_SIZE],
            ),
        );
        socket
            .bind(listen_endpoint(local_port))
            .map_err(error_protocol)?;
        let handle = self.sockets.add(socket);
        let (command_tx, command_rx) = mpsc::channel(64);
        let local_ip = self
            .config
            .local_addresses
            .first()
            .map(|cidr| IpAddr::from(cidr.address()))
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        self.udp_sessions.insert(
            handle,
            UdpSession {
                command_rx,
                pending_recv: None,
                queued_recv: VecDeque::new(),
            },
        );
        Ok(SmoltcpDatagram {
            command_tx,
            local_addr: core_endpoint(Network::Udp, SocketAddr::new(local_ip, local_port)),
        })
    }

    /// Process flow commands and smoltcp timers, returning complete IP
    /// packets ready for the transport adapter.  The returned packets are
    /// already fragmented to the configured wire MTU.
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        self.process_sessions();
        self.interface.poll(
            Instant::from_millis(current_millis()),
            &mut self.device,
            &mut self.sockets,
        );
        let mut packets = Vec::new();
        while let Ok(Some(packet)) = self.device.take_tx() {
            let fragments =
                match fragment_ip_packet(&packet, self.config.mtu, self.fragment_identification) {
                    Ok(fragments) => fragments,
                    Err(_) => continue,
                };
            self.fragment_identification = self.fragment_identification.wrapping_add(1);
            packets.extend(fragments);
        }
        self.ipv6_fragments.expire(StdInstant::now());
        packets
    }

    /// Enqueue one complete or fragmented IP packet received from the tunnel
    /// transport.  IPv6 fragments are reassembled before smoltcp sees them.
    pub fn enqueue_ip_packet(&mut self, packet: &[u8]) -> Result<bool> {
        let Some(packet) = self
            .ipv6_fragments
            .push_borrowed(packet, StdInstant::now())?
        else {
            return Ok(false);
        };
        let packet = normalize_ipv6_extension_headers(packet.as_ref())?;
        self.device.enqueue_rx_reassembled(packet.into_owned())
    }

    fn process_sessions(&mut self) {
        let tcp_handles = self.tcp_sessions.keys().copied().collect::<Vec<_>>();
        for handle in tcp_handles {
            let Some(session) = self.tcp_sessions.get_mut(&handle) else {
                continue;
            };
            while let Ok(command) = session.command_rx.try_recv() {
                match command {
                    StackCommand::Write(data) => session.pending_writes.push_back(data),
                    StackCommand::Close => session.close_requested = true,
                }
            }
            let socket = self.sockets.get_mut::<TcpSocket>(handle);
            if session.close_requested {
                socket.close();
            }
            while socket.can_send() {
                let Some(data) = session.pending_writes.pop_front() else {
                    break;
                };
                match socket.send_slice(&data) {
                    Ok(written) if written < data.len() => {
                        session.pending_writes.push_front(data[written..].to_vec())
                    }
                    Ok(_) => {}
                    Err(_) => {
                        session.pending_writes.push_front(data);
                        break;
                    }
                }
            }
            while let Some(data) = session.pending_output.pop_front() {
                session.pending_output_bytes -= data.len();
                match session.output_tx.try_send(data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        session.pending_output_bytes += data.len();
                        session.pending_output.push_front(data);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        session.close_requested = true;
                        session.pending_output.clear();
                        session.pending_output_bytes = 0;
                        break;
                    }
                }
            }
            if socket.can_recv() && !session.close_requested {
                let mut data = vec![0; SOCKET_BUFFER_SIZE.min(self.config.mtu.saturating_mul(8))];
                if let Ok(length) = socket.recv_slice(&mut data) {
                    data.truncate(length);
                    match session.output_tx.try_send(data) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(data)) => {
                            if session.pending_output_bytes + data.len() > MAX_STREAM_OUTPUT_BYTES {
                                session.close_requested = true;
                                session.pending_output.clear();
                                session.pending_output_bytes = 0;
                            } else {
                                session.pending_output_bytes += data.len();
                                session.pending_output.push_back(data);
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            session.close_requested = true;
                        }
                    }
                }
            }
            if socket.state() == TcpState::Closed
                && session.pending_writes.is_empty()
                && session.pending_output.is_empty()
            {
                self.tcp_sessions.remove(&handle);
                let _ = self.sockets.remove(handle);
            }
        }

        let udp_handles = self.udp_sessions.keys().copied().collect::<Vec<_>>();
        for handle in udp_handles {
            let mut remove = false;
            let Some(session) = self.udp_sessions.get_mut(&handle) else {
                continue;
            };
            while let Ok(command) = session.command_rx.try_recv() {
                match command {
                    DatagramCommand::Send {
                        payload,
                        target,
                        reply,
                    } => {
                        let result = self
                            .sockets
                            .get_mut::<UdpSocket>(handle)
                            .send_slice(&payload, UdpMetadata::from(ip_endpoint(target)));
                        let _ = reply.send(result.map_err(error_protocol));
                    }
                    DatagramCommand::Recv { reply } => {
                        if let Some((payload, target)) = session.queued_recv.pop_front() {
                            let _ = reply.send(Ok((payload, target)));
                        } else {
                            session.pending_recv = Some(reply);
                        }
                    }
                    DatagramCommand::Close => {
                        remove = true;
                        break;
                    }
                }
            }
            if remove {
                self.udp_sessions.remove(&handle);
                let _ = self.sockets.remove(handle);
                continue;
            }
            let socket = self.sockets.get_mut::<UdpSocket>(handle);
            while socket.can_recv() {
                let mut payload = vec![0; SOCKET_BUFFER_SIZE];
                let Ok((length, metadata)) = socket.recv_slice(&mut payload) else {
                    break;
                };
                payload.truncate(length);
                let target: SocketAddr = metadata.endpoint.into();
                if let Some(reply) = session.pending_recv.take() {
                    let _ = reply.send(Ok((payload, target)));
                } else {
                    session.queued_recv.push_back((payload, target));
                }
            }
        }
    }

    fn allocate_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port >= PORT_MAX {
            PORT_MIN
        } else {
            self.next_port + 1
        };
        port
    }
}

fn core_endpoint(network: Network, address: SocketAddr) -> Endpoint {
    Endpoint::ip(network, address)
}

fn ip_endpoint(address: SocketAddr) -> smoltcp::wire::IpEndpoint {
    smoltcp::wire::IpEndpoint::new(address.ip().into(), address.port())
}

fn listen_endpoint(port: u16) -> smoltcp::wire::IpListenEndpoint {
    smoltcp::wire::IpListenEndpoint { addr: None, port }
}

async fn resolve_endpoint_value(endpoint: &Endpoint) -> Result<SocketAddr> {
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("smoltcp UDP target has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("smoltcp UDP target has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "smoltcp UDP target resolved to no address"))
}

fn error_protocol(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, error.to_string())
}

fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_accepts_configured_ipv4_and_ipv6_addresses() {
        let stack = SmoltcpStack::new(SmoltcpStackConfig::new(
            vec![
                IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(
                    smoltcp::wire::Ipv4Address::new(172, 16, 0, 2),
                    32,
                )),
                IpCidr::Ipv6(smoltcp::wire::Ipv6Cidr::new(
                    smoltcp::wire::Ipv6Address::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1),
                    128,
                )),
            ],
            1280,
        ));
        assert!(stack.is_ok());
    }
}
