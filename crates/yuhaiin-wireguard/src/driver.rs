use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant as StdInstant};

use boringtun::noise::TunnResult;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpSocketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    UdpMetadata,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot};
use yuhaiin_core::{Error, Network, Result};
use yuhaiin_tun::{
    Ipv6FragmentReassembler, SmoltcpTunDevice, fragment_ip_packet, normalize_ipv6_extension_headers,
};

use crate::config::{
    ParsedConfig, core_endpoint, error_io, error_protocol, ip_endpoint, listen_endpoint,
};
use crate::engine::{DecapsulatedPacket, WireGuardEngine};
use crate::proxy::{DatagramReceiveReply, WireGuardDatagram, WireGuardStream};
use crate::{
    DEFAULT_QUEUE_CAPACITY, HANDSHAKE_BUFFER_SIZE, MAX_PACKET_SIZE, MAX_STREAM_OUTPUT_BYTES,
    PORT_MAX, PORT_MIN, SOCKET_BUFFER_SIZE,
};

pub(crate) enum DriverCommand {
    OpenTcp {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<WireGuardStream>>,
    },
    OpenUdp {
        reply: oneshot::Sender<Result<WireGuardDatagram>>,
    },
    Close,
}

pub(crate) enum StreamCommand {
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

pub(crate) struct TcpSession {
    command_rx: mpsc::Receiver<StreamCommand>,
    output_tx: mpsc::Sender<Vec<u8>>,
    pending_writes: VecDeque<Vec<u8>>,
    pending_output: VecDeque<Vec<u8>>,
    pending_output_bytes: usize,
    close_requested: bool,
}

pub(crate) struct UdpSession {
    command_rx: mpsc::Receiver<DatagramCommand>,
    pending_recv: Option<DatagramReceiveReply>,
    queued_recv: VecDeque<(Vec<u8>, SocketAddr)>,
}

pub(crate) struct Driver {
    config: ParsedConfig,
    engine: WireGuardEngine,
    underlay: TokioUdpSocket,
    command_rx: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
    ipv6_fragments: Ipv6FragmentReassembler,
    fragment_identification: u32,
    next_port: u16,
    tcp_sessions: HashMap<SocketHandle, TcpSession>,
    udp_sessions: HashMap<SocketHandle, UdpSession>,
}

impl Driver {
    pub(crate) fn new(
        config: ParsedConfig,
        private_key: [u8; 32],
        underlay: TokioUdpSocket,
        command_rx: mpsc::Receiver<DriverCommand>,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            engine: WireGuardEngine::new(config.clone(), private_key),
            config,
            underlay,
            command_rx,
            closed,
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            fragment_identification: 0,
            next_port: PORT_MIN,
            tcp_sessions: HashMap::new(),
            udp_sessions: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self, ready: Option<oneshot::Sender<Result<()>>>) {
        let mut device =
            match yuhaiin_tun::SmoltcpTunDevice::new(self.config.mtu, DEFAULT_QUEUE_CAPACITY) {
                Ok(device) => device,
                Err(error) => {
                    if let Some(ready) = ready {
                        let _ = ready.send(Err(error_io(error)));
                    }
                    self.closed.store(true, Ordering::Release);
                    return;
                }
            };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            for address in &self.config.local_addresses {
                let _ = addresses.push(*address);
            }
        });
        if self
            .config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv4(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0));
        }
        if self
            .config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv6(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);
        }
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }
        let mut sockets = SocketSet::new(vec![]);
        let mut underlay_buffer = vec![0; MAX_PACKET_SIZE + HANDSHAKE_BUFFER_SIZE];
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            self.process_commands(&mut interface, &mut sockets).await;
            self.process_sessions(&mut sockets).await;
            interface.poll(
                Instant::from_millis(current_millis()),
                &mut device,
                &mut sockets,
            );
            self.flush_ip_packets(&device).await;
            self.flush_timers().await;
            self.ipv6_fragments.expire(StdInstant::now());
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command, &mut interface, &mut sockets).await,
                        None => break,
                    }
                }
                received = self.underlay.recv_from(&mut underlay_buffer) => {
                    if let Ok((length, source)) = received {
                        self.process_underlay(&device, source, &underlay_buffer[..length]).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    async fn process_commands(&mut self, interface: &mut Interface, sockets: &mut SocketSet<'_>) {
        while let Ok(command) = self.command_rx.try_recv() {
            self.handle_command(command, interface, sockets).await;
        }
    }

    async fn handle_command(
        &mut self,
        command: DriverCommand,
        interface: &mut Interface,
        sockets: &mut SocketSet<'_>,
    ) {
        match command {
            DriverCommand::OpenTcp { destination, reply } => {
                let local_port = self.allocate_port();
                let socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
                    TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
                );
                let handle = sockets.add(socket);
                let result = sockets.get_mut::<TcpSocket>(handle).connect(
                    interface.context(),
                    ip_endpoint(destination),
                    listen_endpoint(local_port),
                );
                if let Err(error) = result {
                    let _ = sockets.remove(handle);
                    let _ = reply.send(Err(error_protocol(error)));
                    return;
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
                let _ = reply.send(Ok(WireGuardStream {
                    command_tx,
                    output_rx,
                    pending_read: VecDeque::new(),
                    pending_write: None,
                    shutdown_sent: false,
                }));
            }
            DriverCommand::OpenUdp { reply } => {
                let local_port = self.allocate_port();
                let mut socket = UdpSocket::new(
                    UdpSocketBuffer::new(
                        vec![UdpPacketMetadata::EMPTY; 64],
                        vec![0; SOCKET_BUFFER_SIZE],
                    ),
                    UdpSocketBuffer::new(
                        vec![UdpPacketMetadata::EMPTY; 64],
                        vec![0; SOCKET_BUFFER_SIZE],
                    ),
                );
                if let Err(error) = socket.bind(listen_endpoint(local_port)) {
                    let _ = reply.send(Err(error_protocol(error)));
                    return;
                }
                let handle = sockets.add(socket);
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
                let _ = reply.send(Ok(WireGuardDatagram {
                    command_tx,
                    local_addr: core_endpoint(Network::Udp, SocketAddr::new(local_ip, local_port)),
                }));
            }
            DriverCommand::Close => self.closed.store(true, Ordering::Release),
        }
    }

    async fn process_sessions(&mut self, sockets: &mut SocketSet<'_>) {
        let tcp_handles = self.tcp_sessions.keys().copied().collect::<Vec<_>>();
        for handle in tcp_handles {
            let Some(session) = self.tcp_sessions.get_mut(&handle) else {
                continue;
            };
            while let Ok(command) = session.command_rx.try_recv() {
                match command {
                    StreamCommand::Write(data) => session.pending_writes.push_back(data),
                    StreamCommand::Close => session.close_requested = true,
                }
            }
            let socket = sockets.get_mut::<TcpSocket>(handle);
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
            // `may_recv` is true for every established socket, including an
            // empty receive buffer. Only forward an actual payload; an empty
            // async read is EOF to the inbound relay.
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
                let _ = sockets.remove(handle);
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
                        let result = sockets
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
                let _ = sockets.remove(handle);
                continue;
            }
            let socket = sockets.get_mut::<UdpSocket>(handle);
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

    async fn flush_ip_packets(&mut self, device: &SmoltcpTunDevice) {
        while let Ok(Some(packet)) = device.take_tx() {
            let fragments =
                match fragment_ip_packet(&packet, self.config.mtu, self.fragment_identification) {
                    Ok(fragments) => fragments,
                    Err(_) => continue,
                };
            self.fragment_identification = self.fragment_identification.wrapping_add(1);
            for fragment in fragments {
                let Ok((peer, packet)) = self.engine.encapsulate(&fragment) else {
                    continue;
                };
                let _ = self.send_to_peer(peer, packet).await;
            }
        }
    }

    async fn flush_timers(&mut self) {
        for (peer, packet) in self.engine.update_timers() {
            let _ = self.send_to_peer(peer, packet).await;
        }
    }

    async fn process_underlay(
        &mut self,
        device: &SmoltcpTunDevice,
        source: SocketAddr,
        packet: &[u8],
    ) {
        for peer_index in 0..self.engine.peers.len() {
            let Ok(result) = self.engine.decapsulate(peer_index, source, packet) else {
                continue;
            };
            match result {
                DecapsulatedPacket::Tunnel(payload) => {
                    if let Ok(Some(payload)) = self.ipv6_fragments.push(&payload, StdInstant::now())
                        && let Ok(payload) = normalize_ipv6_extension_headers(&payload)
                    {
                        let _ = device.enqueue_rx_reassembled(payload.into_owned());
                    }
                    let mut output = vec![0; HANDSHAKE_BUFFER_SIZE];
                    while let TunnResult::WriteToNetwork(bytes) = self.engine.peers[peer_index]
                        .tunnel
                        .decapsulate(Some(source.ip()), &[], &mut output)
                    {
                        let length = bytes.len();
                        self.engine.apply_reserved(&mut output[..length]);
                        let _ = self
                            .send_to_peer(peer_index, output[..length].to_vec())
                            .await;
                    }
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
                DecapsulatedPacket::Network(payload) => {
                    let _ = self.send_to_peer(peer_index, payload).await;
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
                DecapsulatedPacket::Done => {
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
            }
        }
    }

    async fn send_to_peer(&self, peer_index: usize, mut packet: Vec<u8>) -> Result<()> {
        let endpoint = self
            .engine
            .peers
            .get(peer_index)
            .ok_or_else(|| Error::invalid("WireGuard peer index is invalid"))?
            .endpoint;
        if self.engine.reserved.len() == 3 && packet.len() >= 4 {
            packet[1..4].copy_from_slice(&self.engine.reserved);
        }
        self.underlay
            .send_to(&packet, endpoint)
            .await
            .map_err(error_io)?;
        Ok(())
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

fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
