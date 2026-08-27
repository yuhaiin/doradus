use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use boringtun::noise::TunnResult;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot};
use yuhaiin_core::{Error, Result};
use yuhaiin_tun::{SmoltcpStack, SmoltcpStackConfig};

use crate::config::{ParsedConfig, error_io};
use crate::engine::{DecapsulatedPacket, WireGuardEngine};
use crate::{HANDSHAKE_BUFFER_SIZE, MAX_PACKET_SIZE};

pub(crate) enum DriverCommand {
    OpenTcp {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<yuhaiin_tun::SmoltcpStream>>,
    },
    OpenUdp {
        reply: oneshot::Sender<Result<yuhaiin_tun::SmoltcpDatagram>>,
    },
    Close,
}

pub(crate) struct Driver {
    config: ParsedConfig,
    engine: WireGuardEngine,
    underlay: TokioUdpSocket,
    command_rx: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
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
        }
    }

    pub(crate) async fn run(mut self, ready: Option<oneshot::Sender<Result<()>>>) {
        let mut stack = match SmoltcpStack::new(SmoltcpStackConfig::new(
            self.config.local_addresses.clone(),
            self.config.mtu,
        )) {
            Ok(stack) => stack,
            Err(error) => {
                if let Some(ready) = ready {
                    let _ = ready.send(Err(error_io(error)));
                }
                self.closed.store(true, Ordering::Release);
                return;
            }
        };
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }
        let mut underlay_buffer = vec![0; MAX_PACKET_SIZE + HANDSHAKE_BUFFER_SIZE];
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            self.process_commands(&mut stack);
            self.flush_ip_packets(&mut stack).await;
            self.flush_timers().await;
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command, &mut stack),
                        None => break,
                    }
                }
                received = self.underlay.recv_from(&mut underlay_buffer) => {
                    if let Ok((length, source)) = received {
                        self.process_underlay(&mut stack, source, &underlay_buffer[..length]).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    fn process_commands(&mut self, stack: &mut SmoltcpStack) {
        while let Ok(command) = self.command_rx.try_recv() {
            self.handle_command(command, stack);
        }
    }

    fn handle_command(&mut self, command: DriverCommand, stack: &mut SmoltcpStack) {
        match command {
            DriverCommand::OpenTcp { destination, reply } => {
                let _ = reply.send(stack.open_tcp(destination));
            }
            DriverCommand::OpenUdp { reply } => {
                let _ = reply.send(stack.open_udp());
            }
            DriverCommand::Close => self.closed.store(true, Ordering::Release),
        }
    }

    async fn flush_ip_packets(&mut self, stack: &mut SmoltcpStack) {
        for packet in stack.poll() {
            let Ok((peer, packet)) = self.engine.encapsulate(&packet) else {
                continue;
            };
            let _ = self.send_to_peer(peer, packet).await;
        }
    }

    async fn flush_timers(&mut self) {
        for (peer, packet) in self.engine.update_timers() {
            let _ = self.send_to_peer(peer, packet).await;
        }
    }

    async fn process_underlay(
        &mut self,
        stack: &mut SmoltcpStack,
        source: SocketAddr,
        packet: &[u8],
    ) {
        for peer_index in 0..self.engine.peers.len() {
            let Ok(result) = self.engine.decapsulate(peer_index, source, packet) else {
                continue;
            };
            match result {
                DecapsulatedPacket::Tunnel(payload) => {
                    let _ = stack.enqueue_ip_packet(&payload);
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
}
