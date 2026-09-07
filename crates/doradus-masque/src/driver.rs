use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use doradus_core::Result;
use doradus_tun::{SmoltcpDatagram, SmoltcpStack, SmoltcpStackConfig, SmoltcpStream};

use crate::codec::encode_datagram;
use crate::config::ParsedWarpMasqueConfig;
use crate::session::{
    MAX_QUIC_PACKET_SIZE, MasqueSession, flush_quic_packets, process_h3_events, receive_quic_packet,
};

const DEFAULT_MTU: usize = 1280;
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) enum DriverCommand {
    OpenTcp {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<SmoltcpStream>>,
    },
    OpenUdp {
        reply: oneshot::Sender<Result<SmoltcpDatagram>>,
    },
    Close,
}

enum DriverState {
    Idle,
    Connected(Box<ConnectedState>),
}

struct ConnectedState {
    stack: SmoltcpStack,
    session: MasqueSession,
}

enum SessionAction {
    Continue,
    Reconnect,
    Stop,
}

pub(crate) struct Driver {
    config: ParsedWarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<String>,
    command_rx: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
}

impl Driver {
    pub(crate) fn new(
        config: ParsedWarpMasqueConfig,
        timeout: Duration,
        bind_interface: Option<String>,
        command_rx: mpsc::Receiver<DriverCommand>,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            timeout,
            bind_interface,
            command_rx,
            closed,
        }
    }

    pub(crate) async fn run(mut self) {
        let mut state = DriverState::Idle;
        let mut input_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        let mut output_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        let mut keepalive = tokio::time::interval(KEEP_ALIVE_INTERVAL);

        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }

            if matches!(state, DriverState::Idle) {
                let Some(command) = self.command_rx.recv().await else {
                    break;
                };
                match command {
                    DriverCommand::OpenTcp { destination, reply } => {
                        match self.open_tcp(destination).await {
                            Ok((next_state, stream)) => {
                                state = next_state;
                                let _ = reply.send(Ok(stream));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                    DriverCommand::OpenUdp { reply } => match self.open_udp().await {
                        Ok((next_state, datagram)) => {
                            state = next_state;
                            let _ = reply.send(Ok(datagram));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    },
                    DriverCommand::Close => break,
                }
                continue;
            }

            let DriverState::Connected(connected) = &mut state else {
                unreachable!("idle state handled above");
            };
            match self
                .drive_session(
                    &mut connected.stack,
                    &mut connected.session,
                    &mut input_buffer,
                    &mut output_buffer,
                    &mut keepalive,
                )
                .await
            {
                SessionAction::Continue => {}
                SessionAction::Reconnect => state = DriverState::Idle,
                SessionAction::Stop => break,
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    async fn open_tcp(&self, destination: SocketAddr) -> Result<(DriverState, SmoltcpStream)> {
        let session = self.open_session().await?;
        let mut stack = self.new_stack()?;
        let stream = stack.open_tcp(destination)?;
        Ok((
            DriverState::Connected(Box::new(ConnectedState { stack, session })),
            stream,
        ))
    }

    async fn open_udp(&self) -> Result<(DriverState, SmoltcpDatagram)> {
        let session = self.open_session().await?;
        let mut stack = self.new_stack()?;
        let datagram = stack.open_udp()?;
        Ok((
            DriverState::Connected(Box::new(ConnectedState { stack, session })),
            datagram,
        ))
    }

    fn new_stack(&self) -> Result<SmoltcpStack> {
        SmoltcpStack::new(SmoltcpStackConfig::new(
            self.config.local_addresses.clone(),
            DEFAULT_MTU,
        ))
    }

    async fn open_session(&self) -> Result<MasqueSession> {
        MasqueSession::connect(&self.config, self.timeout, self.bind_interface.as_deref()).await
    }

    async fn drive_session(
        &mut self,
        stack: &mut SmoltcpStack,
        session: &mut MasqueSession,
        input_buffer: &mut [u8],
        output_buffer: &mut [u8],
        keepalive: &mut tokio::time::Interval,
    ) -> SessionAction {
        let mut transport_failed = false;

        for packet in stack.poll() {
            let Ok(datagram) = encode_datagram(session.flow_id, &packet) else {
                continue;
            };
            match session.connection.dgram_send_vec(datagram.to_vec()) {
                Ok(()) | Err(quiche::Error::Done) | Err(quiche::Error::BufferTooShort) => {}
                Err(_) => {
                    transport_failed = true;
                    break;
                }
            }
        }
        if !transport_failed && flush_quic_packets(session, output_buffer).await.is_err() {
            transport_failed = true;
        }

        if !transport_failed {
            let timer = session
                .connection
                .timeout()
                .unwrap_or(Duration::from_millis(100));
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(DriverCommand::OpenTcp { destination, reply }) => {
                            let _ = reply.send(stack.open_tcp(destination));
                        }
                        Some(DriverCommand::OpenUdp { reply }) => {
                            let _ = reply.send(stack.open_udp());
                        }
                        Some(DriverCommand::Close) | None => return SessionAction::Stop,
                    }
                }
                received = session.socket.recv_from(input_buffer) => {
                    match received {
                        Ok((length, peer)) if peer == session.peer_addr => {
                            if receive_quic_packet(
                                &mut session.connection,
                                &mut input_buffer[..length],
                                session.local_addr,
                                peer,
                            ).is_err() {
                                transport_failed = true;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => transport_failed = true,
                    }
                }
                _ = tokio::time::sleep(timer) => session.connection.on_timeout(),
                _ = keepalive.tick() => {
                    if session.connection.send_ack_eliciting().is_err() {
                        transport_failed = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }

        if !transport_failed
            && (process_h3_events(session, stack).is_err()
                || flush_quic_packets(session, output_buffer).await.is_err()
                || session.connection.is_closed())
        {
            transport_failed = true;
        }
        if transport_failed {
            SessionAction::Reconnect
        } else {
            SessionAction::Continue
        }
    }
}
