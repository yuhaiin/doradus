use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use doradus_core::{Error, ErrorKind, FlowContext, Result};
use doradus_tun::{SmoltcpDatagram, SmoltcpStack, SmoltcpStackConfig, SmoltcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::tun::TunEvent;

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

pub(crate) struct Driver {
    stack: SmoltcpStack,
    tun_io: openvpn_connect::ExternalTunIo,
    tun_events: mpsc::Receiver<TunEvent>,
    commands: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
}

impl Driver {
    pub(crate) async fn start(
        mut tun_events: mpsc::Receiver<TunEvent>,
        commands: mpsc::Receiver<DriverCommand>,
        closed: Arc<AtomicBool>,
    ) -> Result<Self> {
        loop {
            match tun_events.recv().await {
                Some(TunEvent::Started { io, addresses, mtu }) => {
                    return Ok(Self {
                        stack: SmoltcpStack::new(SmoltcpStackConfig::new(addresses, mtu))?,
                        tun_io: io,
                        tun_events,
                        commands,
                        closed,
                    });
                }
                Some(TunEvent::Packet(_)) => {}
                Some(TunEvent::Stopped) | None => {
                    return Err(Error::new(
                        ErrorKind::Closed,
                        "OpenVPN tunnel stopped before becoming ready",
                    ));
                }
            }
        }
    }

    pub(crate) async fn run(mut self) {
        let mut tick = tokio::time::interval(Duration::from_millis(2));
        while !self.closed.load(Ordering::Acquire) {
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(DriverCommand::OpenTcp { destination, reply }) => {
                        let _ = reply.send(self.stack.open_tcp(destination));
                    }
                    Some(DriverCommand::OpenUdp { reply }) => {
                        let _ = reply.send(self.stack.open_udp());
                    }
                    Some(DriverCommand::Close) | None => break,
                },
                event = self.tun_events.recv() => match event {
                    Some(TunEvent::Packet(packet)) => {
                        let _ = self.stack.enqueue_ip_packet(&packet);
                    }
                    Some(TunEvent::Started { io, .. }) => {
                        self.tun_io = io;
                    }
                    Some(TunEvent::Stopped) | None => break,
                },
                _ = tick.tick() => {}
            }
            self.flush_stack();
        }
        self.closed.store(true, Ordering::Release);
    }

    fn flush_stack(&mut self) {
        for packet in self.stack.poll() {
            if self.tun_io.receive(&packet).is_err() {
                break;
            }
        }
    }
}

pub(crate) async fn resolve_flow_destination(context: &FlowContext) -> Result<SocketAddr> {
    if let Some(address) = context
        .resolved_destination
        .as_ref()
        .and_then(|addresses| addresses.first().copied())
    {
        return Ok(address);
    }
    if let Some(address) = context.destination.addr() {
        return Ok(address);
    }
    let host = context
        .destination
        .host()
        .ok_or_else(|| Error::invalid("OpenVPN destination has no host"))?;
    let port = context
        .destination
        .port()
        .ok_or_else(|| Error::invalid("OpenVPN destination has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "OpenVPN destination resolved to no address"))
}
