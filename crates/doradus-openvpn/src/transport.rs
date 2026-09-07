use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use doradus_core::network::bind_tokio_udp_socket_for_target;
use doradus_core::{Error, ErrorKind, Result};
use doradus_types::{AsyncIpResolver, DomainName, ResolveStrategy};
use openvpn_connect::{
    ExternalTransport, ExternalTransportConfig, ExternalTransportEndpoint, ExternalTransportIo,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error_openvpn;

const QUEUE_CAPACITY: usize = 256;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct TransportState {
    config: Option<ExternalTransportConfig>,
    endpoint: ExternalTransportEndpoint,
    sender: Option<mpsc::Sender<Vec<u8>>>,
    task: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub(crate) struct TokioUdpTransport {
    runtime: tokio::runtime::Handle,
    bind_interface: Option<String>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
    state: Arc<Mutex<TransportState>>,
}

impl TokioUdpTransport {
    pub(crate) fn new(
        bind_interface: Option<String>,
        resolver: Option<Arc<dyn AsyncIpResolver>>,
    ) -> Self {
        Self {
            runtime: tokio::runtime::Handle::current(),
            bind_interface,
            resolver,
            state: Arc::new(Mutex::new(TransportState::default())),
        }
    }

    pub(crate) async fn shutdown(&self) {
        let task = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.sender.take();
            state.task.take()
        };
        if let Some(mut task) = task
            && tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }

    pub(crate) fn abort(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sender.take();
        if let Some(task) = state.task.take() {
            task.abort();
        }
    }
}

impl ExternalTransport for TokioUdpTransport {
    fn configure(&self, config: &ExternalTransportConfig) -> bool {
        if !config.protocol.to_ascii_lowercase().starts_with("udp") {
            return false;
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .config = Some(config.clone());
        true
    }

    fn start(&self, io: ExternalTransportIo) {
        let config = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .config
            .clone();
        let Some(config) = config else { return };

        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.sender = Some(sender);
            if let Some(previous) = state.task.take() {
                previous.abort();
            }
        }
        let state = Arc::clone(&self.state);
        let bind_interface = self.bind_interface.clone();
        let resolver = self.resolver.clone();
        let task = self.runtime.spawn(async move {
            if let Err(error) = run_udp_transport(
                config,
                io.clone(),
                state,
                receiver,
                bind_interface.as_deref(),
                resolver.as_deref(),
            )
            .await
            {
                let _ = io.error(&error.to_string());
            }
        });
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .task = Some(task);
    }

    fn stop(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sender = None;
    }

    fn send(&self, packet: &[u8]) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sender
            .as_ref()
            .is_some_and(|sender| sender.try_send(packet.to_vec()).is_ok())
    }

    fn has_send_queue(&self) -> bool {
        true
    }

    fn send_queue_empty(&self) -> bool {
        self.send_queue_size() == 0
    }

    fn send_queue_size(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sender
            .as_ref()
            .map_or(0, |sender| sender.max_capacity() - sender.capacity())
    }

    fn endpoint(&self) -> ExternalTransportEndpoint {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .endpoint
            .clone()
    }
}

async fn run_udp_transport(
    config: ExternalTransportConfig,
    io: ExternalTransportIo,
    state: Arc<Mutex<TransportState>>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    bind_interface: Option<&str>,
    resolver: Option<&dyn AsyncIpResolver>,
) -> Result<()> {
    io.pre_resolve().map_err(error_openvpn)?;
    let port = config
        .port
        .parse::<u16>()
        .map_err(|error| Error::invalid(format!("invalid OpenVPN remote port: {error}")))?;
    let remote = resolve_remote(&config.host, port, resolver).await?;
    let bind = if remote.is_ipv6() {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    };
    let socket = bind_tokio_udp_socket_for_target(bind, remote, bind_interface, "OpenVPN").await?;
    socket
        .connect(remote)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("OpenVPN UDP connect: {error}")))?;
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .endpoint = ExternalTransportEndpoint {
        host: config.host.clone(),
        port: remote.port().to_string(),
        protocol: config.protocol.clone(),
        ip_address: remote.ip().to_string(),
    };
    io.connecting().map_err(error_openvpn)?;

    let mut buffer = vec![0; 65_536];
    loop {
        tokio::select! {
            packet = outbound.recv() => match packet {
                Some(packet) => {
                    socket.send(&packet).await.map_err(|error| {
                        Error::new(ErrorKind::Io, format!("OpenVPN UDP send: {error}"))
                    })?;
                    io.needs_send().map_err(error_openvpn)?;
                }
                None => break,
            },
            received = socket.recv(&mut buffer) => {
                let length = received.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("OpenVPN UDP receive: {error}"))
                })?;
                io.receive(&buffer[..length]).map_err(error_openvpn)?;
            }
        }
    }
    Ok(())
}

async fn resolve_remote(
    host: &str,
    port: u16,
    resolver: Option<&dyn AsyncIpResolver>,
) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(resolver) = resolver {
        let domain = DomainName::new(host)?;
        let addresses = resolver.resolve(&domain, ResolveStrategy::Default).await?;
        if let Some(ip) = addresses.iter().next() {
            return Ok(SocketAddr::new(ip, port));
        }
        return Err(Error::new(
            ErrorKind::Io,
            format!("OpenVPN remote {host} resolved to no addresses"),
        ));
    }
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("OpenVPN DNS lookup: {error}")))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "OpenVPN remote resolved to no addresses"))
}
