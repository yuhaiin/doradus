use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use quiche::h3::NameValue;
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::network::bind_tokio_udp_socket_for_target;
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Error, ErrorKind, FlowContext, Network, ResolveStrategy, Result};
use doradus_tun::{SmoltcpStack, SmoltcpStackConfig};

use crate::codec::{decode_datagram, encode_datagram};
use crate::config::{ParsedWarpMasqueConfig, WarpMasqueConfig};
use crate::tls::{TlsMaterial, prepare_tls_material, verify_endpoint_key};

const DEFAULT_MTU: usize = 1280;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const SERVER_NAME: &str = "consumer-masque.cloudflareclient.com";
const CONNECT_AUTHORITY: &str = "cloudflareaccess.com";
const MAX_QUIC_PACKET_SIZE: usize = 65_535;
const MAX_HTTP3_BODY_CHUNK: usize = 16 * 1024;

enum DriverCommand {
    OpenTcp {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<doradus_tun::SmoltcpStream>>,
    },
    OpenUdp {
        reply: oneshot::Sender<Result<doradus_tun::SmoltcpDatagram>>,
    },
    Close,
}

struct MasqueSession {
    socket: UdpSocket,
    connection: quiche::Connection,
    h3: quiche::h3::Connection,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    flow_id: u64,
    _tls_material: TlsMaterial,
}

pub struct WarpMasqueProxy {
    command_tx: mpsc::Sender<DriverCommand>,
    closed: Arc<AtomicBool>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
    timeout: Duration,
}

pub async fn build_proxy(config: WarpMasqueConfig, timeout: Duration) -> Result<WarpMasqueProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, None, None).await
}

pub async fn build_proxy_with_interface(
    config: WarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
) -> Result<WarpMasqueProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, bind_interface, None).await
}

pub async fn build_proxy_with_interface_and_resolver(
    config: WarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
) -> Result<WarpMasqueProxy> {
    let parsed = config.parse()?;
    WarpMasqueProxy::start(parsed, timeout, bind_interface, resolver).await
}

impl WarpMasqueProxy {
    async fn start(
        config: ParsedWarpMasqueConfig,
        timeout: Duration,
        bind_interface: Option<&str>,
        resolver: Option<Arc<dyn AsyncIpResolver>>,
    ) -> Result<Self> {
        let (command_tx, command_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = Arc::clone(&closed);
        let bind_interface = bind_interface.map(str::to_owned);
        tokio::spawn(async move {
            Driver::new(config, timeout, bind_interface, command_rx, task_closed)
                .run(Some(ready_tx))
                .await;
        });
        ready_rx.await.map_err(|_| {
            Error::new(
                ErrorKind::Closed,
                "WARP MASQUE driver exited before it became ready",
            )
        })??;
        Ok(Self {
            command_tx,
            closed,
            resolver,
            timeout,
        })
    }
}

impl AsyncProxy for WarpMasqueProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            if context.network != Network::Tcp {
                return Err(error_unsupported(
                    "WARP MASQUE TCP proxy received a non-TCP flow",
                ));
            }
            let destination =
                resolve_flow_destination(context, self.resolver.as_deref(), self.timeout).await?;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenTcp {
                    destination,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WARP MASQUE driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WARP MASQUE driver dropped TCP request")
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
                    "WARP MASQUE UDP proxy received a non-UDP flow",
                ));
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenUdp { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WARP MASQUE driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WARP MASQUE driver dropped UDP request")
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

struct Driver {
    config: ParsedWarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<String>,
    command_rx: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
}

impl Driver {
    fn new(
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

    async fn run(mut self, ready: Option<oneshot::Sender<Result<()>>>) {
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }
        let mut stack = None;
        let mut session = None;
        let mut input_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        let mut output_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        let mut keepalive = tokio::time::interval(KEEP_ALIVE_INTERVAL);

        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            if stack.is_none() {
                let Some(command) = self.command_rx.recv().await else {
                    break;
                };
                match command {
                    DriverCommand::OpenTcp { destination, reply } => {
                        let result = self.open_session().await.and_then(|new_session| {
                            let mut new_stack = SmoltcpStack::new(SmoltcpStackConfig::new(
                                self.config.local_addresses.clone(),
                                DEFAULT_MTU,
                            ))?;
                            let stream = new_stack.open_tcp(destination)?;
                            session = Some(new_session);
                            stack = Some(new_stack);
                            Ok(stream)
                        });
                        let _ = reply.send(result);
                    }
                    DriverCommand::OpenUdp { reply } => {
                        let result = self.open_session().await.and_then(|new_session| {
                            let mut new_stack = SmoltcpStack::new(SmoltcpStackConfig::new(
                                self.config.local_addresses.clone(),
                                DEFAULT_MTU,
                            ))?;
                            let datagram = new_stack.open_udp()?;
                            session = Some(new_session);
                            stack = Some(new_stack);
                            Ok(datagram)
                        });
                        let _ = reply.send(result);
                    }
                    DriverCommand::Close => break,
                }
                continue;
            }

            let mut transport_failed = false;
            let stack_ref = stack.as_mut().expect("stack exists");
            let session_ref = session.as_mut().expect("session exists");

            for packet in stack_ref.poll() {
                let Ok(datagram) = encode_datagram(session_ref.flow_id, &packet) else {
                    continue;
                };
                match session_ref.connection.dgram_send_vec(datagram.to_vec()) {
                    Ok(()) | Err(quiche::Error::Done) | Err(quiche::Error::BufferTooShort) => {}
                    Err(error) => {
                        transport_failed = true;
                        let _ = error;
                        break;
                    }
                }
            }
            if !transport_failed
                && flush_quic_packets(session_ref, &mut output_buffer)
                    .await
                    .is_err()
            {
                transport_failed = true;
            }

            if !transport_failed {
                let timer = session_ref
                    .connection
                    .timeout()
                    .unwrap_or(Duration::from_millis(100));
                tokio::select! {
                    command = self.command_rx.recv() => {
                        match command {
                            Some(DriverCommand::OpenTcp { destination, reply }) => {
                                let _ = reply.send(stack_ref.open_tcp(destination));
                            }
                            Some(DriverCommand::OpenUdp { reply }) => {
                                let _ = reply.send(stack_ref.open_udp());
                            }
                            Some(DriverCommand::Close) | None => break,
                        }
                    }
                    received = session_ref.socket.recv_from(&mut input_buffer) => {
                        match received {
                            Ok((length, peer)) if peer == session_ref.peer_addr => {
                                if receive_quic_packet(
                                    &mut session_ref.connection,
                                    &mut input_buffer[..length],
                                    session_ref.local_addr,
                                    peer,
                                ).is_err() {
                                    transport_failed = true;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => transport_failed = true,
                        }
                    }
                    _ = tokio::time::sleep(timer) => session_ref.connection.on_timeout(),
                    _ = keepalive.tick() => {
                        if session_ref.connection.send_ack_eliciting().is_err() {
                            transport_failed = true;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }

            if !transport_failed
                && (process_h3_events(session_ref, stack_ref).is_err()
                    || flush_quic_packets(session_ref, &mut output_buffer)
                        .await
                        .is_err()
                    || session_ref.connection.is_closed())
            {
                transport_failed = true;
            }
            if transport_failed {
                stack = None;
                session = None;
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    async fn open_session(&self) -> Result<MasqueSession> {
        let mut errors = Vec::new();
        for endpoint in [self.config.endpoint_v4, self.config.endpoint_v6]
            .into_iter()
            .flatten()
        {
            match self.open_session_at(endpoint).await {
                Ok(session) => return Ok(session),
                Err(error) => errors.push(format!("{endpoint}: {error}")),
            }
        }
        Err(Error::new(
            ErrorKind::Io,
            format!("WARP MASQUE endpoints failed: {}", errors.join("; ")),
        ))
    }

    async fn open_session_at(&self, endpoint: SocketAddr) -> Result<MasqueSession> {
        let tls_material =
            prepare_tls_material(&self.config.private_key, &self.config.endpoint_pub_key)?;
        let mut quic_config = build_quiche_config(&tls_material)?;
        let socket = make_socket(endpoint, self.bind_interface.as_deref()).await?;
        let local_addr = socket.local_addr().map_err(error_io)?;
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        OsRng.fill_bytes(&mut scid);
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut connection = quiche::connect(
            Some(SERVER_NAME),
            &scid,
            local_addr,
            endpoint,
            &mut quic_config,
        )
        .map_err(error_quic)?;
        let mut input_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        let mut output_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
        establish_connection(
            &socket,
            &mut connection,
            local_addr,
            endpoint,
            self.timeout,
            &mut input_buffer,
            &mut output_buffer,
        )
        .await?;

        let peer_certificate = connection
            .peer_cert()
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "WARP endpoint sent no certificate"))?;
        if !verify_endpoint_key(peer_certificate, &tls_material.endpoint_pub_key_spki_der) {
            return Err(Error::new(
                ErrorKind::Protocol,
                "WARP endpoint certificate public key does not match the configured pin",
            ));
        }

        let mut h3_config = quiche::h3::Config::new().map_err(error_h3)?;
        h3_config.enable_extended_connect(true);
        let mut h3 = quiche::h3::Connection::with_transport(&mut connection, &h3_config)
            .map_err(error_h3)?;
        let request = [
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", CONNECT_AUTHORITY.as_bytes()),
            quiche::h3::Header::new(b":path", b"/"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"user-agent", b""),
        ];
        let flow_id = h3
            .send_request(&mut connection, &request, false)
            .map_err(error_h3)?;
        flush_quic_packets_raw(&mut connection, &socket, &mut output_buffer).await?;
        wait_for_connect_response(
            &socket,
            &mut connection,
            &mut h3,
            local_addr,
            endpoint,
            flow_id,
            self.timeout,
        )
        .await?;

        Ok(MasqueSession {
            socket,
            connection,
            h3,
            peer_addr: endpoint,
            local_addr,
            flow_id,
            _tls_material: tls_material,
        })
    }
}

async fn establish_connection(
    socket: &UdpSocket,
    connection: &mut quiche::Connection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    timeout: Duration,
    input_buffer: &mut [u8],
    output_buffer: &mut [u8],
) -> Result<()> {
    tokio::time::timeout(timeout, async {
        loop {
            flush_quic_packets_raw(connection, socket, output_buffer).await?;
            if connection.is_established() {
                return Ok(());
            }
            if connection.is_closed() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "WARP QUIC connection closed during handshake",
                ));
            }
            let timer = connection.timeout().unwrap_or(Duration::from_millis(100));
            tokio::select! {
                received = socket.recv_from(input_buffer) => {
                    let (length, peer) = received.map_err(error_io)?;
                    if peer == peer_addr {
                        receive_quic_packet(
                            connection,
                            &mut input_buffer[..length],
                            local_addr,
                            peer,
                        )?;
                    }
                }
                _ = tokio::time::sleep(timer) => connection.on_timeout(),
            }
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Timeout, "WARP MASQUE QUIC handshake timed out"))??;
    Ok(())
}

async fn wait_for_connect_response(
    socket: &UdpSocket,
    connection: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    flow_id: u64,
    timeout: Duration,
) -> Result<()> {
    let mut input_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
    let mut output_buffer = vec![0; MAX_QUIC_PACKET_SIZE];
    tokio::time::timeout(timeout, async {
        loop {
            loop {
                match h3.poll(connection) {
                    Ok((stream_id, event)) if stream_id == flow_id => match event {
                        quiche::h3::Event::Headers { list, .. } => {
                            let status = list
                                .iter()
                                .find(|header| header.name() == b":status")
                                .and_then(|header| std::str::from_utf8(header.value()).ok())
                                .and_then(|value| value.parse::<u16>().ok())
                                .ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::Protocol,
                                        "WARP MASQUE response has no valid status",
                                    )
                                })?;
                            if (200..300).contains(&status) {
                                return Ok(());
                            }
                            return Err(Error::new(
                                ErrorKind::Protocol,
                                format!("WARP MASQUE CONNECT-IP returned {status}"),
                            ));
                        }
                        quiche::h3::Event::Finished | quiche::h3::Event::Reset(_) => {
                            return Err(Error::new(
                                ErrorKind::Protocol,
                                "WARP MASQUE CONNECT-IP stream closed before response",
                            ));
                        }
                        _ => {}
                    },
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(error) => return Err(error_h3(error)),
                }
            }
            if connection.is_closed() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "WARP QUIC connection closed before CONNECT-IP response",
                ));
            }
            flush_quic_packets_raw(connection, socket, &mut output_buffer).await?;
            let timer = connection.timeout().unwrap_or(Duration::from_millis(100));
            tokio::select! {
                received = socket.recv_from(&mut input_buffer) => {
                    let (length, peer) = received.map_err(error_io)?;
                    if peer == peer_addr {
                        receive_quic_packet(
                            connection,
                            &mut input_buffer[..length],
                            local_addr,
                            peer,
                        )?;
                    }
                }
                _ = tokio::time::sleep(timer) => connection.on_timeout(),
            }
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::Timeout,
            "WARP MASQUE CONNECT-IP response timed out",
        )
    })??;
    Ok(())
}

async fn flush_quic_packets(session: &mut MasqueSession, output_buffer: &mut [u8]) -> Result<()> {
    flush_quic_packets_raw(&mut session.connection, &session.socket, output_buffer).await
}

async fn flush_quic_packets_raw(
    connection: &mut quiche::Connection,
    socket: &UdpSocket,
    output_buffer: &mut [u8],
) -> Result<()> {
    loop {
        match connection.send(output_buffer) {
            Ok((length, send_info)) => {
                socket
                    .send_to(&output_buffer[..length], send_info.to)
                    .await
                    .map_err(error_io)?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(error_quic(error)),
        }
    }
}

fn receive_quic_packet(
    connection: &mut quiche::Connection,
    packet: &mut [u8],
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<()> {
    match connection.recv(
        packet,
        quiche::RecvInfo {
            to: local_addr,
            from: peer_addr,
        },
    ) {
        Ok(_) | Err(quiche::Error::Done) | Err(quiche::Error::InvalidPacket) => Ok(()),
        Err(error) => Err(error_quic(error)),
    }
}

fn process_h3_events(session: &mut MasqueSession, stack: &mut SmoltcpStack) -> Result<()> {
    loop {
        match session.h3.poll(&mut session.connection) {
            Ok((stream_id, quiche::h3::Event::Data)) => {
                let mut body = [0; MAX_HTTP3_BODY_CHUNK];
                while session
                    .h3
                    .recv_body(&mut session.connection, stream_id, &mut body)
                    .is_ok()
                {}
            }
            Ok((stream_id, quiche::h3::Event::Finished | quiche::h3::Event::Reset(_)))
                if stream_id == session.flow_id =>
            {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "WARP MASQUE CONNECT-IP stream closed",
                ));
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(error) => return Err(error_h3(error)),
        }
    }
    while let Ok(datagram) = session.connection.dgram_recv_vec() {
        if let Ok((flow_id, payload)) = decode_datagram(&datagram)
            && flow_id == session.flow_id
        {
            let _ = stack.enqueue_ip_packet(payload)?;
        }
    }
    Ok(())
}

fn build_quiche_config(material: &TlsMaterial) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(error_quic)?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(error_quic)?;
    let cert_path = material
        .cert_pem_file
        .path()
        .to_str()
        .ok_or_else(|| Error::invalid("WARP client certificate path is not UTF-8"))?;
    let key_path = material
        .key_pem_file
        .path()
        .to_str()
        .ok_or_else(|| Error::invalid("WARP client key path is not UTF-8"))?;
    config
        .load_cert_chain_from_pem_file(cert_path)
        .map_err(error_quic)?;
    config
        .load_priv_key_from_pem_file(key_path)
        .map_err(error_quic)?;
    config.set_max_idle_timeout(DEFAULT_IDLE_TIMEOUT.as_millis() as u64);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 1000, 1000);
    Ok(config)
}

async fn make_socket(remote: SocketAddr, bind_interface: Option<&str>) -> Result<UdpSocket> {
    let bind_address = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("static WARP MASQUE bind address");
    bind_tokio_udp_socket_for_target(bind_address, remote, bind_interface, "WARP MASQUE").await
}

async fn resolve_flow_destination(
    context: &FlowContext,
    resolver: Option<&dyn AsyncIpResolver>,
    timeout: Duration,
) -> Result<SocketAddr> {
    let endpoint = context
        .resolved_destination
        .as_ref()
        .unwrap_or(&context.destination);
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WARP MASQUE destination has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WARP MASQUE destination has no port"))?;
    if let Some(resolver) = resolver {
        let addresses =
            tokio::time::timeout(timeout, resolver.resolve(host, ResolveStrategy::Default))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        "WARP MASQUE destination resolution timed out",
                    )
                })??;
        let address = addresses
            .v4
            .first()
            .copied()
            .map(IpAddr::V4)
            .or_else(|| addresses.v6.first().copied().map(IpAddr::V6))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Io,
                    "WARP MASQUE destination resolved to no address",
                )
            })?;
        return Ok(SocketAddr::new(address, port));
    }
    tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::Timeout,
                "WARP MASQUE destination resolution timed out",
            )
        })?
        .map_err(error_io)?
        .next()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Io,
                "WARP MASQUE destination resolved to no address",
            )
        })
}

fn error_quic(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("WARP QUIC: {error}"))
}

fn error_h3(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("WARP HTTP/3: {error}"))
}

fn error_io(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn error_unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_warp_defaults() {
        assert_eq!(SERVER_NAME, "consumer-masque.cloudflareclient.com");
        assert_eq!(CONNECT_AUTHORITY, "cloudflareaccess.com");
    }
}
