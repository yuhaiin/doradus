use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::UdpSocket;
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Network, Result};

use crate::inbound::adapters::common::io_error;
use crate::inbound::{InboundHandler, InboundUdpFlowPolicy, InboundUdpSession};

pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec();
    let central_auth = spec.auth.as_deref().filter(|auth| auth.has_basic_users());
    let requires_auth =
        central_auth.is_some() || !spec.username.is_empty() || !spec.password.is_empty();
    let request = yuhaiin_protocol::socks5_server::server_handshake(
        &mut stream,
        Network::Tcp,
        requires_auth,
        |username, password| {
            if let Some(auth) = central_auth {
                auth.authenticate_basic(username, password)
            } else {
                username == spec.username.as_bytes() && password == spec.password.as_bytes()
            }
        },
    )
    .await?;
    if matches!(
        request.command,
        yuhaiin_protocol::socks5_server::Socks5Command::UdpAssociate
    ) {
        let bind_ip = if peer.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(io_error)?;
        let address = socket.local_addr().map_err(io_error)?;
        let advertised_address = SocketAddr::new(peer.ip(), address.port());
        yuhaiin_protocol::socks5_server::write_reply_endpoint(&mut stream, 0, advertised_address)
            .await?;
        return serve_socks5_udp_loop(
            Box::new(RuntimeUdpTransport(Box::new(socket))),
            Arc::clone(&inbound),
            Some(peer.ip()),
        )
        .await;
    }
    let destination = request.destination;
    let connection = match inbound.open_stream("socks5", peer, destination).await {
        Ok(connection) => connection,
        Err(error) => {
            yuhaiin_protocol::socks5_server::write_reply(&mut stream, 5).await?;
            return Err(error);
        }
    };
    yuhaiin_protocol::socks5_server::write_reply(&mut stream, 0).await?;
    inbound
        .relay(stream, connection, peer)
        .await
        .map_err(io_error)
}

pub(crate) async fn serve_udp_socket(
    socket: Box<dyn yuhaiin_protocol::socks5_server::UdpTransport>,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    serve_socks5_udp_loop(socket, inbound, None).await
}

pub(crate) async fn serve_socks5_udp_loop(
    socket: Box<dyn yuhaiin_protocol::socks5_server::UdpTransport>,
    inbound: Arc<InboundHandler>,
    allowed_peer: Option<IpAddr>,
) -> Result<()> {
    let codec = yuhaiin_protocol::socks5_server::UdpServer::new(
        socket,
        allowed_peer,
        inbound.selector().udp_buffer_size(),
    );
    InboundUdpSession::new(codec, inbound).run().await
}

#[allow(clippy::type_complexity)]
pub(crate) trait InboundUdpSocket: Send + Unpin + 'static {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

pub(crate) struct RuntimeUdpTransport(pub(crate) Box<dyn InboundUdpSocket>);

impl yuhaiin_protocol::socks5_server::UdpTransport for RuntimeUdpTransport {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        self.0.recv_from(buffer)
    }

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        self.0.send_to(buffer, peer)
    }
}

impl InboundUdpSocket for UdpSocket {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(UdpSocket::recv_from(self, buffer))
    }

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(UdpSocket::send_to(self, buffer, peer))
    }
}

impl<S> InboundUdpFlowPolicy for yuhaiin_protocol::socks5_server::UdpServer<S> where
    S: yuhaiin_protocol::socks5_server::UdpTransport
{
}
