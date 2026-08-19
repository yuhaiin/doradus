//! Trojan inbound listener protocol.
//!
//! Framing/authentication belongs to `yuhaiin-protocol`; this module only
//! connects an accepted request to the live route selector and monitor, just
//! like the HTTP/SOCKS/Yuubinsya inbound adapters.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::split;
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_protocol::trojan::{self, Command};

use crate::inbound::{
    InboundHandler, InboundUdpCodec, InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};

pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec();
    let hashes = spec
        .auth
        .as_ref()
        .map(|auth| {
            auth.inbound_passwords()
                .into_iter()
                .map(|password| trojan::password_hash(&password))
                .collect::<Vec<_>>()
        })
        .filter(|hashes| !hashes.is_empty())
        .unwrap_or_else(|| vec![trojan::password_hash(spec.password.as_bytes())]);
    let request = trojan::read_request_any(&mut stream, &hashes).await?;
    if request.command == Command::Associate {
        return handle_udp(stream, peer, Arc::clone(&inbound)).await;
    }
    if request.command != Command::Connect {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Trojan MUX inbound is not implemented",
        ));
    }
    let destination = request.destination;
    inbound
        .serve_stream(stream, peer, "trojan", destination)
        .await
}

async fn handle_udp(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let (reader, writer) = split(stream);
    let codec = TrojanUdpCodec {
        reader,
        writer,
        peer,
        packet: vec![0u8; inbound.selector().udp_buffer_size().max(512)],
    };
    InboundUdpSession::new(codec, inbound).run().await
}

struct TrojanUdpCodec {
    reader: tokio::io::ReadHalf<BoxAsyncStream>,
    writer: tokio::io::WriteHalf<BoxAsyncStream>,
    peer: SocketAddr,
    packet: Vec<u8>,
}

impl InboundUdpCodec for TrojanUdpCodec {
    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let (length, target) = trojan::read_udp_frame(&mut self.reader, &mut self.packet)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
            Ok(Some(InboundUdpRequest {
                id: crate::proxy::common::UdpFlowId {
                    peer: self.peer,
                    target: target.clone(),
                    authentication: None,
                },
                peer: Endpoint::ip(Network::Udp, self.peer),
                target,
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            trojan::write_udp_frame(&mut self.writer, &response.target, &response.payload)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
        })
    }
}
