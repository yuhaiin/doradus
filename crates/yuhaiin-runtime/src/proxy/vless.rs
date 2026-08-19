//! VLESS inbound adapter.
//!
//! Wire parsing and response framing live in `yuhaiin-protocol`; this module
//! only authenticates the configured UUID and routes the resulting TCP or
//! UDP-over-TCP flow through the shared runtime selector.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_protocol::vless::{self, Command};

use super::common::UdpFlowId;
use crate::inbound::{
    InboundHandler, InboundUdpCodec, InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};

pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec();
    let uuid = vless::parse_uuid(&spec.password)?;
    let request = vless::read_request(&mut stream, &uuid).await?;
    let destination = request.destination;
    match request.command {
        Command::Tcp => {
            let connection = match inbound.open_stream("vless", peer, destination).await {
                Ok(connection) => connection,
                Err(error) => {
                    return Err(error);
                }
            };
            vless::write_response(&mut stream, &[]).await?;
            inbound
                .relay(stream, connection, peer)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
        }
        Command::Udp => handle_udp(stream, peer, inbound, destination).await,
    }
}

/// Serve a VLESS UDP request. VLESS v0 fixes the destination in the initial
/// request; each subsequent packet is only length-prefixed. The UDP path does
/// not emit a response header because Go's `PacketConn.ReadFrom` starts at the
/// first packet length, while the TCP path still uses the response header.
async fn handle_udp(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
    destination: Endpoint,
) -> Result<()> {
    let (reader, writer) = split(stream);
    let codec = VlessUdpCodec {
        reader,
        writer,
        peer,
        destination,
        packet: vec![0u8; inbound.selector().udp_buffer_size().max(512)],
        flow_key: None,
    };
    InboundUdpSession::new(codec, inbound).run().await
}

struct VlessUdpCodec {
    reader: tokio::io::ReadHalf<BoxAsyncStream>,
    writer: tokio::io::WriteHalf<BoxAsyncStream>,
    peer: SocketAddr,
    destination: Endpoint,
    packet: Vec<u8>,
    flow_key: Option<TunFlowKey>,
}

impl InboundUdpCodec for VlessUdpCodec {
    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let length = usize::from(self.reader.read_u16().await.map_err(io_error)?);
            if length > self.packet.len() {
                return Err(Error::invalid("VLESS UDP payload is too large"));
            }
            self.reader
                .read_exact(&mut self.packet[..length])
                .await
                .map_err(io_error)?;
            Ok(Some(InboundUdpRequest {
                id: UdpFlowId {
                    peer: self.peer,
                    target: self.destination.clone(),
                    authentication: None,
                },
                peer: Endpoint::ip(Network::Udp, self.peer),
                target: self.destination.clone(),
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let length = u16::try_from(response.payload.len())
                .map_err(|_| Error::invalid("VLESS UDP response is too large"))?;
            self.writer.write_u16(length).await.map_err(io_error)?;
            self.writer
                .write_all(&response.payload)
                .await
                .map_err(io_error)
        })
    }

    fn note_flow(&mut self, flow: TunFlowKey) {
        self.flow_key = Some(flow);
    }

    fn owns_flow(&self, flow: TunFlowKey) -> bool {
        self.flow_key == Some(flow)
    }
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
