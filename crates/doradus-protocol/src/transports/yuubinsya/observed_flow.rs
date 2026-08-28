use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::common::{MAX_DNS_TCP_PACKET, io_error};
use doradus_core::flow::{FlowDirection, FlowKey, FlowObserver, FlowObserverGuard};
use doradus_core::{Endpoint, Error, ErrorKind, Result};
use doradus_types::InboundDnsHandler;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) struct ObservedInbound {
    pub(super) source: SocketAddr,
    pub(super) observer: Arc<dyn FlowObserver>,
    pub(super) annotate: Arc<dyn Fn(&mut doradus_core::FlowContext) + Send + Sync>,
}

pub(super) struct ObservedFlow {
    pub(super) flow: FlowKey,
    pub(super) _observation: FlowObserverGuard,
}

pub(super) enum DnsTcpDecision {
    Forward(Vec<u8>),
    Answered { upload: usize, download: usize },
}

pub(super) async fn intercept_dns_tcp<S>(
    stream: &mut S,
    handler: &dyn InboundDnsHandler,
    destination_port: Option<u16>,
) -> Result<DnsTcpDecision>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut length = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut length))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "Yuubinsya DNS over TCP query timed out"))?
        .map_err(io_error)?;
    let length = usize::from(u16::from_be_bytes(length));
    // A Yuubinsya TCP payload is not necessarily DNS over TCP.  If its first
    // two bytes describe an implausibly large DNS frame, forward the prefix
    // immediately instead of waiting for a full frame that belongs to the
    // normal application stream.
    if length > MAX_DNS_TCP_PACKET {
        return Ok(DnsTcpDecision::Forward(
            (length as u16).to_be_bytes().to_vec(),
        ));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await.map_err(io_error)?;
    let mut framed = Vec::with_capacity(length + 2);
    framed.extend_from_slice(&(length as u16).to_be_bytes());
    framed.extend_from_slice(&packet);
    if !handler.should_hijack(destination_port, &packet) {
        return Ok(DnsTcpDecision::Forward(framed));
    }
    let Some(response) = handler.answer(&packet).await else {
        return Ok(DnsTcpDecision::Forward(framed));
    };
    let response = response?;
    if response.len() > usize::from(u16::MAX) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya DNS over TCP response is too large",
        ));
    }
    stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.write_all(&response).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)?;
    Ok(DnsTcpDecision::Answered {
        upload: framed.len(),
        download: response.len() + 2,
    })
}

pub(super) async fn answer_dns_packet(
    handler: &dyn InboundDnsHandler,
    destination_port: Option<u16>,
    packet: &[u8],
) -> Result<Option<Vec<u8>>> {
    if !handler.should_hijack(destination_port, packet) {
        return Ok(None);
    }
    match handler.answer(packet).await {
        Some(response) => response.map(Some),
        None => Ok(None),
    }
}

pub(super) fn endpoint_socket_addr(endpoint: &Endpoint, source: SocketAddr) -> SocketAddr {
    endpoint.addr().unwrap_or_else(|| {
        SocketAddr::new(
            match source.ip() {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            endpoint.port().unwrap_or(0),
        )
    })
}

pub(super) async fn copy_bidirectional_observed<A, B>(
    left: &mut A,
    right: &mut B,
    observer: Arc<dyn FlowObserver>,
    flow: FlowKey,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let upload = copy_observed(
        &mut left_read,
        &mut right_write,
        Arc::clone(&observer),
        flow,
        FlowDirection::Upload,
    );
    let download = copy_observed(
        &mut right_read,
        &mut left_write,
        observer,
        flow,
        FlowDirection::Download,
    );
    tokio::try_join!(upload, download).map(|_| ())
}

async fn copy_observed<R, W>(
    reader: &mut R,
    writer: &mut W,
    observer: Arc<dyn FlowObserver>,
    flow: FlowKey,
    direction: FlowDirection,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..length]).await?;
        observer.bytes(flow, direction, length);
    }
}
