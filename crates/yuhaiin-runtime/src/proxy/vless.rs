//! VLESS inbound adapter.
//!
//! Wire parsing and response framing live in `yuhaiin-protocol`; this module
//! only authenticates the configured UUID and routes the resulting TCP or
//! UDP-over-TCP flow through the shared runtime selector.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::sync::{Mutex, mpsc};
use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey, FlowObserver,
    FlowObserverGuard,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_protocol::vless::{self, Command};

use super::common::{answer_dns_packet, relay_counted_with_buffer, udp_flow_key};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) async fn serve<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let uuid = vless::parse_uuid(&spec.password)?;
    let request = vless::read_request(&mut stream, &uuid).await?;
    let destination = request.destination;
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(Endpoint::ip(Network::Tcp, peer));
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let process = context.process.clone();
    match request.command {
        Command::Tcp => {
            let flow = TunFlowKey {
                network: Network::Tcp,
                source: peer,
                destination: destination
                    .addr()
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            };
            let outbound = match selector.select(&context).connect(&context).await {
                Ok(stream) => stream,
                Err(error) => {
                    monitor.record_failure_with_process(
                        "vless",
                        &destination.to_string(),
                        &error.to_string(),
                        process.as_deref(),
                    );
                    return Err(error);
                }
            };
            vless::write_response(&mut stream, &[]).await?;
            relay_counted_with_buffer(
                stream,
                outbound,
                flow,
                context,
                monitor,
                selector.relay_buffer_size(),
            )
            .await
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
        }
        Command::Udp => serve_udp(stream, peer, spec, selector, monitor, destination).await,
    }
}

/// Serve a VLESS UDP request. VLESS v0 fixes the destination in the initial
/// request; each subsequent packet is only length-prefixed. The UDP path does
/// not emit a response header because Go's `PacketConn.ReadFrom` starts at the
/// first packet length, while the TCP path still uses the response header.
async fn serve_udp<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    destination: Endpoint,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(Endpoint::ip(Network::Udp, peer));
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let flow = udp_flow_key(peer, &destination);
    let datagram: Arc<dyn AsyncDatagram> =
        Arc::from(selector.select(&context).open_datagram(&context).await?);
    let _observation = FlowObserverGuard::open(monitor.clone(), TunFlow { key: flow }, context);
    let (mut reader, writer) = split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<Vec<u8>>(udp_ringbuffer_size);
    let receiver = Arc::clone(&datagram);
    let receive_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; udp_buffer_size];
        while let Ok((length, _target)) = receiver.recv_from(&mut buffer).await {
            if reply_tx.send(buffer[..length].to_vec()).await.is_err() {
                break;
            }
        }
    });
    let mut close_events = monitor.subscribe_close_requests();
    let result = async {
        let mut packet = vec![0u8; udp_buffer_size];
        loop {
            tokio::select! {
                length = reader.read_u16() => {
                    let length = usize::from(length.map_err(io_error)?);
                    if length > packet.len() {
                        return Err(Error::invalid("VLESS UDP payload is too large"));
                    }
                    reader.read_exact(&mut packet[..length]).await.map_err(io_error)?;
                    if destination.port() == Some(53)
                        && let Some(answer) = answer_dns_packet(&monitor, &packet[..length]).await
                    {
                        if let Ok(response) = answer {
                            let mut writer = writer.lock().await;
                            writer.write_u16(response.len() as u16).await.map_err(io_error)?;
                            writer.write_all(&response).await.map_err(io_error)?;
                        }
                        continue;
                    }
                    datagram.send_to(&packet[..length], destination.clone()).await?;
                    monitor.bytes(flow, TunFlowDirection::Upload, length);
                }
                Some(payload) = reply_rx.recv() => {
                    let mut writer = writer.lock().await;
                    writer.write_u16(payload.len() as u16).await.map_err(io_error)?;
                    writer.write_all(&payload).await.map_err(io_error)?;
                    monitor.bytes(flow, TunFlowDirection::Download, payload.len());
                }
                close = close_events.recv() => {
                    match close {
                        Ok(requested) if requested == flow => break,
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                else => break,
            }
        }
        Ok(())
    }
    .await;
    receive_task.abort();
    let _ = receive_task.await;
    let _ = datagram.close().await;
    result
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
