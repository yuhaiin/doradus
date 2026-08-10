//! Trojan inbound listener protocol.
//!
//! Framing/authentication belongs to `yuhaiin-protocol`; this module only
//! connects an accepted request to the live route selector and monitor, just
//! like the HTTP/SOCKS/Yuubinsya inbound adapters.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, split};
use tokio::sync::{Mutex, mpsc};
use yuhaiin_core::flow::{Flow, FlowKey as TunFlowKey, FlowObserver, FlowObserverGuard};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_protocol::trojan::{self, Command};

use super::common::{
    UDP_IDLE_TIMEOUT, answer_dns_packet, relay_counted_with_buffer, relay_counted_with_prefix,
    udp_flow_expired,
};
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
        return serve_udp(stream, peer, spec, selector, monitor).await;
    }
    if request.command != Command::Connect {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Trojan MUX inbound is not implemented",
        ));
    }
    let destination = request.destination;
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(Endpoint::ip(Network::Tcp, peer));
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
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
            monitor.record_failure("trojan", &destination.to_string(), &error.to_string());
            return Err(error);
        }
    };
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

struct UdpReply {
    id: Endpoint,
    target: Endpoint,
    payload: Vec<u8>,
}

struct UdpFlowState {
    datagram: Arc<dyn AsyncDatagram>,
    receiver_task: tokio::task::JoinHandle<()>,
    key: TunFlowKey,
    last_seen: std::time::Instant,
    _observation: FlowObserverGuard,
}

async fn shutdown_udp_flow(state: UdpFlowState) {
    let UdpFlowState {
        datagram,
        receiver_task,
        ..
    } = state;
    receiver_task.abort();
    let _ = receiver_task.await;
    let _ = datagram.close().await;
}

async fn serve_udp<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(udp_ringbuffer_size);
    let mut flows = HashMap::<Endpoint, UdpFlowState>::new();
    let mut idle_tick = tokio::time::interval(UDP_IDLE_TIMEOUT);
    let mut packet = vec![0u8; udp_buffer_size];
    loop {
        tokio::select! {
            received = trojan::read_udp_frame(&mut reader, &mut packet) => {
                let (length, target) = received?;
                if target.port() == Some(53)
                    && let Some(answer) = answer_dns_packet(&monitor, &packet[..length]).await
                {
                    if let Ok(response) = answer {
                        trojan::write_udp_frame(
                            &mut *writer.lock().await,
                            &target,
                            &response,
                        )
                        .await?;
                    }
                    continue;
                }
                let (datagram, flow) = if let Some(state) = flows.get(&target) {
                    (Arc::clone(&state.datagram), state.key)
                } else {
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(Endpoint::ip(Network::Udp, peer));
                    context.original_domain = target.host().cloned();
                    spec.annotate_context(&mut context);
                    selector.route_context(&mut context);
                    let flow = TunFlowKey {
                        network: Network::Udp,
                        source: peer,
                        destination: target.addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                    };
                    let datagram: Arc<dyn AsyncDatagram> = Arc::from(selector.select(&context).open_datagram(&context).await?);
                    let observation =
                        FlowObserverGuard::open(monitor.clone(), Flow { key: flow }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id = target.clone();
                    let receiver_task = tokio::spawn(async move {
                        let mut buffer = vec![0u8; udp_buffer_size];
                        while let Ok((length, target)) = receiver.recv_from(&mut buffer).await {
                            if reply_tx.send(UdpReply { id: id.clone(), target, payload: buffer[..length].to_vec() }).await.is_err() {
                                break;
                            }
                        }
                    });
                    flows.insert(
                        target.clone(),
                        UdpFlowState {
                            datagram: Arc::clone(&datagram),
                            receiver_task,
                            key: flow,
                            last_seen: std::time::Instant::now(),
                            _observation: observation,
                        },
                    );
                    (datagram, flow)
                };
                let target_id = target.clone();
                datagram.send_to(&packet[..length], target).await?;
                monitor.bytes(flow, yuhaiin_core::flow::FlowDirection::Upload, length);
                if let Some(state) = flows.get_mut(&target_id) {
                    state.last_seen = std::time::Instant::now();
                }
            }
            Some(reply) = reply_rx.recv() => {
                if !flows.contains_key(&reply.id) { continue; }
                trojan::write_udp_frame(&mut *writer.lock().await, &reply.target, &reply.payload).await?;
                if let Some(state) = flows.get(&reply.id) {
                    monitor.bytes(
                        state.key,
                        yuhaiin_core::flow::FlowDirection::Download,
                        reply.payload.len(),
                    );
                    if let Some(state) = flows.get_mut(&reply.id) {
                        state.last_seen = std::time::Instant::now();
                    }
                }
            }
            _ = idle_tick.tick() => {
                let now = std::time::Instant::now();
                let expired = flows
                    .iter()
                    .filter(|(_, state)| udp_flow_expired(state.last_seen, now, UDP_IDLE_TIMEOUT))
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for id in expired {
                    if let Some(state) = flows.remove(&id) {
                        shutdown_udp_flow(state).await;
                    }
                }
            }
            else => break,
        }
    }
    for (_, state) in flows {
        shutdown_udp_flow(state).await;
    }
    Ok(())
}

/// Relay a Trojan CONNECT request whose header has already been consumed.
/// This helper is kept separate so a future Mux command can reuse the same
/// flow accounting without duplicating the inbound selector path.
#[allow(dead_code)]
pub(crate) async fn relay_prefixed<S>(
    stream: S,
    outbound: yuhaiin_core::proxy::BoxAsyncStream,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    prefix: &[u8],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_counted_with_prefix(stream, outbound, flow, context, monitor, prefix)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
}
