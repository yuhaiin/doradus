use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use yuhaiin_chain::{YuubinsyaDnsHandler, YuubinsyaServerProxy};
use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowObserver as TunFlowObserver,
    FlowObserverGuard,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector, YuubinsyaUdpServer};
use yuhaiin_core::yuubinsya::derive_salt;
use yuhaiin_core::{BoxFuture, Error, FlowContext, Result};

use super::common::{
    RoutedProxy, UDP_IDLE_TIMEOUT, UdpFlowId, UdpFlowState, UdpReply, answer_dns_packet,
    close_udp_flows, reap_expired_udp_flows, shutdown_udp_flow, udp_flow_key,
};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) fn new_server(
    spec: &InboundSpec,
    selector: Arc<RuntimeProxySelector>,
) -> Arc<YuubinsyaServerProxy> {
    let upstream: Arc<dyn AsyncProxy> = Arc::new(RoutedProxy { selector });
    let password_hashes = spec
        .auth
        .as_ref()
        .map(|auth| {
            auth.inbound_passwords()
                .into_iter()
                .map(|password| derive_salt(&password))
                .collect::<Vec<_>>()
        })
        .filter(|passwords| !passwords.is_empty())
        .unwrap_or_else(|| vec![derive_salt(spec.password.as_bytes())]);
    Arc::new(YuubinsyaServerProxy::new_with_password_hashes(
        password_hashes,
        upstream,
    ))
}

struct ChainDnsHandler(Arc<dyn crate::monitor::SocketDnsHandler>);

impl YuubinsyaDnsHandler for ChainDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.0.answer(packet)
    }
}

pub(crate) async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server = new_server(&spec, Arc::clone(&selector));
    serve_with_server(stream, peer, spec, selector, server, monitor).await
}

pub(crate) async fn serve_with_server<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    server: Arc<YuubinsyaServerProxy>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let annotate = spec.clone();
    let route = selector;
    let dns_handler = monitor
        .socket_dns_handler()
        .map(|handler| Arc::new(ChainDnsHandler(handler)) as Arc<dyn YuubinsyaDnsHandler>);
    server
        .serve_observed_with_dns(
            stream,
            peer,
            monitor,
            move |context| {
                annotate.annotate_context(context);
                // The server owns the routed upstream, so this callback is the
                // mutable point where management metadata is attached.
                route.route_context(context);
            },
            dns_handler,
        )
        .await
}

pub(crate) async fn serve_udp(
    server: YuubinsyaUdpServer,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(udp_ringbuffer_size);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut close_events = monitor.subscribe_close_requests();
    let mut idle_tick = tokio::time::interval(UDP_IDLE_TIMEOUT);
    let mut packet = vec![0u8; udp_buffer_size];
    loop {
        tokio::select! {
            received = server.recv_from(&mut packet) => {
                let (length, target, peer) = received?;
                let peer_addr = peer.addr().ok_or_else(|| Error::invalid("Yuubinsya UDP peer has no IP address"))?;
                if target.port() == Some(53) {
                    if let Some(answer) = answer_dns_packet(&monitor, &packet[..length]).await {
                        if let Ok(response) = answer {
                            server.send_to(&response, target, peer.clone()).await?;
                        }
                        continue;
                    }
                }
                let id = UdpFlowId { peer: peer_addr, target: target.clone() };
                let state = if let Some(state) = flows.get(&id) {
                    state
                } else {
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(peer.clone());
                    context.original_domain = target.host().cloned();
                    spec.annotate_context(&mut context);
                    selector.route_context(&mut context);
                    let key = udp_flow_key(peer_addr, &target);
                    let datagram = selector.select(&context).open_datagram(&context).await?;
                    let datagram: Arc<dyn AsyncDatagram> = Arc::from(datagram);
                    let observation =
                        FlowObserverGuard::open(monitor.clone(), TunFlow { key }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id_for_task = id.clone();
                    let receiver_task = tokio::spawn(async move {
                        let mut buffer = vec![0u8; udp_buffer_size];
                        loop {
                            match receiver.recv_from(&mut buffer).await {
                                Ok((length, target)) => {
                                    if reply_tx.send(UdpReply {
                                        id: id_for_task.clone(),
                                        target,
                                        payload: buffer[..length].to_vec(),
                                    }).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    flows.entry(id.clone()).or_insert(UdpFlowState {
                        datagram,
                        receiver_task,
                        key,
                        peer,
                        last_seen: std::time::Instant::now(),
                        _observation: observation,
                    })
                };
                state.datagram.send_to(&packet[..length], target).await?;
                monitor.bytes(state.key, TunFlowDirection::Upload, length);
                if let Some(state) = flows.get_mut(&id) {
                    state.last_seen = std::time::Instant::now();
                }
            }
            close_event = close_events.recv() => {
                match close_event {
                    Ok(flow) => {
                        close_udp_flows(&mut flows, flow).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Some(reply) = reply_rx.recv() => {
                let Some(state) = flows.get(&reply.id) else { continue; };
                server.send_to(&reply.payload, reply.target, state.peer.clone()).await?;
                monitor.bytes(state.key, TunFlowDirection::Download, reply.payload.len());
                if let Some(state) = flows.get_mut(&reply.id) {
                    state.last_seen = std::time::Instant::now();
                }
            }
            _ = idle_tick.tick() => {
                reap_expired_udp_flows(&mut flows).await;
            }
            else => break,
        }
    }
    for state in flows.into_values() {
        shutdown_udp_flow(state).await;
    }
    let _ = spec;
    Ok(())
}
