use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use yuhaiin_chain::YuubinsyaServerProxy;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector, YuubinsyaUdpServer};
use yuhaiin_core::tun::{TunFlow, TunFlowDirection, TunFlowObserver};
use yuhaiin_core::yuubinsya::derive_salt;
use yuhaiin_core::{Error, FlowContext, Result};

use super::common::{RoutedProxy, UdpFlowId, UdpFlowState, UdpReply, udp_flow_key};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) async fn serve(
    stream: TcpStream,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
) -> Result<()> {
    let upstream: Arc<dyn AsyncProxy> = Arc::new(RoutedProxy { selector });
    let server = YuubinsyaServerProxy::new(derive_salt(spec.password.as_bytes()), upstream);
    server.serve(stream).await
}

pub(crate) async fn serve_udp(
    server: YuubinsyaUdpServer,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(64);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut packet = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            received = server.recv_from(&mut packet) => {
                let (length, target, peer) = received?;
                let peer_addr = peer.addr().ok_or_else(|| Error::invalid("Yuubinsya UDP peer has no IP address"))?;
                let id = UdpFlowId { peer: peer_addr, target: target.clone() };
                let state = if let Some(state) = flows.get(&id) {
                    state
                } else {
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(peer.clone());
                    context.original_domain = target.host().cloned();
                    let key = udp_flow_key(peer_addr, &target);
                    let datagram = selector.select(&context).open_datagram(&context).await?;
                    let datagram: Arc<dyn AsyncDatagram> = Arc::from(datagram);
                    monitor.opened(TunFlow { key }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id_for_task = id.clone();
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 64 * 1024];
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
                        key,
                        peer,
                    })
                };
                state.datagram.send_to(&packet[..length], target).await?;
                monitor.bytes(state.key, TunFlowDirection::Upload, length);
            }
            Some(reply) = reply_rx.recv() => {
                let Some(state) = flows.get(&reply.id) else { continue; };
                server.send_to(&reply.payload, reply.target, state.peer.clone()).await?;
                monitor.bytes(state.key, TunFlowDirection::Download, reply.payload.len());
            }
            else => break,
        }
    }
    for state in flows.into_values() {
        let _ = state.datagram.close().await;
        monitor.closed(state.key);
    }
    let _ = spec;
    Ok(())
}
