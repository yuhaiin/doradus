//! Per-source UDP flow worker for routing and relay I/O.

use super::*;

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

use super::udp_types::{InboundUdpSessionEvent, UdpFlowEvent, UdpIngress, UdpSourceKey};
use crate::inbound::adapters::common::{UdpFlowId, udp_idle_timeout};
use doradus_core::Endpoint;
use doradus_core::flow::FlowDirection;
use doradus_core::proxy::AsyncDatagram;

pub(super) struct UdpFlowWorker {
    pub(super) inbound: Weak<InboundHandler>,
    pub(super) key: UdpSourceKey,
    pub(super) generation: u64,
    pub(super) rx: mpsc::Receiver<UdpIngress>,
    pub(super) cancel_rx: watch::Receiver<bool>,
    pub(super) session_cancel_rx: watch::Receiver<bool>,
    pub(super) event_tx: mpsc::Sender<UdpFlowEvent>,
    pub(super) datagram: Option<Arc<dyn AsyncDatagram>>,
    pub(super) flow: Option<TunFlowKey>,
    pub(super) reply_id: Option<UdpFlowId>,
    pub(super) reply_peer: Option<Endpoint>,
    pub(super) reply_tx: Option<mpsc::Sender<InboundUdpResponse>>,
    pub(super) session_event_tx: Option<mpsc::Sender<InboundUdpSessionEvent>>,
    pub(super) observation: Option<doradus_core::flow::FlowObserverGuard>,
    pub(super) last_seen: Instant,
}

impl UdpFlowWorker {
    pub(super) async fn run(mut self) {
        let Some(inbound) = self.inbound.upgrade() else {
            return;
        };
        let buffer_size = inbound.selector().udp_buffer_size().max(512);
        let mut close_events = inbound.monitor().subscribe_close_requests();
        drop(inbound);
        let idle_timeout = udp_idle_timeout();
        let mut buffer = vec![0u8; buffer_size];
        let mut idle = Box::pin(tokio::time::sleep(idle_timeout));

        loop {
            if *self.cancel_rx.borrow() || *self.session_cancel_rx.borrow() {
                break;
            }
            if let Some(datagram) = self.datagram.clone() {
                tokio::select! {
                    packet = self.rx.recv() => {
                        let Some(packet) = packet else { break; };
                        let mut cancel = self.cancel_rx.clone();
                        let mut session_cancel = self.session_cancel_rx.clone();
                        let mut process = Box::pin(self.process_packet(packet));
                        tokio::select! {
                            result = &mut process => if !result { break; },
                            changed = cancel.changed() => {
                                if changed.is_err() || *cancel.borrow() { break; }
                            }
                            changed = session_cancel.changed() => {
                                if changed.is_err() || *session_cancel.borrow() { break; }
                            }
                        }
                    }
                    result = datagram.recv_from(&mut buffer) => {
                        let Ok((length, target)) = result else { break; };
                        self.last_seen = Instant::now();
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        if !self.send_reply(target, buffer[..length].to_vec()) { break; }
                    }
                    _ = &mut idle => break,
                    changed = self.cancel_rx.changed() => {
                        if changed.is_err() || *self.cancel_rx.borrow() { break; }
                    }
                    changed = self.session_cancel_rx.changed() => {
                        if changed.is_err() || *self.session_cancel_rx.borrow() { break; }
                    }
                    close_event = close_events.recv() => {
                        match close_event {
                            Ok(flow) if self.flow == Some(flow) => break,
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                if self.flow.is_some_and(|flow| self.close_requested(flow)) {
                                    break;
                                }
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            } else {
                tokio::select! {
                    packet = self.rx.recv() => {
                        let Some(packet) = packet else { break; };
                        let mut cancel = self.cancel_rx.clone();
                        let mut session_cancel = self.session_cancel_rx.clone();
                        let mut process = Box::pin(self.process_packet(packet));
                        tokio::select! {
                            result = &mut process => if !result { break; },
                            changed = cancel.changed() => {
                                if changed.is_err() || *cancel.borrow() { break; }
                            }
                            changed = session_cancel.changed() => {
                                if changed.is_err() || *session_cancel.borrow() { break; }
                            }
                        }
                    }
                    _ = &mut idle => break,
                    changed = self.cancel_rx.changed() => {
                        if changed.is_err() || *self.cancel_rx.borrow() { break; }
                    }
                    changed = self.session_cancel_rx.changed() => {
                        if changed.is_err() || *self.session_cancel_rx.borrow() { break; }
                    }
                    close_event = close_events.recv() => {
                        match close_event {
                            Ok(flow) if self.flow == Some(flow) => break,
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                if self.flow.is_some_and(|flow| self.close_requested(flow)) {
                                    break;
                                }
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            self.last_seen = Instant::now();
            idle.as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
        }

        if let (Some(flow), Some(event_tx)) = (self.flow, self.session_event_tx.take()) {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                event_tx.send(InboundUdpSessionEvent::FlowClosed(flow)),
            )
            .await;
        }
        if let Some(datagram) = self.datagram.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), datagram.close()).await;
        }
        drop(self.observation.take());
    }

    fn close_requested(&self, flow: TunFlowKey) -> bool {
        self.inbound
            .upgrade()
            .is_some_and(|inbound| inbound.monitor().close_requested(flow))
    }

    async fn process_packet(&mut self, packet: UdpIngress) -> bool {
        let Some(inbound) = self.inbound.upgrade() else {
            return false;
        };
        self.session_event_tx = Some(packet.event_tx.clone());
        self.last_seen = Instant::now();
        if let Some(answer) = inbound
            .answer_datagram(&packet.target, &packet.payload)
            .await
        {
            if let Ok(payload) = answer {
                return Self::try_send_reply(
                    &packet.reply_tx,
                    InboundUdpResponse {
                        id: packet.id,
                        peer: packet.peer,
                        target: packet.target,
                        payload,
                    },
                );
            }
            return true;
        }

        if self.datagram.is_none() {
            let Some(source) = packet.peer.addr() else {
                return false;
            };
            let opened = match inbound
                .open_datagram(
                    inbound.context_with_source(packet.peer.clone(), packet.target.clone()),
                    source,
                )
                .await
            {
                Ok(opened) => opened,
                Err(_) => return false,
            };
            let flow = opened.flow;
            let observed = inbound.observe_datagram(opened);
            self.datagram = Some(observed.datagram);
            self.observation = Some(observed._observation);
            self.flow = Some(flow);
            self.reply_id = Some(packet.id.clone());
            self.reply_peer = Some(packet.peer.clone());
            self.reply_tx = Some(packet.reply_tx.clone());
            if self
                .event_tx
                .send(UdpFlowEvent::Opened {
                    key: self.key.clone(),
                    generation: self.generation,
                    flow,
                })
                .await
                .is_err()
            {
                return false;
            }
            if packet
                .event_tx
                .send(InboundUdpSessionEvent::FlowOpened(flow))
                .await
                .is_err()
            {
                return false;
            }
            // The close broadcast can win the race before the manager sees
            // Opened. Check monitor state at the point the flow is known and
            // notify the session so a stream-scoped codec can terminate even
            // if it already consumed that close broadcast.
            if inbound.monitor().close_requested(flow) {
                let _ = packet
                    .event_tx
                    .send(InboundUdpSessionEvent::FlowClosed(flow))
                    .await;
                return false;
            }
        }

        let Some(datagram) = self.datagram.as_ref() else {
            return false;
        };
        let Some(flow) = self.flow else {
            return false;
        };
        let result = tokio::select! {
            result = datagram.send_to(&packet.payload, packet.target.clone()) => result,
            _ = inbound.monitor().wait_for_close(flow) => {
                self.notify_flow_closed(&packet.event_tx, flow).await;
                return false;
            }
        };
        if let Err(error) = result {
            inbound.monitor.error(format!(
                "UDP forwarding send failed source={} target={}: {error}",
                packet.peer, packet.target
            ));
            return false;
        }
        inbound
            .monitor()
            .bytes(flow, FlowDirection::Upload, packet.payload.len());
        if inbound.monitor().close_requested(flow) {
            self.notify_flow_closed(&packet.event_tx, flow).await;
            return false;
        }
        true
    }

    async fn notify_flow_closed(
        &self,
        event_tx: &mpsc::Sender<InboundUdpSessionEvent>,
        flow: TunFlowKey,
    ) {
        let _ = event_tx
            .send(InboundUdpSessionEvent::FlowClosed(flow))
            .await;
    }

    fn send_reply(&mut self, target: Endpoint, payload: Vec<u8>) -> bool {
        let (Some(reply_tx), Some(id), Some(peer), Some(flow)) = (
            self.reply_tx.as_ref(),
            self.reply_id.as_ref(),
            self.reply_peer.as_ref(),
            self.flow,
        ) else {
            return false;
        };
        if let Some(inbound) = self.inbound.upgrade() {
            inbound
                .monitor()
                .bytes(flow, FlowDirection::Download, payload.len());
        }
        Self::try_send_reply(
            reply_tx,
            InboundUdpResponse {
                id: id.clone(),
                peer: peer.clone(),
                target,
                payload,
            },
        )
    }

    fn try_send_reply(
        reply_tx: &mpsc::Sender<InboundUdpResponse>,
        response: InboundUdpResponse,
    ) -> bool {
        match reply_tx.try_send(response) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}
