//! Protocol-facing session loop for framed inbound UDP codecs.

use super::udp_manager::{InboundUdpManager, UdpDispatchResult};
use super::*;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

use super::udp_types::{InboundUdpSessionEvent, UdpIngress};
use crate::inbound::ConnectionMonitor;
use crate::inbound::InboundUdpFlowPolicy;
use doradus_core::Result;
use doradus_core::flow::FlowKey as TunFlowKey;
use doradus_types::{InboundUdpCodec, InboundUdpRequest, InboundUdpResponse};

// Only single-flow stream protocols tie their session to the outbound flow.
// Keep this state outside the codec so lifecycle events remain actionable
// while a codec write borrows the codec until completion.
struct UdpSessionFlow {
    close_on_end: bool,
    active: Option<TunFlowKey>,
}

impl UdpSessionFlow {
    fn owns(&self, flow: TunFlowKey) -> bool {
        self.close_on_end && self.active == Some(flow)
    }

    fn close_requested(&self, monitor: &ConnectionMonitor) -> bool {
        self.active
            .is_some_and(|flow| monitor.close_requested(flow))
    }

    fn on_event(&mut self, event: InboundUdpSessionEvent, monitor: &ConnectionMonitor) -> bool {
        if !self.close_on_end {
            return false;
        }
        match event {
            InboundUdpSessionEvent::FlowOpened(flow) => {
                self.active = Some(flow);
                monitor.close_requested(flow)
            }
            InboundUdpSessionEvent::FlowClosed(flow) => self.owns(flow),
        }
    }
}

async fn send_session_reply<C: InboundUdpCodec<Response = InboundUdpResponse>>(
    codec: &mut C,
    response: InboundUdpResponse,
    scope: &mut UdpSessionFlow,
    events: &mut mpsc::Receiver<InboundUdpSessionEvent>,
    closes: &mut tokio::sync::broadcast::Receiver<TunFlowKey>,
    monitor: &ConnectionMonitor,
) -> Result<bool> {
    let send = codec.send(response);
    tokio::pin!(send);
    loop {
        if scope.close_requested(monitor) {
            return Ok(false);
        }
        tokio::select! {
            result = &mut send => return result.map(|()| true),
            Some(event) = events.recv(), if scope.close_on_end => {
                if scope.on_event(event, monitor) {
                    return Ok(false);
                }
            }
            event = closes.recv(), if scope.close_on_end => match event {
                Ok(flow) if scope.owns(flow) => return Ok(false),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(false),
            },
        }
    }
}

pub(crate) struct InboundUdpSession<C> {
    pub(super) codec: C,
    pub(super) inbound: Arc<InboundHandler>,
    pub(super) manager: Arc<InboundUdpManager>,
    pub(super) session_id: u64,
    pub(super) reply_rx: mpsc::Receiver<InboundUdpResponse>,
    pub(super) event_rx: mpsc::Receiver<InboundUdpSessionEvent>,
    pub(super) reply_tx: mpsc::Sender<InboundUdpResponse>,
    pub(super) event_tx: mpsc::Sender<InboundUdpSessionEvent>,
    pub(super) session_cancel_tx: watch::Sender<bool>,
}

impl<C> Drop for InboundUdpSession<C> {
    fn drop(&mut self) {
        // The session can be aborted while waiting on codec I/O. Cancelling
        // the token synchronously also covers ingress packets already queued
        // in the manager; those workers will observe it before opening a new
        // outbound datagram.
        let _ = self.session_cancel_tx.send(true);
    }
}

impl<C> InboundUdpSession<C>
where
    C: InboundUdpCodec<Request = InboundUdpRequest, Response = InboundUdpResponse>
        + InboundUdpFlowPolicy,
{
    pub(crate) fn new(codec: C, inbound: Arc<InboundHandler>) -> Self {
        let capacity = inbound.selector().udp_ringbuffer_size().max(1);
        let channels = inbound.udp().open_session(capacity);
        Self {
            codec,
            inbound: Arc::clone(&inbound),
            manager: Arc::clone(inbound.udp()),
            session_id: channels.session_id,
            reply_rx: channels.reply_rx,
            event_rx: channels.event_rx,
            reply_tx: channels.reply_tx,
            event_tx: channels.event_tx,
            session_cancel_tx: channels.session_cancel_tx,
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        let mut close_events = self.inbound.monitor().subscribe_close_requests();
        let mut scope = UdpSessionFlow {
            close_on_end: self.codec.close_on_flow_end(),
            active: None,
        };
        let mut input_closed = false;
        let mut pending_packets = 0usize;
        let mut drain = Box::pin(tokio::time::sleep(Duration::from_secs(5)));
        let result = async {
            loop {
                tokio::select! {
                    received = self.codec.recv(), if !input_closed => {
                        let Some(request) = received? else {
                            input_closed = true;
                            if pending_packets == 0 { break; }
                            drain.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(5));
                            continue;
                        };
                        match self.manager.dispatch(UdpIngress {
                            session_id: self.session_id,
                            session_cancel_rx: self.session_cancel_tx.subscribe(),
                            id: request.id,
                            peer: request.peer,
                            target: request.target,
                            payload: request.payload,
                            reply_tx: self.reply_tx.clone(),
                            event_tx: self.event_tx.clone(),
                        }) {
                            UdpDispatchResult::Accepted => pending_packets += 1,
                            UdpDispatchResult::Dropped => {}
                            UdpDispatchResult::Closed => break,
                        }
                    }
                    Some(response) = self.reply_rx.recv() => {
                        pending_packets = pending_packets.saturating_sub(1);
                        if !send_session_reply(
                            &mut self.codec, response, &mut scope, &mut self.event_rx,
                            &mut close_events, self.inbound.monitor(),
                        ).await? {
                            break;
                        }
                        if input_closed && pending_packets == 0 { break; }
                    }
                    Some(event) = self.event_rx.recv() => {
                        if scope.on_event(event, self.inbound.monitor()) {
                            if let Some(flow) = scope.active {
                                self.manager.close_flow(self.session_id, flow).await;
                            }
                            break;
                        }
                    }
                    close_event = close_events.recv() => {
                        match close_event {
                            Ok(flow) => {
                                // Each session receives the global broadcast.
                                // Only single-flow stream sessions end with
                                // this flow. Socket sessions stay available;
                                // their worker handles the individual close.
                                let stop = scope.owns(flow);
                                if stop {
                                    self.manager.close_flow(self.session_id, flow).await;
                                }
                                if stop {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                if scope.close_requested(self.inbound.monitor()) {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = &mut drain, if input_closed => break,
                }
            }
            Ok(())
        }
        .await;
        let _ = self.session_cancel_tx.send(true);
        self.manager.close_session(self.session_id).await;
        result
    }
}
