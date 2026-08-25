use super::*;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use yuhaiin_core::flow::FlowDirection;
use yuhaiin_core::proxy::AsyncDatagram;
use yuhaiin_core::{Endpoint, Result};

use crate::inbound::adapters::common::{UdpFlowId, udp_idle_timeout};

pub(crate) use yuhaiin_types::{InboundUdpCodec, InboundUdpRequest, InboundUdpResponse};

/// A source-owned UDP flow. The destination is deliberately absent from the
/// key so one client can use one full-cone datagram for multiple targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSourceKey {
    inbound_id: String,
    session_id: u64,
    source: SocketAddr,
    authentication: Option<[u8; 32]>,
}

struct UdpIngress {
    session_id: u64,
    id: UdpFlowId,
    peer: Endpoint,
    target: Endpoint,
    payload: Vec<u8>,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    event_tx: mpsc::UnboundedSender<InboundUdpSessionEvent>,
}

impl UdpIngress {
    fn source_key(&self, inbound_id: &str) -> Option<UdpSourceKey> {
        Some(UdpSourceKey {
            inbound_id: inbound_id.to_owned(),
            session_id: self.session_id,
            source: self.peer.addr()?,
            authentication: self.id.authentication,
        })
    }
}

enum InboundUdpSessionEvent {
    FlowOpened(TunFlowKey),
}

enum UdpManagerCommand {
    CloseFlow(TunFlowKey),
    CloseSession(u64),
}

struct UdpFlowHandle {
    generation: u64,
    data_tx: mpsc::Sender<UdpIngress>,
    cancel_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    flow: Option<TunFlowKey>,
    session_id: u64,
}

enum UdpFlowEvent {
    Opened {
        key: UdpSourceKey,
        generation: u64,
        flow: TunFlowKey,
    },
    Closed {
        key: UdpSourceKey,
        generation: u64,
    },
}

/// The protocol-independent UDP ingress actor.
///
/// The actor owns the source-to-flow map, while every flow owns its outbound
/// datagram and all potentially slow DNS/route/open/send/recv operations.
/// Neither the protocol session nor this manager waits on a flow's data queue
/// or network I/O.
pub(crate) struct InboundUdpManager {
    ingress_tx: mpsc::Sender<UdpIngress>,
    command_tx: mpsc::UnboundedSender<UdpManagerCommand>,
    next_session_id: AtomicU64,
}

struct InboundUdpSessionChannels {
    session_id: u64,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    reply_rx: mpsc::Receiver<InboundUdpResponse>,
    event_rx: mpsc::UnboundedReceiver<InboundUdpSessionEvent>,
    event_tx: mpsc::UnboundedSender<InboundUdpSessionEvent>,
}

impl InboundUdpManager {
    pub(super) fn new(inbound: Weak<InboundHandler>, capacity: usize) -> Self {
        let (ingress_tx, ingress_rx) = mpsc::channel(capacity.max(1));
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_udp_manager(
            inbound.clone(),
            ingress_rx,
            command_rx,
            capacity.max(1),
        ));
        Self {
            ingress_tx,
            command_tx,
            next_session_id: AtomicU64::new(1),
        }
    }

    fn open_session(&self, capacity: usize) -> InboundUdpSessionChannels {
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (reply_tx, reply_rx) = mpsc::channel(capacity.max(1));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        InboundUdpSessionChannels {
            session_id,
            reply_tx,
            reply_rx,
            event_rx,
            event_tx,
        }
    }

    fn dispatch(&self, ingress: UdpIngress) -> UdpDispatchResult {
        match self.ingress_tx.try_send(ingress) {
            Ok(()) => UdpDispatchResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => UdpDispatchResult::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => UdpDispatchResult::Closed,
        }
    }

    fn close_flow(&self, flow: TunFlowKey) {
        let _ = self.command_tx.send(UdpManagerCommand::CloseFlow(flow));
    }

    fn close_session(&self, session_id: u64) {
        let _ = self
            .command_tx
            .send(UdpManagerCommand::CloseSession(session_id));
    }
}

enum UdpDispatchResult {
    Accepted,
    Dropped,
    Closed,
}

async fn run_udp_manager(
    inbound: Weak<InboundHandler>,
    mut ingress_rx: mpsc::Receiver<UdpIngress>,
    mut command_rx: mpsc::UnboundedReceiver<UdpManagerCommand>,
    capacity: usize,
) {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut flows = HashMap::<UdpSourceKey, UdpFlowHandle>::new();
    let mut pending_close = std::collections::HashSet::<TunFlowKey>::new();
    let mut next_generation = 1u64;

    loop {
        tokio::select! {
            Some(ingress) = ingress_rx.recv() => {
                let Some(inbound_ref) = inbound.upgrade() else { break; };
                let Some(key) = ingress.source_key(&inbound_ref.spec.id) else { continue; };
                let generation = next_generation;
                let handle = match flows.entry(key.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        match entry.get().data_tx.try_send(ingress) {
                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                            Err(mpsc::error::TrySendError::Closed(ingress)) => {
                                let old = entry.remove();
                                let _ = old.cancel_tx.send(true);
                                spawn_udp_flow(
                                    Arc::downgrade(&inbound_ref),
                                    key.clone(),
                                    generation,
                                    capacity,
                                    ingress,
                                    event_tx.clone(),
                                )
                            }
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(_) => {
                        spawn_udp_flow(
                            Arc::downgrade(&inbound_ref),
                            key.clone(),
                            generation,
                            capacity,
                            ingress,
                            event_tx.clone(),
                        )
                    }
                };
                next_generation = next_generation.wrapping_add(1).max(1);
                flows.insert(key, handle);
            }
            Some(command) = command_rx.recv() => {
                match command {
                    UdpManagerCommand::CloseFlow(flow) => {
                        let mut matched = false;
                        for handle in flows.values() {
                            if handle.flow == Some(flow) {
                                matched = true;
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                        if !matched {
                            pending_close.insert(flow);
                        }
                    }
                    UdpManagerCommand::CloseSession(session_id) => {
                        let keys = flows
                            .iter()
                            .filter_map(|(key, handle)| (handle.session_id == session_id).then_some(key.clone()))
                            .collect::<Vec<_>>();
                        for key in keys {
                            if let Some(handle) = flows.remove(&key) {
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                    }
                }
            }
            Some(event) = event_rx.recv() => {
                match event {
                    UdpFlowEvent::Opened { key, generation, flow } => {
                        if let Some(handle) = flows.get_mut(&key)
                            && handle.generation == generation
                        {
                            handle.flow = Some(flow);
                            if pending_close.remove(&flow) {
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                    }
                    UdpFlowEvent::Closed { key, generation } => {
                        if flows.get(&key).is_some_and(|handle| handle.generation == generation) {
                            flows.remove(&key);
                        }
                    }
                }
            }
            else => break,
        }
    }

    for handle in flows.into_values() {
        let _ = handle.cancel_tx.send(true);
        handle.join.abort();
    }
}

fn spawn_udp_flow(
    inbound: Weak<InboundHandler>,
    key: UdpSourceKey,
    generation: u64,
    capacity: usize,
    first: UdpIngress,
    event_tx: mpsc::UnboundedSender<UdpFlowEvent>,
) -> UdpFlowHandle {
    let (data_tx, data_rx) = mpsc::channel(capacity.max(1));
    let first_tx = data_tx.clone();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let key_for_task = key.clone();
    let join = tokio::spawn(async move {
        let _ = first_tx.try_send(first);
        UdpFlowWorker {
            inbound,
            key: key_for_task.clone(),
            generation,
            rx: data_rx,
            cancel_rx,
            event_tx: event_tx.clone(),
            datagram: None,
            flow: None,
            reply_id: None,
            reply_peer: None,
            reply_tx: None,
            observation: None,
            last_seen: Instant::now(),
        }
        .run()
        .await;
        let _ = event_tx.send(UdpFlowEvent::Closed {
            key: key_for_task,
            generation,
        });
    });
    UdpFlowHandle {
        generation,
        data_tx,
        cancel_tx,
        join,
        flow: None,
        session_id: key.session_id,
    }
}

struct UdpFlowWorker {
    inbound: Weak<InboundHandler>,
    key: UdpSourceKey,
    generation: u64,
    rx: mpsc::Receiver<UdpIngress>,
    cancel_rx: watch::Receiver<bool>,
    event_tx: mpsc::UnboundedSender<UdpFlowEvent>,
    datagram: Option<Arc<dyn AsyncDatagram>>,
    flow: Option<TunFlowKey>,
    reply_id: Option<UdpFlowId>,
    reply_peer: Option<Endpoint>,
    reply_tx: Option<mpsc::Sender<InboundUdpResponse>>,
    observation: Option<yuhaiin_core::flow::FlowObserverGuard>,
    last_seen: Instant,
}

impl UdpFlowWorker {
    async fn run(mut self) {
        let Some(inbound) = self.inbound.upgrade() else {
            return;
        };
        let buffer_size = inbound.selector().udp_buffer_size().max(512);
        let idle_timeout = udp_idle_timeout();
        let mut buffer = vec![0u8; buffer_size];
        let mut idle = Box::pin(tokio::time::sleep(idle_timeout));

        loop {
            if let Some(datagram) = self.datagram.clone() {
                tokio::select! {
                    packet = self.rx.recv() => {
                        let Some(packet) = packet else { break; };
                        if !self.process_packet(&inbound, packet).await { break; }
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
                }
            } else {
                tokio::select! {
                    packet = self.rx.recv() => {
                        let Some(packet) = packet else { break; };
                        if !self.process_packet(&inbound, packet).await { break; }
                    }
                    _ = &mut idle => break,
                    changed = self.cancel_rx.changed() => {
                        if changed.is_err() || *self.cancel_rx.borrow() { break; }
                    }
                }
            }
            self.last_seen = Instant::now();
            idle.as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
        }

        if let Some(datagram) = self.datagram.take() {
            let _ = datagram.close().await;
        }
        drop(self.observation.take());
    }

    async fn process_packet(&mut self, inbound: &Arc<InboundHandler>, packet: UdpIngress) -> bool {
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
            let _ = self.event_tx.send(UdpFlowEvent::Opened {
                key: self.key.clone(),
                generation: self.generation,
                flow,
            });
            let _ = packet
                .event_tx
                .send(InboundUdpSessionEvent::FlowOpened(flow));
        }

        let Some(datagram) = self.datagram.as_ref() else {
            return false;
        };
        if let Err(error) = datagram
            .send_to(&packet.payload, packet.target.clone())
            .await
        {
            inbound.monitor.error(format!(
                "UDP forwarding send failed source={} target={}: {error}",
                packet.peer, packet.target
            ));
            return false;
        }
        if let Some(flow) = self.flow {
            inbound
                .monitor()
                .bytes(flow, FlowDirection::Upload, packet.payload.len());
        }
        true
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

pub(crate) struct InboundUdpSession<C> {
    codec: C,
    inbound: Arc<InboundHandler>,
    manager: Arc<InboundUdpManager>,
    session_id: u64,
    reply_rx: mpsc::Receiver<InboundUdpResponse>,
    event_rx: mpsc::UnboundedReceiver<InboundUdpSessionEvent>,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    event_tx: mpsc::UnboundedSender<InboundUdpSessionEvent>,
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
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        let mut close_events = self.inbound.monitor().subscribe_close_requests();
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
                        self.codec.send(response).await?;
                        if input_closed && pending_packets == 0 { break; }
                    }
                    Some(event) = self.event_rx.recv() => {
                        match event {
                            InboundUdpSessionEvent::FlowOpened(flow) => self.codec.note_flow(flow),
                        }
                    }
                    close_event = close_events.recv() => {
                        match close_event {
                            Ok(flow) => {
                                let stop = self.codec.owns_flow(flow);
                                self.manager.close_flow(flow);
                                if stop {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = &mut drain, if input_closed => break,
                }
            }
            Ok(())
        }
        .await;
        self.manager.close_session(self.session_id);
        result
    }
}
