use super::*;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use doradus_core::flow::FlowDirection;
use doradus_core::proxy::AsyncDatagram;
use doradus_core::{Endpoint, Result};

use crate::inbound::adapters::common::{UdpFlowId, udp_idle_timeout};

pub(crate) use doradus_types::{InboundUdpCodec, InboundUdpRequest, InboundUdpResponse};

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
    session_cancel_rx: watch::Receiver<bool>,
    id: UdpFlowId,
    peer: Endpoint,
    target: Endpoint,
    payload: Vec<u8>,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    event_tx: mpsc::Sender<InboundUdpSessionEvent>,
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
    FlowClosed(TunFlowKey),
}

enum UdpManagerCommand {
    CloseFlow { session_id: u64, flow: TunFlowKey },
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
    command_tx: mpsc::Sender<UdpManagerCommand>,
    next_session_id: AtomicU64,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

struct InboundUdpSessionChannels {
    session_id: u64,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    reply_rx: mpsc::Receiver<InboundUdpResponse>,
    event_rx: mpsc::Receiver<InboundUdpSessionEvent>,
    event_tx: mpsc::Sender<InboundUdpSessionEvent>,
    session_cancel_tx: watch::Sender<bool>,
}

impl InboundUdpManager {
    pub(super) fn new(inbound: Weak<InboundHandler>, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (ingress_tx, ingress_rx) = mpsc::channel(capacity);
        let (command_tx, command_rx) = mpsc::channel(capacity.max(16));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(run_udp_manager(
            inbound.clone(),
            ingress_rx,
            command_rx,
            capacity.max(1),
            shutdown_rx,
        ));
        Self {
            ingress_tx,
            command_tx,
            next_session_id: AtomicU64::new(1),
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        }
    }

    fn open_session(&self, capacity: usize) -> InboundUdpSessionChannels {
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let capacity = capacity.max(1);
        let (reply_tx, reply_rx) = mpsc::channel(capacity);
        let (event_tx, event_rx) = mpsc::channel(capacity);
        let (session_cancel_tx, _session_cancel_rx) = watch::channel(false);
        InboundUdpSessionChannels {
            session_id,
            reply_tx,
            reply_rx,
            event_rx,
            event_tx,
            session_cancel_tx,
        }
    }

    fn dispatch(&self, ingress: UdpIngress) -> UdpDispatchResult {
        match self.ingress_tx.try_send(ingress) {
            Ok(()) => UdpDispatchResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => UdpDispatchResult::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => UdpDispatchResult::Closed,
        }
    }

    async fn close_flow(&self, session_id: u64, flow: TunFlowKey) {
        let _ = self
            .command_tx
            .send(UdpManagerCommand::CloseFlow { session_id, flow })
            .await;
    }

    async fn close_session(&self, session_id: u64) {
        let _ = self
            .command_tx
            .send(UdpManagerCommand::CloseSession(session_id))
            .await;
    }
}

impl Drop for InboundUdpManager {
    fn drop(&mut self) {
        // Dropping the last manager is the owner lifecycle boundary. The
        // manager task owns the worker handles and will cancel and reap them
        // before it exits. The task handle stays attached to this owner for
        // its entire live lifetime; the shutdown signal lets its cleanup run
        // after the owner itself is dropped.
        self.shutdown_tx.take();
        drop(self.join.take());
    }
}

enum UdpDispatchResult {
    Accepted,
    Dropped,
    Closed,
}

fn opening_worker_key<'a>(
    flows: impl IntoIterator<Item = (&'a UdpSourceKey, u64, bool)>,
    session_id: u64,
    flow: TunFlowKey,
) -> Option<UdpSourceKey> {
    flows
        .into_iter()
        .find(|(key, worker_session, opening)| {
            *worker_session == session_id && *opening && key.source == flow.source
        })
        .map(|(key, _, _)| key.clone())
}

async fn run_udp_manager(
    inbound: Weak<InboundHandler>,
    mut ingress_rx: mpsc::Receiver<UdpIngress>,
    mut command_rx: mpsc::Receiver<UdpManagerCommand>,
    capacity: usize,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let (event_tx, mut event_rx) = mpsc::channel(capacity.max(16));
    let mut flows = HashMap::<UdpSourceKey, UdpFlowHandle>::new();
    // A pending close belongs to a concrete source worker that is still
    // opening. This keeps unrelated global close notifications out and limits
    // the map to at most one entry per opening worker.
    let mut pending_close = HashMap::<UdpSourceKey, TunFlowKey>::new();
    let mut reapers = JoinSet::new();
    let mut next_generation = 1u64;
    let mut ingress_open = true;
    let mut command_open = true;

    loop {
        tokio::select! {
            ingress = ingress_rx.recv(), if ingress_open => {
                if let Some(ingress) = ingress {
                    if *ingress.session_cancel_rx.borrow() {
                        continue;
                    }
                    let Some(inbound_ref) = inbound.upgrade() else { break; };
                    let Some(key) = ingress.source_key(&inbound_ref.spec.id) else { continue; };
                    let generation = next_generation;
                    let handle = match flows.entry(key.clone()) {
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            match entry.get().data_tx.try_send(ingress) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                                Err(mpsc::error::TrySendError::Closed(ingress)) => {
                                    let old = entry.remove();
                                    pending_close.remove(&key);
                                    let UdpFlowHandle {
                                        cancel_tx, join, ..
                                    } = old;
                                    let _ = cancel_tx.send(true);
                                    reapers.spawn(async move {
                                        let _ = join.await;
                                    });
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
                } else {
                    ingress_open = false;
                }
            }
            command = command_rx.recv(), if command_open => {
                match command {
                    Some(UdpManagerCommand::CloseFlow { session_id, flow }) => {
                        let mut matched = false;
                        for handle in flows.values() {
                            if handle.session_id == session_id && handle.flow == Some(flow) {
                                matched = true;
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                        if !matched {
                            // A close can race with the worker's open event.
                            // Scope the fallback to an opening worker with the
                            // same session and source; an unrelated global
                            // flow must never create permanent manager state.
                            let key = opening_worker_key(
                                flows.iter().map(|(key, handle)| {
                                    (key, handle.session_id, handle.flow.is_none())
                                }),
                                session_id,
                                flow,
                            );
                            if let Some(key) = key {
                                pending_close.insert(key, flow);
                            }
                        }
                    }
                    Some(UdpManagerCommand::CloseSession(session_id)) => {
                        for handle in flows.values() {
                            if handle.session_id == session_id {
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                        pending_close.retain(|key, _| key.session_id != session_id);
                    }
                    None => command_open = false,
                }
            }
            Some(event) = event_rx.recv() => {
                match event {
                    UdpFlowEvent::Opened { key, generation, flow } => {
                        if let Some(handle) = flows.get_mut(&key)
                            && handle.generation == generation
                        {
                            handle.flow = Some(flow);
                            if pending_close.remove(&key) == Some(flow) {
                                let _ = handle.cancel_tx.send(true);
                            }
                        }
                    }
                    UdpFlowEvent::Closed { key, generation } => {
                        if flows.get(&key).is_some_and(|handle| handle.generation == generation) {
                            pending_close.remove(&key);
                            if let Some(handle) = flows.remove(&key) {
                                // Closed is emitted after the worker has
                                // released its datagram and observation. The
                                // join only reaps that completed task; it does
                                // not wait on network I/O.
                                let _ = handle.join.await;
                            }
                        }
                    }
                }
            }
            _ = &mut shutdown_rx => break,
            result = reapers.join_next(), if !reapers.is_empty() => {
                let _ = result;
            }
        }
        // `event_tx` is owned by this manager task, so event_rx never closes
        // merely because ingress and command senders disappeared. Explicitly
        // stop once both external inputs are gone.
        if !ingress_open && !command_open {
            break;
        }
    }

    // Release lifecycle senders before joining workers. Normal flow cancellation
    // must still publish Closed so the live manager removes its map entry.
    drop(event_rx);
    let handles = flows.into_values().collect::<Vec<_>>();
    for handle in &handles {
        let _ = handle.cancel_tx.send(true);
    }
    for handle in handles {
        let _ = handle.join.await;
    }
    while reapers.join_next().await.is_some() {}
}

fn spawn_udp_flow(
    inbound: Weak<InboundHandler>,
    key: UdpSourceKey,
    generation: u64,
    capacity: usize,
    first: UdpIngress,
    event_tx: mpsc::Sender<UdpFlowEvent>,
) -> UdpFlowHandle {
    let (data_tx, data_rx) = mpsc::channel(capacity.max(1));
    let first_tx = data_tx.clone();
    let session_cancel_rx = first.session_cancel_rx.clone();
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
            session_cancel_rx,
            event_tx: event_tx.clone(),
            datagram: None,
            flow: None,
            reply_id: None,
            reply_peer: None,
            reply_tx: None,
            session_event_tx: None,
            observation: None,
            last_seen: Instant::now(),
        }
        .run()
        .await;
        let _ = event_tx
            .send(UdpFlowEvent::Closed {
                key: key_for_task,
                generation,
            })
            .await;
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
    session_cancel_rx: watch::Receiver<bool>,
    event_tx: mpsc::Sender<UdpFlowEvent>,
    datagram: Option<Arc<dyn AsyncDatagram>>,
    flow: Option<TunFlowKey>,
    reply_id: Option<UdpFlowId>,
    reply_peer: Option<Endpoint>,
    reply_tx: Option<mpsc::Sender<InboundUdpResponse>>,
    session_event_tx: Option<mpsc::Sender<InboundUdpSessionEvent>>,
    observation: Option<doradus_core::flow::FlowObserverGuard>,
    last_seen: Instant,
}

impl UdpFlowWorker {
    async fn run(mut self) {
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
    codec: C,
    inbound: Arc<InboundHandler>,
    manager: Arc<InboundUdpManager>,
    session_id: u64,
    reply_rx: mpsc::Receiver<InboundUdpResponse>,
    event_rx: mpsc::Receiver<InboundUdpSessionEvent>,
    reply_tx: mpsc::Sender<InboundUdpResponse>,
    event_tx: mpsc::Sender<InboundUdpSessionEvent>,
    session_cancel_tx: watch::Sender<bool>,
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

#[cfg(test)]
#[path = "handler_udp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "handler_udp_slow_send_tests.rs"]
mod slow_send_tests;
