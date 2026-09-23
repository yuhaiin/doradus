//! Source-keyed actor that owns and reaps inbound UDP flow workers.

use super::udp_worker::UdpFlowWorker;
use super::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use super::udp_types::{
    InboundUdpSessionEvent, UdpFlowEvent, UdpFlowHandle, UdpIngress, UdpManagerCommand,
    UdpSourceKey,
};

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

pub(super) struct InboundUdpSessionChannels {
    pub(super) session_id: u64,
    pub(super) reply_tx: mpsc::Sender<InboundUdpResponse>,
    pub(super) reply_rx: mpsc::Receiver<InboundUdpResponse>,
    pub(super) event_rx: mpsc::Receiver<InboundUdpSessionEvent>,
    pub(super) event_tx: mpsc::Sender<InboundUdpSessionEvent>,
    pub(super) session_cancel_tx: watch::Sender<bool>,
}

impl InboundUdpManager {
    pub(in crate::plane::inbounds) fn new(inbound: Weak<InboundHandler>, capacity: usize) -> Self {
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

    pub(super) fn open_session(&self, capacity: usize) -> InboundUdpSessionChannels {
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

    #[cfg(test)]
    pub(crate) fn take_join_for_test(&mut self) -> tokio::task::JoinHandle<()> {
        self.join
            .take()
            .expect("manager owner must retain its task handle")
    }

    pub(super) fn dispatch(&self, ingress: UdpIngress) -> UdpDispatchResult {
        match self.ingress_tx.try_send(ingress) {
            Ok(()) => UdpDispatchResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => UdpDispatchResult::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => UdpDispatchResult::Closed,
        }
    }

    pub(super) async fn close_flow(&self, session_id: u64, flow: TunFlowKey) {
        let _ = self
            .command_tx
            .send(UdpManagerCommand::CloseFlow { session_id, flow })
            .await;
    }

    pub(super) async fn close_session(&self, session_id: u64) {
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

pub(super) enum UdpDispatchResult {
    Accepted,
    Dropped,
    Closed,
}

pub(super) fn opening_worker_key<'a>(
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

pub(super) async fn run_udp_manager(
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

pub(super) fn spawn_udp_flow(
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
