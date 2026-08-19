//! The common inbound boundary.
//!
//! Protocol listeners only decode their wire format.  Once a request has a
//! source and destination, this type owns the parts that are common to every
//! inbound: flow metadata, route selection, DNS policy, outbound creation,
//! accounting and relay lifetime.  This is the Rust equivalent of Go's
//! `inbound.Inbound` forwarding to one shared `netapi.Handler`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection, FlowKey as TunFlowKey, FlowObserver as TunFlowObserver,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, Network, Result};

use super::InboundSpec;
use crate::proxy::common::{
    UdpFlowId, record_outbound_datagram, record_outbound_stream, relay_counted_with_buffer,
    relay_counted_with_prefix_and_buffer, udp_idle_timeout,
};
use crate::{ConnectionMonitor, RuntimeProxySelector};

/// The single DNS boundary shared by every inbound protocol.
///
/// Go evaluates this predicate in inbound.Inbound before dispatching to a
/// protocol handler. Rust protocol adapters only own their wire framing and
/// call this policy; they must not each decide whether a packet is DNS.
pub(crate) trait InboundDnsHandler: Send + Sync {
    fn should_hijack(&self, destination_port: Option<u16>, packet: &[u8]) -> bool;

    fn answer<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Option<yuhaiin_core::Result<Vec<u8>>>>;
}

#[derive(Clone)]
pub(crate) struct InboundDnsPolicy {
    monitor: Arc<ConnectionMonitor>,
}

impl InboundDnsPolicy {
    pub(crate) fn new(monitor: Arc<ConnectionMonitor>) -> Self {
        Self { monitor }
    }

    pub(crate) async fn answer_datagram(
        &self,
        destination_port: Option<u16>,
        packet: &[u8],
    ) -> Option<yuhaiin_core::Result<Vec<u8>>> {
        if !self.should_hijack(destination_port, packet) {
            return None;
        }
        self.answer(packet).await
    }
}

impl InboundDnsHandler for InboundDnsPolicy {
    fn should_hijack(&self, destination_port: Option<u16>, packet: &[u8]) -> bool {
        self.monitor.dns_hijack_enabled()
            && (destination_port == Some(53) || yuhaiin_core::dns::decode_query(packet).is_ok())
    }

    fn answer<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Option<yuhaiin_core::Result<Vec<u8>>>> {
        Box::pin(async move { self.monitor.answer_dns(packet).await })
    }
}

/// Adapts the shared inbound DNS policy to the generic TUN input boundary.
/// The TUN crate only knows about packets and the shared output queue; DNS
/// ownership stays with this inbound module.
#[cfg(feature = "tun")]
pub(crate) struct InboundInputInterceptor {
    dns: InboundDnsPolicy,
    dns_tasks: JoinSet<yuhaiin_tun::ProxyInputAction>,
    max_pending_dns: usize,
}

#[cfg(feature = "tun")]
impl InboundInputInterceptor {
    pub(crate) fn new(monitor: Arc<ConnectionMonitor>, max_pending_dns: usize) -> Self {
        Self {
            dns: InboundDnsPolicy::new(monitor),
            dns_tasks: JoinSet::new(),
            max_pending_dns: max_pending_dns.clamp(16, 512),
        }
    }
}

#[cfg(feature = "tun")]
impl yuhaiin_tun::ProxyInputInterceptor for InboundInputInterceptor {
    fn intercept(
        &mut self,
        input: yuhaiin_tun::ProxyInput,
    ) -> Result<yuhaiin_tun::ProxyInputAction> {
        match input {
            yuhaiin_tun::ProxyInput::UdpDatagram { flow, payload } => {
                let destination_port = Some(flow.key.destination.port());
                if !self.dns.should_hijack(destination_port, &payload) {
                    return Ok(yuhaiin_tun::ProxyInputAction::Forward(
                        yuhaiin_tun::ProxyInput::UdpDatagram { flow, payload },
                    ));
                }

                if self.dns_tasks.len() >= self.max_pending_dns {
                    return Ok(yuhaiin_tun::ProxyInputAction::Drop);
                }

                let dns = self.dns.clone();
                let flow_key = flow.key;
                self.dns_tasks.spawn(async move {
                    let result =
                        tokio::time::timeout(Duration::from_secs(10), dns.answer(&payload)).await;

                    match result {
                        Ok(Some(Ok(response))) => yuhaiin_tun::ProxyInputAction::Reply {
                            flow: flow_key,
                            payload: response,
                        },
                        Ok(Some(Err(_))) | Ok(None) | Err(_) => yuhaiin_tun::ProxyInputAction::Drop,
                    }
                });

                Ok(yuhaiin_tun::ProxyInputAction::Deferred)
            }
            other => Ok(yuhaiin_tun::ProxyInputAction::Forward(other)),
        }
    }

    fn wait_for_output<'a>(&'a mut self) -> BoxFuture<'a, yuhaiin_tun::ProxyInputAction> {
        Box::pin(async move {
            loop {
                match self.dns_tasks.join_next().await {
                    Some(Ok(action)) => return action,
                    Some(Err(error)) => {
                        self.dns
                            .monitor
                            .warn(format!("TUN DNS interceptor task failed: {error}"));
                    }
                    None => return std::future::pending().await,
                }
            }
        })
    }
}

pub(crate) struct InboundHandler {
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    dns: InboundDnsPolicy,
    udp: Arc<InboundUdpManager>,
}

impl InboundHandler {
    pub(crate) fn new(
        spec: InboundSpec,
        selector: Arc<RuntimeProxySelector>,
        monitor: Arc<ConnectionMonitor>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|inbound| Self {
            dns: InboundDnsPolicy::new(Arc::clone(&monitor)),
            udp: Arc::new(InboundUdpManager::new(
                inbound.clone(),
                selector.udp_ringbuffer_size().max(1),
            )),
            spec,
            selector,
            monitor,
        })
    }

    pub(crate) fn spec(&self) -> &InboundSpec {
        &self.spec
    }

    pub(crate) fn selector(&self) -> &Arc<RuntimeProxySelector> {
        &self.selector
    }

    pub(crate) fn monitor(&self) -> &Arc<ConnectionMonitor> {
        &self.monitor
    }

    pub(crate) fn dns_policy(&self) -> InboundDnsPolicy {
        self.dns.clone()
    }

    pub(crate) fn udp(&self) -> &Arc<InboundUdpManager> {
        &self.udp
    }

    pub(crate) fn context(
        &self,
        peer: SocketAddr,
        network: Network,
        destination: Endpoint,
    ) -> FlowContext {
        self.context_with_source(Endpoint::ip(network, peer), destination)
    }

    pub(crate) fn context_with_source(
        &self,
        source: Endpoint,
        destination: Endpoint,
    ) -> FlowContext {
        let mut context = FlowContext::new(destination.clone());
        context.source = Some(source);
        context.original_domain = destination.host().cloned();
        self.spec.annotate_context(&mut context);
        context
    }

    pub(crate) fn flow_key(&self, context: &FlowContext, peer: SocketAddr) -> TunFlowKey {
        TunFlowKey {
            network: context.network,
            source: peer,
            destination: context
                .destination
                .addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback address")),
        }
    }

    pub(crate) async fn connect(
        &self,
        protocol: &str,
        mut context: FlowContext,
    ) -> Result<InboundStream> {
        self.selector.route_context(&mut context);
        let process = context.process.clone();
        let destination = context.destination.clone();
        let outbound = match self.selector.select(&context).connect(&context).await {
            Ok(outbound) => outbound,
            Err(error) => {
                self.monitor.record_failure_with_process(
                    protocol,
                    &destination.to_string(),
                    &error.to_string(),
                    process.as_deref(),
                );
                return Err(error);
            }
        };
        record_outbound_stream(&mut context, &outbound);
        Ok(InboundStream { outbound, context })
    }

    pub(crate) async fn open_stream(
        &self,
        protocol: &str,
        peer: SocketAddr,
        destination: Endpoint,
    ) -> Result<InboundStream> {
        self.connect(protocol, self.context(peer, Network::Tcp, destination))
            .await
    }

    pub(crate) async fn serve_stream(
        &self,
        stream: BoxAsyncStream,
        peer: SocketAddr,
        protocol: &str,
        destination: Endpoint,
    ) -> Result<()> {
        let connection = self.open_stream(protocol, peer, destination).await?;
        self.relay(stream, connection, peer).await.map_err(|error| {
            yuhaiin_core::Error::new(yuhaiin_core::ErrorKind::Io, error.to_string())
        })
    }

    pub(crate) async fn serve_stream_with_prefix(
        &self,
        stream: BoxAsyncStream,
        peer: SocketAddr,
        protocol: &str,
        destination: Endpoint,
        prefix: &[u8],
    ) -> Result<()> {
        let connection = self.open_stream(protocol, peer, destination).await?;
        self.relay_with_prefix(stream, connection, peer, prefix)
            .await
            .map_err(|error| {
                yuhaiin_core::Error::new(yuhaiin_core::ErrorKind::Io, error.to_string())
            })
    }

    pub(crate) async fn open_datagram(
        &self,
        mut context: FlowContext,
        peer: SocketAddr,
    ) -> Result<InboundDatagram> {
        self.selector.route_context(&mut context);
        let datagram = self
            .selector
            .select(&context)
            .open_datagram(&context)
            .await?;
        record_outbound_datagram(&mut context, &*datagram);
        let flow = self.flow_key(&context, peer);
        Ok(InboundDatagram {
            datagram: Arc::from(datagram),
            flow,
            context,
        })
    }

    pub(crate) async fn answer_datagram(
        &self,
        destination: &Endpoint,
        payload: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        self.dns.answer_datagram(destination.port(), payload).await
    }

    pub(crate) async fn relay<S>(
        &self,
        stream: S,
        connection: InboundStream,
        peer: SocketAddr,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let flow = self.flow_key(&connection.context, peer);
        relay_counted_with_buffer(
            stream,
            connection.outbound,
            flow,
            connection.context,
            self.monitor.clone(),
            &self.dns,
            self.selector.relay_buffer_size(),
        )
        .await
    }

    pub(crate) async fn relay_with_prefix<S>(
        &self,
        stream: S,
        connection: InboundStream,
        peer: SocketAddr,
        prefix: &[u8],
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let flow = self.flow_key(&connection.context, peer);
        relay_counted_with_prefix_and_buffer(
            stream,
            connection.outbound,
            flow,
            connection.context,
            self.monitor.clone(),
            &self.dns,
            prefix,
            self.selector.relay_buffer_size(),
        )
        .await
    }

    pub(crate) fn observe_datagram(&self, datagram: InboundDatagram) -> ObservedDatagram {
        let observation = yuhaiin_core::flow::FlowObserverGuard::open(
            self.monitor.clone(),
            TunFlow { key: datagram.flow },
            datagram.context,
        );
        ObservedDatagram {
            datagram: datagram.datagram,
            _observation: observation,
        }
    }
}

pub(crate) struct InboundStream {
    pub(crate) outbound: BoxAsyncStream,
    pub(crate) context: FlowContext,
}

pub(crate) struct InboundDatagram {
    pub(crate) datagram: Arc<dyn AsyncDatagram>,
    pub(crate) flow: TunFlowKey,
    context: FlowContext,
}

pub(crate) struct ObservedDatagram {
    pub(crate) datagram: Arc<dyn AsyncDatagram>,
    pub(crate) _observation: yuhaiin_core::flow::FlowObserverGuard,
}

pub(crate) struct InboundUdpRequest {
    pub(crate) id: UdpFlowId,
    pub(crate) peer: Endpoint,
    pub(crate) target: Endpoint,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct InboundUdpResponse {
    pub(crate) id: UdpFlowId,
    pub(crate) peer: Endpoint,
    pub(crate) target: Endpoint,
    pub(crate) payload: Vec<u8>,
    pub(crate) flow: Option<TunFlowKey>,
}

/// Protocol adapters implement only wire framing. The shared session owns
/// DNS interception, outbound datagrams, flow accounting, close requests and
/// idle cleanup, matching Go's `inbound.Inbound` packet loop.
pub(crate) trait InboundUdpCodec: Send {
    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>>;

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>>;

    fn note_flow(&mut self, _flow: TunFlowKey) {}

    fn owns_flow(&self, _flow: TunFlowKey) -> bool {
        false
    }
}

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
    fn new(inbound: Weak<InboundHandler>, capacity: usize) -> Self {
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
                        flow: None,
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
        if datagram
            .send_to(&packet.payload, packet.target)
            .await
            .is_err()
        {
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
                flow: Some(flow),
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
    C: InboundUdpCodec,
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
                        if let Some(flow) = response.flow {
                            self.codec.note_flow(flow);
                        }
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
