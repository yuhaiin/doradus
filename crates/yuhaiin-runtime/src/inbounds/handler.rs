//! The common inbound boundary.
//!
//! Protocol listeners only decode their wire format.  Once a request has a
//! source and destination, this type owns the parts that are common to every
//! inbound: flow metadata, route selection, DNS policy, outbound creation,
//! accounting and relay lifetime.  This is the Rust equivalent of Go's
//! `inbound.Inbound` forwarding to one shared `netapi.Handler`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection, FlowKey as TunFlowKey, FlowObserver as TunFlowObserver,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, Network, Result};

use super::InboundSpec;
use crate::proxy::common::{
    UdpFlowId, UdpFlowState, UdpReply, reap_expired_udp_flows_with_timeout,
    record_outbound_datagram, record_outbound_stream, relay_counted_with_buffer,
    relay_counted_with_prefix_and_buffer, shutdown_udp_flow, udp_idle_timeout,
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
}

#[cfg(feature = "tun")]
impl InboundInputInterceptor {
    pub(crate) fn new(monitor: Arc<ConnectionMonitor>) -> Self {
        Self {
            dns: InboundDnsPolicy::new(monitor),
        }
    }
}

#[cfg(feature = "tun")]
impl yuhaiin_tun::ProxyInputInterceptor for InboundInputInterceptor {
    fn intercept<'a>(
        &'a mut self,
        input: yuhaiin_tun::ProxyInput,
    ) -> BoxFuture<'a, Result<yuhaiin_tun::ProxyInputAction>> {
        Box::pin(async move {
            match input {
                yuhaiin_tun::ProxyInput::UdpDatagram { flow, payload } => {
                    match self
                        .dns
                        .answer_datagram(Some(flow.key.destination.port()), &payload)
                        .await
                    {
                        Some(Ok(response)) => Ok(yuhaiin_tun::ProxyInputAction::Reply {
                            flow: flow.key,
                            payload: response,
                        }),
                        Some(Err(_)) => Ok(yuhaiin_tun::ProxyInputAction::Drop),
                        None => Ok(yuhaiin_tun::ProxyInputAction::Forward(
                            yuhaiin_tun::ProxyInput::UdpDatagram { flow, payload },
                        )),
                    }
                }
                other => Ok(yuhaiin_tun::ProxyInputAction::Forward(other)),
            }
        })
    }
}

pub(crate) struct InboundHandler {
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    dns: InboundDnsPolicy,
}

impl InboundHandler {
    pub(crate) fn new(
        spec: InboundSpec,
        selector: Arc<RuntimeProxySelector>,
        monitor: Arc<ConnectionMonitor>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dns: InboundDnsPolicy::new(Arc::clone(&monitor)),
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

pub(crate) enum InboundUdpPacket {
    Drop,
    Reply(Vec<u8>),
    Forward { flow: TunFlowKey },
}

pub(crate) struct InboundUdpReply {
    pub(crate) id: UdpFlowId,
    pub(crate) peer: Endpoint,
    pub(crate) target: Endpoint,
    pub(crate) payload: Vec<u8>,
    pub(crate) flow: TunFlowKey,
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
}

impl InboundUdpReply {
    fn into_response(self) -> InboundUdpResponse {
        InboundUdpResponse {
            id: self.id,
            peer: self.peer,
            target: self.target,
            payload: self.payload,
        }
    }
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

/// Shared UDP flow ownership for every inbound protocol.
///
/// Go's `inbound.Inbound` owns the packet channel, DNS gate, NAT/relay flow
/// lifecycle and reply observation. Protocol adapters only decode/encode their
/// wire format and call this service with a normalized packet.
pub(crate) struct InboundUdpFlows {
    inbound: Arc<InboundHandler>,
    flows: HashMap<UdpFlowId, UdpFlowState>,
    reply_tx: mpsc::Sender<UdpReply>,
    reply_rx: mpsc::Receiver<UdpReply>,
    udp_buffer_size: usize,
    idle_timeout: std::time::Duration,
}

impl InboundUdpFlows {
    pub(crate) fn new(inbound: Arc<InboundHandler>) -> Self {
        let capacity = inbound.selector().udp_ringbuffer_size().max(1);
        let (reply_tx, reply_rx) = mpsc::channel(capacity);
        Self {
            udp_buffer_size: inbound.selector().udp_buffer_size().max(512),
            idle_timeout: udp_idle_timeout(),
            inbound,
            flows: HashMap::new(),
            reply_tx,
            reply_rx,
        }
    }

    pub(crate) fn idle_timeout(&self) -> std::time::Duration {
        self.idle_timeout
    }

    pub(crate) fn subscribe_close_requests(&self) -> tokio::sync::broadcast::Receiver<TunFlowKey> {
        self.inbound.monitor().subscribe_close_requests()
    }

    pub(crate) async fn recv_reply(&mut self) -> Option<UdpReply> {
        self.reply_rx.recv().await
    }

    pub(crate) async fn handle_packet(
        &mut self,
        id: UdpFlowId,
        peer: Endpoint,
        target: Endpoint,
        payload: &[u8],
    ) -> Result<InboundUdpPacket> {
        if let Some(answer) = self.inbound.answer_datagram(&target, payload).await {
            return Ok(match answer {
                Ok(response) => InboundUdpPacket::Reply(response),
                Err(_) => InboundUdpPacket::Drop,
            });
        }

        let (datagram, flow) = if let Some(state) = self.flows.get_mut(&id) {
            state.last_seen = Instant::now();
            (Arc::clone(&state.datagram), state.key)
        } else {
            let source = peer.addr().ok_or_else(|| {
                yuhaiin_core::Error::invalid("inbound UDP peer has no IP address")
            })?;
            let opened = self
                .inbound
                .open_datagram(
                    self.inbound
                        .context_with_source(peer.clone(), target.clone()),
                    source,
                )
                .await?;
            let flow = opened.flow;
            let observed = self.inbound.observe_datagram(opened);
            let datagram = observed.datagram;
            let observation = observed._observation;
            let receiver = Arc::clone(&datagram);
            let reply_tx = self.reply_tx.clone();
            let id_for_task = id.clone();
            let udp_buffer_size = self.udp_buffer_size;
            let receiver_task = tokio::spawn(async move {
                let mut buffer = vec![0u8; udp_buffer_size];
                while let Ok((length, target)) = receiver.recv_from(&mut buffer).await {
                    if reply_tx
                        .send(UdpReply {
                            id: id_for_task.clone(),
                            target,
                            payload: buffer[..length].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            self.flows.insert(
                id.clone(),
                UdpFlowState {
                    datagram: Arc::clone(&datagram),
                    receiver_task,
                    key: flow,
                    peer,
                    last_seen: Instant::now(),
                    _observation: observation,
                },
            );
            (datagram, flow)
        };

        if let Err(error) = datagram.send_to(payload, target).await {
            if let Some(state) = self.flows.remove(&id) {
                shutdown_udp_flow(state).await;
            }
            return Err(error);
        }
        self.inbound
            .monitor()
            .bytes(flow, FlowDirection::Upload, payload.len());
        Ok(InboundUdpPacket::Forward { flow })
    }

    pub(crate) fn take_reply(&mut self, reply: UdpReply) -> Option<InboundUdpReply> {
        let state = self.flows.get_mut(&reply.id)?;
        state.last_seen = Instant::now();
        self.inbound
            .monitor()
            .bytes(state.key, FlowDirection::Download, reply.payload.len());
        Some(InboundUdpReply {
            id: reply.id,
            peer: state.peer.clone(),
            target: reply.target,
            payload: reply.payload,
            flow: state.key,
        })
    }

    pub(crate) async fn close_flow(&mut self, flow: TunFlowKey) {
        crate::proxy::common::close_udp_flows(&mut self.flows, flow).await;
    }

    pub(crate) async fn reap_expired(&mut self) {
        reap_expired_udp_flows_with_timeout(&mut self.flows, self.idle_timeout).await;
    }

    pub(crate) async fn shutdown(mut self) {
        for state in std::mem::take(&mut self.flows).into_values() {
            shutdown_udp_flow(state).await;
        }
    }
}

impl Drop for InboundUdpFlows {
    fn drop(&mut self) {
        // An adapter can leave through a transport error before reaching its
        // explicit async shutdown. Abort receiver tasks here so their cloned
        // datagrams do not outlive the inbound session.
        for state in self.flows.values() {
            state.receiver_task.abort();
        }
    }
}

pub(crate) struct InboundUdpSession<C> {
    codec: C,
    flows: InboundUdpFlows,
}

impl<C> InboundUdpSession<C>
where
    C: InboundUdpCodec,
{
    pub(crate) fn new(codec: C, inbound: Arc<InboundHandler>) -> Self {
        Self {
            codec,
            flows: InboundUdpFlows::new(inbound),
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        let mut close_events = self.flows.subscribe_close_requests();
        let idle_timeout = self.flows.idle_timeout();
        let mut idle_tick = tokio::time::interval(idle_timeout);
        let result = async {
            loop {
                let (codec, flows) = (&mut self.codec, &mut self.flows);
                tokio::select! {
                    received = codec.recv() => {
                        let Some(request) = received? else { break; };
                        let response = InboundUdpResponse {
                            id: request.id.clone(),
                            peer: request.peer.clone(),
                            target: request.target.clone(),
                            payload: Vec::new(),
                        };
                        match flows
                            .handle_packet(
                                request.id,
                                request.peer,
                                request.target,
                                &request.payload,
                            )
                            .await?
                        {
                            InboundUdpPacket::Reply(payload) => {
                                codec.send(InboundUdpResponse { payload, ..response }).await?;
                            }
                            InboundUdpPacket::Drop => {}
                            InboundUdpPacket::Forward { flow } => codec.note_flow(flow),
                        }
                    }
                    Some(reply) = flows.recv_reply() => {
                        if let Some(reply) = flows.take_reply(reply) {
                            codec.note_flow(reply.flow);
                            codec.send(reply.into_response()).await?;
                        }
                    }
                    close_event = close_events.recv() => {
                        match close_event {
                            Ok(flow) => {
                                let stop = codec.owns_flow(flow);
                                flows.close_flow(flow).await;
                                if stop {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = idle_tick.tick() => flows.reap_expired().await,
                }
            }
            Ok(())
        }
        .await;
        self.flows.shutdown().await;
        result
    }
}
