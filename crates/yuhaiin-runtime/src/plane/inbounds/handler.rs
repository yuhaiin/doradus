//! The common inbound boundary.
//!
//! Protocol listeners only decode their wire format.  Once a request has a
//! source and destination, this type owns the parts that are common to every
//! inbound: flow metadata, route selection, DNS policy, outbound creation,
//! accounting and relay lifetime.  This is the Rust equivalent of Go's
//! `inbound.Inbound` forwarding to one shared `netapi.Handler`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use yuhaiin_core::flow::{Flow as TunFlow, FlowKey as TunFlowKey, FlowObserver as TunFlowObserver};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, Network, Result};

use super::InboundSpec;
use crate::inbound::adapters::common::{
    record_outbound_datagram, record_outbound_stream, relay_counted_with_buffer,
    relay_counted_with_prefix_and_buffer,
};
use crate::{ConnectionMonitor, RuntimeProxySelector};

#[path = "handler_udp.rs"]
mod udp;

pub(crate) use udp::{
    InboundUdpCodec, InboundUdpManager, InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};

/// The single DNS boundary shared by every inbound protocol.
///
/// Go evaluates this predicate in inbound.Inbound before dispatching to a
/// protocol handler. Rust protocol adapters only own their wire framing and
/// call this policy; they must not each decide whether a packet is DNS.
pub(crate) use yuhaiin_types::inbound::InboundDnsHandler;

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
            && (destination_port == Some(53)
                || yuhaiin_core::dns::looks_like_supported_query(packet))
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

    pub(crate) async fn serve_stream<S>(
        &self,
        stream: S,
        peer: SocketAddr,
        protocol: &str,
        destination: Endpoint,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let target = destination.clone();
        let connection = self.open_stream(protocol, peer, destination).await?;
        let result = self.relay(stream, connection, peer).await;
        if let Err(error) = &result {
            self.monitor.error(format!(
                "relay failed protocol={protocol} peer={peer} target={target}: {error}"
            ));
        }
        result.map_err(|error| {
            yuhaiin_core::Error::new(yuhaiin_core::ErrorKind::Io, error.to_string())
        })
    }

    pub(crate) async fn serve_stream_with_prefix<S>(
        &self,
        stream: S,
        peer: SocketAddr,
        protocol: &str,
        destination: Endpoint,
        prefix: &[u8],
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let target = destination.clone();
        let connection = self.open_stream(protocol, peer, destination).await?;
        let result = self
            .relay_with_prefix(stream, connection, peer, prefix)
            .await;
        if let Err(error) = &result {
            self.monitor.error(format!(
                "relay failed protocol={protocol} peer={peer} target={target}: {error}"
            ));
        }
        result.map_err(|error| {
            yuhaiin_core::Error::new(yuhaiin_core::ErrorKind::Io, error.to_string())
        })
    }

    pub(crate) async fn open_datagram(
        &self,
        mut context: FlowContext,
        peer: SocketAddr,
    ) -> Result<InboundDatagram> {
        self.selector.route_context(&mut context);
        let target = context.effective_destination().to_string();
        let process = context.process.clone();
        let datagram = match self.selector.select(&context).open_datagram(&context).await {
            Ok(datagram) => datagram,
            Err(error) => {
                self.monitor.record_failure_with_process(
                    "udp",
                    &target,
                    &error.to_string(),
                    process.as_deref(),
                );
                return Err(error);
            }
        };
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

/// Runtime implementation of the protocol crate's stream hand-off port.
///
/// The protocol server has already authenticated and parsed the destination
/// when this is called.  From here on, route selection, outbound creation,
/// flow accounting and relay lifetime are runtime responsibilities.
impl yuhaiin_types::InboundStreamHandler<BoxAsyncStream> for InboundHandler {
    fn handle_stream<'a>(
        &'a self,
        stream: BoxAsyncStream,
        peer: SocketAddr,
        destination: Endpoint,
        protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.serve_stream(stream, peer, protocol, destination).await })
    }
}

impl<S> yuhaiin_types::InboundStreamHandler<yuhaiin_protocol::reverse_http::PrefixedIo<S>>
    for InboundHandler
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn handle_stream<'a>(
        &'a self,
        stream: yuhaiin_protocol::reverse_http::PrefixedIo<S>,
        peer: SocketAddr,
        destination: Endpoint,
        protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.serve_stream(stream, peer, protocol, destination).await })
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

/// Runtime-only flow lifecycle hooks.  A protocol codec must not depend on
/// the TUN flow key, but a stream-scoped inbound (currently VLESS) still needs
/// to close when its one outbound flow is closed.
pub(crate) trait InboundUdpFlowPolicy: InboundUdpCodec {
    fn note_flow(&mut self, _flow: TunFlowKey) {}

    fn owns_flow(&self, _flow: TunFlowKey) -> bool {
        false
    }
}
