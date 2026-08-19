use std::net::SocketAddr;
use std::sync::Arc;

use yuhaiin_chain::{YuubinsyaDnsHandler, YuubinsyaServerProxy};
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, Result};
use yuhaiin_protocol::yuubinsya::derive_salt;
use yuhaiin_protocol::yuubinsya_udp::YuubinsyaUdpServer;

use super::common::{RoutedProxy, UdpFlowId};
use crate::RuntimeProxySelector;
use crate::inbound::{
    InboundDnsHandler, InboundDnsPolicy, InboundHandler, InboundSpec, InboundUdpCodec,
    InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};

pub(crate) fn new_server(
    spec: &InboundSpec,
    selector: Arc<RuntimeProxySelector>,
) -> Option<Arc<YuubinsyaServerProxy>> {
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let upstream: Arc<dyn AsyncProxy> = Arc::new(RoutedProxy { selector });
    let password_hashes = if let Some(auth) = spec.auth.as_ref() {
        auth.inbound_passwords()
            .into_iter()
            .map(|password| derive_salt(&password))
            .collect::<Vec<_>>()
    } else {
        vec![derive_salt(spec.password.as_bytes())]
    };
    if password_hashes.is_empty() {
        return None;
    }
    Some(Arc::new(
        YuubinsyaServerProxy::new_with_password_hashes_and_udp_buffer_size(
            password_hashes,
            upstream,
            udp_buffer_size,
        ),
    ))
}

impl YuubinsyaDnsHandler for InboundDnsPolicy {
    fn should_hijack(&self, destination_port: Option<u16>, packet: &[u8]) -> bool {
        InboundDnsHandler::should_hijack(self, destination_port, packet)
    }

    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            InboundDnsHandler::answer(self, packet)
                .await
                .ok_or_else(|| {
                    Error::new(yuhaiin_core::ErrorKind::Closed, "DNS hijacking disabled")
                })?
        })
    }
}

pub(crate) async fn handle(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let server = new_server(inbound.spec(), Arc::clone(inbound.selector())).ok_or_else(|| {
        Error::new(
            yuhaiin_core::ErrorKind::Unsupported,
            "Yuubinsya inbound has no concrete password hash",
        )
    })?;
    handle_with_server(stream, peer, inbound, server).await
}

pub(crate) async fn handle_with_server(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
    server: Arc<YuubinsyaServerProxy>,
) -> Result<()> {
    let annotate = inbound.spec().clone();
    let route = Arc::clone(inbound.selector());
    let monitor = Arc::clone(inbound.monitor());
    let dns_handler = monitor
        .dns_hijack_enabled()
        .then(|| Arc::new(inbound.dns_policy()) as Arc<dyn YuubinsyaDnsHandler>);
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

pub(crate) async fn handle_udp(
    server: YuubinsyaUdpServer,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let codec = YuubinsyaUdpCodec {
        server,
        packet: vec![0u8; inbound.selector().udp_buffer_size().max(512)],
    };
    InboundUdpSession::new(codec, inbound).run().await
}

struct YuubinsyaUdpCodec {
    server: YuubinsyaUdpServer,
    packet: Vec<u8>,
}

impl InboundUdpCodec for YuubinsyaUdpCodec {
    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let (length, target, peer, password_hash) = self
                .server
                .recv_from_authenticated(&mut self.packet)
                .await?;
            let peer_addr = peer
                .addr()
                .ok_or_else(|| Error::invalid("Yuubinsya UDP peer has no IP address"))?;
            Ok(Some(InboundUdpRequest {
                id: UdpFlowId {
                    peer: peer_addr,
                    target: target.clone(),
                    authentication: Some(password_hash),
                },
                peer,
                target,
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let password_hash = response
                .id
                .authentication
                .ok_or_else(|| Error::invalid("Yuubinsya UDP response has no password hash"))?;
            self.server
                .send_to_with_password_hash(
                    &response.payload,
                    response.target,
                    response.peer,
                    password_hash,
                )
                .await?;
            Ok(())
        })
    }
}
