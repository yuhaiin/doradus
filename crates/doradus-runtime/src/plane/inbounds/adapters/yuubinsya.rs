use std::sync::Arc;

use doradus_chain::YuubinsyaServerProxy;
use doradus_core::Result;
use doradus_core::proxy::AsyncProxy;
use doradus_protocol::yuubinsya::derive_salt;
use doradus_protocol::yuubinsya_udp::YuubinsyaUdpServer;

use super::common::RoutedProxy;
use crate::RuntimeProxySelector;
use crate::inbound::{InboundHandler, InboundSpec, InboundUdpFlowPolicy, InboundUdpSession};

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

pub(crate) async fn handle_udp(
    server: YuubinsyaUdpServer,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let codec = doradus_protocol::yuubinsya_udp::InboundUdpServer::new(
        server,
        inbound.selector().udp_buffer_size(),
    );
    InboundUdpSession::new(codec, inbound).run().await
}

impl InboundUdpFlowPolicy for doradus_protocol::yuubinsya_udp::InboundUdpServer {}
