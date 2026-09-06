//! Trojan inbound listener protocol.
//!
//! Framing/authentication belongs to `doradus-protocol`; this module only
//! connects an accepted request to the live route selector and monitor, just
//! like the HTTP/SOCKS/Yuubinsya inbound adapters.

use doradus_protocol::trojan;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::inbound::{InboundProtocolPlan, InboundSpec, InboundUdpFlowPolicy};

pub(crate) fn password_hashes_with_protocol_plan(
    spec: &InboundSpec,
    protocol: &InboundProtocolPlan,
) -> Vec<[u8; trojan::PASSWORD_HASH_LENGTH]> {
    spec.auth
        .as_ref()
        .map(|auth| {
            auth.inbound_passwords()
                .into_iter()
                .map(|password| trojan::password_hash(&password))
                .collect::<Vec<_>>()
        })
        .filter(|hashes| !hashes.is_empty())
        .unwrap_or_else(|| {
            let password = protocol.password().unwrap_or_default().as_bytes().to_vec();
            vec![trojan::password_hash(&password)]
        })
}

#[cfg(test)]
pub(crate) fn password_hashes(spec: &InboundSpec) -> Vec<[u8; trojan::PASSWORD_HASH_LENGTH]> {
    let protocol = InboundProtocolPlan::compile(&crate::inbound::InboundProtocolKind::Trojan, spec);
    password_hashes_with_protocol_plan(spec, &protocol)
}

impl<R, W> InboundUdpFlowPolicy for doradus_protocol::trojan::UdpServer<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
}
