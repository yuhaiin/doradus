//! Trojan inbound listener protocol.
//!
//! Framing/authentication belongs to `yuhaiin-protocol`; this module only
//! connects an accepted request to the live route selector and monitor, just
//! like the HTTP/SOCKS/Yuubinsya inbound adapters.

use tokio::io::{AsyncRead, AsyncWrite};
use yuhaiin_protocol::trojan;

use crate::inbound::{InboundSpec, InboundUdpFlowPolicy};

pub(crate) fn password_hashes(spec: &InboundSpec) -> Vec<[u8; trojan::PASSWORD_HASH_LENGTH]> {
    spec.auth
        .as_ref()
        .map(|auth| {
            auth.inbound_passwords()
                .into_iter()
                .map(|password| trojan::password_hash(&password))
                .collect::<Vec<_>>()
        })
        .filter(|hashes| !hashes.is_empty())
        .unwrap_or_else(|| vec![trojan::password_hash(spec.password.as_bytes())])
}

impl<R, W> InboundUdpFlowPolicy for yuhaiin_protocol::trojan::UdpServer<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
}
