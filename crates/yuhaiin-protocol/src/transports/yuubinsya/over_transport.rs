use std::sync::Arc;

use super::AsyncYuubinsyaTcpSession;
use super::udp::YuubinsyaUdpDatagram;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, FlowContext, Result};

/// Yuubinsya destination-protocol adapter over a raw transport.
///
/// The parent owns the carrier connection. This adapter only adds Yuubinsya's
/// authentication and logical destination framing, so a QUIC parent can carry
/// both transparent TCP streams and full-cone UDP packets without putting
/// proxy addresses into the QUIC envelope.
pub struct YuubinsyaOverTransportProxy {
    upstream: Arc<dyn AsyncProxy>,
    password_hash: [u8; 32],
    server: Endpoint,
    socks5_prefix: bool,
}

impl YuubinsyaOverTransportProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
    ) -> Result<Self> {
        if server.network() != yuhaiin_core::Network::Udp || server.addr().is_none() {
            return Err(Error::invalid(
                "Yuubinsya transport server must be an IP UDP endpoint",
            ));
        }
        Ok(Self {
            upstream,
            password_hash,
            server,
            socks5_prefix,
        })
    }
}

impl AsyncProxy for YuubinsyaOverTransportProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            if context.network != yuhaiin_core::Network::Tcp {
                return Err(Error::invalid(
                    "Yuubinsya TCP transport requires a TCP flow",
                ));
            }
            let stream = self.upstream.connect(context).await?;
            let session = AsyncYuubinsyaTcpSession::connect(
                stream,
                self.password_hash,
                context.effective_destination(),
            )
            .await?;
            Ok(Box::new(session) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            if context.network != yuhaiin_core::Network::Udp {
                return Err(Error::invalid(
                    "Yuubinsya UDP transport requires a UDP flow",
                ));
            }
            let transport = self.upstream.open_datagram(context).await?;
            Ok(Box::new(YuubinsyaUdpDatagram::new(
                transport,
                self.password_hash,
                self.server.clone(),
                self.socks5_prefix,
            )?) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}
