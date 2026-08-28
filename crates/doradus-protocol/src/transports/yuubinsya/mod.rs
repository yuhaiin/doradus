//! Yuubinsya transport protocol implementations.

mod codec;
pub use codec::*;

pub mod direct_uot;
pub mod direct_uot_session;
pub mod over_transport;
pub mod session;
pub mod udp;

pub use over_transport::YuubinsyaOverTransportProxy;
pub use session::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession,
};
pub use udp::{YuubinsyaUdpDatagram, YuubinsyaUdpProxy, YuubinsyaUdpServer};

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
