//! Yuubinsya session protocol boundaries.

#[path = "common.rs"]
mod common;
#[path = "observed_flow.rs"]
mod observed_flow;
#[path = "server_proxy.rs"]
mod server_proxy;
#[path = "server_udp_session.rs"]
mod server_udp_session;
#[path = "tcp.rs"]
mod tcp_impl;
#[path = "uot.rs"]
mod uot_impl;

pub use common::{MAX_UOT_COALESCE_BYTES, MAX_UOT_COALESCE_FRAMES, read_uot_frame};
pub use server_proxy::YuubinsyaServerProxy;
pub use tcp_impl::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
};
pub use uot_impl::{AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession};

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
