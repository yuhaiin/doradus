//! Reusable proxy protocol codecs and async adapters.
//!
//! Protocols live here instead of in the management/runtime crate.  The
//! runtime owns listener policy and flow metadata; this crate owns bytes on
//! the wire and wrappers which can be composed around an [`AsyncProxy`].

pub mod aead;
pub mod direct_uot;
pub mod direct_uot_session;
pub mod h2_server;
pub mod h2_tunnel;
pub mod http;
pub mod http_mock;
pub mod http_obfs;
pub mod http_server;
pub mod proxy_factory;
pub mod reverse_http;
pub mod session;
pub mod shadowsocks;
pub mod shadowsocksr;
pub mod socks4a_server;
pub mod socks5;
pub mod socks5_server;
#[cfg(feature = "tls-ring")]
pub mod tls;
#[cfg(feature = "tls-ring")]
mod tls_sync;
pub mod trojan;
pub mod vless;
pub mod vmess;
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "websocket")]
mod websocket_io;
#[cfg(feature = "websocket")]
pub mod websocket_server;
pub mod yuubinsya;
pub mod yuubinsya_udp;

pub use h2_server::YuubinsyaH2Server;
pub use h2_tunnel::{H2Connection, H2Pool, H2PoolEndpoint, H2PoolStats, send_h2_data};
pub use session::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaDnsHandler,
    YuubinsyaServerProxy,
};
pub use yuubinsya_udp::{YuubinsyaUdpDatagram, YuubinsyaUdpProxy, YuubinsyaUdpServer};
