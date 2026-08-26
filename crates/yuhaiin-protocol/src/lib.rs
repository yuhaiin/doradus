//! Reusable proxy protocol implementations and async transport adapters.

pub mod composition;
pub mod protocols;
pub mod proxy;
pub mod servers;
pub mod transports;

// Root re-exports keep call sites focused on the protocol name while the
// implementation is organized by responsibility on disk.
pub use composition::base_proxy as proxy_factory;
pub use protocols::{
    aead, http, http_mock, http_obfs, shadowsocks, shadowsocksr, socks5, trojan, vless, vmess,
};
#[cfg(target_os = "linux")]
pub use servers::transparent;
pub use servers::{
    http as http_server, reverse_http, socks4a as socks4a_server, socks5 as socks5_server,
};
pub use transports::h2::{
    H2Connection, H2Pool, H2PoolEndpoint, H2PoolStats, YuubinsyaH2Server, server as h2_server,
    tunnel as h2_tunnel,
};
pub use transports::stream;
#[cfg(feature = "tls-ring")]
pub use transports::tls::{self, auto as tls_auto, server as tls_server};
#[cfg(feature = "websocket")]
pub use transports::websocket;
#[cfg(feature = "websocket")]
pub use transports::websocket::server as websocket_server;
pub use transports::yuubinsya;
pub use transports::yuubinsya::direct_uot;
pub use transports::yuubinsya::direct_uot_session;
pub use transports::yuubinsya::session;
pub use transports::yuubinsya::udp as yuubinsya_udp;
pub use transports::yuubinsya::udp::{YuubinsyaUdpDatagram, YuubinsyaUdpProxy, YuubinsyaUdpServer};

pub use transports::yuubinsya::session::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaServerProxy,
};
