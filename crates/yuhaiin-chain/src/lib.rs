//! Runnable transport chain for the proxy configuration format.
//!
//! The crate keeps each protocol boundary explicit:
//!
//! ```text
//! Go chain[0] -> chain[1] -> ... -> chain[n]
//! ```
//!
//! TCP and UDP-over-TCP use the same HTTP/2 stream transport, but different
//! Yuubinsya sessions. This prevents the UDP framing and TCP byte stream from
//! being accidentally mixed into one "universal" connection type.

mod config;
mod go_node;

pub use config::{
    ChainConfig, ChainNode, ValidatedChain, ValidatedDirect, ValidatedFixedAddress,
    ValidatedFixedConfig, ValidatedHttp, ValidatedHttp2, ValidatedNode, ValidatedSocks5,
    ValidatedTls, ValidatedWebSocket, ValidatedYuubinsya, parse_config,
};
pub use go_node::parse_go_node;
pub use yuhaiin_protocol::YuubinsyaH2Server;
pub use yuhaiin_protocol::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaServerProxy,
};
pub use yuhaiin_protocol::{H2Connection, H2PoolStats};

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, Notify, watch};
use tokio_rustls::TlsConnector;
use yuhaiin_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, BindInterfaceProxy, BoxAsyncStream, DirectAsyncProxy,
    FixedAsyncProxy, stream_local_addr, with_stream_local_addr,
};
use yuhaiin_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, ResolveStrategy, Result,
};

use yuhaiin_protocol::direct_uot::{DirectUotProxy, parse_go_direct_uot};
use yuhaiin_protocol::session::{MAX_UOT_COALESCE_BYTES, MAX_UOT_COALESCE_FRAMES, read_uot_frame};
use yuhaiin_protocol::yuubinsya::derive_salt;
use yuhaiin_protocol::{H2Pool, H2PoolEndpoint};

mod chain_client;
mod chain_proxy;
mod chain_transports;
mod chain_uot;

pub use chain_client::ChainClient;
pub use chain_proxy::ChainProxy;
#[cfg(test)]
use chain_transports::root_store;
#[cfg(test)]
use chain_uot::{ChainUotSession, PendingUotDatagram, RetryQueue};

/// A single best-effort runtime observation for the reusable chain client.
/// The pool counters are monotonic, while connection/stream counts describe
/// the instant at which this snapshot was taken.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainRuntimeStats {
    pub h2_connections: usize,
    pub h2_active_streams: usize,
    pub h2_pool: H2PoolStats,
}

impl ChainRuntimeStats {
    /// Render a dependency-free Prometheus text snapshot.
    ///
    /// This is intentionally a pure pull-format encoder: the embedding app
    /// owns the HTTP endpoint, logging cadence, labels and authentication.
    /// No listener, task or global registry is created by the transport crate.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP yuhaiin_chain_h2_connections Current live HTTP/2 connections.\n\
# TYPE yuhaiin_chain_h2_connections gauge\n\
yuhaiin_chain_h2_connections {}\n\
# HELP yuhaiin_chain_h2_active_streams Current active HTTP/2 CONNECT streams.\n\
# TYPE yuhaiin_chain_h2_active_streams gauge\n\
yuhaiin_chain_h2_active_streams {}\n\
# HELP yuhaiin_chain_h2_connection_attempts Total HTTP/2 connection attempts.\n\
# TYPE yuhaiin_chain_h2_connection_attempts counter\n\
yuhaiin_chain_h2_connection_attempts {}\n\
# HELP yuhaiin_chain_h2_connection_failures Total HTTP/2 connection failures.\n\
# TYPE yuhaiin_chain_h2_connection_failures counter\n\
yuhaiin_chain_h2_connection_failures {}\n\
# HELP yuhaiin_chain_h2_stream_capacity_rejections Total stream-capacity rejections.\n\
# TYPE yuhaiin_chain_h2_stream_capacity_rejections counter\n\
yuhaiin_chain_h2_stream_capacity_rejections {}\n\
# HELP yuhaiin_chain_h2_stream_open_failures Total CONNECT stream open failures.\n\
# TYPE yuhaiin_chain_h2_stream_open_failures counter\n\
yuhaiin_chain_h2_stream_open_failures {}\n",
            self.h2_connections,
            self.h2_active_streams,
            self.h2_pool.connection_attempts,
            self.h2_pool.connection_failures,
            self.h2_pool.stream_capacity_rejections,
            self.h2_pool.stream_open_failures,
        )
    }
}

const PING_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_UOT_RETRY_BYTES: usize = 256 * 1024;
const MAX_UOT_RETRY_FRAMES: usize = 128;
const MAX_UOT_RECONNECT_ATTEMPTS: usize = 3;

const TRANSPORT_ENDPOINT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
