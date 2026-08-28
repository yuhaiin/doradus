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
pub use doradus_protocol::YuubinsyaH2Server;
pub use doradus_protocol::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaServerProxy,
};
pub use doradus_protocol::{H2Connection, H2PoolStats};
pub use go_node::parse_go_node;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use doradus_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use doradus_core::network::{HappyEyeballsV2Dialer, TcpDialCandidate};
use doradus_core::proxy::{
    AsyncDatagram, AsyncProxy, BoxAsyncStream, stream_local_addr, with_stream_local_addr,
};
use doradus_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, ResolveStrategy, Result,
};
use doradus_protocol::proxy::{
    BindInterfaceProxy, DirectAsyncProxy, FixedAsyncProxy, HappyEyeballsTcpProxy,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, Notify, watch};
use tokio_rustls::TlsConnector;

use doradus_protocol::direct_uot::{DirectUotProxy, parse_go_direct_uot};
use doradus_protocol::session::{MAX_UOT_COALESCE_BYTES, MAX_UOT_COALESCE_FRAMES, read_uot_frame};
use doradus_protocol::yuubinsya::derive_salt;
use doradus_protocol::{H2Pool, H2PoolEndpoint};

mod chain_client;
mod chain_proxy;
mod chain_transports;
mod chain_uot;

pub use chain_client::ChainClient;
pub use chain_proxy::ChainProxy;
#[cfg(test)]
use chain_transports::root_store;
#[cfg(test)]
use chain_uot::{ChainDatagram, ChainUotSession, PendingUotDatagram, RetryQueue};

/// A single best-effort runtime observation for the reusable chain client.
/// The pool counters are monotonic, while connection/stream counts describe
/// the instant at which this snapshot was taken.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainRuntimeStats {
    pub h2_connections: usize,
    pub h2_active_streams: usize,
    pub h2_pool: H2PoolStats,
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
