//! Shared runtime data-plane owners.
//!
//! The binary is only one host for the runtime.  Android `VpnService`, iOS
//! `PacketTunnelProvider`, and future embedders can create their platform TUN
//! device themselves and hand the owned [`TunRuntime`] to the same runner.

#[cfg(all(
    feature = "tun",
    feature = "tun-routes",
    any(target_os = "linux", target_os = "macos")
))]
use std::net::IpAddr;
#[cfg(feature = "tun")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::dns_tcp::AsyncTcpDnsServer;
use yuhaiin_core::{BoxFuture, Result, RouteMode};
#[cfg(feature = "tun")]
use yuhaiin_core::{Error, ErrorKind};
#[cfg(feature = "tun")]
use yuhaiin_store::GoInboundRecord;

use crate::{RuntimeController, RuntimeSnapshot, parse_dns_server};

const DEFAULT_DNS_SERVER: &str = "127.0.0.1:5353";

#[cfg(feature = "tun")]
fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[path = "data_plane_dns.rs"]
mod dns;
#[path = "data_plane_supervisor.rs"]
mod supervisor;
#[path = "data_plane_tun.rs"]
mod tun;

use dns::LoggedDnsHandler;
pub use dns::RuntimeDnsHandler;
pub(crate) use dns::{ReloadableAsyncDnsHandler, inbound_dns_handler};
#[cfg(all(test, feature = "tun"))]
use supervisor::configured_dns_server;
#[allow(unused_imports)]
pub use supervisor::{
    run_dns_supervisor, wait_for_shutdown_or_dns_reload, wait_for_shutdown_or_inbound_reload,
    wait_for_shutdown_or_matching_inbound_reload, wait_for_shutdown_or_reload,
};
#[cfg(feature = "tun")]
pub use supervisor::{run_tun_device_until, run_tun_device_until_ref};
#[cfg(all(feature = "tun", test))]
use tun::tun_dns_servers;
#[cfg(all(test, feature = "tun"))]
use tun::{
    DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE, DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE,
    DEFAULT_TUN_UDP_PACKET_CAPACITY, select_go_tun_record,
};
#[cfg(feature = "tun")]
pub use tun::{TunRuntimeConfig, load_tun_config};
#[cfg(feature = "tun")]
pub(crate) use tun::{load_tun_config_for_supervisor, load_tun_configs_for_desktop, open_tun};

#[cfg(all(test, feature = "tun"))]
#[path = "data_plane_tests.rs"]
mod tests;
