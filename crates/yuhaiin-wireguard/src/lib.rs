//! Cloudflare BoringTun based WireGuard outbound support.
//!
//! BoringTun intentionally stops at the WireGuard protocol boundary. This
//! crate supplies the missing yuhaiin adapter: a small smoltcp IP stack feeds
//! packets to BoringTun and exposes TCP/UDP sockets through `AsyncProxy`.
//! The OS-facing TUN implementation remains in `yuhaiin-core`; this is the
//! virtual stack required for a WireGuard *outbound* node.

use std::sync::atomic::AtomicU32;

const DEFAULT_MTU: usize = 1_420;
const DEFAULT_QUEUE_CAPACITY: usize = 256;
const SOCKET_BUFFER_SIZE: usize = 64 * 1024;
const WIREGUARD_OVERHEAD: usize = 32;
const HANDSHAKE_BUFFER_SIZE: usize = 2_048;
const MAX_PACKET_SIZE: usize = 65_535;
const MAX_STREAM_OUTPUT_BYTES: usize = SOCKET_BUFFER_SIZE * 4;
const MAX_PENDING_IP_PACKETS: usize = 256;
const PORT_MIN: u16 = 32_768;
const PORT_MAX: u16 = 60_000;
static NEXT_TUNNEL_INDEX: AtomicU32 = AtomicU32::new(1);

mod config;
mod driver;
mod engine;
mod proxy;

pub use config::{WireGuardConfig, WireGuardPeerConfig};
pub use engine::WireGuardEngine;
pub use proxy::{
    WireGuardProxy, build_proxy, build_proxy_with_interface,
    build_proxy_with_interface_and_resolver,
};

#[cfg(test)]
mod tests;
