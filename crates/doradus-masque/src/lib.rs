//! Cloudflare WARP MASQUE (`cf-connect-ip`) outbound support.
//!
//! The crate uses Cloudflare's low-level quiche QUIC/HTTP/3 stack so the
//! WARP-specific `cf-connect-ip` protocol token can be sent as a raw header.
//! A connection is created lazily on the first flow and discarded after a
//! transport failure. The next flow starts a new session.

mod codec;
mod config;
mod proxy;
mod tls;

pub use config::WarpMasqueConfig;
pub use proxy::{
    WarpMasqueProxy, build_proxy, build_proxy_with_interface,
    build_proxy_with_interface_and_resolver,
};
