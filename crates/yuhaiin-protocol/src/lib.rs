//! Reusable proxy protocol codecs and async adapters.
//!
//! Protocols live here instead of in the management/runtime crate.  The
//! runtime owns listener policy and flow metadata; this crate owns bytes on
//! the wire and wrappers which can be composed around an [`AsyncProxy`].

pub mod aead;
pub mod http;
pub mod http_obfs;
pub mod shadowsocks;
pub mod shadowsocksr;
pub mod socks5;
#[cfg(feature = "tls-rustcrypto")]
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod vmess;
#[cfg(feature = "websocket")]
pub mod websocket;
