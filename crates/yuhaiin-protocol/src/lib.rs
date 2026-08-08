//! Reusable proxy protocol codecs and async adapters.
//!
//! Protocols live here instead of in the management/runtime crate.  The
//! runtime owns listener policy and flow metadata; this crate owns bytes on
//! the wire and wrappers which can be composed around an [`AsyncProxy`].

pub mod shadowsocks;
#[cfg(feature = "tls-rustcrypto")]
pub mod tls;
pub mod trojan;
pub mod vless;
