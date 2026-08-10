//! Small platform boundaries shared by the safe runtime crates.
//!
//! Unsafe code is intentionally isolated here.  Higher-level crates receive
//! safe owned handles and never manipulate raw descriptors or platform APIs.

#[cfg(feature = "tun")]
pub use tun_rs::AsyncDevice;
#[cfg(all(
    feature = "tun",
    not(any(target_os = "android", target_os = "ios", target_os = "tvos"))
))]
pub use tun_rs::DeviceBuilder;

#[cfg(all(feature = "tun", unix))]
use std::os::fd::{IntoRawFd, OwnedFd};

/// Convert a host-owned TUN descriptor into the async device used by the
/// single Rust TUN data path.
///
/// The `OwnedFd` is consumed.  On success `tun-rs` owns the descriptor and
/// closes it with the returned device; on error its ownership has likewise
/// been transferred to the constructor boundary.  Callers must therefore
/// never close or reuse the descriptor after calling this function.
#[cfg(all(feature = "tun", unix))]
pub fn async_device_from_owned_fd(fd: OwnedFd) -> std::io::Result<AsyncDevice> {
    let raw_fd = fd.into_raw_fd();
    // SAFETY: OwnedFd guarantees a valid open descriptor and transfers its
    // unique ownership exactly once to tun-rs::AsyncDevice.
    unsafe { AsyncDevice::from_fd(raw_fd) }
}
