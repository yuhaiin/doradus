#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Platform TUN boundaries used by the yuhaiin TUN data plane.
//!
//! Unsafe code is intentionally isolated here.  Higher-level crates receive
//! safe owned handles and never manipulate raw descriptors or platform APIs.

pub use tun_rs::AsyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
pub use tun_rs::DeviceBuilder;

/// Pick the same macOS utun name that the Go implementation uses before it
/// asks the kernel to create the device. `tun-rs` treats an explicit
/// `utunN` name as a fixed control-unit request, so passing a configured
/// `utun0` through unchanged fails when macOS already owns that unit.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn choose_macos_tun_name<'a>(
    configured_name: Option<&str>,
    existing_names: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut name = configured_name
        .filter(|name| name.starts_with("utun"))
        .unwrap_or("utun0")
        .to_owned();
    let mut requested_name_exists = false;
    let mut max_index = None;

    for existing_name in existing_names {
        if existing_name == name {
            requested_name_exists = true;
        }
        let Some(index) = existing_name
            .strip_prefix("utun")
            .and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };
        max_index = Some(max_index.map_or(index, |current: u32| current.max(index)));
    }

    if requested_name_exists {
        name = format!("utun{}", max_index.unwrap_or(0).saturating_add(1));
    }
    name
}

#[cfg(target_os = "macos")]
pub(crate) fn resolve_macos_tun_name(configured_name: Option<&str>) -> String {
    let existing_names = getifaddrs::getifaddrs()
        .map(|interfaces| {
            interfaces
                .map(|interface| interface.name)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    choose_macos_tun_name(configured_name, existing_names.iter().map(String::as_str))
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) fn next_macos_tun_name(name: &str) -> String {
    let index = name
        .strip_prefix("utun")
        .and_then(|suffix| suffix.parse::<u32>().ok())
        .unwrap_or(0);
    format!("utun{}", index.saturating_add(1))
}

#[cfg(unix)]
use std::os::fd::{IntoRawFd, OwnedFd};

/// Convert a host-owned TUN descriptor into the async device used by the
/// single Rust TUN data path.
///
/// The `OwnedFd` is consumed.  On success `tun-rs` owns the descriptor and
/// closes it with the returned device; on error its ownership has likewise
/// been transferred to the constructor boundary.  Callers must therefore
/// never close or reuse the descriptor after calling this function.
#[cfg(unix)]
pub fn async_device_from_owned_fd(fd: OwnedFd) -> std::io::Result<AsyncDevice> {
    let raw_fd = fd.into_raw_fd();
    // SAFETY: OwnedFd guarantees a valid open descriptor and transfers its
    // unique ownership exactly once to tun-rs::AsyncDevice.
    unsafe { AsyncDevice::from_fd(raw_fd) }
}

/// Bring the namespace-local loopback interface up.
///
/// This is used by disposable Linux smoke namespaces whose `--network=none`
/// loopback starts down. It is also a small safe platform boundary that can be
/// reused by future Linux integration fixtures without duplicating netlink
/// message construction in individual binaries.
#[cfg(target_os = "linux")]
pub fn enable_loopback() -> std::io::Result<()> {
    use netlink_packet_core::{
        NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    };
    use netlink_packet_route::{
        AddressFamily, RouteNetlinkMessage,
        link::{LinkFlags, LinkMessage},
    };
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

    let index = nix::net::if_::if_nametoindex("lo")
        .map_err(|error| std::io::Error::other(format!("find loopback interface: {error}")))?;
    let mut link = LinkMessage::default();
    link.header.interface_family = AddressFamily::Unspec;
    link.header.index = index;
    link.header.flags = LinkFlags::Up;
    link.header.change_mask = LinkFlags::Up;
    let mut packet = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::SetLink(link)),
    );
    packet.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    packet.header.sequence_number = 1;
    packet.finalize();
    let mut request = vec![0; packet.header.length as usize];
    packet.serialize(&mut request);

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    socket.send(&request, 0)?;

    let mut response = vec![0; 4096];
    loop {
        let size = socket.recv(&mut &mut response[..], 0)?;
        let mut offset = 0;
        while offset < size {
            let message =
                NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response[offset..size])
                    .map_err(|error| {
                        std::io::Error::other(format!("parse loopback response: {error}"))
                    })?;
            let length = message.header.length as usize;
            if length == 0 || offset.saturating_add(length) > size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid loopback netlink response length",
                ));
            }
            offset += length;
            if let NetlinkPayload::Error(error) = message.payload {
                return match error.code {
                    None => Ok(()),
                    Some(_) => Err(error.into()),
                };
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn enable_loopback() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{choose_macos_tun_name, next_macos_tun_name};

    #[test]
    fn macos_tun_name_defaults_to_utun0_when_free() {
        assert_eq!(choose_macos_tun_name(None, ["en0", "lo"]), "utun0");
    }

    #[test]
    fn macos_tun_name_uses_the_highest_existing_index_when_requested_name_exists() {
        assert_eq!(
            choose_macos_tun_name(Some("utun0"), ["utun0", "utun1", "utun3"]),
            "utun4"
        );
    }

    #[test]
    fn macos_tun_name_keeps_a_free_explicit_name() {
        assert_eq!(
            choose_macos_tun_name(Some("utun10"), ["utun0", "utun3"]),
            "utun10"
        );
    }

    #[test]
    fn macos_tun_name_normalizes_non_utun_names() {
        assert_eq!(
            choose_macos_tun_name(Some("tun0"), ["utun0", "utun2"]),
            "utun3"
        );
    }

    #[test]
    fn macos_tun_name_retry_advances_the_control_unit() {
        assert_eq!(next_macos_tun_name("utun4"), "utun5");
    }
}
