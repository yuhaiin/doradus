#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Platform TUN boundaries used by the yuhaiin TUN data plane.
//!
//! Unsafe code is intentionally isolated here.  Higher-level crates receive
//! safe owned handles and never manipulate raw descriptors or platform APIs.

pub use tun_rs::AsyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
pub use tun_rs::DeviceBuilder;

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
