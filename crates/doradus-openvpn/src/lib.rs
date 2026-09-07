//! OpenVPN 3 Core based stateful outbound support.
//!
//! OpenVPN Core runs with external transport and external TUN enabled: the
//! encrypted OpenVPN packets use a doradus-controlled UDP underlay while the
//! cleartext IP packets are exchanged with the shared smoltcp userspace stack.

mod config;
mod driver;
mod proxy;
mod transport;
mod tun;

pub use config::OpenVpnConfig;
pub use proxy::{OpenVpnProxy, build_proxy, build_proxy_with_interface_and_resolver};

fn error_openvpn(error: openvpn_connect::Error) -> doradus_core::Error {
    doradus_core::Error::new(doradus_core::ErrorKind::Io, error.to_string())
}
