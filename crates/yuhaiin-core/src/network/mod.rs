//! Runtime-independent networking helpers shared by proxy implementations.

/// Internal marker used by the runtime for Go's `useDefaultInterface` mode.
/// It is resolved to the current physical default-route interface immediately
/// before each outbound socket is bound.
pub const DEFAULT_INTERFACE: &str = "__yuhaiin_default_interface__";

mod socket;

pub use socket::{
    bind_socket_to_interface, bind_tokio_udp_socket_for_target, connect_tokio_tcp,
    connect_tokio_tcp_with_interface, interface_for_address,
};
#[cfg(target_os = "linux")]
pub use socket::{default_route_interface_v4, default_route_interface_v6};
