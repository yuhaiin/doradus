//! Concrete proxy implementations built on the shared [`AsyncProxy`] contract.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use doradus_core::network::{
    bind_socket_to_interface, bind_tokio_udp_socket_for_target, connect_tokio_tcp_with_interface,
};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::stream_metadata::{with_stream_local_addr, with_stream_socket_addrs};
use doradus_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;
use tokio::time::Sleep;

mod datagrams;
mod direct;
mod drop;
mod socks5_client;
mod wrappers;

pub use direct::DirectAsyncProxy;
pub use drop::{DelayedDropAsyncProxy, DropAsyncProxy};
pub use socks5_client::Socks5AsyncProxy;
pub use wrappers::{BindInterfaceProxy, FallbackAsyncProxy, FixedAsyncProxy};

#[cfg(test)]
mod tests;
