//! QUIC transport for the raw async proxy boundary.
//!
//! QUIC streams carry the upper proxy protocol byte-for-byte. UDP packets use
//! QUIC DATAGRAM and a small association/fragments envelope. The envelope has
//! no address or authentication fields: those belong to the upper protocol
//! (Yuubinsya, for example), which keeps full-cone NAT semantics at the right
//! layer.

mod codec;
mod tls;

use tls::{
    build_client_tls_config, build_quinn_client_config, build_quinn_server_config, force_alpn,
};

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use doradus_core::network::bind_tokio_udp_socket_for_target;
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use doradus_metrics::RuntimeMetrics;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};

pub use codec::{
    DecodeError, EncodeError, EncodedDatagrams, FRAGMENT_HEADER_LEN, FRAGMENT_REASSEMBLY_TIMEOUT,
    FragmentReassembler, Frame, MAX_ASSOCIATION_ID, MAX_FRAGMENT_COUNT,
    MAX_INCOMPLETE_BYTES_PER_ASSOCIATION, MAX_INCOMPLETE_MESSAGES_PER_ASSOCIATION,
    MAX_REASSEMBLED_PAYLOAD, decode_frame, encode_datagrams, varint_len,
};

pub const ALPN: &[u8] = b"doradus-quic-v1";
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
pub const DEFAULT_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub const DEFAULT_MAX_ASSOCIATIONS: usize = 4096;
pub const DEFAULT_RX_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_RX_MEMORY_BUDGET: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicStats {
    pub datagrams_sent: usize,
    pub datagrams_received: usize,
    pub datagrams_dropped: usize,
    pub fragments_expired: usize,
}

#[derive(Debug, Default)]
struct StatsInner {
    datagrams_sent: AtomicUsize,
    datagrams_received: AtomicUsize,
    datagrams_dropped: AtomicUsize,
    fragments_expired: AtomicUsize,
    runtime: Option<Arc<RuntimeMetrics>>,
}

impl StatsInner {
    fn new(runtime: Option<Arc<RuntimeMetrics>>) -> Self {
        Self {
            runtime,
            ..Self::default()
        }
    }

    fn datagram_sent(&self) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        if let Some(runtime) = &self.runtime {
            runtime.quic_datagram_sent();
        }
    }

    fn datagram_received(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
        if let Some(runtime) = &self.runtime {
            runtime.quic_datagram_received();
        }
    }

    fn datagram_dropped(&self) {
        self.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
        if let Some(runtime) = &self.runtime {
            runtime.quic_datagram_dropped();
        }
    }

    fn fragments_expired(&self, count: usize) {
        self.fragments_expired.fetch_add(count, Ordering::Relaxed);
        if let Some(runtime) = &self.runtime {
            runtime.quic_fragments_expired(count as u64);
        }
    }

    fn queued_bytes_changed(&self, bytes: i64) {
        if let Some(runtime) = &self.runtime {
            runtime.change_quic_queued_bytes(bytes);
        }
    }

    fn snapshot(&self) -> QuicStats {
        QuicStats {
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_dropped: self.datagrams_dropped.load(Ordering::Relaxed),
            fragments_expired: self.fragments_expired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub server: SocketAddr,
    pub server_name: String,
    pub ca_certificates: Vec<Vec<u8>>,
    pub insecure_skip_verify: bool,
    pub timeout: Duration,
    pub idle_timeout: Duration,
    pub association_idle_timeout: Duration,
    pub max_associations: usize,
    pub rx_queue_capacity: usize,
    pub rx_memory_budget: usize,
}

impl QuicConfig {
    pub fn new(server: SocketAddr, server_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            server,
            server_name: server_name.into(),
            ca_certificates: Vec::new(),
            insecure_skip_verify: false,
            timeout,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            association_idle_timeout: DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
            rx_queue_capacity: DEFAULT_RX_QUEUE_CAPACITY,
            rx_memory_budget: DEFAULT_RX_MEMORY_BUDGET,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.server.port() == 0 {
            return Err(Error::invalid("QUIC server port must be non-zero"));
        }
        if self.server_name.trim().is_empty() {
            return Err(Error::invalid("QUIC server name must not be empty"));
        }
        if self.timeout.is_zero() || self.idle_timeout.is_zero() {
            return Err(Error::invalid("QUIC timeout must be greater than zero"));
        }
        if self.association_idle_timeout.is_zero()
            || self.max_associations == 0
            || self.rx_queue_capacity == 0
            || self.rx_memory_budget == 0
        {
            return Err(Error::invalid("QUIC resource limits must be non-zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct QuicServerConfig {
    pub idle_timeout: Duration,
    pub association_idle_timeout: Duration,
    pub max_associations: usize,
    pub rx_queue_capacity: usize,
    pub rx_memory_budget: usize,
}

impl Default for QuicServerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            association_idle_timeout: DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
            rx_queue_capacity: DEFAULT_RX_QUEUE_CAPACITY,
            rx_memory_budget: DEFAULT_RX_MEMORY_BUDGET,
        }
    }
}

impl QuicServerConfig {
    fn validate(&self) -> Result<()> {
        if self.idle_timeout.is_zero()
            || self.association_idle_timeout.is_zero()
            || self.max_associations == 0
            || self.rx_queue_capacity == 0
            || self.rx_memory_budget == 0
        {
            return Err(Error::invalid(
                "QUIC server resource limits must be non-zero",
            ));
        }
        Ok(())
    }
}

mod association;
mod client;
mod server;
mod stream;

pub use association::QuicDatagram;
pub use client::QuicProxy;
pub use server::{QuicServer, QuicServerConnection};
pub use stream::QuicStream;

#[cfg(test)]
mod tests;
