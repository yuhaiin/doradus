//! DNS wire codec and a small UDP client/server boundary.
//!
//! Hickory handles DNS name compression, record encoding, and malformed packet
//! checks. The surrounding code owns timeout, routing, caching, and FakeIP
//! policy; this module deliberately does not hide those decisions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use futures_util::future::BoxFuture;
use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, Unknown,
};
use hickory_proto::rr::{
    Name, RData, RecordType,
    rdata::{A, AAAA, HTTPS, PTR, SVCB},
};

pub use crate::cache::{CachingDnsHandler, DnsCache};
use crate::{DomainName, Error, ErrorKind, IpSet, ResolveStrategy, Result};
pub use doradus_types::dns::{
    AsyncDnsHandler, DnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding, DnsServiceParam,
};

#[path = "dns_async_udp.rs"]
mod async_udp;
#[path = "dns_clients.rs"]
mod clients;
#[path = "dns_codec.rs"]
mod codec;
#[path = "dns_server.rs"]
mod server;

pub use async_udp::{AsyncUdpDnsClient, AsyncUdpDnsHandler, AsyncUdpDnsServer};
pub use clients::*;
pub use codec::*;
pub use server::*;

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
