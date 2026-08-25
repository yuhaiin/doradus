//! Unified synchronous DNS resolver facade.
//!
//! UDP, TCP and DoH keep their own transport implementations.  This module
//! composes them behind one `DnsHandler` implementation so Router/TUN code can
//! select a resolver without knowing its wire protocol.  DoH remains injected
//! through [`crate::dns::DohTransport`], which keeps proxy/TLS ownership out of
//! the DNS core.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;

#[cfg(target_os = "windows")]
use crate::dns::decode_response;
use crate::dns::{
    AsyncDnsHandler, AsyncUdpDnsClient, DnsCache, DnsHandler, DnsRecordType, DnsResponse,
    DohClient, DohTransport, UdpDnsClient, decode_query, decode_raw_query_key, encode_response,
    rewrite_dns_response_for_query, validate_query_packet,
};
use crate::dns_tcp::TcpDnsClient;
use crate::{BoxFuture, DomainName, IpSet, LocalBoxFuture, ResolveStrategy, Result};
pub use yuhaiin_types::dns::AsyncIpResolver;

#[path = "dns_resolver_async.rs"]
mod asynchronous;
#[path = "dns_resolver_sync.rs"]
mod sync;
#[path = "dns_resolver_system.rs"]
mod system;
#[path = "dns_resolver_traits.rs"]
mod traits;

pub use asynchronous::AsyncDnsResolver;
pub use sync::{DnsResolver, ResolverTransport};
pub use system::SystemAsyncIpResolver;
#[allow(unused_imports)]
pub(crate) use system::resolve_internet_addresses;
pub(crate) use system::resolve_internet_server;
pub use traits::{AsyncDnsQuery, SendAsyncDnsQuery};

#[cfg(test)]
#[path = "dns_resolver_async_tests.rs"]
mod async_tests;
#[cfg(test)]
#[path = "dns_resolver_sync_tests.rs"]
mod tests;
