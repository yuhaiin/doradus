//! Async DNS resolver composition and system resolver adapters.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Notify;

use crate::dns::{AsyncDnsHandler, AsyncUdpDnsClient, DnsCache, DnsRecordType, DnsResponse};
use crate::{BoxFuture, DomainName, IpSet, LocalBoxFuture, ResolveStrategy, Result};
pub use doradus_types::dns::AsyncIpResolver;

#[path = "dns_resolver_async.rs"]
mod asynchronous;
#[path = "dns_resolver_system.rs"]
mod system;
#[path = "dns_resolver_traits.rs"]
mod traits;

pub use asynchronous::AsyncDnsResolver;
pub use system::SystemAsyncIpResolver;
#[allow(unused_imports)]
pub(crate) use system::resolve_internet_addresses;
pub(crate) use system::resolve_internet_server;
pub use traits::{AsyncDnsQuery, SendAsyncDnsQuery};

#[cfg(test)]
#[path = "dns_resolver_async_tests.rs"]
mod async_tests;
