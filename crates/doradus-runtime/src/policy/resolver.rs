//! Runtime resolver transport selection.
//!
//! The registry keeps transport construction separate from configuration
//! loading.  UDP, TCP and system DNS have safe built-ins; encrypted transports
//! are intentionally injected by the platform/application because their
//! connector, trust store and bootstrap policy are deployment-specific.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

#[cfg(feature = "http2")]
use std::marker::PhantomData;

use doradus_core::dns::AsyncUdpDnsClient;
use doradus_core::dns::{
    DnsCache, DnsRecordType, DnsResponse, decode_response, encode_query, response_is_truncated,
    validate_query_packet, validate_response_packet,
};
use doradus_core::dns_resolver::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery, SystemAsyncIpResolver,
};
use doradus_core::dns_tcp::AsyncTcpDnsClient;
use doradus_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use doradus_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network,
    ResolveStrategy, Result, RouteMode,
};
use doradus_store::{GoResolverRuntimeConfig, GoResolverTransport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::ConnectionMonitor;

#[cfg(feature = "http2")]
use doradus_core::dns_http::{DnsOverHttp, DnsOverHttpConnector};
#[cfg(all(feature = "http2", test))]
use doradus_core::dns_http::{HttpConnection, HttpVersion};
#[cfg(feature = "doh-tls")]
use doradus_dns::{
    DnsIoStream, DnsStreamConnector, DnsTlsResolverConfig, DohResolverFactory, DotResolverFactory,
};

pub trait ResolverTransportFactory: Send + Sync {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>>;

    /// Build a resolver while honoring the runtime's selected source
    /// addresses. Existing custom factories remain source-compatible and can
    /// opt in only when their transport owns a direct socket dialer.
    fn build_with_policy(
        &self,
        config: &GoResolverRuntimeConfig,
        _local_bind_addresses: &[IpAddr],
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build(config)
    }

    /// Build a resolver with both the source-address fallback and the
    /// interface policy used by runtime-owned outbound sockets. The default
    /// keeps third-party factories source-compatible; built-in transports
    /// override it because they own their sockets.
    fn build_with_policy_and_interface(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
        _bind_interface: Option<&str>,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy(config, local_bind_addresses)
    }
}

#[path = "resolver_bridge.rs"]
mod resolver_bridge;
#[path = "resolver_builtin.rs"]
mod resolver_builtin;
#[path = "resolver_encrypted.rs"]
mod resolver_encrypted;

pub use resolver_bridge::ResolverProxyBridge;
pub use resolver_builtin::{
    BuiltinResolverFactory, ResolverFailurePolicy, TimeoutResolver, parse_dns_server,
};
#[cfg(feature = "http2")]
pub use resolver_encrypted::DnsOverHttpResolverFactory;
#[cfg(feature = "doh-tls")]
pub use resolver_encrypted::{RustlsDohResolverFactory, RustlsDotResolverFactory};

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
