//! DNS wire format, cache, resolver composition and transports.
//!
//! This crate deliberately does not depend on `yuhaiin-core`: proxy, TUN and
//! NAT code consume the DNS traits, while DNS transports remain reusable by
//! those higher layers without creating a dependency cycle.

pub use yuhaiin_types::{
    BoxFuture, DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result,
};

pub mod fakeip;
pub use fakeip::{
    FakeIpConfig, FakeIpPolicy, FakeIpPoolOptions, FakeIpV6Config, FakeIpView, FakeIpViewStore,
    reverse_name_to_ip,
};

pub mod dns;
pub use dns::*;
pub mod dns_hosts;
#[cfg(feature = "async-proxy")]
pub use dns_hosts::AsyncHostsDnsHandler;
pub use dns_hosts::{
    HostsDispatchTarget, HostsDnsHandler, HostsTable, HostsTarget, host_without_port,
};
pub mod dns_resolver;
pub use dns_resolver::{DnsResolver, ResolverTransport};
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_async;
#[cfg(feature = "async-proxy")]
pub use dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery, SystemAsyncIpResolver,
};
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_stack;
#[cfg(feature = "async-proxy")]
pub use dns_resolver_stack::AsyncHostsResolver;
#[cfg(feature = "async-proxy")]
mod dns_datagram;
#[cfg(feature = "async-proxy")]
pub use dns_datagram::{AsyncDnsDatagram, DnsDatagramConnector, probe_dns_udp};
pub mod dns_tcp;
pub use dns_tcp::{TcpDnsClient, TcpDnsServer};
#[cfg(feature = "async-proxy")]
pub mod dns_tcp_async;
#[cfg(feature = "async-proxy")]
pub use dns_tcp_async::{AsyncTcpDnsClient, AsyncTcpDnsHandler, AsyncTcpDnsServer};
#[cfg(feature = "async-proxy")]
pub mod dns_udp_async;
#[cfg(feature = "async-proxy")]
pub use dns_udp_async::{AsyncUdpDnsClient, AsyncUdpDnsHandler, AsyncUdpDnsServer};
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "http2")]
pub use http2::{H2DohClient, H2DohConnector, H2DohDnsHandler};
#[cfg(feature = "quic")]
pub mod dns_quic;
#[cfg(feature = "quic")]
pub use dns_quic::{DoqResolverConfig, DoqResolverFactory, probe_doq, query_doq};
#[cfg(feature = "tls")]
pub mod dns_tls;
#[cfg(feature = "tls")]
pub use dns_tls::{
    DnsIoStream, DnsStreamConnector, DnsTlsConnector, DnsTlsResolverConfig, DohResolverFactory,
    DotResolverFactory, RustCryptoH2Connector, RustCryptoTlsConnector, webpki_client_config,
};
#[cfg(feature = "async-proxy")]
mod transport;
