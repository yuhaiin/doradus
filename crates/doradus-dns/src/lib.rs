//! DNS wire format, cache, resolver composition and transports.
//!
//! This crate deliberately does not depend on `doradus-core`: proxy, TUN and
//! NAT code consume the DNS traits, while DNS transports remain reusable by
//! those higher layers without creating a dependency cycle.

pub use doradus_types::{
    BoxFuture, DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result,
};

pub mod fakeip;
pub use fakeip::{
    FakeIpConfig, FakeIpPolicy, FakeIpPoolOptions, FakeIpV6Config, FakeIpView, FakeIpViewStore,
    reverse_name_to_ip,
};

pub mod dns;
pub use dns::*;
pub mod cache;
pub mod dns_hosts;
pub use dns_hosts::AsyncHostsDnsHandler;
pub use dns_hosts::{
    HostsDispatchTarget, HostsDnsHandler, HostsTable, HostsTarget, host_without_port,
};
pub mod dns_resolver;
pub use dns_resolver::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery, SystemAsyncIpResolver,
};
pub mod dns_resolver_stack;
pub use dns_resolver_stack::AsyncHostsResolver;
mod dns_datagram;
pub use dns_datagram::{AsyncDnsDatagram, DnsDatagramConnector, probe_dns_udp};
pub mod dns_tcp;
pub use dns_tcp::{
    AsyncTcpDnsClient, AsyncTcpDnsHandler, AsyncTcpDnsServer, TcpDnsClient, TcpDnsServer,
};
#[cfg(feature = "http")]
pub mod dns_http;
#[cfg(feature = "http")]
pub use dns_http::{
    DnsOverHttp, DnsOverHttpConnector, DnsOverHttpHandler, HttpConnection, HttpVersion,
};
#[cfg(feature = "quic")]
pub mod dns_quic;
#[cfg(feature = "quic")]
pub use dns_quic::{DoqResolverConfig, DoqResolverFactory, probe_doq, query_doq};
#[cfg(feature = "tls")]
pub mod dns_tls;
#[cfg(feature = "tls")]
pub use dns_tls::{
    DnsIoStream, DnsStreamConnector, DnsTlsConnector, DnsTlsResolverConfig, DohResolverFactory,
    DotResolverFactory, RustCryptoHttpConnector, RustCryptoTlsConnector, webpki_client_config,
};
mod transport;
