//! Stable contracts shared by the yuhaiin-rust crates.
//!
//! This crate intentionally has no asynchronous-runtime or platform dependency.
//! Higher-level crates can therefore be tested independently and can choose the
//! runtime appropriate for desktop, Android, or embedded integration.

pub mod dns {
    pub use yuhaiin_dns::dns::*;
}
pub mod dns_hosts {
    pub use yuhaiin_dns::dns_hosts::*;
}
pub mod dns_resolver {
    pub use yuhaiin_dns::dns_resolver::*;
}
pub mod dns_resolver_stack {
    pub use yuhaiin_dns::dns_resolver_stack::*;
}
pub mod dns_tcp {
    pub use yuhaiin_dns::dns_tcp::*;
}
pub mod flow;
pub mod geo;
pub use geo::GeoLookup;
#[cfg(feature = "http")]
pub mod dns_http {
    pub use yuhaiin_dns::dns_http::*;
}
#[cfg(feature = "http")]
pub mod http2 {
    pub use yuhaiin_dns::dns_http::*;
}
pub mod nat;
pub mod network;
pub mod process;
pub mod proxy;
pub mod sniff;
pub mod stream_metadata;

pub use yuhaiin_types::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, LocalBoxFuture,
    MatchHistoryEntry, MatchResult, Network, ResolveStrategy, ResolverPolicy, Result, RouteMode,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn domain_names_are_canonicalized_and_checked() {
        assert_eq!(
            DomainName::new(" Example.COM. ").unwrap().as_str(),
            "example.com"
        );
        assert!(DomainName::new("").is_err());
        assert!(DomainName::new("a..example.com").is_err());
        assert!(DomainName::new("-bad.example.com").is_err());
        assert!(DomainName::new("bad label.example.com").is_err());
    }

    #[test]
    fn endpoint_key_includes_kind_and_port() {
        let domain = DomainName::new("example.com").unwrap();
        let a = Endpoint::domain(Network::Tcp, domain.clone(), 443);
        let b = Endpoint::domain(Network::Tcp, domain.clone(), 8443);
        let c = Endpoint::ip(Network::Tcp, "93.184.216.34:443".parse().unwrap());
        assert_ne!(a.comparable_key(), b.comparable_key());
        assert_ne!(a.comparable_key(), c.comparable_key());
    }

    #[test]
    fn fakeip_context_preserves_packet_tuple_but_restores_proxy_domain() {
        let mut context = FlowContext::new(Endpoint::ip(
            Network::Udp,
            "198.18.0.1:443".parse().unwrap(),
        ));
        context.original_domain = Some(DomainName::new("example.com").unwrap());
        assert_eq!(
            context.destination,
            Endpoint::ip(Network::Udp, "198.18.0.1:443".parse().unwrap())
        );
        assert_eq!(
            context.effective_destination(),
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443)
        );
    }

    #[test]
    fn local_bind_selects_the_remote_address_family() {
        let mut context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        context.local_bind_addresses = vec![
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V4("192.0.2.10".parse().unwrap()),
        ];
        assert_eq!(
            context.local_bind_for("198.51.100.1:443".parse().unwrap()),
            Some("192.0.2.10:0".parse().unwrap())
        );
        assert_eq!(
            context.local_bind_for("[2001:db8::20]:443".parse().unwrap()),
            Some("[2001:db8::10]:0".parse().unwrap())
        );
    }

    #[test]
    fn ip_set_iterates_ipv4_before_ipv6() {
        let set = IpSet {
            v4: vec![Ipv4Addr::LOCALHOST],
            v6: vec![Ipv6Addr::LOCALHOST],
        };
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );
    }
}
