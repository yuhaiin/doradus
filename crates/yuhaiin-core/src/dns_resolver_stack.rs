//! Composable address-resolver layers shared by the application runtime.
//!
//! These layers keep configuration concerns out of proxy implementations:
//! hosts is checked first, then the configured upstream resolver is used. The
//! returned trait object is also the boundary later HTTP handlers can expose.

use std::sync::Arc;

use crate::dns_hosts::HostsTable;
use crate::dns_resolver_async::AsyncIpResolver;
use crate::{BoxFuture, DomainName, IpSet, ResolveStrategy, Result};

/// Resolve static hosts entries before consulting the configured upstream.
#[derive(Clone)]
pub struct AsyncHostsResolver {
    pub hosts: HostsTable,
    pub upstream: Arc<dyn AsyncIpResolver>,
}

impl AsyncHostsResolver {
    pub fn new(hosts: HostsTable, upstream: Arc<dyn AsyncIpResolver>) -> Self {
        Self { hosts, upstream }
    }
}

impl AsyncIpResolver for AsyncHostsResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            if let Some(addresses) = self.hosts.resolve(domain)? {
                return Ok(filter_strategy(addresses, strategy));
            }
            Ok(filter_strategy(
                self.upstream.resolve(domain, strategy).await?,
                strategy,
            ))
        })
    }
}

fn filter_strategy(mut addresses: IpSet, strategy: ResolveStrategy) -> IpSet {
    match strategy {
        ResolveStrategy::OnlyIpv4 => addresses.v6.clear(),
        ResolveStrategy::OnlyIpv6 => addresses.v4.clear(),
        ResolveStrategy::Default | ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => {}
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 9)],
                    v6: vec![Ipv6Addr::LOCALHOST],
                })
            })
        }
    }

    #[test]
    fn hosts_layer_precedes_upstream_and_applies_family_policy() {
        let hosts = HostsTable::new();
        let domain = DomainName::new("example.com").unwrap();
        hosts
            .insert_ip(domain.clone(), "198.51.100.9".parse().unwrap())
            .unwrap();
        let resolver = AsyncHostsResolver::new(hosts, Arc::new(StaticResolver));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let addresses = runtime
            .block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv6))
            .unwrap();
        assert!(addresses.is_empty());

        let missing = DomainName::new("missing.example.com").unwrap();
        let addresses = runtime
            .block_on(resolver.resolve(&missing, ResolveStrategy::OnlyIpv4))
            .unwrap();
        assert_eq!(addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 9)]);
        assert!(addresses.v6.is_empty());
    }
}
