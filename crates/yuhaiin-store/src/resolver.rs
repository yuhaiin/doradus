//! FakeIP address-resolver layer for the shared application runtime.

use std::sync::Arc;

use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy, Result};

use crate::fakeip::{FakeIpPool, FakeIpV6Pool};

/// The two persistent pools used by one resolver snapshot.
#[derive(Clone)]
pub struct FakeIpPools {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
}

impl FakeIpPools {
    pub fn new(ipv4: Arc<FakeIpPool>, ipv6: Arc<FakeIpV6Pool>) -> Self {
        Self { ipv4, ipv6 }
    }
}

/// Resolve through the normal upstream and replace successful A/AAAA results
/// with persistent FakeIP addresses.  The upstream remains injected, so this
/// layer works with UDP, DoH, hosts and future resolver groups alike.
#[derive(Clone)]
pub struct FakeIpResolver {
    pub upstream: Arc<dyn AsyncIpResolver>,
    pub pools: FakeIpPools,
    pub skip_check_upstream: bool,
}

impl FakeIpResolver {
    pub fn new(
        upstream: Arc<dyn AsyncIpResolver>,
        pools: FakeIpPools,
        skip_check_upstream: bool,
    ) -> Self {
        Self {
            upstream,
            pools,
            skip_check_upstream,
        }
    }
}

impl AsyncIpResolver for FakeIpResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            let upstream = if self.skip_check_upstream {
                IpSet::default()
            } else {
                self.upstream.resolve(domain, strategy).await?
            };
            let mut result = filter_strategy(upstream.clone(), strategy);

            if should_resolve_v4(strategy) && (self.skip_check_upstream || !upstream.v4.is_empty())
            {
                result.v4 = vec![self.pools.ipv4.allocate(domain.clone()).await?];
            }
            if should_resolve_v6(strategy) && (self.skip_check_upstream || !upstream.v6.is_empty())
            {
                result.v6 = vec![self.pools.ipv6.allocate(domain.clone()).await?];
            }
            Ok(result)
        })
    }
}

fn should_resolve_v4(strategy: ResolveStrategy) -> bool {
    !matches!(strategy, ResolveStrategy::OnlyIpv6)
}

fn should_resolve_v6(strategy: ResolveStrategy) -> bool {
    !matches!(strategy, ResolveStrategy::OnlyIpv4)
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
    use std::future::Future;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                    v6: vec![Ipv6Addr::LOCALHOST],
                })
            })
        }
    }

    #[test]
    fn fakeip_resolver_reuses_dual_stack_addresses_and_keeps_family_policy() {
        let store = block_on(crate::ConfigStore::open_memory()).unwrap();
        let ipv4 = Arc::new(
            block_on(FakeIpPool::open(
                store.clone(),
                crate::fakeip::FakeIpConfig::new(
                    Ipv4Addr::new(198, 18, 0, 1),
                    Ipv4Addr::new(198, 18, 0, 8),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let ipv6 = Arc::new(
            block_on(FakeIpV6Pool::open(
                store,
                crate::fakeip::FakeIpV6Config::new(
                    "fc00::1".parse().unwrap(),
                    "fc00::8".parse().unwrap(),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let resolver = FakeIpResolver::new(
            Arc::new(StaticResolver),
            FakeIpPools::new(ipv4, ipv6),
            false,
        );
        let domain = DomainName::new("example.com").unwrap();
        let first = block_on(resolver.resolve(&domain, ResolveStrategy::Default)).unwrap();
        let second = block_on(resolver.resolve(&domain, ResolveStrategy::Default)).unwrap();
        assert_eq!(first, second);
        assert!((198..=199).contains(&first.v4[0].octets()[0]));
        assert_eq!(first.v6[0], "fc00::1".parse::<Ipv6Addr>().unwrap());

        let only_v4 = block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv4)).unwrap();
        assert_eq!(only_v4.v4, first.v4);
        assert!(only_v4.v6.is_empty());
    }

    #[test]
    fn skip_check_upstream_allocates_without_network_lookup() {
        let store = block_on(crate::ConfigStore::open_memory()).unwrap();
        let ipv4 = Arc::new(
            block_on(FakeIpPool::open(
                store.clone(),
                crate::fakeip::FakeIpConfig::new(
                    Ipv4Addr::new(198, 18, 1, 1),
                    Ipv4Addr::new(198, 18, 1, 2),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let ipv6 = Arc::new(
            block_on(FakeIpV6Pool::open(
                store,
                crate::fakeip::FakeIpV6Config::new(
                    "fc00:1::1".parse().unwrap(),
                    "fc00:1::2".parse().unwrap(),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let resolver =
            FakeIpResolver::new(Arc::new(StaticResolver), FakeIpPools::new(ipv4, ipv6), true);
        let result = block_on(resolver.resolve(
            &DomainName::new("offline.example.com").unwrap(),
            ResolveStrategy::Default,
        ))
        .unwrap();
        assert_eq!(result.v4, vec![Ipv4Addr::new(198, 18, 1, 1)]);
        assert_eq!(result.v6, vec!["fc00:1::1".parse::<Ipv6Addr>().unwrap()]);
    }
}
