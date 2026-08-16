//! FakeIP address-resolver layer for the shared application runtime.

use std::net::IpAddr;
use std::sync::Arc;

use yuhaiin_core::dns::{DnsRecordType, DnsResponse, DnsServiceParam};
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy, Result};
pub use yuhaiin_dns::FakeIpPolicy;

use crate::fakeip::{FakeIpPool, FakeIpV6Pool, FakeIpView, FakeIpViewStore, reverse_name_to_ip};

/// The two persistent pools used by one resolver snapshot.
#[derive(Clone)]
pub struct FakeIpPools {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
    view: FakeIpViewStore,
}

impl FakeIpPools {
    pub fn new(ipv4: Arc<FakeIpPool>, ipv6: Arc<FakeIpV6Pool>) -> Self {
        Self {
            ipv4,
            ipv6,
            view: FakeIpViewStore::default(),
        }
    }

    /// Build a SQLite-free reverse view for packet-plane flow creation.
    ///
    /// The TUN context provider is synchronous and may run on the packet
    /// polling boundary.  Capturing this immutable view avoids holding the
    /// pool's async mutex or moving a store handle into that callback.
    pub async fn snapshot(&self) -> FakeIpView {
        let ipv4 = self.ipv4.snapshot().await;
        let ipv6 = self.ipv6.snapshot().await;
        let view = ipv4.merge(&ipv6);
        self.view.replace(view.clone());
        view
    }

    pub fn view_store(&self) -> FakeIpViewStore {
        self.view.clone()
    }

    /// Match Go FakeDNS's fail-closed check for an address inside an active
    /// FakeIP range that has no reverse mapping.
    pub fn contains_ip(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.ipv4.contains(address),
            IpAddr::V6(address) => self.ipv6.contains(address),
        }
    }

    /// Resolve an `in-addr.arpa` or `ip6.arpa` name from the current
    /// persistent FakeIP reverse maps.  Refreshing the immutable view here
    /// also makes preloaded mappings visible to socket DNS before the first
    /// new A/AAAA allocation happens after startup.
    pub async fn lookup_ptr_domain(&self, domain: &DomainName) -> Option<DomainName> {
        let address = reverse_name_to_ip(domain)?;
        let view = self.snapshot().await;
        view.lookup_domain_ip(address)
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
    pub policy: FakeIpPolicy,
}

impl FakeIpResolver {
    pub fn new(
        upstream: Arc<dyn AsyncIpResolver>,
        pools: FakeIpPools,
        skip_check_upstream: bool,
    ) -> Self {
        Self::new_with_policy(
            upstream,
            pools,
            skip_check_upstream,
            FakeIpPolicy::default(),
        )
    }

    pub fn new_with_policy(
        upstream: Arc<dyn AsyncIpResolver>,
        pools: FakeIpPools,
        skip_check_upstream: bool,
        policy: FakeIpPolicy,
    ) -> Self {
        Self {
            upstream,
            pools,
            skip_check_upstream,
            policy,
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
            if self.policy.is_whitelisted(domain) {
                return self.upstream.resolve(domain, strategy).await;
            }
            let skip_check = self.skip_check_upstream || self.policy.is_skip_check(domain);
            let upstream = if skip_check {
                IpSet::default()
            } else {
                self.upstream.resolve(domain, strategy).await?
            };
            let mut result = filter_strategy(upstream.clone(), strategy);

            if should_resolve_v4(strategy) && (skip_check || !upstream.v4.is_empty()) {
                result.v4 = vec![self.pools.ipv4.allocate(domain.clone()).await?];
            }
            if should_resolve_v6(strategy) && (skip_check || !upstream.v6.is_empty()) {
                result.v6 = vec![self.pools.ipv6.allocate(domain.clone()).await?];
            }
            self.pools.snapshot().await;
            Ok(result)
        })
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            if self.policy.is_whitelisted(domain) {
                return self.upstream.query(domain, record_type).await;
            }

            if record_type == DnsRecordType::Ptr {
                if let Some(mapped) = self.pools.lookup_ptr_domain(domain).await {
                    return Ok(DnsResponse {
                        addresses: IpSet::default(),
                        ptr_names: vec![mapped],
                        service_bindings: Vec::new(),
                        minimum_ttl: Some(60),
                    });
                }
                return self.upstream.query(domain, record_type).await;
            }

            let skip_check = self.skip_check_upstream || self.policy.is_skip_check(domain);
            let mut response =
                if skip_check && matches!(record_type, DnsRecordType::A | DnsRecordType::Aaaa) {
                    empty_dns_response()
                } else {
                    self.upstream.query(domain, record_type).await?
                };
            match record_type {
                DnsRecordType::A if skip_check || !response.addresses.v4.is_empty() => {
                    let address = self.pools.ipv4.allocate(domain.clone()).await?;
                    response.addresses = IpSet {
                        v4: vec![address],
                        v6: Vec::new(),
                    };
                    self.pools.snapshot().await;
                }
                DnsRecordType::Aaaa if skip_check || !response.addresses.v6.is_empty() => {
                    let address = self.pools.ipv6.allocate(domain.clone()).await?;
                    response.addresses = IpSet {
                        v4: Vec::new(),
                        v6: vec![address],
                    };
                    self.pools.snapshot().await;
                }
                DnsRecordType::Https | DnsRecordType::Svcb => {
                    let wants_v4 = response.service_bindings.iter().any(|binding| {
                        binding.params.iter().any(|param| {
                            matches!(param, DnsServiceParam::Ipv4Hint(values) if !values.is_empty())
                        })
                    });
                    let wants_v6 = response.service_bindings.iter().any(|binding| {
                        binding.params.iter().any(|param| {
                            matches!(param, DnsServiceParam::Ipv6Hint(values) if !values.is_empty())
                        })
                    });
                    let ipv4 = if wants_v4 {
                        Some(self.pools.ipv4.allocate(domain.clone()).await?)
                    } else {
                        None
                    };
                    let ipv6 = if wants_v6 {
                        Some(self.pools.ipv6.allocate(domain.clone()).await?)
                    } else {
                        None
                    };
                    if ipv4.is_some() || ipv6.is_some() {
                        for binding in &mut response.service_bindings {
                            for param in &mut binding.params {
                                match param {
                                    DnsServiceParam::Ipv4Hint(values) if ipv4.is_some() => {
                                        if let Some(address) = ipv4 {
                                            *values = vec![address];
                                        }
                                    }
                                    DnsServiceParam::Ipv6Hint(values) if ipv6.is_some() => {
                                        if let Some(address) = ipv6 {
                                            *values = vec![address];
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        self.pools.snapshot().await;
                    }
                }
                DnsRecordType::Ptr => unreachable!("PTR handled before the response query"),
                DnsRecordType::A | DnsRecordType::Aaaa => {}
            }
            Ok(response)
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        // FakeIP only rewrites address-bearing records. Unknown records must
        // retain their upstream wire representation and are therefore passed
        // through unchanged.
        self.upstream.query_packet(packet)
    }
}

fn empty_dns_response() -> DnsResponse {
    DnsResponse {
        addresses: IpSet::default(),
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(0),
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
        let view = resolver.pools.view_store();
        assert_eq!(
            view.lookup_domain_ip(first.v4[0].into()),
            Some(domain.clone())
        );
        assert_eq!(
            view.lookup_domain_ip(first.v6[0].into()),
            Some(domain.clone())
        );

        let only_v4 = block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv4)).unwrap();
        assert_eq!(only_v4.v4, first.v4);
        assert!(only_v4.v6.is_empty());
    }

    #[test]
    fn fakeip_pools_snapshot_merges_ipv4_and_ipv6_reverse_mappings() {
        let store = block_on(crate::ConfigStore::open_memory()).unwrap();
        let ipv4 = Arc::new(
            block_on(FakeIpPool::open(
                store.clone(),
                crate::fakeip::FakeIpConfig::new(
                    Ipv4Addr::new(198, 18, 2, 1),
                    Ipv4Addr::new(198, 18, 2, 2),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let ipv6 = Arc::new(
            block_on(FakeIpV6Pool::open(
                store,
                crate::fakeip::FakeIpV6Config::new(
                    "fc00:2::1".parse().unwrap(),
                    "fc00:2::2".parse().unwrap(),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let v4_domain = DomainName::new("v4.example.com").unwrap();
        let v6_domain = DomainName::new("v6.example.com").unwrap();
        let v4 = block_on(ipv4.allocate(v4_domain.clone())).unwrap();
        let v6 = block_on(ipv6.allocate(v6_domain.clone())).unwrap();

        let view = block_on(FakeIpPools::new(ipv4, ipv6).snapshot());
        assert_eq!(view.lookup_domain_ip(v4.into()), Some(v4_domain));
        assert_eq!(view.lookup_domain_ip(v6.into()), Some(v6_domain));
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

    #[test]
    fn fakeip_policy_whitelist_precedes_skip_check_and_matches_subdomains() {
        let store = block_on(crate::ConfigStore::open_memory()).unwrap();
        let ipv4 = Arc::new(
            block_on(FakeIpPool::open(
                store.clone(),
                crate::fakeip::FakeIpConfig::new(
                    Ipv4Addr::new(198, 18, 3, 1),
                    Ipv4Addr::new(198, 18, 3, 8),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let ipv6 = Arc::new(
            block_on(FakeIpV6Pool::open(
                store,
                crate::fakeip::FakeIpV6Config::new(
                    "fc00:3::1".parse().unwrap(),
                    "fc00:3::8".parse().unwrap(),
                )
                .unwrap(),
            ))
            .unwrap(),
        );
        let whitelist = vec!["example.com".to_owned()];
        let skip_check = vec!["*.skip.other.test".to_owned()];
        let policy = FakeIpPolicy::from_lists(&whitelist, &skip_check).unwrap();
        assert!(policy.is_skip_check(&DomainName::new("api.skip.other.test").unwrap()));
        let resolver = FakeIpResolver::new_with_policy(
            Arc::new(StaticResolver),
            FakeIpPools::new(ipv4, ipv6),
            false,
            policy,
        );

        let whitelisted = block_on(resolver.resolve(
            &DomainName::new("api.example.com").unwrap(),
            ResolveStrategy::Default,
        ))
        .unwrap();
        assert_eq!(whitelisted.v4, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(whitelisted.v6, vec![Ipv6Addr::LOCALHOST]);

        let skipped = block_on(resolver.resolve(
            &DomainName::new("api.skip.other.test").unwrap(),
            ResolveStrategy::Default,
        ))
        .unwrap();
        assert_eq!(skipped.v4, vec![Ipv4Addr::new(198, 18, 3, 1)]);
        assert_eq!(skipped.v6, vec!["fc00:3::1".parse::<Ipv6Addr>().unwrap()]);

        let skipped_query = block_on(resolver.query(
            &DomainName::new("api.skip.other.test").unwrap(),
            DnsRecordType::A,
        ))
        .unwrap();
        assert_eq!(skipped_query.addresses.v4, skipped.v4);

        let whitelisted_query = block_on(resolver.query(
            &DomainName::new("api.example.com").unwrap(),
            DnsRecordType::A,
        ))
        .unwrap();
        assert_eq!(whitelisted_query.addresses.v4, whitelisted.v4);
    }
}
