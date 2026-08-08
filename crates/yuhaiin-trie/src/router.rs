//! Immutable-after-build route rule index built on the domain/CIDR tries.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use yuhaiin_core::{Endpoint, GeoLookup, Network, ResolverPolicy, RouteMode};

#[cfg(feature = "async-proxy")]
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector};

use crate::CombinedTrie;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Direct,
    Proxy,
    Bypass,
    Drop,
}
impl From<RuleAction> for RouteMode {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Direct => Self::Direct,
            RuleAction::Proxy => Self::Proxy,
            RuleAction::Bypass => Self::Bypass,
            RuleAction::Drop => Self::Block,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub pattern: String,
    pub action: RuleAction,
    pub network: Option<Network>,
    pub port: Option<(u16, u16)>,
    /// Optional MaxMind country code constraint for IP endpoints.
    pub geo_country: Option<String>,
    pub resolver_policy: ResolverPolicy,
    pub priority: i32,
}

impl RouteRule {
    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        self.matches_with_geo(endpoint, None)
    }

    fn matches_with_geo(&self, endpoint: &Endpoint, geo: Option<&dyn GeoLookup>) -> bool {
        if self
            .network
            .is_some_and(|network| network != endpoint.network())
        {
            return false;
        }
        if let Some((start, end)) = self.port {
            let Some(port) = endpoint.port() else {
                return false;
            };
            if port < start || port > end {
                return false;
            }
        }
        if let Some(expected) = self.geo_country.as_deref() {
            let Some(address) = endpoint.addr().map(|address| address.ip()) else {
                return false;
            };
            let Some(geo) = geo else {
                return false;
            };
            let Ok(Some(actual)) = geo.country_code(address) else {
                return false;
            };
            if !actual.eq_ignore_ascii_case(expected) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub mode: RouteMode,
    pub resolver_policy: ResolverPolicy,
    pub priority: i32,
}

#[derive(Clone)]
pub struct Router {
    rules: CombinedTrie<Vec<RouteRule>>,
    /// Rules without a domain/CIDR matcher (for example Go's network-only or
    /// empty `all` rule) are evaluated for every endpoint. Keeping them out of
    /// the trie avoids inventing a fake domain that would not match IP flows.
    global_rules: Vec<RouteRule>,
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
}

/// Runtime owner for immutable route snapshots. Compilation happens before
/// taking the write lock, so a malformed update cannot disturb readers or the
/// currently active snapshot.
#[derive(Clone)]
pub struct RouterRuntime {
    current: Arc<RwLock<Arc<Router>>>,
}

impl Router {
    pub fn compile(mut rules: Vec<RouteRule>, fallback: RouteDecision) -> crate::Result<Self> {
        rules.sort_by_key(|rule| rule.priority);
        let mut index = Self {
            rules: CombinedTrie::new(),
            global_rules: Vec::new(),
            fallback,
            geo: None,
        };
        let mut grouped: BTreeMap<String, Vec<RouteRule>> = BTreeMap::new();
        for rule in rules {
            if rule.pattern.trim().is_empty() {
                index.global_rules.push(rule);
            } else {
                grouped.entry(rule.pattern.clone()).or_default().push(rule);
            }
        }
        index.global_rules.sort_by_key(|rule| rule.priority);
        for (pattern, values) in grouped {
            index.rules.insert(pattern.as_str(), values)?;
        }
        Ok(index)
    }

    /// Attach an immutable geographic reader to this route snapshot.
    ///
    /// The reader is held by `Arc`, so publishing a new Router can replace a
    /// MaxMindDB reader while existing flows continue using their old
    /// snapshot safely.
    pub fn with_geo_lookup(mut self, geo: Arc<dyn GeoLookup>) -> Self {
        self.geo = Some(geo);
        self
    }

    pub fn decide(&self, endpoint: &Endpoint) -> RouteDecision {
        let candidates = self.rules.search(endpoint);
        self.global_rules
            .iter()
            .chain(candidates.into_iter().flat_map(|rules| rules.iter()))
            .filter(|rule| rule.matches_with_geo(endpoint, self.geo.as_deref()))
            // Go's route matcher walks rules in persisted priority order and
            // stops at the first match.  Lower priority values therefore win;
            // this is also what makes the UI's drag-and-drop order effective.
            .min_by_key(|rule| rule.priority)
            .map(|rule| RouteDecision {
                mode: rule.action.into(),
                resolver_policy: rule.resolver_policy,
                priority: rule.priority,
            })
            .unwrap_or_else(|| self.fallback.clone())
    }

    /// Evaluate both the packet tuple and a FakeIP-restored hostname.  A
    /// CIDR rule on the virtual address must keep working, while an explicit
    /// domain rule must also be able to override the fallback.  The normal
    /// rule priority decides when both forms match.
    pub fn decide_context(&self, context: &yuhaiin_core::FlowContext) -> RouteDecision {
        let packet = self.decide(&context.destination);
        let Some(_) = context.original_domain else {
            return packet;
        };
        let domain = self.decide(&context.effective_destination());
        if domain.priority <= packet.priority {
            domain
        } else {
            packet
        }
    }
}

impl RouterRuntime {
    pub fn new(router: Router) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(router))),
        }
    }

    pub fn snapshot(&self) -> Arc<Router> {
        self.current
            .read()
            .expect("router snapshot lock poisoned")
            .clone()
    }

    pub fn decide(&self, endpoint: &Endpoint) -> RouteDecision {
        self.snapshot().decide(endpoint)
    }

    pub fn publish(&self, router: Router) -> Arc<Router> {
        let mut current = self.current.write().expect("router snapshot lock poisoned");
        std::mem::replace(&mut *current, Arc::new(router))
    }

    pub fn compile_and_publish(
        &self,
        rules: Vec<RouteRule>,
        fallback: RouteDecision,
    ) -> crate::Result<Arc<Router>> {
        let router = Router::compile(rules, fallback)?;
        Ok(self.publish(router))
    }

    pub fn compile_and_publish_with_geo(
        &self,
        rules: Vec<RouteRule>,
        fallback: RouteDecision,
        geo: Arc<dyn GeoLookup>,
    ) -> crate::Result<Arc<Router>> {
        let router = Router::compile(rules, fallback)?.with_geo_lookup(geo);
        Ok(self.publish(router))
    }

    pub fn rollback(&self, previous: Arc<Router>) -> Arc<Router> {
        let mut current = self.current.write().expect("router snapshot lock poisoned");
        std::mem::replace(&mut *current, previous)
    }

    pub fn apply_to_context(&self, context: &mut yuhaiin_core::FlowContext) -> RouteDecision {
        let decision = self.snapshot().decide_context(context);
        if !context.skip_route {
            context.route_mode = decision.mode;
            context.resolver_policy = decision.resolver_policy;
        }
        decision
    }
}

/// Selects the async proxy implementation for a flow using one immutable
/// router snapshot.  The selector deliberately lives in the trie crate rather
/// than in `yuhaiin-core`, so the core packet/proxy contracts do not depend on
/// a particular rule index implementation.
#[cfg(feature = "async-proxy")]
pub struct RoutedProxySelector {
    pub router: Arc<Router>,
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxySelector for RoutedProxySelector {
    fn select(&self, context: &yuhaiin_core::FlowContext) -> Arc<dyn AsyncProxy> {
        let mode = if context.skip_route {
            context.route_mode
        } else {
            self.router.decide_context(context).mode
        };
        select_proxy(mode, &self.direct, &self.proxy, &self.bypass, &self.drop)
    }
}

/// A route selector backed by the atomically published runtime snapshot.
///
/// `RoutedProxySelector` is intentionally kept as a static-snapshot adapter
/// for existing flows.  New TUN flows should use this selector so a published
/// route update is observed at selection time, while an already selected
/// proxy/session continues to own the old snapshot and is not retargeted.
#[cfg(feature = "async-proxy")]
pub struct RuntimeRoutedProxySelector {
    pub router: RouterRuntime,
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "async-proxy")]
impl AsyncProxySelector for RuntimeRoutedProxySelector {
    fn select(&self, context: &yuhaiin_core::FlowContext) -> Arc<dyn AsyncProxy> {
        let mode = if context.skip_route {
            context.route_mode
        } else {
            self.router.snapshot().decide_context(context).mode
        };
        select_proxy(mode, &self.direct, &self.proxy, &self.bypass, &self.drop)
    }
}

#[cfg(feature = "async-proxy")]
fn select_proxy(
    mode: RouteMode,
    direct: &Arc<dyn AsyncProxy>,
    proxy: &Arc<dyn AsyncProxy>,
    bypass: &Arc<dyn AsyncProxy>,
    drop: &Arc<dyn AsyncProxy>,
) -> Arc<dyn AsyncProxy> {
    match mode {
        RouteMode::Direct => Arc::clone(direct),
        RouteMode::Proxy => Arc::clone(proxy),
        RouteMode::Bypass => Arc::clone(bypass),
        RouteMode::Block => Arc::clone(drop),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use yuhaiin_core::{DomainName, ResolveStrategy, Result};

    struct StaticGeo {
        code: Option<&'static str>,
    }

    impl GeoLookup for StaticGeo {
        fn country_code(&self, _address: IpAddr) -> Result<Option<String>> {
            Ok(self.code.map(str::to_owned))
        }
    }

    fn rule(pattern: &str, action: RuleAction, priority: i32) -> RouteRule {
        RouteRule {
            pattern: pattern.to_owned(),
            action,
            network: None,
            port: None,
            geo_country: None,
            resolver_policy: ResolverPolicy {
                strategy: ResolveStrategy::Default,
                use_fake_ip: action == RuleAction::Proxy,
                ..ResolverPolicy::default()
            },
            priority,
        }
    }

    #[test]
    fn router_prefers_lower_priority_matching_rule() {
        let router = Router::compile(
            vec![
                rule("example.com", RuleAction::Direct, 1),
                rule("example.com", RuleAction::Proxy, 2),
            ],
            RouteDecision {
                mode: RouteMode::Block,
                resolver_policy: ResolverPolicy::default(),
                priority: -1,
            },
        )
        .unwrap();
        let endpoint = Endpoint::domain(
            Network::Tcp,
            DomainName::new("www.example.com").unwrap(),
            443,
        );
        let decision = router.decide(&endpoint);
        assert_eq!(decision.mode, RouteMode::Direct);
        assert!(!decision.resolver_policy.use_fake_ip);
    }

    #[test]
    fn router_filters_network_and_port() {
        let mut udp_rule = rule("192.0.2.0/24", RuleAction::Proxy, 10);
        udp_rule.network = Some(Network::Udp);
        udp_rule.port = Some((53, 53));
        let router = Router::compile(
            vec![udp_rule],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap();
        let endpoint = Endpoint::ip(Network::Udp, SocketAddr::from(([192, 0, 2, 1], 53)));
        assert_eq!(router.decide(&endpoint).mode, RouteMode::Proxy);
        let other = Endpoint::ip(Network::Tcp, SocketAddr::from(([192, 0, 2, 1], 53)));
        assert_eq!(router.decide(&other).mode, RouteMode::Direct);
    }

    #[test]
    fn geo_country_rule_changes_ip_route_dispatch() {
        let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 20);
        geo_rule.geo_country = Some("cn".to_owned());
        let router = Router::compile(
            vec![geo_rule],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap()
        .with_geo_lookup(Arc::new(StaticGeo { code: Some("CN") }));
        let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
        assert_eq!(router.decide(&endpoint).mode, RouteMode::Proxy);
    }

    #[test]
    fn geo_country_rule_falls_back_without_a_match_or_database() {
        let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 20);
        geo_rule.geo_country = Some("CN".to_owned());
        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let without_db = Router::compile(vec![geo_rule.clone()], fallback.clone()).unwrap();
        let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
        assert_eq!(without_db.decide(&endpoint), fallback);

        let wrong_country = Router::compile(vec![geo_rule], fallback.clone())
            .unwrap()
            .with_geo_lookup(Arc::new(StaticGeo { code: Some("US") }));
        assert_eq!(wrong_country.decide(&endpoint), fallback);
    }

    #[test]
    fn fakeip_context_uses_the_first_priority_of_ip_and_domain_rules() {
        let mut cidr = rule("198.18.0.0/15", RuleAction::Proxy, 10);
        cidr.network = Some(Network::Udp);
        cidr.port = Some((443, 443));
        let mut domain = rule("example.com", RuleAction::Direct, 20);
        domain.network = Some(Network::Udp);
        domain.port = Some((443, 443));
        let router = Router::compile(
            vec![cidr, domain],
            RouteDecision {
                mode: RouteMode::Block,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap();
        let mut context = yuhaiin_core::FlowContext::new(Endpoint::ip(
            Network::Udp,
            "198.18.0.1:443".parse().unwrap(),
        ));
        context.original_domain = Some(DomainName::new("example.com").unwrap());
        assert_eq!(router.decide_context(&context).mode, RouteMode::Proxy);
    }

    #[test]
    fn runtime_publishes_and_rolls_back_immutable_snapshots() {
        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let first = Router::compile(vec![], fallback.clone()).unwrap();
        let runtime = RouterRuntime::new(first);
        let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);

        let previous = runtime
            .compile_and_publish(vec![rule("example.com", RuleAction::Proxy, 10)], fallback)
            .unwrap();
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);
        runtime.rollback(previous);
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);
    }

    #[test]
    fn failed_publish_keeps_the_previous_snapshot() {
        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let runtime = RouterRuntime::new(
            Router::compile(
                vec![rule("example.com", RuleAction::Proxy, 10)],
                fallback.clone(),
            )
            .unwrap(),
        );
        let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);

        let mut invalid = rule("bad..example.com", RuleAction::Direct, 20);
        invalid.network = Some(Network::Tcp);
        assert!(
            runtime
                .compile_and_publish(vec![invalid], fallback)
                .is_err()
        );
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);
    }

    #[test]
    fn hot_publish_can_replace_the_geo_reader_with_the_route_snapshot() {
        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 10);
        geo_rule.geo_country = Some("CN".to_owned());
        let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
        let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());

        runtime
            .compile_and_publish_with_geo(
                vec![geo_rule.clone()],
                fallback.clone(),
                Arc::new(StaticGeo { code: Some("CN") }),
            )
            .unwrap();
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);

        runtime
            .compile_and_publish_with_geo(
                vec![geo_rule],
                fallback,
                Arc::new(StaticGeo { code: Some("US") }),
            )
            .unwrap();
        assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);
    }

    #[test]
    fn runtime_applies_resolver_policy_with_route_decision() {
        let rule = rule("example.com", RuleAction::Proxy, 10);
        let runtime = RouterRuntime::new(
            Router::compile(
                vec![rule],
                RouteDecision {
                    mode: RouteMode::Direct,
                    resolver_policy: ResolverPolicy::default(),
                    priority: 0,
                },
            )
            .unwrap(),
        );
        let mut context = yuhaiin_core::FlowContext::new(Endpoint::domain(
            Network::Udp,
            DomainName::new("example.com").unwrap(),
            53,
        ));
        let decision = runtime.apply_to_context(&mut context);
        assert_eq!(decision.mode, RouteMode::Proxy);
        assert_eq!(context.route_mode, RouteMode::Proxy);
        assert!(context.resolver_policy.use_fake_ip);
    }

    #[test]
    fn runtime_hot_publish_keeps_readers_on_whole_snapshots() {
        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
        let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let runtime = runtime.clone();
                let endpoint = endpoint.clone();
                scope.spawn(move || {
                    for _ in 0..50_000 {
                        let decision = runtime.decide(&endpoint);
                        assert_eq!(
                            decision.resolver_policy.use_fake_ip,
                            decision.mode == RouteMode::Proxy
                        );
                    }
                });
            }
            for index in 0..50_000 {
                let action = if index % 2 == 0 {
                    RuleAction::Proxy
                } else {
                    RuleAction::Direct
                };
                runtime
                    .compile_and_publish(vec![rule("example.com", action, 10)], fallback.clone())
                    .unwrap();
            }
        });
        let snapshot = runtime.snapshot();
        let decision = snapshot.decide(&endpoint);
        assert!(decision.mode == RouteMode::Proxy || decision.mode == RouteMode::Direct);
    }

    #[cfg(feature = "async-proxy")]
    #[test]
    fn routed_proxy_selector_uses_snapshot_and_honors_skip_route() {
        use std::sync::Arc;
        use yuhaiin_core::FlowContext;
        use yuhaiin_core::proxy::{AsyncProxySelector, DropAsyncProxy};

        let router = Arc::new(
            Router::compile(
                vec![rule("example.com", RuleAction::Direct, 10)],
                RouteDecision {
                    mode: RouteMode::Proxy,
                    resolver_policy: ResolverPolicy::default(),
                    priority: 0,
                },
            )
            .unwrap(),
        );
        let direct: Arc<dyn yuhaiin_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
        let proxy: Arc<dyn yuhaiin_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
        let bypass: Arc<dyn yuhaiin_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
        let drop: Arc<dyn yuhaiin_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = RoutedProxySelector {
            router,
            direct: Arc::clone(&direct),
            proxy: Arc::clone(&proxy),
            bypass: Arc::clone(&bypass),
            drop: Arc::clone(&drop),
        };

        let domain = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        let selected = selector.select(&FlowContext::new(domain));
        assert!(Arc::ptr_eq(&selected, &direct));

        let mut skipped =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        skipped.route_mode = RouteMode::Bypass;
        skipped.skip_route = true;
        let selected = selector.select(&skipped);
        assert!(Arc::ptr_eq(&selected, &bypass));
    }

    #[cfg(feature = "async-proxy")]
    #[test]
    fn runtime_routed_proxy_selector_observes_new_snapshots_without_retargeting_old_flows() {
        use yuhaiin_core::FlowContext;
        use yuhaiin_core::proxy::{AsyncProxySelector, DropAsyncProxy};

        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
        let direct: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let bypass: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = RuntimeRoutedProxySelector {
            router: runtime.clone(),
            direct: Arc::clone(&direct),
            proxy: Arc::clone(&proxy),
            bypass: Arc::clone(&bypass),
            drop: Arc::clone(&drop),
        };
        let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        let old_snapshot = runtime.snapshot();
        let old_flow = FlowContext::new(endpoint.clone());
        assert!(Arc::ptr_eq(&selector.select(&old_flow), &direct));

        runtime
            .compile_and_publish(vec![rule("example.com", RuleAction::Proxy, 10)], fallback)
            .unwrap();
        assert!(Arc::ptr_eq(
            &selector.select(&FlowContext::new(endpoint.clone())),
            &proxy
        ));
        assert_eq!(old_snapshot.decide(&endpoint).mode, RouteMode::Direct);

        let mut skipped = FlowContext::new(endpoint);
        skipped.skip_route = true;
        skipped.route_mode = RouteMode::Bypass;
        assert!(Arc::ptr_eq(&selector.select(&skipped), &bypass));
    }

    #[cfg(feature = "async-proxy")]
    #[test]
    fn runtime_selector_keeps_old_flow_and_selects_whole_snapshots_under_pressure() {
        use yuhaiin_core::FlowContext;
        use yuhaiin_core::proxy::{AsyncProxySelector, DropAsyncProxy};

        let fallback = RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        };
        let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
        let direct: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let bypass: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = Arc::new(RuntimeRoutedProxySelector {
            router: runtime.clone(),
            direct: Arc::clone(&direct),
            proxy: Arc::clone(&proxy),
            bypass: Arc::clone(&bypass),
            drop: Arc::clone(&drop),
        });
        let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        let old_flow_proxy = selector.select(&FlowContext::new(endpoint.clone()));
        assert!(Arc::ptr_eq(&old_flow_proxy, &direct));

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let selector = Arc::clone(&selector);
                let direct = Arc::clone(&direct);
                let proxy = Arc::clone(&proxy);
                let endpoint = endpoint.clone();
                scope.spawn(move || {
                    for _ in 0..50_000 {
                        let selected = selector.select(&FlowContext::new(endpoint.clone()));
                        assert!(
                            Arc::ptr_eq(&selected, &direct) || Arc::ptr_eq(&selected, &proxy),
                            "selector returned a proxy not belonging to its published snapshot"
                        );
                    }
                });
            }
            for index in 0..50_000 {
                let action = if index % 2 == 0 {
                    RuleAction::Proxy
                } else {
                    RuleAction::Direct
                };
                runtime
                    .compile_and_publish(vec![rule("example.com", action, 10)], fallback.clone())
                    .unwrap();
            }
        });

        // Selection is per-flow.  Publishing a new snapshot must not mutate
        // the proxy/session that an old flow already retained.
        assert!(Arc::ptr_eq(&old_flow_proxy, &direct));
    }
}
