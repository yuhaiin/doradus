//! Immutable-after-build route rule index built on the domain/CIDR tries.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use yuhaiin_core::{
    Endpoint, FlowContext, GeoLookup, MatchHistoryEntry, MatchResult, Network, ResolverPolicy,
    RouteMode,
};

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
    /// Stable Go rule name used by the management and telemetry contracts.
    pub rule_name: String,
    pub tag: String,
    /// Names of Go host/process lists contributing to this expanded rule.
    pub list_names: Vec<String>,
    pub pattern: String,
    pub action: RuleAction,
    pub network: Option<Network>,
    /// Negative network constraints from Go's `not` expression.
    pub excluded_networks: Vec<Network>,
    pub port: Option<(u16, u16)>,
    /// Negative port constraints from Go's `not` expression.
    pub excluded_ports: Vec<(u16, u16)>,
    /// Optional MaxMind country code constraint for IP endpoints.
    pub geo_country: Option<String>,
    /// Negative MaxMind country constraints from Go's `not` expression.
    pub excluded_geo_countries: Vec<String>,
    /// Optional Go inbound-name matcher. Empty means that the rule is not
    /// constrained by the accepting inbound.
    pub inbound_names: Vec<String>,
    /// Negative inbound-name constraints from Go's `not` expression.
    pub excluded_inbound_names: Vec<String>,
    /// Optional Go process-list matcher. Empty means that the rule is not
    /// constrained by process metadata.
    pub process_names: Vec<String>,
    /// Negative process-list constraints from Go's `not` expression.
    pub excluded_process_names: Vec<String>,
    /// Patterns compiled once at route publication time and excluded from
    /// this rule. This keeps negative domain/CIDR matching on the same trie
    /// implementation as positive routing.
    pub excluded_patterns: CombinedTrie<()>,
    pub resolver_policy: ResolverPolicy,
    pub priority: i32,
}

impl RouteRule {
    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        self.matches_with_context(endpoint, None, None)
    }

    fn matches_with_context(
        &self,
        endpoint: &Endpoint,
        geo: Option<&dyn GeoLookup>,
        context: Option<&FlowContext>,
    ) -> bool {
        if self.excluded_patterns.search(endpoint).is_some() {
            return false;
        }
        if self
            .network
            .is_some_and(|network| network != endpoint.network())
        {
            return false;
        }
        if self
            .excluded_networks
            .iter()
            .any(|network| *network == endpoint.network())
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
        if let Some(port) = endpoint.port() {
            if self
                .excluded_ports
                .iter()
                .any(|(start, end)| port >= *start && port <= *end)
            {
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
        if !self.excluded_geo_countries.is_empty() {
            if let (Some(address), Some(geo)) = (endpoint.addr().map(|address| address.ip()), geo) {
                if let Ok(Some(actual)) = geo.country_code(address) {
                    if self
                        .excluded_geo_countries
                        .iter()
                        .any(|expected| actual.eq_ignore_ascii_case(expected))
                    {
                        return false;
                    }
                }
            }
        }
        if !self.inbound_names.is_empty() {
            let Some(context) = context else {
                return false;
            };
            let inbound = context
                .inbound_name
                .as_deref()
                .or(context.inbound.as_deref());
            if !inbound.is_some_and(|value| self.inbound_names.iter().any(|name| name == value)) {
                return false;
            }
        }
        if !self.process_names.is_empty() {
            let Some(context) = context else {
                return false;
            };
            if !context
                .process
                .as_deref()
                .is_some_and(|process| self.process_names.iter().any(|name| name == process))
            {
                return false;
            }
        }
        if let Some(context) = context {
            let inbound = context
                .inbound_name
                .as_deref()
                .or(context.inbound.as_deref());
            if inbound
                .is_some_and(|value| self.excluded_inbound_names.iter().any(|name| name == value))
            {
                return false;
            }
            if context.process.as_deref().is_some_and(|process| {
                self.excluded_process_names
                    .iter()
                    .any(|name| name == process)
            }) {
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
    /// Expanded rules in the same persisted-priority order used by Go's
    /// matcher.  The indexes above are for fast selection; this flat view is
    /// retained so connection metadata can explain rules that were tried and
    /// rejected before the selected rule.
    all_rules: Vec<RouteRule>,
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
        let all_rules = rules.clone();
        let mut index = Self {
            rules: CombinedTrie::new(),
            all_rules,
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
        self.decide_with_context(endpoint, None)
    }

    fn decide_with_context(
        &self,
        endpoint: &Endpoint,
        context: Option<&FlowContext>,
    ) -> RouteDecision {
        self.matched_decision(endpoint, context)
            .unwrap_or_else(|| self.fallback.clone())
    }

    fn matched_decision(
        &self,
        endpoint: &Endpoint,
        context: Option<&FlowContext>,
    ) -> Option<RouteDecision> {
        self.matched_rule(endpoint, context)
            .map(|rule| RouteDecision {
                mode: rule.action.into(),
                resolver_policy: rule.resolver_policy,
                priority: rule.priority,
            })
    }

    fn matched_rule<'a>(
        &'a self,
        endpoint: &Endpoint,
        context: Option<&FlowContext>,
    ) -> Option<&'a RouteRule> {
        let candidates = self.rules.search(endpoint);
        self.global_rules
            .iter()
            .chain(candidates.into_iter().flat_map(|rules| rules.iter()))
            .filter(|rule| rule.matches_with_context(endpoint, self.geo.as_deref(), context))
            // Go's route matcher walks rules in persisted priority order and
            // stops at the first match.  Lower priority values therefore win;
            // this is also what makes the UI's drag-and-drop order effective.
            .min_by_key(|rule| rule.priority)
    }

    fn selected_rule<'a>(&'a self, context: &FlowContext) -> Option<&'a RouteRule> {
        let packet = self.matched_rule(&context.destination, Some(context));
        let Some(_) = context.original_domain else {
            return packet;
        };
        let domain = self.matched_rule(&context.effective_destination(), Some(context));
        match (packet, domain) {
            (Some(packet), Some(domain)) if domain.priority <= packet.priority => Some(domain),
            (Some(packet), _) => Some(packet),
            (None, Some(domain)) => Some(domain),
            (None, None) => None,
        }
    }

    /// Evaluate both the packet tuple and a FakeIP-restored hostname.  A
    /// CIDR rule on the virtual address must keep working, while an explicit
    /// domain rule must also be able to override the fallback.  The normal
    /// rule priority decides when both forms match.
    pub fn decide_context(&self, context: &yuhaiin_core::FlowContext) -> RouteDecision {
        let packet = self.matched_decision(&context.destination, Some(context));
        let Some(_) = context.original_domain else {
            return packet.unwrap_or_else(|| self.fallback.clone());
        };
        let domain = self.matched_decision(&context.effective_destination(), Some(context));
        match (packet, domain) {
            (Some(packet), Some(domain)) if domain.priority <= packet.priority => domain,
            (Some(packet), _) => packet,
            (None, Some(domain)) => domain,
            (None, None) => self.fallback.clone(),
        }
    }

    /// Apply the same route decision as `decide_context` and retain the
    /// selected rule's explainability metadata on the flow.
    pub fn apply_to_context(&self, context: &mut FlowContext) -> RouteDecision {
        let selected_key = self
            .selected_rule(context)
            .map(|rule| (rule.rule_name.clone(), rule.priority));
        let decision = self
            .selected_rule(context)
            .map(|rule| RouteDecision {
                mode: rule.action.into(),
                resolver_policy: rule.resolver_policy,
                priority: rule.priority,
            })
            .unwrap_or_else(|| self.fallback.clone());
        if context.skip_route {
            return decision;
        }

        context.route_mode = decision.mode;
        context.resolver_policy = decision.resolver_policy;
        context.tag = None;
        context.match_history.clear();
        context.geo = None;
        if let Some(rule) = self.selected_rule(context) {
            context.tag = (!rule.tag.is_empty()).then(|| rule.tag.clone());
        }
        if let (Some(geo), Some(address)) = (
            self.geo.as_deref(),
            context
                .effective_destination()
                .addr()
                .map(|address| address.ip()),
        ) {
            if let Ok(Some(country)) = geo.country_code(address) {
                context.geo = Some(country);
            }
        }
        context.match_history = self.match_history(context, selected_key.as_ref());
        decision
    }

    fn pattern_matches(&self, rule: &RouteRule, endpoint: &Endpoint) -> bool {
        if rule.pattern.trim().is_empty() {
            return true;
        }
        self.rules
            .search(endpoint)
            .is_some_and(|rules| rules.iter().any(|candidate| candidate == rule))
    }

    fn rule_matches(&self, rule: &RouteRule, endpoint: &Endpoint, context: &FlowContext) -> bool {
        self.pattern_matches(rule, endpoint)
            && rule.matches_with_context(endpoint, self.geo.as_deref(), Some(context))
    }

    fn match_history(
        &self,
        context: &FlowContext,
        selected_key: Option<&(String, i32)>,
    ) -> Vec<MatchHistoryEntry> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < self.all_rules.len() {
            let first = &self.all_rules[offset];
            let key = (first.rule_name.clone(), first.priority);
            let mut history = Vec::new();
            let mut matched = false;
            while offset < self.all_rules.len()
                && self.all_rules[offset].rule_name == key.0
                && self.all_rules[offset].priority == key.1
            {
                let rule = &self.all_rules[offset];
                let endpoint = context.effective_destination();
                matched |= self.rule_matches(rule, &context.destination, context)
                    || (context.original_domain.is_some()
                        && self.rule_matches(rule, &endpoint, context));
                append_rule_history(&mut history, rule, context, &endpoint);
                offset += 1;
            }
            if !key.0.is_empty() {
                output.push(MatchHistoryEntry {
                    rule_name: key.0.clone(),
                    history,
                });
            }
            if selected_key == Some(&key) || matched && selected_key.is_none() {
                break;
            }
        }
        output
    }
}

fn append_rule_history(
    history: &mut Vec<MatchResult>,
    rule: &RouteRule,
    context: &FlowContext,
    endpoint: &Endpoint,
) {
    if let Some(expected) = rule
        .network
        .or_else(|| rule.excluded_networks.first().copied())
    {
        let label = match expected {
            Network::Tcp => Some("Net TCP"),
            Network::Udp => Some("Net UDP"),
            Network::Icmp | Network::Any => None,
        };
        if let Some(label) = label {
            history.push(MatchResult {
                list_name: label.to_owned(),
                matched: endpoint.network() == expected,
            });
        }
    }
    if let Some((start, end)) = rule.port {
        if let Some(port) = endpoint.port() {
            history.push(MatchResult {
                list_name: format!("Port {port}"),
                matched: (start..=end).contains(&port),
            });
        }
    } else if let Some((start, end)) = rule.excluded_ports.first() {
        if let Some(port) = endpoint.port() {
            history.push(MatchResult {
                list_name: format!("Port {port}"),
                matched: (*start..=*end).contains(&port),
            });
        }
    }
    if !rule.inbound_names.is_empty() || !rule.excluded_inbound_names.is_empty() {
        let inbound = context
            .inbound_name
            .as_deref()
            .or(context.inbound.as_deref())
            .unwrap_or_default();
        let matched = rule
            .inbound_names
            .iter()
            .chain(rule.excluded_inbound_names.iter())
            .any(|name| name == inbound);
        history.push(MatchResult {
            list_name: inbound.to_owned(),
            matched,
        });
    }
    if rule.geo_country.is_some() || !rule.excluded_geo_countries.is_empty() {
        let country = context.geo.as_deref().unwrap_or_default();
        let matched = rule
            .geo_country
            .as_deref()
            .into_iter()
            .chain(rule.excluded_geo_countries.iter().map(String::as_str))
            .any(|expected| expected.eq_ignore_ascii_case(country));
        history.push(MatchResult {
            list_name: format!("Geoip {country}"),
            matched,
        });
    }
    // Go's nested List matcher consults the host/process trie membership that
    // was populated before route evaluation. It does not re-run the rule's
    // domain/process expression here; a rule can therefore report a matched
    // list even when a later matcher rejects the whole rule.
    for list_name in &rule.list_names {
        history.push(MatchResult {
            list_name: format!("List {list_name}"),
            matched: context.lists.iter().any(|name| name == list_name),
        });
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
        self.snapshot().apply_to_context(context)
    }

    /// Return the rule that actually selected the current context, if any.
    /// This is distinct from the last match-history entry: Go keeps rejected
    /// rules in that history even when the fallback mode is ultimately used.
    pub fn selected_rule_name(&self, context: &yuhaiin_core::FlowContext) -> Option<String> {
        self.snapshot()
            .selected_rule(context)
            .filter(|rule| !rule.rule_name.is_empty())
            .map(|rule| rule.rule_name.clone())
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
    fn route_context(&self, context: &mut FlowContext) {
        self.router.apply_to_context(context);
    }

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
    fn route_context(&self, context: &mut FlowContext) {
        self.router.apply_to_context(context);
    }

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
            rule_name: String::new(),
            tag: String::new(),
            list_names: Vec::new(),
            pattern: pattern.to_owned(),
            action,
            network: None,
            excluded_networks: Vec::new(),
            port: None,
            excluded_ports: Vec::new(),
            geo_country: None,
            excluded_geo_countries: Vec::new(),
            inbound_names: Vec::new(),
            excluded_inbound_names: Vec::new(),
            process_names: Vec::new(),
            excluded_process_names: Vec::new(),
            excluded_patterns: CombinedTrie::new(),
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
    fn route_metadata_follows_the_selected_rule_and_geo_snapshot() {
        let mut selected = rule("198.51.100.0/24", RuleAction::Proxy, 10);
        selected.rule_name = "media-rule".to_owned();
        selected.tag = "streaming".to_owned();
        selected.list_names = vec!["media-hosts".to_owned(), "media-hosts".to_owned()];
        let router = Router::compile(
            vec![selected],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
        )
        .unwrap()
        .with_geo_lookup(Arc::new(StaticGeo { code: Some("CN") }));
        let mut context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.7:443".parse().unwrap(),
        ));
        context.lists = vec!["media-hosts".to_owned()];

        router.apply_to_context(&mut context);

        assert_eq!(context.route_mode, RouteMode::Proxy);
        assert_eq!(context.tag.as_deref(), Some("streaming"));
        assert_eq!(context.lists, vec!["media-hosts"]);
        assert_eq!(context.geo.as_deref(), Some("CN"));
        assert_eq!(context.match_history.len(), 1);
        assert_eq!(context.match_history[0].rule_name, "media-rule");
        assert_eq!(
            context.match_history[0].history[0].list_name,
            "List media-hosts"
        );
        assert!(context.match_history[0].history[0].matched);
    }

    #[test]
    fn route_match_history_keeps_rejected_rules_before_the_selected_rule() {
        let mut rejected = rule("not-example.com", RuleAction::Direct, 1);
        rejected.rule_name = "rejected-rule".to_owned();
        rejected.list_names = vec!["not-example".to_owned()];
        let mut selected = rule("example.com", RuleAction::Proxy, 2);
        selected.rule_name = "selected-rule".to_owned();
        selected.list_names = vec!["example".to_owned()];
        let router = Router::compile(
            vec![rejected, selected],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
        )
        .unwrap();
        let mut context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("www.example.com").unwrap(),
            443,
        ));
        context.lists = vec!["example".to_owned()];
        router.apply_to_context(&mut context);

        assert_eq!(context.match_history.len(), 2);
        assert_eq!(context.match_history[0].rule_name, "rejected-rule");
        assert_eq!(
            context.match_history[0].history[0],
            MatchResult {
                list_name: "List not-example".to_owned(),
                matched: false,
            }
        );
        assert_eq!(context.match_history[1].rule_name, "selected-rule");
        assert!(context.match_history[1].history[0].matched);
    }

    #[test]
    fn route_match_history_keeps_list_match_when_a_later_process_match_rejects_rule() {
        let mut rejected = rule("example.com", RuleAction::Direct, 1);
        rejected.rule_name = "process-rejected".to_owned();
        rejected.list_names = vec!["shared-hosts".to_owned()];
        rejected.process_names = vec!["curl".to_owned()];
        let mut selected = rule("example.com", RuleAction::Proxy, 2);
        selected.rule_name = "fallback-rule".to_owned();
        selected.list_names = vec!["selected-hosts".to_owned()];
        let router = Router::compile(
            vec![rejected, selected],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
        )
        .unwrap();
        let mut context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("www.example.com").unwrap(),
            443,
        ));
        context.process = Some("browser".to_owned());
        context.lists = vec!["shared-hosts".to_owned(), "selected-hosts".to_owned()];

        router.apply_to_context(&mut context);

        assert_eq!(context.match_history.len(), 2);
        assert_eq!(context.match_history[0].rule_name, "process-rejected");
        assert_eq!(
            context.match_history[0].history[0].list_name,
            "List shared-hosts"
        );
        assert!(context.match_history[0].history[0].matched);
        assert_eq!(context.match_history[1].rule_name, "fallback-rule");
        assert!(context.match_history[1].history[0].matched);
    }

    #[test]
    fn runtime_selected_rule_name_ignores_last_rejected_rule_on_fallback() {
        let mut rejected = rule("example.com", RuleAction::Direct, 1);
        rejected.rule_name = "rejected-rule".to_owned();
        let router = RouterRuntime::new(
            Router::compile(
                vec![rejected],
                RouteDecision {
                    mode: RouteMode::Proxy,
                    resolver_policy: ResolverPolicy::default(),
                    priority: 100,
                },
            )
            .unwrap(),
        );
        let mut context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("other.example").unwrap(),
            443,
        ));

        assert_eq!(router.apply_to_context(&mut context).mode, RouteMode::Proxy);
        assert_eq!(context.match_history.len(), 1);
        assert!(router.selected_rule_name(&context).is_none());
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
    fn router_applies_negative_pattern_network_port_and_context_constraints() {
        let mut negative = rule("", RuleAction::Proxy, 10);
        negative
            .excluded_patterns
            .insert("blocked.example", ())
            .unwrap();
        negative.excluded_networks.push(Network::Udp);
        negative.excluded_ports.push((80, 80));
        negative.excluded_inbound_names.push("http-main".to_owned());
        negative.excluded_process_names.push("browser".to_owned());
        let router = Router::compile(
            vec![negative],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap();
        let allowed = Endpoint::domain(
            Network::Tcp,
            DomainName::new("allowed.example").unwrap(),
            443,
        );
        let blocked_domain = Endpoint::domain(
            Network::Tcp,
            DomainName::new("www.blocked.example").unwrap(),
            443,
        );
        assert_eq!(router.decide(&allowed).mode, RouteMode::Proxy);
        assert_eq!(router.decide(&blocked_domain).mode, RouteMode::Direct);

        let udp = Endpoint::ip(Network::Udp, "192.0.2.1:443".parse().unwrap());
        let port = Endpoint::ip(Network::Tcp, "192.0.2.1:80".parse().unwrap());
        assert_eq!(router.decide(&udp).mode, RouteMode::Direct);
        assert_eq!(router.decide(&port).mode, RouteMode::Direct);

        let mut context = FlowContext::new(allowed.clone());
        context.inbound_name = Some("http-main".to_owned());
        assert_eq!(router.decide_context(&context).mode, RouteMode::Direct);
        context.inbound_name = Some("socks-main".to_owned());
        context.process = Some("browser".to_owned());
        assert_eq!(router.decide_context(&context).mode, RouteMode::Direct);
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
    fn fakeip_context_does_not_let_domain_fallback_override_a_cidr_match() {
        let mut cidr = rule("198.18.0.0/15", RuleAction::Proxy, 10);
        cidr.network = Some(Network::Udp);
        cidr.port = Some((443, 443));
        let router = Router::compile(
            vec![cidr],
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
