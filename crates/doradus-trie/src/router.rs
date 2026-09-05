//! Immutable-after-build route rule index built on the domain/CIDR tries.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use doradus_core::{
    Endpoint, FlowContext, GeoLookup, MatchHistoryEntry, MatchResult, Network, ResolverPolicy,
    RouteMode,
};

use doradus_core::proxy::{AsyncProxy, AsyncProxySelector};

use crate::{CombinedTrie, HostTrie};

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
    /// Names of Go host/process lists contributing to this route rule.
    pub list_names: Vec<String>,
    /// Primary domain/CIDR pattern used to find candidates in `Router::rules`.
    pub pattern: String,
    /// Positive Go host-list constraints. The list index is shared with the
    /// route-list snapshot instead of expanding one RouteRule per entry.
    pub host_lists: Vec<Arc<HostTrie>>,
    /// Additional positive domain/CIDR constraints from a Go `all` matcher.
    /// Every index must match the endpoint after the primary candidate lookup.
    pub required_patterns: Vec<HostTrie>,
    /// Preserve a rule whose Go list is not loaded yet, but keep it
    /// fail-closed until the list contents become available.
    pub always_false: bool,
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
    pub excluded_patterns: HostTrie,
    /// Negative Go host-list constraints, also shared by Arc.
    pub excluded_host_lists: Vec<Arc<HostTrie>>,
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
        if self.always_false {
            return false;
        }
        if self.excluded_patterns.search(endpoint).is_some() {
            return false;
        }
        if self
            .excluded_host_lists
            .iter()
            .any(|index| index.search_parent(endpoint).is_some())
        {
            return false;
        }
        if self
            .host_lists
            .iter()
            .any(|index| index.search_parent(endpoint).is_none())
        {
            return false;
        }
        if self
            .required_patterns
            .iter()
            .any(|patterns| patterns.search(endpoint).is_none())
        {
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
        if let Some(port) = endpoint.port()
            && self
                .excluded_ports
                .iter()
                .any(|(start, end)| port >= *start && port <= *end)
        {
            return false;
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
        if !self.excluded_geo_countries.is_empty()
            && let (Some(address), Some(geo)) = (endpoint.addr().map(|address| address.ip()), geo)
            && let Ok(Some(actual)) = geo.country_code(address)
            && self
                .excluded_geo_countries
                .iter()
                .any(|expected| actual.eq_ignore_ascii_case(expected))
        {
            return false;
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
    rules: CombinedTrie<Vec<Arc<RouteRule>>>,
    /// Rules in the same persisted-priority order used by Go's matcher. The
    /// indexes above are for fast selection; this flat view is retained so
    /// connection metadata can explain rules that were tried and rejected.
    all_rules: Vec<Arc<RouteRule>>,
    /// Rules without a domain/CIDR matcher (for example Go's network-only or
    /// empty `all` rule) are evaluated for every endpoint. Keeping them out of
    /// the trie avoids inventing a fake domain that would not match IP flows.
    global_rules: Vec<Arc<RouteRule>>,
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
        let rules = rules.into_iter().map(Arc::new).collect::<Vec<_>>();
        let all_rules = rules.clone();
        let mut index = Self {
            rules: CombinedTrie::new(),
            all_rules,
            global_rules: Vec::new(),
            fallback,
            geo: None,
        };
        let mut grouped: BTreeMap<String, Vec<Arc<RouteRule>>> = BTreeMap::new();
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
            .map(|rule| rule.as_ref())
    }

    fn selected_rule<'a>(&'a self, context: &FlowContext) -> Option<&'a RouteRule> {
        let endpoint = context.effective_destination();
        self.matched_rule(&endpoint, Some(context))
    }

    /// Route using the effective destination. For a FakeIP flow this is the
    /// hostname restored from the pool; the synthetic packet address must not
    /// match LAN/CIDR rules before the hostname gets a chance to use the
    /// normal rule set or the proxy fallback.
    pub fn decide_context(&self, context: &doradus_core::FlowContext) -> RouteDecision {
        let endpoint = context.effective_destination();
        self.matched_decision(&endpoint, Some(context))
            .unwrap_or_else(|| self.fallback.clone())
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
        ) && let Ok(Some(country)) = geo.country_code(address)
        {
            context.geo = Some(country);
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
            .is_some_and(|rules| rules.iter().any(|candidate| candidate.as_ref() == rule))
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
            let first = self.all_rules[offset].as_ref();
            let key = (first.rule_name.clone(), first.priority);
            let mut history = Vec::new();
            let mut matched = false;
            while offset < self.all_rules.len()
                && self.all_rules[offset].rule_name == key.0
                && self.all_rules[offset].priority == key.1
            {
                let rule = self.all_rules[offset].as_ref();
                let endpoint = context.effective_destination();
                matched |= self.rule_matches(rule, &endpoint, context);
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
    // Go sorts nested predicates before evaluating them and stops an `all`
    // expression at its first false child. The expanded Rust rule may carry
    // several variants for one Go rule, so also suppress the duplicate
    // explainability entries produced by those variants.
    let mut record = |list_name: String, matched: bool| {
        if !history.iter().any(|result| result.list_name == list_name) {
            history.push(MatchResult { list_name, matched });
        }
        matched
    };
    if let Some((start, end)) = rule.port {
        if let Some(port) = endpoint.port()
            && !record(format!("Port {port}"), (start..=end).contains(&port))
        {
            return;
        }
    } else if let Some((start, end)) = rule.excluded_ports.first()
        && let Some(port) = endpoint.port()
        && !record(format!("Port {port}"), (*start..=*end).contains(&port))
    {
        return;
    }
    if let Some(expected) = rule
        .network
        .or_else(|| rule.excluded_networks.first().copied())
    {
        let label = match expected {
            Network::Tcp => Some("Net TCP"),
            Network::Udp => Some("Net UDP"),
            Network::Icmp | Network::Any => None,
        };
        if let Some(label) = label
            && !record(label.to_owned(), endpoint.network() == expected)
        {
            return;
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
        if !record(inbound.to_owned(), matched) {
            return;
        }
    }
    if rule.geo_country.is_some() || !rule.excluded_geo_countries.is_empty() {
        let country = context.geo.as_deref().unwrap_or_default();
        let matched = rule
            .geo_country
            .as_deref()
            .into_iter()
            .chain(rule.excluded_geo_countries.iter().map(String::as_str))
            .any(|expected| expected.eq_ignore_ascii_case(country));
        if !record(format!("Geoip {country}"), matched) {
            return;
        }
    }
    // Go's nested List matcher consults the host/process trie membership that
    // was populated before route evaluation. It does not re-run the rule's
    // domain/process expression here; a rule can therefore report a matched
    // list even when a later matcher rejects the whole rule.
    for list_name in &rule.list_names {
        if !record(
            format!("List {list_name}"),
            context.lists.iter().any(|name| name == list_name),
        ) {
            return;
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

    pub fn apply_to_context(&self, context: &mut doradus_core::FlowContext) -> RouteDecision {
        self.snapshot().apply_to_context(context)
    }

    /// Return the rule that actually selected the current context, if any.
    /// This is distinct from the last match-history entry: Go keeps rejected
    /// rules in that history even when the fallback mode is ultimately used.
    pub fn selected_rule_name(&self, context: &doradus_core::FlowContext) -> Option<String> {
        self.snapshot()
            .selected_rule(context)
            .filter(|rule| !rule.rule_name.is_empty())
            .map(|rule| rule.rule_name.clone())
    }
}

/// Selects the async proxy implementation for a flow using one immutable
/// router snapshot.  The selector deliberately lives in the trie crate rather
/// than in `doradus-core`, so the core packet/proxy contracts do not depend on
/// a particular rule index implementation.
pub struct RoutedProxySelector {
    pub router: Arc<Router>,
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for RoutedProxySelector {
    fn route_context(&self, context: &mut FlowContext) {
        self.router.apply_to_context(context);
    }

    fn select(&self, context: &doradus_core::FlowContext) -> Arc<dyn AsyncProxy> {
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
#[derive(Clone)]
pub struct RuntimeRoutedProxySelector {
    pub router: RouterRuntime,
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for RuntimeRoutedProxySelector {
    fn route_context(&self, context: &mut FlowContext) {
        self.router.apply_to_context(context);
    }

    fn select(&self, context: &doradus_core::FlowContext) -> Arc<dyn AsyncProxy> {
        let mode = if context.skip_route {
            context.route_mode
        } else {
            self.router.snapshot().decide_context(context).mode
        };
        select_proxy(mode, &self.direct, &self.proxy, &self.bypass, &self.drop)
    }
}

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
#[path = "router_tests.rs"]
mod tests;
