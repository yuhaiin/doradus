//! Build and own the effective node choices and their shared proxy instances.

use super::*;

#[derive(Clone)]
pub(super) struct ProxySelection {
    pub(super) direct: String,
    pub(super) tcp: String,
    pub(super) udp: String,
    pub(super) bypass: String,
    pub(super) drop: String,
}

impl ProxySelection {
    pub(super) fn new(direct: &str, tcp: &str, udp: &str, bypass: &str, drop: &str) -> Self {
        Self {
            direct: direct.into(),
            tcp: tcp.into(),
            udp: udp.into(),
            bypass: bypass.into(),
            drop: drop.into(),
        }
    }

    pub(super) fn ids(&self) -> [&str; 5] {
        [&self.direct, &self.tcp, &self.udp, &self.bypass, &self.drop]
    }

    pub(super) fn retarget_to_direct(&mut self, id: &str) {
        for slot in [
            &mut self.direct,
            &mut self.tcp,
            &mut self.udp,
            &mut self.bypass,
            &mut self.drop,
        ] {
            if slot == id {
                slot.clear();
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct TaggedProxy {
    pub(super) members: Vec<(String, Arc<dyn AsyncProxy>)>,
    pub(super) proxy: Arc<dyn AsyncProxy>,
    strategy: NodeSelectionStrategy,
}

impl TaggedProxy {
    fn new(members: Vec<(String, Arc<dyn AsyncProxy>)>, strategy: NodeSelectionStrategy) -> Self {
        let mut binding = Self {
            members,
            strategy,
            proxy: Arc::new(DropAsyncProxy),
        };
        binding.rebuild();
        binding
    }

    pub(super) fn rebuild(&mut self) {
        self.proxy = match self.members.len() {
            0 => Arc::new(DropAsyncProxy),
            1 => self.members[0].1.clone(),
            _ => Arc::new(
                NodeSetProxy::new(
                    self.members
                        .iter()
                        .map(|(_, proxy)| proxy.clone())
                        .collect(),
                    self.strategy,
                )
                .expect("nonempty node set"),
            ),
        };
    }
}

pub(super) struct SelectorBuild<'a> {
    snapshot: &'a RuntimeSnapshot,
    timeout: Duration,
    loopback: &'a LoopbackDetector,
    nodes: BTreeMap<String, Arc<dyn AsyncProxy>>,
    direct: Option<Arc<dyn AsyncProxy>>,
    reject: Option<Arc<dyn AsyncProxy>>,
}

impl<'a> SelectorBuild<'a> {
    pub(super) fn new(
        snapshot: &'a RuntimeSnapshot,
        timeout: Duration,
        loopback: &'a LoopbackDetector,
    ) -> Self {
        Self {
            snapshot,
            timeout,
            loopback,
            nodes: BTreeMap::new(),
            direct: None,
            reject: None,
        }
    }

    async fn node(&mut self, id: &str) -> Result<Arc<dyn AsyncProxy>> {
        if let Some(proxy) = self.nodes.get(id) {
            return Ok(proxy.clone());
        }
        let proxy = track_proxy(
            self.snapshot.build_proxy(id, self.timeout).await?.proxy,
            self.loopback,
        );
        self.nodes.insert(id.to_owned(), proxy.clone());
        Ok(proxy)
    }

    async fn slot(&mut self, id: &str, reject: bool) -> Result<Arc<dyn AsyncProxy>> {
        if !id.trim().is_empty() && (reject || id != "direct") {
            return self.node(id).await;
        }
        let cached = if reject { &self.reject } else { &self.direct };
        if let Some(proxy) = cached {
            return Ok(proxy.clone());
        }
        let kind = if reject {
            BaseProxyKind::Reject
        } else {
            BaseProxyKind::Direct
        };
        let proxy = track_proxy(
            self.snapshot
                .build_proxy_slot("", self.timeout, kind)
                .await?,
            self.loopback,
        );
        let cached = if reject {
            &mut self.reject
        } else {
            &mut self.direct
        };
        *cached = Some(proxy.clone());
        Ok(proxy)
    }

    pub(super) async fn build(mut self, selection: ProxySelection) -> Result<SelectorState> {
        let direct = self.slot(&selection.direct, false).await?;
        let tcp = self.slot(&selection.tcp, false).await?;
        let udp = self.slot(&selection.udp, false).await?;
        let bypass = self.slot(&selection.bypass, false).await?;
        let drop = self.slot(&selection.drop, true).await?;
        let current = RuntimeRoutedProxySelector {
            router: self.snapshot.router.clone(),
            direct: direct.clone(),
            proxy: tcp,
            bypass: bypass.clone(),
            drop: drop.clone(),
        };
        let udp_current = RuntimeRoutedProxySelector {
            router: self.snapshot.router.clone(),
            direct,
            proxy: udp,
            bypass,
            drop,
        };
        let definitions = self.snapshot.node_tag_definitions()?;
        let mut tagged = BTreeMap::new();
        for (tag, definition) in &definitions {
            let mut members = Vec::new();
            let mut seen = BTreeSet::new();
            for id in resolve_node_tag_targets(tag, &definitions, &mut BTreeSet::new()) {
                // Disabled/missing tag members keep the existing fallback policy.
                if seen.insert(id.clone())
                    && let Ok(proxy) = self.node(&id).await
                {
                    members.push((id, proxy));
                }
            }
            if !members.is_empty() {
                tagged.insert(tag.clone(), TaggedProxy::new(members, definition.strategy));
            }
        }
        let metadata = Arc::new(
            self.snapshot
                .proxy_context_metadata(
                    &selection.direct,
                    &selection.tcp,
                    &selection.udp,
                    &selection.bypass,
                    &selection.drop,
                )
                .await?,
        );
        Ok(SelectorState {
            current,
            udp_current,
            selection,
            nodes: self.nodes,
            tagged,
            closed_nodes: BTreeSet::new(),
            metadata,
            settings: self.snapshot.settings.clone(),
        })
    }
}
