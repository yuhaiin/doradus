use std::{
    collections::BTreeSet,
    future::Future,
    path::PathBuf,
    sync::{Arc, RwLock, Weak},
};

use yuhaiin_core::Result;
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_store::{ConfigMutation, ConfigStore};

use crate::data_plane::{ReloadableAsyncDnsHandler, inbound_dns_handler};
use crate::monitor::SocketDnsHandler;
use crate::{
    ConnectionMonitor, ResolverProxyBridge, RuntimeBuilder, RuntimeHandle, RuntimeProxySelector,
    RuntimeSnapshot,
};

/// Shared configuration-to-runtime owner for management APIs.
///
/// The controller keeps the persisted store, builder and published snapshot
/// together.  A management handler can apply generic configuration mutations
/// or request a reload without creating a second DTO tree or independently
/// inventing transaction/revision rules.
#[derive(Clone)]
pub struct RuntimeController {
    builder: Arc<RuntimeBuilder>,
    handle: RuntimeHandle,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    reload_error: Arc<RwLock<Option<String>>>,
    selectors: Arc<RwLock<Vec<Weak<RuntimeProxySelector>>>>,
    monitor: Arc<ConnectionMonitor>,
    reload_events: tokio::sync::broadcast::Sender<()>,
    inbound_reload_events: tokio::sync::broadcast::Sender<()>,
    tun_dns_handler: Arc<ReloadableAsyncDnsHandler>,
    restore_request: Arc<RwLock<Option<PathBuf>>>,
    resolver_proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

impl RuntimeController {
    /// Build and publish the initial snapshot before exposing the controller.
    pub async fn from_builder(builder: RuntimeBuilder) -> Result<Self> {
        let builder = Arc::new(builder);
        let resolver_proxy_bridge = builder.resolver_proxy_bridge();
        let initial_snapshot = builder.build().await?;
        let (reload_events, _) = tokio::sync::broadcast::channel(32);
        let (inbound_reload_events, _) = tokio::sync::broadcast::channel(32);
        let monitor = Arc::new(ConnectionMonitor::load_with_store(builder.store().clone()).await?);
        if let Some(bridge) = &resolver_proxy_bridge {
            bridge.set_monitor(&monitor);
        }
        monitor.set_sniff_enabled(initial_snapshot.inbound_settings.sniff);
        monitor.set_dns_handler(
            inbound_dns_handler(&initial_snapshot)
                .map(|handler| handler as Arc<dyn SocketDnsHandler>),
        );
        let tun_dns_handler = Arc::new(ReloadableAsyncDnsHandler::new(
            inbound_dns_handler(&initial_snapshot).map(|handler| (*handler).clone()),
        ));
        let handle = RuntimeHandle::new(initial_snapshot);
        Ok(Self {
            builder,
            handle,
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            reload_error: Arc::new(RwLock::new(None)),
            selectors: Arc::new(RwLock::new(Vec::new())),
            monitor,
            reload_events,
            inbound_reload_events,
            tun_dns_handler,
            restore_request: Arc::new(RwLock::new(None)),
            resolver_proxy_bridge,
        })
    }

    pub fn store(&self) -> &ConfigStore {
        self.builder.store()
    }

    pub fn handle(&self) -> &RuntimeHandle {
        &self.handle
    }

    pub fn monitor(&self) -> Arc<ConnectionMonitor> {
        self.monitor.clone()
    }

    pub(crate) fn tun_dns_handler(&self) -> Arc<ReloadableAsyncDnsHandler> {
        self.tun_dns_handler.clone()
    }

    /// Flush and stop the monitor's owned SQLite persistence task after all
    /// data-plane owners have been joined.
    pub async fn persist_monitor(&self) -> Result<()> {
        self.monitor.shutdown().await
    }

    /// Close the runtime instance associated with a node without deleting its
    /// persisted configuration. Existing selectors replace matching slots by
    /// a fail-closed proxy and close the previous instances; a later
    /// successful reload reconstructs the slots from persisted configuration.
    pub async fn close_node(&self, id: &str) -> Result<()> {
        if id.trim().is_empty() {
            return Ok(());
        }
        let _guard = self.reload_lock.lock().await;
        for selector in self.live_selectors() {
            selector.close_node(id).await;
        }
        Ok(())
    }

    /// Prepare every live selector for deletion of a node. The selected node
    /// is closed immediately, then its selector roles are changed to the
    /// built-in fallbacks so the following store mutation can reload the
    /// runtime without referring to a row that no longer exists.
    pub async fn retarget_node_to_direct(&self, id: &str) -> Result<()> {
        if id.trim().is_empty() {
            return Ok(());
        }
        let _guard = self.reload_lock.lock().await;
        for selector in self.live_selectors() {
            selector.retarget_node_to_direct(id).await;
        }
        Ok(())
    }

    pub fn subscribe_reload(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.reload_events.subscribe()
    }

    /// Subscribe to changes that require rebinding inbound listeners.
    ///
    /// Node, route, resolver, and backup changes publish only the ordinary
    /// reload event because registered selectors are refreshed in place.
    /// Inbound/user changes additionally publish this event so listeners can
    /// be replaced without interrupting unrelated live connections.
    pub fn subscribe_inbound_reload(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.inbound_reload_events.subscribe()
    }

    pub fn request_restore(&self, source: PathBuf) {
        *self
            .restore_request
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(source);
    }

    pub fn take_restore_request(&self) -> Option<PathBuf> {
        self.restore_request
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// Build and register a TUN proxy selector. The controller refreshes all
    /// live registered selectors before publishing a new snapshot, so a
    /// configuration reload cannot expose a new route table with old proxy
    /// instances to new flows.
    pub async fn build_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: std::time::Duration,
    ) -> Result<Arc<RuntimeProxySelector>> {
        self.build_proxy_selector_with_udp(
            direct_id, proxy_id, proxy_id, bypass_id, drop_id, timeout,
        )
        .await
    }

    /// Build one short-lived proxy for management-plane traffic such as S3
    /// backup. It uses the same immutable snapshot and proxy slot assembly as
    /// inbound flows, but does not register a second long-lived selector.
    pub async fn build_management_proxy(
        &self,
        id: &str,
        timeout: std::time::Duration,
    ) -> Result<Arc<dyn AsyncProxy>> {
        self.handle
            .load()
            .build_proxy_for_management(id, timeout)
            .await
    }

    /// Build a live selector with independent TCP and UDP proxy nodes, as
    /// persisted by Go's `selected_tcp_node_v2` and `selected_udp_node_v2`.
    pub async fn build_proxy_selector_with_udp(
        &self,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: std::time::Duration,
    ) -> Result<Arc<RuntimeProxySelector>> {
        let _guard = self.reload_lock.lock().await;
        let selector = Arc::new(
            self.handle
                .load()
                .build_proxy_selector_with_udp(
                    direct_id,
                    tcp_proxy_id,
                    udp_proxy_id,
                    bypass_id,
                    drop_id,
                    timeout,
                )
                .await?,
        );
        self.register_selector(&selector);
        if let Some(bridge) = &self.resolver_proxy_bridge {
            bridge.set_selector(selector.clone());
        }
        Ok(selector)
    }

    /// Return the persisted node IDs represented by currently live runtime
    /// proxy selectors. This mirrors Go's `NodeRuntime.Active`, which reports
    /// proxy entries that have actually been opened rather than every enabled
    /// row in the node store.
    pub fn active_proxy_ids(&self) -> Vec<String> {
        let mut ids = BTreeSet::new();
        for selector in self.live_selectors() {
            ids.extend(selector.active_node_ids());
        }
        ids.into_iter().collect()
    }

    /// Assemble the first TUN data-plane runtime from one consistent
    /// snapshot. The selector is registered before it is returned to the
    /// caller, so later reloads replace its proxy slots atomically. NAT is
    /// always endpoint-independent Full Cone NAT and uses the persisted idle
    /// timeout from the same snapshot.
    #[cfg(feature = "tun")]
    pub async fn build_tun_proxy_runtime(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        proxy_timeout: std::time::Duration,
        channel_capacity: usize,
    ) -> Result<yuhaiin_core::tun::TunProxyRuntime> {
        self.build_tun_proxy_runtime_with_dns(
            direct_id,
            proxy_id,
            bypass_id,
            drop_id,
            proxy_timeout,
            channel_capacity,
            None,
        )
        .await
    }

    /// Variant of [`Self::build_tun_proxy_runtime`] that installs the
    /// application's packet-level async DNS handler while the TUN runtime is
    /// assembled. The handler is injected because the shared runtime
    /// resolver is intentionally an IP-resolution trait; this keeps DoH/UDP/
    /// FakeIP packet policy in the DNS layer instead of duplicating it here.
    #[cfg(feature = "tun")]
    #[allow(clippy::too_many_arguments)]
    pub async fn build_tun_proxy_runtime_with_dns(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        proxy_timeout: std::time::Duration,
        channel_capacity: usize,
        async_dns_handler: Option<Arc<dyn yuhaiin_core::dns::AsyncDnsHandler>>,
    ) -> Result<yuhaiin_core::tun::TunProxyRuntime> {
        self.build_tun_proxy_runtime_with_dns_and_udp(
            direct_id,
            proxy_id,
            proxy_id,
            bypass_id,
            drop_id,
            proxy_timeout,
            channel_capacity,
            async_dns_handler,
        )
        .await
    }

    /// TUN variant with separate TCP and UDP selected outbound nodes.
    #[cfg(feature = "tun")]
    #[allow(clippy::too_many_arguments)]
    pub async fn build_tun_proxy_runtime_with_dns_and_udp(
        &self,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        proxy_timeout: std::time::Duration,
        channel_capacity: usize,
        async_dns_handler: Option<Arc<dyn yuhaiin_core::dns::AsyncDnsHandler>>,
    ) -> Result<yuhaiin_core::tun::TunProxyRuntime> {
        let _guard = self.reload_lock.lock().await;
        let snapshot = self.handle.load();
        let selector = Arc::new(
            snapshot
                .build_proxy_selector_with_udp(
                    direct_id,
                    tcp_proxy_id,
                    udp_proxy_id,
                    bypass_id,
                    drop_id,
                    proxy_timeout,
                )
                .await?,
        );
        let (nat, idle_timeout) = snapshot.new_full_cone_nat()?;
        let fakeip_view = match snapshot
            .inbound_fakeip
            .as_ref()
            .or(snapshot.fakeip.as_ref())
        {
            Some(pools) => {
                pools.snapshot().await;
                Some(pools.view_store())
            }
            None => None,
        };
        let mut runtime =
            yuhaiin_core::tun::TunProxyRuntime::new(selector.clone(), channel_capacity)?
                .with_nat(nat, idle_timeout)?;
        runtime = runtime.with_context_provider(move |flow| {
            let mut context = flow.context();
            if let Some(fakeip_view) = &fakeip_view
                && let Some(domain) = fakeip_view.lookup_domain_ip(flow.key.destination.ip())
            {
                context.original_domain = Some(domain);
                context.fake_ip = Some(flow.key.destination.ip().to_string());
            }
            context
        });
        runtime = runtime.with_observer(self.monitor.clone());
        if let Some(handler) = async_dns_handler {
            runtime = runtime.with_async_dns_handler(handler);
        }
        self.register_selector(&selector);
        Ok(runtime)
    }

    /// Last mutation/reload error for a management status response.  A
    /// successful reload clears it; the persisted configuration is never
    /// replaced by this in-memory status value.
    pub fn last_reload_error(&self) -> Option<String> {
        self.reload_error
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Rebuild and publish the current persisted configuration.  Concurrent
    /// reloads are serialized so a slower build cannot supersede a newer one.
    pub async fn reload(&self) -> Result<Arc<RuntimeSnapshot>> {
        let _guard = self.reload_lock.lock().await;
        self.rebuild_locked(false).await
    }

    /// Run a typed repository mutation under the same management lock, then
    /// rebuild and publish.  The closure receives the shared store handle, so
    /// node/resolver/route APIs can be used without duplicating controller
    /// methods for every persisted record.
    pub async fn mutate_and_reload<F, Fut>(&self, operation: F) -> Result<Arc<RuntimeSnapshot>>
    where
        F: FnOnce(ConfigStore) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let _guard = self.reload_lock.lock().await;
        if let Err(error) = operation(self.store().clone()).await {
            self.set_reload_error(&error.to_string());
            return Err(error);
        }
        self.rebuild_locked(false).await
    }

    pub async fn mutate_and_reload_inbounds<F, Fut>(
        &self,
        operation: F,
    ) -> Result<Arc<RuntimeSnapshot>>
    where
        F: FnOnce(ConfigStore) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let _guard = self.reload_lock.lock().await;
        if let Err(error) = operation(self.store().clone()).await {
            self.set_reload_error(&error.to_string());
            return Err(error);
        }
        self.rebuild_locked(true).await
    }

    /// Commit generic configuration mutations, then rebuild the runtime from
    /// the same store.  If rebuilding fails, the committed configuration is
    /// retained and the previous snapshot remains active for existing/new
    /// flows; the returned error tells the management layer to report/retry it.
    pub async fn apply(&self, mutations: &[ConfigMutation]) -> Result<Arc<RuntimeSnapshot>> {
        let mutations = mutations.to_vec();
        self.mutate_and_reload_inbounds(|store| async move { store.apply(&mutations).await })
            .await
    }

    async fn rebuild_locked(&self, reload_inbounds: bool) -> Result<Arc<RuntimeSnapshot>> {
        let expected_revision = self.handle.revision();
        let next = match self.builder.build().await {
            Ok(snapshot) => Arc::new(snapshot),
            Err(error) => {
                self.set_reload_error(&error.to_string());
                return Err(error);
            }
        };

        let selectors = self.live_selectors();
        let mut prepared = Vec::with_capacity(selectors.len());
        for selector in &selectors {
            match selector.prepare(&next).await {
                Ok(proxy) => prepared.push(proxy),
                Err(error) => {
                    self.set_reload_error(&error.to_string());
                    return Err(error);
                }
            }
        }

        if let Err(error) = self
            .handle
            .publish_arc_if_revision(expected_revision, next.clone())
        {
            self.set_reload_error(&error.to_string());
            return Err(error);
        }
        for (selector, proxy) in selectors.into_iter().zip(prepared) {
            selector.replace(proxy);
        }
        self.monitor.set_sniff_enabled(next.inbound_settings.sniff);
        self.monitor.set_dns_handler(
            inbound_dns_handler(&next).map(|handler| handler as Arc<dyn SocketDnsHandler>),
        );
        self.tun_dns_handler
            .replace(inbound_dns_handler(&next).map(|handler| (*handler).clone()));
        let _ = self.reload_events.send(());
        if reload_inbounds {
            let _ = self.inbound_reload_events.send(());
        }
        self.set_reload_error("");
        Ok(next)
    }

    fn live_selectors(&self) -> Vec<Arc<RuntimeProxySelector>> {
        let mut selectors = self
            .selectors
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        selectors.retain(|selector| selector.strong_count() != 0);
        selectors.iter().filter_map(Weak::upgrade).collect()
    }

    fn register_selector(&self, selector: &Arc<RuntimeProxySelector>) {
        self.selectors
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(selector));
    }

    fn set_reload_error(&self, message: &str) {
        let mut error = self
            .reload_error
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *error = (!message.is_empty()).then(|| message.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::proxy::AsyncProxySelector;
    use yuhaiin_core::{Endpoint, ErrorKind, FlowContext, Network, RouteMode};
    use yuhaiin_store::{
        ConfigMutation, ConfigStore, GoNodeRecord, GoRouteRuleRecord, MaxMindMetadataRecord,
    };

    use super::*;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }

    fn controller() -> RuntimeController {
        block_on(RuntimeController::from_builder(RuntimeBuilder::new(
            block_on(ConfigStore::open_memory()).unwrap(),
            Arc::new(SystemAsyncIpResolver),
        )))
        .unwrap()
    }

    #[test]
    fn apply_commits_config_and_publishes_a_new_shared_snapshot() {
        let controller = controller();
        let before = controller.handle().load_with_revision();
        let next = block_on(controller.apply(&[ConfigMutation::Put {
            key: "http.listen_port".to_owned(),
            value: b"1080".to_vec(),
        }]))
        .unwrap();

        assert_eq!(
            block_on(controller.store().get_config("http.listen_port")).unwrap(),
            Some(b"1080".to_vec())
        );
        assert_eq!(controller.handle().revision(), before.0 + 1);
        assert!(Arc::ptr_eq(&next, &controller.handle().load()));
    }

    #[test]
    fn inbound_reload_notifications_are_reserved_for_listener_changes() {
        let controller = controller();
        let mut ordinary = controller.subscribe_reload();
        let mut inbound = controller.subscribe_inbound_reload();

        block_on(controller.reload()).unwrap();
        assert!(ordinary.try_recv().is_ok());
        assert!(matches!(
            inbound.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        block_on(controller.mutate_and_reload_inbounds(|store| async move {
            store.put_config("test.inbound", b"changed").await
        }))
        .unwrap();
        assert!(inbound.try_recv().is_ok());
    }

    #[test]
    fn reload_failure_keeps_the_previous_snapshot_and_persisted_config() {
        let controller = controller();
        let before = controller.handle().load_with_revision();
        block_on(
            controller
                .store()
                .repository()
                .put_maxmind_metadata(&MaxMindMetadataRecord {
                    id: "broken".to_owned(),
                    path: ".cache/yuhaiin-rust/missing.mmdb".to_owned(),
                    sha256: Vec::new(),
                    size: 0,
                    updated_at: 0,
                }),
        )
        .unwrap();

        assert!(block_on(controller.reload()).is_err());
        assert!(controller.last_reload_error().is_some());
        let after = controller.handle().load_with_revision();
        assert_eq!(after.0, before.0);
        assert!(Arc::ptr_eq(&before.1, &after.1));
        assert_eq!(
            block_on(controller.store().repository().list_maxmind_metadata())
                .unwrap()
                .len(),
            1
        );

        block_on(
            controller
                .store()
                .repository()
                .delete_maxmind_metadata("broken"),
        )
        .unwrap();
        block_on(controller.reload()).unwrap();
        assert_eq!(controller.last_reload_error(), None);
    }

    #[test]
    fn typed_repository_mutation_reuses_the_same_reload_boundary() {
        let controller = controller();
        let record = GoRouteRuleRecord {
            id: "controller-rule".to_owned(),
            name: "controller-rule".to_owned(),
            priority: 10,
            disabled: false,
            action_mode: "direct".to_owned(),
            match_type: "domain".to_owned(),
            tag: "test".to_owned(),
            updated_at: 1,
            data_json: br#"{"match":{"domain":"example.com"},"mode":"direct"}"#.to_vec(),
        };

        let snapshot = block_on(controller.mutate_and_reload(move |store| async move {
            store.repository().put_go_route_rule(&record).await
        }))
        .unwrap();

        assert_eq!(snapshot.route_rules.len(), 2);
        assert!(
            snapshot
                .route_rules
                .iter()
                .any(|rule| rule.id == "controller-rule")
        );
    }

    #[test]
    fn registered_proxy_selector_refreshes_only_after_a_successful_reload() {
        let controller = controller();
        let mut node = GoNodeRecord {
            id: "proxy".to_owned(),
            name: "proxy-v1".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        block_on(controller.store().repository().put_go_node(&node)).unwrap();
        block_on(controller.reload()).unwrap();

        let selector = block_on(controller.build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            std::time::Duration::from_secs(1),
        ))
        .unwrap();
        let mut context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        context.route_mode = RouteMode::Proxy;
        context.skip_route = true;
        let before = selector.select(&context);
        let revision = controller.handle().revision();

        node.enabled = false;
        node.updated_at = 2;
        block_on(controller.store().repository().put_go_node(&node)).unwrap();
        assert!(block_on(controller.reload()).is_err());
        assert_eq!(controller.handle().revision(), revision);
        let after_failed_reload = selector.select(&context);
        assert!(Arc::ptr_eq(&before, &after_failed_reload));

        node.enabled = true;
        node.updated_at = 3;
        node.name = "proxy-v2".to_owned();
        block_on(controller.store().repository().put_go_node(&node)).unwrap();
        block_on(controller.reload()).unwrap();
        let after_successful_reload = selector.select(&context);
        assert!(!Arc::ptr_eq(&before, &after_successful_reload));
    }

    #[test]
    fn close_node_closes_live_slots_without_deleting_config_and_reload_reopens_them() {
        let controller = controller();
        block_on(controller.store().repository().put_go_node(&GoNodeRecord {
            id: "proxy".to_owned(),
            name: "proxy".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        }))
        .unwrap();
        block_on(controller.reload()).unwrap();
        let selector = block_on(controller.build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            std::time::Duration::from_secs(1),
        ))
        .unwrap();
        assert_eq!(controller.active_proxy_ids(), vec!["proxy"]);

        let mut context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        context.route_mode = RouteMode::Proxy;
        context.skip_route = true;
        let old_proxy = selector.select(&context);

        block_on(controller.close_node("proxy")).unwrap();
        assert!(controller.active_proxy_ids().is_empty());
        let error = match block_on(selector.select(&context).connect(&context)) {
            Ok(_) => panic!("closed node unexpectedly accepted a new connection"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);
        assert!(
            block_on(controller.store().repository().list_go_nodes())
                .unwrap()
                .iter()
                .any(|node| node.id == "proxy")
        );

        block_on(controller.close_node("")).unwrap();
        block_on(controller.close_node("missing")).unwrap();
        block_on(controller.reload()).unwrap();
        assert_eq!(controller.active_proxy_ids(), vec!["proxy"]);
        let reopened = selector.select(&context);
        assert!(!Arc::ptr_eq(&old_proxy, &reopened));
    }

    #[test]
    fn registered_selector_refreshes_connection_metadata_with_snapshot() {
        let controller = controller();
        block_on(controller.store().repository().put_go_node(&GoNodeRecord {
            id: "proxy".to_owned(),
            name: "proxy".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        }))
        .unwrap();
        block_on(controller.reload()).unwrap();
        let selector = block_on(controller.build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            std::time::Duration::from_secs(1),
        ))
        .unwrap();

        block_on(controller.store().put_config(
            "resolver.hosts",
            br#"{"hosts":{"reload.example":"192.0.2.44"}}"#,
        ))
        .unwrap();
        block_on(controller.reload()).unwrap();

        let mut context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "192.0.2.44:443".parse().unwrap(),
        ));
        context.original_domain = Some(yuhaiin_core::DomainName::new("reload.example").unwrap());
        selector.route_context(&mut context);
        assert_eq!(context.hosts.as_deref(), Some("reload.example:443"));
    }

    #[cfg(feature = "tun")]
    #[test]
    fn controller_assembles_tun_runtime_from_one_full_cone_snapshot() {
        let controller = controller();
        block_on(controller.store().repository().put_go_node(&GoNodeRecord {
            id: "proxy".to_owned(),
            name: "proxy".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        }))
        .unwrap();
        block_on(controller.reload()).unwrap();

        let runtime = block_on(controller.build_tun_proxy_runtime(
            "",
            "proxy",
            "",
            "",
            std::time::Duration::from_secs(1),
            8,
        ))
        .unwrap();
        assert_eq!(runtime.task_len(), 0);
    }

    #[cfg(feature = "tun")]
    #[test]
    fn tun_runtime_restores_fakeip_domain_before_route_and_monitor_open() {
        let controller = controller();
        block_on(controller.store().put_config(
            "resolver.fakedns",
            br#"{"enabled":true,"ipv4Range":"198.18.2.0/30","ipv6Range":"fc00:2::/126"}"#,
        ))
        .unwrap();
        block_on(controller.store().repository().put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "direct".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        }))
        .unwrap();
        block_on(controller.reload()).unwrap();

        let domain = yuhaiin_core::DomainName::new("fake.example.com").unwrap();
        let fake_ip = block_on(
            controller
                .handle()
                .load()
                .fakeip
                .as_ref()
                .expect("FakeIP should be enabled")
                .ipv4
                .allocate(domain.clone()),
        )
        .unwrap();
        let mut runtime = block_on(controller.build_tun_proxy_runtime(
            "direct",
            "direct",
            "",
            "",
            std::time::Duration::from_secs(1),
            8,
        ))
        .unwrap();
        let flow = yuhaiin_core::flow::Flow {
            key: yuhaiin_core::flow::FlowKey {
                network: Network::Tcp,
                source: "10.0.0.2:41000".parse().unwrap(),
                destination: std::net::SocketAddr::new(fake_ip.into(), 443),
            },
        };
        block_on(async {
            runtime
                .handle_event(yuhaiin_core::tun::TunEvent::TcpOpened { flow })
                .unwrap();

            let connection = &controller.monitor().connections_value()["connections"][0];
            assert_eq!(connection["domain"], domain.to_string());
            assert_eq!(connection["fakeIp"], fake_ip.to_string());
            assert_eq!(connection["destination"], format!("tcp://{fake_ip}:443"));
            runtime
                .close_graceful(std::time::Duration::from_millis(100))
                .await;
        });
    }

    #[cfg(feature = "tun")]
    #[test]
    fn controller_can_install_packet_dns_handler_during_tun_assembly() {
        struct RejectingDns;

        impl yuhaiin_core::dns::AsyncDnsHandler for RejectingDns {
            fn answer<'a>(
                &'a self,
                _packet: &'a [u8],
            ) -> yuhaiin_core::LocalBoxFuture<'a, yuhaiin_core::Result<Vec<u8>>> {
                Box::pin(async {
                    Err(yuhaiin_core::Error::new(
                        yuhaiin_core::ErrorKind::Closed,
                        "controller DNS handler fixture",
                    ))
                })
            }
        }

        let controller = controller();
        block_on(controller.store().repository().put_go_node(&GoNodeRecord {
            id: "proxy".to_owned(),
            name: "proxy".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        }))
        .unwrap();
        block_on(controller.reload()).unwrap();

        let runtime = block_on(controller.build_tun_proxy_runtime_with_dns(
            "",
            "proxy",
            "",
            "",
            std::time::Duration::from_secs(1),
            8,
            Some(Arc::new(RejectingDns)),
        ))
        .unwrap();
        assert_eq!(runtime.task_len(), 0);
    }
}
