use std::{
    future::Future,
    sync::{Arc, RwLock, Weak},
};

use yuhaiin_core::Result;
use yuhaiin_store::{ConfigMutation, ConfigStore};

use crate::{
    ConnectionMonitor, RuntimeBuilder, RuntimeHandle, RuntimeProxySelector, RuntimeSnapshot,
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
}

impl RuntimeController {
    /// Build and publish the initial snapshot before exposing the controller.
    pub async fn from_builder(builder: RuntimeBuilder) -> Result<Self> {
        let builder = Arc::new(builder);
        let handle = RuntimeHandle::new(builder.build().await?);
        let (reload_events, _) = tokio::sync::broadcast::channel(32);
        Ok(Self {
            builder,
            handle,
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            reload_error: Arc::new(RwLock::new(None)),
            selectors: Arc::new(RwLock::new(Vec::new())),
            monitor: Arc::new(ConnectionMonitor::new()),
            reload_events,
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

    pub fn subscribe_reload(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.reload_events.subscribe()
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
        let _guard = self.reload_lock.lock().await;
        let selector = Arc::new(
            self.handle
                .load()
                .build_proxy_selector(direct_id, proxy_id, bypass_id, drop_id, timeout)
                .await?,
        );
        self.register_selector(&selector);
        Ok(selector)
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
        let _guard = self.reload_lock.lock().await;
        let snapshot = self.handle.load();
        let selector = Arc::new(
            snapshot
                .build_proxy_selector(direct_id, proxy_id, bypass_id, drop_id, proxy_timeout)
                .await?,
        );
        let (nat, idle_timeout) = snapshot.new_full_cone_nat()?;
        let mut runtime =
            yuhaiin_core::tun::TunProxyRuntime::new(selector.clone(), channel_capacity)?
                .with_nat(nat, idle_timeout)?;
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
        self.rebuild_locked().await
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
        self.rebuild_locked().await
    }

    /// Commit generic configuration mutations, then rebuild the runtime from
    /// the same store.  If rebuilding fails, the committed configuration is
    /// retained and the previous snapshot remains active for existing/new
    /// flows; the returned error tells the management layer to report/retry it.
    pub async fn apply(&self, mutations: &[ConfigMutation]) -> Result<Arc<RuntimeSnapshot>> {
        let mutations = mutations.to_vec();
        self.mutate_and_reload(|store| async move { store.apply(&mutations).await })
            .await
    }

    async fn rebuild_locked(&self) -> Result<Arc<RuntimeSnapshot>> {
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
        let _ = self.reload_events.send(());
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
    use yuhaiin_core::{Endpoint, FlowContext, Network, RouteMode};
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

        assert_eq!(snapshot.route_rules.len(), 1);
        assert_eq!(snapshot.route_rules[0].id, "controller-rule");
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
