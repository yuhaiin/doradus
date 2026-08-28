use std::{
    collections::BTreeSet,
    future::Future,
    path::PathBuf,
    sync::{Arc, RwLock, Weak},
};

use doradus_core::Result;
use doradus_core::proxy::AsyncProxy;
use doradus_store::{ConfigMutation, ConfigStore};

use crate::data_plane::{ReloadableAsyncDnsHandler, RuntimeDnsHandler, inbound_dns_handler};
use crate::inbound_runtime::InboundRuntimeState;
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
    inbound_runtime: Arc<InboundRuntimeState>,
    reload_events: tokio::sync::broadcast::Sender<()>,
    dns_reload_events: tokio::sync::broadcast::Sender<()>,
    inbound_reload_events: tokio::sync::broadcast::Sender<InboundReload>,
    dns_handler: Arc<ReloadableAsyncDnsHandler>,
    restore_request: Arc<RwLock<Option<PathBuf>>>,
    resolver_proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundReload {
    All,
    One(String),
}

#[derive(Clone, Debug, Default)]
struct ReloadPlan {
    inbound: Option<InboundReload>,
    dns: bool,
}

impl ReloadPlan {
    fn inbound(reload: InboundReload) -> Self {
        Self {
            inbound: Some(reload),
            ..Self::default()
        }
    }

    fn dns() -> Self {
        Self {
            dns: true,
            ..Self::default()
        }
    }
}

impl RuntimeController {
    /// Build and publish the initial snapshot before exposing the controller.
    pub async fn from_builder(builder: RuntimeBuilder) -> Result<Self> {
        let builder = Arc::new(builder);
        let resolver_proxy_bridge = builder.resolver_proxy_bridge();
        let initial_snapshot = builder.build().await?;
        let (reload_events, _) = tokio::sync::broadcast::channel(32);
        let (dns_reload_events, _) = tokio::sync::broadcast::channel(32);
        let (inbound_reload_events, _) = tokio::sync::broadcast::channel(32);
        let inbound_runtime = Arc::new(InboundRuntimeState::new(builder.store().clone()));
        let monitor = Arc::new(ConnectionMonitor::load_with_store(builder.store().clone()).await?);
        if let Some(bridge) = &resolver_proxy_bridge {
            bridge.set_monitor(&monitor);
        }
        monitor.set_sniff_enabled(initial_snapshot.inbound_settings.sniff);
        let initial_inbound_dns_handler = inbound_dns_handler(&initial_snapshot)?;
        monitor.set_dns_handler(
            initial_inbound_dns_handler
                .clone()
                .map(|handler| handler as Arc<dyn SocketDnsHandler>),
        );
        let dns_handler = Arc::new(ReloadableAsyncDnsHandler::new(Some(RuntimeDnsHandler {
            resolver: initial_snapshot.resolver.clone(),
            fakeip: initial_snapshot.fakeip.clone(),
        })));
        let handle = RuntimeHandle::new(initial_snapshot);
        Ok(Self {
            builder,
            handle,
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            reload_error: Arc::new(RwLock::new(None)),
            selectors: Arc::new(RwLock::new(Vec::new())),
            monitor,
            inbound_runtime,
            reload_events,
            dns_reload_events,
            inbound_reload_events,
            dns_handler,
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

    pub fn inbound_runtime(&self) -> Arc<InboundRuntimeState> {
        self.inbound_runtime.clone()
    }

    pub(crate) fn dns_handler(&self) -> Arc<ReloadableAsyncDnsHandler> {
        self.dns_handler.clone()
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

    pub(crate) fn subscribe_dns_reload(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.dns_reload_events.subscribe()
    }

    /// Subscribe to changes that require rebinding inbound listeners.
    ///
    /// Node, route, resolver, and backup changes publish only the ordinary
    /// reload event because registered selectors are refreshed in place.
    /// Inbound/user changes additionally publish this event. A single inbound
    /// mutation identifies its owner so supervisors can preserve siblings;
    /// shared user changes use `All` because every authenticated listener
    /// depends on that user table.
    pub fn subscribe_inbound_reload(&self) -> tokio::sync::broadcast::Receiver<InboundReload> {
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
    ) -> Result<doradus_tun::TunProxyRuntime> {
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
        async_dns_handler: Option<Arc<dyn doradus_core::dns::AsyncDnsHandler>>,
    ) -> Result<doradus_tun::TunProxyRuntime> {
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
        _async_dns_handler: Option<Arc<dyn doradus_core::dns::AsyncDnsHandler>>,
    ) -> Result<doradus_tun::TunProxyRuntime> {
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
        if let Some(bridge) = &self.resolver_proxy_bridge {
            bridge.set_selector(selector.clone());
        }
        let (nat, idle_timeout) = snapshot.new_full_cone_nat()?;
        let mut runtime = doradus_tun::TunProxyRuntime::new(selector.clone(), channel_capacity)?
            .with_nat(nat, idle_timeout)?
            .with_udp_buffer_size(snapshot.settings.udp_buffer_size)?;
        runtime = runtime.with_observer(self.monitor.clone());
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
        self.rebuild_locked(ReloadPlan::default()).await
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
        self.mutate_and_reload_with_plan(ReloadPlan::default(), operation)
            .await
    }

    pub async fn mutate_and_reload_inbounds<F, Fut>(
        &self,
        operation: F,
    ) -> Result<Arc<RuntimeSnapshot>>
    where
        F: FnOnce(ConfigStore) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        self.mutate_and_reload_with_plan(ReloadPlan::inbound(InboundReload::All), operation)
            .await
    }

    pub async fn mutate_and_reload_inbound<F, Fut>(
        &self,
        id: impl Into<String>,
        operation: F,
    ) -> Result<Arc<RuntimeSnapshot>>
    where
        F: FnOnce(ConfigStore) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        self.mutate_and_reload_with_plan(
            ReloadPlan::inbound(InboundReload::One(id.into())),
            operation,
        )
        .await
    }

    /// Request a fresh start of one enabled inbound without changing its
    /// persisted configuration. The supervisor owns the actual bind and will
    /// publish the eventual ready/failed state independently of its siblings.
    pub async fn retry_inbound(&self, id: impl Into<String>) -> Result<()> {
        let id = id.into();
        let _guard = self.reload_lock.lock().await;
        let record = self
            .store()
            .repository()
            .list_go_inbounds()
            .await?
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(|| {
                doradus_core::Error::new(doradus_core::ErrorKind::NotFound, "inbound not found")
            })?;
        if !record.enabled {
            return Err(doradus_core::Error::new(
                doradus_core::ErrorKind::InvalidInput,
                "disabled inbound cannot be retried",
            ));
        }
        self.inbound_runtime.mark_starting(&id, true);
        let _ = self.inbound_reload_events.send(InboundReload::One(id));
        Ok(())
    }

    pub async fn mutate_and_reload_dns<F, Fut>(&self, operation: F) -> Result<Arc<RuntimeSnapshot>>
    where
        F: FnOnce(ConfigStore) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        self.mutate_and_reload_with_plan(ReloadPlan::dns(), operation)
            .await
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

    async fn mutate_and_reload_with_plan<F, Fut>(
        &self,
        plan: ReloadPlan,
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
        self.rebuild_locked(plan).await
    }

    async fn rebuild_locked(&self, plan: ReloadPlan) -> Result<Arc<RuntimeSnapshot>> {
        let expected_revision = self.handle.revision();
        let next = match self.builder.build().await {
            Ok(snapshot) => Arc::new(snapshot),
            Err(error) => {
                self.set_reload_error(&error.to_string());
                return Err(error);
            }
        };
        let next_inbound_dns_handler = inbound_dns_handler(&next)?;

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
            next_inbound_dns_handler
                .clone()
                .map(|handler| handler as Arc<dyn SocketDnsHandler>),
        );
        self.dns_handler.replace(Some(RuntimeDnsHandler {
            resolver: next.resolver.clone(),
            fakeip: next.fakeip.clone(),
        }));
        let _ = self.reload_events.send(());
        if plan.dns {
            let _ = self.dns_reload_events.send(());
        }
        if let Some(reload_inbound) = plan.inbound {
            match &reload_inbound {
                InboundReload::All => {
                    if let Ok(records) = self.store().repository().list_go_inbounds().await {
                        for record in records {
                            self.inbound_runtime.mark_reload(&record.id);
                        }
                    }
                }
                InboundReload::One(id) => self.inbound_runtime.mark_reload(id),
            }
            let _ = self.inbound_reload_events.send(reload_inbound);
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
        if !message.is_empty() {
            self.monitor
                .error(format!("runtime reload failed: {message}"));
        }
    }
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
