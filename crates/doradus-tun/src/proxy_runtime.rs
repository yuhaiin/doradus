//! Async proxy task runtime for TUN flows.

use super::*;
use doradus_metrics::RuntimeMetrics;

#[path = "proxy_flow.rs"]
mod proxy_flow;
#[path = "proxy_output.rs"]
mod proxy_output;
#[path = "proxy_task_manager.rs"]
mod proxy_task_manager;
#[path = "proxy_tasks.rs"]
mod proxy_tasks;

use proxy_flow::FlowTracker;
use proxy_task_manager::ProxyTaskRuntime;
pub(crate) use proxy_task_manager::{
    IcmpTaskManager, ProxyCommand, ProxyOutput, TcpTaskManager, UdpProxyCommand, UdpSourceKey,
    UdpTaskManager,
};
pub use proxy_task_manager::{ProxyInputAction, ProxyInputInterceptor, ProxyTimeouts};
#[cfg(test)]
pub(crate) use proxy_task_manager::{ProxyTask, UdpProxyTask};
use proxy_tasks::{run_icmp_proxy, run_tcp_proxy, run_udp_proxy};

/// Bridges owned TUN events to async proxy tasks.
///
/// The dispatcher remains the owner of smoltcp sockets.  Each flow task owns
/// exactly one proxy stream/datagram and communicates through bounded Tokio
/// channels.  This gives the packet side a visible backpressure boundary and
/// ensures no blocking connector or async read/write is performed while
/// `Interface::poll` holds mutable access to the packet engine.
pub struct TunProxyRuntime {
    metrics: Arc<RuntimeMetrics>,
    selector: Arc<dyn AsyncProxySelector>,
    context_provider: Arc<dyn Fn(TunFlow) -> crate::FlowContext + Send + Sync>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    observer: Option<Arc<dyn TunFlowObserver>>,
    flow_tracker: FlowTracker,
    pub(crate) tasks: TcpTaskManager,
    icmp_tasks: IcmpTaskManager,
    pub(crate) udp_tasks: UdpTaskManager,
    pending_proxy_output: Option<ProxyOutput>,
    udp_buffer_size: usize,
    pub(crate) proxy_output_tx: mpsc::Sender<ProxyOutput>,
    proxy_output_rx: mpsc::Receiver<ProxyOutput>,
    channel_capacity: usize,
    timeouts: ProxyTimeouts,
}

impl TunProxyRuntime {
    pub fn new(selector: Arc<dyn AsyncProxySelector>, channel_capacity: usize) -> Result<Self> {
        if channel_capacity == 0 {
            return Err(Error::invalid(
                "proxy flow channel capacity must be non-zero",
            ));
        }
        let (proxy_output_tx, proxy_output_rx) = mpsc::channel(channel_capacity);
        Ok(Self {
            metrics: Arc::new(RuntimeMetrics::new()),
            selector,
            context_provider: Arc::new(|flow| flow.context()),
            process_resolver: default_process_resolver(),
            observer: None,
            flow_tracker: FlowTracker::default(),
            tasks: TcpTaskManager::default(),
            icmp_tasks: IcmpTaskManager::default(),
            udp_tasks: UdpTaskManager::default(),
            pending_proxy_output: None,
            udp_buffer_size: u16::MAX as usize,
            proxy_output_tx,
            proxy_output_rx,
            channel_capacity,
            timeouts: ProxyTimeouts::default(),
        })
    }

    pub(crate) async fn wait_for_output(&mut self) {
        if self.pending_proxy_output.is_some() {
            return;
        }
        match self.proxy_output_rx.recv().await {
            Some(output) => self.pending_proxy_output = Some(output),
            None => std::future::pending::<()>().await,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn TunFlowObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn with_context_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn(TunFlow) -> crate::FlowContext + Send + Sync + 'static,
    {
        self.context_provider = Arc::new(provider);
        self
    }

    /// Add process ownership metadata to newly opened flows when the target
    /// platform exposes socket ownership.  The default is Linux `/proc`; a
    /// caller can replace it with a native Android or desktop resolver.
    pub fn with_process_resolver<R>(mut self, resolver: R) -> Self
    where
        R: ProcessResolver + 'static,
    {
        self.process_resolver = Some(Arc::new(resolver));
        self
    }

    pub fn set_process_resolver(&mut self, resolver: Option<Arc<dyn ProcessResolver>>) {
        self.process_resolver = resolver;
        self.flow_tracker.clear_process_cache();
    }

    /// Replace the read-only flow context snapshot at a lifecycle boundary.
    ///
    /// FakeIP allocation and other owner-task state can change while the TUN
    /// runtime is running. Updating the provider explicitly keeps that state
    /// out of `Send + Sync` packet tasks while allowing the next flow to use a
    /// refreshed reverse-lookup view.
    pub fn set_context_provider<F>(&mut self, provider: F)
    where
        F: Fn(TunFlow) -> crate::FlowContext + Send + Sync + 'static,
    {
        self.context_provider = Arc::new(provider);
    }

    pub fn with_nat(mut self, table: NatTable, idle_timeout: Duration) -> Result<Self> {
        if idle_timeout.is_zero() {
            return Err(Error::invalid("TUN proxy NAT timeout must be non-zero"));
        }
        self.flow_tracker.with_nat(table, idle_timeout);
        self.sync_nat_metrics();
        Ok(self)
    }

    /// Share the owning runtime's metrics collector with this TUN adapter.
    pub fn with_metrics(mut self, metrics: Arc<RuntimeMetrics>) -> Self {
        self.metrics = metrics;
        self.sync_nat_metrics();
        self
    }

    pub fn with_io_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.timeouts = ProxyTimeouts::all(timeout)?;
        Ok(self)
    }

    pub fn with_timeouts(mut self, timeouts: ProxyTimeouts) -> Result<Self> {
        timeouts.validate()?;
        self.timeouts = timeouts;
        Ok(self)
    }

    /// Set the payload buffer retained by each live UDP proxy task. This is
    /// normally the runtime's `advanced.udpBufferSize`; keep the standalone
    /// TUN API's historical maximum as the constructor default.
    pub fn with_udp_buffer_size(mut self, size: usize) -> Result<Self> {
        if size == 0 {
            return Err(Error::invalid("TUN UDP buffer size must be non-zero"));
        }
        self.udp_buffer_size = size.min(u16::MAX as usize).max(512);
        Ok(self)
    }

    pub fn nat_len(&self) -> Result<usize> {
        self.flow_tracker.nat().map_or(Ok(0), |nat| nat.table.len())
    }

    fn sync_nat_metrics(&self) {
        let Some(nat) = self.flow_tracker.nat() else {
            self.metrics.set_nat_state(0, 0, 0);
            return;
        };
        let Ok(stats) = nat.table.stats() else {
            return;
        };
        self.metrics.set_nat_counters(
            stats.active_bindings as i64,
            stats.active_destinations as i64,
            stats.reverse_mappings as i64,
            stats.allocations,
            stats.reuses,
            stats.touch_hits,
            stats.touch_misses,
            stats.reverse_lookups,
            stats.reverse_hits,
            stats.translated_rebinds,
            stats.expired_bindings,
            stats.explicit_closes,
        );
    }

    fn task_runtime(&self) -> ProxyTaskRuntime {
        ProxyTaskRuntime {
            output: self.proxy_output_tx.clone(),
            channel_capacity: self.channel_capacity,
            timeouts: self.timeouts,
            observer: self.observer.clone(),
            udp_buffer_size: self.udp_buffer_size,
        }
    }

    /// Number of currently registered proxy flow tasks.
    ///
    /// This is intentionally a small lifecycle metric: callers can assert
    /// that timeout, close, and cancellation paths have released their task
    /// owner without reaching into the task map.
    pub fn task_len(&self) -> usize {
        self.tasks.len() + self.icmp_tasks.len() + self.udp_tasks.len()
    }

    pub(crate) fn context_for_flow(&mut self, flow: TunFlow) -> crate::FlowContext {
        let mut context = (self.context_provider)(flow);
        if context.component.is_none() {
            context.component = Some("tun".to_owned());
        }
        let needs_process =
            context.process.is_none() || context.process_id.is_none() || context.user_id.is_none();
        let process = needs_process.then(|| {
            let source = udp_source_key(flow.key);
            if let Some(process) = self.flow_tracker.cached_process(&source) {
                return process.clone();
            }
            let process = self.process_resolver.as_ref().and_then(|resolver| {
                resolver
                    .resolve(flow.key.network, flow.key.source, flow.key.destination)
                    .ok()
                    .flatten()
            });
            self.flow_tracker.cache_process(source, process.clone());
            process
        });
        if let Some(Some(process)) = process {
            if context.process.is_none() {
                context.process = Some(process.path);
            }
            if context.process_id.is_none() {
                context.process_id = Some(process.pid);
            }
            if context.user_id.is_none() {
                context.user_id = Some(process.uid);
            }
        }
        context
    }

    pub fn sweep(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let Some(nat) = self.flow_tracker.nat() else {
            return Ok(0);
        };
        let idle_timeout = nat.idle_timeout;
        let expired = nat.table.sweep_keys()?;
        for key in &expired {
            let flow = TunFlowKey {
                network: key.network,
                source: key.source,
                destination: key.destination,
            };
            if key.network == Network::Tcp {
                let _ = dispatcher.abort_tcp(flow);
            } else if key.network == Network::Udp {
                let error = format!("NAT entry expired after {:?}", idle_timeout);
                tun_debug(format!(
                    "TUN UDP NAT entry expired flow={flow:?} timeout={:?}",
                    idle_timeout
                ));
                if let Some(observer) = &self.observer {
                    observer.failed(flow, "udp-nat-sweep", &error);
                }
                self.close_udp_flow(dispatcher, flow)?;
                continue;
            }
            self.remove_flow_task(&flow);
        }
        self.sync_nat_metrics();
        Ok(expired.len())
    }

    pub fn handle_proxy_input(&mut self, event: ProxyInput) -> Result<()> {
        match event {
            ProxyInput::TcpOpened { flow } => self.open_tcp_flow(flow)?,
            ProxyInput::TcpData { flow, payload } => self.send_tcp_data(flow, payload)?,
            ProxyInput::TcpHalfClosed { flow } => self.half_close_tcp(flow)?,
            ProxyInput::TcpClosed { flow } => self.close_tcp_flow(flow)?,
            ProxyInput::IcmpEchoRequest { flow, packet } => self.open_icmp_flow(flow, packet)?,
            ProxyInput::UdpDatagram { flow, payload } => self.handle_udp_datagram(flow, payload)?,
        }
        Ok(())
    }

    fn open_tcp_flow(&mut self, flow: TunFlow) -> Result<()> {
        self.track_flow(flow.key)?;
        let mut context = self.context_for_flow(flow);
        self.selector.route_context(&mut context);
        if let Some(observer) = &self.observer {
            observer.opened(flow, context.clone());
        }
        let proxy = self.selector.select(&context);
        let task_runtime = self.task_runtime();
        self.tasks.spawn(flow.key, proxy, context, &task_runtime);
        Ok(())
    }

    fn send_tcp_data(&mut self, flow: TunFlow, payload: Vec<u8>) -> Result<()> {
        self.touch_flow(flow.key)?;
        if let Some(observer) = &self.observer {
            observer.bytes(flow.key, TunFlowDirection::Upload, payload.len());
        }
        self.send_command_or_cleanup(&flow.key, ProxyCommand::Data(payload))
    }

    fn half_close_tcp(&mut self, flow: TunFlow) -> Result<()> {
        tun_debug(format!("TUN TCP half-closed flow={:?}", flow.key));
        self.touch_flow(flow.key)?;
        self.send_command_or_cleanup(&flow.key, ProxyCommand::Shutdown)
    }

    fn close_tcp_flow(&mut self, flow: TunFlow) -> Result<()> {
        tun_debug(format!("TUN TCP socket closed flow={:?}", flow.key));
        self.remove_task(&flow.key);
        self.untrack_flow(&flow.key)
    }

    fn open_icmp_flow(&mut self, flow: TunFlow, packet: Vec<u8>) -> Result<()> {
        self.track_flow(flow.key)?;
        let mut context = self.context_for_flow(flow);
        // ICMP follows the UDP route selection, while retaining its ICMP flow
        // key for telemetry and NAT bookkeeping.
        context.network = Network::Udp;
        context.destination = match context.destination {
            Endpoint::Ip { addr, .. } => Endpoint::ip(Network::Udp, addr),
            Endpoint::Domain { host, port, .. } => Endpoint::domain(Network::Udp, host, port),
        };
        self.selector.route_context(&mut context);
        if let Some(observer) = &self.observer {
            observer.opened(flow, context.clone());
            observer.bytes(flow.key, TunFlowDirection::Upload, packet.len());
        }
        let proxy = self.selector.select(&context);
        let task_runtime = self.task_runtime();
        self.icmp_tasks
            .spawn(flow.key, packet, proxy, context, &task_runtime);
        Ok(())
    }

    fn handle_udp_datagram(&mut self, flow: TunFlow, payload: Vec<u8>) -> Result<()> {
        let first = !self.flow_tracker.contains(&flow.key);
        self.track_flow(flow.key)?;
        let mut context = self.context_for_flow(flow);
        self.selector.route_context(&mut context);
        if first && let Some(observer) = &self.observer {
            observer.opened(flow, context.clone());
        }
        if let Some(observer) = &self.observer {
            observer.bytes(flow.key, TunFlowDirection::Upload, payload.len());
        }
        let target = context.effective_destination();
        let source = udp_source_key(flow.key);
        let proxy = self.selector.select(&context);
        let task_runtime = self.task_runtime();
        self.udp_tasks
            .ensure_source(source, flow.key, proxy, context, &task_runtime);
        if let Err(error) = self.udp_tasks.send(
            &source,
            UdpProxyCommand::Data {
                flow: flow.key,
                target,
                payload,
            },
        ) {
            let error_message = error.to_string();
            if let Some(observer) = &self.observer {
                observer.failed(flow.key, "udp-command", &error_message);
            }
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                self.untrack_flow(&flow)?;
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn close(&mut self) {
        // This is the force-stop path. The async path below gives transports a
        // bounded opportunity to flush/shutdown before falling back here.
        for flow in self.tasks.abort_all() {
            let _ = self.untrack_flow(&flow);
        }
        for flow in self.icmp_tasks.abort_all() {
            let _ = self.untrack_flow(&flow);
        }
        for flow in self.udp_tasks.abort_all() {
            let _ = self.untrack_flow(&flow);
        }
        self.clear_tracked_flows();
    }

    /// Ask every owned transport to perform its protocol-level shutdown, then
    /// force-abort whatever has not exited by `deadline`.
    pub async fn close_graceful(&mut self, deadline: Duration) {
        let end = tokio::time::Instant::now() + deadline;
        let tcp_commands = self.tasks.shutdown_senders();
        let udp_commands = self.udp_tasks.shutdown_senders();
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            let send_commands = async move {
                let tcp_sends = async move {
                    let mut sends = FuturesUnordered::new();
                    for command in tcp_commands {
                        sends.push(async move {
                            let _ = command.send(ProxyCommand::Shutdown).await;
                        });
                    }
                    while sends.next().await.is_some() {}
                };
                let udp_sends = async move {
                    let mut sends = FuturesUnordered::new();
                    for command in udp_commands {
                        sends.push(async move {
                            let _ = command.send(UdpProxyCommand::Shutdown).await;
                        });
                    }
                    while sends.next().await.is_some() {}
                };
                tokio::join!(tcp_sends, udp_sends);
            };
            let _ = tokio::time::timeout(remaining, send_commands).await;
        }
        while !self.tasks.all_tasks_finished()
            || !self.icmp_tasks.all_tasks_finished()
            || !self.udp_tasks.all_tasks_finished()
        {
            if tokio::time::Instant::now() >= end {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.close();
    }

    fn send_command_or_cleanup(&mut self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
        match self.tasks.send(flow, command) {
            Ok(()) => Ok(()),
            Err(error) => {
                if matches!(
                    error.kind,
                    ErrorKind::Closed | ErrorKind::NotFound | ErrorKind::Timeout
                ) {
                    self.remove_task(flow);
                    self.untrack_flow(flow)?;
                }
                Err(error)
            }
        }
    }

    fn remove_task(&mut self, flow: &TunFlowKey) {
        self.tasks.abort_flow(flow);
    }

    fn remove_icmp_tasks_for_flow(&mut self, flow: &TunFlowKey) {
        self.icmp_tasks.remove_for_flow(flow);
    }

    fn remove_flow_task(&mut self, flow: &TunFlowKey) {
        self.remove_task(flow);
        self.remove_icmp_tasks_for_flow(flow);
        let Some(source) = self.udp_tasks.unbind_flow(flow) else {
            return;
        };
        let remove_source = self.udp_tasks.remove_flow(source, flow);
        if remove_source {
            let _ = self.remove_udp_source_task(source);
        }
    }

    pub(crate) fn close_udp_flow(
        &mut self,
        dispatcher: &mut TunDispatcher,
        flow: TunFlowKey,
    ) -> Result<()> {
        self.remove_flow_task(&flow);

        let another_flow_uses_destination = self.flow_tracker.iter().any(|candidate| {
            candidate.network == Network::Udp
                && candidate.destination == flow.destination
                && *candidate != flow
        });
        if !another_flow_uses_destination {
            // UDP sockets are shared by all source tuples bound to the same
            // destination endpoint. Only the last active flow may close the
            // socket; closing one source tuple must not invalidate replies
            // for unrelated tuples.
            let _ = dispatcher.close_udp(flow);
        }
        self.untrack_flow(&flow)
    }

    fn remove_udp_source_task(&mut self, source: UdpSourceKey) -> Vec<TunFlowKey> {
        self.udp_tasks.remove_source(source)
    }

    pub(crate) fn track_flow(&mut self, flow: TunFlowKey) -> Result<()> {
        self.flow_tracker.track(flow)?;
        self.sync_nat_metrics();
        Ok(())
    }

    fn touch_flow(&self, flow: TunFlowKey) -> Result<()> {
        self.flow_tracker.touch(flow)?;
        self.sync_nat_metrics();
        Ok(())
    }

    fn untrack_flow(&mut self, flow: &TunFlowKey) -> Result<()> {
        if !self.flow_tracker.untrack(flow)? {
            return Ok(());
        }
        if let Some(observer) = &self.observer {
            observer.closed(*flow);
        }
        self.sync_nat_metrics();
        Ok(())
    }

    fn clear_tracked_flows(&mut self) {
        let flows = self.flow_tracker.drain();
        for flow in flows {
            if let Some(observer) = &self.observer {
                observer.closed(flow);
            }
        }
        self.sync_nat_metrics();
    }
}

impl Drop for TunProxyRuntime {
    fn drop(&mut self) {
        let _ = self.tasks.abort_all();
        let _ = self.icmp_tasks.abort_all();
        let _ = self.udp_tasks.abort_all();
        self.flow_tracker.drain();
    }
}

pub(crate) fn nat_key(flow: TunFlowKey) -> NatKey {
    NatKey {
        network: flow.network,
        source: flow.source,
        destination: flow.destination,
    }
}

pub(crate) fn udp_source_key(flow: TunFlowKey) -> UdpSourceKey {
    UdpSourceKey {
        network: flow.network,
        source: flow.source,
    }
}
