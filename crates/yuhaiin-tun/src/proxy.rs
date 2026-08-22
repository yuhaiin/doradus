//! Async proxy task runtime for TUN flows.

use super::*;
use yuhaiin_core::process::ProcessInfo;

#[path = "proxy_output.rs"]
mod proxy_output;
#[path = "proxy_tasks.rs"]
mod proxy_tasks;

use proxy_tasks::{run_icmp_proxy, run_tcp_proxy, run_udp_proxy};

pub(crate) enum ProxyCommand {
    Data(Vec<u8>),
    Shutdown,
}

/// Result of a generic input interception boundary. The TUN crate does not
/// know why an input was intercepted; protocol policy stays in the owning
/// runtime (for example, inbound-wide DNS handling).
pub enum ProxyInputAction {
    Forward(ProxyInput),

    Reply {
        flow: TunFlowKey,
        payload: Vec<u8>,
    },

    /// Input has been consumed and asynchronous work was started.
    /// A completion may later be returned by `wait_for_output`.
    Deferred,

    Drop,
}

pub trait ProxyInputInterceptor: Send {
    /// Must not perform asynchronous I/O.
    fn intercept(&mut self, input: ProxyInput) -> Result<ProxyInputAction>;

    /// Wait for an asynchronously produced interceptor result.
    ///
    /// Interceptors without asynchronous work simply never complete.
    fn wait_for_output<'a>(&'a mut self) -> yuhaiin_core::BoxFuture<'a, ProxyInputAction> {
        Box::pin(std::future::pending())
    }
}

/// Independent deadlines for one TUN proxy flow.
///
/// `connect` bounds proxy stream/datagram establishment, `write` bounds one
/// outbound write, and `idle` bounds completion of a queued proxy output.
/// TCP reads intentionally have no synthetic inactivity deadline: EOF and
/// actual I/O errors own their lifetime, as in Go's stream relay. The
/// UDP-specific deadlines below retain Go's 90-second idle semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTimeouts {
    pub connect: Duration,
    /// Retained for the shared timeout configuration; TCP reads do not use a
    /// synthetic inactivity deadline. UDP reads use `udp_read` instead.
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
    /// Go's `UDPIdleTimeout` covers both the remote datagram read deadline
    /// and the idle lifetime of the UDP source. Keep those separate from the
    /// TCP flow deadlines so the two runtimes share the same UDP behavior.
    pub udp_read: Duration,
    pub udp_idle: Duration,
}

impl ProxyTimeouts {
    pub fn all(timeout: Duration) -> Result<Self> {
        let timeouts = Self {
            connect: timeout,
            read: timeout,
            write: timeout,
            idle: timeout,
            udp_read: timeout,
            udp_idle: timeout,
        };
        timeouts.validate()?;
        Ok(timeouts)
    }

    pub fn validate(&self) -> Result<()> {
        if self.connect.is_zero()
            || self.read.is_zero()
            || self.write.is_zero()
            || self.idle.is_zero()
            || self.udp_read.is_zero()
            || self.udp_idle.is_zero()
        {
            return Err(Error::invalid("TUN proxy timeouts must be non-zero"));
        }
        Ok(())
    }
}

impl Default for ProxyTimeouts {
    fn default() -> Self {
        Self {
            // Go wraps inbound stream/datagram setup in configuration.Timeout
            // (16 seconds), rather than the 30-second post-connect read
            // watchdog that this runtime used previously.
            connect: Duration::from_secs(16),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
            idle: Duration::from_secs(30),
            udp_read: Duration::from_secs(90),
            udp_idle: Duration::from_secs(90),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyTimeouts;
    use std::time::Duration;

    #[test]
    fn defaults_match_go_flow_timeouts() {
        let timeouts = ProxyTimeouts::default();

        assert_eq!(timeouts.connect, Duration::from_secs(16));
        assert_eq!(timeouts.udp_read, Duration::from_secs(90));
        assert_eq!(timeouts.udp_idle, Duration::from_secs(90));
    }
}

pub(crate) enum UdpProxyCommand {
    Data {
        flow: TunFlowKey,
        target: Endpoint,
        payload: Vec<u8>,
    },
    CloseFlow(TunFlowKey),
    Shutdown,
}

pub(crate) enum ProxyOutput {
    TcpData {
        flow: TunFlowKey,
        payload: Vec<u8>,
    },
    TcpClosed {
        flow: TunFlowKey,
    },
    UdpBound {
        source: UdpSourceKey,
        translated: SocketAddr,
    },
    UdpData {
        flow: TunFlowKey,
        payload: Vec<u8>,
    },
    UdpClosed {
        flow: TunFlowKey,
    },
    IcmpData {
        id: u64,
        flow: TunFlowKey,
        packet: Vec<u8>,
    },
}

pub(crate) struct ProxyTask {
    pub(crate) command: mpsc::Sender<ProxyCommand>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UdpSourceKey {
    network: Network,
    source: SocketAddr,
}

pub(crate) struct UdpProxyTask {
    pub(crate) command: mpsc::Sender<UdpProxyCommand>,
    pub(crate) join: tokio::task::JoinHandle<()>,
    pub(crate) flows: HashSet<TunFlowKey>,
}

pub(crate) struct IcmpProxyTask {
    flow: TunFlowKey,
    join: tokio::task::JoinHandle<()>,
}

pub(crate) struct NatBinding {
    table: NatTable,
    idle_timeout: Duration,
}

/// Bridges owned TUN events to async proxy tasks.
///
/// The dispatcher remains the owner of smoltcp sockets.  Each flow task owns
/// exactly one proxy stream/datagram and communicates through bounded Tokio
/// channels.  This gives the packet side a visible backpressure boundary and
/// ensures no blocking connector or async read/write is performed while
/// `Interface::poll` holds mutable access to the packet engine.
pub struct TunProxyRuntime {
    selector: Arc<dyn AsyncProxySelector>,
    context_provider: Arc<dyn Fn(TunFlow) -> crate::FlowContext + Send + Sync>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    observer: Option<Arc<dyn TunFlowObserver>>,
    nat: Option<NatBinding>,
    pub(crate) tasks: HashMap<TunFlowKey, ProxyTask>,
    icmp_tasks: HashMap<u64, IcmpProxyTask>,
    next_icmp_id: u64,
    pub(crate) udp_tasks: HashMap<UdpSourceKey, UdpProxyTask>,
    pub(crate) udp_flow_sources: HashMap<TunFlowKey, UdpSourceKey>,
    pending_tcp_to_tun: HashMap<TunFlowKey, VecDeque<Vec<u8>>>,
    pending_tcp_keys: Vec<TunFlowKey>,
    pending_tcp_closes: HashSet<TunFlowKey>,
    pending_proxy_output: Option<ProxyOutput>,
    tracked_flows: HashSet<TunFlowKey>,
    process_cache: HashMap<UdpSourceKey, Option<ProcessInfo>>,
    process_cache_refs: HashMap<UdpSourceKey, usize>,
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
            selector,
            context_provider: Arc::new(|flow| flow.context()),
            process_resolver: default_process_resolver(),
            observer: None,
            nat: None,
            tasks: HashMap::new(),
            icmp_tasks: HashMap::new(),
            next_icmp_id: 0,
            udp_tasks: HashMap::new(),
            udp_flow_sources: HashMap::new(),
            pending_tcp_to_tun: HashMap::new(),
            pending_tcp_keys: Vec::new(),
            pending_tcp_closes: HashSet::new(),
            pending_proxy_output: None,
            tracked_flows: HashSet::new(),
            process_cache: HashMap::new(),
            process_cache_refs: HashMap::new(),
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
        self.process_cache.clear();
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
        self.nat = Some(NatBinding {
            table,
            idle_timeout,
        });
        Ok(self)
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
        self.nat.as_ref().map_or(Ok(0), |nat| nat.table.len())
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
            if let Some(process) = self.process_cache.get(&source) {
                return process.clone();
            }
            let process = self.process_resolver.as_ref().and_then(|resolver| {
                resolver
                    .resolve(flow.key.network, flow.key.source, flow.key.destination)
                    .ok()
                    .flatten()
            });
            self.process_cache.insert(source, process.clone());
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
        let Some(nat) = &self.nat else {
            return Ok(0);
        };
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
                let _ = dispatcher.close_udp(flow);
            }
            self.remove_flow_task(&flow);
        }
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
        self.remove_task(&flow.key);
        let mut context = self.context_for_flow(flow);
        self.selector.route_context(&mut context);
        if let Some(observer) = &self.observer {
            observer.opened(flow, context.clone());
        }
        let proxy = self.selector.select(&context);
        let (command, commands) = mpsc::channel(self.channel_capacity);
        let output = self.proxy_output_tx.clone();
        let key = flow.key;
        let timeouts = self.timeouts;
        let observer = self.observer.clone();
        let join = tokio::spawn(async move {
            run_tcp_proxy(proxy, context, key, commands, output, timeouts, observer).await;
        });
        self.tasks.insert(key, ProxyTask { command, join });
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
        let id = self.next_icmp_id();
        let output = self.proxy_output_tx.clone();
        let timeouts = self.timeouts;
        let join = tokio::spawn(async move {
            run_icmp_proxy(proxy, context, id, flow.key, packet, output, timeouts).await;
        });
        self.icmp_tasks.insert(
            id,
            IcmpProxyTask {
                flow: flow.key,
                join,
            },
        );
        Ok(())
    }

    fn next_icmp_id(&mut self) -> u64 {
        loop {
            self.next_icmp_id = self.next_icmp_id.wrapping_add(1);
            if !self.icmp_tasks.contains_key(&self.next_icmp_id) {
                return self.next_icmp_id;
            }
        }
    }

    fn handle_udp_datagram(&mut self, flow: TunFlow, payload: Vec<u8>) -> Result<()> {
        let first = !self.tracked_flows.contains(&flow.key);
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
        self.ensure_udp_proxy(source, context, flow.key)?;
        self.udp_flow_sources.insert(flow.key, source);
        if let Err(error) = self.send_udp_command(
            &source,
            UdpProxyCommand::Data {
                flow: flow.key,
                target,
                payload,
            },
        ) {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                self.untrack_flow(&flow)?;
            }
            return Err(error);
        }
        Ok(())
    }

    fn ensure_udp_proxy(
        &mut self,
        source: UdpSourceKey,
        context: FlowContext,
        flow: TunFlowKey,
    ) -> Result<()> {
        if let Some(task) = self.udp_tasks.get_mut(&source) {
            task.flows.insert(flow);
            return Ok(());
        }
        let proxy = self.selector.select(&context);
        let (command, commands) = mpsc::channel(self.channel_capacity);
        let output = self.proxy_output_tx.clone();
        let timeouts = self.timeouts;
        let observer = self.observer.clone();
        let udp_buffer_size = self.udp_buffer_size;
        let join = tokio::spawn(async move {
            run_udp_proxy(
                proxy,
                context,
                flow,
                commands,
                output,
                timeouts,
                observer,
                udp_buffer_size,
            )
            .await;
        });
        self.udp_tasks.insert(
            source,
            UdpProxyTask {
                command,
                join,
                flows: HashSet::from([flow]),
            },
        );
        Ok(())
    }

    pub fn close(&mut self) {
        // This is the force-stop path. The async path below gives transports a
        // bounded opportunity to flush/shutdown before falling back here.
        let flows: Vec<_> = self.tasks.keys().copied().collect();
        for (_, task) in self.tasks.drain() {
            task.join.abort();
        }
        for flow in flows {
            let _ = self.untrack_flow(&flow);
        }
        let icmp_flows: Vec<_> = self
            .icmp_tasks
            .drain()
            .map(|(_, task)| {
                task.join.abort();
                task.flow
            })
            .collect();
        for flow in icmp_flows {
            let _ = self.untrack_flow(&flow);
        }
        let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
        for source in sources {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                let _ = self.untrack_flow(&flow);
            }
        }
        self.clear_tracked_flows();
    }

    /// Ask every owned transport to perform its protocol-level shutdown, then
    /// force-abort whatever has not exited by `deadline`.
    pub async fn close_graceful(&mut self, deadline: Duration) {
        let end = tokio::time::Instant::now() + deadline;
        let tcp_commands = self
            .tasks
            .values()
            .map(|task| task.command.clone())
            .collect::<Vec<_>>();
        let udp_commands = self
            .udp_tasks
            .values()
            .map(|task| task.command.clone())
            .collect::<Vec<_>>();
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
        while self.tasks.values().any(|task| !task.join.is_finished())
            || self
                .icmp_tasks
                .values()
                .any(|task| !task.join.is_finished())
            || self.udp_tasks.values().any(|task| !task.join.is_finished())
        {
            if tokio::time::Instant::now() >= end {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.close();
    }

    fn send_command(&self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
        let Some(task) = self.tasks.get(flow) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "TUN flow has no proxy task",
            ));
        };
        task.command.try_send(command).map_err(|error| {
            let message = error.to_string();
            let kind = match &error {
                mpsc::error::TrySendError::Full(_) => ErrorKind::Timeout,
                mpsc::error::TrySendError::Closed(_) => ErrorKind::Closed,
            };
            Error::new(kind, format!("TUN proxy flow channel: {message}"))
        })
    }

    fn send_command_or_cleanup(&mut self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
        match self.send_command(flow, command) {
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
        if let Some(task) = self.tasks.remove(flow) {
            task.join.abort();
        }
        self.pending_tcp_to_tun.remove(flow);
        self.pending_tcp_closes.remove(flow);
    }

    fn remove_icmp_tasks_for_flow(&mut self, flow: &TunFlowKey) {
        let ids = self
            .icmp_tasks
            .iter()
            .filter_map(|(id, task)| (task.flow == *flow).then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(task) = self.icmp_tasks.remove(&id) {
                task.join.abort();
            }
        }
    }

    fn remove_flow_task(&mut self, flow: &TunFlowKey) {
        self.remove_task(flow);
        self.remove_icmp_tasks_for_flow(flow);
        let Some(source) = self.udp_flow_sources.remove(flow) else {
            return;
        };
        let remove_source = if let Some(task) = self.udp_tasks.get_mut(&source) {
            task.flows.remove(flow);
            if task.flows.is_empty() {
                true
            } else {
                let _ = task.command.try_send(UdpProxyCommand::CloseFlow(*flow));
                false
            }
        } else {
            false
        };
        if remove_source {
            let _ = self.remove_udp_source_task(source);
        }
    }

    fn send_udp_command(&self, source: &UdpSourceKey, command: UdpProxyCommand) -> Result<()> {
        let Some(task) = self.udp_tasks.get(source) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "TUN UDP source has no proxy task",
            ));
        };
        task.command.try_send(command).map_err(|error| {
            let message = error.to_string();
            let kind = match &error {
                mpsc::error::TrySendError::Full(_) => ErrorKind::Timeout,
                mpsc::error::TrySendError::Closed(_) => ErrorKind::Closed,
            };
            Error::new(kind, format!("TUN UDP source channel: {message}"))
        })
    }

    fn remove_udp_source_task(&mut self, source: UdpSourceKey) -> Vec<TunFlowKey> {
        let Some(task) = self.udp_tasks.remove(&source) else {
            return Vec::new();
        };
        let _ = task.command.try_send(UdpProxyCommand::Shutdown);
        task.join.abort();
        let flows = task.flows.into_iter().collect::<Vec<_>>();
        for flow in &flows {
            self.udp_flow_sources.remove(flow);
        }
        flows
    }

    pub(crate) fn track_flow(&mut self, flow: TunFlowKey) -> Result<()> {
        if let Some(nat) = &self.nat {
            let key = nat_key(flow);
            if nat.table.touch(&key)?.is_none() {
                nat.table.insert(key, flow.source, nat.idle_timeout)?;
            }
        }
        if self.tracked_flows.insert(flow) {
            let source = udp_source_key(flow);
            *self.process_cache_refs.entry(source).or_default() += 1;
        }
        Ok(())
    }

    fn touch_flow(&self, flow: TunFlowKey) -> Result<()> {
        let Some(nat) = &self.nat else {
            return Ok(());
        };
        let key = nat_key(flow);
        let _ = nat.table.touch(&key)?;
        Ok(())
    }

    fn untrack_flow(&mut self, flow: &TunFlowKey) -> Result<()> {
        if !self.tracked_flows.remove(flow) {
            return Ok(());
        }
        self.release_process_cache(*flow);
        let Some(nat) = &self.nat else {
            if let Some(observer) = &self.observer {
                observer.closed(*flow);
            }
            return Ok(());
        };
        let _ = nat.table.remove(&nat_key(*flow))?;
        if let Some(observer) = &self.observer {
            observer.closed(*flow);
        }
        Ok(())
    }

    fn clear_tracked_flows(&mut self) {
        let flows = self.tracked_flows.drain().collect::<Vec<_>>();
        for flow in flows {
            self.release_process_cache(flow);
            if let Some(nat) = &self.nat {
                let _ = nat.table.remove(&nat_key(flow));
            }
            if let Some(observer) = &self.observer {
                observer.closed(flow);
            }
        }
    }

    fn release_process_cache(&mut self, flow: TunFlowKey) {
        let source = udp_source_key(flow);
        let Some(references) = self.process_cache_refs.get_mut(&source) else {
            return;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            self.process_cache_refs.remove(&source);
            self.process_cache.remove(&source);
        }
    }
}

impl Drop for TunProxyRuntime {
    fn drop(&mut self) {
        let flows: Vec<_> = self.tasks.keys().copied().collect();
        for task in self.tasks.drain().map(|(_, task)| task) {
            task.join.abort();
        }
        for task in self.icmp_tasks.drain().map(|(_, task)| task) {
            task.join.abort();
        }
        let nat_table = self.nat.as_ref().map(|nat| nat.table.clone());
        if let Some(nat_table) = nat_table {
            for flow in flows {
                let _ = nat_table.remove(&nat_key(flow));
            }
            let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
            for source in sources {
                let flows = self.remove_udp_source_task(source);
                for flow in flows {
                    let _ = nat_table.remove(&nat_key(flow));
                }
            }
            for flow in self.tracked_flows.drain() {
                let _ = nat_table.remove(&nat_key(flow));
            }
        } else {
            let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
            for source in sources {
                let _ = self.remove_udp_source_task(source);
            }
            self.tracked_flows.clear();
        }
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
