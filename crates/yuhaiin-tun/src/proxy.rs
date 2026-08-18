//! Async proxy task runtime for TUN flows.

use super::*;

#[cfg(feature = "async-proxy")]
pub(crate) enum ProxyCommand {
    Data(Vec<u8>),
    Shutdown,
}

/// Independent deadlines for one TUN proxy flow.
///
/// `connect` bounds proxy stream/datagram establishment, `read` bounds one
/// inbound read, `write` bounds one outbound write, and `idle` bounds the
/// period in which a flow may make no progress at all.  Keeping these
/// meanings separate lets callers tune UDP idle expiry without accidentally
/// shortening a TLS/HTTP2 connect or a large backpressured write.
#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTimeouts {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
}

#[cfg(feature = "async-proxy")]
impl ProxyTimeouts {
    pub fn all(timeout: Duration) -> Result<Self> {
        let timeouts = Self {
            connect: timeout,
            read: timeout,
            write: timeout,
            idle: timeout,
        };
        timeouts.validate()?;
        Ok(timeouts)
    }

    pub fn validate(&self) -> Result<()> {
        if self.connect.is_zero()
            || self.read.is_zero()
            || self.write.is_zero()
            || self.idle.is_zero()
        {
            return Err(Error::invalid("TUN proxy timeouts must be non-zero"));
        }
        Ok(())
    }
}

#[cfg(feature = "async-proxy")]
impl Default for ProxyTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
            idle: Duration::from_secs(30),
        }
    }
}

#[cfg(feature = "async-proxy")]
pub(crate) enum UdpProxyCommand {
    Data {
        flow: TunFlowKey,
        target: Endpoint,
        payload: Vec<u8>,
    },
    CloseFlow(TunFlowKey),
    Shutdown,
}

#[cfg(feature = "async-proxy")]
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

#[cfg(feature = "async-proxy")]
pub(crate) struct ProxyTask {
    pub(crate) command: mpsc::Sender<ProxyCommand>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UdpSourceKey {
    network: Network,
    source: SocketAddr,
}

#[cfg(feature = "async-proxy")]
pub(crate) struct UdpProxyTask {
    pub(crate) command: mpsc::Sender<UdpProxyCommand>,
    pub(crate) join: tokio::task::JoinHandle<()>,
    pub(crate) flows: HashSet<TunFlowKey>,
}

#[cfg(feature = "async-proxy")]
pub(crate) struct SyncDnsTask {
    pub(crate) flow: TunFlowKey,
    pub(crate) join: tokio::task::JoinHandle<Option<Vec<u8>>>,
}

#[cfg(feature = "async-proxy")]
pub(crate) struct IcmpProxyTask {
    flow: TunFlowKey,
    join: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "async-proxy")]
pub(crate) struct NatBinding {
    table: NatTable,
    idle_timeout: Duration,
}

#[cfg(feature = "async-proxy")]
pub(crate) type AsyncDnsTask = LocalBoxFuture<'static, (TunFlowKey, Result<Vec<u8>>)>;

/// Bridges owned TUN events to async proxy tasks.
///
/// The dispatcher remains the owner of smoltcp sockets.  Each flow task owns
/// exactly one proxy stream/datagram and communicates through bounded Tokio
/// channels.  This gives the packet side a visible backpressure boundary and
/// ensures no blocking connector or async read/write is performed while
/// `Interface::poll` holds mutable access to the packet engine.
#[cfg(feature = "async-proxy")]
pub struct TunProxyRuntime {
    selector: Arc<dyn AsyncProxySelector>,
    context_provider: Arc<dyn Fn(TunFlow) -> crate::FlowContext + Send + Sync>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    observer: Option<Arc<dyn TunFlowObserver>>,
    dns_handler: Option<Arc<dyn DnsHandler>>,
    async_dns_handler: Option<Arc<dyn AsyncDnsHandler>>,
    nat: Option<NatBinding>,
    pub(crate) tasks: HashMap<TunFlowKey, ProxyTask>,
    icmp_tasks: HashMap<u64, IcmpProxyTask>,
    next_icmp_id: u64,
    pub(crate) udp_tasks: HashMap<UdpSourceKey, UdpProxyTask>,
    pub(crate) udp_flow_sources: HashMap<TunFlowKey, UdpSourceKey>,
    pending_tcp: HashMap<TunFlowKey, VecDeque<Vec<u8>>>,
    pub(crate) dns_tasks: Vec<SyncDnsTask>,
    async_dns_tasks: FuturesUnordered<AsyncDnsTask>,
    tracked_flows: HashSet<TunFlowKey>,
    pub(crate) output_tx: mpsc::Sender<ProxyOutput>,
    output_rx: mpsc::Receiver<ProxyOutput>,
    icmp_output_tx: mpsc::Sender<ProxyOutput>,
    icmp_output_rx: mpsc::Receiver<ProxyOutput>,
    channel_capacity: usize,
    timeouts: ProxyTimeouts,
}

#[cfg(feature = "async-proxy")]
impl TunProxyRuntime {
    pub fn new(selector: Arc<dyn AsyncProxySelector>, channel_capacity: usize) -> Result<Self> {
        if channel_capacity == 0 {
            return Err(Error::invalid(
                "proxy flow channel capacity must be non-zero",
            ));
        }
        let (output_tx, output_rx) = mpsc::channel(channel_capacity);
        let (icmp_output_tx, icmp_output_rx) = mpsc::channel(channel_capacity);
        Ok(Self {
            selector,
            context_provider: Arc::new(|flow| flow.context()),
            process_resolver: default_process_resolver(),
            observer: None,
            dns_handler: None,
            async_dns_handler: None,
            nat: None,
            tasks: HashMap::new(),
            icmp_tasks: HashMap::new(),
            next_icmp_id: 0,
            udp_tasks: HashMap::new(),
            udp_flow_sources: HashMap::new(),
            pending_tcp: HashMap::new(),
            dns_tasks: Vec::new(),
            async_dns_tasks: FuturesUnordered::new(),
            tracked_flows: HashSet::new(),
            output_tx,
            output_rx,
            icmp_output_tx,
            icmp_output_rx,
            channel_capacity,
            timeouts: ProxyTimeouts::default(),
        })
    }

    pub fn with_dns_handler(mut self, handler: Arc<dyn DnsHandler>) -> Self {
        self.dns_handler = Some(handler);
        self
    }

    pub fn with_async_dns_handler(mut self, handler: Arc<dyn AsyncDnsHandler>) -> Self {
        self.async_dns_handler = Some(handler);
        self
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

    pub fn nat_len(&self) -> Result<usize> {
        self.nat.as_ref().map_or(Ok(0), |nat| nat.table.len())
    }

    /// Number of currently registered proxy flow tasks.
    ///
    /// This is intentionally a small lifecycle metric: callers can assert
    /// that timeout, close, and cancellation paths have released their task
    /// owner without reaching into the task map.
    pub fn task_len(&self) -> usize {
        self.tasks.len()
            + self.icmp_tasks.len()
            + self.udp_tasks.len()
            + self.dns_tasks.len()
            + self.async_dns_tasks.len()
    }

    pub(crate) fn context_for_flow(&self, flow: TunFlow) -> crate::FlowContext {
        let mut context = (self.context_provider)(flow);
        if context.component.is_none() {
            context.component = Some("tun".to_owned());
        }
        let needs_process =
            context.process.is_none() || context.process_id.is_none() || context.user_id.is_none();
        if needs_process
            && let Some(resolver) = &self.process_resolver
            && let Ok(Some(process)) =
                resolver.resolve(flow.key.network, flow.key.source, flow.key.destination)
        {
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

    pub fn handle_event(&mut self, event: TunEvent) -> Result<()> {
        match event {
            TunEvent::TcpOpened { flow } => {
                self.track_flow(flow.key)?;
                self.remove_task(&flow.key);
                let mut context = self.context_for_flow(flow);
                self.selector.route_context(&mut context);
                if let Some(observer) = &self.observer {
                    observer.opened(flow, context.clone());
                }
                let proxy = self.selector.select(&context);
                let (command, commands) = mpsc::channel(self.channel_capacity);
                let output = self.output_tx.clone();
                let key = flow.key;
                let timeouts = self.timeouts;
                let observer = self.observer.clone();
                let join = tokio::spawn(async move {
                    run_tcp_proxy(proxy, context, key, commands, output, timeouts, observer).await;
                });
                self.tasks.insert(key, ProxyTask { command, join });
            }
            TunEvent::TcpData { flow, payload } => {
                self.touch_flow(flow.key)?;
                if let Some(observer) = &self.observer {
                    observer.bytes(flow.key, TunFlowDirection::Upload, payload.len());
                }
                self.send_command_or_cleanup(&flow.key, ProxyCommand::Data(payload))?;
            }
            TunEvent::TcpHalfClosed { flow } => {
                tun_debug(format!("TUN TCP half-closed flow={:?}", flow.key));
                self.touch_flow(flow.key)?;
                self.send_command_or_cleanup(&flow.key, ProxyCommand::Shutdown)?;
            }
            TunEvent::TcpClosed { flow } => {
                tun_debug(format!("TUN TCP socket closed flow={:?}", flow.key));
                self.remove_task(&flow.key);
                self.untrack_flow(&flow.key)?;
            }
            TunEvent::IcmpEchoRequest { flow, packet } => {
                self.track_flow(flow.key)?;
                let mut context = self.context_for_flow(flow);
                // Go's tun2socket ping path enters route.Ping, which selects
                // the UDP node set before it invokes the protocol-level ping
                // method. Keep the ICMP flow key for telemetry/NAT, but use a
                // UDP routing context so the same selected chain is used.
                context.network = Network::Udp;
                context.destination = match context.destination {
                    Endpoint::Ip { addr, .. } => Endpoint::ip(Network::Udp, addr),
                    Endpoint::Domain { host, port, .. } => {
                        Endpoint::domain(Network::Udp, host, port)
                    }
                };
                self.selector.route_context(&mut context);
                if let Some(observer) = &self.observer {
                    observer.opened(flow, context.clone());
                    observer.bytes(flow.key, TunFlowDirection::Upload, packet.len());
                }
                let proxy = self.selector.select(&context);
                let id = loop {
                    self.next_icmp_id = self.next_icmp_id.wrapping_add(1);
                    if !self.icmp_tasks.contains_key(&self.next_icmp_id) {
                        break self.next_icmp_id;
                    }
                };
                let output = self.icmp_output_tx.clone();
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
            }
            TunEvent::UdpDatagram { flow, payload } => {
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
                if flow.key.destination.port() == 53
                    && let Some(handler) = self.dns_handler.clone()
                {
                    let timeout = self.timeouts.read;
                    let join =
                        tokio::spawn(async move { run_dns_query(handler, payload, timeout).await });
                    self.dns_tasks.push(SyncDnsTask {
                        flow: flow.key,
                        join,
                    });
                    return Ok(());
                }
                let target = context.effective_destination();
                let source = udp_source_key(flow.key);
                if !self.udp_tasks.contains_key(&source) {
                    let proxy = self.selector.select(&context);
                    let (command, commands) = mpsc::channel(self.channel_capacity);
                    let output = self.output_tx.clone();
                    let timeouts = self.timeouts;
                    let observer = self.observer.clone();
                    let join = tokio::spawn(async move {
                        run_udp_proxy(
                            proxy, context, flow.key, commands, output, timeouts, observer,
                        )
                        .await;
                    });
                    self.udp_tasks.insert(
                        source,
                        UdpProxyTask {
                            command,
                            join,
                            flows: HashSet::from([flow.key]),
                        },
                    );
                } else if let Some(task) = self.udp_tasks.get_mut(&source) {
                    task.flows.insert(flow.key);
                }
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
            }
        }
        Ok(())
    }

    pub async fn handle_event_async(&mut self, event: TunEvent) -> Result<()> {
        if let TunEvent::UdpDatagram { flow, payload } = event {
            if flow.key.destination.port() == 53
                && let Some(handler) = self.async_dns_handler.clone()
            {
                self.track_flow(flow.key)?;
                let timeout = self.timeouts.read;
                self.async_dns_tasks.push(Box::pin(async move {
                    let answer = match tokio::time::timeout(timeout, handler.answer(&payload)).await
                    {
                        Ok(answer) => answer,
                        Err(_) => Err(Error::new(
                            ErrorKind::Timeout,
                            "TUN async DNS resolver timed out",
                        )),
                    };
                    (flow.key, answer)
                }));
                return Ok(());
            }
            return self.handle_event(TunEvent::UdpDatagram { flow, payload });
        }
        self.handle_event(event)
    }

    pub fn poll_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        self.apply_close_requests(dispatcher)?;
        let mut count = 0;
        let pending_flows = self.pending_tcp.keys().copied().collect::<Vec<_>>();
        for flow in pending_flows {
            let mut drained = false;
            while let Some(payload) = self
                .pending_tcp
                .get_mut(&flow)
                .and_then(VecDeque::pop_front)
            {
                match dispatcher.write_tcp(flow, &payload) {
                    Ok(written) if written == payload.len() => {
                        drained = true;
                    }
                    Ok(written) => {
                        self.pending_tcp
                            .entry(flow)
                            .or_default()
                            .push_front(payload[written..].to_vec());
                        break;
                    }
                    Err(_) => {
                        self.pending_tcp
                            .entry(flow)
                            .or_default()
                            .push_front(payload);
                        break;
                    }
                }
            }
            if drained && self.pending_tcp.get(&flow).is_some_and(VecDeque::is_empty) {
                self.pending_tcp.remove(&flow);
            }
        }
        // ICMP has its own bounded completion queue.  A blocked TCP/UDP
        // payload must not delay a completed ping response behind unrelated
        // stream data; Go writes the ping result back independently of those
        // relays.
        while let Ok(output) = self.icmp_output_rx.try_recv() {
            count += 1;
            if let ProxyOutput::IcmpData { id, flow, packet } = output {
                self.handle_icmp_output(dispatcher, id, flow, packet)?;
            }
        }
        while let Ok(output) = self.output_rx.try_recv() {
            count += 1;
            match output {
                ProxyOutput::TcpData { flow, payload } => {
                    self.touch_flow(flow)?;
                    if let Some(observer) = &self.observer {
                        observer.bytes(flow, TunFlowDirection::Download, payload.len());
                    }
                    match dispatcher.write_tcp(flow, &payload) {
                        Ok(written) if written == payload.len() => {}
                        Ok(written) => {
                            tun_debug(format!(
                                "TCP output backpressure flow={flow:?}: wrote {written} of {}",
                                payload.len()
                            ));
                            self.pending_tcp
                                .entry(flow)
                                .or_default()
                                .push_back(payload[written..].to_vec());
                            break;
                        }
                        Err(error) => {
                            tun_debug(format!(
                                "TCP output backpressure/close flow={flow:?}: {error}"
                            ));
                            self.pending_tcp.entry(flow).or_default().push_back(payload);
                            break;
                        }
                    }
                }
                ProxyOutput::UdpData { flow, payload } => {
                    self.touch_flow(flow)?;
                    if let Some(observer) = &self.observer {
                        observer.bytes(flow, TunFlowDirection::Download, payload.len());
                    }
                    match dispatcher.write_udp(flow, &payload) {
                        Ok(()) => tun_debug(format!(
                            "TUN UDP output queued flow={flow:?} bytes={}",
                            payload.len()
                        )),
                        Err(error) => {
                            tun_debug(format!(
                                "TUN UDP output dropped flow={flow:?} bytes={} error={error}",
                                payload.len()
                            ));
                            self.remove_flow_task(&flow);
                            self.untrack_flow(&flow)?;
                        }
                    }
                }
                ProxyOutput::IcmpData { id, flow, packet } => {
                    self.handle_icmp_output(dispatcher, id, flow, packet)?;
                }
                ProxyOutput::UdpClosed { flow } => {
                    let source = self.udp_flow_sources.get(&flow).copied();
                    let flows = source
                        .map(|source| self.remove_udp_source_task(source))
                        .unwrap_or_else(|| {
                            self.remove_flow_task(&flow);
                            vec![flow]
                        });
                    for flow in flows {
                        let _ = dispatcher.close_udp(flow);
                        self.untrack_flow(&flow)?;
                    }
                }
                ProxyOutput::TcpClosed { flow } => {
                    tun_debug(format!("TCP proxy task closed flow={flow:?}"));
                    let _ = dispatcher.close_tcp(flow);
                    self.pending_tcp.remove(&flow);
                    self.remove_task(&flow);
                    self.untrack_flow(&flow)?;
                }
                ProxyOutput::UdpBound { source, translated } => {
                    let Some(nat) = &self.nat else {
                        continue;
                    };
                    if let Err(error) =
                        nat.table
                            .bind_translated(source.network, source.source, translated)
                    {
                        tun_debug(format!(
                            "TUN UDP translated endpoint rejected source={source:?} translated={translated}: {error}"
                        ));
                        let flows = self.remove_udp_source_task(source);
                        for flow in flows {
                            let _ = dispatcher.close_udp(flow);
                            self.untrack_flow(&flow)?;
                        }
                        // A translated endpoint collision belongs to this
                        // UDP source.  Drop that source and keep the owner
                        // alive for unrelated TCP/UDP/DNS flows.
                        continue;
                    }
                }
            }
        }
        // Drain the shared proxy output queue before polling DNS completions.
        // DNS responses are delivered directly below, so a full proxy queue
        // can never turn a completed DNS query into an inbound-fatal error.
        count += self.poll_async_dns(dispatcher)?;
        count += self.poll_sync_dns(dispatcher)?;
        let finished_tcp: Vec<_> = self
            .tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(flow, _)| *flow)
            .collect();
        for flow in finished_tcp {
            if let Some(task) = self.tasks.remove(&flow) {
                if let Some(Err(error)) = task.join.now_or_never() {
                    tun_debug(format!(
                        "TCP proxy task ended with join error flow={flow:?}: {error}"
                    ));
                }
                let _ = dispatcher.close_tcp(flow);
                self.untrack_flow(&flow)?;
            }
        }
        let finished_icmp: Vec<_> = self
            .icmp_tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(id, _)| *id)
            .collect();
        for id in finished_icmp {
            if let Some(task) = self.icmp_tasks.remove(&id) {
                if let Some(Err(error)) = task.join.now_or_never() {
                    tun_debug(format!(
                        "ICMP proxy task ended with join error flow={:?}: {error}",
                        task.flow
                    ));
                }
                self.untrack_icmp_flow_if_idle(task.flow)?;
            }
        }
        let finished: Vec<_> = self
            .udp_tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(source, _)| *source)
            .collect();
        for source in finished {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                let _ = dispatcher.close_udp(flow);
                self.untrack_flow(&flow)?;
            }
        }
        Ok(count)
    }

    fn handle_icmp_output(
        &mut self,
        dispatcher: &mut TunDispatcher,
        id: u64,
        flow: TunFlowKey,
        packet: Vec<u8>,
    ) -> Result<()> {
        self.icmp_tasks.remove(&id);
        self.touch_flow(flow)?;
        if let Some(observer) = &self.observer {
            observer.bytes(flow, TunFlowDirection::Download, packet.len());
        }
        if let Err(error) = dispatcher.write_icmp(packet) {
            tun_debug(format!(
                "TUN ICMP output dropped flow={flow:?} error={error}"
            ));
        }
        self.untrack_icmp_flow_if_idle(flow)
    }

    fn untrack_icmp_flow_if_idle(&mut self, flow: TunFlowKey) -> Result<()> {
        if self.icmp_tasks.values().any(|task| task.flow == flow) {
            return Ok(());
        }
        self.untrack_flow(&flow)
    }

    fn apply_close_requests(&mut self, dispatcher: &mut TunDispatcher) -> Result<()> {
        let Some(observer) = &self.observer else {
            return Ok(());
        };
        let requested = self
            .tracked_flows
            .iter()
            .copied()
            .filter(|flow| observer.close_requested(*flow))
            .collect::<Vec<_>>();
        for flow in requested {
            self.remove_flow_task(&flow);
            if flow.network == Network::Tcp {
                let _ = dispatcher.abort_tcp(flow);
            } else if flow.network == Network::Udp {
                let _ = dispatcher.close_udp(flow);
            }
            self.untrack_flow(&flow)?;
        }
        Ok(())
    }

    /// Deliver a DNS response through the dispatcher-owned UDP socket.
    ///
    /// DNS interception is part of the TUN packet path, not a proxy task. It
    /// must therefore not compete with proxy task output for the bounded
    /// `output_tx` queue: a busy proxy queue is normal backpressure and must
    /// not stop the whole TUN owner.
    fn deliver_dns_output(
        &mut self,
        dispatcher: &mut TunDispatcher,
        flow: TunFlowKey,
        payload: Option<Vec<u8>>,
    ) -> Result<()> {
        match payload {
            Some(payload) => {
                self.touch_flow(flow)?;
                if let Some(observer) = &self.observer {
                    observer.bytes(flow, TunFlowDirection::Download, payload.len());
                }
                if let Err(error) = dispatcher.write_udp(flow, &payload) {
                    tun_debug(format!(
                        "TUN DNS output dropped flow={flow:?} bytes={} error={error}",
                        payload.len()
                    ));
                    self.remove_flow_task(&flow);
                    let _ = dispatcher.close_udp(flow);
                    self.untrack_flow(&flow)?;
                }
            }
            None => {
                self.remove_flow_task(&flow);
                let _ = dispatcher.close_udp(flow);
                self.untrack_flow(&flow)?;
            }
        }
        Ok(())
    }

    /// Poll locally-owned async DNS futures without awaiting a pending
    /// resolver. This keeps the TUN packet loop responsive while preserving
    /// `LocalBoxFuture` support for handlers that do not require `Send`.
    fn poll_async_dns(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let mut count = 0;
        while let Some(Some((flow, answer))) = self.async_dns_tasks.next().now_or_never() {
            count += 1;
            self.deliver_dns_output(dispatcher, flow, answer.ok())?;
        }
        Ok(count)
    }

    fn poll_sync_dns(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let finished = self
            .dns_tasks
            .iter()
            .enumerate()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let mut count = 0;
        for index in finished.into_iter().rev() {
            let SyncDnsTask { flow, join } = self.dns_tasks.swap_remove(index);
            let answer = match join
                .now_or_never()
                .expect("finished DNS join handle must be ready")
            {
                Ok(answer) => answer,
                Err(error) => {
                    tun_debug(format!(
                        "TUN synchronous DNS task ended with join error flow={flow:?}: {error}"
                    ));
                    None
                }
            };
            count += 1;
            self.deliver_dns_output(dispatcher, flow, answer)?;
        }
        Ok(count)
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
        for task in self.dns_tasks.drain(..) {
            task.join.abort();
        }
        self.async_dns_tasks = FuturesUnordered::new();
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
            || self.dns_tasks.iter().any(|task| !task.join.is_finished())
            || !self.async_dns_tasks.is_empty()
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
        self.pending_tcp.remove(flow);
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
        self.tracked_flows.insert(flow);
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
            if let Some(nat) = &self.nat {
                let _ = nat.table.remove(&nat_key(flow));
            }
            if let Some(observer) = &self.observer {
                observer.closed(flow);
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
impl Drop for TunProxyRuntime {
    fn drop(&mut self) {
        let flows: Vec<_> = self.tasks.keys().copied().collect();
        for task in self.tasks.drain().map(|(_, task)| task) {
            task.join.abort();
        }
        for task in self.icmp_tasks.drain().map(|(_, task)| task) {
            task.join.abort();
        }
        for task in self.dns_tasks.drain(..) {
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

#[cfg(feature = "async-proxy")]
pub(crate) fn nat_key(flow: TunFlowKey) -> NatKey {
    NatKey {
        network: flow.network,
        source: flow.source,
        destination: flow.destination,
    }
}

#[cfg(feature = "async-proxy")]
pub(crate) fn udp_source_key(flow: TunFlowKey) -> UdpSourceKey {
    UdpSourceKey {
        network: flow.network,
        source: flow.source,
    }
}

#[cfg(feature = "async-proxy")]
async fn run_tcp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    flow: TunFlowKey,
    mut commands: mpsc::Receiver<ProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
    observer: Option<Arc<dyn TunFlowObserver>>,
) {
    let stream = match tokio::time::timeout(timeouts.connect, proxy.connect(&context)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tun_debug(format!("TCP proxy connect failed flow={flow:?}: {error}"));
            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
            return;
        }
        Err(_) => {
            tun_debug(format!("TCP proxy connect timed out flow={flow:?}"));
            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
            return;
        }
    };
    if let Some(local_addr) = stream_local_addr(&*stream) {
        context.outbound_local_addr = Some(Endpoint::ip(context.network, local_addr));
    }
    if let Some(remote_addr) = stream_remote_addr(&*stream) {
        context.outbound_addr = Some(Endpoint::ip(context.network, remote_addr));
        // For direct/bypass flows the stream peer is the actual resolved
        // destination.  A proxy-mode stream peer is the proxy node itself,
        // not the user's target, so exposing it as `resolved_destination`
        // would make connection metadata lie in the opposite direction.
        if matches!(context.route_mode, RouteMode::Direct | RouteMode::Bypass) {
            context.resolved_destination = Some(Endpoint::ip(context.network, remote_addr));
        }
    }
    if let Some(observer) = observer {
        // TUN opens are published before the async connect so the management
        // plane can show a pending flow. Publish the same flow once more after
        // connect so the monitor can merge socket metadata without allocating
        // a second connection ID.
        observer.opened(TunFlow { key: flow }, context.clone());
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut write_closed = false;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.idle));
    loop {
        tokio::select! {
            result = tokio::time::timeout(timeouts.read, tokio::io::AsyncReadExt::read(&mut reader, &mut buffer)) => {
                match result {
                    Ok(Ok(0)) => {
                        tun_debug(format!("TCP proxy remote EOF flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Ok(Err(_)) => {
                        tun_debug(format!("TCP proxy remote read failed flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Err(_) => {
                        tun_debug(format!("TCP proxy remote read timed out flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Ok(Ok(length)) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                        if !emit_output(
                            &output,
                            ProxyOutput::TcpData { flow, payload: buffer[..length].to_vec() },
                            timeouts.idle,
                        ).await {
                            tun_debug(format!("TCP proxy output channel timed out flow={flow:?}"));
                            let _ = tokio::time::timeout(
                                timeouts.write,
                                tokio::io::AsyncWriteExt::shutdown(&mut writer),
                            )
                            .await;
                            return;
                        }
                    }
                }
            }
            command = commands.recv() => {
                match command {
                    Some(ProxyCommand::Data(payload)) if !write_closed => {
                        let write = tokio::time::timeout(
                            timeouts.write,
                            tokio::io::AsyncWriteExt::write_all(&mut writer, &payload),
                        )
                        .await;
                        if !matches!(write, Ok(Ok(()))) {
                            tun_debug(format!("TCP proxy remote write failed flow={flow:?}"));
                            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                            return;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(ProxyCommand::Shutdown) | None if !write_closed => {
                        let _ = tokio::time::timeout(
                            timeouts.write,
                            tokio::io::AsyncWriteExt::shutdown(&mut writer),
                        ).await;
                        write_closed = true;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(ProxyCommand::Data(_)) | Some(ProxyCommand::Shutdown) | None => {}
                }
            }
            _ = &mut idle => {
                tun_debug(format!("TCP proxy idle timeout flow={flow:?}"));
                let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                return;
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
async fn run_udp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    initial_flow: TunFlowKey,
    mut commands: mpsc::Receiver<UdpProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
    observer: Option<Arc<dyn TunFlowObserver>>,
) {
    let datagram = match tokio::time::timeout(timeouts.connect, proxy.open_datagram(&context)).await
    {
        Ok(Ok(datagram)) => datagram,
        Ok(Err(error)) => {
            tun_debug(format!(
                "UDP proxy open failed flow={initial_flow:?}: {error}"
            ));
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.idle,
            )
            .await;
            return;
        }
        Err(_) => {
            tun_debug(format!("UDP proxy open timed out flow={initial_flow:?}"));
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.idle,
            )
            .await;
            return;
        }
    };
    if let Ok(endpoint) = datagram.local_addr()
        && endpoint.addr().is_some()
    {
        context.outbound_local_addr = Some(endpoint);
    }
    if let Some(observer) = observer {
        observer.opened(TunFlow { key: initial_flow }, context.clone());
    }
    if let Ok(Endpoint::Ip {
        network: Network::Udp,
        addr: translated,
    }) = datagram.local_addr()
        && !emit_output(
            &output,
            ProxyOutput::UdpBound {
                source: udp_source_key(initial_flow),
                translated,
            },
            timeouts.idle,
        )
        .await
    {
        let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
        return;
    }
    let mut buffer = vec![0u8; 65_535];
    let mut routes = HashMap::<Endpoint, TunFlowKey>::new();
    let mut last_flow = None;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.idle));
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(UdpProxyCommand::Data {
                        flow,
                        target,
                        payload,
                    }) => {
                        let destination = target;
                        routes.insert(destination.clone(), flow);
                        last_flow = Some(flow);
                        let send = tokio::time::timeout(
                            timeouts.write,
                            datagram.send_to(&payload, destination.clone()),
                        )
                        .await;
                        if !matches!(send, Ok(Ok(_))) {
                            tun_debug(format!(
                                "UDP proxy send failed flow={flow:?} target={destination:?} result={send:?}"
                            ));
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            for flow in routes.values().copied().collect::<HashSet<_>>() {
                                let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                            }
                            return;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(UdpProxyCommand::CloseFlow(flow)) => {
                        routes.retain(|_, current| *current != flow);
                        if last_flow == Some(flow) {
                            last_flow = routes.values().next().copied();
                        }
                        if routes.is_empty() {
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                            return;
                        }
                    }
                    Some(UdpProxyCommand::Shutdown) | None => {
                        let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                        for flow in routes.values().copied().collect::<HashSet<_>>() {
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                        }
                        return;
                    }
                }
            }
            result = tokio::time::timeout(timeouts.read, datagram.recv_from(&mut buffer)) => {
                let Ok(Ok((length, source))) = result else {
                    tun_debug(format!("UDP proxy receive ended flow={initial_flow:?} result={result:?}"));
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    for flow in routes.values().copied().collect::<HashSet<_>>() {
                        let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                    }
                    return;
                };
                idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                let flow = routes
                    .get(&source)
                    .copied()
                    .or(last_flow);
                let Some(flow) = flow else {
                    continue;
                };
                routes.entry(source).or_insert(flow);
                if !emit_output(
                    &output,
                    ProxyOutput::UdpData {
                        flow,
                        payload: buffer[..length].to_vec(),
                    },
                    timeouts.idle,
                ).await {
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    return;
                }
            }
            _ = &mut idle => {
                let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                for flow in routes.values().copied().collect::<HashSet<_>>() {
                    let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                }
                return;
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
async fn emit_output(
    output: &mpsc::Sender<ProxyOutput>,
    value: ProxyOutput,
    timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout, output.send(value)).await,
        Ok(Ok(()))
    )
}

#[cfg(feature = "async-proxy")]
async fn run_dns_query(
    handler: Arc<dyn DnsHandler>,
    payload: Vec<u8>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let mut task = tokio::task::spawn_blocking(move || answer_query(&payload, handler.as_ref()));
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(answer)) => answer.ok(),
        Ok(Err(_)) | Err(_) => {
            task.abort();
            None
        }
    }
}

#[cfg(feature = "async-proxy")]
async fn run_icmp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    id: u64,
    flow: TunFlowKey,
    packet: Vec<u8>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
) {
    // Routing and telemetry selected this flow as ICMP. The existing
    // ChainProxy ping contract deliberately accepts a TCP endpoint, however,
    // and its effective-destination helper uses `context.network` when a
    // FakeIP reverse lookup restored a domain. Convert only the task-local
    // context after selection so that both IP and restored-domain pings use
    // the same protocol-level probe as the Go TUN path.
    let destination = context.effective_destination();
    context.network = Network::Tcp;
    context.destination = match destination {
        Endpoint::Ip { addr, .. } => Endpoint::ip(Network::Tcp, addr),
        Endpoint::Domain { host, port, .. } => Endpoint::domain(Network::Tcp, host, port),
    };
    let result = tokio::time::timeout(timeouts.connect, proxy.ping(&context)).await;
    let success = matches!(result, Ok(Ok(_)));
    if !success {
        tun_debug(format!(
            "ICMP proxy ping failed flow={flow:?} result={result:?}"
        ));
    }
    let packet = match rewrite_icmp_echo_reply(packet, success) {
        Ok(packet) => packet,
        Err(error) => {
            tun_debug(format!(
                "ICMP proxy reply rewrite failed flow={flow:?}: {error}"
            ));
            return;
        }
    };
    let _ = emit_output(
        &output,
        ProxyOutput::IcmpData { id, flow, packet },
        timeouts.idle,
    )
    .await;
}
