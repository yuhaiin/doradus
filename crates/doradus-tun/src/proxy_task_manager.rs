//! Ownership and lifecycle operations for asynchronous TUN proxy tasks.

use super::*;

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
    fn wait_for_output<'a>(&'a mut self) -> doradus_core::BoxFuture<'a, ProxyInputAction> {
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
    pub(super) network: Network,
    pub(super) source: SocketAddr,
}

pub(crate) struct UdpProxyTask {
    pub(crate) command: mpsc::Sender<UdpProxyCommand>,
    pub(crate) join: tokio::task::JoinHandle<()>,
    pub(crate) flows: HashSet<TunFlowKey>,
}

pub(crate) struct IcmpProxyTask {
    pub(super) flow: TunFlowKey,
    pub(super) join: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
pub(super) struct ProxyTaskRuntime {
    pub(super) output: mpsc::Sender<ProxyOutput>,
    pub(super) channel_capacity: usize,
    pub(super) timeouts: ProxyTimeouts,
    pub(super) observer: Option<Arc<dyn TunFlowObserver>>,
    pub(super) udp_buffer_size: usize,
}

#[derive(Default)]
pub(crate) struct TcpTaskManager {
    tasks: HashMap<TunFlowKey, ProxyTask>,
    pending_to_tun: HashMap<TunFlowKey, VecDeque<Vec<u8>>>,
    pending_closes: HashSet<TunFlowKey>,
}

impl TcpTaskManager {
    pub(super) fn spawn(
        &mut self,
        flow: TunFlowKey,
        proxy: Arc<dyn AsyncProxy>,
        context: FlowContext,
        runtime: &ProxyTaskRuntime,
    ) {
        self.abort_flow(&flow);
        let (command, commands) = mpsc::channel(runtime.channel_capacity);
        let output = runtime.output.clone();
        let timeouts = runtime.timeouts;
        let observer = runtime.observer.clone();
        let join = tokio::spawn(async move {
            run_tcp_proxy(proxy, context, flow, commands, output, timeouts, observer).await;
        });
        self.tasks.insert(flow, ProxyTask { command, join });
    }

    pub(super) fn send(&self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
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

    pub(super) fn abort_flow(&mut self, flow: &TunFlowKey) {
        if let Some(task) = self.remove_task(flow) {
            task.join.abort();
        }
        self.clear_pending_output(flow);
    }

    pub(super) fn remove_task(&mut self, flow: &TunFlowKey) -> Option<ProxyTask> {
        self.tasks.remove(flow)
    }

    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn shutdown_senders(&self) -> Vec<mpsc::Sender<ProxyCommand>> {
        self.tasks
            .values()
            .map(|task| task.command.clone())
            .collect()
    }

    pub(super) fn abort_all(&mut self) -> Vec<TunFlowKey> {
        let flows = self.tasks.keys().copied().collect::<Vec<_>>();
        for (_, task) in self.tasks.drain() {
            task.join.abort();
        }
        self.pending_to_tun.clear();
        self.pending_closes.clear();
        flows
    }

    pub(super) fn all_tasks_finished(&self) -> bool {
        self.tasks.values().all(|task| task.join.is_finished())
    }

    pub(super) fn finished_flows(&self) -> Vec<TunFlowKey> {
        self.tasks
            .iter()
            .filter_map(|(flow, task)| task.join.is_finished().then_some(*flow))
            .collect()
    }

    pub(super) fn take_finished(&mut self, flow: &TunFlowKey) -> Option<ProxyTask> {
        self.tasks
            .get(flow)
            .is_some_and(|task| task.join.is_finished())
            .then(|| self.tasks.remove(flow))
            .flatten()
    }

    pub(super) fn pending_flows(&self) -> Vec<TunFlowKey> {
        self.pending_to_tun.keys().copied().collect()
    }

    pub(super) fn pop_pending_output(&mut self, flow: &TunFlowKey) -> Option<Vec<u8>> {
        self.pending_to_tun
            .get_mut(flow)
            .and_then(VecDeque::pop_front)
    }

    pub(super) fn queue_pending_output(&mut self, flow: TunFlowKey, payload: Vec<u8>) {
        self.pending_to_tun
            .entry(flow)
            .or_default()
            .push_back(payload);
    }

    pub(super) fn requeue_pending_output(&mut self, flow: TunFlowKey, payload: Vec<u8>) {
        self.pending_to_tun
            .entry(flow)
            .or_default()
            .push_front(payload);
    }

    pub(super) fn has_pending_output(&self, flow: &TunFlowKey) -> bool {
        self.pending_to_tun
            .get(flow)
            .is_some_and(|pending| !pending.is_empty())
    }

    pub(super) fn clear_pending_output(&mut self, flow: &TunFlowKey) {
        self.pending_to_tun.remove(flow);
        self.pending_closes.remove(flow);
    }

    pub(super) fn pending_close_requested(&self, flow: &TunFlowKey) -> bool {
        self.pending_closes.contains(flow)
    }

    pub(super) fn request_pending_close(&mut self, flow: TunFlowKey) {
        self.pending_closes.insert(flow);
    }

    #[cfg(test)]
    pub(crate) fn insert_fixture(&mut self, flow: TunFlowKey, task: ProxyTask) {
        self.tasks.insert(flow, task);
    }

    #[cfg(test)]
    pub(crate) fn task_keys(&self) -> Vec<TunFlowKey> {
        self.tasks.keys().copied().collect()
    }
}

#[derive(Default)]
pub(crate) struct UdpTaskManager {
    tasks: HashMap<UdpSourceKey, UdpProxyTask>,
    flow_sources: HashMap<TunFlowKey, UdpSourceKey>,
}

impl UdpTaskManager {
    pub(super) fn ensure_source(
        &mut self,
        source: UdpSourceKey,
        flow: TunFlowKey,
        proxy: Arc<dyn AsyncProxy>,
        context: FlowContext,
        runtime: &ProxyTaskRuntime,
    ) {
        if let Some(task) = self.tasks.get_mut(&source) {
            task.flows.insert(flow);
            self.bind_flow(flow, source);
            return;
        }
        let (command, commands) = mpsc::channel(runtime.channel_capacity);
        let output = runtime.output.clone();
        let timeouts = runtime.timeouts;
        let observer = runtime.observer.clone();
        let udp_buffer_size = runtime.udp_buffer_size;
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
        self.tasks.insert(
            source,
            UdpProxyTask {
                command,
                join,
                flows: HashSet::from([flow]),
            },
        );
        self.bind_flow(flow, source);
    }

    pub(super) fn send(&self, source: &UdpSourceKey, command: UdpProxyCommand) -> Result<()> {
        let Some(task) = self.tasks.get(source) else {
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

    pub(super) fn shutdown_senders(&self) -> Vec<mpsc::Sender<UdpProxyCommand>> {
        self.tasks
            .values()
            .map(|task| task.command.clone())
            .collect()
    }

    pub(super) fn source_for_flow(&self, flow: &TunFlowKey) -> Option<UdpSourceKey> {
        self.flow_sources.get(flow).copied()
    }

    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    #[cfg(test)]
    pub(crate) fn contains_source(&self, source: &UdpSourceKey) -> bool {
        self.tasks.contains_key(source)
    }

    pub(super) fn finished_sources(&self) -> Vec<UdpSourceKey> {
        self.tasks
            .iter()
            .filter_map(|(source, task)| task.join.is_finished().then_some(*source))
            .collect()
    }

    pub(super) fn all_tasks_finished(&self) -> bool {
        self.tasks.values().all(|task| task.join.is_finished())
    }

    pub(super) fn remove_flow(&mut self, source: UdpSourceKey, flow: &TunFlowKey) -> bool {
        let Some(task) = self.tasks.get_mut(&source) else {
            return false;
        };
        task.flows.remove(flow);
        if task.flows.is_empty() {
            true
        } else {
            let _ = task.command.try_send(UdpProxyCommand::CloseFlow(*flow));
            false
        }
    }

    fn bind_flow(&mut self, flow: TunFlowKey, source: UdpSourceKey) {
        self.flow_sources.insert(flow, source);
    }

    pub(super) fn unbind_flow(&mut self, flow: &TunFlowKey) -> Option<UdpSourceKey> {
        self.flow_sources.remove(flow)
    }

    pub(super) fn remove_source(&mut self, source: UdpSourceKey) -> Vec<TunFlowKey> {
        let Some(task) = self.tasks.remove(&source) else {
            return Vec::new();
        };
        let _ = task.command.try_send(UdpProxyCommand::Shutdown);
        task.join.abort();
        let flows = task.flows.into_iter().collect::<Vec<_>>();
        for flow in &flows {
            self.flow_sources.remove(flow);
        }
        flows
    }

    pub(super) fn abort_all(&mut self) -> Vec<TunFlowKey> {
        let sources = self.tasks.keys().copied().collect::<Vec<_>>();
        let mut flows = Vec::new();
        for source in sources {
            flows.extend(self.remove_source(source));
        }
        self.flow_sources.clear();
        flows
    }

    #[cfg(test)]
    pub(crate) fn flow_sources(&self) -> &HashMap<TunFlowKey, UdpSourceKey> {
        &self.flow_sources
    }

    #[cfg(test)]
    pub(crate) fn flow_sources_mut(&mut self) -> &mut HashMap<TunFlowKey, UdpSourceKey> {
        &mut self.flow_sources
    }

    #[cfg(test)]
    pub(crate) fn insert_fixture(&mut self, source: UdpSourceKey, task: UdpProxyTask) {
        self.tasks.insert(source, task);
    }
}

#[derive(Default)]
pub(crate) struct IcmpTaskManager {
    tasks: HashMap<u64, IcmpProxyTask>,
    next_id: u64,
}

impl IcmpTaskManager {
    fn next_id(&mut self) -> u64 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if !self.tasks.contains_key(&self.next_id) {
                return self.next_id;
            }
        }
    }

    pub(super) fn spawn(
        &mut self,
        flow: TunFlowKey,
        packet: Vec<u8>,
        proxy: Arc<dyn AsyncProxy>,
        context: FlowContext,
        runtime: &ProxyTaskRuntime,
    ) {
        let id = self.next_id();
        let output = runtime.output.clone();
        let timeouts = runtime.timeouts;
        let join = tokio::spawn(async move {
            run_icmp_proxy(proxy, context, id, flow, packet, output, timeouts).await;
        });
        self.tasks.insert(id, IcmpProxyTask { flow, join });
    }

    pub(super) fn remove_for_flow(&mut self, flow: &TunFlowKey) {
        let ids = self
            .tasks
            .iter()
            .filter_map(|(id, task)| (task.flow == *flow).then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(task) = self.tasks.remove(&id) {
                task.join.abort();
            }
        }
    }

    pub(super) fn has_flow(&self, flow: TunFlowKey) -> bool {
        self.tasks.values().any(|task| task.flow == flow)
    }

    pub(super) fn abort_all(&mut self) -> Vec<TunFlowKey> {
        self.tasks
            .drain()
            .map(|(_, task)| {
                task.join.abort();
                task.flow
            })
            .collect()
    }
}

impl IcmpTaskManager {
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn all_tasks_finished(&self) -> bool {
        self.tasks.values().all(|task| task.join.is_finished())
    }

    pub(super) fn take_finished(&mut self) -> Vec<(u64, IcmpProxyTask)> {
        let ids = self
            .tasks
            .iter()
            .filter_map(|(id, task)| task.join.is_finished().then_some(*id))
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.tasks.remove(&id).map(|task| (id, task)))
            .collect()
    }

    pub(super) fn remove_task(&mut self, id: u64) -> Option<IcmpProxyTask> {
        self.tasks.remove(&id)
    }
}
