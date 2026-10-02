//! Bounded process ownership lookup before routing a new source socket.

use super::*;
use doradus_core::process::ProcessInfo;

struct PendingLookup {
    id: u64,
    events: VecDeque<ProxyInput>,
    task: tokio::task::JoinHandle<()>,
}

pub(super) struct ProcessLookups {
    pending: HashMap<UdpSourceKey, PendingLookup>,
    next_id: u64,
    permits: Arc<tokio::sync::Semaphore>,
}

impl Default for ProcessLookups {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            next_id: 0,
            // /proc scans are expensive; concurrent scans also contend for
            // the same kernel tables. Bound active scans independently from
            // the per-source event queues.
            permits: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}

impl ProcessLookups {
    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn clear(&mut self) {
        for (_, lookup) in self.pending.drain() {
            lookup.task.abort();
        }
    }

    pub(super) fn remove_flow(&mut self, flow: &TunFlowKey) {
        let source = udp_source_key(*flow);
        let Some(lookup) = self.pending.get_mut(&source) else {
            return;
        };
        lookup
            .events
            .retain(|event| proxy_input_flow_key(event) != *flow);
        if lookup.events.is_empty()
            && let Some(lookup) = self.pending.remove(&source)
        {
            lookup.task.abort();
        }
    }
}

impl TunProxyRuntime {
    pub(super) fn defer_process_lookup(&mut self, event: ProxyInput) -> Result<Option<ProxyInput>> {
        let flow = proxy_input_flow_key(&event);
        let source = udp_source_key(flow);
        if matches!(event, ProxyInput::TcpClosed { .. }) {
            if self.process_lookups.pending.contains_key(&source) {
                self.process_lookups.remove_flow(&flow);
                self.untrack_flow(&flow)?;
                return Ok(None);
            }
            return Ok(Some(event));
        }
        if let Some(lookup) = self.process_lookups.pending.get_mut(&source) {
            let queued_commands = lookup
                .events
                .len()
                .saturating_sub(usize::from(source.network == Network::Tcp));
            if queued_commands >= self.channel_capacity {
                // UDP and ICMP may lose a packet under backpressure. TCP
                // must close rather than silently discard stream bytes.
                if flow.network != Network::Tcp {
                    return Ok(None);
                }
                self.process_lookups.remove_flow(&flow);
                self.untrack_flow(&flow)?;
                return Err(Error::new(
                    ErrorKind::Timeout,
                    "TUN process lookup queue is full",
                ));
            }
            lookup.events.push_back(event);
            self.track_flow(flow)?;
            return Ok(None);
        }
        if !matches!(
            event,
            ProxyInput::TcpOpened { .. }
                | ProxyInput::UdpDatagram { .. }
                | ProxyInput::IcmpEchoRequest { .. }
        ) || self.flow_tracker.cached_process(&source).is_some()
        {
            return Ok(Some(event));
        }
        let Some(resolver) = self.process_resolver.clone() else {
            return Ok(Some(event));
        };
        let context = (self.context_provider)(TunFlow { key: flow });
        if context.process.is_some() && context.process_id.is_some() && context.user_id.is_some() {
            return Ok(Some(event));
        }
        if self.process_lookups.len() >= self.channel_capacity {
            return Err(Error::new(
                ErrorKind::Timeout,
                "TUN process lookup capacity is full",
            ));
        }
        self.track_flow(flow)?;
        self.process_lookups.next_id = self.process_lookups.next_id.wrapping_add(1);
        let id = self.process_lookups.next_id;
        let permits = self.process_lookups.permits.clone();
        let output = self.proxy_output_tx.clone();
        let task = tokio::spawn(async move {
            let Ok(permit) = permits.acquire_owned().await else {
                return;
            };
            let process = tokio::task::spawn_blocking(move || {
                // Keep the permit until the blocking scan actually exits,
                // even if its async owner is cancelled in the meantime.
                let _permit = permit;
                resolver
                    .resolve(flow.network, flow.source, flow.destination)
                    .ok()
                    .flatten()
            })
            .await
            .ok()
            .flatten();
            let _ = output
                .send(ProxyOutput::ProcessResolved {
                    source,
                    id,
                    process,
                })
                .await;
        });
        self.process_lookups.pending.insert(
            source,
            PendingLookup {
                id,
                events: VecDeque::from([event]),
                task,
            },
        );
        Ok(None)
    }

    pub(super) fn complete_process_lookup(
        &mut self,
        source: UdpSourceKey,
        id: u64,
        process: Option<ProcessInfo>,
        dispatcher: &mut TunDispatcher,
    ) -> Result<()> {
        if !self
            .process_lookups
            .pending
            .get(&source)
            .is_some_and(|lookup| lookup.id == id)
        {
            return Ok(());
        }
        let Some(lookup) = self.process_lookups.pending.remove(&source) else {
            return Ok(());
        };
        self.flow_tracker.cache_process(source, process);
        // A failed UDP send may already untrack every destination. Retain
        // the deferred socket identities so their dispatcher sockets are
        // still released when replay encounters backpressure.
        let mut deferred_flows = lookup
            .events
            .iter()
            .map(proxy_input_flow_key)
            .collect::<HashSet<_>>();
        for event in lookup.events {
            if let Err(error) = self.handle_ready_input(event) {
                // Release every deferred flow if replay cannot continue.
                deferred_flows.extend(
                    self.flow_tracker
                        .iter()
                        .copied()
                        .filter(|flow| udp_source_key(*flow) == source),
                );
                for flow in deferred_flows {
                    if flow.network == Network::Udp {
                        self.close_udp_flow(dispatcher, flow)?;
                    } else {
                        self.remove_flow_task(&flow);
                        if flow.network == Network::Tcp {
                            let _ = dispatcher.abort_tcp(flow);
                        }
                        self.untrack_flow(&flow)?;
                    }
                }
                if is_recoverable_proxy_flow_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn restart_process_lookups(&mut self) {
        let events = self
            .process_lookups
            .pending
            .drain()
            .flat_map(|(_, lookup)| {
                lookup.task.abort();
                lookup.events
            })
            .collect::<Vec<_>>();
        for event in events {
            let flow = proxy_input_flow_key(&event);
            if self.handle_proxy_input(event).is_err() {
                let _ = self.untrack_flow(&flow);
            }
        }
    }
}

#[cfg(test)]
#[path = "proxy_process_tests.rs"]
mod tests;
