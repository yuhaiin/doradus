//! Proxy completion queues and task reaping.

use super::*;

impl TunProxyRuntime {
    pub fn process_proxy_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        self.apply_close_requests(dispatcher)?;
        self.flush_pending_tcp_to_tun(dispatcher)?;

        let count = self.drain_proxy_outputs(dispatcher)?;

        self.reap_finished_tasks(dispatcher)?;
        Ok(count)
    }

    fn flush_pending_tcp_to_tun(&mut self, dispatcher: &mut TunDispatcher) -> Result<()> {
        self.tasks.pending_keys.clear();
        self.tasks
            .pending_keys
            .extend(self.tasks.pending_to_tun.keys().copied());
        let pending_tcp_keys = self.tasks.pending_keys.clone();
        for flow in pending_tcp_keys {
            let mut drained = false;
            let mut failed = false;
            while let Some(payload) = self
                .tasks
                .pending_to_tun
                .get_mut(&flow)
                .and_then(VecDeque::pop_front)
            {
                match dispatcher.write_tcp(flow, &payload) {
                    Ok(written) if written == payload.len() => drained = true,
                    Ok(written) => {
                        self.tasks
                            .pending_to_tun
                            .entry(flow)
                            .or_default()
                            .push_front(payload[written..].to_vec());
                        break;
                    }
                    Err(_) => {
                        if self.tasks.pending_closes.contains(&flow) {
                            failed = true;
                        } else {
                            self.tasks
                                .pending_to_tun
                                .entry(flow)
                                .or_default()
                                .push_front(payload);
                        }
                        break;
                    }
                }
            }
            if failed {
                self.finish_tcp_close(dispatcher, flow)?;
            } else if drained
                && self
                    .tasks
                    .pending_to_tun
                    .get(&flow)
                    .is_some_and(VecDeque::is_empty)
            {
                self.tasks.pending_to_tun.remove(&flow);
                if self.tasks.pending_closes.contains(&flow) {
                    self.finish_tcp_close(dispatcher, flow)?;
                }
            }
        }
        Ok(())
    }

    fn finish_tcp_close(&mut self, dispatcher: &mut TunDispatcher, flow: TunFlowKey) -> Result<()> {
        tun_debug(format!("TCP proxy flow fully closed flow={flow:?}"));
        let _ = dispatcher.close_tcp(flow);
        if let Some(task) = self.tasks.remove(&flow) {
            task.join.abort();
        }
        self.tasks.pending_to_tun.remove(&flow);
        self.tasks.pending_closes.remove(&flow);
        self.untrack_flow(&flow)
    }

    fn drain_proxy_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let mut count = 0;
        while let Some(output) = self
            .pending_proxy_output
            .take()
            .or_else(|| self.proxy_output_rx.try_recv().ok())
        {
            count += 1;
            if !self.handle_proxy_output(dispatcher, output)? {
                break;
            }
        }
        Ok(count)
    }

    /// Handle one proxy completion. Returns `false` when TCP backpressure
    /// leaves the queue blocked; later completions must wait for the next poll.
    fn handle_proxy_output(
        &mut self,
        dispatcher: &mut TunDispatcher,
        output: ProxyOutput,
    ) -> Result<bool> {
        match output {
            ProxyOutput::TcpData { flow, payload } => {
                self.touch_flow(flow)?;
                if let Some(observer) = &self.observer {
                    observer.bytes(flow, TunFlowDirection::Download, payload.len());
                }
                match dispatcher.write_tcp(flow, &payload) {
                    Ok(written) if written == payload.len() => Ok(true),
                    Ok(written) => {
                        tun_debug(format!(
                            "TCP output backpressure flow={flow:?}: wrote {written} of {}",
                            payload.len()
                        ));
                        self.tasks
                            .pending_to_tun
                            .entry(flow)
                            .or_default()
                            .push_back(payload[written..].to_vec());
                        Ok(false)
                    }
                    Err(error) => {
                        tun_debug(format!(
                            "TCP output backpressure/close flow={flow:?}: {error}"
                        ));
                        self.tasks
                            .pending_to_tun
                            .entry(flow)
                            .or_default()
                            .push_back(payload);
                        Ok(false)
                    }
                }
            }
            ProxyOutput::UdpData { flow, payload } => {
                if !self.flow_tracker.contains(&flow) {
                    tun_debug(format!(
                        "TUN UDP output dropped for stale flow={flow:?} bytes={}",
                        payload.len()
                    ));
                    return Ok(true);
                }
                self.touch_flow(flow)?;
                if let Some(observer) = &self.observer {
                    observer.bytes(flow, TunFlowDirection::Download, payload.len());
                }
                match dispatcher.write_udp(flow, &payload) {
                    Ok(()) => tun_debug(format!(
                        "TUN UDP output queued flow={flow:?} bytes={}",
                        payload.len()
                    )),
                    Err(error) if error.kind == ErrorKind::Timeout => {
                        // UDP is lossy by contract. A full smoltcp TX buffer
                        // means the TUN side is temporarily backpressured;
                        // drop this datagram but keep the flow and NAT entry
                        // alive so the peer can apply its own congestion
                        // control instead of reopening the same flow.
                        tun_debug(format!(
                            "TUN UDP output backpressure flow={flow:?} bytes={} error={error}",
                            payload.len()
                        ));
                    }
                    Err(error) => {
                        let error_message = error.to_string();
                        tun_debug(format!(
                            "TUN UDP output dropped flow={flow:?} bytes={} error={error}",
                            payload.len()
                        ));
                        if let Some(observer) = &self.observer {
                            observer.failed(flow, "udp-output-to-tun", &error_message);
                        }
                        self.close_udp_flow(dispatcher, flow)?;
                    }
                }
                Ok(true)
            }
            ProxyOutput::IcmpData { id, flow, packet } => {
                self.handle_icmp_output(dispatcher, id, flow, packet)?;
                Ok(true)
            }
            ProxyOutput::UdpClosed { flow } => {
                let source = self.udp_tasks.source_for_flow(&flow);
                let flows = source
                    .map(|source| self.remove_udp_source_task(source))
                    .unwrap_or_else(|| {
                        self.remove_flow_task(&flow);
                        vec![flow]
                    });
                for flow in flows {
                    self.close_udp_flow(dispatcher, flow)?;
                }
                Ok(true)
            }
            ProxyOutput::TcpClosed { flow } => {
                tun_debug(format!("TCP proxy task closed flow={flow:?}"));
                if self
                    .tasks
                    .pending_to_tun
                    .get(&flow)
                    .is_some_and(|pending| !pending.is_empty())
                {
                    self.tasks.pending_closes.insert(flow);
                } else {
                    self.finish_tcp_close(dispatcher, flow)?;
                }
                Ok(true)
            }
            ProxyOutput::UdpBound { source, translated } => {
                let Some(nat) = self.flow_tracker.nat() else {
                    return Ok(true);
                };
                if let Err(error) =
                    nat.table
                        .bind_translated(source.network, source.source, translated)
                {
                    let error_message = error.to_string();
                    tun_debug(format!(
                        "TUN UDP translated endpoint rejected source={source:?} translated={translated}: {error}"
                    ));
                    let flows = self.remove_udp_source_task(source);
                    for flow in flows {
                        if let Some(observer) = &self.observer {
                            observer.failed(flow, "udp-bind-translated", &error_message);
                        }
                        self.close_udp_flow(dispatcher, flow)?;
                    }
                }
                self.sync_nat_metrics();
                Ok(true)
            }
        }
    }

    fn reap_finished_tasks(&mut self, dispatcher: &mut TunDispatcher) -> Result<()> {
        let finished_tcp: Vec<_> = self
            .tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(flow, _)| *flow)
            .collect();
        for flow in finished_tcp {
            let pending = self
                .tasks
                .pending_to_tun
                .get(&flow)
                .is_some_and(|pending| !pending.is_empty());
            if pending {
                self.tasks.pending_closes.insert(flow);
            } else if let Some(task) = self.tasks.remove(&flow) {
                if let Some(Err(error)) = task.join.now_or_never() {
                    tun_debug(format!(
                        "TCP proxy task ended with join error flow={flow:?}: {error}"
                    ));
                }
                self.finish_tcp_close(dispatcher, flow)?;
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

        let finished_udp: Vec<_> = self
            .udp_tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(source, _)| *source)
            .collect();
        for source in finished_udp {
            let flows = self.remove_udp_source_task(source);
            tun_debug(format!(
                "TUN UDP proxy task reaped before close output source={source:?} flows={flows:?}"
            ));
            for flow in flows {
                if let Some(observer) = &self.observer {
                    observer.failed(
                        flow,
                        "udp-task-reaped",
                        "UDP proxy task ended before emitting a close result",
                    );
                }
                self.close_udp_flow(dispatcher, flow)?;
            }
        }
        Ok(())
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
        if self.icmp_tasks.has_flow(flow) {
            return Ok(());
        }
        self.untrack_flow(&flow)
    }

    fn apply_close_requests(&mut self, dispatcher: &mut TunDispatcher) -> Result<()> {
        let Some(observer) = &self.observer else {
            return Ok(());
        };
        let requested = self
            .flow_tracker
            .iter()
            .copied()
            .filter(|flow| observer.close_requested(*flow))
            .collect::<Vec<_>>();
        for flow in requested {
            match flow.network {
                Network::Tcp => {
                    self.remove_flow_task(&flow);
                    let _ = dispatcher.abort_tcp(flow);
                }
                Network::Udp => {
                    self.close_udp_flow(dispatcher, flow)?;
                    continue;
                }
                Network::Icmp | Network::Any => {}
            }
            self.untrack_flow(&flow)?;
        }
        Ok(())
    }
}
