//! Proxy completion queues, DNS delivery, and task reaping.

use super::*;

impl TunProxyRuntime {
    pub fn poll_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        self.apply_close_requests(dispatcher)?;
        self.flush_pending_tcp(dispatcher);

        // ICMP has its own bounded completion queue. A blocked TCP/UDP
        // payload must not delay a completed ping response behind unrelated
        // stream data.
        let mut count = self.drain_icmp_outputs(dispatcher)?;
        count += self.drain_proxy_outputs(dispatcher)?;

        // DNS responses are delivered directly below, so a full proxy queue
        // can never turn a completed DNS query into an inbound-fatal error.
        count += self.poll_async_dns(dispatcher)?;
        count += self.poll_sync_dns(dispatcher)?;
        self.reap_finished_tasks(dispatcher)?;
        Ok(count)
    }

    fn flush_pending_tcp(&mut self, dispatcher: &mut TunDispatcher) {
        self.pending_tcp_keys.clear();
        self.pending_tcp_keys
            .extend(self.pending_tcp.keys().copied());
        for &flow in &self.pending_tcp_keys {
            let mut drained = false;
            while let Some(payload) = self
                .pending_tcp
                .get_mut(&flow)
                .and_then(VecDeque::pop_front)
            {
                match dispatcher.write_tcp(flow, &payload) {
                    Ok(written) if written == payload.len() => drained = true,
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
    }

    fn drain_icmp_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let mut count = 0;
        while let Ok(output) = self.icmp_output_rx.try_recv() {
            count += 1;
            if let ProxyOutput::IcmpData { id, flow, packet } = output {
                self.handle_icmp_output(dispatcher, id, flow, packet)?;
            }
        }
        Ok(count)
    }

    fn drain_proxy_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let mut count = 0;
        while let Ok(output) = self.output_rx.try_recv() {
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
                        self.pending_tcp
                            .entry(flow)
                            .or_default()
                            .push_back(payload[written..].to_vec());
                        Ok(false)
                    }
                    Err(error) => {
                        tun_debug(format!(
                            "TCP output backpressure/close flow={flow:?}: {error}"
                        ));
                        self.pending_tcp.entry(flow).or_default().push_back(payload);
                        Ok(false)
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
                Ok(true)
            }
            ProxyOutput::IcmpData { id, flow, packet } => {
                self.handle_icmp_output(dispatcher, id, flow, packet)?;
                Ok(true)
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
                Ok(true)
            }
            ProxyOutput::TcpClosed { flow } => {
                tun_debug(format!("TCP proxy task closed flow={flow:?}"));
                let _ = dispatcher.close_tcp(flow);
                self.pending_tcp.remove(&flow);
                self.remove_task(&flow);
                self.untrack_flow(&flow)?;
                Ok(true)
            }
            ProxyOutput::UdpBound { source, translated } => {
                let Some(nat) = &self.nat else {
                    return Ok(true);
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
                }
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

        let finished_udp: Vec<_> = self
            .udp_tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(source, _)| *source)
            .collect();
        for source in finished_udp {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                let _ = dispatcher.close_udp(flow);
                self.untrack_flow(&flow)?;
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
            match flow.network {
                Network::Tcp => {
                    let _ = dispatcher.abort_tcp(flow);
                }
                Network::Udp => {
                    let _ = dispatcher.close_udp(flow);
                }
                Network::Icmp | Network::Any => {}
            }
            self.untrack_flow(&flow)?;
        }
        Ok(())
    }

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
}
