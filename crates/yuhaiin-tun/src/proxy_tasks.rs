//! Async TCP, UDP, DNS, and ICMP proxy workers.

use super::*;

fn report_failure(
    observer: Option<&Arc<dyn TunFlowObserver>>,
    flow: TunFlowKey,
    stage: &str,
    error: impl std::fmt::Display,
) {
    if let Some(observer) = observer {
        let error = error.to_string();
        observer.failed(flow, stage, &error);
    }
}

pub(super) async fn run_tcp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    flow: TunFlowKey,
    mut commands: mpsc::Receiver<ProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
    observer: Option<Arc<dyn TunFlowObserver>>,
) {
    let failure_observer = observer.clone();
    let stream = match tokio::time::timeout(timeouts.connect, proxy.connect(&context)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            report_failure(failure_observer.as_ref(), flow, "tcp-connect", &error);
            tun_debug(format!("TCP proxy connect failed flow={flow:?}: {error}"));
            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
            return;
        }
        Err(_) => {
            report_failure(
                failure_observer.as_ref(),
                flow,
                "tcp-connect",
                format!("timeout after {:?}", timeouts.connect),
            );
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
        if matches!(context.route_mode, RouteMode::Direct | RouteMode::Bypass) {
            context.resolved_destination = Some(Endpoint::ip(context.network, remote_addr));
        }
    }
    if let Some(observer) = observer {
        observer.opened(TunFlow { key: flow }, context.clone());
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut write_closed = false;
    loop {
        tokio::select! {
            result = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer) => {
                match result {
                    Ok(0) => {
                        tun_debug(format!("TCP proxy remote EOF flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Err(error) => {
                        report_failure(
                            failure_observer.as_ref(),
                            flow,
                            "tcp-read",
                            &error,
                        );
                        tun_debug(format!("TCP proxy remote read failed flow={flow:?}: {error}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Ok(length) => {
                        if !emit_output(
                            &output,
                            ProxyOutput::TcpData { flow, payload: buffer[..length].to_vec() },
                            timeouts.idle,
                        ).await {
                            report_failure(
                                failure_observer.as_ref(),
                                flow,
                                "tcp-output",
                                "proxy output queue timed out",
                            );
                            tun_debug(format!("TCP proxy output channel timed out flow={flow:?}"));
                            let _ = tokio::time::timeout(
                                timeouts.write,
                                tokio::io::AsyncWriteExt::shutdown(&mut writer),
                            ).await;
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
                        ).await;
                        if !matches!(write, Ok(Ok(()))) {
                            report_failure(
                                failure_observer.as_ref(),
                                flow,
                                "tcp-write",
                                format!("{write:?}"),
                            );
                            tun_debug(format!("TCP proxy remote write failed flow={flow:?}"));
                            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                            return;
                        }
                    }
                    Some(ProxyCommand::Shutdown) | None if !write_closed => {
                        let _ = tokio::time::timeout(
                            timeouts.write,
                            tokio::io::AsyncWriteExt::shutdown(&mut writer),
                        ).await;
                        write_closed = true;
                    }
                    None => {
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Some(ProxyCommand::Data(_)) | Some(ProxyCommand::Shutdown) => {}
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    initial_flow: TunFlowKey,
    mut commands: mpsc::Receiver<UdpProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
    observer: Option<Arc<dyn TunFlowObserver>>,
    udp_buffer_size: usize,
) {
    let failure_observer = observer.clone();
    let datagram = match tokio::time::timeout(timeouts.connect, proxy.open_datagram(&context)).await
    {
        Ok(Ok(datagram)) => datagram,
        Ok(Err(error)) => {
            report_failure(failure_observer.as_ref(), initial_flow, "udp-open", &error);
            tun_debug(format!(
                "UDP proxy open failed flow={initial_flow:?}: {error}"
            ));
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.udp_idle,
            )
            .await;
            return;
        }
        Err(_) => {
            report_failure(
                failure_observer.as_ref(),
                initial_flow,
                "udp-open",
                format!("timeout after {:?}", timeouts.connect),
            );
            tun_debug(format!("UDP proxy open timed out flow={initial_flow:?}"));
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.udp_idle,
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
            timeouts.udp_idle,
        )
        .await
    {
        let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
        return;
    }
    let mut buffer = vec![0u8; udp_buffer_size];
    let mut routes = HashMap::<Endpoint, TunFlowKey>::new();
    let mut last_flow = None;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.udp_idle));
    // UDP send_to can succeed after the route has disappeared because it only
    // queues bytes locally. Reset this watchdog only after a remote datagram;
    // continuous uploads therefore cannot pin a stale SOCKS5 association.
    let mut remote_progress = Box::pin(tokio::time::sleep(timeouts.udp_read));
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(UdpProxyCommand::Data { flow, target, payload }) => {
                        let destination = target;
                        routes.insert(destination.clone(), flow);
                        last_flow = Some(flow);
                        let send = tokio::time::timeout(
                            timeouts.write,
                            datagram.send_to(&payload, destination.clone()),
                        ).await;
                        if !matches!(send, Ok(Ok(_))) {
                            report_failure(
                                failure_observer.as_ref(),
                                flow,
                                "udp-send",
                                format!("{send:?}"),
                            );
                            tun_debug(format!(
                                "UDP proxy send failed flow={flow:?} target={destination:?} result={send:?}"
                            ));
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            for flow in routes.values().copied().collect::<HashSet<_>>() {
                                let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                            }
                            return;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.udp_idle);
                    }
                    Some(UdpProxyCommand::CloseFlow(flow)) => {
                        routes.retain(|_, current| *current != flow);
                        if last_flow == Some(flow) {
                            last_flow = routes.values().next().copied();
                        }
                        if routes.is_empty() {
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                            return;
                        }
                    }
                    Some(UdpProxyCommand::Shutdown) | None => {
                        let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                        for flow in routes.values().copied().collect::<HashSet<_>>() {
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                        }
                        return;
                    }
                }
            }
            result = tokio::time::timeout(timeouts.udp_read, datagram.recv_from(&mut buffer)) => {
                let Ok(Ok((length, source))) = result else {
                    report_failure(
                        failure_observer.as_ref(),
                        initial_flow,
                        "udp-receive",
                        format!("{result:?}"),
                    );
                    tun_debug(format!("UDP proxy receive ended flow={initial_flow:?} result={result:?}"));
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    for flow in routes.values().copied().collect::<HashSet<_>>() {
                        let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                    }
                    return;
                };
                idle.as_mut().reset(tokio::time::Instant::now() + timeouts.udp_idle);
                remote_progress.as_mut().reset(tokio::time::Instant::now() + timeouts.udp_read);
                let flow = routes.get(&source).copied().or(last_flow);
                let Some(flow) = flow else { continue; };
                routes.entry(source).or_insert(flow);
                if !emit_output(
                    &output,
                    ProxyOutput::UdpData { flow, payload: buffer[..length].to_vec() },
                    timeouts.udp_idle,

                ).await {
                    report_failure(
                        failure_observer.as_ref(),
                        flow,
                        "udp-output",
                        "proxy output queue timed out",
                    );
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    return;
                }
            }
            _ = &mut idle => {
                let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                for flow in routes.values().copied().collect::<HashSet<_>>() {
                    let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                }
                return;
            }
            _ = &mut remote_progress => {
                report_failure(
                    failure_observer.as_ref(),
                    initial_flow,
                    "udp-receive",
                    format!("no remote datagram after {:?}", timeouts.udp_read),
                );
                let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                for flow in routes.values().copied().collect::<HashSet<_>>() {
                    let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.udp_idle).await;
                }
                return;
            }
        }
    }
}

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

pub(super) async fn run_icmp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    id: u64,
    flow: TunFlowKey,
    packet: Vec<u8>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio::time::{sleep, timeout};
    use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};

    struct BlackholeProxy;

    struct BlackholeDatagram;

    impl AsyncProxy for BlackholeProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> yuhaiin_core::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                let (client, peer) = duplex(64 * 1024);
                tokio::spawn(async move {
                    let _peer = peer;
                    pending::<()>().await;
                });
                Ok(Box::new(client) as BoxAsyncStream)
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> yuhaiin_core::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async { Ok(Box::new(BlackholeDatagram) as Box<dyn AsyncDatagram>) })
        }

        fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl AsyncDatagram for BlackholeDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> yuhaiin_core::BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> yuhaiin_core::BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(pending())
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "0.0.0.0:0".parse().unwrap()))
        }

        fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn tcp_flow() -> TunFlowKey {
        TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:1234".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
        }
    }

    fn udp_flow() -> TunFlowKey {
        TunFlowKey {
            network: Network::Udp,
            source: "10.0.0.2:1234".parse().unwrap(),
            destination: "203.0.113.10:53".parse().unwrap(),
        }
    }

    fn short_timeouts() -> ProxyTimeouts {
        ProxyTimeouts {
            connect: Duration::from_millis(50),
            read: Duration::from_millis(25),
            write: Duration::from_millis(50),
            idle: Duration::from_secs(1),
            udp_read: Duration::from_millis(25),
            udp_idle: Duration::from_secs(1),
        }
    }

    #[tokio::test]
    async fn tcp_flow_stays_open_without_remote_progress_until_shutdown() {
        let flow = tcp_flow();
        let (commands_tx, commands_rx) = mpsc::channel(32);
        let (output_tx, mut output_rx) = mpsc::channel(8);
        let worker = tokio::spawn(run_tcp_proxy(
            Arc::new(BlackholeProxy),
            yuhaiin_core::flow::Flow { key: flow }.context(),
            flow,
            commands_rx,
            output_tx,
            short_timeouts(),
            None,
        ));

        let closed = timeout(Duration::from_millis(150), async {
            loop {
                if matches!(output_rx.recv().await, Some(ProxyOutput::TcpClosed { flow: key }) if key == flow)
                {
                    break;
                }
            }
        })
        .await;
        assert!(
            closed.is_err(),
            "TCP read inactivity must not close the flow"
        );
        commands_tx.send(ProxyCommand::Shutdown).await.unwrap();
        drop(commands_tx);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn udp_association_closes_when_upload_continues_without_remote_progress() {
        let flow = udp_flow();
        let (commands_tx, commands_rx) = mpsc::channel(32);
        let (output_tx, mut output_rx) = mpsc::channel(8);
        let sender = tokio::spawn(async move {
            loop {
                if commands_tx
                    .send(UdpProxyCommand::Data {
                        flow,
                        target: Endpoint::ip(Network::Udp, flow.destination),
                        payload: vec![1],
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                sleep(Duration::from_millis(2)).await;
            }
        });
        let worker = tokio::spawn(run_udp_proxy(
            Arc::new(BlackholeProxy),
            yuhaiin_core::flow::Flow { key: flow }.context(),
            flow,
            commands_rx,
            output_tx,
            short_timeouts(),
            None,
            2048,
        ));

        let closed = timeout(Duration::from_millis(150), async {
            loop {
                if matches!(output_rx.recv().await, Some(ProxyOutput::UdpClosed { flow: key }) if key == flow)
                {
                    break;
                }
            }
        })
        .await;
        sender.abort();
        worker.await.unwrap();
        assert!(
            closed.is_ok(),
            "continuous upload masked the UDP receive timeout"
        );
    }
}
