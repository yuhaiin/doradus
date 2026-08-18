//! Async TCP, UDP, DNS, and ICMP proxy workers.

use super::*;

#[cfg(feature = "async-proxy")]
pub(super) async fn run_tcp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    flow: TunFlowKey,
    mut commands: mpsc::Receiver<ProxyCommand>,
    output: ProxyOutputSender,
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
pub(super) async fn run_udp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    initial_flow: TunFlowKey,
    mut commands: mpsc::Receiver<UdpProxyCommand>,
    output: ProxyOutputSender,
    timeouts: ProxyTimeouts,
    observer: Option<Arc<dyn TunFlowObserver>>,
    udp_buffer_size: usize,
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
    let mut buffer = vec![0u8; udp_buffer_size];
    let mut routes = HashMap::<Endpoint, TunFlowKey>::new();
    let mut last_flow = None;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.idle));
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
                let flow = routes.get(&source).copied().or(last_flow);
                let Some(flow) = flow else { continue; };
                routes.entry(source).or_insert(flow);
                if !emit_output(
                    &output,
                    ProxyOutput::UdpData { flow, payload: buffer[..length].to_vec() },
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
async fn emit_output(output: &ProxyOutputSender, value: ProxyOutput, timeout: Duration) -> bool {
    output.send(value, timeout).await
}

#[cfg(feature = "async-proxy")]
pub(super) async fn run_dns_query(
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
pub(super) async fn run_icmp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    mut context: crate::FlowContext,
    id: u64,
    flow: TunFlowKey,
    packet: Vec<u8>,
    output: ProxyOutputSender,
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
