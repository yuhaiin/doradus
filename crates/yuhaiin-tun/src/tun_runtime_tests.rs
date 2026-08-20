use super::tun_test_support::*;
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn external_icmp_flow_uses_proxy_ping_and_writes_back_echo_reply() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct PingProxy {
        checked_context: Arc<AtomicBool>,
    }

    impl AsyncProxy for PingProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "ICMP fixture has no TCP stream path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "ICMP fixture has no UDP path",
                ))
            })
        }

        fn ping<'a>(
            &'a self,
            context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Duration>> {
            let checked_context = Arc::clone(&self.checked_context);
            Box::pin(async move {
                if context.network == Network::Tcp && context.destination.network() == Network::Tcp
                {
                    checked_context.store(true, Ordering::Release);
                    Ok(Duration::from_millis(3))
                } else {
                    Err(Error::invalid("ICMP fixture received the wrong context"))
                }
            })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let checked_context = Arc::new(AtomicBool::new(false));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(PingProxy {
        checked_context: Arc::clone(&checked_context),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let mut runtime = TunProxyRuntime::new(selector, 1).unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Icmp,
            source: "10.0.0.2:0".parse().unwrap(),
            destination: "8.8.8.8:0".parse().unwrap(),
        },
    };
    // A full TCP/UDP output queue must not block an ICMP completion.  Go's
    // ping path writes its result independently of ordinary relay payloads.
    runtime
        .proxy_output_tx
        .try_send(ProxyOutput::TcpClosed { flow: flow.key })
        .unwrap();
    runtime
        .handle_proxy_input(ProxyInput::IcmpEchoRequest {
            flow,
            packet: icmp_echo_packet(
                "10.0.0.2".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                7,
                9,
                b"ping",
                false,
            ),
        })
        .unwrap();

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    for _ in 0..20 {
        runtime.process_proxy_outputs(&mut dispatcher).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(checked_context.load(Ordering::Acquire));
    assert_eq!(runtime.task_len(), 0);

    let local = Ipv4Address::new(10, 0, 0, 1);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let reply = device.take_tx().unwrap().expect("proxy ICMP reply");
    let ip = Ipv4Packet::new_checked(&reply).unwrap();
    assert_eq!(ip.src_addr(), Ipv4Address::new(8, 8, 8, 8));
    assert_eq!(ip.dst_addr(), Ipv4Address::new(10, 0, 0, 2));
    assert!(matches!(
        Icmpv4Repr::parse(
            &Icmpv4Packet::new_checked(ip.payload()).unwrap(),
            &ChecksumCapabilities::default(),
        )
        .unwrap(),
        Icmpv4Repr::EchoReply { ident: 7, seq_no: 9, data } if data == b"ping"
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_proxy_runtime_releases_full_cone_nat_tracking() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlowKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "198.51.100.1:53".parse().unwrap(),
    };
    runtime.track_flow(flow).unwrap();
    let (command, _commands) = mpsc::channel(1);
    let join = tokio::spawn(async { std::future::pending::<()>().await });
    runtime.tasks.insert(flow, ProxyTask { command, join });
    assert_eq!(runtime.nat_len().unwrap(), 1);
    drop(runtime);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_proxy_runtime_close_signals_owned_tasks_then_releases_nat() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlowKey {
        network: Network::Tcp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
    };
    runtime.track_flow(flow).unwrap();
    let (command, mut commands) = mpsc::channel(1);
    let join = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    runtime.tasks.insert(flow, ProxyTask { command, join });

    runtime.close_graceful(Duration::from_millis(20)).await;

    assert!(matches!(commands.try_recv(), Ok(ProxyCommand::Shutdown)));
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_proxy_runtime_broadcasts_shutdown_when_one_command_queue_is_full() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let mut runtime = TunProxyRuntime::new(selector, 4).unwrap();
    let mut fixtures = Vec::new();
    for port in 40000..40003 {
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: format!("192.0.2.10:{port}").parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
        };
        runtime.track_flow(flow).unwrap();
        let (command, commands) = mpsc::channel(1);
        let fill_command = command.clone();
        let join = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        runtime.tasks.insert(flow, ProxyTask { command, join });
        fixtures.push((flow, commands, fill_command));
    }

    // Fill every queue except the last task in HashMap iteration order. A
    // sequential close would block on an earlier full queue and never signal
    // that last task before its deadline expires.
    let last_flow = *runtime.tasks.keys().last().unwrap();
    for (flow, _, fill_command) in &fixtures {
        if *flow != last_flow {
            fill_command.try_send(ProxyCommand::Data(vec![1])).unwrap();
        }
    }

    runtime.close_graceful(Duration::from_millis(20)).await;

    let (_, mut last_commands, _) = fixtures
        .into_iter()
        .find(|(flow, _, _)| *flow == last_flow)
        .unwrap();
    assert!(matches!(
        last_commands.try_recv(),
        Ok(ProxyCommand::Shutdown)
    ));
    assert_eq!(runtime.task_len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_input_backpressure_releases_only_the_affected_flow() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
        },
    };
    runtime.track_flow(flow.key).unwrap();
    let (command, _commands) = mpsc::channel(1);
    command.try_send(ProxyCommand::Data(vec![1])).unwrap();
    let join = tokio::spawn(async { std::future::pending::<()>().await });
    runtime.tasks.insert(flow.key, ProxyTask { command, join });

    let error = runtime
        .handle_proxy_input(ProxyInput::TcpData {
            flow,
            payload: b"blocked".to_vec(),
        })
        .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn idle_timeout_closes_quiet_tcp_flow_and_releases_nat() {
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let direct: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&direct),
        bypass: Arc::clone(&direct),
        drop: Arc::clone(&direct),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap()
        .with_timeouts(ProxyTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(1),
            write: Duration::from_secs(1),
            idle: Duration::from_millis(10),
        })
        .unwrap();
    let flow = TunFlowKey {
        network: Network::Tcp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: address,
    };
    runtime
        .handle_proxy_input(ProxyInput::TcpOpened {
            flow: TunFlow { key: flow },
        })
        .unwrap();
    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        runtime.process_proxy_outputs(&mut dispatcher).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
    }
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn idle_timeout_closes_quiet_udp_source_and_releases_full_cone_nat() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};

    struct IdleDatagram;
    impl AsyncDatagram for IdleDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async { std::future::pending::<Result<(usize, Endpoint)>>().await })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct IdleProxy;
    impl AsyncProxy for IdleProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "UDP idle fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async { Ok(Box::new(IdleDatagram) as Box<dyn AsyncDatagram>) })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let proxy: Arc<dyn AsyncProxy> = Arc::new(IdleProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap()
        .with_timeouts(ProxyTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(1),
            write: Duration::from_secs(1),
            idle: Duration::from_millis(10),
        })
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:5353".parse().unwrap(),
        },
    };
    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"one-way".to_vec(),
        })
        .unwrap();
    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        runtime.process_proxy_outputs(&mut dispatcher).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
    }
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn full_cone_udp_input_backpressure_releases_the_shared_source() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};

    struct PendingProxy;
    impl AsyncProxy for PendingProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "backpressure fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async { std::future::pending::<Result<Box<dyn AsyncDatagram>>>().await })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let proxy: Arc<dyn AsyncProxy> = Arc::new(PendingProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let source = "192.0.2.10:40000".parse().unwrap();
    let first = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source,
            destination: "198.51.100.1:5353".parse().unwrap(),
        },
    };
    let second = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source,
            destination: "198.51.100.2:5353".parse().unwrap(),
        },
    };
    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow: first,
            payload: b"first".to_vec(),
        })
        .unwrap();
    tokio::task::yield_now().await;

    let error = runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow: second,
            payload: b"second".to_vec(),
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn full_cone_udp_output_backpressure_closes_datagram_and_releases_nat() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CloseTrackingDatagram {
        closed: Arc<AtomicUsize>,
    }

    impl AsyncDatagram for CloseTrackingDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async move {
                let payload = b"blocked-output";
                buffer[..payload.len()].copy_from_slice(payload);
                Ok((
                    payload.len(),
                    Endpoint::ip(Network::Udp, "198.51.100.1:5353".parse().unwrap()),
                ))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            self.closed.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Ok(()) })
        }
    }

    struct OutputBackpressureProxy {
        closed: Arc<AtomicUsize>,
        opened: Arc<tokio::sync::Notify>,
    }

    impl AsyncProxy for OutputBackpressureProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "output backpressure fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            let closed = Arc::clone(&self.closed);
            let opened = Arc::clone(&self.opened);
            Box::pin(async move {
                opened.notify_one();
                Ok(Box::new(CloseTrackingDatagram { closed }) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let closed = Arc::new(AtomicUsize::new(0));
    let opened = Arc::new(tokio::sync::Notify::new());
    let proxy: Arc<dyn AsyncProxy> = Arc::new(OutputBackpressureProxy {
        closed: Arc::clone(&closed),
        opened: Arc::clone(&opened),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap()
        .with_timeouts(ProxyTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(1),
            write: Duration::from_secs(1),
            idle: Duration::from_millis(10),
        })
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:5353".parse().unwrap(),
        },
    };
    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"request".to_vec(),
        })
        .unwrap();
    opened.notified().await;

    for _ in 0..20 {
        if closed.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(closed.load(Ordering::Acquire), 1);

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    runtime.process_proxy_outputs(&mut dispatcher).unwrap();
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn full_cone_udp_repeated_transport_errors_release_shared_sources() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ErrorDatagram {
        closed: Arc<AtomicUsize>,
        sent: Arc<tokio::sync::Notify>,
    }

    impl AsyncDatagram for ErrorDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            self.sent.notify_one();
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
                sent.notified().await;
                Err(Error::new(
                    ErrorKind::Io,
                    "full-cone transport failed after send",
                ))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            self.closed.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Ok(()) })
        }
    }

    struct ErrorProxy {
        closed: Arc<AtomicUsize>,
        opened: Arc<AtomicUsize>,
        sent: Arc<tokio::sync::Notify>,
    }

    impl AsyncProxy for ErrorProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "full-cone error fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            self.opened.fetch_add(1, Ordering::AcqRel);
            let closed = Arc::clone(&self.closed);
            let sent = Arc::clone(&self.sent);
            Box::pin(async move {
                Ok(Box::new(ErrorDatagram { closed, sent }) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let closed = Arc::new(AtomicUsize::new(0));
    let opened = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(tokio::sync::Notify::new());
    let proxy: Arc<dyn AsyncProxy> = Arc::new(ErrorProxy {
        closed: Arc::clone(&closed),
        opened: Arc::clone(&opened),
        sent,
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    let source = "192.0.2.10:40000".parse().unwrap();

    for cycle in 0..32 {
        for destination in [
            format!("198.51.100.{}:5353", (cycle % 2) + 1)
                .parse()
                .unwrap(),
            format!("198.51.100.{}:5353", (cycle % 2) + 3)
                .parse()
                .unwrap(),
        ] {
            runtime
                .handle_proxy_input(ProxyInput::UdpDatagram {
                    flow: TunFlow {
                        key: TunFlowKey {
                            network: Network::Udp,
                            source,
                            destination,
                        },
                    },
                    payload: format!("error-cycle-{cycle}").into_bytes(),
                })
                .unwrap();
        }

        for _ in 0..100 {
            runtime.process_proxy_outputs(&mut dispatcher).unwrap();
            if runtime.task_len() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.task_len(), 0, "cycle {cycle} left a UDP task");
        assert_eq!(
            runtime.nat_len().unwrap(),
            0,
            "cycle {cycle} left NAT state"
        );
        assert_eq!(table.len().unwrap(), 0, "cycle {cycle} left table state");
    }

    assert_eq!(opened.load(Ordering::Acquire), 32);
    assert_eq!(closed.load(Ordering::Acquire), 32);
}

#[tokio::test(flavor = "current_thread")]
async fn polling_finished_tcp_task_releases_nat_tracking() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlowKey {
        network: Network::Tcp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
    };
    runtime.track_flow(flow).unwrap();
    let (command, _commands) = mpsc::channel(1);
    let join = tokio::spawn(async {});
    runtime.tasks.insert(flow, ProxyTask { command, join });
    tokio::task::yield_now().await;

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    runtime.process_proxy_outputs(&mut dispatcher).unwrap();

    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(any())]
#[tokio::test(flavor = "current_thread")]
async fn sync_dns_task_is_owned_and_releases_full_cone_mapping_on_force_close() {
    use crate::dns::{DnsHandler, DnsRecordType, DnsResponse};
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};
    use crate::{DomainName, IpSet};

    struct FixedDns;
    impl DnsHandler for FixedDns {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_dns_handler(Arc::new(FixedDns))
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:53".parse().unwrap(),
        },
    };

    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"owned-dns-task".to_vec(),
        })
        .unwrap();
    assert_eq!(runtime.task_len(), 1);
    assert_eq!(runtime.nat_len().unwrap(), 1);

    runtime.close();
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(any())]
#[tokio::test(flavor = "current_thread")]
async fn sync_dns_completion_does_not_use_shared_proxy_output_queue() {
    use crate::dns::{DnsHandler, DnsRecordType, DnsResponse};
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};
    use crate::{DomainName, IpSet};

    struct FixedDns;
    impl DnsHandler for FixedDns {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_dns_handler(Arc::new(FixedDns))
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:53".parse().unwrap(),
        },
    };
    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"malformed-dns-packet".to_vec(),
        })
        .unwrap();
    runtime
        .proxy_output_tx
        .try_send(ProxyOutput::UdpClosed {
            flow: TunFlowKey {
                network: Network::Udp,
                source: "192.0.2.1:40000".parse().unwrap(),
                destination: "192.0.2.2:53".parse().unwrap(),
            },
        })
        .unwrap();

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    dispatcher.ensure_udp_socket(flow.key.destination).unwrap();
    for _ in 0..100 {
        if runtime.dns_tasks[0].join.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    runtime.process_proxy_outputs(&mut dispatcher).unwrap();

    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(any())]
#[tokio::test(flavor = "current_thread")]
async fn proxy_runtime_hijacks_dns_udp_flow_without_entering_proxy() {
    use crate::dns::{DnsHandler, DnsRecordType, DnsResponse, encode_query};
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};
    use crate::{DomainName, IpSet};

    struct FixedDns;
    impl DnsHandler for FixedDns {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }
    impl crate::dns::AsyncDnsHandler for FixedDns {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> crate::BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move { crate::dns::answer_query(packet, self) })
        }
    }

    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    let direct: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: std::time::Duration::from_secs(1),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&direct),
        bypass: Arc::clone(&direct),
        drop: Arc::new(crate::proxy::DropAsyncProxy),
    });
    let mut proxy_runtime = TunProxyRuntime::new(selector, 1)
        .unwrap()
        .with_async_dns_handler(Arc::new(FixedDns));
    let query = encode_query(
        7,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::A,
    )
    .unwrap();
    device
        .enqueue_rx(udp_packet(remote, local, 41000, 53, &query))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    for event in dispatcher.proxy_inputs().collect::<Vec<_>>() {
        proxy_runtime.handle_proxy_input(event).unwrap();
    }

    // Keep the shared proxy output queue full while the DNS future completes.
    // DNS interception must not turn this unrelated flow backpressure into a
    // fatal TUN owner error.
    proxy_runtime
        .proxy_output_tx
        .try_send(ProxyOutput::UdpClosed {
            flow: TunFlowKey {
                network: Network::Udp,
                source: "192.0.2.1:40000".parse().unwrap(),
                destination: "192.0.2.2:53".parse().unwrap(),
            },
        })
        .unwrap();

    let mut response = None;
    for tick in 2..100 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        proxy_runtime
            .process_proxy_outputs(&mut dispatcher)
            .unwrap();
        dispatcher
            .poll_with(&mut interface, &mut device, Instant::from_millis(tick))
            .unwrap();
        if let Some(packet) = device.take_tx().unwrap() {
            response = Some(packet);
            break;
        }
    }
    proxy_runtime.close();

    let response = response.expect("DNS hijack did not return a response to TUN");
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    let response = crate::dns::decode_response(udp.payload(), 7, DnsRecordType::A).unwrap();
    assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn translated_udp_endpoint_conflict_releases_only_the_conflicting_source() {
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 2)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let first = TunFlowKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
    };
    let second = TunFlowKey {
        network: Network::Udp,
        source: "192.0.2.10:40001".parse().unwrap(),
        destination: "198.51.100.2:443".parse().unwrap(),
    };
    for flow in [first, second] {
        runtime.track_flow(flow).unwrap();
        let (command, _commands) = mpsc::channel(1);
        let join = tokio::spawn(async { std::future::pending::<()>().await });
        let source = udp_source_key(flow);
        runtime.udp_tasks.insert(
            source,
            UdpProxyTask {
                command,
                join,
                flows: HashSet::from([flow]),
            },
        );
        runtime.udp_flow_sources.insert(flow, source);
    }
    let translated = "127.0.0.1:53000".parse().unwrap();
    runtime
        .proxy_output_tx
        .try_send(ProxyOutput::UdpBound {
            source: udp_source_key(first),
            translated,
        })
        .unwrap();
    runtime
        .proxy_output_tx
        .try_send(ProxyOutput::UdpBound {
            source: udp_source_key(second),
            translated,
        })
        .unwrap();

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    runtime.process_proxy_outputs(&mut dispatcher).unwrap();

    assert!(runtime.udp_tasks.contains_key(&udp_source_key(first)));
    assert!(!runtime.udp_tasks.contains_key(&udp_source_key(second)));
    assert_eq!(runtime.nat_len().unwrap(), 1);
    runtime.close();
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(any())]
#[tokio::test(flavor = "current_thread")]
async fn pending_async_dns_does_not_block_tun_shutdown_and_releases_full_cone_flow() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::dns::AsyncDnsHandler;
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};

    struct PendingDns {
        dropped: Arc<AtomicBool>,
    }

    impl AsyncDnsHandler for PendingDns {
        fn answer<'a>(&'a self, _packet: &'a [u8]) -> crate::BoxFuture<'a, Result<Vec<u8>>> {
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                let _guard = Guard(dropped);
                std::future::pending::<Result<Vec<u8>>>().await
            })
        }
    }

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_async_dns_handler(Arc::new(PendingDns {
            dropped: Arc::clone(&dropped),
        }))
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "198.51.100.1:53".parse().unwrap(),
        },
    };

    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"pending-dns".to_vec(),
        })
        .unwrap();
    assert_eq!(runtime.task_len(), 1);
    assert_eq!(runtime.nat_len().unwrap(), 1);

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    runtime.process_proxy_outputs(&mut dispatcher).unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        runtime.close_graceful(Duration::from_millis(5)),
    )
    .await
    .expect("pending async DNS blocked TUN shutdown");

    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(any())]
#[tokio::test(flavor = "current_thread")]
async fn async_dns_upstream_timeout_closes_flow_and_releases_full_cone_mapping() {
    use crate::dns::AsyncDnsHandler;
    use crate::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct PendingDns {
        dropped: Arc<AtomicBool>,
    }

    impl AsyncDnsHandler for PendingDns {
        fn answer<'a>(&'a self, _packet: &'a [u8]) -> crate::BoxFuture<'a, Result<Vec<u8>>> {
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                let _guard = Guard(dropped);
                std::future::pending::<Result<Vec<u8>>>().await
            })
        }
    }

    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: Arc::clone(&drop_proxy),
        bypass: Arc::clone(&drop_proxy),
        drop: Arc::clone(&drop_proxy),
    });
    let table = NatTable::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_async_dns_handler(Arc::new(PendingDns {
            dropped: Arc::clone(&dropped),
        }))
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap()
        .with_io_timeout(Duration::from_millis(5))
        .unwrap();
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            source: "192.0.2.11:40001".parse().unwrap(),
            destination: "198.51.100.2:53".parse().unwrap(),
        },
    };
    runtime
        .handle_proxy_input(ProxyInput::UdpDatagram {
            flow,
            payload: b"timeout-dns".to_vec(),
        })
        .unwrap();
    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.process_proxy_outputs(&mut dispatcher).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
    }
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_runtime_relays_established_tcp_flow_through_direct_proxy() {
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer[..7])
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer[..7])
            .await
            .unwrap();
    });

    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let destination = match server_address.ip() {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => panic!("test TCP server unexpectedly used IPv6"),
    };
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(destination), 32))
            .unwrap();
    });
    // Force the proxy output to take the partial-write path.  The response
    // must still be delivered before the proxy's EOF/close completion is
    // allowed to tear down the smoltcp socket.
    let mut dispatcher = TunDispatcher::new(4096, 4, 4).unwrap();
    let direct: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: std::time::Duration::from_secs(1),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&direct),
        bypass: Arc::clone(&direct),
        drop: Arc::new(crate::proxy::DropAsyncProxy),
    });
    let mut proxy_runtime = TunProxyRuntime::new(selector, 8).unwrap();

    device
        .enqueue_rx(tcp_syn_packet(
            remote,
            destination,
            41000,
            server_address.port(),
            100,
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let syn_ack = device.take_tx().unwrap().unwrap();
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let server_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;
    assert!(dispatcher.proxy_inputs().next().is_none());

    device
        .enqueue_rx(tcp_data_packet(
            remote,
            destination,
            41000,
            server_address.port(),
            101,
            server_sequence + 1,
            &[],
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();
    for event in dispatcher.proxy_inputs().collect::<Vec<_>>() {
        proxy_runtime.handle_proxy_input(event).unwrap();
    }

    device
        .enqueue_rx(tcp_data_packet(
            remote,
            destination,
            41000,
            server_address.port(),
            101,
            server_sequence + 1,
            b"request",
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(3))
        .unwrap();
    for event in dispatcher.proxy_inputs().collect::<Vec<_>>() {
        proxy_runtime.handle_proxy_input(event).unwrap();
    }

    let mut response_payload = Vec::new();
    let mut next_server_sequence = server_sequence + 1;
    let client_sequence = 108;
    for tick in 4..150 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        proxy_runtime
            .process_proxy_outputs(&mut dispatcher)
            .unwrap();
        dispatcher
            .poll_with(&mut interface, &mut device, Instant::from_millis(tick))
            .unwrap();
        while let Some(packet) = device.take_tx().unwrap() {
            let ip = Ipv4Packet::new_checked(&packet).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if !tcp.payload().is_empty() {
                let sequence = tcp.seq_number().0 as u32;
                if sequence == next_server_sequence {
                    response_payload.extend_from_slice(tcp.payload());
                    next_server_sequence += tcp.payload().len() as u32;
                    device
                        .enqueue_rx(tcp_data_packet(
                            remote,
                            destination,
                            41000,
                            server_address.port(),
                            client_sequence,
                            next_server_sequence,
                            &[],
                        ))
                        .unwrap();
                }
            }
            if response_payload == b"request" {
                break;
            }
        }
        if response_payload == b"request" {
            break;
        }
    }
    proxy_runtime.close();
    server_task.await.unwrap();

    assert_eq!(response_payload, b"request");
}
