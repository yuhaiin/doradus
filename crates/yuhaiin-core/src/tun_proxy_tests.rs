use super::tun_test_support::*;
use super::*;

#[cfg(feature = "async-proxy")]
#[test]
fn proxy_runtime_enriches_context_with_injected_process_metadata() {
    use crate::process::{ProcessInfo, ProcessResolver};
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};
    use std::io;

    struct FixedResolver;
    impl ProcessResolver for FixedResolver {
        fn resolve(
            &self,
            _network: Network,
            _source: SocketAddr,
            _destination: SocketAddr,
        ) -> io::Result<Option<ProcessInfo>> {
            Ok(Some(ProcessInfo {
                path: "/usr/bin/test-client".to_owned(),
                pid: 42,
                uid: 1000,
            }))
        }
    }

    let direct: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    });
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&direct),
        bypass: Arc::clone(&direct),
        drop: Arc::new(crate::proxy::DropAsyncProxy),
    });
    let runtime = TunProxyRuntime::new(selector, 4)
        .unwrap()
        .with_process_resolver(FixedResolver);
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:40000".parse().unwrap(),
            destination: "93.184.216.34:443".parse().unwrap(),
        },
    };
    let context = runtime.context_for_flow(flow);
    assert_eq!(context.component.as_deref(), Some("tun"));
    assert_eq!(context.process.as_deref(), Some("/usr/bin/test-client"));
    assert_eq!(context.process_id, Some(42));
    assert_eq!(context.user_id, Some(1000));
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn proxy_runtime_relays_udp_event_through_direct_proxy() {
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, source) = server.recv_from(&mut buffer).await.unwrap();
        server.send_to(&buffer[..length], source).await.unwrap();
    });

    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let destination = match server_address.ip() {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => panic!("test UDP server unexpectedly used IPv6"),
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
    let mut proxy_runtime = TunProxyRuntime::new(selector, 8)
        .unwrap()
        .with_nat(NatTable::new(), Duration::from_secs(30))
        .unwrap();
    device
        .enqueue_rx(udp_packet(
            remote,
            destination,
            41000,
            server_address.port(),
            b"through-runtime",
        ))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        proxy_runtime.handle_event(event).unwrap();
    }
    assert_eq!(proxy_runtime.nat_len().unwrap(), 1);

    let mut response = None;
    for tick in 2..100 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        proxy_runtime.poll_outputs(&mut dispatcher).unwrap();
        dispatcher
            .poll_with(&mut interface, &mut device, Instant::from_millis(tick))
            .unwrap();
        if let Some(packet) = device.take_tx().unwrap() {
            response = Some(packet);
            break;
        }
    }
    proxy_runtime.close();
    assert_eq!(proxy_runtime.nat_len().unwrap(), 0);
    server_task.await.unwrap();

    let response = response.expect("direct proxy did not return UDP data to TUN");
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(udp.src_port(), server_address.port());
    assert_eq!(udp.dst_port(), 41000);
    assert_eq!(udp.payload(), b"through-runtime");
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn proxy_runtime_shares_one_udp_proxy_per_source_for_full_cone_nat() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Packet = (Vec<u8>, Endpoint);

    struct EchoDatagram {
        packets: Arc<Mutex<VecDeque<Packet>>>,
        notify: Arc<tokio::sync::Notify>,
    }

    impl AsyncDatagram for EchoDatagram {
        fn send_to<'a>(
            &'a self,
            _payload: &'a [u8],
            _target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(_payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            let packets = Arc::clone(&self.packets);
            let notify = Arc::clone(&self.notify);
            Box::pin(async move {
                loop {
                    if let Some((payload, source)) = packets.lock().unwrap().pop_front() {
                        if buffer.len() < payload.len() {
                            return Err(Error::invalid("test datagram buffer too small"));
                        }
                        buffer[..payload.len()].copy_from_slice(&payload);
                        return Ok((payload.len(), source));
                    }
                    notify.notified().await;
                }
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct SourceSharingProxy {
        opens: Arc<AtomicUsize>,
    }

    impl AsyncProxy for SourceSharingProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "source sharing test has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            self.opens.fetch_add(1, Ordering::AcqRel);
            Box::pin(async {
                Ok(Box::new(EchoDatagram {
                    packets: Arc::new(Mutex::new(VecDeque::new())),
                    notify: Arc::new(tokio::sync::Notify::new()),
                }) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let opens = Arc::new(AtomicUsize::new(0));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(SourceSharingProxy {
        opens: Arc::clone(&opens),
    });
    let selector: Arc<dyn AsyncProxySelector> = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 8)
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
        .handle_event(TunEvent::UdpDatagram {
            flow: first,
            payload: b"first".to_vec(),
        })
        .unwrap();
    runtime
        .handle_event(TunEvent::UdpDatagram {
            flow: second,
            payload: b"second".to_vec(),
        })
        .unwrap();

    for _ in 0..20 {
        if opens.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(opens.load(Ordering::Acquire), 1);
    assert_eq!(runtime.nat_len().unwrap(), 1);
    assert_eq!(runtime.task_len(), 1);

    let mut dispatcher = TunDispatcher::new(32, 32, 4).unwrap();
    runtime.poll_outputs(&mut dispatcher).unwrap();
    assert_eq!(
        table
            .lookup_translated(
                "127.0.0.1:1".parse().unwrap(),
                "203.0.113.200:9".parse().unwrap(),
            )
            .unwrap()
            .unwrap()
            .source,
        source
    );

    runtime.close();
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn full_cone_udp_long_flow_reuses_one_relay_and_force_close_releases_it() {
    use crate::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, StaticProxySelector};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct LongFlowState {
        packets: Mutex<VecDeque<(Vec<u8>, Endpoint)>>,
        notify: tokio::sync::Notify,
        sent: AtomicUsize,
    }

    struct LongFlowDatagram {
        state: Arc<LongFlowState>,
    }

    impl AsyncDatagram for LongFlowDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            let state = Arc::clone(&self.state);
            let payload = payload.to_vec();
            Box::pin(async move {
                let length = payload.len();
                state.packets.lock().unwrap().push_back((payload, target));
                state.sent.fetch_add(1, Ordering::AcqRel);
                state.notify.notify_one();
                Ok(length)
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                loop {
                    if let Some((payload, source)) = state.packets.lock().unwrap().pop_front() {
                        if buffer.len() < payload.len() {
                            return Err(Error::invalid("long flow buffer too small"));
                        }
                        buffer[..payload.len()].copy_from_slice(&payload);
                        return Ok((payload.len(), source));
                    }
                    state.notify.notified().await;
                }
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:9".parse().unwrap()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct LongFlowProxy {
        state: Arc<LongFlowState>,
        opens: AtomicUsize,
    }

    impl AsyncProxy for LongFlowProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "long flow fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            self.opens.fetch_add(1, Ordering::AcqRel);
            let state = Arc::clone(&self.state);
            Box::pin(
                async move { Ok(Box::new(LongFlowDatagram { state }) as Box<dyn AsyncDatagram>) },
            )
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let state = Arc::new(LongFlowState {
        packets: Mutex::new(VecDeque::new()),
        notify: tokio::sync::Notify::new(),
        sent: AtomicUsize::new(0),
    });
    let proxy = Arc::new(LongFlowProxy {
        state: Arc::clone(&state),
        opens: AtomicUsize::new(0),
    });
    let proxy_selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy) as Arc<dyn AsyncProxy>,
        proxy: Arc::clone(&proxy) as Arc<dyn AsyncProxy>,
        bypass: Arc::clone(&proxy) as Arc<dyn AsyncProxy>,
        drop: Arc::clone(&proxy) as Arc<dyn AsyncProxy>,
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(proxy_selector, 256)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let source = "192.0.2.10:40000".parse().unwrap();
    let destinations = [
        "198.51.100.1:5353".parse().unwrap(),
        "198.51.100.2:5353".parse().unwrap(),
    ];

    for index in 0..128 {
        let flow = TunFlow {
            key: TunFlowKey {
                network: Network::Udp,
                source,
                destination: destinations[index % destinations.len()],
            },
        };
        runtime
            .handle_event(TunEvent::UdpDatagram {
                flow,
                payload: format!("long-flow-{index}").into_bytes(),
            })
            .unwrap();
        if index % 8 == 0 {
            tokio::task::yield_now().await;
        }
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        while state.sent.load(Ordering::Acquire) < 128 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("full-cone long flow did not send all datagrams");
    assert_eq!(proxy.opens.load(Ordering::Acquire), 1);
    assert_eq!(runtime.task_len(), 1);
    assert_eq!(runtime.nat_len().unwrap(), 1);
    assert_eq!(table.len().unwrap(), 1);

    runtime.close();
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn full_cone_real_direct_tun_accepts_unseen_peer_and_force_closes_source() {
    use crate::proxy::{AsyncProxy, DirectAsyncProxy, StaticProxySelector};

    let destination_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address_a = destination_a.local_addr().unwrap();
    let address_b = destination_b.local_addr().unwrap();
    let server_a = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            let (length, source) = destination_a.recv_from(&mut buffer).await.unwrap();
            destination_a
                .send_to(&buffer[..length], source)
                .await
                .unwrap();
        }
    });
    let server_b = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            let (length, source) = destination_b.recv_from(&mut buffer).await.unwrap();
            destination_b
                .send_to(&buffer[..length], source)
                .await
                .unwrap();
        }
    });

    let local = Ipv4Address::new(10, 0, 0, 1);
    let application = Ipv4Address::new(10, 0, 0, 2);
    let destination_ip = Ipv4Address::new(127, 0, 0, 1);
    let mut device = SmoltcpTunDevice::new(1500, 128).unwrap();
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
            .push(IpCidr::new(IpAddress::Ipv4(destination_ip), 32))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(4096, 4096, 16).unwrap();
    let direct: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    });
    let selector: Arc<dyn AsyncProxySelector> = Arc::new(StaticProxySelector {
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&direct),
        bypass: Arc::clone(&direct),
        drop: Arc::new(crate::proxy::DropAsyncProxy),
    });
    let table = NatTable::new();
    let mut runtime = TunProxyRuntime::new(selector, 128)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    let source = std::net::SocketAddr::new(application.into(), 41000);

    let first_payload = b"real-direct-first".to_vec();
    device
        .enqueue_rx(udp_packet(
            application,
            destination_ip,
            source.port(),
            address_a.port(),
            &first_payload,
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let first_event = dispatcher.events().next().expect("first UDP event");
    runtime.handle_event(first_event).unwrap();

    let mut first_response = None;
    for tick in 2..200 {
        tokio::task::yield_now().await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        dispatcher
            .poll_with(&mut interface, &mut device, Instant::from_millis(tick))
            .unwrap();
        if let Some(packet) = device.take_tx().unwrap() {
            first_response = Some(packet);
            break;
        }
    }
    let first_response = first_response.expect("real direct UDP response did not reach TUN");
    let first_ip = Ipv4Packet::new_checked(&first_response).unwrap();
    assert_eq!(
        UdpPacket::new_checked(first_ip.payload())
            .unwrap()
            .payload(),
        first_payload
    );
    let translated = table
        .lookup_source(Network::Udp, source)
        .unwrap()
        .expect("real direct transport did not bind NAT endpoint")
        .translated;
    assert_ne!(translated, source);

    for round in 0..64 {
        let port = if round % 2 == 0 {
            address_b.port()
        } else {
            address_a.port()
        };
        let payload = format!("real-direct-round-{round}").into_bytes();
        device
            .enqueue_rx(udp_packet(
                application,
                destination_ip,
                source.port(),
                port,
                &payload,
            ))
            .unwrap();
        dispatcher
            .poll_with(
                &mut interface,
                &mut device,
                Instant::from_millis(1_000 + round * 4),
            )
            .unwrap();
        let event = dispatcher.events().next().expect("long UDP event");
        runtime.handle_event(event).unwrap();

        let mut response = None;
        for step in 0..200 {
            tokio::task::yield_now().await;
            runtime.poll_outputs(&mut dispatcher).unwrap();
            dispatcher
                .poll_with(
                    &mut interface,
                    &mut device,
                    Instant::from_millis(1_001 + round * 4 + step),
                )
                .unwrap();
            if let Some(packet) = device.take_tx().unwrap() {
                response = Some(packet);
                break;
            }
        }
        let response = response.expect("real direct long-flow response did not reach TUN");
        let ip = Ipv4Packet::new_checked(&response).unwrap();
        assert_eq!(
            UdpPacket::new_checked(ip.payload()).unwrap().payload(),
            payload
        );
    }

    let unseen_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    unseen_peer
        .send_to(b"unseen-external-peer", translated)
        .await
        .unwrap();
    assert_eq!(
        table
            .lookup_translated(translated, unseen_peer.local_addr().unwrap())
            .unwrap()
            .unwrap()
            .source,
        source
    );
    let mut unseen_response = None;
    for tick in 2_000..2_200 {
        tokio::task::yield_now().await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        dispatcher
            .poll_with(&mut interface, &mut device, Instant::from_millis(tick))
            .unwrap();
        if let Some(packet) = device.take_tx().unwrap() {
            unseen_response = Some(packet);
            break;
        }
    }
    let unseen_response = unseen_response.expect("unseen peer response did not reach TUN");
    let unseen_ip = Ipv4Packet::new_checked(&unseen_response).unwrap();
    assert_eq!(
        UdpPacket::new_checked(unseen_ip.payload())
            .unwrap()
            .payload(),
        b"unseen-external-peer"
    );
    assert_eq!(runtime.task_len(), 1);
    assert_eq!(runtime.nat_len().unwrap(), 1);

    runtime.close();
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);
    server_a.abort();
    server_b.abort();
    let _ = server_a.await;
    let _ = server_b.await;
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn full_cone_runtime_restarts_after_aborting_multiple_real_udp_sockets() {
    use crate::proxy::{
        AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream, StaticProxySelector,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RealDatagram {
        socket: tokio::net::UdpSocket,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for RealDatagram {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl AsyncDatagram for RealDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: Endpoint,
        ) -> crate::BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                let address = target
                    .addr()
                    .ok_or_else(|| Error::invalid("real socket fixture needs an IP target"))?;
                self.socket
                    .send_to(payload, address)
                    .await
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> crate::BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async move {
                let (length, source) = self
                    .socket
                    .recv_from(buffer)
                    .await
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
                Ok((length, Endpoint::ip(Network::Udp, source)))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            self.socket
                .local_addr()
                .map(|address| Endpoint::ip(Network::Udp, address))
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct RealSocketProxy {
        opened: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl AsyncProxy for RealSocketProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "real UDP socket fixture has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a crate::FlowContext,
        ) -> crate::BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            let opened = Arc::clone(&self.opened);
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
                opened.fetch_add(1, Ordering::AcqRel);
                Ok(Box::new(RealDatagram { socket, dropped }) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let mut servers = Vec::new();
    for _ in 0..6 {
        servers.push(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    let destinations = servers
        .iter()
        .map(|server| server.local_addr().unwrap())
        .collect::<Vec<_>>();
    let opened = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(RealSocketProxy {
        opened: Arc::clone(&opened),
        dropped: Arc::clone(&dropped),
    });
    let selector: Arc<dyn AsyncProxySelector> = Arc::new(StaticProxySelector {
        direct: Arc::clone(&proxy),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&proxy),
        drop: Arc::clone(&proxy),
    });
    let table = NatTable::new();
    let source_count = destinations.len();

    let mut runtime = TunProxyRuntime::new(Arc::clone(&selector), 32)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    for (index, destination) in destinations.iter().copied().enumerate() {
        runtime
            .handle_event(TunEvent::UdpDatagram {
                flow: TunFlow {
                    key: TunFlowKey {
                        network: Network::Udp,
                        source: format!("192.0.2.{}:{}", index + 10, 40_000 + index)
                            .parse()
                            .unwrap(),
                        destination,
                    },
                },
                payload: format!("generation-one-{index}").into_bytes(),
            })
            .unwrap();
    }
    for _ in 0..100 {
        if opened.load(Ordering::Acquire) == source_count {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(opened.load(Ordering::Acquire), source_count);
    assert_eq!(runtime.task_len(), source_count);
    assert_eq!(runtime.nat_len().unwrap(), source_count);

    // Abort while every real socket is blocked in recv_from.  The owner
    // must drop each socket and release every source mapping atomically.
    runtime.close();
    for _ in 0..100 {
        if dropped.load(Ordering::Acquire) == source_count {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(dropped.load(Ordering::Acquire), source_count);
    assert_eq!(runtime.task_len(), 0);
    assert_eq!(runtime.nat_len().unwrap(), 0);
    assert_eq!(table.len().unwrap(), 0);

    // Recreate the runtime with the same table and sources.  A restart
    // starts from no stale translated endpoint while the next generation
    // can allocate fresh real sockets normally.
    let mut restarted = TunProxyRuntime::new(selector, 32)
        .unwrap()
        .with_nat(table.clone(), Duration::from_secs(30))
        .unwrap();
    for (index, destination) in destinations.iter().copied().enumerate() {
        restarted
            .handle_event(TunEvent::UdpDatagram {
                flow: TunFlow {
                    key: TunFlowKey {
                        network: Network::Udp,
                        source: format!("192.0.2.{}:{}", index + 10, 40_000 + index)
                            .parse()
                            .unwrap(),
                        destination,
                    },
                },
                payload: format!("generation-two-{index}").into_bytes(),
            })
            .unwrap();
    }
    for _ in 0..100 {
        if opened.load(Ordering::Acquire) == source_count * 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(opened.load(Ordering::Acquire), source_count * 2);
    assert_eq!(restarted.task_len(), source_count);
    assert_eq!(restarted.nat_len().unwrap(), source_count);
    restarted.close();
    for _ in 0..100 {
        if dropped.load(Ordering::Acquire) == source_count * 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(dropped.load(Ordering::Acquire), source_count * 2);
    assert_eq!(table.len().unwrap(), 0);
}
