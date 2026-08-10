use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use smoltcp::iface::{Config, Interface};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_response, encode_query,
};
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, BlockingStreamProxy, BoxAsyncStream, FixedAsyncProxy,
    HttpProxyConnector, Socks5Connector, StaticProxySelector,
};
use yuhaiin_core::tun::{SmoltcpTunDevice, TunDispatcher, TunEvent, TunFlowKey, TunProxyRuntime};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network, ResolverPolicy,
    Result, RouteMode,
};
use yuhaiin_store::ConfigStore;
use yuhaiin_store::fakeip::{
    AsyncDomainResolver, FakeIpAnswerTransform, FakeIpAsyncDnsHandler, FakeIpConfig, FakeIpPool,
};

use yuhaiin_trie::router::{
    RouteDecision, RouteRule, Router, RouterRuntime, RuleAction, RuntimeRoutedProxySelector,
};

fn udp_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 8 + payload.len()];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    UdpRepr {
        src_port: source_port,
        dst_port: destination_port,
    }
    .emit(
        &mut UdpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        payload.len(),
        |packet| packet.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    bytes
}

fn poll(
    dispatcher: &mut TunDispatcher,
    interface: &mut Interface,
    device: &mut SmoltcpTunDevice,
    millis: i64,
) -> Result<()> {
    dispatcher.poll_with(interface, device, Instant::from_millis(millis))?;
    Ok(())
}

fn take_udp_payload(device: &SmoltcpTunDevice) -> Vec<u8> {
    let packet = device.take_tx().unwrap().expect("TUN response packet");
    let ip = Ipv4Packet::new_checked(&packet).unwrap();
    UdpPacket::new_checked(ip.payload())
        .unwrap()
        .payload()
        .to_vec()
}

fn tcp_syn_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    TcpRepr {
        src_port: source_port,
        dst_port: destination_port,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(sequence as i32),
        ack_number: None,
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    }
    .emit(
        &mut TcpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        &ChecksumCapabilities::default(),
    );
    bytes
}

fn tcp_data_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20 + payload.len()];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Tcp,
        payload_len: 20 + payload.len(),
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    TcpRepr {
        src_port: source_port,
        dst_port: destination_port,
        control: TcpControl::Psh,
        seq_number: TcpSeqNumber(sequence as i32),
        ack_number: Some(TcpSeqNumber(acknowledgement as i32)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    }
    .emit(
        &mut TcpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        &ChecksumCapabilities::default(),
    );
    bytes
}

#[derive(Clone, Copy)]
enum StreamProxyKind {
    Http,
    Socks5,
}

fn spawn_stream_proxy(kind: StreamProxyKind) -> (SocketAddr, SocketAddr, JoinHandle<()>) {
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let task = std::thread::spawn(move || {
        let target_task = std::thread::spawn(move || {
            let (mut target, _) = target_listener.accept().unwrap();
            target
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut payload = [0u8; 7];
            target.read_exact(&mut payload).unwrap();
            target.write_all(&payload).unwrap();
        });

        let (mut client, _) = proxy_listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        match kind {
            StreamProxyKind::Http => {
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    client.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let expected = format!("CONNECT {target_address} HTTP/1.1");
                assert!(String::from_utf8_lossy(&request).starts_with(&expected));
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .unwrap();
            }
            StreamProxyKind::Socks5 => {
                let mut greeting = [0u8; 3];
                client.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                client.write_all(&[5, 0]).unwrap();
                let mut request = [0u8; 10];
                client.read_exact(&mut request).unwrap();
                assert_eq!(&request[..4], &[5, 1, 0, 1]);
                let requested = SocketAddr::from((
                    [request[4], request[5], request[6], request[7]],
                    u16::from_be_bytes([request[8], request[9]]),
                ));
                assert_eq!(requested, target_address);
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            }
        }

        let mut target = TcpStream::connect(target_address).unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut payload = [0u8; 7];
        client.read_exact(&mut payload).unwrap();
        target.write_all(&payload).unwrap();
        target.read_exact(&mut payload).unwrap();
        client.write_all(&payload).unwrap();
        target_task.join().unwrap();
    });
    (proxy_address, target_address, task)
}

struct Resolver;

impl AsyncDomainResolver for Resolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> yuhaiin_core::LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        })
    }
}

struct EchoDatagram {
    input: AsyncMutex<mpsc::Receiver<(Vec<u8>, Endpoint)>>,
    output: mpsc::Sender<(Vec<u8>, Endpoint)>,
    sent_targets: Arc<Mutex<Vec<Endpoint>>>,
}

impl AsyncDatagram for EchoDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let length = payload.len();
            self.sent_targets.lock().unwrap().push(target.clone());
            self.output
                .send((payload.to_vec(), target))
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "echo datagram closed"))?;
            Ok(length)
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (payload, source) = self
                .input
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| Error::new(ErrorKind::Closed, "echo datagram closed"))?;
            if payload.len() > buffer.len() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "echo datagram is too large",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), source))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            "127.0.0.1:10000".parse().unwrap(),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct RecordingProxy {
    contexts: Arc<Mutex<Vec<FlowContext>>>,
    sent_targets: Arc<Mutex<Vec<Endpoint>>>,
}

impl AsyncProxy for RecordingProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "TCP is not part of this UDP composition fixture",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let contexts = Arc::clone(&self.contexts);
        let sent_targets = Arc::clone(&self.sent_targets);
        Box::pin(async move {
            contexts.lock().unwrap().push(context.clone());
            let (output, input) = mpsc::channel(4);
            Ok(Box::new(EchoDatagram {
                input: AsyncMutex::new(input),
                output,
                sent_targets,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct PendingGuard(Arc<AtomicBool>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct PendingProxy {
    dropped: Arc<AtomicBool>,
}

impl AsyncProxy for PendingProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _guard = PendingGuard(dropped);
            std::future::pending::<Result<BoxAsyncStream>>().await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "pending fixture has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct DuplexProxy {
    saw_eof: Arc<AtomicBool>,
}

impl AsyncProxy for DuplexProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let saw_eof = Arc::clone(&self.saw_eof);
        Box::pin(async move {
            let (client, mut server) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut request = [0u8; 7];
                if tokio::io::AsyncReadExt::read_exact(&mut server, &mut request)
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut server, b"response").await;
                    let mut rest = Vec::new();
                    let _ = tokio::io::AsyncReadExt::read_to_end(&mut server, &mut rest).await;
                    saw_eof.store(true, Ordering::Release);
                }
            });
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "duplex fixture has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

fn route_rule(pattern: &str) -> RouteRule {
    RouteRule {
        rule_name: String::new(),
        tag: String::new(),
        list_names: Vec::new(),
        pattern: pattern.to_owned(),
        required_patterns: Vec::new(),
        always_false: false,
        action: RuleAction::Proxy,
        network: Some(Network::Udp),
        excluded_networks: Vec::new(),
        port: Some((443, 443)),
        excluded_ports: Vec::new(),
        geo_country: None,
        excluded_geo_countries: Vec::new(),
        inbound_names: Vec::new(),
        excluded_inbound_names: Vec::new(),
        process_names: Vec::new(),
        excluded_process_names: Vec::new(),
        excluded_patterns: yuhaiin_trie::CombinedTrie::new(),
        resolver_policy: ResolverPolicy::default(),
        priority: 10,
    }
}

async fn run_stream_proxy_tun(kind: StreamProxyKind) {
    let (proxy_address, target_address, fixture) = spawn_stream_proxy(kind);
    let target_ip = match target_address.ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => panic!("stream fixture unexpectedly used IPv6"),
    };
    let connector: Arc<dyn yuhaiin_core::proxy::StreamConnector> = match kind {
        StreamProxyKind::Http => Arc::new(HttpProxyConnector {
            proxy: proxy_address,
            timeout: Duration::from_secs(2),
            username: None,
            password: None,
        }),
        StreamProxyKind::Socks5 => Arc::new(Socks5Connector {
            proxy: proxy_address,
            timeout: Duration::from_secs(2),
            username: None,
            password: None,
        }),
    };
    let proxy: Arc<dyn AsyncProxy> = Arc::new(BlockingStreamProxy { connector });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(yuhaiin_core::proxy::StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy,
        bypass: Arc::clone(&drop),
        drop,
    });
    let mut runtime = TunProxyRuntime::new(selector, 8)
        .unwrap()
        .with_io_timeout(Duration::from_secs(2))
        .unwrap();

    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 16).unwrap();
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
            .push(IpCidr::new(IpAddress::Ipv4(target_ip), 32))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(4096, 4096, 4).unwrap();
    let source_port = 41000;
    let initial_sequence = 100;
    device
        .enqueue_rx(tcp_syn_packet(
            remote,
            target_ip,
            source_port,
            target_address.port(),
            initial_sequence,
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 1).unwrap();
    let syn_ack = device.take_tx().unwrap().expect("TUN SYN-ACK");
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let proxy_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;
    assert!(dispatcher.events().next().is_none());

    device
        .enqueue_rx(tcp_data_packet(
            remote,
            target_ip,
            source_port,
            target_address.port(),
            initial_sequence + 1,
            proxy_sequence + 1,
            &[],
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 2).unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        runtime.handle_event(event).unwrap();
    }

    let request = b"request";
    device
        .enqueue_rx(tcp_data_packet(
            remote,
            target_ip,
            source_port,
            target_address.port(),
            initial_sequence + 1,
            proxy_sequence + 1,
            request,
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 3).unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        runtime.handle_event(event).unwrap();
    }

    let mut response = None;
    for tick in 4..250 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        while let Some(packet) = device.take_tx().unwrap() {
            let is_response = {
                let ip = Ipv4Packet::new_checked(&packet).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                tcp.payload() == request
            };
            if is_response {
                response = Some(packet);
                break;
            }
        }
        if response.is_some() {
            break;
        }
    }
    runtime.close();
    fixture.join().unwrap();

    let response = response.expect("stream proxy did not return TCP data to TUN");
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.src_addr(), target_ip);
    assert_eq!(tcp.src_port(), target_address.port());
    assert_eq!(tcp.dst_port(), source_port);
    assert_eq!(tcp.payload(), request);
}

#[tokio::test(flavor = "current_thread")]
async fn http_connect_proxy_runs_through_tun_tcp_runtime() {
    run_stream_proxy_tun(StreamProxyKind::Http).await;
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_proxy_runs_through_tun_tcp_runtime() {
    run_stream_proxy_tun(StreamProxyKind::Socks5).await;
}

fn spawn_target_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).unwrap();
        stream.write_all(&payload).unwrap();
    });
    (address, task)
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_async_proxy_runs_through_tun_tcp_runtime() {
    let (target_address, target_task) = spawn_target_echo();
    let target_ip = match target_address.ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => panic!("fixed fixture unexpectedly used IPv6"),
    };
    let fixed: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address: target_address,
        timeout: Duration::from_secs(2),
    });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy: fixed,
        bypass: Arc::clone(&drop),
        drop,
    });
    let mut runtime = TunProxyRuntime::new(selector, 8).unwrap();
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 16).unwrap();
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
            .push(IpCidr::new(IpAddress::Ipv4(target_ip), 32))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(4096, 4096, 4).unwrap();
    device
        .enqueue_rx(tcp_syn_packet(
            remote,
            target_ip,
            41002,
            target_address.port(),
            100,
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 1).unwrap();
    let syn_ack = device.take_tx().unwrap().unwrap();
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let server_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;
    device
        .enqueue_rx(tcp_data_packet(
            remote,
            target_ip,
            41002,
            target_address.port(),
            101,
            server_sequence + 1,
            &[],
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 2).unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        runtime.handle_event(event).unwrap();
    }
    let request = b"fixed-p";
    device
        .enqueue_rx(tcp_data_packet(
            remote,
            target_ip,
            41002,
            target_address.port(),
            101,
            server_sequence + 1,
            request,
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 3).unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        runtime.handle_event(event).unwrap();
    }
    let mut response = None;
    for tick in 4..250 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        while let Some(packet) = device.take_tx().unwrap() {
            let ip = Ipv4Packet::new_checked(&packet).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.payload() == request {
                response = Some(packet);
                break;
            }
        }
        if response.is_some() {
            break;
        }
    }
    runtime.close();
    target_task.join().unwrap();
    let response = response.expect("fixed proxy did not return TCP data to TUN");
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    assert_eq!(ip.src_addr(), target_ip);
    assert_eq!(
        TcpPacket::new_checked(ip.payload()).unwrap().payload(),
        request
    );
}

#[tokio::test(flavor = "current_thread")]
async fn drop_proxy_closes_established_tun_tcp_flow() {
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy: Arc::clone(&drop),
        bypass: Arc::clone(&drop),
        drop: Arc::clone(&drop),
    });
    let mut runtime = TunProxyRuntime::new(selector, 8).unwrap();
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let destination = Ipv4Address::new(192, 0, 2, 4);
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
    let mut dispatcher = TunDispatcher::new(2048, 2048, 2).unwrap();
    device
        .enqueue_rx(tcp_syn_packet(remote, destination, 41004, 443, 100))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 1).unwrap();
    let syn_ack = device.take_tx().unwrap().unwrap();
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let server_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;
    device
        .enqueue_rx(tcp_data_packet(
            remote,
            destination,
            41004,
            443,
            101,
            server_sequence + 1,
            &[],
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 2).unwrap();
    for event in dispatcher.events().collect::<Vec<_>>() {
        runtime.handle_event(event).unwrap();
    }
    for tick in 3..50 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
    }
    assert_eq!(runtime.task_len(), 0);
    runtime.close();
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_half_close_forwards_eof_and_close_releases_task() {
    let saw_eof = Arc::new(AtomicBool::new(false));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(DuplexProxy {
        saw_eof: Arc::clone(&saw_eof),
    });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy,
        bypass: Arc::clone(&drop),
        drop,
    });
    let mut runtime = TunProxyRuntime::new(selector, 8)
        .unwrap()
        .with_io_timeout(Duration::from_secs(1))
        .unwrap();
    let flow = yuhaiin_core::tun::TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "192.0.2.1:443".parse().unwrap(),
        },
    };
    runtime.handle_event(TunEvent::TcpOpened { flow }).unwrap();
    runtime
        .handle_event(TunEvent::TcpData {
            flow,
            payload: b"request".to_vec(),
        })
        .unwrap();
    runtime
        .handle_event(TunEvent::TcpHalfClosed { flow })
        .unwrap();

    for _ in 0..50 {
        if saw_eof.load(Ordering::Acquire) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        saw_eof.load(Ordering::Acquire),
        "half-close did not reach proxy"
    );
    assert_eq!(runtime.task_len(), 1);
    runtime.close();
    assert_eq!(runtime.task_len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_connect_timeout_drops_pending_future_and_task() {
    let dropped = Arc::new(AtomicBool::new(false));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(PendingProxy {
        dropped: Arc::clone(&dropped),
    });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy,
        bypass: Arc::clone(&drop),
        drop,
    });
    let mut runtime = TunProxyRuntime::new(selector, 8)
        .unwrap()
        .with_io_timeout(Duration::from_millis(10))
        .unwrap();
    let flow = yuhaiin_core::tun::TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:41001".parse().unwrap(),
            destination: "192.0.2.2:443".parse().unwrap(),
        },
    };
    runtime.handle_event(TunEvent::TcpOpened { flow }).unwrap();
    let mut dispatcher = TunDispatcher::new(1024, 1024, 2).unwrap();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(2)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        if runtime.task_len() == 0 {
            break;
        }
    }
    assert!(
        dropped.load(Ordering::Acquire),
        "timeout did not drop connect future"
    );
    assert_eq!(runtime.task_len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_proxy_runtime_aborts_owned_flow_tasks() {
    let dropped = Arc::new(AtomicBool::new(false));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(PendingProxy {
        dropped: Arc::clone(&dropped),
    });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy,
        bypass: Arc::clone(&drop),
        drop,
    });
    {
        let mut runtime = TunProxyRuntime::new(selector, 8).unwrap();
        let flow = yuhaiin_core::tun::TunFlow {
            key: TunFlowKey {
                network: Network::Tcp,
                source: "10.0.0.2:41003".parse().unwrap(),
                destination: "192.0.2.3:443".parse().unwrap(),
            },
        };
        runtime.handle_event(TunEvent::TcpOpened { flow }).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(runtime.task_len(), 1);
    }
    tokio::task::yield_now().await;
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test(flavor = "current_thread")]
async fn dns_fakeip_reverse_lookup_router_and_proxy_form_one_udp_flow() {
    let store = ConfigStore::open_memory().await.unwrap();
    let pool = Arc::new(
        FakeIpPool::open(
            store,
            FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 8)).unwrap(),
        )
        .await
        .unwrap(),
    );
    let dns_handler: Arc<dyn AsyncDnsHandler> = Arc::new(FakeIpAsyncDnsHandler {
        upstream: Resolver,
        transform: FakeIpAnswerTransform {
            pool: Arc::clone(&pool),
        },
    });

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sent_targets = Arc::new(Mutex::new(Vec::new()));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(RecordingProxy {
        contexts: Arc::clone(&recorded),
        sent_targets: Arc::clone(&sent_targets),
    });
    let drop: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
    let mut fake_ip_rule = route_rule("198.18.0.0/15");
    fake_ip_rule.port = Some((443, 444));
    let fallback = RouteDecision {
        mode: RouteMode::Block,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let router = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
    let selector = RuntimeRoutedProxySelector {
        router: router.clone(),
        direct: Arc::clone(&drop),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&drop),
        drop,
    };
    let mut runtime = TunProxyRuntime::new(Arc::new(selector), 8)
        .unwrap()
        .with_async_dns_handler(Arc::clone(&dns_handler));

    let local = Ipv4Address::new(10, 0, 0, 1);
    let application = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 16).unwrap();
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
    let mut dispatcher = TunDispatcher::new(2048, 2048, 8).unwrap();

    let query = encode_query(
        7,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::A,
    )
    .unwrap();
    device
        .enqueue_rx(udp_packet(application, local, 41000, 53, &query))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 1).unwrap();
    let dns_event = dispatcher.events().next().expect("DNS event");
    runtime.handle_event_async(dns_event).await.unwrap();
    let mut dns_response = None;
    for tick in 2..100 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        if device.queued_tx().unwrap() > 0 {
            dns_response =
                Some(decode_response(&take_udp_payload(&device), 7, DnsRecordType::A).unwrap());
            break;
        }
    }
    let dns_response = dns_response.expect("DNS resolver did not return a response to TUN");
    let fake_ip = dns_response.addresses.v4[0];
    assert_eq!(fake_ip, Ipv4Addr::new(198, 18, 0, 1));
    let view = pool.snapshot().await;
    assert_eq!(view.lookup_domain(fake_ip).unwrap().as_str(), "example.com");
    // The route is published after the selector/runtime has already been
    // installed.  This models a config reload between DNS answer and the
    // first FakeIP flow: new flows must see the proxy rule, while any flow
    // that had already selected a proxy keeps its own session.
    router
        .compile_and_publish(vec![fake_ip_rule], fallback)
        .unwrap();
    let second_domain = DomainName::new("second.example.com").unwrap();
    let second_domain_for_context = second_domain.clone();
    runtime.set_context_provider(move |flow| {
        let mut context = flow.context();
        if let std::net::IpAddr::V4(address) = flow.key.destination.ip() {
            context.original_domain = view.lookup_domain(address);
            if flow.key.destination.port() == 444 {
                context.original_domain = Some(second_domain_for_context.clone());
            }
        }
        context
    });

    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(fake_ip), 32))
            .unwrap();
    });
    let payload = b"through-router";
    let destination = fake_ip;
    device
        .enqueue_rx(udp_packet(application, destination, 41001, 443, payload))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 3).unwrap();
    let event = dispatcher.events().next().expect("FakeIP UDP event");
    let flow = match event {
        TunEvent::UdpDatagram { flow, .. } => flow,
        other => panic!("unexpected event: {other:?}"),
    };
    assert_eq!(
        flow.key,
        TunFlowKey {
            network: Network::Udp,
            source: SocketAddr::new(application.into(), 41001),
            destination: SocketAddr::new(destination.into(), 443),
        }
    );
    runtime
        .handle_event(TunEvent::UdpDatagram {
            flow: yuhaiin_core::tun::TunFlow { key: flow.key },
            payload: payload.to_vec(),
        })
        .unwrap();
    let mut echoed = None;
    for tick in 4..100 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        if device.queued_tx().unwrap() > 0 {
            echoed = Some(take_udp_payload(&device));
            break;
        }
    }
    let echoed = echoed.expect("router proxy did not return UDP data to TUN");
    assert_eq!(echoed, payload);

    device
        .enqueue_rx(udp_packet(
            application,
            destination,
            41001,
            444,
            b"through-second-domain",
        ))
        .unwrap();
    poll(&mut dispatcher, &mut interface, &mut device, 5).unwrap();
    let second_event = dispatcher.events().next().expect("second FakeIP UDP event");
    runtime
        .handle_event(second_event)
        .expect("second FakeIP flow should share the source task");
    let mut second_echoed = None;
    for tick in 6..100 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        runtime.poll_outputs(&mut dispatcher).unwrap();
        poll(&mut dispatcher, &mut interface, &mut device, tick).unwrap();
        if device.queued_tx().unwrap() > 0 {
            second_echoed = Some(take_udp_payload(&device));
            break;
        }
    }
    assert_eq!(
        second_echoed.expect("shared router proxy did not return UDP data to TUN"),
        b"through-second-domain"
    );

    let contexts = recorded.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(
        contexts[0].original_domain.as_ref().unwrap().as_str(),
        "example.com"
    );
    assert_eq!(
        contexts[0].destination,
        Endpoint::ip(Network::Udp, SocketAddr::new(destination.into(), 443))
    );
    assert_eq!(
        sent_targets.lock().unwrap().as_slice(),
        &[
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443,),
            Endpoint::domain(Network::Udp, second_domain, 444)
        ]
    );
}
