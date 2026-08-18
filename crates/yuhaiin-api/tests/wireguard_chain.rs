//! Process-level inbound -> router -> WireGuard outbound coverage.
//!
//! The WireGuard peer in this test is a deterministic userspace BoringTun
//! endpoint. It owns a smoltcp TCP listener on the virtual address
//! `192.0.2.1`, so the test exercises the same route, proxy construction,
//! Noise handshake, encrypted packet path, and runtime statistics that a
//! third-party peer would use without requiring credentials or host network
//! capabilities.

mod support;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde_json::json;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata,
    Socket as SmoltcpUdpSocket,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use support::{
    ServiceProcess, add_socks5_inbound, api_json, connect_loopback, integration_dir,
    seed_empty_database, wait_for_connection,
};

const RUNTIME_PRIVATE_KEY: [u8; 32] = [41; 32];
const PEER_PRIVATE_KEY: [u8; 32] = [42; 32];
const PEER_ADDRESS: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
const PEER_TUNNEL_ADDRESS: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const PEER_TCP_PORT: u16 = 18_080;
const PEER_HEALTH_PORT: u16 = 18_081;
const PEER_UDP_PORT: u16 = 18_082;
const MTU: usize = 1_420;

struct WireGuardPeer {
    endpoint: SocketAddr,
    public_key: [u8; 32],
    stats: Arc<PeerStats>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct PeerStats {
    underlay_packets: AtomicUsize,
    tunnel_packets: AtomicUsize,
    device_packets: AtomicUsize,
    tcp_reads: AtomicUsize,
    tcp_writes: AtomicUsize,
    udp_reads: AtomicUsize,
    udp_writes: AtomicUsize,
    crypto_errors: AtomicUsize,
    network_responses: AtomicUsize,
    trace: Mutex<Vec<String>>,
}

impl PeerStats {
    fn record(&self, packet: &[u8], direction: &str) {
        self.trace
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(packet_summary(packet, direction));
    }
}

impl WireGuardPeer {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = socket.local_addr().unwrap();
        let private = StaticSecret::from(PEER_PRIVATE_KEY);
        let public_key = *PublicKey::from(&private).as_bytes();
        let (shutdown, receiver) = watch::channel(false);
        let stats = Arc::new(PeerStats::default());
        let task = tokio::spawn(run_peer(socket, private, receiver, Arc::clone(&stats)));
        Self {
            endpoint,
            public_key,
            stats,
            shutdown,
            task,
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

async fn run_peer(
    socket: UdpSocket,
    private: StaticSecret,
    mut shutdown: watch::Receiver<bool>,
    stats: Arc<PeerStats>,
) {
    let runtime_public = *PublicKey::from(&StaticSecret::from(RUNTIME_PRIVATE_KEY)).as_bytes();
    let mut tunnel = Tunn::new(
        private,
        PublicKey::from(runtime_public),
        None,
        None,
        2,
        None,
    );
    let mut device = yuhaiin_tun::SmoltcpTunDevice::new(MTU, 256).unwrap();
    let mut interface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(PEER_TUNNEL_ADDRESS), 32))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(PEER_ADDRESS), 32))
            .unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let listener = sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 64 * 1024]),
        TcpSocketBuffer::new(vec![0; 64 * 1024]),
    ));
    sockets
        .get_mut::<TcpSocket>(listener)
        .listen(PEER_TCP_PORT)
        .unwrap();
    let health_listener = sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 64 * 1024]),
        TcpSocketBuffer::new(vec![0; 64 * 1024]),
    ));
    sockets
        .get_mut::<TcpSocket>(health_listener)
        .listen(PEER_HEALTH_PORT)
        .unwrap();
    let udp_listener = sockets.add(SmoltcpUdpSocket::new(
        UdpPacketBuffer::new(vec![UdpPacketMetadata::EMPTY; 16], vec![0; 64 * 1024]),
        UdpPacketBuffer::new(vec![UdpPacketMetadata::EMPTY; 16], vec![0; 64 * 1024]),
    ));
    sockets
        .get_mut::<SmoltcpUdpSocket>(udp_listener)
        .bind(PEER_UDP_PORT)
        .unwrap();

    let mut underlay_buffer = vec![0_u8; 65_535 + 2_048];
    let mut crypto_buffer = vec![0_u8; 65_535 + 2_048];
    let mut source = None;
    let mut pending_http = Vec::new();
    let mut pending_health = Vec::new();

    loop {
        if *shutdown.borrow() {
            return;
        }

        interface.poll(
            Instant::from_millis(current_millis()),
            &mut device,
            &mut sockets,
        );
        echo_tcp_socket(&mut sockets, listener, &mut pending_http, &stats);
        echo_tcp_socket(&mut sockets, health_listener, &mut pending_health, &stats);
        echo_udp_socket(&mut sockets, udp_listener, &stats);
        interface.poll(
            Instant::from_millis(current_millis()),
            &mut device,
            &mut sockets,
        );
        flush_device_packets(
            &device,
            &mut tunnel,
            source,
            &socket,
            &mut crypto_buffer,
            &stats,
        )
        .await;

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            received = socket.recv_from(&mut underlay_buffer) => {
                let Ok((length, peer)) = received else { return };
                stats.underlay_packets.fetch_add(1, Ordering::Relaxed);
                source = Some(peer);
                process_wireguard_packet(
                    &mut tunnel,
                    &device,
                    peer,
                    &underlay_buffer[..length],
                    &mut crypto_buffer,
                    &socket,
                    &stats,
                ).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(2)) => {
                if let (Some(peer), TunnResult::WriteToNetwork(bytes)) =
                    (source, tunnel.update_timers(&mut crypto_buffer))
                {
                    socket.send_to(bytes, peer).await.unwrap();
                }
            }
        }
    }
}

fn echo_tcp_socket(
    sockets: &mut SocketSet<'_>,
    handle: smoltcp::iface::SocketHandle,
    pending_http: &mut Vec<u8>,
    stats: &PeerStats,
) {
    let socket = sockets.get_mut::<TcpSocket>(handle);
    if socket.can_recv() {
        let mut data = [0_u8; 16 * 1024];
        if let Ok(length) = socket.recv_slice(&mut data) {
            stats.tcp_reads.fetch_add(1, Ordering::Relaxed);
            pending_http.extend_from_slice(&data[..length]);
            if pending_http.starts_with(b"GET /health") {
                if pending_http.windows(4).any(|window| window == b"\r\n\r\n") {
                    if socket
                        .send_slice(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .is_ok()
                    {
                        stats.tcp_writes.fetch_add(1, Ordering::Relaxed);
                    }
                    pending_http.clear();
                }
            } else if !pending_http.is_empty() {
                let data = std::mem::take(pending_http);
                if socket.send_slice(&data).is_ok() {
                    stats.tcp_writes.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn echo_udp_socket(
    sockets: &mut SocketSet<'_>,
    handle: smoltcp::iface::SocketHandle,
    stats: &PeerStats,
) {
    let socket = sockets.get_mut::<SmoltcpUdpSocket>(handle);
    if !socket.can_recv() {
        return;
    }
    let Ok((payload, endpoint)) = socket.recv() else {
        return;
    };
    let payload = payload.to_vec();
    stats.udp_reads.fetch_add(1, Ordering::Relaxed);
    if socket.send_slice(&payload, endpoint).is_ok() {
        stats.udp_writes.fetch_add(1, Ordering::Relaxed);
    }
}

fn packet_summary(packet: &[u8], direction: &str) -> String {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return format!("{direction}: non-ip len={}", packet.len());
    };
    if ip.next_header() != IpProtocol::Tcp {
        return format!(
            "{direction}: ip proto={:?} len={}",
            ip.next_header(),
            packet.len()
        );
    }
    let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
        return format!("{direction}: malformed-tcp len={}", packet.len());
    };
    format!(
        "{direction}: {}:{} -> {}:{} syn={} ack={} fin={} rst={} payload={}",
        ip.src_addr(),
        tcp.src_port(),
        ip.dst_addr(),
        tcp.dst_port(),
        tcp.syn(),
        tcp.ack(),
        tcp.fin(),
        tcp.rst(),
        tcp.payload().len()
    )
}

async fn flush_device_packets(
    device: &yuhaiin_tun::SmoltcpTunDevice,
    tunnel: &mut Tunn,
    source: Option<SocketAddr>,
    socket: &UdpSocket,
    output: &mut [u8],
    stats: &PeerStats,
) {
    let Some(source) = source else { return };
    while let Ok(Some(packet)) = device.take_tx() {
        let TunnResult::WriteToNetwork(bytes) = tunnel.encapsulate(&packet, output) else {
            continue;
        };
        stats.device_packets.fetch_add(1, Ordering::Relaxed);
        stats.record(&packet, "device");
        socket.send_to(bytes, source).await.unwrap();
    }
}

async fn process_wireguard_packet(
    tunnel: &mut Tunn,
    device: &yuhaiin_tun::SmoltcpTunDevice,
    source: SocketAddr,
    packet: &[u8],
    output: &mut [u8],
    socket: &UdpSocket,
    stats: &PeerStats,
) {
    let result = tunnel.decapsulate(Some(source.ip()), packet, output);
    match result {
        TunnResult::WriteToNetwork(bytes) => {
            stats.network_responses.fetch_add(1, Ordering::Relaxed);
            socket.send_to(bytes, source).await.unwrap();
        }
        TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
            stats.tunnel_packets.fetch_add(1, Ordering::Relaxed);
            stats.record(bytes, "tunnel");
            let _ = device.enqueue_rx(bytes.to_vec());
            while let TunnResult::WriteToNetwork(bytes) =
                tunnel.decapsulate(Some(source.ip()), &[], output)
            {
                stats.network_responses.fetch_add(1, Ordering::Relaxed);
                socket.send_to(bytes, source).await.unwrap();
            }
        }
        TunnResult::Done => {}
        TunnResult::Err(_) => {
            stats.crypto_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn key(value: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

async fn configure_wireguard_network_split_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    peer: &WireGuardPeer,
) {
    configure_wireguard_network_split_node_and_route(service, peer).await;

    let inbound_config = json!({
        "id":"wireguard-network-split-in",
        "name":"WireGuard network split inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound_config),
    )
    .await;
}

async fn configure_wireguard_node_and_route(service: &ServiceProcess, peer: &WireGuardPeer) {
    configure_wireguard_node_and_route_with_network_split(service, peer, false).await;
}

async fn configure_wireguard_network_split_node_and_route(
    service: &ServiceProcess,
    peer: &WireGuardPeer,
) {
    configure_wireguard_node_and_route_with_network_split(service, peer, true).await;
}

async fn configure_wireguard_node_and_route_with_network_split(
    service: &ServiceProcess,
    peer: &WireGuardPeer,
    network_split: bool,
) {
    let wireguard = json!({
        "secretKey":key(RUNTIME_PRIVATE_KEY),
        "endpoint":["10.0.0.2/32"],
        "mtu":1420,
        "peers":[{
            "publicKey":key(peer.public_key),
            "endpoint":peer.endpoint.to_string(),
            "allowedIps":["0.0.0.0/0"]
        }]
    });
    let chain = if network_split {
        json!([
            {
                "type":"fixedv2",
                "fixedv2":{
                    "addresses":[{
                        "host":peer.endpoint.ip().to_string(),
                        "port":peer.endpoint.port()
                    }]
                }
            },
            {
                "type":"network_split",
                "network_split":{
                    "tcp":{"type":"wireguard","wireguard":wireguard.clone()},
                    "udp":{"type":"wireguard","wireguard":wireguard}
                }
            }
        ])
    } else {
        json!([{"type":"wireguard","wireguard":wireguard}])
    };
    let node = json!({
        "id":"wireguard-runtime-out",
        "name":"WireGuard runtime outbound",
        "group":"integration",
        "enabled":true,
        "chain":chain
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/wireguard-runtime-out/use",
        None,
    )
    .await;

    let route = json!({
        "name":"wireguard-cidr-route",
        "mode":"proxy",
        "match":{"cidr":"192.0.2.1/32"},
        "tag":"wireguard-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&route),
    )
    .await;
}

async fn configure_wireguard_udp_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    peer: &WireGuardPeer,
) {
    configure_wireguard_node_and_route(service, peer).await;
    add_socks5_inbound(service, "wireguard-runtime-udp-in", inbound, "", "").await;
}

async fn configure_wireguard_network_split_udp_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    peer: &WireGuardPeer,
) {
    configure_wireguard_network_split_node_and_route(service, peer).await;
    add_socks5_inbound(service, "wireguard-network-split-udp-in", inbound, "", "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_wireguard_userspace_outbound() {
    let peer = WireGuardPeer::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-wireguard-chain");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_wireguard_network_split_chain(&service, inbound, &peer).await;

    let mut client = connect_loopback(inbound).await;
    client
        .write_all(
            format!(
                "CONNECT 192.0.2.1:{PEER_TCP_PORT} HTTP/1.1\r\nHost: 192.0.2.1:{PEER_TCP_PORT}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = match client.read(&mut buffer).await {
            Ok(length) => length,
            Err(error) => {
                let logs = api_json(
                    &service.client,
                    &service.base_url,
                    reqwest::Method::POST,
                    "/api/v2/rpc/tools.logs",
                    Some(&json!({})),
                )
                .await;
                panic!(
                    "HTTP inbound reset before WireGuard response: {error}; logs={logs}; stderr={}",
                    service.diagnostics()
                );
            }
        };
        if length == 0 {
            let logs = api_json(
                &service.client,
                &service.base_url,
                reqwest::Method::POST,
                "/api/v2/rpc/tools.logs",
                Some(&json!({})),
            )
            .await;
            panic!(
                "HTTP inbound closed before WireGuard response; logs={logs}; stderr={}",
                service.diagnostics()
            );
        }
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let payload = b"wireguard-runtime-chain-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = Vec::new();
    let read_result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut data = [0_u8; 1024];
        loop {
            let length = client.read(&mut data).await?;
            if length == 0 {
                break Ok::<_, std::io::Error>(());
            }
            echoed.extend_from_slice(&data[..length]);
            if echoed.len() >= payload.len() {
                break Ok(());
            }
        }
    })
    .await
    .unwrap();
    if let Err(error) = read_result {
        let logs = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::POST,
            "/api/v2/rpc/tools.logs",
            Some(&json!({})),
        )
        .await;
        let connections = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        panic!(
            "WireGuard runtime payload did not echo: {error}; received={echoed:?}; peer underlay={} tunnel={} device={} tcp_reads={} tcp_writes={} crypto_errors={} network_responses={}; trace={:?}; connections={connections}; logs={logs}; stderr={}",
            peer.stats.underlay_packets.load(Ordering::Relaxed),
            peer.stats.tunnel_packets.load(Ordering::Relaxed),
            peer.stats.device_packets.load(Ordering::Relaxed),
            peer.stats.tcp_reads.load(Ordering::Relaxed),
            peer.stats.tcp_writes.load(Ordering::Relaxed),
            peer.stats.crypto_errors.load(Ordering::Relaxed),
            peer.stats.network_responses.load(Ordering::Relaxed),
            peer.stats
                .trace
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            service.diagnostics()
        );
    }
    if echoed != payload {
        let connections = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let logs = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::POST,
            "/api/v2/rpc/tools.logs",
            Some(&json!({})),
        )
        .await;
        let runtime_diagnostics = service.force_stop_with_diagnostics().await;
        panic!(
            "WireGuard runtime payload mismatch; received={echoed:?}; peer underlay={} tunnel={} device={} tcp_reads={} tcp_writes={} crypto_errors={} network_responses={}; trace={:?}; connections={connections}; logs={logs}; stderr={}",
            peer.stats.underlay_packets.load(Ordering::Relaxed),
            peer.stats.tunnel_packets.load(Ordering::Relaxed),
            peer.stats.device_packets.load(Ordering::Relaxed),
            peer.stats.tcp_reads.load(Ordering::Relaxed),
            peer.stats.tcp_writes.load(Ordering::Relaxed),
            peer.stats.crypto_errors.load(Ordering::Relaxed),
            peer.stats.network_responses.load(Ordering::Relaxed),
            peer.stats
                .trace
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            runtime_diagnostics
        );
    }

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "WireGuard network split inbound")
        .expect("WireGuard network split chain connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["nodeId"], "wireguard-runtime-out");
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "wireguard-cidr-route")
    }));

    let latency = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/wireguard-runtime-out/latency",
        Some(&json!({
            "type":"http",
            "url":format!("http://192.0.2.1:{PEER_HEALTH_PORT}/health"),
            "timeoutMs":5000
        })),
    )
    .await;
    assert_eq!(latency["ok"], true, "WireGuard latency failed: {latency}");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_inbound_routes_through_wireguard_userspace_outbound() {
    let peer = WireGuardPeer::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-wireguard-udp-chain");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_wireguard_udp_chain(&service, inbound, &peer).await;

    let mut control = connect_loopback(inbound).await;
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut bind_reply = [0_u8; 10];
    control.read_exact(&mut bind_reply).await.unwrap();
    assert_eq!(&bind_reply[..4], &[5, 0, 0, 1]);
    let relay_address = SocketAddr::new(
        std::net::Ipv4Addr::new(bind_reply[4], bind_reply[5], bind_reply[6], bind_reply[7]).into(),
        u16::from_be_bytes([bind_reply[8], bind_reply[9]]),
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"wireguard-runtime-udp-payload";
    let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 1];
    packet.extend_from_slice(&PEER_UDP_PORT.to_be_bytes());
    packet.extend_from_slice(payload);
    client.send_to(&packet, relay_address).await.unwrap();

    let mut response = [0_u8; 2048];
    let received =
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response)).await;
    let (length, source) = match received {
        Ok(Ok(value)) => value,
        other => {
            let connections = api_json(
                &service.client,
                &service.base_url,
                reqwest::Method::GET,
                "/api/v2/connections",
                None,
            )
            .await;
            let logs = api_json(
                &service.client,
                &service.base_url,
                reqwest::Method::POST,
                "/api/v2/rpc/tools.logs",
                Some(&json!({})),
            )
            .await;
            panic!(
                "WireGuard runtime UDP response missing: result={other:?}; peer underlay={} tunnel={} device={} udp_reads={} udp_writes={} crypto_errors={} network_responses={}; trace={:?}; connections={connections}; logs={logs}; stderr={}",
                peer.stats.underlay_packets.load(Ordering::Relaxed),
                peer.stats.tunnel_packets.load(Ordering::Relaxed),
                peer.stats.device_packets.load(Ordering::Relaxed),
                peer.stats.udp_reads.load(Ordering::Relaxed),
                peer.stats.udp_writes.load(Ordering::Relaxed),
                peer.stats.crypto_errors.load(Ordering::Relaxed),
                peer.stats.network_responses.load(Ordering::Relaxed),
                peer.stats
                    .trace
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
                service.diagnostics()
            );
        }
    };
    assert_eq!(source, relay_address);
    assert!(length >= 10);
    assert_eq!(&response[..10], &packet[..10]);
    assert_eq!(&response[10..length], payload);
    assert!(peer.stats.udp_reads.load(Ordering::Relaxed) > 0);
    assert!(peer.stats.udp_writes.load(Ordering::Relaxed) > 0);

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["inboundName"] == "SOCKS5 integration inbound"
                && item["nodeId"] == "wireguard-runtime-out"
        })
        .expect("WireGuard runtime UDP connection must be visible");
    assert_eq!(item["nodeId"], "wireguard-runtime-out");
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "wireguard-cidr-route")
    }));

    let total = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert!(total["download"].is_string());
    assert!(total["upload"].is_string());

    control.shutdown().await.unwrap();
    service.shutdown().await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_inbound_routes_through_wireguard_network_split_branch() {
    let peer = WireGuardPeer::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-wireguard-network-split-udp-chain");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_wireguard_network_split_udp_chain(&service, inbound, &peer).await;

    let mut control = connect_loopback(inbound).await;
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut bind_reply = [0_u8; 10];
    control.read_exact(&mut bind_reply).await.unwrap();
    assert_eq!(&bind_reply[..4], &[5, 0, 0, 1]);
    let relay_address = SocketAddr::new(
        std::net::Ipv4Addr::new(bind_reply[4], bind_reply[5], bind_reply[6], bind_reply[7]).into(),
        u16::from_be_bytes([bind_reply[8], bind_reply[9]]),
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"wireguard-network-split-udp-payload";
    let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 1];
    packet.extend_from_slice(&PEER_UDP_PORT.to_be_bytes());
    packet.extend_from_slice(payload);
    client.send_to(&packet, relay_address).await.unwrap();

    let mut response = [0_u8; 2048];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, relay_address);
    assert!(length >= 10);
    assert_eq!(&response[..10], &packet[..10]);
    assert_eq!(&response[10..length], payload);
    assert!(peer.stats.udp_reads.load(Ordering::Relaxed) > 0);
    assert!(peer.stats.udp_writes.load(Ordering::Relaxed) > 0);

    control.shutdown().await.unwrap();
    service.shutdown().await;
    peer.shutdown().await;
}
