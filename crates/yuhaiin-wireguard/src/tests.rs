use super::config::*;
use super::driver::*;
use super::engine::*;
use super::proxy::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use crate::DEFAULT_MTU;
use base64::{Engine, engine::general_purpose::STANDARD};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::mpsc;
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::network::DEFAULT_INTERFACE;
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, ErrorKind, FlowContext, IpSet, Network, ResolveStrategy,
    Result,
};

struct FixedResolver;

impl AsyncIpResolver for FixedResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        assert_eq!(domain.as_str(), "peer.invalid");
        Box::pin(async {
            Ok(IpSet {
                v4: vec![std::net::Ipv4Addr::LOCALHOST],
                v6: Vec::new(),
            })
        })
    }
}

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

#[test]
fn parses_go_wireguard_config() {
    let config = WireGuardConfig {
        secret_key: key(1),
        endpoint: vec!["10.0.0.2/32".to_owned()],
        peers: vec![WireGuardPeerConfig {
            public_key: key(2),
            pre_shared_key: String::new(),
            endpoint: "127.0.0.1:51820".to_owned(),
            keep_alive: 25,
            allowed_ips: vec!["0.0.0.0/0".to_owned()],
        }],
        mtu: 1_420,
        reserved: vec![0, 0, 0],
    };
    let parsed = futures_lite::future::block_on(async {
        let peer = config.peers[0]
            .parse(Duration::from_secs(1), None)
            .await
            .unwrap();
        config.parse(vec![peer]).unwrap()
    });
    assert_eq!(parsed.local_addresses.len(), 1);
    assert_eq!(parsed.peers[0].allowed_ips[0].prefix_len(), 0);
    assert_eq!(parsed.peers[0].keep_alive, Some(25));

    let json = serde_json::json!({
        "secretKey": key(1),
        "endpoint": ["10.0.0.2/32"],
        "reserved": "AAAA",
        "peers": [{
            "publicKey": key(2),
            "endpoint": "127.0.0.1:51820",
            "allowedIps": ["0.0.0.0/0"]
        }]
    });
    let json_bytes = serde_json::to_vec(&json).unwrap();
    let decoded = WireGuardConfig::from_json_or_ini(&json_bytes).unwrap();
    assert_eq!(decoded.reserved, vec![0, 0, 0]);
}

#[test]
fn parses_cloudflare_warp_wireguard_ini() {
    let config = WireGuardConfig::from_json_or_ini(
        br#"
                [Interface]
                PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                Address = 172.16.0.2/32, 2606:4700:110:8765:1111:2222:3333:4444/128
                DNS = 1.1.1.1
                MTU = 1280
                Reserved = 1, 2, 3

                [Peer]
                PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
                AllowedIPs = 0.0.0.0/0, ::/0
                Endpoint = engage.cloudflareclient.com:2408
                PersistentKeepalive = 25
            "#,
    )
    .unwrap();

    assert_eq!(config.endpoint.len(), 2);
    assert_eq!(config.mtu, 1_280);
    assert_eq!(config.reserved, vec![1, 2, 3]);
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].allowed_ips, ["0.0.0.0/0", "::/0"]);
    assert_eq!(config.peers[0].keep_alive, 25);
    assert_eq!(config.peers[0].endpoint, "engage.cloudflareclient.com:2408");
}

#[test]
fn rejects_incomplete_wireguard_ini() {
    let error = WireGuardConfig::from_wireguard_ini(
        "[Interface]\nPrivateKey = invalid\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = invalid\n",
    )
    .unwrap_err();
    assert!(
        error
            .message
            .contains("missing PublicKey, Endpoint, or AllowedIPs")
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn wireguard_underlay_applies_linux_network_interface() {
    let socket = bind_udp_underlay("0.0.0.0:0", Some("lo")).await.unwrap();
    assert_eq!(
        socket.local_addr().unwrap().ip(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn dynamic_interface_does_not_exclude_loopback_wireguard_peers() {
    let peer = ParsedPeer {
        endpoint: "127.0.0.1:51820".parse().unwrap(),
        allowed_ips: Vec::new(),
        public_key: [0; 32],
        pre_shared_key: None,
        keep_alive: None,
    };
    let peers = [peer];
    assert_eq!(
        underlay_interface_for_peers(Some(DEFAULT_INTERFACE), &peers),
        None
    );
    assert_eq!(underlay_interface_for_peers(Some("lo"), &peers), Some("lo"));
}

#[test]
fn rejects_non_32_byte_keys() {
    let error = decode_key("AQ==", "secretKey").unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidInput);
}

#[tokio::test(flavor = "current_thread")]
async fn peer_endpoint_uses_injected_runtime_resolver() {
    let peer = WireGuardPeerConfig {
        public_key: key(2),
        pre_shared_key: String::new(),
        endpoint: "peer.invalid:51820".to_owned(),
        keep_alive: 0,
        allowed_ips: vec!["0.0.0.0/0".to_owned()],
    };
    let parsed = peer
        .parse(Duration::from_secs(1), Some(&FixedResolver))
        .await
        .unwrap();
    assert_eq!(parsed.endpoint, "127.0.0.1:51820".parse().unwrap());
}

#[test]
fn boringtun_round_trip_is_authenticated() {
    let first_private = StaticSecret::from([3; 32]);
    let second_private = StaticSecret::from([4; 32]);
    let first_public = PublicKey::from(&first_private);
    let second_public = PublicKey::from(&second_private);
    let mut first = Tunn::new(first_private, second_public, None, None, 1, None);
    let mut second = Tunn::new(second_private, first_public, None, None, 2, None);
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
    ];
    let mut first_out = vec![0; 2_048];
    let handshake = first.encapsulate(&packet, &mut first_out);
    let handshake = match handshake {
        TunnResult::WriteToNetwork(value) => value.to_vec(),
        other => panic!("unexpected {other:?}"),
    };
    let mut second_out = vec![0; 2_048];
    let response = second.decapsulate(
        Some("127.0.0.1".parse().unwrap()),
        &handshake,
        &mut second_out,
    );
    let response = match response {
        TunnResult::WriteToNetwork(value) => value.to_vec(),
        other => panic!("unexpected {other:?}"),
    };
    let mut first_out2 = vec![0; 2_048];
    let keepalive = first.decapsulate(
        Some("127.0.0.1".parse().unwrap()),
        &response,
        &mut first_out2,
    );
    assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

    let data = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
    ];
    let mut data_out = vec![0; 2_048];
    let encrypted = first.encapsulate(&data, &mut data_out);
    let encrypted = match encrypted {
        TunnResult::WriteToNetwork(value) => value.to_vec(),
        other => panic!("unexpected {other:?}"),
    };
    let mut plain_out = vec![0; 2_048];
    let plain = second.decapsulate(
        Some("127.0.0.1".parse().unwrap()),
        &encrypted,
        &mut plain_out,
    );
    match plain {
        TunnResult::WriteToTunnelV4(value, source) => {
            assert_eq!(value, data);
            assert_eq!(source, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn allowed_ips_use_the_longest_prefix_match() {
    let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
    let broad_peer = ParsedPeer {
        endpoint: "127.0.0.1:51820".parse().unwrap(),
        allowed_ips: vec![all_v4],
        public_key: *PublicKey::from(&StaticSecret::from([12; 32])).as_bytes(),
        pre_shared_key: None,
        keep_alive: None,
    };
    let specific_peer = ParsedPeer {
        endpoint: "127.0.0.1:51821".parse().unwrap(),
        allowed_ips: vec![parse_cidr("10.23.0.0/16").unwrap()],
        public_key: *PublicKey::from(&StaticSecret::from([13; 32])).as_bytes(),
        pre_shared_key: None,
        keep_alive: None,
    };
    let engine = WireGuardEngine::new(
        ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
            peers: vec![broad_peer, specific_peer],
            mtu: DEFAULT_MTU,
            reserved: Vec::new(),
        },
        [11; 32],
    );

    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    let packet_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 23, 4, 5]);
    assert_eq!(engine.peer_for_packet(&packet).unwrap(), 1);

    packet[16..20].copy_from_slice(&[192, 0, 2, 5]);
    assert_eq!(engine.peer_for_packet(&packet).unwrap(), 0);
}

#[test]
fn persistent_keepalive_is_emitted_by_the_engine() {
    let first_private = [14; 32];
    let second_private = [15; 32];
    let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
    let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
    let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
    let make_config =
        |endpoint: &str, public_key: [u8; 32], keep_alive: Option<u16>| ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
            peers: vec![ParsedPeer {
                endpoint: endpoint.parse().unwrap(),
                allowed_ips: vec![all_v4],
                public_key,
                pre_shared_key: None,
                keep_alive,
            }],
            mtu: DEFAULT_MTU,
            reserved: Vec::new(),
        };
    let mut first = WireGuardEngine::new(
        make_config("127.0.0.1:51820", second_public, Some(1)),
        first_private,
    );
    let mut second = WireGuardEngine::new(
        make_config("127.0.0.1:51821", first_public, None),
        second_private,
    );
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
    ];
    let (_, handshake) = first.encapsulate(&packet).unwrap();
    let response = match second.decapsulate(0, source, &handshake).unwrap() {
        DecapsulatedPacket::Network(packet) => packet,
        other => panic!("expected handshake response, got {other:?}"),
    };
    let acknowledgement = match first.decapsulate(0, source, &response).unwrap() {
        DecapsulatedPacket::Network(packet) => packet,
        other => panic!("expected handshake acknowledgement, got {other:?}"),
    };
    assert!(matches!(
        second.decapsulate(0, source, &acknowledgement).unwrap(),
        DecapsulatedPacket::Done
    ));

    std::thread::sleep(Duration::from_millis(1_100));
    let keepalive = first.update_timers();
    assert_eq!(keepalive.len(), 1);
    assert!(matches!(
        second.decapsulate(0, source, &keepalive[0].1).unwrap(),
        DecapsulatedPacket::Done
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn userspace_proxy_crosses_two_local_wireguard_peers() {
    use tokio::io::AsyncReadExt;

    let first_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_endpoint = first_socket.local_addr().unwrap();
    let second_endpoint = second_socket.local_addr().unwrap();
    let first_private = [5; 32];
    let second_private = [6; 32];
    let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
    let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
    let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
    let first_config = ParsedConfig {
        local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
        peers: vec![ParsedPeer {
            endpoint: second_endpoint,
            allowed_ips: vec![all_v4],
            public_key: second_public,
            pre_shared_key: None,
            keep_alive: None,
        }],
        mtu: DEFAULT_MTU,
        reserved: Vec::new(),
    };
    let second_config = ParsedConfig {
        local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32)],
        peers: vec![ParsedPeer {
            endpoint: first_endpoint,
            allowed_ips: vec![all_v4],
            public_key: first_public,
            pre_shared_key: None,
            keep_alive: None,
        }],
        mtu: DEFAULT_MTU,
        reserved: Vec::new(),
    };
    let (first_tx, first_rx) = mpsc::channel(64);
    let (second_tx, second_rx) = mpsc::channel(64);
    let first_closed = Arc::new(AtomicBool::new(false));
    let second_closed = Arc::new(AtomicBool::new(false));
    let first_task = tokio::spawn(
        Driver::new(
            first_config,
            first_private,
            first_socket,
            first_rx,
            Arc::clone(&first_closed),
        )
        .run(None),
    );
    let second_task = tokio::spawn(
        Driver::new(
            second_config,
            second_private,
            second_socket,
            second_rx,
            Arc::clone(&second_closed),
        )
        .run(None),
    );

    let proxy = WireGuardProxy {
        command_tx: first_tx.clone(),
        closed: Arc::clone(&first_closed),
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:80".parse().unwrap()));
    let mut stream = proxy.connect(&context).await.unwrap();
    let mut buffer = [0; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result, 0,
        "a peer without a listener must close the TCP stream"
    );

    let first_datagram = proxy
        .open_datagram(&FlowContext::new(Endpoint::ip(
            Network::Udp,
            "192.0.2.1:53".parse().unwrap(),
        )))
        .await
        .unwrap();
    let second_proxy = WireGuardProxy {
        command_tx: second_tx.clone(),
        closed: Arc::clone(&second_closed),
    };
    let second_datagram = second_proxy
        .open_datagram(&FlowContext::new(Endpoint::ip(
            Network::Udp,
            "192.0.2.2:53".parse().unwrap(),
        )))
        .await
        .unwrap();
    let second_target = second_datagram.local_addr().unwrap();
    let payload: Vec<u8> = (0..8 * 1024).map(|offset| (offset % 251) as u8).collect();
    assert_eq!(
        first_datagram
            .send_to(&payload, second_target)
            .await
            .unwrap(),
        payload.len()
    );
    let mut received = vec![0; payload.len()];
    let (length, first_target) = tokio::time::timeout(
        Duration::from_secs(2),
        second_datagram.recv_from(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&received[..length], payload);
    assert_eq!(first_target.network(), Network::Udp);
    assert_eq!(
        second_datagram
            .send_to(&received[..length], first_target)
            .await
            .unwrap(),
        payload.len()
    );
    let (length, second_target) = tokio::time::timeout(
        Duration::from_secs(2),
        first_datagram.recv_from(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&received[..length], payload);
    assert_eq!(second_target.network(), Network::Udp);
    first_datagram.close().await.unwrap();
    second_datagram.close().await.unwrap();

    first_closed.store(true, Ordering::Release);
    second_closed.store(true, Ordering::Release);
    let _ = first_tx.send(DriverCommand::Close).await;
    let _ = second_tx.send(DriverCommand::Close).await;
    let _ = first_task.await;
    let _ = second_task.await;
}

#[test]
fn reserved_bytes_are_stripped_before_boringtun_decode() {
    let first_private = [7; 32];
    let second_private = [8; 32];
    let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
    let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
    let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
    let mut first = WireGuardEngine::new(
        ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
            peers: vec![ParsedPeer {
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                allowed_ips: vec![all_v4],
                public_key: second_public,
                pre_shared_key: None,
                keep_alive: None,
            }],
            mtu: DEFAULT_MTU,
            reserved: vec![1, 2, 3],
        },
        first_private,
    );
    let mut second = WireGuardEngine::new(
        ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32)],
            peers: vec![ParsedPeer {
                endpoint: "127.0.0.1:51821".parse().unwrap(),
                allowed_ips: vec![all_v4],
                public_key: first_public,
                pre_shared_key: None,
                keep_alive: None,
            }],
            mtu: DEFAULT_MTU,
            reserved: vec![1, 2, 3],
        },
        second_private,
    );
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
    ];
    let (_, handshake) = first.encapsulate(&packet).unwrap();
    assert_eq!(&handshake[1..4], &[1, 2, 3]);
    let roaming_source: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let response = match second.decapsulate(0, roaming_source, &handshake).unwrap() {
        DecapsulatedPacket::Network(response) => response,
        _ => panic!("expected handshake response"),
    };
    assert_eq!(second.peers[0].endpoint, roaming_source);
    let response_source: SocketAddr = "127.0.0.1:40002".parse().unwrap();
    let _ = first.decapsulate(0, response_source, &response).unwrap();
    assert_eq!(first.peers[0].endpoint, response_source);
}

#[test]
#[ignore = "opt-in packet encryption benchmark; run scripts/benchmark/wireguard.sh"]
fn wireguard_packet_throughput_benchmark() {
    use std::time::Instant;

    let bytes = std::env::var("YUHAIIN_WIREGUARD_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(64 * 1024 * 1024);
    let first_private = [9; 32];
    let second_private = [10; 32];
    let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
    let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
    let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
    let config = |endpoint: SocketAddr, public_key: [u8; 32], reserved: Vec<u8>| ParsedConfig {
        local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
        peers: vec![ParsedPeer {
            endpoint,
            allowed_ips: vec![all_v4],
            public_key,
            pre_shared_key: None,
            keep_alive: None,
        }],
        mtu: DEFAULT_MTU,
        reserved,
    };
    let source: SocketAddr = "127.0.0.1:40000"
        .parse()
        .expect("benchmark source must include a UDP port");
    let mut first = WireGuardEngine::new(
        config(
            "127.0.0.1:51820".parse().unwrap(),
            second_public,
            vec![1, 2, 3],
        ),
        first_private,
    );
    let mut second = WireGuardEngine::new(
        config(
            "127.0.0.1:51821".parse().unwrap(),
            first_public,
            vec![1, 2, 3],
        ),
        second_private,
    );
    let handshake_packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
    ];
    let (_, handshake) = first.encapsulate(&handshake_packet).unwrap();
    let response = match second.decapsulate(0, source, &handshake).unwrap() {
        DecapsulatedPacket::Network(packet) => packet,
        other => panic!("expected handshake response, got {other:?}"),
    };
    let _ = first.decapsulate(0, source, &response).unwrap();

    let payload_size = 1_400;
    let mut packet = vec![0; 20 + payload_size];
    packet[0] = 0x45;
    let packet_length = packet.len() as u16;
    packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);

    let read_rss_kib = || {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:")
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u64>().ok())
                })
            })
    };
    let read_cpu_ticks = || {
        std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|stat| {
                let (_, fields) = stat.rsplit_once(") ")?;
                let mut fields = fields.split_whitespace();
                let user = fields.nth(11)?.parse::<u64>().ok()?;
                let system = fields.next()?.parse::<u64>().ok()?;
                Some(user.saturating_add(system))
            })
    };
    let mut peak_rss_kib = None;
    let mut proc_samples = 0u64;
    let mut sample_usage = || {
        let rss_kib = read_rss_kib();
        if let Some(rss_kib) = rss_kib {
            peak_rss_kib = Some(peak_rss_kib.unwrap_or(0).max(rss_kib));
        }
        let cpu_ticks = read_cpu_ticks();
        if rss_kib.is_some() || cpu_ticks.is_some() {
            proc_samples += 1;
        }
        cpu_ticks
    };
    let cpu_start = sample_usage();
    let started = Instant::now();
    let mut transferred = 0usize;
    while transferred < bytes {
        let length = (bytes - transferred).min(payload_size);
        packet.truncate(20 + length);
        let packet_length = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        let (_, encrypted) = first.encapsulate(&packet).unwrap();
        match second.decapsulate(0, source, &encrypted).unwrap() {
            DecapsulatedPacket::Tunnel(received) => assert_eq!(received, packet),
            other => panic!("expected tunnel packet, got {other:?}"),
        }
        transferred += length;
        packet.resize(20 + payload_size, 0);
        if transferred % (payload_size * 256) < length || transferred == bytes {
            let _ = sample_usage();
        }
    }
    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    let cpu_end = sample_usage();
    let cpu_ticks = cpu_start
        .zip(cpu_end)
        .map(|(start, end)| end.saturating_sub(start));
    println!(
        "BENCHMARK {}",
        serde_json::json!({
            "scenario": "wireguard-boringtun-packet",
            "bytes": bytes,
            "seconds": seconds,
            "mib_per_sec": bytes as f64 / seconds / (1024.0 * 1024.0),
            "peak_rss_kib": peak_rss_kib,
            "cpu_ticks": cpu_ticks,
            "proc_samples": proc_samples,
        })
    );
}
