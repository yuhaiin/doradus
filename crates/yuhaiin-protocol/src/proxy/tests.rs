//! Proxy primitive tests.

use super::datagrams::socks_address;
use super::drop::DelayedDropState;
use super::*;
#[cfg(target_os = "linux")]
use yuhaiin_core::network::{default_route_interface_v4, default_route_interface_v6};
use yuhaiin_core::stream_metadata::stream_local_addr;
use yuhaiin_core::{DomainName, Network};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn endpoint() -> Endpoint {
    Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
}

#[test]
fn delayed_drop_escalates_per_destination() {
    let state = DelayedDropState::default();
    let destination = Endpoint::domain(
        Network::Tcp,
        DomainName::new("blocked.example").unwrap(),
        443,
    );
    assert_eq!(state.next_delay(&destination), Duration::ZERO);
    assert_eq!(state.next_delay(&destination), Duration::from_secs(1));
    assert_eq!(state.next_delay(&destination), Duration::from_secs(2));
    assert_eq!(state.next_delay(&destination), Duration::from_secs(4));
}

#[tokio::test(flavor = "current_thread")]
async fn local_stream_metadata_survives_async_io_delegation() {
    let (mut peer, stream) = tokio::io::duplex(64);
    let local = "127.0.0.1:24568".parse().unwrap();
    let mut stream = with_stream_local_addr(Box::new(stream), Some(local));
    assert_eq!(stream_local_addr(&*stream), Some(local));

    peer.write_all(b"ping").await.unwrap();
    let mut buffer = [0; 4];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"ping");
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_async_proxy_routes_datagrams_to_fixed_endpoint() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixed = server.local_addr().unwrap();
    let proxy = FixedAsyncProxy {
        address: fixed,
        timeout: Duration::from_secs(1),
    };
    let logical_target = Endpoint::ip(Network::Udp, "127.0.0.1:9".parse().unwrap());
    let context = FlowContext::new(logical_target.clone());
    let datagram = proxy.open_datagram(&context).await.unwrap();

    let payload = b"fixed-udp";
    assert_eq!(
        datagram.send_to(payload, logical_target).await.unwrap(),
        payload.len()
    );

    let mut buffer = [0u8; 64];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..length], payload);
    server.send_to(b"fixed-reply", peer).await.unwrap();

    let (length, source) =
        tokio::time::timeout(Duration::from_secs(1), datagram.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..length], b"fixed-reply");
    assert_eq!(source, Endpoint::ip(Network::Udp, fixed));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn fixed_async_proxy_applies_linux_network_interface_to_udp() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixed = server.local_addr().unwrap();
    let proxy = FixedAsyncProxy {
        address: fixed,
        timeout: Duration::from_secs(1),
    };
    let mut context = FlowContext::new(Endpoint::ip(Network::Udp, fixed));
    context.bind_interface = Some("lo".to_owned());
    let datagram = proxy.open_datagram(&context).await.unwrap();
    datagram
        .send_to(b"interface-udp", Endpoint::ip(Network::Udp, fixed))
        .await
        .unwrap();

    let mut buffer = [0u8; 64];
    let (length, _) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"interface-udp");
}

#[cfg(target_os = "linux")]
#[test]
fn default_route_parser_skips_virtual_interfaces() {
    let routes = r#"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
tun0 00000000 00000000 0001 0 0 0 00000000 0 0 0
wg0 00000000 00000000 0001 0 0 0 00000000 0 0 0
enp0s5 00000000 0100370A 0001 0 0 100 00000000 0 0 0"#;
    assert_eq!(
        default_route_interface_v4(routes).as_deref(),
        Some("enp0s5")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn default_ipv6_route_parser_skips_virtual_interfaces() {
    let routes = r#"00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000 00000000 00000000 tun0
00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000 00000000 00000000 enp0s5"#;
    assert_eq!(
        default_route_interface_v6(routes).as_deref(),
        Some("enp0s5")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn direct_async_proxy_resolves_domain_when_called_without_runtime_wrapper() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 13];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    });

    let context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    let proxy = DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    };
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"direct-domain").await.unwrap();
    assert_eq!(server.await.unwrap(), *b"direct-domain");
}

#[tokio::test(flavor = "current_thread")]
async fn direct_async_datagram_resolves_domain_targets_on_send() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut payload = [0u8; 64];
        let (length, peer) = server.recv_from(&mut payload).await.unwrap();
        server.send_to(&payload[..length], peer).await.unwrap();
        payload[..length].to_vec()
    });

    let mut context = FlowContext::new(Endpoint::domain(
        Network::Udp,
        DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    context
        .local_bind_addresses
        .push("127.0.0.1".parse().unwrap());
    let proxy = DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    };
    let datagram = proxy.open_datagram(&context).await.unwrap();
    let target = Endpoint::domain(
        Network::Udp,
        DomainName::new("localhost").unwrap(),
        address.port(),
    );
    datagram
        .send_to(b"direct-udp-domain", target)
        .await
        .unwrap();
    let mut response = [0u8; 64];
    let (length, _) = datagram.recv_from(&mut response).await.unwrap();
    assert_eq!(&response[..length], b"direct-udp-domain");
    assert_eq!(server_task.await.unwrap(), b"direct-udp-domain");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn direct_async_proxy_pings_loopback_with_icmp() {
    let proxy = DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:0".parse().unwrap()));
    let elapsed = proxy.ping(&context).await.unwrap();
    assert!(elapsed >= Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn direct_async_proxy_pings_ipv6_loopback_with_icmp() {
    let proxy = DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, "[::1]:0".parse().unwrap()));
    let elapsed = proxy.ping(&context).await.unwrap();
    assert!(elapsed >= Duration::ZERO);
}

#[test]
fn socks_address_encodes_domain_and_ip() {
    assert_eq!(socks_address(&endpoint()).unwrap().0, 3);
    let ip = Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap());
    assert_eq!(socks_address(&ip).unwrap(), (1, vec![192, 0, 2, 1]));
}

#[tokio::test(flavor = "current_thread")]
async fn native_socks5_udp_associate_round_trips_authenticated_domain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_address = relay.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();

        let mut greeting = [0u8; 4];
        control.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        control.write_all(&[5, 2]).await.unwrap();

        let mut auth = [0u8; 1];
        control.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth[0], 1);
        let mut username_length = [0u8; 1];
        control.read_exact(&mut username_length).await.unwrap();
        let mut username = vec![0u8; usize::from(username_length[0])];
        control.read_exact(&mut username).await.unwrap();
        let mut password_length = [0u8; 1];
        control.read_exact(&mut password_length).await.unwrap();
        let mut password = vec![0u8; usize::from(password_length[0])];
        control.read_exact(&mut password).await.unwrap();
        assert_eq!(username, b"user");
        assert_eq!(password, b"pass");
        control.write_all(&[1, 0]).await.unwrap();

        let mut request = [0u8; 10];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[5, 3, 0, 1]);
        control
            .write_all(&[
                5,
                0,
                0,
                1,
                127,
                0,
                0,
                1,
                relay_address.port().to_be_bytes()[0],
                relay_address.port().to_be_bytes()[1],
            ])
            .await
            .unwrap();

        let mut packet = [0u8; 2048];
        let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
        assert!(length >= 12);
        assert_eq!(&packet[..4], &[0, 0, 0, 3]);
        let host_length = usize::from(packet[4]);
        let host_end = 5 + host_length;
        assert_eq!(&packet[5..host_end], b"example.com");
        let port = u16::from_be_bytes([packet[host_end], packet[host_end + 1]]);
        assert_eq!(port, 53);
        assert_eq!(&packet[host_end + 2..length], b"ping");

        let mut response = vec![0, 0, 0, 3, 11];
        response.extend_from_slice(b"example.com");
        response.extend_from_slice(&53u16.to_be_bytes());
        response.extend_from_slice(b"pong");
        relay.send_to(&response, peer).await.unwrap();

        let mut closed = [0u8; 1];
        let _ = control.read(&mut closed).await;
    });

    let proxy = Socks5AsyncProxy {
        proxy: proxy_address,
        timeout: Duration::from_secs(1),
        username: Some("user".to_owned()),
        password: Some("pass".to_owned()),
    };
    let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
    let mut context = FlowContext::new(target.clone());
    context
        .local_bind_addresses
        .push("127.0.0.2".parse().unwrap());
    let datagram = proxy.open_datagram(&context).await.unwrap();
    assert_eq!(
        datagram.local_addr().unwrap().addr().unwrap().ip(),
        "127.0.0.2".parse::<IpAddr>().unwrap()
    );
    assert_eq!(datagram.send_to(b"ping", target.clone()).await.unwrap(), 4);

    let mut buffer = [0u8; 64];
    let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"pong");
    assert_eq!(response_target, target);
    datagram.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
