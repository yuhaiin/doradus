use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use doradus_core::proxy::AsyncProxy;
use doradus_core::{Endpoint, FlowContext, Network};
use doradus_openvpn::{OpenVpnConfig, build_proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn profile_path() -> Option<String> {
    std::env::var("DORADUS_OPENVPN_E2E_PROFILE").ok()
}

async fn test_proxy() -> doradus_openvpn::OpenVpnProxy {
    let path = profile_path().expect("DORADUS_OPENVPN_E2E_PROFILE must be set");
    let profile = std::fs::read_to_string(Path::new(&path)).expect("read OpenVPN test profile");
    build_proxy(
        OpenVpnConfig {
            profile,
            username: None,
            password: None,
        },
        Duration::from_secs(15),
    )
    .await
    .expect("connect OpenVPN test tunnel")
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the local Podman OpenVPN integration server"]
async fn podman_tcp_round_trip() {
    let proxy = test_proxy().await;
    let target = Endpoint::ip(
        Network::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 88, 0, 1)), 18_080),
    );
    let context = FlowContext::new(target);
    let mut stream = tokio::time::timeout(Duration::from_secs(10), proxy.connect(&context))
        .await
        .expect("OpenVPN TCP connect timed out")
        .expect("OpenVPN TCP connect failed");

    let payload = b"doradus-openvpn-tcp";
    stream.write_all(payload).await.expect("write TCP payload");
    let mut response = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut response))
        .await
        .expect("OpenVPN TCP response timed out")
        .expect("read TCP response");
    assert_eq!(response, payload);

    proxy.close().await.expect("close OpenVPN proxy");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the local Podman OpenVPN integration server"]
async fn podman_udp_round_trip() {
    let proxy = test_proxy().await;
    let target = Endpoint::ip(
        Network::Udp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 88, 0, 1)), 18_081),
    );
    let context = FlowContext::new(target.clone());
    let datagram = tokio::time::timeout(Duration::from_secs(10), proxy.open_datagram(&context))
        .await
        .expect("OpenVPN UDP open timed out")
        .expect("OpenVPN UDP open failed");

    let payload = b"doradus-openvpn-udp";
    datagram
        .send_to(payload, target)
        .await
        .expect("send UDP payload");
    let mut response = vec![0; 65_535];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(10), datagram.recv_from(&mut response))
            .await
            .expect("OpenVPN UDP response timed out")
            .expect("receive UDP response");
    assert_eq!(&response[..length], payload);

    datagram.close().await.expect("close OpenVPN datagram");
    proxy.close().await.expect("close OpenVPN proxy");
}
