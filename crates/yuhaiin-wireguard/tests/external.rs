use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_wireguard::{WireGuardConfig, build_proxy};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the external smoke"))
}

fn parse_target(raw: &str, network: Network) -> Result<Endpoint> {
    if let Ok(address) = raw.parse::<SocketAddr>() {
        return Ok(Endpoint::ip(network, address));
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| Error::invalid("external target is missing an IPv6 port"))?;
        (host, port)
    } else {
        raw.rsplit_once(':')
            .ok_or_else(|| Error::invalid("external target must be host:port"))?
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::invalid("external target port is invalid"))?;
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(network, SocketAddr::new(address, port)));
    }
    Ok(Endpoint::domain(network, DomainName::new(host)?, port))
}

async fn external_proxy() -> Result<yuhaiin_wireguard::WireGuardProxy> {
    let config_path = required_env("YUHAIIN_WIREGUARD_EXTERNAL_CONFIG");
    let config_bytes = std::fs::read(Path::new(&config_path))
        .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
    let config = WireGuardConfig::from_json_or_ini(&config_bytes)
        .map_err(|error| Error::invalid(format!("invalid external WireGuard config: {error}")))?;
    build_proxy(config, Duration::from_secs(15)).await
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a user-supplied third-party/WARP WireGuard config and network target"]
async fn external_peer_tcp_connects() {
    let target_raw = match std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET") {
        Ok(target) => target,
        Err(_) => {
            eprintln!("skipping external TCP smoke: target is not configured");
            return;
        }
    };
    let proxy = external_proxy().await.unwrap();
    let target = parse_target(&target_raw, Network::Tcp).unwrap();
    let context = FlowContext::new(target);
    let mut stream = tokio::time::timeout(Duration::from_secs(20), proxy.connect(&context))
        .await
        .unwrap()
        .unwrap();
    if let Ok(request) = std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_TCP_REQUEST") {
        stream.write_all(request.as_bytes()).await.unwrap();
    }
    if let Ok(expected) = std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_TCP_EXPECT") {
        let mut response = vec![0; expected.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected.as_bytes());
    }
    proxy.close().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a user-supplied third-party/WARP WireGuard config and network target"]
async fn external_peer_udp_round_trips() {
    let target_raw = match std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET") {
        Ok(target) => target,
        Err(_) => {
            eprintln!("skipping external UDP smoke: target is not configured");
            return;
        }
    };
    let proxy = external_proxy().await.unwrap();
    let target = parse_target(&target_raw, Network::Udp).unwrap();
    let context = FlowContext::new(target.clone());
    let datagram = tokio::time::timeout(Duration::from_secs(20), proxy.open_datagram(&context))
        .await
        .unwrap()
        .unwrap();
    let payload = std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_UDP_PAYLOAD_HEX")
        .map(|value| {
            hex::decode(value).unwrap_or_else(|error| panic!("invalid UDP payload hex: {error}"))
        })
        .unwrap_or_else(|_| {
            base64::engine::general_purpose::STANDARD
                .decode("EjQBAAABAAAAAAAAA3dpcmUHY29uZmlnAABAAQ==")
                .unwrap()
        });
    datagram.send_to(&payload, target).await.unwrap();
    let expect_reply = std::env::var("YUHAIIN_WIREGUARD_EXTERNAL_UDP_EXPECT_REPLY")
        .map(|value| value != "0")
        .unwrap_or(true);
    if expect_reply {
        let mut buffer = vec![0; 65_535];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(20), datagram.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert!(length > 0, "external WireGuard UDP response was empty");
    }
    datagram.close().await.unwrap();
    proxy.close().await.unwrap();
}
