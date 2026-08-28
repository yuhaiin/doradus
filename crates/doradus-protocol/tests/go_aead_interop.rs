//! Go/Rust interoperability checks for the custom Go `aead` transport.
//!
//! These tests are ignored in normal workspace runs because they start the
//! sibling Go checkout. All Go build scratch state stays under the user cache.

#![cfg(unix)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use doradus_core::proxy::AsyncProxy;
use doradus_core::{Endpoint, FlowContext, Network};
use doradus_protocol::aead::{self, AeadProxy, CryptoMethod};
use doradus_protocol::proxy::FixedAsyncProxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

fn go_cache() -> std::path::PathBuf {
    std::env::var_os("DORADUS_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".cache"))
        .join("doradus/go-tmp")
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_aead_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = aead::server(Box::new(stream), b"secret", CryptoMethod::XChacha20Poly1305)
            .await
            .unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let cache_root = go_cache();
    std::fs::create_dir_all(&cache_root).unwrap();
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/aead_go_client.go");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .arg("run")
            .arg(helper)
            .current_dir("/home/asutorufa/Documents/Programming/doradus")
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("AEAD_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go AEAD client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn rust_aead_client_round_trips_against_go_wire_server() {
    let cache_root = go_cache();
    std::fs::create_dir_all(&cache_root).unwrap();
    let ready = cache_root.join(format!("aead-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let address = "127.0.0.1:24447";
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/aead_go_server.go");
    let mut child = Command::new("go")
        .arg("run")
        .arg(helper)
        .current_dir("/home/asutorufa/Documents/Programming/doradus")
        .env("GOEXPERIMENT", "jsonv2,greenteagc")
        .env("GOTMPDIR", &cache_root)
        .env("AEAD_LISTEN", address)
        .env("AEAD_READY", &ready)
        .spawn()
        .expect("start Go AEAD server");
    for _ in 0..250 {
        if ready.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Go AEAD server exited before ready: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready.exists(), "Go AEAD server did not become ready");

    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address: address.parse().unwrap(),
        timeout: Duration::from_secs(2),
    });
    let proxy = AeadProxy::new(
        parent,
        b"secret",
        CryptoMethod::XChacha20Poly1305,
        Some(address.parse().unwrap()),
    );
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    drop(stream);

    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success(), "Go AEAD server failed: {status}");
    let _ = std::fs::remove_file(ready);
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_aead_client_packet_conn_round_trips_against_rust_udp_server() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut packet = [0u8; 64 * 1024];
        let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
        let request = aead::decrypt_packet(
            &packet[..length],
            b"secret",
            CryptoMethod::XChacha20Poly1305,
        )
        .unwrap();
        assert_eq!(request, b"ping");
        let response =
            aead::encrypt_packet(b"pong", b"secret", CryptoMethod::XChacha20Poly1305).unwrap();
        socket.send_to(&response, peer).await.unwrap();
    });

    let cache_root = go_cache();
    std::fs::create_dir_all(&cache_root).unwrap();
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/aead_go_client.go");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .arg("run")
            .arg(helper)
            .current_dir("/home/asutorufa/Documents/Programming/doradus")
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("AEAD_MODE", "udp")
            .env("AEAD_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go AEAD UDP client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn rust_aead_packet_conn_round_trips_against_go_udp_server() {
    let cache_root = go_cache();
    std::fs::create_dir_all(&cache_root).unwrap();
    let ready = cache_root.join(format!("aead-udp-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/aead_go_server.go");
    let mut child = Command::new("go")
        .arg("run")
        .arg(helper)
        .current_dir("/home/asutorufa/Documents/Programming/doradus")
        .env("GOEXPERIMENT", "jsonv2,greenteagc")
        .env("GOTMPDIR", &cache_root)
        .env("AEAD_MODE", "udp")
        .env("AEAD_LISTEN", "127.0.0.1:0")
        .env("AEAD_READY", &ready)
        .spawn()
        .expect("start Go AEAD UDP server");
    for _ in 0..250 {
        if ready.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Go AEAD UDP server exited before ready: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready.exists(), "Go AEAD UDP server did not become ready");
    let address: std::net::SocketAddr = std::fs::read_to_string(&ready).unwrap().parse().unwrap();

    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address,
        timeout: Duration::from_secs(2),
    });
    let proxy = AeadProxy::new(
        parent,
        b"secret",
        CryptoMethod::XChacha20Poly1305,
        Some(address),
    );
    let context = FlowContext::new(Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap()));
    let datagram = proxy.open_datagram(&context).await.unwrap();
    datagram
        .send_to(
            b"ping",
            Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap()),
        )
        .await
        .unwrap();
    let mut response = [0u8; 64];
    let (length, _) = datagram.recv_from(&mut response).await.unwrap();
    assert_eq!(&response[..length], b"pong");
    datagram.close().await.unwrap();

    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success(), "Go AEAD UDP server failed: {status}");
    let _ = std::fs::remove_file(ready);
}
