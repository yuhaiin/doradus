//! Cross-language VLESS v0 stream check against a small Go wire server.

#![cfg(unix)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use doradus_core::proxy::AsyncProxy;
use doradus_core::{DomainName, Endpoint, FlowContext, Network};
use doradus_protocol::proxy::FixedAsyncProxy;
use doradus_protocol::vless::{self, VlessProxy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
mod support;

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn rust_vless_client_round_trips_against_go_server() {
    let go_root = std::env::var_os("DORADUS_GO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/home/asutorufa/Documents/Programming/doradus")
        });
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/vless_go_server.go");
    let cache_root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".cache"))
        .join("doradus/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let ready = cache_root.join(format!("vless-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let address = "127.0.0.1:24445";

    let mut child = Command::new("go")
        .arg("run")
        .arg(helper)
        .current_dir(&go_root)
        .env("GOEXPERIMENT", "jsonv2,greenteagc")
        .env("GOTMPDIR", &cache_root)
        .env("VLESS_LISTEN", address)
        .env("VLESS_READY", &ready)
        .spawn()
        .expect("start Go VLESS server");

    for _ in 0..250 {
        if ready.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Go VLESS server exited before ready: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready.exists(), "Go VLESS server did not become ready");

    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address: address.parse().unwrap(),
        timeout: Duration::from_secs(2),
    });
    let proxy = VlessProxy::new(parent, "00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let destination = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let context = FlowContext::new(destination);
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    drop(stream);

    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success(), "Go VLESS server failed: {status}");
    let _ = std::fs::remove_file(ready);
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vless_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_vless_wire(&mut stream).await;
    });

    run_go_vless_client(address, None).await;
    server.await.unwrap();
}

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vless_client_over_tls_websocket_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let websocket = support::accept_tls_websocket(stream).await;
        let mut stream = doradus_protocol::websocket::WebSocketIo::new(websocket);
        serve_vless_wire(&mut stream).await;
    });

    run_go_vless_client(address, Some("tls-websocket")).await;
    server.await.unwrap();
}

async fn serve_vless_wire<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = vless::read_request(
        stream,
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
    )
    .await
    .unwrap();
    assert_eq!(request.command, vless::Command::Tcp);
    assert_eq!(
        request.destination,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    );
    vless::write_response(stream, &[]).await.unwrap();
    let mut payload = [0u8; 4];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ping");
    stream.write_all(b"pong").await.unwrap();
}

async fn run_go_vless_client(address: std::net::SocketAddr, transport: Option<&str>) {
    let go_root = std::env::var_os("DORADUS_GO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/home/asutorufa/Documents/Programming/doradus")
        });
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/vless_go_client.go");
    let cache_root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".cache"))
        .join("doradus/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let listen = address.to_string();
    let transport = transport.map(str::to_owned);
    let output = tokio::task::spawn_blocking(move || {
        let mut command = Command::new("go");
        command
            .arg("run")
            .arg(helper)
            .current_dir(&go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("VLESS_LISTEN", listen);
        if let Some(transport) = transport {
            command.env("VLESS_TRANSPORT", transport);
        }
        command.output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go VLESS client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
