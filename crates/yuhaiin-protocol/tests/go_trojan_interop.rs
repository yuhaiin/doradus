//! Real Go client interoperability smoke for the Trojan wire contract.
//!
//! This is intentionally ignored: it needs the sibling Go checkout and a Go
//! toolchain.  It never uses `/tmp`; Go's build scratch directory is placed
//! under the user's cache as required by the migration workflow.

use std::process::Command;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use yuhaiin_core::{DomainName, Endpoint, Network};
use yuhaiin_protocol::trojan::{self, Command as TrojanCommand};

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
mod support;

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_trojan_client_connects_to_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_trojan_wire(&mut stream).await;
    });

    run_go_trojan_client(address, None).await;
    server.await.unwrap();
}

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_trojan_client_over_tls_websocket_connects_to_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let websocket = support::accept_tls_websocket(stream).await;
        let mut stream = yuhaiin_protocol::websocket::WebSocketIo::new(websocket);
        serve_trojan_wire(&mut stream).await;
    });

    run_go_trojan_client(address, Some("tls-websocket")).await;
    server.await.unwrap();
}

async fn serve_trojan_wire<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = trojan::password_hash(b"secret");
    let request = trojan::read_request(stream, &hash).await.unwrap();
    assert_eq!(request.command, TrojanCommand::Connect);
    assert_eq!(
        request.destination,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    );
    let mut payload = [0u8; 4];
    stream.read_exact(&mut payload).await.unwrap();
    stream.write_all(b"pong").await.unwrap();
}

async fn run_go_trojan_client(address: std::net::SocketAddr, transport: Option<&str>) {
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin")
        });
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/trojan_go_client.go");
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/home/asutorufa/.cache"))
        .join("yuhaiin-rust/go-tmp");
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
            .env("TROJAN_LISTEN", listen);
        if let Some(transport) = transport {
            command.env("TROJAN_TRANSPORT", transport);
        }
        command.output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go Trojan client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
