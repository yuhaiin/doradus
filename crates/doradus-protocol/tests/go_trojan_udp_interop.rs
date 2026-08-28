//! Cross-language Trojan UDP packet framing check against the real Go client.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use doradus_core::{DomainName, Endpoint, Network};
use doradus_protocol::trojan::{self, Command as TrojanCommand};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_trojan_udp_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_trojan_udp_wire(&mut stream).await;
    });

    run_go_trojan_udp_client(address).await;
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("Rust Trojan UDP server did not close")
        .unwrap();
}

async fn serve_trojan_udp_wire<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = trojan::password_hash(b"secret");
    let request = trojan::read_request(stream, &hash).await.unwrap();
    assert_eq!(request.command, TrojanCommand::Associate);
    assert_eq!(
        request.destination,
        Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53)
    );

    let mut payload = [0u8; 64];
    let (length, destination) = trojan::read_udp_frame(stream, &mut payload).await.unwrap();
    assert_eq!(
        destination,
        Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53)
    );
    assert_eq!(&payload[..length], b"go-trojan-udp");
    trojan::write_udp_frame(stream, &destination, &payload[..length])
        .await
        .unwrap();
}

async fn run_go_trojan_udp_client(address: std::net::SocketAddr) {
    let go_root = std::env::var_os("DORADUS_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/doradus"));
    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/trojan_udp_go_client.go");
    let cache_root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("doradus/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args(["run", helper.to_str().unwrap()])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("TROJAN_UDP_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "Go Trojan UDP client failed: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
