//! Cross-language VMess UDP packet framing check against the real Go client.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use yuhaiin_core::{DomainName, Endpoint, Network};
use yuhaiin_protocol::vmess::{
    encode_response_header, read_body_frame, read_request, write_body_frame,
};

const UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vmess_udp_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_vmess_udp_wire(&mut stream).await;
    });

    run_go_vmess_udp_client(address).await;
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("Rust VMess UDP server did not close")
        .unwrap();
}

async fn serve_vmess_udp_wire<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(stream, &UUID).await.unwrap();
    assert_eq!(request.command, 2, "VMess UDP command");
    assert_eq!(
        request.destination,
        Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53)
    );

    let response_key = sha256_key(&request.body_key);
    let response_iv = sha256_key(&request.body_iv);
    stream
        .write_all(
            &encode_response_header(request.response_v, &response_key, &response_iv).unwrap(),
        )
        .await
        .unwrap();

    let payload = read_body_frame(
        stream,
        &request.body_key,
        &request.body_iv,
        request.security,
        0,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(payload, b"go-vmess-udp");
    write_body_frame(
        stream,
        &response_key,
        &response_iv,
        request.security,
        0,
        b"go-vmess-udp",
    )
    .await
    .unwrap();
}

async fn run_go_vmess_udp_client(address: std::net::SocketAddr) {
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin"));
    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/vmess_udp_go_client.go");
    let cache_root = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args(["run", helper.to_str().unwrap()])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("VMESS_UDP_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "Go VMess UDP client failed: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sha256_key(input: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)[..16].try_into().unwrap()
}
