//! Cross-language VMess modern AEAD stream check against the Go client.

#![cfg(unix)]

use std::process::Command;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use yuhaiin_core::{DomainName, Endpoint, Network};
use yuhaiin_protocol::vmess::{
    encode_response_header, read_body_frame, read_request, write_body_frame,
};

#[cfg(all(feature = "tls-rustcrypto", feature = "websocket"))]
mod support;

const UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vmess_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_vmess_wire(&mut stream).await;
    });

    run_go_vmess_client(address, None).await;
    server.await.unwrap();
}

#[cfg(all(feature = "tls-rustcrypto", feature = "websocket"))]
#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vmess_client_over_tls_websocket_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let websocket = support::accept_tls_websocket(stream).await;
        let mut stream = yuhaiin_protocol::websocket::WebSocketIo::new(websocket);
        serve_vmess_wire(&mut stream).await;
    });

    run_go_vmess_client(address, Some("tls-websocket")).await;
    server.await.unwrap();
}

async fn serve_vmess_wire<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(stream, &UUID).await.unwrap();
    assert_eq!(
        request.destination,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
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
    assert_eq!(payload, b"ping");
    write_body_frame(
        stream,
        &response_key,
        &response_iv,
        request.security,
        0,
        b"pong",
    )
    .await
    .unwrap();
}

async fn run_go_vmess_client(address: std::net::SocketAddr, transport: Option<&str>) {
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin")
        });
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/vmess_go_client.go");
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
            .env("VMESS_LISTEN", listen);
        if let Some(transport) = transport {
            command.env("VMESS_TRANSPORT", transport);
        }
        command.output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go VMess client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sha256_key(input: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)[..16].try_into().unwrap()
}
