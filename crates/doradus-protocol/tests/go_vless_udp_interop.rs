//! Cross-language VLESS UDP framing check against the real Go client.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_vless_udp_client_round_trips_against_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut fixed = [0u8; 22];
        stream.read_exact(&mut fixed).await.unwrap();
        assert_eq!(fixed[0], 0);
        assert_eq!(&fixed[1..17], &UUID);
        assert_eq!(fixed[17], 0);
        assert_eq!(fixed[18], 2, "VLESS UDP command");
        assert_eq!(u16::from_be_bytes([fixed[19], fixed[20]]), 53);
        assert_eq!(fixed[21], 2, "VLESS domain address type");
        let mut domain_len = [0u8; 1];
        stream.read_exact(&mut domain_len).await.unwrap();
        let mut domain = vec![0u8; usize::from(domain_len[0])];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(&domain, b"example.com");

        // Go's PacketConn.ReadFrom starts at the first datagram length and
        // does not consume the response header used by its TCP Conn.Read
        // path. Rust's VLESS inbound follows this Go-compatible UDP shape.
        let payload_len = stream.read_u16().await.unwrap();
        let mut payload = vec![0u8; usize::from(payload_len)];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"go-vless-udp");
        stream.write_u16(payload_len).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let go_root = std::env::var_os("DORADUS_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/doradus"));
    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/vless_udp_go_client.go");
    let go_tmp = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("doradus/go-tmp");
    std::fs::create_dir_all(&go_tmp).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args(["run", helper.to_str().unwrap()])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &go_tmp)
            .env("VLESS_UDP_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "Go VLESS UDP client failed: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("Rust VLESS UDP server did not close")
        .unwrap();
}
