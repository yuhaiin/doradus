//! Real Go client interoperability smoke for the Trojan wire contract.
//!
//! This is intentionally ignored: it needs the sibling Go checkout and a Go
//! toolchain.  It never uses `/tmp`; Go's build scratch directory is placed
//! under the user's cache as required by the migration workflow.

use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use yuhaiin_core::{DomainName, Endpoint, Network};
use yuhaiin_protocol::trojan::{self, Command as TrojanCommand};

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_trojan_client_connects_to_rust_wire_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hash = trojan::password_hash(b"secret");
        let request = trojan::read_request(&mut stream, &hash).await.unwrap();
        assert_eq!(request.command, TrojanCommand::Connect);
        assert_eq!(
            request.destination,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
        );
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

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
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .arg("run")
            .arg(helper)
            .current_dir(&go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("TROJAN_LISTEN", listen)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go Trojan client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}
