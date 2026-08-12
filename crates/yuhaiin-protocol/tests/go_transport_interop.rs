//! Go/Rust interoperability for a protocol wrapped by the RustCrypto TLS
//! transport.  The ordinary VLESS wire test intentionally uses a plain
//! parent; this test makes the transport boundary observable as well.

#![cfg(all(unix, feature = "tls-rustcrypto"))]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yuhaiin_core::proxy::{AsyncProxy, FixedAsyncProxy};
use yuhaiin_core::{DomainName, Endpoint, FlowContext, Network};
use yuhaiin_protocol::tls::RustCryptoTlsProxy;
use yuhaiin_protocol::vless::VlessProxy;

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn rust_vless_client_over_tls_round_trips_against_go_server() {
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin")
        });
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/vless_tls_go_server.go");
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/home/asutorufa/.cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let ready = cache_root.join(format!("vless-tls-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let address = "127.0.0.1:24446";

    let mut child = Command::new("go")
        .arg("run")
        .arg(helper)
        .current_dir(&go_root)
        .env("GOEXPERIMENT", "jsonv2,greenteagc")
        .env("GOTMPDIR", &cache_root)
        .env("VLESS_TLS_LISTEN", address)
        .env("VLESS_TLS_READY", &ready)
        .spawn()
        .expect("start Go VLESS-over-TLS server");

    for _ in 0..250 {
        if ready.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Go VLESS-over-TLS server exited before ready: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        ready.exists(),
        "Go VLESS-over-TLS server did not become ready"
    );

    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address: address.parse().unwrap(),
        timeout: Duration::from_secs(2),
    });
    let tls = RustCryptoTlsProxy::new_with_options(
        parent,
        RootCertStore::empty(),
        "localhost",
        &[],
        true,
    )
    .unwrap();
    let proxy = VlessProxy::new(Arc::new(tls), "00112233-4455-6677-8899-aabbccddeeff").unwrap();
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
    assert!(
        status.success(),
        "Go VLESS-over-TLS server failed: {status}"
    );
    let _ = std::fs::remove_file(ready);
}
