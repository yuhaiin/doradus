//! Cross-language Shadowsocks stream check against the sibling Go checkout.
//!
//! The test is ignored in ordinary workspace runs because it starts the Go
//! toolchain.  All generated state lives under the user's cache directory.

#![cfg(unix)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_core::{DomainName, Endpoint, FlowContext, Network};
use yuhaiin_protocol::proxy::FixedAsyncProxy;
use yuhaiin_protocol::shadowsocks::{Method, ShadowsocksProxy};

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn rust_shadowsocks_client_round_trips_against_go_server() {
    let go_root = "/home/asutorufa/Documents/Programming/yuhaiin";
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/shadowsocks_go_server.go");
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/home/asutorufa/.cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let ready = cache_root.join(format!("shadowsocks-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let address = "127.0.0.1:24444";

    let mut child = Command::new("go")
        .arg("run")
        .arg(helper)
        .current_dir(go_root)
        .env("GOEXPERIMENT", "jsonv2,greenteagc")
        .env("GOTMPDIR", &cache_root)
        .env("SHADOWSOCKS_LISTEN", address)
        .env("SHADOWSOCKS_READY", &ready)
        .spawn()
        .expect("start Go Shadowsocks server");

    for _ in 0..250 {
        if ready.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Go Shadowsocks server exited before ready: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready.exists(), "Go Shadowsocks server did not become ready");

    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address: address.parse().unwrap(),
        timeout: Duration::from_secs(2),
    });
    let proxy = ShadowsocksProxy::new(parent, Method::Aes256Gcm.name(), "secret").unwrap();
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
    assert!(status.success(), "Go Shadowsocks server failed: {status}");
    let _ = std::fs::remove_file(ready);
}
