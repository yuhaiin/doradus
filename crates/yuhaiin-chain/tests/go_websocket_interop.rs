//! Ignored Go client interoperability for fixed -> WebSocket -> HTTP/2.

use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async;
use yuhaiin_chain::{YuubinsyaH2Server, YuubinsyaServerProxy};
use yuhaiin_core::proxy::{AsyncProxy, DirectAsyncProxy};
use yuhaiin_core::websocket::WebSocketIo;
use yuhaiin_core::yuubinsya::derive_salt;

const PASSWORD: &str = "rust-go-websocket-interop";

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the Go checkout and an available Go toolchain"]
async fn go_websocket_http2_client_round_trips_against_rust_server() {
    run_go_websocket_http2_client(false).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the Go checkout and an available Go toolchain"]
async fn go_websocket_http2_tls_client_round_trips_against_rust_server() {
    run_go_websocket_http2_client(true).await;
}

async fn run_go_websocket_http2_client(tls: bool) {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut request = vec![0u8; 17];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"go-websocket-echo");
        stream.write_all(&request).await.unwrap();
    });

    let upstream: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(3),
    });
    let proxy = Arc::new(YuubinsyaServerProxy::new(
        derive_salt(PASSWORD.as_bytes()),
        upstream,
    ));
    let h2_server = Arc::new(YuubinsyaH2Server::new(websocket_server_config(), proxy).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server_task = {
        let h2_server = Arc::clone(&h2_server);
        if tls {
            let acceptor = TlsAcceptor::from(websocket_tls_server_config());
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = acceptor.accept(stream).await.unwrap();
                let websocket = accept_async(stream).await.unwrap();
                let _ = h2_server.serve_h2(WebSocketIo::new(websocket)).await;
            })
        } else {
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let websocket = accept_async(stream).await.unwrap();
                let _ = h2_server.serve_h2(WebSocketIo::new(websocket)).await;
            })
        }
    };

    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/websocket_go_client.go");
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin"));
    let server = server_address.to_string();
    let target = target_address.to_string();
    let go_tmp = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&go_tmp).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args([
                "run",
                helper.to_str().expect("interop helper path is UTF-8"),
                &server,
                &target,
            ])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", go_tmp)
            .env("WEBSOCKET_TLS", if tls { "1" } else { "0" })
            .output()
    })
    .await
    .unwrap()
    .unwrap();

    server_task.abort();
    let _ = server_task.await;
    target_task.abort();
    let _ = target_task.await;
    assert!(
        output.status.success(),
        "Go WebSocket interoperability probe failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn websocket_server_config() -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
                    .next()
                    .unwrap()
                    .unwrap()
                    .to_vec(),
            )],
            rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn websocket_tls_server_config() -> Arc<rustls::ServerConfig> {
    websocket_server_config()
}

const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;

const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;
