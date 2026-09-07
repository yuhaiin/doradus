use std::{sync::Arc, time::Duration};

#[cfg(feature = "websocket")]
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

use super::*;
use crate::{RuntimeBuilder, RuntimeController};
use doradus_chain::AsyncYuubinsyaTcpSession;
use doradus_core::dns_resolver::SystemAsyncIpResolver;
use doradus_core::process::ProcessInfo;
use doradus_core::{Endpoint, Network};
use doradus_protocol::trojan::{self, Command};
use doradus_protocol::vless::{self, Command as VlessCommand};
use doradus_store::{ConfigStore, GoInboundRecord, GoNodeRecord};
use serde_json::json;

#[cfg(feature = "doh-tls")]
const CA_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUbS/bRRel4PtBGY4lbCYyc2lxKngwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwMzRaFw0zNjA4
MDMxODIwMzRaMBgxFjAUBgNVBAMMDXl1aGFpaW4tcDAtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATBHNZR0dSTLNKfYwheVmhyGdCeMBSibhHEGBzXtZ6v0nIA
DhHIIK38v1qnoiTWN9Fof8HXKfhvl1LxSY0rSqe0o2MwYTAdBgNVHQ4EFgQUhaYk
OXheQ1JzLpIKK4I2FEcRMyMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcR
MyMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIhAOzmDAm07/ezq+5WBQhYYOi/F1onvS4skssoRtRq8w8XAiBH0LCIlJk5
QX0jqAZz0309NRht+WWJtz28CPHvuhGXNg==
-----END CERTIFICATE-----
"#;

#[cfg(feature = "doh-tls")]
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

#[cfg(feature = "doh-tls")]
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(future)
}

async fn direct_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    controller
        .store()
        .repository()
        .put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        })
        .await
        .unwrap();
    controller.reload().await.unwrap();
    let selector = controller
        .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
        .await
        .unwrap();
    (selector, controller.monitor())
}

async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(size) = stream.read(&mut buffer).await {
                    if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, task)
}

async fn read_exact_array<const N: usize>(
    stream: &mut doradus_core::proxy::BoxAsyncStream,
) -> [u8; N] {
    let mut value = [0u8; N];
    stream.read_exact(&mut value).await.unwrap();
    value
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        headers.push(byte[0]);
    }
    headers
}

struct FixedProcessResolver;

impl ProcessResolver for FixedProcessResolver {
    fn resolve(
        &self,
        _network: Network,
        _source: SocketAddr,
        _destination: SocketAddr,
    ) -> std::io::Result<Option<ProcessInfo>> {
        Ok(Some(ProcessInfo {
            path: "/usr/bin/inbound-client".to_owned(),
            pid: 4242,
            uid: 1000,
        }))
    }
}

#[path = "inbounds_tests/configuration.rs"]
mod configuration;
#[path = "inbounds_tests/context.rs"]
mod context;
#[path = "inbounds_tests/protocols.rs"]
mod protocols;
#[path = "inbounds_tests/reverse.rs"]
mod reverse;
#[path = "inbounds_tests/socks.rs"]
mod socks;
#[path = "inbounds_tests/transports.rs"]
mod transports;
#[path = "inbounds_tests/websocket.rs"]
mod websocket;
