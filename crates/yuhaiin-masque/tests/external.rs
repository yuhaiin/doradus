//! Opt-in interoperability check against a real Cloudflare WARP account.
//!
//! The test is ignored by default and reads a local usque-rs-compatible JSON
//! file from `YUHAIIN_WARP_MASQUE_EXTERNAL_CONFIG`.  Credentials and private
//! configuration stay outside the repository.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_core::{Endpoint, FlowContext, Network};
use yuhaiin_masque::{WarpMasqueConfig, build_proxy};

#[tokio::test]
#[ignore = "requires a local Cloudflare WARP configuration"]
async fn connects_to_ip_through_cloudflare_warp() {
    let path = std::env::var("YUHAIIN_WARP_MASQUE_EXTERNAL_CONFIG")
        .expect("set YUHAIIN_WARP_MASQUE_EXTERNAL_CONFIG to a usque-rs JSON config");
    let config = WarpMasqueConfig::from_json(
        &std::fs::read(path).expect("read YUHAIIN_WARP_MASQUE_EXTERNAL_CONFIG"),
    )
    .expect("parse usque-rs WARP config");
    let proxy = build_proxy(config, Duration::from_secs(20))
        .await
        .expect("build WARP MASQUE proxy");
    let context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "1.1.1.1:80".parse().expect("test endpoint"),
    ));
    let mut stream = proxy.connect(&context).await.expect("connect through WARP");
    stream
        .write_all(b"HEAD / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    assert!(
        response.starts_with(b"HTTP/"),
        "unexpected response: {response:?}"
    );
}
