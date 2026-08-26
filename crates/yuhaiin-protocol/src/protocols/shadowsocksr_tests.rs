//! ShadowsocksR protocol tests.

use super::*;
use yuhaiin_core::{DomainName, Endpoint, Network};

#[test]
fn parses_supported_ssr_surface_and_rejects_unsupported_layers() {
    assert!(
        ShadowsocksrConfig::new(
            "aes-128-cfb",
            "password",
            "auth_aes128_md5",
            "",
            "plain",
            "",
        )
        .is_ok()
    );
    assert!(
        ShadowsocksrConfig::new("aes-128-cfb", "password", "auth_chain_a", "", "plain", "",)
            .is_err()
    );
    assert!(
        ShadowsocksrConfig::new("aes-128-cfb", "password", "origin", "", "http_simple", "",)
            .is_err()
    );
}

#[test]
fn auth_aes128_md5_stream_frames_round_trip() {
    let key = md5_password_kdf(b"password", 32);
    let mut sender = ProtocolState::new(ProtocolKind::AuthAes128Md5, &key, "");
    let mut receiver = sender.clone();
    let auth_header = sender.encode_stream(b"target-and-payload").unwrap();
    assert!(auth_header.len() >= 35 + b"target-and-payload".len());
    let encoded = sender.encode_stream(b"second").unwrap();
    let mut pending = encoded;
    let mut decoded = Vec::new();
    receiver.decode_stream(&mut pending, &mut decoded).unwrap();
    assert!(pending.is_empty());
    assert_eq!(decoded, b"second");
}

#[test]
fn stream_cipher_is_symmetric_for_all_aes_modes() {
    for method in [
        CipherMethod::Aes128Cfb,
        CipherMethod::Aes192Cfb,
        CipherMethod::Aes256Cfb,
        CipherMethod::Aes128Ctr,
        CipherMethod::Aes192Ctr,
        CipherMethod::Aes256Ctr,
        CipherMethod::Aes128Ofb,
        CipherMethod::Aes192Ofb,
        CipherMethod::Aes256Ofb,
    ] {
        let key = vec![7u8; method.key_len()];
        let iv = vec![3u8; method.iv_len()];
        let mut encrypted = b"stream-cipher-round-trip".to_vec();
        let expected = encrypted.clone();
        StreamCipher::new(method, &key, &iv, false)
            .unwrap()
            .apply(&mut encrypted)
            .unwrap();
        let mut decoded = encrypted;
        StreamCipher::new(method, &key, &iv, true)
            .unwrap()
            .apply(&mut decoded)
            .unwrap();
        assert_eq!(decoded, expected, "{method:?}");
    }
}

#[test]
fn udp_packet_preserves_target_and_payload() {
    let key = md5_password_kdf(b"password", 32);
    let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443);
    let sender = ProtocolState::new(ProtocolKind::AuthAes128Md5, &key, "");
    let mut plain = Vec::new();
    encode_endpoint(&target, &mut plain).unwrap();
    plain.extend_from_slice(b"ping");
    let packet = sender.encode_packet(&plain).unwrap();
    let decoded = sender.decode_packet(&packet).unwrap();
    let mut cursor = 0;
    assert_eq!(
        decode_endpoint(&decoded, &mut cursor, Network::Udp).unwrap(),
        target
    );
    assert_eq!(
        &decoded[cursor..decoded.len() - sender.uid().len()],
        b"ping"
    );
}

#[tokio::test]
#[ignore = "requires the sibling Go checkout and Go toolchain"]
async fn go_shadowsocksr_client_round_trips_against_rust_wire_server() {
    use std::process::Command;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let key = md5_password_kdf(b"password", 32);
        let mut iv = [0u8; 16];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut iv)
            .await
            .unwrap();
        let mut cipher = StreamCipher::new(CipherMethod::Aes256Ctr, &key, &iv, true).unwrap();
        let mut pending = Vec::new();
        let mut wire = [0u8; 16 * 1024];
        let target = loop {
            let count = tokio::io::AsyncReadExt::read(&mut stream, &mut wire)
                .await
                .unwrap();
            assert!(count > 0);
            cipher.apply(&mut wire[..count]).unwrap();
            pending.extend_from_slice(&wire[..count]);
            if let Some(target) = decode_auth_header(&mut pending, &key, &iv).unwrap() {
                break target;
            }
        };
        let mut cursor = 0;
        assert_eq!(
            decode_endpoint(&target, &mut cursor, Network::Tcp).unwrap(),
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
        );

        let response_iv = [9u8; 16];
        stream.write_all(&response_iv).await.unwrap();
        let mut response_cipher =
            StreamCipher::new(CipherMethod::Aes256Ctr, &key, &response_iv, false).unwrap();
        let mut response = ProtocolState::new(ProtocolKind::AuthAes128Md5, &key, "");
        response.sent_header = true;
        let mut frame = response.encode_stream(b"pong").unwrap();
        response_cipher.apply(&mut frame).unwrap();
        stream.write_all(&frame).await.unwrap();
    });

    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop/shadowsocksr_go_client.go");
    let cache_root = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&cache_root).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .arg("run")
            .arg(helper)
            .current_dir("/home/asutorufa/Documents/Programming/yuhaiin")
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", &cache_root)
            .env("SSR_LISTEN", address.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "Go ShadowsocksR client failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}
