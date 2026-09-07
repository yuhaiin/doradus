use super::*;

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_inbound_preserves_go_early_data_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (stream, early_data) = accept_websocket_stream(stream).await.unwrap();
        assert_eq!(early_data, b"early-data");
        let mut stream = PrefixedIo::new(early_data, stream);
        let mut received = vec![0u8; b"early-dataafter".len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, b"early-dataafter");
    });

    let raw = TcpStream::connect(address).await.unwrap();
    let mut request = format!("ws://{address}/proxy")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Key",
        HeaderValue::from_static("ZWFybHktZGF0YQ"),
    );
    request
        .headers_mut()
        .insert("early_data", HeaderValue::from_static("base64"));
    let (mut websocket, response) = tokio_tungstenite::client_async(request, raw).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("early_data")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    websocket
        .send(tokio_tungstenite::tungstenite::Message::binary(
            b"after".to_vec(),
        ))
        .await
        .unwrap();
    server.await.unwrap();
}
