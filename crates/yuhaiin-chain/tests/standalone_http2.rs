use std::time::Duration;

use bytes::Bytes;
use http::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use yuhaiin_chain::{ChainClient, ChainProxy};
use yuhaiin_core::{Endpoint, Network};

#[tokio::test(flavor = "current_thread")]
async fn standalone_http2_matches_go_raw_connect_wire_contract() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        let (request, mut respond) = request;
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().host(), Some("localhost"));

        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let echo = tokio::spawn(async move {
            while let Some(data) = body.data().await {
                let Ok(data) = data else {
                    return;
                };
                if body.flow_control().release_capacity(data.len()).is_err() {
                    return;
                }
                if send.send_data(data, false).is_err() {
                    return;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });

        while let Some(result) = connection.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            assert_eq!(request.method(), http::Method::CONNECT);
            let _body = request.into_body();
            respond.send_response(Response::new(()), true).unwrap();
        }
        let _ = echo.await;
    });

    let config = format!(
        r#"{{
            "id":"standalone-http2",
            "chain":[
                {{"type":"fixedv2","fixedv2":{{"addresses":[{{"host":"127.0.0.1","port":{}}}]}}}},
                {{"type":"http2","http2":{{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}}}}
            ]
        }}"#,
        address.port()
    );
    let client = ChainClient::from_go_json(&config).unwrap();
    let error = ChainProxy::from_go_json(&config).err().unwrap();
    assert!(
        error
            .message
            .contains("requires a destination protocol layer")
    );
    let mut stream = client.connect_raw_with_bind(&[]).await.unwrap();
    stream.write_all(b"client-to-server").await.unwrap();
    let mut response = vec![0; 16];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"client-to-server");
    stream.shutdown().await.unwrap();

    let ping = client
        .ping(Endpoint::ip(Network::Tcp, address))
        .await
        .unwrap();
    assert!(ping < Duration::from_secs(1));

    client.close().await;
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
