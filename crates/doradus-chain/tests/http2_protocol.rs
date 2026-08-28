use std::time::Duration;

use bytes::Bytes;
use doradus_chain::ChainProxy;
use doradus_core::proxy::AsyncProxy;
use doradus_core::{DomainName, Endpoint, FlowContext, Network};
use http::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[derive(Clone, Copy)]
enum FinalProtocol {
    Http,
    Socks5,
}

const HTTP_PAYLOAD: &[u8] = b"http-over-h2";
const SOCKS5_PAYLOAD: &[u8] = b"socks5-over-h2";

#[tokio::test(flavor = "current_thread")]
async fn http2_transport_wraps_http_connect_and_relays_payload() {
    run_chain(FinalProtocol::Http).await;
}

#[tokio::test(flavor = "current_thread")]
async fn http2_transport_wraps_authenticated_socks5_and_relays_payload() {
    run_chain(FinalProtocol::Socks5).await;
}

async fn run_chain(protocol: FinalProtocol) {
    let (address, server) = spawn_h2_protocol_server(protocol).await;
    let final_node = match protocol {
        FinalProtocol::Http => r#"{"type":"http","http":{"user":"user","password":"pass"}}"#,
        FinalProtocol::Socks5 => {
            r#"{"type":"socks5","socks5":{"user":"user","password":"pass","hostname":"","override_port":0}}"#
        }
    };
    let config = format!(
        r#"{{
            "id":"h2-protocol",
            "chain":[
                {{"type":"fixedv2","fixedv2":{{"addresses":[{{"host":"127.0.0.1","port":{}}}]}}}},
                {{"type":"proxy","proxy":{{}}}},
                {{"type":"none","none":{{}}}},
                {{"type":"http2","http2":{{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}}}},
                {}
            ]
        }}"#,
        address.port(),
        final_node
    );
    let proxy = ChainProxy::from_go_json(&config).unwrap();
    let context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("example.com").unwrap(),
        443,
    ));
    let payload = match protocol {
        FinalProtocol::Http => HTTP_PAYLOAD,
        FinalProtocol::Socks5 => SOCKS5_PAYLOAD,
    };
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(payload).await.unwrap();
    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, payload);
    stream.shutdown().await.unwrap();
    proxy.close().await.unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

async fn spawn_h2_protocol_server(
    protocol: FinalProtocol,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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
        let (application, relay) = tokio::io::duplex(64 * 1024);
        let (mut application_read, mut application_write) = tokio::io::split(relay);

        let body_to_application = tokio::spawn(async move {
            while let Some(data) = body.data().await {
                let Ok(data) = data else { break };
                if body.flow_control().release_capacity(data.len()).is_err() {
                    break;
                }
                if application_write.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = application_write.shutdown().await;
        });
        let application_to_body = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let length = application_read.read(&mut buffer).await.unwrap();
                if length == 0 {
                    break;
                }
                if send
                    .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
                    .is_err()
                {
                    break;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });
        let protocol_task = tokio::spawn(serve_destination_protocol(application, protocol));

        // Keep polling the H2 connection while the three application-side
        // tasks exchange bytes. The client closes the pool after its stream
        // has been verified, which ends this loop.
        while let Some(result) = connection.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let _ = request.into_body();
            respond.send_response(Response::new(()), true).unwrap();
        }
        protocol_task.await.unwrap();
        body_to_application.await.unwrap();
        application_to_body.await.unwrap();
    });
    (address, server)
}

async fn serve_destination_protocol(mut stream: DuplexStream, protocol: FinalProtocol) {
    match protocol {
        FinalProtocol::Http => {
            let request = read_headers(&mut stream).await;
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Host: example.com:443\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            echo_payload(&mut stream, HTTP_PAYLOAD).await;
        }
        FinalProtocol::Socks5 => {
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();

            let mut auth_head = [0u8; 2];
            stream.read_exact(&mut auth_head).await.unwrap();
            assert_eq!(auth_head[0], 1);
            let mut username = vec![0u8; usize::from(auth_head[1])];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_length = [0u8; 1];
            stream.read_exact(&mut password_length).await.unwrap();
            let mut password = vec![0u8; usize::from(password_length[0])];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            stream.write_all(&[1, 0]).await.unwrap();

            let mut request_head = [0u8; 5];
            stream.read_exact(&mut request_head).await.unwrap();
            assert_eq!(&request_head[..4], &[5, 1, 0, 3]);
            let mut host = vec![0u8; usize::from(request_head[4])];
            stream.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(host, b"example.com");
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            echo_payload(&mut stream, SOCKS5_PAYLOAD).await;
        }
    }
}

async fn echo_payload(stream: &mut DuplexStream, expected: &[u8]) {
    let mut payload = vec![0u8; expected.len()];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, expected);
    stream.write_all(&payload).await.unwrap();
}

async fn read_headers(stream: &mut DuplexStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
    String::from_utf8(request).unwrap()
}
