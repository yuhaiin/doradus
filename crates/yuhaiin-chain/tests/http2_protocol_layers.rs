use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, split};
use tokio::net::TcpListener;
use tokio::time::timeout;
use yuhaiin_chain::ChainProxy;
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::proxy::AsyncProxy;
use yuhaiin_core::{DomainName, Endpoint, FlowContext, Network};
use yuhaiin_protocol::{trojan, vless, vmess};

const UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const PAYLOAD: &[u8] = b"protocol-over-http2";

#[derive(Clone, Copy)]
enum Protocol {
    Vless,
    Vmess,
    Trojan,
}

#[tokio::test(flavor = "current_thread")]
async fn protocol_layers_round_trip_over_go_compatible_http2_transport() {
    for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
        let (address, server) = spawn_server(protocol).await;
        let config = format!(
            r#"{{
                "id":"h2-protocol-layer",
                "chain":[
                    {{"type":"fixedv2","fixedv2":{{"addresses":[{{"host":"127.0.0.1","port":{}}}]}}}},
                    {{"type":"http2","http2":{{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}}}}
                ]
            }}"#,
            address.port()
        );
        let transport: Arc<dyn AsyncProxy> = Arc::new(
            ChainProxy::from_go_json_transport_with_resolver(
                &config,
                Arc::new(SystemAsyncIpResolver),
            )
            .unwrap(),
        );
        let proxy: Arc<dyn AsyncProxy> = match protocol {
            Protocol::Vless => Arc::new(
                vless::VlessProxy::new(transport, "00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            ),
            Protocol::Vmess => Arc::new(
                vmess::VmessProxy::new(
                    transport,
                    "00112233-4455-6677-8899-aabbccddeeff",
                    "aes-128-gcm",
                    0,
                )
                .unwrap(),
            ),
            Protocol::Trojan => Arc::new(trojan::TrojanProxy::new(
                transport,
                "runtime-protocol-password",
            )),
        };
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        let mut response = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD, "protocol did not round-trip over H2");
        stream.shutdown().await.unwrap();
        proxy.close().await.unwrap();
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}

async fn spawn_server(protocol: Protocol) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().host(), Some("localhost"));

        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let (application, relay) = tokio::io::duplex(64 * 1024);
        let (mut relay_read, mut relay_write) = split(relay);
        let body_to_relay = tokio::spawn(async move {
            while let Some(data) = body.data().await {
                let Ok(data) = data else { break };
                if body.flow_control().release_capacity(data.len()).is_err() {
                    break;
                }
                if relay_write.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = relay_write.shutdown().await;
        });
        let relay_to_body = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok(length) = relay_read.read(&mut buffer).await {
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
        let protocol_task = tokio::spawn(serve_protocol(application, protocol));

        // The h2 driver must continue polling while the application protocol
        // reads and writes the CONNECT stream body.
        while let Some(result) = connection.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let _ = request.into_body();
            let _ = respond.send_response(Response::new(()), true);
        }
        protocol_task.await.unwrap();
        body_to_relay.await.unwrap();
        relay_to_body.await.unwrap();
    });
    (address, server)
}

async fn serve_protocol(mut stream: DuplexStream, protocol: Protocol) {
    let destination = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    match protocol {
        Protocol::Vless => {
            let request = vless::read_request(&mut stream, &UUID).await.unwrap();
            assert_eq!(request.command, vless::Command::Tcp);
            assert_eq!(request.destination, destination);
            vless::write_response(&mut stream, &[]).await.unwrap();
            echo(&mut stream).await;
        }
        Protocol::Vmess => {
            let request = vmess::read_request(&mut stream, &UUID).await.unwrap();
            assert_eq!(request.command, 1);
            assert_eq!(request.destination, destination);
            let response_key = sha256_key(&request.body_key);
            let response_iv = sha256_key(&request.body_iv);
            stream
                .write_all(
                    &vmess::encode_response_header(request.response_v, &response_key, &response_iv)
                        .unwrap(),
                )
                .await
                .unwrap();
            let payload = vmess::read_body_frame(
                &mut stream,
                &request.body_key,
                &request.body_iv,
                request.security,
                0,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(payload, PAYLOAD);
            vmess::write_body_frame(
                &mut stream,
                &response_key,
                &response_iv,
                request.security,
                0,
                PAYLOAD,
            )
            .await
            .unwrap();
        }
        Protocol::Trojan => {
            let hash = trojan::password_hash(b"runtime-protocol-password");
            let request = trojan::read_request(&mut stream, &hash).await.unwrap();
            assert_eq!(request.command, trojan::Command::Connect);
            assert_eq!(request.destination, destination);
            echo(&mut stream).await;
        }
    }
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    let mut payload = vec![0u8; PAYLOAD.len()];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, PAYLOAD);
    stream.write_all(PAYLOAD).await.unwrap();
}

fn sha256_key(input: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)[..16].try_into().unwrap()
}
