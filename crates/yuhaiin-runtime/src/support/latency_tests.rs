use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use yuhaiin_core::proxy::AsyncDatagram;
use yuhaiin_core::{BoxFuture, FlowContext};

struct EchoProxy;

struct AbruptEofStream {
    bytes: Vec<u8>,
    offset: usize,
}

impl AsyncRead for AbruptEofStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.bytes.len() {
            let length = (self.bytes.len() - self.offset).min(buffer.remaining());
            buffer.put_slice(&self.bytes[self.offset..self.offset + length]);
            self.offset += length;
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed without TLS close_notify",
            )))
        }
    }
}

impl AsyncWrite for AbruptEofStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct StaticResolver {
    addresses: IpSet,
}

impl AsyncIpResolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        let mut addresses = self.addresses.clone();
        match strategy {
            ResolveStrategy::OnlyIpv4 => addresses.v6.clear(),
            ResolveStrategy::OnlyIpv6 => addresses.v4.clear(),
            ResolveStrategy::Default
            | ResolveStrategy::PreferIpv4
            | ResolveStrategy::PreferIpv6 => {}
        }
        Box::pin(async move { Ok(addresses) })
    }
}

struct RecordingEchoProxy {
    destinations: Arc<std::sync::Mutex<Vec<Endpoint>>>,
}

impl AsyncProxy for RecordingEchoProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        self.destinations
            .lock()
            .expect("recording proxy mutex poisoned")
            .push(destination.clone());
        Box::pin(async move {
            let (client, mut server) = tokio::io::duplex(4096);
            let value = if destination.addr().is_some_and(|address| address.is_ipv6()) {
                "2001:db8::7"
            } else {
                "203.0.113.7"
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(count) = server.read(&mut chunk).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.len() > 8192 {
                        return;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}\n",
                    value.len() + 1,
                    value
                );
                let _ = server.write_all(response.as_bytes()).await;
            });
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "recording proxy has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AsyncProxy for EchoProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        Box::pin(async move {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(count) = server.read(&mut chunk).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.len() > 8192 {
                        return;
                    }
                }
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n203.0.113.7\n";
                let _ = server.write_all(response).await;
            });
            let _ = destination;
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
            let datagram = TestDatagram {
                tx,
                rx: tokio::sync::Mutex::new(rx),
            };
            Ok(Box::new(datagram) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct TcpStunProxy;

impl AsyncProxy for TcpStunProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut request = vec![0u8; 20];
                if server.read_exact(&mut request).await.is_err() {
                    return;
                }
                let length = usize::from(u16::from_be_bytes([request[2], request[3]]));
                request.resize(20 + length, 0);
                if server.read_exact(&mut request[20..]).await.is_err() {
                    return;
                }
                let response = stun_response(&request);
                let _ = server.write_all(&response).await;
            });
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "TCP STUN fixture has no datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct TestDatagram {
    tx: mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl AsyncDatagram for TestDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let tx = self.tx.clone();
        Box::pin(async move {
            tx.send(stun_response(payload))
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "test datagram closed"))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        let rx = &self.rx;
        Box::pin(async move {
            let packet = rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| Error::new(ErrorKind::Closed, "test datagram closed"))?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok((
                packet.len(),
                Endpoint::ip(Network::Udp, "127.0.0.1:3478".parse().unwrap()),
            ))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(Network::Udp, "127.0.0.1:0".parse().unwrap()))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

type NatRequest = (SocketAddr, Option<u8>);

struct NatBehaviorDatagram {
    tx: mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    requests: Arc<Mutex<Vec<NatRequest>>>,
}

impl AsyncDatagram for NatBehaviorDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let tx = self.tx.clone();
        let requests = self.requests.clone();
        Box::pin(async move {
            let target = target
                .addr()
                .ok_or_else(|| Error::invalid("NAT behavior target is not an IP"))?;
            let change_request = stun_change_request(payload);
            requests.lock().unwrap().push((target, change_request));
            let response = stun_response_with_addresses(
                payload,
                "198.51.100.10:50000".parse().unwrap(),
                Some("192.0.2.2:3478".parse().unwrap()),
                Some("192.0.2.1:3478".parse().unwrap()),
            );
            tx.send(response)
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "NAT behavior datagram closed"))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        let rx = &self.rx;
        Box::pin(async move {
            let packet = rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| Error::new(ErrorKind::Closed, "NAT behavior datagram closed"))?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok((
                packet.len(),
                Endpoint::ip(Network::Udp, "192.0.2.1:3478".parse().unwrap()),
            ))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            "192.0.2.10:40000".parse().unwrap(),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

fn stun_response(request: &[u8]) -> Vec<u8> {
    stun_response_with_addresses(request, "127.0.0.1:3478".parse().unwrap(), None, None)
}

fn stun_response_with_addresses(
    request: &[u8],
    mapped: SocketAddr,
    other: Option<SocketAddr>,
    origin: Option<SocketAddr>,
) -> Vec<u8> {
    let mut attributes = Vec::new();
    append_xor_address_attribute(&mut attributes, 0x0020, mapped);
    if let Some(other) = other {
        append_xor_address_attribute(&mut attributes, 0x802c, other);
    }
    if let Some(origin) = origin {
        append_xor_address_attribute(&mut attributes, 0x802b, origin);
    }
    let mut response = Vec::with_capacity(20 + attributes.len());
    response.extend_from_slice(&[0x01, 0x01]);
    response.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    response.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    response.extend_from_slice(&request[8..20]);
    response.extend_from_slice(&attributes);
    response
}

fn append_xor_address_attribute(attributes: &mut Vec<u8>, kind: u16, address: SocketAddr) {
    let SocketAddr::V4(address) = address else {
        panic!("STUN fixture only supports IPv4 addresses");
    };
    attributes.extend_from_slice(&kind.to_be_bytes());
    attributes.extend_from_slice(&8u16.to_be_bytes());
    attributes.extend_from_slice(&[0, 1]);
    let encoded_port = if kind == 0x802c {
        address.port()
    } else {
        address.port() ^ 0x2112
    };
    attributes.extend_from_slice(&encoded_port.to_be_bytes());
    let encoded_ip = if kind == 0x802c {
        u32::from_be_bytes(address.ip().octets())
    } else {
        u32::from_be_bytes(address.ip().octets()) ^ 0x2112_A442
    };
    attributes.extend_from_slice(&encoded_ip.to_be_bytes());
}

fn stun_change_request(packet: &[u8]) -> Option<u8> {
    if packet.len() < 20 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let end = 20 + length;
    if end > packet.len() {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset += 4;
        if offset + size > end {
            return None;
        }
        if kind == 0x0003 && size == 4 {
            return Some(packet[offset + 3]);
        }
        offset += (size + 3) & !3;
    }
    None
}

#[test]
fn parses_http_and_stun_authorities() {
    let http = parse_http_target("https://[::1]:8443/path?q=1").unwrap();
    assert!(http.https);
    assert_eq!(http.host, "::1");
    assert_eq!(http.port, 8443);
    assert_eq!(http.path, "/path?q=1");
    assert_eq!(parse_host_port("stun.example:3479", 3478).unwrap().1, 3479);
    assert_eq!(
        LatencyRequest::default().host_or_default(false),
        "stun.nextcloud.com:3478"
    );
    assert_eq!(
        LatencyRequest::default().host_or_default(true),
        "stun.nextcloud.com:443"
    );
}

#[test]
fn stun_xor_address_decodes() {
    let transaction = [1u8; 12];
    let mut packet = stun_binding_request(transaction);
    packet[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
    packet[2..4].copy_from_slice(&12u16.to_be_bytes());
    let port = 3478u16 ^ 0x2112;
    let address = [127u8, 0, 0, 1];
    let cookie = 0x2112_A442u32.to_be_bytes();
    packet.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend(
        address
            .into_iter()
            .zip(cookie)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let reply = parse_stun_response(&packet, transaction).unwrap();
    assert_eq!(reply.values.xor_mapped_address, "127.0.0.1:3478");
}

#[test]
fn stun_other_address_is_not_xor_decoded() {
    let transaction = [2u8; 12];
    let mut packet = stun_binding_request(transaction);
    packet[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
    packet[2..4].copy_from_slice(&36u16.to_be_bytes());

    let mapped_port = 3478u16 ^ 0x2112;
    let mapped_address = [127u8, 0, 0, 1];
    let cookie = 0x2112_A442u32.to_be_bytes();
    packet.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
    packet.extend_from_slice(&mapped_port.to_be_bytes());
    packet.extend(
        mapped_address
            .into_iter()
            .zip(cookie)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let other = Ipv6Addr::new(0x2a01, 0x04f8, 0x1c1e, 0xd769, 0, 0, 0, 1);
    packet.extend_from_slice(&[0x80, 0x2c, 0, 20, 0, 2]);
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.extend_from_slice(&other.octets());

    let reply = parse_stun_response(&packet, transaction).unwrap();
    assert_eq!(
        reply.other_address,
        Some(SocketAddr::new(IpAddr::V6(other), 443))
    );
    assert_eq!(reply.values.other_address, "[2a01:4f8:1c1e:d769::1]:443");
}

#[tokio::test]
async fn http_response_reads_chunked_body_and_trailers() {
    let (client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n6;ext=yes\r\n world\r\n0\r\nX-Test: yes\r\n\r\n",
                )
                .await
                .unwrap();
    });
    let body = read_http_response(
        &mut (Box::new(client) as BoxAsyncStream),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(body, b"hello world");
    server_task.await.unwrap();
}

#[tokio::test]
async fn http_response_accepts_close_delimited_unexpected_eof() {
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody";
    let mut stream = Box::new(AbruptEofStream {
        bytes: response.to_vec(),
        offset: 0,
    }) as BoxAsyncStream;
    let body = read_http_response(&mut stream, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(body, b"body");
}

#[tokio::test]
async fn http_response_rejects_truncated_content_length() {
    let (client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")
            .await
            .unwrap();
        server.shutdown().await.unwrap();
    });
    let result = read_http_response(
        &mut (Box::new(client) as BoxAsyncStream),
        Duration::from_secs(1),
    )
    .await;
    assert!(result.is_err());
    server_task.await.unwrap();
}

#[tokio::test]
async fn udp_stun_probe_uses_proxy_datagram_and_contract_shape() {
    let response = probe_stun(
        Arc::new(EchoProxy),
        LatencyRequest {
            probe_type: "stun".to_owned(),
            host: "127.0.0.1:3478".to_owned(),
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(response.ok);
    let stun = response.stun.unwrap();
    assert_eq!(stun.mapped_address, "127.0.0.1:3478");
    assert_eq!(stun.mapping, "ServerNotSupportChangePort");
    assert_eq!(stun.filtering, "ServerNotSupportChangePort");
}

#[tokio::test]
async fn udp_stun_probe_matches_go_mapping_and_filtering_sequence() {
    let (tx, rx) = mpsc::channel(8);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let datagram = NatBehaviorDatagram {
        tx,
        rx: tokio::sync::Mutex::new(rx),
        requests: Arc::clone(&requests),
    };
    let primary: SocketAddr = "192.0.2.1:3478".parse().unwrap();
    let other_primary: SocketAddr = "192.0.2.2:3478".parse().unwrap();

    let response = probe_stun_udp(
        &datagram,
        Endpoint::ip(Network::Udp, primary),
        primary.port(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert_eq!(response.mapped_address, "198.51.100.10:50000");
    assert_eq!(response.mapping, "EndpointIndependent");
    assert_eq!(response.filtering, "EndpointIndependent");
    assert!(response.xor_mapped_address.is_empty());
    assert!(response.other_address.is_empty());
    assert!(response.response_origin_address.is_empty());

    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            (primary, None),
            (other_primary, None),
            (primary, None),
            (primary, Some(0x06)),
        ]
    );
}

#[tokio::test]
async fn dns_udp_probe_uses_proxy_datagram_and_validates_response() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = [0u8; 4096];
        let (length, peer) = socket.recv_from(&mut query).await.unwrap();
        assert!(length >= 12);
        // The resolver advertises an EDNS UDP size. Build the mock
        // response from the question only; copying the OPT pseudo-record
        // into the answer section would be an invalid DNS response.
        let mut question_end = 12;
        loop {
            let label_length = query[question_end] as usize;
            question_end += 1;
            if label_length == 0 {
                break;
            }
            question_end += label_length;
        }
        question_end += 4; // QTYPE and QCLASS
        let mut response = Vec::with_capacity(length + 16);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..question_end]);
        response.extend_from_slice(&[
            0xc0, 0x0c, // compressed owner name
            0, 1, // A
            0, 1, // IN
            0, 0, 0, 60, // TTL
            0, 4, // IPv4 address length
            1, 2, 3, 4,
        ]);
        socket.send_to(&response, peer).await.unwrap();
    });

    let response = probe(
        Arc::new(yuhaiin_protocol::proxy::DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        }),
        LatencyRequest {
            probe_type: "dns".to_owned(),
            host: address.to_string(),
            target_domain: "example.com".to_owned(),
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(response.ok);
    assert!(response.latency_ms >= 0);
    server.await.unwrap();
}

#[tokio::test]
async fn http_and_ip_probes_use_the_same_async_proxy_boundary() {
    let proxy: Arc<dyn AsyncProxy> = Arc::new(EchoProxy);
    let http = probe(
        Arc::clone(&proxy),
        LatencyRequest {
            probe_type: "tcp".to_owned(),
            url: "http://example.test/health".to_owned(),
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(http.ok);
    assert!(http.latency_ms >= 0);

    let ip = probe_with_resolver(
        proxy,
        Arc::new(StaticResolver {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(192, 0, 2, 7)],
                v6: Vec::new(),
            },
        }),
        LatencyRequest {
            probe_type: "ip".to_owned(),
            url: "http://example.test/ip".to_owned(),
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(ip.ip.unwrap().ipv4, "203.0.113.7");
}

#[tokio::test]
async fn ip_probe_resolves_and_connects_one_endpoint_per_family() {
    let destinations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let proxy: Arc<dyn AsyncProxy> = Arc::new(RecordingEchoProxy {
        destinations: Arc::clone(&destinations),
    });
    let response = probe_with_resolver(
        proxy,
        Arc::new(StaticResolver {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(192, 0, 2, 7)],
                v6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)],
            },
        }),
        LatencyRequest {
            probe_type: "ip".to_owned(),
            url: "http://example.test/ip".to_owned(),
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let ip = response.ip.unwrap();
    assert_eq!(ip.ipv4, "203.0.113.7");
    assert_eq!(ip.ipv6, "2001:db8::7");
    let destinations = destinations
        .lock()
        .expect("recording proxy mutex poisoned")
        .clone();
    assert_eq!(destinations.len(), 2);
    assert!(
        destinations
            .iter()
            .any(|destination| { destination.addr() == Some("192.0.2.7:80".parse().unwrap()) })
    );
    assert!(
        destinations
            .iter()
            .any(|destination| { destination.addr() == Some("[2001:db8::7]:80".parse().unwrap()) })
    );
}

#[tokio::test]
async fn tcp_stun_probe_uses_standard_stun_framing() {
    let response = probe_stun(
        Arc::new(TcpStunProxy),
        LatencyRequest {
            probe_type: "stun_tcp".to_owned(),
            host: "stun.example:3478".to_owned(),
            tcp: true,
            ..LatencyRequest::default()
        },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(response.stun.unwrap().mapped_address, "127.0.0.1:3478");
}
