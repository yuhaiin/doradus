use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::super::{
    YuubinsyaHeader, YuubinsyaProtocol, decode_header, decode_uot_frame, encode_header,
    encode_uot_frame,
};
use super::common::{io_error, read_header_bytes};
use super::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaServerProxy, read_uot_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use yuhaiin_core::flow::{Flow, FlowDirection, FlowKey, FlowObserver};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result,
};
use yuhaiin_types::{InboundDnsHandler, InboundStreamHandler};

struct EchoDnsHandler;

impl InboundDnsHandler for EchoDnsHandler {
    fn should_hijack(&self, _destination_port: Option<u16>, _packet: &[u8]) -> bool {
        true
    }

    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Option<Result<Vec<u8>>>> {
        let response = packet.to_vec();
        Box::pin(async move { Some(Ok(response)) })
    }
}

struct ForwardDnsHandler;

impl InboundDnsHandler for ForwardDnsHandler {
    fn should_hijack(&self, _destination_port: Option<u16>, _packet: &[u8]) -> bool {
        true
    }

    fn answer<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Option<Result<Vec<u8>>>> {
        Box::pin(async { None })
    }
}

#[derive(Clone)]
struct EchoUpstream {
    opens: Arc<AtomicUsize>,
    tcp_echo: bool,
    ping_ok: bool,
}

struct EchoDatagram {
    received: StdMutex<VecDeque<(Vec<u8>, Endpoint)>>,
    notify: Arc<Notify>,
}

impl AsyncDatagram for EchoDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.received
                .lock()
                .unwrap()
                .push_back((payload.to_vec(), target));
            self.notify.notify_one();
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            loop {
                if let Some((payload, source)) = self.received.lock().unwrap().pop_front() {
                    if buffer.len() < payload.len() {
                        return Err(Error::invalid("echo datagram buffer is too small"));
                    }
                    buffer[..payload.len()].copy_from_slice(&payload);
                    return Ok((payload.len(), source));
                }
                self.notify.notified().await;
            }
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Default)]
struct RecordingObserver {
    events: Arc<StdMutex<Vec<&'static str>>>,
    bytes: Arc<AtomicUsize>,
}

impl FlowObserver for RecordingObserver {
    fn opened(&self, _flow: Flow, _context: FlowContext) {
        self.events.lock().unwrap().push("open");
    }

    fn bytes(&self, _flow: FlowKey, _direction: FlowDirection, bytes: usize) {
        self.bytes.fetch_add(bytes, Ordering::AcqRel);
    }

    fn closed(&self, _flow: FlowKey) {
        self.events.lock().unwrap().push("close");
    }
}

#[derive(Default)]
struct RecordingInboundStreamHandler {
    destination: StdMutex<Option<Endpoint>>,
    protocol: StdMutex<Option<&'static str>>,
    payload: StdMutex<Vec<u8>>,
}

impl<S> InboundStreamHandler<S> for RecordingInboundStreamHandler
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn handle_stream<'a>(
        &'a self,
        mut stream: S,
        _peer: SocketAddr,
        destination: Endpoint,
        protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            *self.destination.lock().unwrap() = Some(destination);
            *self.protocol.lock().unwrap() = Some(protocol);
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.map_err(io_error)?;
            *self.payload.lock().unwrap() = payload;
            Ok(())
        })
    }
}

impl AsyncProxy for EchoUpstream {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            if !self.tcp_echo {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "echo upstream has no TCP test path",
                ));
            }
            let (client, mut peer) = duplex(4096);
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(length) = peer.read(&mut buffer).await {
                    if length == 0 || peer.write_all(&buffer[..length]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            self.opens.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(EchoDatagram {
                received: StdMutex::new(VecDeque::new()),
                notify: Arc::new(Notify::new()),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            if self.ping_ok {
                Ok(Duration::from_nanos(1))
            } else {
                Err(Error::new(ErrorKind::Unsupported, "ping not used"))
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn real_loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    (client.await.unwrap(), server)
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_header_and_payload_round_trip() {
    let (client, mut server) = duplex(4096);
    let destination = Endpoint::ip(
        Network::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
    );
    let password = [7u8; 32];
    let client_task = tokio::spawn(async move {
        let mut session = AsyncYuubinsyaTcpSession::connect(client, password, destination)
            .await
            .unwrap();
        session.write_all(b"hello").await.unwrap();
        session
    });
    let mut header = vec![0u8; 1 + 32 + 1 + 4 + 2];
    server.read_exact(&mut header).await.unwrap();
    let (decoded, consumed) = crate::yuubinsya::decode_header(&password, &header).unwrap();
    assert_eq!(decoded.protocol, YuubinsyaProtocol::Tcp);
    assert_eq!(consumed, header.len());
    let mut payload = [0u8; 5];
    server.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"hello");
    let _ = client_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn real_loopback_tcp_session_preserves_half_close_and_idempotent_shutdown() {
    let (client_io, mut server_io) = real_loopback_pair().await;
    let password = [31u8; 32];
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.31:443".parse().unwrap());
    let server_task = tokio::spawn(async move {
        let header = read_header_bytes(&mut server_io).await?;
        let (header, _) = decode_header(&password, &header)?;
        assert_eq!(header.protocol, YuubinsyaProtocol::Tcp);
        let mut request = [0u8; 10];
        server_io.read_exact(&mut request).await.map_err(io_error)?;
        assert_eq!(&request, b"half-close");
        server_io.write_all(b"response").await.map_err(io_error)?;
        server_io.flush().await.map_err(io_error)?;
        server_io.shutdown().await.map_err(io_error)?;
        let mut after_eof = [0u8; 1];
        let length = server_io.read(&mut after_eof).await.map_err(io_error)?;
        assert_eq!(length, 0, "client did not send a TCP half-close");
        Result::<()>::Ok(())
    });

    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
        .await
        .unwrap();
    client.write_all(b"half-close").await.unwrap();
    let mut response = [0u8; 8];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
    let mut eof = [0u8; 1];
    assert_eq!(client.read(&mut eof).await.unwrap(), 0);
    client.shutdown().await.unwrap();
    client
        .shutdown()
        .await
        .expect("repeated TCP shutdown must be idempotent");
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("real TCP half-close server task did not exit")
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn real_loopback_uot_peer_exit_wakes_recv_and_shutdown_is_idempotent() {
    let (client_io, server_io) = real_loopback_pair().await;
    let password = [32u8; 32];
    let server_task = tokio::spawn(async move {
        let session = AsyncYuubinsyaUotServerSession::accept(server_io, password, 7331).await?;
        drop(session);
        Result::<()>::Ok(())
    });
    let client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("real TCP peer-exit task did not finish")
        .unwrap()
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), client.recv_from())
        .await
        .expect("UOT recv remained pending after peer exit")
        .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Io | ErrorKind::Closed));
    client.shutdown().await.unwrap();
    client
        .shutdown()
        .await
        .expect("repeated UOT shutdown must be idempotent");
}

#[tokio::test(flavor = "current_thread")]
async fn server_proxy_reuses_one_upstream_datagram_across_migrated_streams() {
    let password = [11u8; 32];
    let opens = Arc::new(AtomicUsize::new(0));
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::clone(&opens),
        tcp_echo: false,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let destination = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);

    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(server_io).await })
    };
    let first = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
        .await
        .unwrap();
    first.send_to(&destination, b"first").await.unwrap();
    let (_, first_payload) = first.recv_from().await.unwrap();
    assert_eq!(first_payload, b"first");
    let migrate_id = first.migrate_id;
    first.shutdown().await.unwrap();
    let _ = server_task.await.unwrap();

    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(server_io).await })
    };
    let second = AsyncYuubinsyaUotSession::connect(client_io, password, migrate_id, false)
        .await
        .unwrap();
    assert_eq!(second.migrate_id, migrate_id);
    second.send_to(&destination, b"second").await.unwrap();
    let (_, second_payload) = second.recv_from().await.unwrap();
    assert_eq!(second_payload, b"second");
    second.shutdown().await.unwrap();
    let _ = server_task.await.unwrap();
    assert_eq!(opens.load(Ordering::Acquire), 1);
    server.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn server_close_wakes_a_pending_migrated_uot_stream() {
    struct StallDatagram;

    impl AsyncDatagram for StallDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(async { std::future::pending().await })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:1".parse().unwrap()))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct StallUpstream {
        opened: Arc<Notify>,
    }

    impl AsyncProxy for StallUpstream {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "stall upstream has no TCP path",
                ))
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            let opened = Arc::clone(&self.opened);
            Box::pin(async move {
                opened.notify_one();
                Ok(Box::new(StallDatagram) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let password = [17u8; 32];
    let opened = Arc::new(Notify::new());
    let upstream: Arc<dyn AsyncProxy> = Arc::new(StallUpstream {
        opened: Arc::clone(&opened),
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(server_io).await })
    };
    let client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
        .await
        .unwrap();
    let destination = Endpoint::ip(Network::Udp, "192.0.2.17:5353".parse().unwrap());
    client
        .send_to(&destination, b"pending-close")
        .await
        .unwrap();
    opened.notified().await;

    let pending = tokio::spawn(async move { client.recv_from().await });
    tokio::task::yield_now().await;
    server.close().await;
    let result = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("server close did not wake pending UOT recv")
        .unwrap();
    assert!(
        matches!(result, Err(error) if matches!(error.kind, ErrorKind::Io | ErrorKind::Closed))
    );

    let server_result = tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server UOT task did not exit after close")
        .unwrap();
    assert!(server_result.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn server_proxy_routes_concurrent_migrated_streams_to_their_endpoints() {
    let password = [13u8; 32];
    let opens = Arc::new(AtomicUsize::new(0));
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::clone(&opens),
        tcp_echo: false,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let first_destination = Endpoint::ip(Network::Udp, "192.0.2.11:5300".parse().unwrap());
    let second_destination = Endpoint::ip(Network::Udp, "192.0.2.12:5300".parse().unwrap());

    let (first_client_io, first_server_io) = duplex(4096);
    let first_server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(first_server_io).await })
    };
    let first = AsyncYuubinsyaUotSession::connect(first_client_io, password, 0, false)
        .await
        .unwrap();
    let migrate_id = first.migrate_id;

    let (second_client_io, second_server_io) = duplex(4096);
    let second_server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(second_server_io).await })
    };
    let second = AsyncYuubinsyaUotSession::connect(second_client_io, password, migrate_id, false)
        .await
        .unwrap();

    first
        .send_to(&first_destination, b"first-concurrent")
        .await
        .unwrap();
    second
        .send_to(&second_destination, b"second-concurrent")
        .await
        .unwrap();

    let (first_source, first_payload) = first.recv_from().await.unwrap();
    let (second_source, second_payload) = second.recv_from().await.unwrap();
    assert_eq!(first_source, first_destination);
    assert_eq!(first_payload, b"first-concurrent");
    assert_eq!(second_source, second_destination);
    assert_eq!(second_payload, b"second-concurrent");
    assert_eq!(opens.load(Ordering::Acquire), 1);

    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    let _ = first_server_task.await;
    let _ = second_server_task.await;
    server.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn server_proxy_dispatches_tcp_and_ping_to_the_injected_upstream() {
    let password = [12u8; 32];
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::new(AtomicUsize::new(0)),
        tcp_echo: true,
        ping_ok: true,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());

    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(server_io).await })
    };
    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination.clone())
        .await
        .unwrap();
    client.write_all(b"tcp").await.unwrap();
    let mut response = [0u8; 3];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"tcp");
    client.shutdown().await.unwrap();
    server_task.await.unwrap().unwrap();

    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.serve(server_io).await })
    };
    let (mut client, initial) =
        AsyncYuubinsyaPingSession::connect(client_io, password, destination)
            .await
            .unwrap();
    assert!(initial >= Duration::ZERO);
    assert!(client.ping().await.unwrap() >= Duration::ZERO);
    client.shutdown().await.unwrap();
    server_task.await.unwrap().unwrap();
    server.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn observed_server_proxy_publishes_tcp_lifecycle_and_payload_bytes() {
    let password = [19u8; 32];
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::new(AtomicUsize::new(0)),
        tcp_echo: true,
        ping_ok: true,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let observer = Arc::new(RecordingObserver::default());
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            server
                .serve_observed(
                    server_io,
                    "10.0.0.2:12345".parse().unwrap(),
                    observer,
                    |context| {
                        context.inbound = Some("yuubinsya".to_owned());
                        context.inbound_name = Some("test".to_owned());
                    },
                )
                .await
        })
    };
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
        .await
        .unwrap();
    client.write_all(b"observed").await.unwrap();
    let mut response = [0u8; 8];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"observed");
    client.shutdown().await.unwrap();
    server_task.await.unwrap().unwrap();
    assert_eq!(&*observer.events.lock().unwrap(), &["open", "close"]);
    assert_eq!(observer.bytes.load(Ordering::Acquire), 16);
}

#[tokio::test(flavor = "current_thread")]
async fn server_proxy_hands_authenticated_tcp_to_inbound_stream_handler() {
    let password = [20u8; 32];
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::new(AtomicUsize::new(0)),
        tcp_echo: false,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let handler = Arc::new(RecordingInboundStreamHandler::default());
    let observer = Arc::new(RecordingObserver::default());
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        let handler = Arc::clone(&handler);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            server
                .serve_with_handler(
                    server_io,
                    "10.0.0.2:12348".parse().unwrap(),
                    handler.as_ref(),
                    observer,
                    |_| {},
                    None,
                )
                .await
        })
    };
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination.clone())
        .await
        .unwrap();
    client.write_all(b"handled-by-runtime").await.unwrap();
    client.shutdown().await.unwrap();
    server_task.await.unwrap().unwrap();

    assert_eq!(*handler.destination.lock().unwrap(), Some(destination));
    assert_eq!(*handler.protocol.lock().unwrap(), Some("yuubinsya"));
    assert_eq!(&*handler.payload.lock().unwrap(), b"handled-by-runtime");
}

#[tokio::test(flavor = "current_thread")]
async fn observed_yuubinsya_tcp_hijacks_dns_before_upstream_connect() {
    let password = [21u8; 32];
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::new(AtomicUsize::new(0)),
        tcp_echo: false,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let observer = Arc::new(RecordingObserver::default());
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            server
                .serve_observed_with_dns(
                    server_io,
                    "10.0.0.2:12346".parse().unwrap(),
                    observer,
                    |_| {},
                    Some(Arc::new(EchoDnsHandler)),
                )
                .await
        })
    };
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:53".parse().unwrap());
    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
        .await
        .unwrap();
    let query = yuhaiin_core::dns::encode_query(
        19,
        &DomainName::new("example.com").unwrap(),
        yuhaiin_core::dns::DnsRecordType::A,
    )
    .unwrap();
    client
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    client.write_all(&query).await.unwrap();
    let mut length = [0u8; 2];
    client.read_exact(&mut length).await.unwrap();
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, query);
    assert!(server_task.await.unwrap().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn observed_yuubinsya_tcp_forwards_dns_when_handler_returns_none() {
    let password = [23u8; 32];
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::new(AtomicUsize::new(0)),
        tcp_echo: true,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let observer = Arc::new(RecordingObserver::default());
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            server
                .serve_observed_with_dns(
                    server_io,
                    "10.0.0.2:12349".parse().unwrap(),
                    observer,
                    |_| {},
                    Some(Arc::new(ForwardDnsHandler)),
                )
                .await
        })
    };
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:53".parse().unwrap());
    let mut client = AsyncYuubinsyaTcpSession::connect(client_io, password, destination)
        .await
        .unwrap();
    let query = b"forward-this-dns-packet";
    client
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    client.write_all(query).await.unwrap();
    let mut echoed = vec![0; query.len() + 2];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(
        &echoed,
        &[&(query.len() as u16).to_be_bytes()[..], query].concat()
    );
    client.shutdown().await.unwrap();
    assert!(server_task.await.unwrap().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn observed_yuubinsya_uot_hijacks_dns_without_opening_datagram() {
    let password = [22u8; 32];
    let opens = Arc::new(AtomicUsize::new(0));
    let upstream = Arc::new(EchoUpstream {
        opens: Arc::clone(&opens),
        tcp_echo: false,
        ping_ok: false,
    });
    let server = Arc::new(YuubinsyaServerProxy::new(password, upstream));
    let observer = Arc::new(RecordingObserver::default());
    let (client_io, server_io) = duplex(4096);
    let server_task = {
        let server = Arc::clone(&server);
        let observer = Arc::clone(&observer);
        tokio::spawn(async move {
            server
                .serve_observed_with_dns(
                    server_io,
                    "10.0.0.2:12347".parse().unwrap(),
                    observer,
                    |_| {},
                    Some(Arc::new(EchoDnsHandler)),
                )
                .await
        })
    };
    let client = AsyncYuubinsyaUotSession::connect(client_io, password, 0, false)
        .await
        .unwrap();
    let destination = Endpoint::ip(Network::Udp, "192.0.2.10:53".parse().unwrap());
    let query = yuhaiin_core::dns::encode_query(
        20,
        &DomainName::new("example.com").unwrap(),
        yuhaiin_core::dns::DnsRecordType::A,
    )
    .unwrap();
    client.send_to(&destination, &query).await.unwrap();
    let (response_target, response) = client.recv_from().await.unwrap();
    assert_eq!(response_target, destination);
    assert_eq!(response, query);
    assert_eq!(opens.load(Ordering::Acquire), 0);
    client.shutdown().await.unwrap();
    let _ = server_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn ping_session_reuses_stream_for_follow_up_probe() {
    let (client, mut server) = duplex(4096);
    let password = [6u8; 32];
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
    let server_task = tokio::spawn(async move {
        let mut header = vec![0u8; 1 + 32 + 1 + 4 + 2];
        server.read_exact(&mut header).await.unwrap();
        let (header, _) = crate::yuubinsya::decode_header(&password, &header).unwrap();
        assert_eq!(header.protocol, YuubinsyaProtocol::Ping);
        server.write_all(&1u64.to_be_bytes()).await.unwrap();
        let mut probe = [0u8; 8];
        server.read_exact(&mut probe).await.unwrap();
        assert_eq!(probe, [0; 8]);
        server.write_all(&2u64.to_be_bytes()).await.unwrap();
    });
    let (mut session, first_elapsed) =
        AsyncYuubinsyaPingSession::connect(client, password, destination)
            .await
            .unwrap();
    assert!(first_elapsed >= Duration::ZERO);
    assert!(session.ping().await.unwrap() >= Duration::ZERO);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn ping_server_accepts_header_and_serves_follow_up_probe() {
    let (client, server) = duplex(4096);
    let password = [8u8; 32];
    let destination = Endpoint::ip(Network::Tcp, "192.0.2.20:443".parse().unwrap());
    let expected_destination = destination.clone();
    let server_task = tokio::spawn(async move {
        let (mut session, decoded_destination) =
            AsyncYuubinsyaPingServerSession::accept(server, password)
                .await
                .unwrap();
        assert_eq!(decoded_destination, expected_destination);
        session
            .serve_one_probe(Ok(Duration::from_nanos(1)), Ok(Duration::from_nanos(2)))
            .await
            .unwrap();
    });
    let (mut session, _) = AsyncYuubinsyaPingSession::connect(client, password, destination)
        .await
        .unwrap();
    assert!(session.ping().await.unwrap() >= Duration::ZERO);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_handshake_and_frame_round_trip() {
    let (client, mut server) = duplex(4096);
    let password = [9u8; 32];
    let client_task = tokio::spawn(async move {
        let session = AsyncYuubinsyaUotSession::connect(client, password, 12, true)
            .await
            .unwrap();
        assert_eq!(session.migrate_id, 99);
        let destination =
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        session.send_to(&destination, b"query").await.unwrap();
        session.flush().await.unwrap();
        session
    });
    let mut header = vec![0u8; 1 + 8 + 32];
    server.read_exact(&mut header).await.unwrap();
    let (decoded, _) = crate::yuubinsya::decode_header(&password, &header).unwrap();
    assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
    server.write_all(&99u64.to_be_bytes()).await.unwrap();
    let mut endpoint = [0u8; 1 + 1 + 11 + 2 + 2 + 5];
    server.read_exact(&mut endpoint).await.unwrap();
    let (_, payload, _) = decode_uot_frame(&endpoint).unwrap();
    assert_eq!(payload, b"query");
    let _ = client_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_coalesced_frame_flushes_without_a_follow_up_read() {
    let (client, mut server) = duplex(4096);
    let password = [4u8; 32];
    let destination = Endpoint::ip(Network::Udp, "192.0.2.44:5353".parse().unwrap());
    let expected = encode_uot_frame(&destination, b"one-packet").unwrap();
    let server_task = tokio::spawn(async move {
        let mut header = vec![0u8; 1 + 8 + 32];
        server.read_exact(&mut header).await.unwrap();
        let (decoded, _) = crate::yuubinsya::decode_header(&password, &header).unwrap();
        assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
        server.write_all(&77u64.to_be_bytes()).await.unwrap();
        let mut frame = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut frame))
            .await
            .expect("coalesced UOT frame flush timeout")
            .unwrap();
        assert_eq!(frame, expected);
    });

    let client = AsyncYuubinsyaUotSession::connect(client, password, 0, true)
        .await
        .unwrap();
    client.send_to(&destination, b"one-packet").await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_server_assigns_zero_migration_and_round_trips_frames() {
    let (client, server) = duplex(4096);
    let password = [5u8; 32];
    let destination = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
    let expected_destination = destination.clone();
    let server_task = tokio::spawn(async move {
        let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 99)
            .await
            .unwrap();
        assert_eq!(session.migrate_id, 99);
        let (decoded_destination, payload) = session.recv_from().await.unwrap();
        assert_eq!(decoded_destination, expected_destination);
        assert_eq!(payload, b"query");
        session
            .send_to(&expected_destination, b"answer")
            .await
            .unwrap();
    });
    let client = AsyncYuubinsyaUotSession::connect(client, password, 0, false)
        .await
        .unwrap();
    assert_eq!(client.migrate_id, 99);
    client.send_to(&destination, b"query").await.unwrap();
    let (decoded_destination, payload) = client.recv_from().await.unwrap();
    assert_eq!(decoded_destination, destination);
    assert_eq!(payload, b"answer");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_server_handles_fragmented_max_payload_and_truncated_frame() {
    let password = [8u8; 32];
    let destination = Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap());
    let payload = vec![0x5a; u16::MAX as usize];
    let header = encode_header(
        &password,
        &YuubinsyaHeader {
            protocol: YuubinsyaProtocol::UdpWithMigrateId,
            migrate_id: Some(0),
            destination: None,
        },
    )
    .unwrap();
    let frame = encode_uot_frame(&destination, &payload).unwrap();

    let (mut client, server) = duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 123)
            .await
            .unwrap();
        let (decoded_destination, decoded_payload) = session.recv_from().await.unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(decoded_payload, payload);
    });
    for chunk in header.chunks(3) {
        client.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut assigned = [0u8; 8];
    client.read_exact(&mut assigned).await.unwrap();
    assert_eq!(u64::from_be_bytes(assigned), 123);
    for chunk in frame.chunks(257) {
        client.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
    server_task.await.unwrap();

    let (mut client, server) = duplex(4096);
    let server_task = tokio::spawn(async move {
        let mut session = AsyncYuubinsyaUotServerSession::accept(server, password, 123)
            .await
            .unwrap();
        assert!(session.recv_from().await.is_err());
    });
    client.write_all(&header).await.unwrap();
    client.read_exact(&mut assigned).await.unwrap();
    client.write_all(&frame[..frame.len() - 1]).await.unwrap();
    client.shutdown().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_frame_reader_rejects_bounded_random_wire_without_hanging() {
    for length in 0..512 {
        let (mut writer, mut reader) = duplex(4096);
        let mut state = 0x9e37_79b9_u32 ^ length as u32;
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        writer.write_all(&bytes).await.unwrap();
        writer.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(50), read_uot_frame(&mut reader))
            .await
            .expect("random UOT wire input left the frame reader pending");
        assert!(result.is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn uot_reconnect_can_roll_over_to_a_new_h2_stream_with_the_same_migration() {
    let password = [6u8; 32];
    let (first_client, first_server) = duplex(4096);
    let first_server_task = tokio::spawn(async move {
        let session = AsyncYuubinsyaUotServerSession::accept(first_server, password, 77)
            .await
            .unwrap();
        assert_eq!(session.migrate_id, 77);
    });
    let first_client = AsyncYuubinsyaUotSession::connect(first_client, password, 0, false)
        .await
        .unwrap();
    assert_eq!(first_client.migrate_id, 77);
    drop(first_client);
    first_server_task.await.unwrap();

    let (second_client, second_server) = duplex(4096);
    let second_server_task = tokio::spawn(async move {
        let session = AsyncYuubinsyaUotServerSession::accept(second_server, password, 99)
            .await
            .unwrap();
        assert_eq!(session.migrate_id, 77);
    });
    let second_client = AsyncYuubinsyaUotSession::connect(second_client, password, 77, false)
        .await
        .unwrap();
    assert_eq!(second_client.migrate_id, 77);
    second_server_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn uot_coalesce_flushes_multiple_bounded_frames() {
    let (client, mut server) = duplex(4096);
    let password = [4u8; 32];
    let first_destination =
        Endpoint::domain(Network::Udp, DomainName::new("one.example").unwrap(), 53);
    let second_destination = Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap());
    let first = encode_uot_frame(&first_destination, b"one").unwrap();
    let second = encode_uot_frame(&second_destination, b"two").unwrap();
    let client_task = tokio::spawn(async move {
        let session = AsyncYuubinsyaUotSession::connect(client, password, 12, true)
            .await
            .unwrap();
        session.send_to(&first_destination, b"one").await.unwrap();
        session.send_to(&second_destination, b"two").await.unwrap();
        assert_eq!(
            session.writer.as_ref().unwrap().lock().await.pending_frames,
            2
        );
        session.flush().await.unwrap();
    });
    let mut header = vec![0u8; 1 + 8 + 32];
    server.read_exact(&mut header).await.unwrap();
    server.write_all(&99u64.to_be_bytes()).await.unwrap();
    client_task.await.unwrap();
    let mut frames = vec![0u8; first.len() + second.len()];
    server.read_exact(&mut frames).await.unwrap();
    let (_, first_payload, consumed) = decode_uot_frame(&frames).unwrap();
    assert_eq!(first_payload, b"one");
    let (_, second_payload, second_consumed) = decode_uot_frame(&frames[consumed..]).unwrap();
    assert_eq!(second_payload, b"two");
    assert_eq!(consumed + second_consumed, frames.len());
}
