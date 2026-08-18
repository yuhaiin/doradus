//! Cross-language Yuubinsya acceptance.
//!
//! The normal unit tests exercise both sides of the protocol in Rust.  This
//! ignored test adds the real Go fixed+Yuubinsya client and covers the wire
//! paths that are easiest to accidentally drift: TCP, UDP-over-TCP, native
//! authenticated UDP, and Ping.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use yuhaiin_chain::{ChainClient, YuubinsyaServerProxy};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_protocol::yuubinsya::derive_salt;
use yuhaiin_protocol::yuubinsya_udp::YuubinsyaUdpServer;

const PASSWORD: &str = "rust-go-interop";

struct GoServerProcess(Option<Child>);

impl Drop for GoServerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct EchoProxy;

struct EchoDatagram {
    sender: mpsc::Sender<(Vec<u8>, Endpoint)>,
    receiver: Mutex<mpsc::Receiver<(Vec<u8>, Endpoint)>>,
}

impl AsyncProxy for EchoProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        Box::pin(async move {
            let address = destination.addr().ok_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "interop TCP target has no address")
            })?;
            let stream = TcpStream::connect(address).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("interop TCP target: {error}"))
            })?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            let (sender, receiver) = mpsc::channel(32);
            Ok(Box::new(EchoDatagram {
                sender,
                receiver: Mutex::new(receiver),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async { Ok(Duration::from_millis(1)) })
    }
}

impl AsyncDatagram for EchoDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let sender = self.sender.clone();
        let payload = payload.to_vec();
        Box::pin(async move {
            let length = payload.len();
            sender
                .send((payload, target))
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "interop datagram closed"))?;
            Ok(length)
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut receiver = self.receiver.lock().await;
            let (payload, target) = receiver
                .recv()
                .await
                .ok_or_else(|| Error::new(ErrorKind::Closed, "interop datagram closed"))?;
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "interop datagram buffer is too small",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            "127.0.0.1:0".parse().expect("valid interop address"),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the Go checkout and an available Go toolchain"]
async fn go_client_round_trips_against_rust_yuubinsya_server() {
    let password_hash = derive_salt(PASSWORD.as_bytes());

    let echo_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP echo target");
    let echo_address = echo_listener.local_addr().expect("TCP echo address");
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo_listener.accept().await.expect("accept echo target");
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    let length = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(length) => length,
                    };
                    if stream.write_all(&buffer[..length]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Rust Yuubinsya TCP listener");
    let server_address = listener.local_addr().expect("Rust Yuubinsya address");
    let udp_server = YuubinsyaUdpServer::bind(server_address, password_hash, false)
        .await
        .expect("bind Rust Yuubinsya UDP listener");

    let proxy = Arc::new(YuubinsyaServerProxy::new(
        password_hash,
        Arc::new(EchoProxy),
    ));
    let tcp_task = {
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept Yuubinsya stream");
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    let _ = proxy.serve(stream).await;
                });
            }
        })
    };
    let udp_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let (length, target, peer) = match udp_server.recv_from(&mut buffer).await {
                Ok(value) => value,
                Err(_) => return,
            };
            let _ = udp_server.send_to(&buffer[..length], target, peer).await;
        }
    });

    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/yuubinsya_go_client.go");
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin"));
    let go_tmp = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&go_tmp).expect("create Go temp directory");
    let server = server_address.to_string();
    let tcp_target = echo_address.to_string();
    let udp_target = "127.0.0.1:5353".to_owned();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args([
                "run",
                helper.to_str().expect("interop helper path is UTF-8"),
                &server,
                &tcp_target,
                &udp_target,
            ])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", go_tmp)
            .output()
    })
    .await
    .expect("join Go interoperability probe")
    .expect("start Go interoperability probe");

    tcp_task.abort();
    udp_task.abort();
    echo_task.abort();

    assert!(
        output.status.success(),
        "Go Yuubinsya interoperability probe failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the Go checkout and an available Go toolchain"]
async fn rust_client_round_trips_and_measures_uot_against_go_server() {
    let port_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve Go Yuubinsya port");
    let port = port_listener
        .local_addr()
        .expect("Go Yuubinsya port")
        .port();
    drop(port_listener);

    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/yuubinsya_go_server.go");
    let go_root = std::env::var_os("YUHAIIN_GO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/asutorufa/Documents/Programming/yuhaiin"));
    let go_tmp = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust/go-tmp");
    std::fs::create_dir_all(&go_tmp).expect("create Go temp directory");

    let go_server = GoServerProcess(Some(
        Command::new("go")
            .args([
                "run",
                helper.to_str().expect("Go helper path is UTF-8"),
                &port.to_string(),
            ])
            .current_dir(go_root)
            .env("GOEXPERIMENT", "jsonv2,greenteagc")
            .env("GOTMPDIR", go_tmp)
            .env("YUHAIIN_TEST_PASSWORD", PASSWORD)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Go Yuubinsya server"),
    ));

    let address = format!("127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..200 {
        if TcpStream::connect(&address).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Go Yuubinsya server did not become ready");

    let config = format!(
        r#"{{
            "chain": [
                {{"type":"fixedv2","fixedv2":{{"addresses":[{{"host":"127.0.0.1:{port}"}}]}}}},
                {{"type":"http2","http2":{{"concurrency":8}}}},
                {{"type":"yuubinsya","yuubinsya":{{"password":"{PASSWORD}","udp_coalesce":true,"udp_over_stream":true}}}}
            ]
        }}"#
    );
    let client = ChainClient::from_json(&config).expect("parse Rust H2/UOT client config");
    let session = tokio::time::timeout(Duration::from_secs(10), client.connect_uot(0))
        .await
        .expect("Rust H2/UOT handshake timeout")
        .expect("Rust H2/UOT handshake with Go server");
    let session = Arc::new(session);
    let target = Endpoint::ip(Network::Udp, "127.0.0.1:5353".parse().unwrap());
    let packet_count = 4096usize;
    let packet_size = 1200usize;
    let started = std::time::Instant::now();
    let sender_session = Arc::clone(&session);
    let sender = tokio::spawn(async move {
        for sequence in 0..packet_count {
            let mut payload = vec![0u8; packet_size];
            payload[..8].copy_from_slice(&(sequence as u64).to_be_bytes());
            sender_session
                .send_to(&target, &payload)
                .await
                .expect("send Rust UOT packet to Go server");
        }
        sender_session.flush().await.expect("flush Rust UOT sender");
    });

    let receiver_session = Arc::clone(&session);
    let receiver = tokio::spawn(async move {
        let mut response = vec![0u8; packet_size];
        for sequence in 0..packet_count {
            let (_, payload) =
                tokio::time::timeout(Duration::from_secs(20), receiver_session.recv_from())
                    .await
                    .expect("receive Rust UOT packet from Go server")
                    .expect("Rust UOT receive from Go server");
            assert_eq!(payload.len(), packet_size);
            response.copy_from_slice(&payload);
            assert_eq!(
                u64::from_be_bytes(response[..8].try_into().unwrap()),
                sequence as u64
            );
        }
    });
    sender.await.expect("Rust UOT sender task");
    receiver.await.expect("Rust UOT receiver task");
    let elapsed = started.elapsed();
    let wire_bits = (packet_count * packet_size * 2 * 8) as f64;
    eprintln!(
        "Go Yuubinsya UOT echo: {} packets x {} bytes in {:.3}s ({:.2} Mbit/s wire payload)",
        packet_count,
        packet_size,
        elapsed.as_secs_f64(),
        wire_bits / elapsed.as_secs_f64() / 1_000_000.0
    );

    let session = match Arc::try_unwrap(session) {
        Ok(session) => session,
        Err(_) => panic!("Rust UOT session has no task owners"),
    };
    session.shutdown().await.expect("close Rust UOT client");
    client.close().await;
    drop(go_server);
}
