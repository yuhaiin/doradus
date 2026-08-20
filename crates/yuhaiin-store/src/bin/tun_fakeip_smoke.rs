//! Privileged cross-crate smoke test for the first TUN DNS path.
//!
//! This deliberately uses an in-process HTTP/2 DoH peer.  It exercises the
//! same `H2DohClient`, async resolver adapter, persistent FakeIP pool and
//! `TunProxyRuntime` that production code composes, without depending on an
//! external network or a C-backed HTTP/TUN library.

use std::env;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Response, StatusCode, header};
use tokio::io::DuplexStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, decode_response, encode_query,
    encode_response,
};
use yuhaiin_core::http2::{H2DohClient, H2DohConnector};
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, BoxAsyncStream, DropAsyncProxy, StaticProxySelector,
};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network,
    Result as CoreResult,
};
use yuhaiin_store::ConfigStore;
use yuhaiin_store::fakeip::{
    AsyncDomainResolver, FakeIpAnswerTransform, FakeIpAsyncDnsHandler, FakeIpConfig, FakeIpPool,
    FakeIpPoolOptions,
};
use yuhaiin_tun::{TunConfig, TunDispatcher, TunProxyRuntime, TunRuntime};

const FAKEIP_START: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 10);
const FAKEIP_END: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 14);

#[derive(Clone, Copy)]
struct InProcessDohConnector;

impl H2DohConnector for InProcessDohConnector {
    type Stream = DuplexStream;

    fn connect<'a>(&'a self, _uri: &'a http::Uri) -> BoxFuture<'a, CoreResult<Self::Stream>> {
        Box::pin(async {
            let (client, server) = tokio::io::duplex(16 * 1024);
            tokio::spawn(async move {
                if let Err(error) = serve_doh(server).await {
                    eprintln!("in-process DoH server: {error}");
                }
            });
            Ok(client)
        })
    }
}

struct DohResolver {
    client: H2DohClient<InProcessDohConnector>,
}

impl AsyncDomainResolver for DohResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, CoreResult<DnsResponse>> {
        Box::pin(async move { self.client.query(domain, record_type).await })
    }
}

struct FakeIpDnsProxy {
    handler: Arc<dyn AsyncDnsHandler>,
}

struct FakeIpDnsDatagram {
    handler: Arc<dyn AsyncDnsHandler>,
    responses: Mutex<mpsc::Receiver<(Vec<u8>, Endpoint)>>,
    response_tx: mpsc::Sender<(Vec<u8>, Endpoint)>,
    local_addr: Endpoint,
}

impl AsyncProxy for FakeIpDnsProxy {
    fn connect<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, CoreResult<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "fake-IP DNS proxy only supports UDP",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, CoreResult<Box<dyn AsyncDatagram>>> {
        let (response_tx, response_rx) = mpsc::channel(16);
        let datagram = FakeIpDnsDatagram {
            handler: Arc::clone(&self.handler),
            responses: Mutex::new(response_rx),
            response_tx,
            local_addr: Endpoint::ip(Network::Udp, "127.0.0.1:0".parse().expect("loopback")),
        };
        Box::pin(async move { Ok(Box::new(datagram) as Box<dyn AsyncDatagram>) })
    }

    fn close(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AsyncDatagram for FakeIpDnsDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: Endpoint,
    ) -> BoxFuture<'a, CoreResult<usize>> {
        let handler = Arc::clone(&self.handler);
        let response_tx = self.response_tx.clone();
        Box::pin(async move {
            let response = handler.answer(payload).await?;
            response_tx
                .send((response, target))
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "fake-IP DNS proxy closed"))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> BoxFuture<'a, CoreResult<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut responses = self.responses.lock().await;
            let Some((payload, source)) = responses.recv().await else {
                return Err(Error::new(ErrorKind::Closed, "fake-IP DNS proxy closed"));
            };
            if payload.len() > buffer.len() {
                return Err(Error::new(
                    ErrorKind::Io,
                    "fake-IP DNS response buffer is too small",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), source))
        })
    }

    fn local_addr(&self) -> CoreResult<Endpoint> {
        Ok(self.local_addr.clone())
    }

    fn close(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn serve_doh(stream: DuplexStream) -> Result<(), String> {
    let mut connection = h2::server::handshake(stream)
        .await
        .map_err(|error| format!("handshake: {error}"))?;
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            result = connection.accept() => {
                let Some(result) = result else { break };
                let (request, respond) = result.map_err(|error| format!("request: {error}"))?;
                streams.spawn(serve_doh_request(request, respond));
            }
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                result.map_err(|error| format!("DoH request task: {error}"))??;
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    Ok(())
}

async fn serve_doh_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> Result<(), String> {
    if request.method() != http::Method::POST {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .map_err(|error| format!("response: {error}"))?;
        respond
            .send_response(response, true)
            .map_err(|error| format!("send status: {error}"))?;
        return Ok(());
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/dns-message")
    {
        return Err("DoH request content type mismatch".to_owned());
    }

    let mut body = request.into_body();
    let mut query = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| format!("request body: {error}"))?;
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|error| format!("request flow control: {error}"))?;
        query.extend_from_slice(&chunk);
    }
    let question = decode_query(&query).map_err(|error| error.to_string())?;
    let response = encode_response(
        &query,
        &DnsResponse {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(192, 0, 2, 53)],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(30),
        },
    )
    .map_err(|error| format!("encode response: {error}"))?;
    if question.record_type != DnsRecordType::A {
        return Err("smoke DoH server received a non-A query".to_owned());
    }
    let response_head = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .body(())
        .map_err(|error| format!("response: {error}"))?;
    let mut send = respond
        .send_response(response_head, false)
        .map_err(|error| format!("send response: {error}"))?;
    send.send_data(Bytes::from(response), true)
        .map_err(|error| format!("send body: {error}"))?;
    Ok(())
}

fn database_path() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os("YUHAIIN_TUN_FAKEIP_DB") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".cache/yuhaiin-rust-check")
        .join(format!("tun-fakeip-smoke-{}.sqlite", std::process::id())))
}

fn main() -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> io::Result<()> {
    let path = database_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let store = ConfigStore::open(&path)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let config = FakeIpConfig::new(FAKEIP_START, FAKEIP_END)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let pool = Arc::new(
        FakeIpPool::open_with_prefix(
            store,
            config,
            "198.18.0.0/15",
            FakeIpPoolOptions {
                max_entries: 5,
                ttl_seconds: 300,
                touch_interval_seconds: 1,
            },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()))?,
    );
    let resolver = DohResolver {
        client: H2DohClient::new(
            "https://in-process.invalid/dns-query"
                .parse()
                .map_err(|error| io::Error::other(format!("DoH URI: {error}")))?,
            InProcessDohConnector,
        ),
    };
    let mut tun = TunRuntime::open(TunConfig {
        name: env::var("YUHAIIN_TUN_NAME").ok(),
        ipv4: Some((
            "10.0.0.1"
                .parse()
                .map_err(|error| io::Error::other(format!("TUN address: {error}")))?,
            24,
        )),
        ipv6: Vec::new(),
        mtu: 1500,
        queue_capacity: 16,
        skip_multicast: false,
    })?;
    tun.replace_ip_addresses(&[
        smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(
                "10.0.0.2"
                    .parse()
                    .map_err(|error| io::Error::other(format!("TUN virtual address: {error}")))?,
            ),
            24,
        ),
        smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4("10.0.0.1".parse().expect("literal IPv4")),
            24,
        ),
    ])
    .map_err(|error| io::Error::other(error.to_string()))?;

    let query_domain =
        DomainName::new("example.com").map_err(|error| io::Error::other(error.to_string()))?;
    let query = encode_query(53, &query_domain, DnsRecordType::A)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<Ipv4Addr, String>>();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<Ipv4Addr, String>>();
    let client = std::thread::spawn(move || -> io::Result<()> {
        let result = (|| -> io::Result<Ipv4Addr> {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            // Let the TUN dispatcher enter its first receive cycle before the
            // kernel-facing UDP packet is injected.
            std::thread::sleep(Duration::from_millis(50));
            socket.send_to(&query, "10.0.0.2:53")?;
            let mut response = [0u8; 4096];
            let (length, _) = socket.recv_from(&mut response)?;
            let response = decode_response(&response[..length], 53, DnsRecordType::A)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let fake_ip = response.addresses.v4.first().copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DoH/FakeIP response has no A")
            })?;
            if !(FAKEIP_START..=FAKEIP_END).contains(&fake_ip) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("FakeIP address outside configured pool: {fake_ip}"),
                ));
            }
            Ok(fake_ip)
        })();
        let signal = result.as_ref().copied().map_err(ToString::to_string);
        let _ = done_tx.send(signal);
        result.map(|_| ())
    });

    let dns_proxy: Arc<dyn AsyncProxy> = Arc::new(FakeIpDnsProxy {
        handler: Arc::new(FakeIpAsyncDnsHandler {
            upstream: resolver,
            transform: FakeIpAnswerTransform {
                pool: Arc::clone(&pool),
            },
        }),
    });
    let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop_proxy),
        proxy: dns_proxy,
        bypass: Arc::clone(&drop_proxy),
        drop: drop_proxy,
    });
    let mut proxy_runtime =
        TunProxyRuntime::new(selector, 32).map_err(|error| io::Error::other(error.to_string()))?;
    let mut dispatcher =
        TunDispatcher::new(2048, 2048, 16).map_err(|error| io::Error::other(error.to_string()))?;
    tun.run_dispatcher_until(&mut dispatcher, &mut proxy_runtime, async move {
        let result = done_rx
            .await
            .unwrap_or_else(|_| Err("DNS client stopped".into()));
        let _ = result_tx.send(result);
    })
    .await
    .map_err(|error| io::Error::other(format!("TUN dispatcher: {error}")))?;
    proxy_runtime.close();

    let fake_ip = result_rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "smoke result channel closed"))?
        .map_err(io::Error::other)?;
    client
        .join()
        .map_err(|_| io::Error::other("TUN DNS client thread panicked"))??;
    let mapped = pool.lookup_domain(fake_ip).await;
    if mapped.as_ref() != Some(&query_domain) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("FakeIP reverse lookup mismatch: {mapped:?}"),
        ));
    }
    pool.flush_touches()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    tun.shutdown()?;
    println!(
        "tun-fakeip-doh-echo-ok fake_ip={fake_ip} db={}",
        path.display()
    );
    Ok(())
}
