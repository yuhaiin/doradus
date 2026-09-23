//! Minimal privileged Linux smoke test for the one supported TUN path.
//!
//! The binary creates one TUN device and provides small privileged smoke modes.
//! It intentionally does not configure host routes or start a second network
//! stack.

use std::env;
use std::net::Ipv6Addr;
use std::thread;
use std::time::Duration;

use doradus_tun::{TunConfig, TunRuntime};
use smoltcp::iface::SocketSet;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::icmp;
use smoltcp::time::Instant;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpVersion, Ipv4Packet};

fn main() -> std::io::Result<()> {
    if env::var_os("DORADUS_TUN_BENCH_SERVER").is_some() {
        return run_proxy_throughput_server();
    }
    if env::var_os("DORADUS_TUN_BENCH_CLIENT").is_some() {
        return run_proxy_throughput_client();
    }

    let name = env::var("DORADUS_TUN_NAME").ok();
    let hold_ms = env::var("DORADUS_TUN_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2_000);
    let read_once = env::var_os("DORADUS_TUN_READ_ONCE").is_some();
    let echo = env::var_os("DORADUS_TUN_ECHO").is_some();
    let proxy_echo = env::var_os("DORADUS_TUN_PROXY_ECHO").is_some();
    let udp_proxy_echo = env::var_os("DORADUS_TUN_UDP_PROXY_ECHO").is_some();
    let proxy_throughput = env::var_os("DORADUS_TUN_PROXY_THROUGHPUT").is_some();
    let route_smoke = env::var_os("DORADUS_TUN_ROUTE_SMOKE").is_some();
    let ipv6 = env::var("DORADUS_TUN_IPV6")
        .ok()
        .map(|value| {
            let (address, prefix) = value
                .split_once('/')
                .ok_or_else(|| std::io::Error::other("DORADUS_TUN_IPV6 needs address/prefix"))?;
            let address: Ipv6Addr = address
                .parse()
                .map_err(|error| std::io::Error::other(format!("invalid IPv6 address: {error}")))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|error| std::io::Error::other(format!("invalid IPv6 prefix: {error}")))?;
            if prefix > 128 {
                return Err(std::io::Error::other("IPv6 prefix is greater than 128"));
            }
            Ok((address, prefix))
        })
        .transpose()?;
    let queue_capacity = env::var("DORADUS_TUN_QUEUE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(doradus_tun::DEFAULT_QUEUE_CAPACITY);
    let mut runtime = TunRuntime::open(TunConfig {
        name,
        ipv4: ipv6
            .is_none()
            .then(|| ("10.0.0.1".parse().expect("literal IPv4"), 24)),
        ipv6: ipv6.iter().copied().collect(),
        mtu: 1500,
        queue_capacity,
        skip_multicast: false,
    })?;
    if route_smoke {
        #[cfg(all(feature = "tun-routes", target_os = "linux"))]
        {
            use doradus_tun::TunRoute;

            // Keep the route smoke independent from the service fixture's
            // single /32 route.  Multiple disjoint prefixes exercise the
            // same netlink lease with both the normal and metric-bearing
            // route forms, and let the container assert that every owned
            // route disappears when the process exits.
            let mut metered = TunRoute::new(
                "203.0.113.0"
                    .parse()
                    .expect("literal route destination IPv4"),
                24,
            )
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            metered.metric = Some(42_424);
            let mut routes = vec![
                TunRoute::new(
                    "198.18.0.0"
                        .parse()
                        .expect("literal route destination IPv4"),
                    15,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?,
                metered,
                TunRoute::new(
                    "192.0.2.0".parse().expect("literal route destination IPv4"),
                    24,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?,
            ];
            if udp_proxy_echo {
                routes.push(
                    TunRoute::new(
                        "10.0.0.2".parse().expect("literal UDP proxy route IPv4"),
                        32,
                    )
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                );
            }
            runtime.install_linux_routes(&routes)?;
            println!("tun-route-installed count={}", routes.len());
        }
        #[cfg(not(all(feature = "tun-routes", target_os = "linux")))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "DORADUS_TUN_ROUTE_SMOKE requires Linux tun-routes",
            ));
        }
    }
    // Keep 10.0.0.1 as the Linux-facing address and put 10.0.0.2 first in the
    // smoltcp address list. A namespace ping to .2 therefore enters the TUN,
    // while smoltcp emits the echo reply with .2 as its source address.
    let test_addresses = if let Some((address, prefix)) = ipv6 {
        vec![IpCidr::new(IpAddress::Ipv6(address), prefix)]
    } else {
        vec![
            IpCidr::new(
                IpAddress::Ipv4("10.0.0.2".parse().expect("literal IPv4")),
                24,
            ),
            IpCidr::new(
                IpAddress::Ipv4("10.0.0.1".parse().expect("literal IPv4")),
                24,
            ),
        ]
    };
    runtime
        .replace_ip_addresses(&test_addresses)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    // `--network=none` leaves the namespace-local loopback interface down.
    // The proxy benchmark and echo fixture deliberately connect to a local
    // target, so enable only this disposable test namespace; production TUN
    // setup does not use this helper.
    if proxy_throughput || proxy_echo || udp_proxy_echo {
        doradus_tun::enable_loopback()?;
    }
    if proxy_throughput {
        return run_proxy_throughput(runtime);
    }
    if proxy_echo {
        return run_proxy_echo(runtime);
    }
    if udp_proxy_echo {
        return run_udp_proxy_echo(runtime);
    }
    println!("tun-opened");
    println!(
        "rx-queued={}",
        runtime.smoltcp_device().queued_rx().unwrap_or(0)
    );
    if read_once || echo {
        let length = futures_lite::future::block_on(runtime.recv_from_tun())?;
        println!("tun-packet-received length={length}");
        if echo {
            let rx_buffer =
                icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 2], vec![0; 256]);
            let tx_buffer =
                icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 2], vec![0; 256]);
            let ident = loop {
                let packet = runtime
                    .smoltcp_device()
                    .peek_rx_packet()
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "TUN RX queue is empty after receiving a packet",
                        )
                    })?;
                if IpVersion::of_packet(&packet) != Ok(IpVersion::Ipv4) {
                    runtime
                        .smoltcp_device()
                        .take_rx_packet()
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let length = futures_lite::future::block_on(runtime.recv_from_tun())?;
                    println!("tun-packet-received length={length}");
                    continue;
                }
                let ip_packet = match Ipv4Packet::new_checked(&packet) {
                    Ok(packet) => packet,
                    Err(_) => {
                        runtime
                            .smoltcp_device()
                            .take_rx_packet()
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        let length = futures_lite::future::block_on(runtime.recv_from_tun())?;
                        println!("tun-packet-received length={length}");
                        continue;
                    }
                };
                let incoming = match Icmpv4Repr::parse(
                    &Icmpv4Packet::new_checked(ip_packet.payload())
                        .map_err(|error| std::io::Error::other(error.to_string()))?,
                    &ChecksumCapabilities::default(),
                ) {
                    Ok(incoming) => incoming,
                    Err(_) => {
                        runtime
                            .smoltcp_device()
                            .take_rx_packet()
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        let length = futures_lite::future::block_on(runtime.recv_from_tun())?;
                        println!("tun-packet-received length={length}");
                        continue;
                    }
                };
                match incoming {
                    Icmpv4Repr::EchoRequest { ident, .. } => break ident,
                    _ => {
                        runtime
                            .smoltcp_device()
                            .take_rx_packet()
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        let length = futures_lite::future::block_on(runtime.recv_from_tun())?;
                        println!("tun-packet-received length={length}");
                    }
                }
            };
            let mut sockets = SocketSet::new(vec![]);
            let handle = sockets.add(icmp::Socket::new(rx_buffer, tx_buffer));
            sockets
                .get_mut::<icmp::Socket>(handle)
                .bind(icmp::Endpoint::Ident(ident))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            runtime.poll_smoltcp(Instant::from_millis(1), &mut sockets);
            let socket = sockets.get_mut::<icmp::Socket>(handle);
            let (request, endpoint) = socket
                .recv()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let request = Icmpv4Repr::parse(
                &Icmpv4Packet::new_checked(request)
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                &ChecksumCapabilities::default(),
            )
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            let Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } = request
            else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TUN smoke packet is not ICMPv4 echo request",
                ));
            };
            let reply = Icmpv4Repr::EchoReply {
                ident,
                seq_no,
                data,
            };
            let mut reply_bytes = vec![0; reply.buffer_len()];
            reply.emit(
                &mut Icmpv4Packet::new_unchecked(&mut reply_bytes),
                &ChecksumCapabilities::default(),
            );
            socket
                .send_slice(&reply_bytes, endpoint)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            runtime.poll_smoltcp(Instant::from_millis(2), &mut sockets);
            if let Some(packet) = runtime
                .smoltcp_device()
                .peek_tx_packet()
                .map_err(|error| std::io::Error::other(error.to_string()))?
            {
                let packet = Ipv4Packet::new_checked(&packet)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                println!(
                    "tun-packet-ready src={} dst={}",
                    packet.src_addr(),
                    packet.dst_addr()
                );
            }
            let written = futures_lite::future::block_on(runtime.send_to_tun())?;
            if written.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "smoltcp did not produce an ICMP reply",
                ));
            }
            println!("tun-packet-replied");
            thread::sleep(Duration::from_millis(hold_ms));
        }
        return Ok(());
    }
    thread::sleep(Duration::from_millis(hold_ms));
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct ProcessUsage {
    peak_rss_kib: u64,
    samples: u64,
    first_cpu_ticks: Option<u64>,
    last_cpu_ticks: Option<u64>,
}

#[cfg(target_os = "linux")]
impl ProcessUsage {
    fn cpu_ticks(&self) -> u64 {
        self.last_cpu_ticks
            .unwrap_or_default()
            .saturating_sub(self.first_cpu_ticks.unwrap_or_default())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ProcessReading {
    rss_kib: u64,
    cpu_ticks: u64,
}

#[cfg(target_os = "linux")]
fn read_process_usage() -> Option<ProcessReading> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:")?.split_whitespace().next())?
        .parse()
        .ok()?;
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let user_ticks = fields.get(11)?.parse::<u64>().ok()?;
    let system_ticks = fields.get(12)?.parse::<u64>().ok()?;
    Some(ProcessReading {
        rss_kib,
        cpu_ticks: user_ticks.saturating_add(system_ticks),
    })
}

fn run_proxy_throughput_server() -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let bytes = env::var("DORADUS_TUN_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
        .max(1);
    let download =
        env::var("DORADUS_TUN_BENCH_DIRECTION").is_ok_and(|direction| direction == "download");
    let ready_file = env::var_os("DORADUS_TUN_BENCH_SERVER_READY")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| std::io::Error::other("benchmark server ready path is missing"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        std::fs::write(&ready_file, listener.local_addr()?.to_string())?;
        let (mut stream, _) = listener.accept().await?;
        let mut buffer = vec![0u8; 64 * 1024];
        let mut remaining = bytes;
        while remaining > 0 {
            let chunk_len = remaining.min(buffer.len());
            if download {
                buffer[..chunk_len].fill(0x5a);
                stream.write_all(&buffer[..chunk_len]).await?;
                remaining -= chunk_len;
            } else {
                let length = stream.read(&mut buffer[..chunk_len]).await?;
                if length == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "benchmark client closed before sending the payload",
                    ));
                }
                stream.write_all(&buffer[..length]).await?;
                remaining -= length;
            }
        }
        Ok(())
    })
}

fn run_proxy_throughput_client() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::time::Instant;

    let total_bytes = env::var("DORADUS_TUN_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
        .max(1);
    let direction = env::var("DORADUS_TUN_BENCH_DIRECTION").unwrap_or_else(|_| "echo".to_owned());
    let download = direction == "download";
    let mut stream = std::net::TcpStream::connect_timeout(
        &"10.0.0.2:18080".parse().unwrap(),
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let started = Instant::now();
    #[cfg(target_os = "linux")]
    let mut usage = ProcessUsage::default();
    let writer = if download {
        None
    } else {
        let mut writer_stream = stream.try_clone()?;
        writer_stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let payload = vec![0x5a; 64 * 1024];
        Some(thread::spawn(move || -> std::io::Result<()> {
            let mut sent = 0usize;
            while sent < total_bytes {
                let length = (total_bytes - sent).min(payload.len());
                writer_stream.write_all(&payload[..length])?;
                sent += length;
            }
            writer_stream.shutdown(std::net::Shutdown::Write)
        }))
    };
    let mut received = 0usize;
    let mut response = vec![0u8; 64 * 1024];
    #[cfg(target_os = "linux")]
    let mut next_usage_sample = Instant::now();
    while received < total_bytes {
        let length = stream.read(&mut response)?;
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("TUN proxy closed after {received} of {total_bytes} bytes"),
            ));
        }
        if response[..length].iter().any(|byte| *byte != 0x5a) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TUN proxy throughput payload mismatch",
            ));
        }
        received += length;
        #[cfg(target_os = "linux")]
        if Instant::now() >= next_usage_sample {
            if let Some(reading) = read_process_usage() {
                usage.peak_rss_kib = usage.peak_rss_kib.max(reading.rss_kib);
                usage.samples = usage.samples.saturating_add(1);
                usage.first_cpu_ticks.get_or_insert(reading.cpu_ticks);
                usage.last_cpu_ticks = Some(reading.cpu_ticks);
            }
            next_usage_sample = Instant::now() + Duration::from_millis(10);
        }
    }
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| std::io::Error::other("TUN benchmark writer thread panicked"))??;
    }
    #[cfg(target_os = "linux")]
    let (peak_rss_kib, cpu_ticks, proc_samples) =
        (usage.peak_rss_kib, usage.cpu_ticks(), usage.samples);
    #[cfg(not(target_os = "linux"))]
    let (peak_rss_kib, cpu_ticks, proc_samples) = (0, 0, 0);
    let elapsed = started.elapsed();
    println!(
        "BENCHMARK {{\"scenario\":\"tun-inbound-fixed-proxy-loopback-{direction}\",\"bytes\":{received},\"elapsed_ms\":{},\"mib_per_sec\":{},\"peak_rss_kib\":{peak_rss_kib},\"cpu_ticks\":{cpu_ticks},\"proc_samples\":{proc_samples}}}",
        elapsed.as_secs_f64() * 1000.0,
        (received as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64(),
    );
    Ok(())
}

fn run_proxy_throughput(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use doradus_core::proxy::{AsyncProxy, StaticProxySelector};
    use doradus_protocol::proxy::{DropAsyncProxy, FixedAsyncProxy};
    use doradus_tun::{TunDispatcher, TunProxyRuntime};

    let total_bytes = env::var("DORADUS_TUN_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
        .max(1);
    let direction = env::var("DORADUS_TUN_BENCH_DIRECTION").unwrap_or_else(|_| "echo".to_owned());
    if !matches!(direction.as_str(), "echo" | "download") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DORADUS_TUN_BENCH_DIRECTION must be echo or download",
        ));
    }
    let ready_file = std::env::temp_dir().join(format!(
        "doradus-tun-bench-server-{}.addr",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&ready_file);
    let mut target_server = Command::new(std::env::current_exe()?)
        .env("DORADUS_TUN_BENCH_SERVER", "1")
        .env("DORADUS_TUN_BENCH_SERVER_READY", &ready_file)
        .env("DORADUS_TUN_BENCH_DIRECTION", &direction)
        .env("DORADUS_TUN_BENCH_BYTES", total_bytes.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let server_started = Instant::now();
    let target_address = loop {
        if let Ok(address) = std::fs::read_to_string(&ready_file)
            && let Ok(address) = address.trim().parse::<std::net::SocketAddr>()
        {
            break address;
        }
        if let Some(status) = target_server.try_wait()? {
            let _ = std::fs::remove_file(&ready_file);
            return Err(std::io::Error::other(format!(
                "TUN benchmark server exited before ready: {status}"
            )));
        }
        if server_started.elapsed() >= Duration::from_secs(5) {
            let _ = target_server.kill();
            let _ = target_server.wait();
            let _ = std::fs::remove_file(&ready_file);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TUN benchmark server did not become ready",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = async_runtime.block_on(async move {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<String, String>>();
        let client = Command::new(std::env::current_exe()?)
            .env("DORADUS_TUN_BENCH_CLIENT", "1")
            .env("DORADUS_TUN_BENCH_DIRECTION", &direction)
            .env("DORADUS_TUN_BENCH_BYTES", total_bytes.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let client_waiter = thread::spawn(move || {
            let result = client
                .wait_with_output()
                .map_err(|error| error.to_string())
                .and_then(|output| {
                    if !output.status.success() {
                        return Err(format!(
                            "TUN benchmark client exited with {}: {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr).trim()
                        ));
                    }
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .find(|line| line.starts_with("BENCHMARK "))
                        .map(str::to_owned)
                        .ok_or_else(|| "TUN benchmark client omitted its result".to_owned())
                });
            let _ = done_tx.send(());
            let _ = result_tx.send(result);
        });

        let proxy: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address: target_address,
            timeout: Duration::from_secs(10),
        });
        let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = Arc::new(StaticProxySelector {
            direct: Arc::clone(&drop),
            proxy,
            bypass: Arc::clone(&drop),
            drop,
        });
        // Keep the benchmark command/output queues bounded like production;
        // the dispatcher loop itself is responsible for making progress.
        let mut proxy_runtime = TunProxyRuntime::new(selector, 256)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .with_io_timeout(Duration::from_secs(10))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut dispatcher = TunDispatcher::new(4 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        runtime
            .run_dispatcher_until(&mut dispatcher, &mut proxy_runtime, None, async move {
                let _ = done_rx.await;
            })
            .await?;
        proxy_runtime.close();
        let benchmark_line = result_rx
            .await
            .map_err(|_| std::io::Error::other("TUN benchmark result channel closed"))?
            .map_err(std::io::Error::other)?;
        client_waiter
            .join()
            .map_err(|_| std::io::Error::other("TUN benchmark client waiter panicked"))?;
        println!("{benchmark_line}");
        Ok(())
    });
    let _ = target_server.kill();
    let _ = target_server.wait();
    let _ = std::fs::remove_file(&ready_file);
    result
}

fn run_proxy_echo(mut runtime: TunRuntime) -> std::io::Result<()> {
    use doradus_core::proxy::{AsyncProxy, StaticProxySelector};
    use doradus_protocol::proxy::{DropAsyncProxy, FixedAsyncProxy};
    use doradus_tun::{TunDispatcher, TunProxyRuntime};
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(async move {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target_address = target.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await?;
            let mut payload = [0u8; 9];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload).await?;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload).await?;
            Ok::<(), std::io::Error>(())
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let client = std::thread::spawn(move || -> std::io::Result<()> {
            let result = (|| -> std::io::Result<()> {
                let mut stream = std::net::TcpStream::connect_timeout(
                    &"10.0.0.2:18080".parse().unwrap(),
                    Duration::from_secs(5),
                )?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                stream.write_all(b"tun-proxy")?;
                let mut response = [0u8; 9];
                stream.read_exact(&mut response)?;
                if response != *b"tun-proxy" {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TUN proxy echo payload mismatch",
                    ));
                }
                Ok(())
            })();
            let signal = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = done_tx.send(signal);
            result
        });

        let proxy: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address: target_address,
            timeout: Duration::from_secs(2),
        });
        let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = Arc::new(StaticProxySelector {
            direct: Arc::clone(&drop),
            proxy,
            bypass: Arc::clone(&drop),
            drop,
        });
        let mut proxy_runtime = TunProxyRuntime::new(selector, 32)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .with_io_timeout(Duration::from_secs(5))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut dispatcher = TunDispatcher::new(16 * 1024, 16 * 1024, 16)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        runtime
            .run_dispatcher_until(&mut dispatcher, &mut proxy_runtime, None, async move {
                let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                let _ = result_tx.send(result);
            })
            .await?;
        proxy_runtime.close();
        if let Err(message) = result_rx
            .await
            .map_err(|_| std::io::Error::other("TUN proxy result channel closed"))?
        {
            let _ = client.join();
            return Err(std::io::Error::other(message));
        }
        client
            .join()
            .map_err(|_| std::io::Error::other("TUN proxy client thread panicked"))??;
        target_task
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))??;
        println!("tun-proxy-echo-ok");
        Ok(())
    })
}

fn run_udp_proxy_echo(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    use doradus_core::proxy::{AsyncProxy, StaticProxySelector};
    use doradus_protocol::proxy::{DropAsyncProxy, FixedAsyncProxy};
    use doradus_tun::{TunDispatcher, TunProxyRuntime};

    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(async move {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let target_address = target.local_addr()?;
        let target_task = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let (length, peer) = target.recv_from(&mut buffer).await?;
            target.send_to(&buffer[..length], peer).await?;
            Ok::<(), std::io::Error>(())
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let client = std::thread::spawn(move || -> std::io::Result<()> {
            let result = (|| -> std::io::Result<()> {
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                let payload = b"tun-udp-proxy";
                socket.send_to(payload, "10.0.0.2:18080")?;
                let mut response = [0u8; 256];
                let (length, _) = socket.recv_from(&mut response)?;
                if response[..length] != *payload {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TUN UDP proxy echo payload mismatch",
                    ));
                }
                Ok(())
            })();
            let signal = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = done_tx.send(signal);
            result
        });

        let proxy: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address: target_address,
            timeout: Duration::from_secs(2),
        });
        let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = Arc::new(StaticProxySelector {
            direct: Arc::clone(&drop_proxy),
            proxy,
            bypass: Arc::clone(&drop_proxy),
            drop: Arc::clone(&drop_proxy),
        });
        let mut proxy_runtime = TunProxyRuntime::new(selector, 32)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .with_io_timeout(Duration::from_secs(5))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut dispatcher = TunDispatcher::new(2048, 2048, 16)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        runtime
            .run_dispatcher_until(&mut dispatcher, &mut proxy_runtime, None, async move {
                let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                let _ = result_tx.send(result);
            })
            .await?;
        proxy_runtime.close();
        if let Err(message) = result_rx
            .await
            .map_err(|_| std::io::Error::other("TUN UDP proxy result channel closed"))?
        {
            let _ = client.join();
            return Err(std::io::Error::other(message));
        }
        client
            .join()
            .map_err(|_| std::io::Error::other("TUN UDP proxy client thread panicked"))??;
        target_task
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))??;
        println!("tun-udp-proxy-echo-ok");
        Ok(())
    })
}
