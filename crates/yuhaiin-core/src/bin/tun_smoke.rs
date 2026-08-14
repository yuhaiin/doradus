//! Minimal privileged Linux smoke test for the one supported TUN path.
//!
//! The binary creates one TUN device and provides small privileged smoke modes.
//! It intentionally does not configure host routes or start a second network
//! stack.

use std::env;
use std::net::Ipv6Addr;
use std::thread;
use std::time::Duration;

use smoltcp::iface::SocketSet;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::icmp;
use smoltcp::time::Instant;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpVersion, Ipv4Packet};
use yuhaiin_core::tun::{TunConfig, TunRuntime};

fn main() -> std::io::Result<()> {
    let name = env::var("YUHAIIN_TUN_NAME").ok();
    let hold_ms = env::var("YUHAIIN_TUN_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2_000);
    let read_once = env::var_os("YUHAIIN_TUN_READ_ONCE").is_some();
    let echo = env::var_os("YUHAIIN_TUN_ECHO").is_some();
    let proxy_echo = env::var_os("YUHAIIN_TUN_PROXY_ECHO").is_some();
    let udp_proxy_echo = env::var_os("YUHAIIN_TUN_UDP_PROXY_ECHO").is_some();
    let proxy_throughput = env::var_os("YUHAIIN_TUN_PROXY_THROUGHPUT").is_some();
    let dns_echo = env::var_os("YUHAIIN_TUN_DNS_ECHO").is_some();
    let route_smoke = env::var_os("YUHAIIN_TUN_ROUTE_SMOKE").is_some();
    let ipv6 = env::var("YUHAIIN_TUN_IPV6")
        .ok()
        .map(|value| {
            let (address, prefix) = value
                .split_once('/')
                .ok_or_else(|| std::io::Error::other("YUHAIIN_TUN_IPV6 needs address/prefix"))?;
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
    let queue_capacity = env::var("YUHAIIN_TUN_QUEUE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(8);
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
            use yuhaiin_core::tun::TunRoute;

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
                "YUHAIIN_TUN_ROUTE_SMOKE requires Linux tun-routes",
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
        yuhaiin_platform::enable_loopback()?;
    }
    if proxy_throughput {
        #[cfg(feature = "async-proxy")]
        {
            return run_proxy_throughput(runtime);
        }
        #[cfg(not(feature = "async-proxy"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "YUHAIIN_TUN_PROXY_THROUGHPUT requires the async-proxy feature",
            ));
        }
    }
    if proxy_echo {
        #[cfg(feature = "async-proxy")]
        {
            return run_proxy_echo(runtime);
        }
        #[cfg(not(feature = "async-proxy"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "YUHAIIN_TUN_PROXY_ECHO requires the async-proxy feature",
            ));
        }
    }
    if udp_proxy_echo {
        #[cfg(feature = "async-proxy")]
        {
            return run_udp_proxy_echo(runtime);
        }
        #[cfg(not(feature = "async-proxy"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "YUHAIIN_TUN_UDP_PROXY_ECHO requires the async-proxy feature",
            ));
        }
    }
    if dns_echo {
        #[cfg(feature = "async-proxy")]
        {
            return run_dns_echo(runtime);
        }
        #[cfg(not(feature = "async-proxy"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "YUHAIIN_TUN_DNS_ECHO requires the async-proxy feature",
            ));
        }
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

#[cfg(feature = "async-proxy")]
fn run_proxy_throughput(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use yuhaiin_core::proxy::{AsyncProxy, DropAsyncProxy, FixedAsyncProxy, StaticProxySelector};
    use yuhaiin_core::tun::{TunDispatcher, TunProxyRuntime};

    let total_bytes = env::var("YUHAIIN_TUN_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
        .max(1);
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(async move {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target_address = target.local_addr()?;
        let (target_release_tx, target_release_rx) = tokio::sync::oneshot::channel::<()>();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await?;
            let mut buffer = vec![0u8; 64 * 1024];
            let mut remaining = total_bytes;
            while remaining > 0 {
                let chunk_len = remaining.min(buffer.len());
                let length = tokio::io::AsyncReadExt::read(
                    &mut stream,
                    &mut buffer[..chunk_len],
                )
                .await?;
                if length == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "TUN benchmark client closed before target received the payload",
                    ));
                }
                tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer[..length]).await?;
                remaining -= length;
            }
            let _ = target_release_rx.await;
            Ok::<(), std::io::Error>(())
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (metrics_tx, metrics_rx) = mpsc::channel();
        let client = std::thread::spawn(move || -> std::io::Result<()> {
            let result = (|| -> std::io::Result<()> {
                let mut stream = std::net::TcpStream::connect_timeout(
                    &"10.0.0.2:18080".parse().unwrap(),
                    Duration::from_secs(10),
                )?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                let mut writer_stream = stream.try_clone()?;
                writer_stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                let payload = vec![0x5a; 64 * 1024];
                let started = Instant::now();
                #[cfg(target_os = "linux")]
                let mut usage = ProcessUsage::default();
                let writer = std::thread::spawn(move || -> std::io::Result<()> {
                    let mut sent = 0usize;
                    while sent < total_bytes {
                        let length = (total_bytes - sent).min(payload.len());
                        writer_stream.write_all(&payload[..length])?;
                        sent += length;
                    }
                    writer_stream.shutdown(std::net::Shutdown::Write)
                });
                let mut received = 0usize;
                let mut response = vec![0u8; 64 * 1024];
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
                    if let Some(reading) = read_process_usage() {
                        usage.peak_rss_kib = usage.peak_rss_kib.max(reading.rss_kib);
                        usage.samples = usage.samples.saturating_add(1);
                        usage.first_cpu_ticks.get_or_insert(reading.cpu_ticks);
                        usage.last_cpu_ticks = Some(reading.cpu_ticks);
                    }
                }
                let _ = target_release_tx.send(());
                writer
                    .join()
                    .map_err(|_| std::io::Error::other("TUN benchmark writer thread panicked"))??;
                #[cfg(target_os = "linux")]
                let (peak_rss_kib, cpu_ticks, proc_samples) =
                    (usage.peak_rss_kib, usage.cpu_ticks(), usage.samples);
                #[cfg(not(target_os = "linux"))]
                let (peak_rss_kib, cpu_ticks, proc_samples) = (0, 0, 0);
                metrics_tx
                    .send((received, started.elapsed(), peak_rss_kib, cpu_ticks, proc_samples))
                    .map_err(|_| std::io::Error::other("benchmark metrics receiver closed"))?;
                Ok(())
            })();
            let signal = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = done_tx.send(signal);
            result
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
            .run_dispatcher_until(
                &mut dispatcher,
                &mut proxy_runtime,
                Duration::from_millis(1),
                async move {
                    let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                    let _ = result_tx.send(result);
                },
            )
            .await?;
        proxy_runtime.close();
        if let Err(message) = result_rx
            .await
            .map_err(|_| std::io::Error::other("TUN benchmark result channel closed"))?
        {
            let _ = client.join();
            return Err(std::io::Error::other(message));
        }
        client
            .join()
            .map_err(|_| std::io::Error::other("TUN benchmark client thread panicked"))??;
        target_task
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))??;
        let (bytes, elapsed, peak_rss_kib, cpu_ticks, proc_samples) = metrics_rx
            .recv()
            .map_err(|_| std::io::Error::other("TUN benchmark metrics missing"))?;
        println!(
            "BENCHMARK {{\"scenario\":\"tun-inbound-fixed-proxy-loopback\",\"bytes\":{bytes},\"elapsed_ms\":{},\"mib_per_sec\":{},\"peak_rss_kib\":{},\"cpu_ticks\":{},\"proc_samples\":{}}}",
            elapsed.as_secs_f64() * 1000.0,
            (bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64(),
            peak_rss_kib,
            cpu_ticks,
            proc_samples
        );
        Ok(())
    })
}

#[cfg(feature = "async-proxy")]
fn run_proxy_echo(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;
    use yuhaiin_core::proxy::{AsyncProxy, DropAsyncProxy, FixedAsyncProxy, StaticProxySelector};
    use yuhaiin_core::tun::{TunDispatcher, TunProxyRuntime};

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
            .run_dispatcher_until(
                &mut dispatcher,
                &mut proxy_runtime,
                Duration::from_millis(1),
                async move {
                    let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                    let _ = result_tx.send(result);
                },
            )
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

#[cfg(feature = "async-proxy")]
fn run_udp_proxy_echo(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    use yuhaiin_core::proxy::{AsyncProxy, DropAsyncProxy, FixedAsyncProxy, StaticProxySelector};
    use yuhaiin_core::tun::{TunDispatcher, TunProxyRuntime};

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
            .run_dispatcher_until(
                &mut dispatcher,
                &mut proxy_runtime,
                Duration::from_millis(1),
                async move {
                    let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                    let _ = result_tx.send(result);
                },
            )
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

#[cfg(feature = "async-proxy")]
fn run_dns_echo(mut runtime: TunRuntime) -> std::io::Result<()> {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;

    use yuhaiin_core::dns::{
        AsyncDnsHandler, DnsHandler, DnsRecordType, DnsResponse, answer_query, decode_response,
        encode_query,
    };
    use yuhaiin_core::proxy::{AsyncProxy, DropAsyncProxy, StaticProxySelector};
    use yuhaiin_core::tun::{TunDispatcher, TunProxyRuntime};
    use yuhaiin_core::{DomainName, IpSet, LocalBoxFuture, Result as CoreResult};

    struct FixedDns;
    impl DnsHandler for FixedDns {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> CoreResult<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec!["192.0.2.53".parse().expect("literal IPv4")],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }
    impl AsyncDnsHandler for FixedDns {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, CoreResult<Vec<u8>>> {
            Box::pin(async move { answer_query(packet, self) })
        }
    }

    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(async move {
        let dns_port = env::var("YUHAIIN_TUN_DNS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(53);
        let query = encode_query(
            dns_port,
            &DomainName::new("example.com").map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
            })?,
            DnsRecordType::A,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let client = std::thread::spawn(move || -> std::io::Result<()> {
            let result = (|| -> std::io::Result<()> {
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.send_to(
                    &query,
                    SocketAddr::new("10.0.0.2".parse().unwrap(), dns_port),
                )?;
                let mut response = [0u8; 4096];
                let (length, _) = socket.recv_from(&mut response)?;
                let response = decode_response(&response[..length], dns_port, DnsRecordType::A)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                if response.addresses.v4
                    != vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TUN DNS response address mismatch",
                    ));
                }
                Ok(())
            })();
            let signal = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = done_tx.send(signal);
            result
        });

        let drop_proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
        let selector = Arc::new(StaticProxySelector {
            direct: Arc::clone(&drop_proxy),
            proxy: Arc::clone(&drop_proxy),
            bypass: Arc::clone(&drop_proxy),
            drop: Arc::clone(&drop_proxy),
        });
        let mut proxy_runtime = TunProxyRuntime::new(selector, 32)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .with_async_dns_handler(Arc::new(FixedDns));
        let mut dispatcher = TunDispatcher::new(2048, 2048, 16)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        runtime
            .run_dispatcher_until(
                &mut dispatcher,
                &mut proxy_runtime,
                Duration::from_millis(1),
                async move {
                    let result = done_rx.await.unwrap_or_else(|_| Err("shutdown".into()));
                    let _ = result_tx.send(result);
                },
            )
            .await?;
        proxy_runtime.close();
        if let Err(message) = result_rx
            .await
            .map_err(|_| std::io::Error::other("TUN DNS result channel closed"))?
        {
            let _ = client.join();
            return Err(std::io::Error::other(message));
        }
        client
            .join()
            .map_err(|_| std::io::Error::other("TUN DNS client thread panicked"))??;
        println!("tun-dns-echo-ok");
        Ok(())
    })
}
