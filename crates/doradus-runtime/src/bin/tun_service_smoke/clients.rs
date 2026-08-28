use super::*;

pub(super) fn assert_tun_target_unreachable(
    device_name: &str,
    timeout: Duration,
) -> std::io::Result<()> {
    let address = configured_tun_target()?;
    let deadline = Instant::now() + timeout;
    loop {
        if device_is_present(device_name) || route_uses_device(device_name, address) {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(format!(
                    "TUN device or route for {address} remained while the inbound was disabled"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        return Ok(());
    }
}

pub(super) fn run_tun_dns_client() -> std::io::Result<()> {
    use std::net::UdpSocket;

    let target = match std::env::var("DORADUS_TUN_DNS_TARGET") {
        Ok(value) => value.parse().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid DORADUS_TUN_DNS_TARGET: {error}"),
            )
        })?,
        Err(_) => {
            let configured = configured_tun_target()?;
            SocketAddr::new(configured.ip(), 53)
        }
    };
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let domain = DomainName::new("tun-fakeip.example.test")
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let query = encode_query(0x5455, &domain, DnsRecordType::A)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    socket.send_to(&query, target)?;
    let mut response = vec![0u8; 4096];
    let length = socket.recv(&mut response)?;
    let response = decode_response(&response[..length], 0x5455, DnsRecordType::A)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let address = response.addresses.v4.first().copied().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN DNS response did not contain an IPv4 address",
        )
    })?;
    let octets = address.octets();
    if octets[0] != 198 || octets[1] != 18 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TUN DNS response was not FakeIP: {address}"),
        ));
    }
    println!("runtime-tun-dns-address={address}");
    Ok(())
}

fn traffic_byte(offset: usize) -> u8 {
    (offset as u64)
        .wrapping_mul(31)
        .wrapping_add(17)
        .to_le_bytes()[0]
}

fn fill_traffic_chunk(buffer: &mut [u8], offset: usize) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = traffic_byte(offset + index);
    }
}

pub(super) fn spawn_tun_connection_assertion(
    monitor: Arc<doradus_runtime::ConnectionMonitor>,
    selected_node: String,
    timeout: Duration,
    assert_process: bool,
) -> tokio::task::JoinHandle<Result<serde_json::Value>> {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let connections = monitor
                .connections_value()
                .get("connections")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(connection) = connections.into_iter().find(|connection| {
                connection
                    .get("component")
                    .and_then(serde_json::Value::as_str)
                    == Some("tun")
                    && connection.get("nodeId").and_then(serde_json::Value::as_str)
                        == Some(selected_node.as_str())
                    && connection
                        .get("outbound")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && connection
                        .get("localAddr")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && (!assert_process
                        || (connection
                            .get("process")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| !value.is_empty())
                            && connection
                                .get("pid")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                            && connection
                                .get("uid")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|value| !value.is_empty())))
            }) {
                return Ok(connection);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorKind::Timeout,
                    format!(
                        "TUN connection metadata did not appear for selected node {selected_node}"
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

pub(super) fn run_tun_traffic_client(
    total_bytes: usize,
    connection_hold_ms: u64,
) -> std::io::Result<()> {
    use std::io::{Read, Write};

    let address = configured_tun_target()?;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("connect TUN traffic target {address}: {error}"),
            )
        })?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let mut writer_stream = stream.try_clone().map_err(|error| {
        std::io::Error::new(error.kind(), format!("clone TUN traffic stream: {error}"))
    })?;
    writer_stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut payload = vec![0u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < total_bytes {
            let length = (total_bytes - sent).min(payload.len());
            fill_traffic_chunk(&mut payload[..length], sent);
            writer_stream
                .write_all(&payload[..length])
                .map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!("write TUN traffic payload at byte {sent}: {error}"),
                    )
                })?;
            sent += length;
        }
        if connection_hold_ms != 0 {
            std::thread::sleep(Duration::from_millis(connection_hold_ms));
        }
        writer_stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("shutdown TUN traffic writer: {error}"),
                )
            })
    });
    let mut echoed = vec![0u8; 64 * 1024];
    let mut received = 0usize;
    let mut read_result = Ok(());
    while received < total_bytes {
        let length = (total_bytes - received).min(echoed.len());
        if let Err(error) = stream.read_exact(&mut echoed[..length]) {
            read_result = Err(error);
            break;
        }
        for (index, byte) in echoed[..length].iter().enumerate() {
            if *byte != traffic_byte(received + index) {
                read_result = Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("runtime TUN echo mismatch at byte {}", received + index),
                ));
                break;
            }
        }
        if read_result.is_err() {
            break;
        }
        received += length;
    }
    if read_result.is_err() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    let writer_result = writer
        .join()
        .map_err(|_| std::io::Error::other("runtime TUN traffic writer panicked"))?;
    read_result.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("read TUN traffic echo after {received} bytes: {error}"),
        )
    })?;
    writer_result
}

pub(super) fn run_tun_udp_traffic_client(total_bytes: usize) -> std::io::Result<()> {
    let source = configured_tun_source()?;
    let socket = std::net::UdpSocket::bind(SocketAddr::new(source, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let destination = configured_tun_udp_target()?;
    eprintln!(
        "runtime-tun-udp-client local={} destination={destination}",
        socket.local_addr()?
    );
    let mut payload = vec![0u8; total_bytes];
    fill_traffic_chunk(&mut payload, 0);
    let sent = socket.send_to(&payload, destination).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("write TUN UDP traffic payload to {destination}: {error}"),
        )
    })?;
    eprintln!("runtime-tun-udp-client-sent bytes={sent}");
    let mut echoed = vec![0u8; 65_507];
    let (length, _) = socket.recv_from(&mut echoed).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("read TUN UDP traffic echo from {destination}: {error}"),
        )
    })?;
    if length != total_bytes || echoed[..length] != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("runtime TUN UDP echo mismatch: received {length} of {total_bytes} bytes"),
        ));
    }
    Ok(())
}

pub(super) async fn run_tun_ipv6_extension_child(total_bytes: usize) -> Result<()> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut child = std::process::Command::new(executable)
        .arg("--ipv6-extension-client")
        .env("DORADUS_TUN_UDP_TRAFFIC_BYTES", total_bytes.to_string())
        .spawn()
        .map_err(io_error)?;
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(join_error)?
        .map_err(io_error)?;
    if status.success() {
        Ok(())
    } else {
        Err(io_error(std::io::Error::other(format!(
            "TUN IPv6 extension client exited with {status}"
        ))))
    }
}

pub(super) fn run_tun_ipv6_extension_client(total_bytes: usize) -> std::io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = total_bytes;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw IPv6 extension smoke is only available on Linux",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let source = configured_tun_ipv6_source()?;
        let target = configured_tun_ipv6_target()?;
        let source_port = 41_000;
        let receiver = std::net::UdpSocket::bind(SocketAddrV6::new(source, source_port, 0, 0))?;
        receiver.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut payload = vec![0u8; total_bytes];
        fill_traffic_chunk(&mut payload, 0);
        let packet = build_ipv6_extension_udp_packet(
            source,
            *target.ip(),
            source_port,
            target.port(),
            &payload,
        );
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(255)))?;
        socket.set_header_included_v6(true)?;
        // Raw IPv6 sockets do not accept a transport port in sockaddr_in6;
        // the UDP destination port is carried by the packet header above.
        let route_target = SocketAddrV6::new(*target.ip(), 0, target.flowinfo(), target.scope_id());
        let sent = socket.send_to(&packet, &SockAddr::from(route_target))?;
        if sent != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "raw IPv6 extension packet was truncated: sent {sent} of {}",
                    packet.len()
                ),
            ));
        }
        let mut echoed = vec![0u8; 65_507];
        let (length, peer) = receiver.recv_from(&mut echoed).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("read raw IPv6 extension echo from {target}: {error}"),
            )
        })?;
        if length != total_bytes || echoed[..length] != payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "raw IPv6 extension echo mismatch from {peer}: received {length} of {total_bytes} bytes"
                ),
            ));
        }
        eprintln!(
            "runtime-tun-ipv6-extension-client-roundtrip bytes={} source={source} destination={target}",
            payload.len(),
        );
        Ok(())
    }
}

pub(super) fn build_ipv6_extension_udp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let extension_len = 16;
    let mut packet = vec![0u8; 40 + extension_len + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(u16::try_from(extension_len + udp_len).unwrap()).to_be_bytes());
    packet[6] = 0; // Hop-by-Hop Options
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    // Two eight-byte extension headers. All option bytes are Pad1, which is
    // valid and keeps this fixture focused on extension-header traversal.
    packet[40] = 60; // Destination Options follows Hop-by-Hop Options.
    packet[48] = 17; // UDP follows Destination Options.

    let udp_offset = 56;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6]
        .copy_from_slice(&(u16::try_from(udp_len).unwrap()).to_be_bytes());
    packet[udp_offset + 8..].copy_from_slice(payload);

    let checksum = ipv6_udp_checksum(source, destination, &packet[udp_offset..]);
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub(super) fn ipv6_udp_checksum(source: Ipv6Addr, destination: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + udp_packet.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(u32::try_from(udp_packet.len()).unwrap()).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 17]);
    pseudo_header.extend_from_slice(udp_packet);
    internet_checksum(&pseudo_header)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, remainder) = bytes.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&byte) = remainder.first() {
        sum += u32::from(byte) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) async fn run_tun_udp_traffic_child(total_bytes: usize) -> Result<()> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut child = std::process::Command::new(executable)
        .arg("--udp-traffic-client")
        .env("DORADUS_TUN_UDP_TRAFFIC_BYTES", total_bytes.to_string())
        .spawn()
        .map_err(io_error)?;
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(join_error)?
        .map_err(io_error)?;
    if status.success() {
        Ok(())
    } else {
        Err(io_error(std::io::Error::other(format!(
            "TUN UDP traffic client exited with {status}"
        ))))
    }
}

pub(super) fn run_tun_reset_client() -> std::io::Result<()> {
    use std::io::Write;

    let address = configured_tun_target()?;
    let stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("connect TUN reset target {address}: {error}"),
            )
        })?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let socket = socket2::SockRef::from(&stream);
    socket.set_linger(Some(Duration::ZERO))?;
    let mut stream = stream;
    stream.write_all(b"tun-reset-before-reconnect")?;
    // SO_LINGER=0 makes the close send RST, exercising the inbound's
    // connection-task cleanup before the normal reconnect below.
    drop(stream);
    Ok(())
}
