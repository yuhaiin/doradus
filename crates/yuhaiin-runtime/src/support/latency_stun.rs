//! STUN latency probes and wire codec.

use super::*;

pub(super) async fn probe_stun(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let tcp = request.probe_type == "stun_tcp" || request.tcp;
    let target = parse_host_port(&request.host_or_default(tcp), 3478)?;
    let request_timeout = timeout.min(Duration::from_secs(5));
    let values = if tcp {
        let transaction = transaction_id();
        let packet = stun_binding_request(transaction);
        let endpoint = endpoint(Network::Tcp, &target.0, target.1)?;
        let context = FlowContext::new(endpoint);
        let mut stream = tokio::time::timeout(timeout, proxy.connect(&context))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP connect timed out"))??;
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(timeout, stream.write_all(&packet))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP write timed out"))?
            .map_err(io_error)?;
        let response = read_stun_tcp(&mut stream, timeout).await?;
        let response = parse_stun_response(&response, transaction)?;
        let mapped_address = response.xor_mapped.ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "STUN response has no XOR mapped address",
            )
        })?;
        StunLatency {
            mapped_address: mapped_address.to_string(),
            ..StunLatency::default()
        }
    } else {
        let endpoint = endpoint(Network::Udp, &target.0, target.1)?;
        let context = FlowContext::new(endpoint.clone());
        let datagram = tokio::time::timeout(timeout, proxy.open_datagram(&context))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP open timed out"))??;
        let result = probe_stun_udp(datagram.as_ref(), endpoint, target.1, request_timeout).await;
        datagram.close().await?;
        result?
    };
    Ok(LatencyResponse {
        ok: true,
        latency_ms: 0,
        ip: None,
        stun: Some(values),
        error: String::new(),
    })
}

pub(super) async fn probe_stun_udp(
    datagram: &dyn AsyncDatagram,
    primary: Endpoint,
    primary_port: u16,
    timeout: Duration,
) -> Result<StunLatency> {
    // Keep one datagram association for every probe, matching Go's Mapping
    // and Filtering tests and preserving the NAT source mapping.
    let first = stun_udp_request(datagram, primary.clone(), None, timeout).await?;
    let mapped_address = first.xor_mapped.ok_or_else(|| {
        Error::new(
            ErrorKind::Protocol,
            "STUN response has no XOR mapped address",
        )
    })?;

    let mapping = if datagram
        .local_addr()
        .ok()
        .and_then(|address| address.addr())
        == Some(mapped_address)
    {
        "EndpointIndependentNoNAT"
    } else {
        let Some(other_address) = first.other_address.or(first.changed_address) else {
            return Ok(StunLatency {
                mapped_address: mapped_address.to_string(),
                mapping: "ServerNotSupportChangePort".to_owned(),
                filtering: "ServerNotSupportChangePort".to_owned(),
                ..StunLatency::default()
            });
        };

        let other_primary = Endpoint::ip(
            Network::Udp,
            SocketAddr::new(other_address.ip(), primary_port),
        );
        let second = stun_udp_request(datagram, other_primary, None, timeout).await;
        match second {
            Ok(second) if second.xor_mapped == Some(mapped_address) => "EndpointIndependent",
            Ok(second) => {
                let third = stun_udp_request(
                    datagram,
                    Endpoint::ip(Network::Udp, other_address),
                    None,
                    timeout,
                )
                .await;
                match third {
                    Ok(third) if third.xor_mapped == second.xor_mapped => "AddressDependent",
                    Ok(_) => "AddressAndPortDependent",
                    Err(error) if is_stun_timeout(&error) => "AddressAndPortDependent",
                    Err(error) => return Err(error),
                }
            }
            Err(error) if is_stun_timeout(&error) => {
                let third = stun_udp_request(
                    datagram,
                    Endpoint::ip(Network::Udp, other_address),
                    None,
                    timeout,
                )
                .await;
                match third {
                    Ok(_) => "AddressAndPortDependent",
                    Err(error) if is_stun_timeout(&error) => "AddressAndPortDependent",
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    };

    let filtering = if mapping == "ServerNotSupportChangePort" {
        mapping
    } else {
        stun_udp_request(datagram, primary.clone(), None, timeout).await?;
        match stun_udp_request(datagram, primary.clone(), Some(0x06), timeout).await {
            Ok(_) => "EndpointIndependent",
            Err(error) if is_stun_timeout(&error) => {
                match stun_udp_request(datagram, primary, Some(0x02), timeout).await {
                    Ok(_) => "AddressDependent",
                    Err(error) if is_stun_timeout(&error) => "AddressAndPortDependent",
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    };

    Ok(StunLatency {
        mapped_address: mapped_address.to_string(),
        mapping: mapping.to_owned(),
        filtering: filtering.to_owned(),
        ..StunLatency::default()
    })
}

async fn stun_udp_request(
    datagram: &dyn AsyncDatagram,
    target: Endpoint,
    change_request: Option<u8>,
    timeout: Duration,
) -> Result<ParsedStunResponse> {
    let transaction = transaction_id();
    let packet = match change_request {
        Some(change_request) => stun_binding_request_with_change(transaction, change_request),
        None => stun_binding_request(transaction),
    };
    tokio::time::timeout(timeout, datagram.send_to(&packet, target))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP write timed out"))??;
    let mut buffer = vec![0u8; 2048];
    let (length, _) = tokio::time::timeout(timeout, datagram.recv_from(&mut buffer))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP response timed out"))??;
    parse_stun_response(&buffer[..length], transaction)
}

async fn read_stun_tcp(stream: &mut BoxAsyncStream, timeout: Duration) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut response = vec![0u8; 20];
    tokio::time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP header timed out"))?
        .map_err(io_error)?;
    let length = usize::from(u16::from_be_bytes([response[2], response[3]]));
    if length > 2048 - 20 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "STUN TCP response is too large",
        ));
    }
    response.resize(20 + length, 0);
    tokio::time::timeout(timeout, stream.read_exact(&mut response[20..]))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP response timed out"))?
        .map_err(io_error)?;
    Ok(response)
}

fn transaction_id() -> [u8; 12] {
    let counter = TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&(now as u64 ^ counter).to_be_bytes());
    id[8..].copy_from_slice(&(counter as u32).to_be_bytes());
    id
}

#[derive(Debug, Default)]
pub(super) struct ParsedStunResponse {
    pub(super) values: StunLatency,
    pub(super) xor_mapped: Option<SocketAddr>,
    pub(super) other_address: Option<SocketAddr>,
    pub(super) changed_address: Option<SocketAddr>,
}

pub(super) fn stun_binding_request(transaction: [u8; 12]) -> Vec<u8> {
    stun_binding_request_with_attributes(transaction, &[])
}

fn stun_binding_request_with_change(transaction: [u8; 12], change_request: u8) -> Vec<u8> {
    stun_binding_request_with_attributes(
        transaction,
        &[0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, change_request],
    )
}

fn stun_binding_request_with_attributes(transaction: [u8; 12], attributes: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + attributes.len());
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(attributes);
    packet
}

pub(super) fn parse_stun_response(
    packet: &[u8],
    transaction: [u8; 12],
) -> Result<ParsedStunResponse> {
    if packet.len() < 20 || packet[0] & 0xc0 != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid STUN response"));
    }
    let message_type = u16::from_be_bytes([packet[0], packet[1]]);
    if message_type != 0x0101 && message_type != 0x0111 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("unexpected STUN response type 0x{message_type:04x}"),
        ));
    }
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if length > packet.len().saturating_sub(20) {
        return Err(Error::new(ErrorKind::Protocol, "truncated STUN response"));
    }
    if packet[8..20] != transaction {
        return Err(Error::new(ErrorKind::Protocol, "STUN transaction mismatch"));
    }
    let mut result = ParsedStunResponse::default();
    let end = 20 + length;
    let mut offset = 20;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset += 4;
        if offset + size > end {
            return Err(Error::new(ErrorKind::Protocol, "truncated STUN attribute"));
        }
        let value = &packet[offset..offset + size];
        match kind {
            0x0001 => {
                result.values.mapped_address =
                    decode_address(value, false, transaction)?.to_string();
            }
            0x0005 => {
                result.changed_address = Some(decode_address(value, false, transaction)?);
            }
            0x0020 => {
                let address = decode_address(value, true, transaction)?;
                result.values.xor_mapped_address = address.to_string();
                result.xor_mapped = Some(address);
            }
            0x8022 => result.values.software = String::from_utf8_lossy(value).to_string(),
            0x802b => {
                result.values.response_origin_address =
                    decode_address(value, true, transaction)?.to_string();
            }
            0x802c => {
                // OTHER-ADDRESS is a plain address attribute.  Unlike
                // XOR-MAPPED-ADDRESS and RESPONSE-ORIGIN, its address and
                // port are not XOR encoded.
                let address = decode_address(value, false, transaction)?;
                result.values.other_address = address.to_string();
                result.other_address = Some(address);
            }
            _ => {}
        }
        offset += (size + 3) & !3;
    }
    if result.xor_mapped.is_none() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "STUN response has no XOR mapped address",
        ));
    }
    Ok(result)
}

fn decode_address(value: &[u8], xor: bool, transaction: [u8; 12]) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "short STUN address attribute",
        ));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= 0x2112;
    }
    let address = match family {
        1 if value.len() >= 8 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[4..8]);
            if xor {
                for (byte, cookie) in bytes.iter_mut().zip(0x2112_A442u32.to_be_bytes()) {
                    *byte ^= cookie;
                }
            }
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        2 if value.len() >= 20 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&0x2112_A442u32.to_be_bytes());
                mask[4..].copy_from_slice(&transaction);
                for (byte, mask) in bytes.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown STUN address family",
            ));
        }
    };
    Ok(SocketAddr::new(address, port))
}
