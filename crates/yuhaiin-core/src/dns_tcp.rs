//! DNS over TCP using the RFC 1035 two-byte length prefix.
//!
//! The wire codec remains in [`crate::dns`].  This module only owns stream
//! framing, socket deadlines, and the reusable client/server boundary so TCP
//! fallback does not become coupled to a particular resolver implementation.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::dns::{
    DnsHandler, DnsRecordType, DnsResponse, answer_query, decode_response, encode_query,
};
use crate::{DomainName, Error, ErrorKind, IpSet, ResolveStrategy, Result};

const DNS_TCP_MAX_FRAME: usize = u16::MAX as usize;

#[derive(Debug, Clone)]
pub struct TcpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
}

impl TcpDnsClient {
    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let mut stream = TcpStream::connect_timeout(&self.server, self.timeout)
            .map_err(|error| Error::new(ErrorKind::Timeout, format!("connect DNS TCP: {error}")))?;
        configure_stream(&stream, self.timeout)?;

        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        write_frame(&mut stream, &request)?;
        let response = read_frame(&mut stream, self.max_packet_size)?;
        decode_response(&response, id, record_type)
    }

    pub fn resolve(&self, domain: &DomainName, strategy: ResolveStrategy) -> Result<IpSet> {
        let mut result = IpSet::default();
        match strategy {
            ResolveStrategy::OnlyIpv4 => {
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
            }
            ResolveStrategy::OnlyIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
            }
            ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
            }
            ResolveStrategy::PreferIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
            }
        }
        Ok(result)
    }
}

pub struct TcpDnsServer<H> {
    pub listener: TcpListener,
    pub handler: H,
    pub max_packet_size: usize,
    pub timeout: Duration,
}

impl<H: DnsHandler> TcpDnsServer<H> {
    pub fn bind(
        address: SocketAddr,
        handler: H,
        max_packet_size: usize,
        timeout: Duration,
    ) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS TCP server: {error}")))?;
        Ok(Self {
            listener,
            handler,
            max_packet_size: normalize_max_packet_size(max_packet_size),
            timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn serve_once(&self) -> Result<usize> {
        let (mut stream, _peer) = self
            .listener
            .accept()
            .map_err(|error| Error::new(ErrorKind::Io, format!("accept DNS TCP: {error}")))?;
        configure_stream(&stream, self.timeout)?;
        let request = read_frame(&mut stream, self.max_packet_size)?;
        let response = answer_query(&request, &self.handler)?;
        write_frame(&mut stream, &response)
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<()> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| Error::new(ErrorKind::Io, format!("set DNS TCP read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| Error::new(ErrorKind::Io, format!("set DNS TCP write timeout: {error}")))
}

fn normalize_max_packet_size(value: usize) -> usize {
    value.clamp(512, DNS_TCP_MAX_FRAME)
}

fn write_frame(stream: &mut TcpStream, packet: &[u8]) -> Result<usize> {
    if packet.len() > DNS_TCP_MAX_FRAME {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DNS TCP frame is too large: {}", packet.len()),
        ));
    }
    let length = (packet.len() as u16).to_be_bytes();
    stream
        .write_all(&length)
        .and_then(|_| stream.write_all(packet))
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DNS TCP frame: {error}")))?;
    Ok(packet.len() + length.len())
}

fn read_frame(stream: &mut TcpStream, max_packet_size: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).map_err(read_error)?;
    let length = u16::from_be_bytes(length) as usize;
    let max_packet_size = normalize_max_packet_size(max_packet_size);
    if length > max_packet_size {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DNS TCP frame exceeds configured limit: {length} > {max_packet_size}"),
        ));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).map_err(read_error)?;
    Ok(packet)
}

fn read_error(error: std::io::Error) -> Error {
    let kind = match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ErrorKind::Timeout,
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => ErrorKind::Closed,
        _ => ErrorKind::Io,
    };
    Error::new(kind, format!("read DNS TCP frame: {error}"))
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsRecordType;
    use std::net::Ipv4Addr;
    use std::thread;

    struct StaticHandler;

    impl DnsHandler for StaticHandler {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 53)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    #[test]
    fn tcp_client_and_server_round_trip_dns_frame() {
        let server = TcpDnsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            StaticHandler,
            4096,
            Duration::from_secs(2),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = thread::spawn(move || server.serve_once());

        let client = TcpDnsClient {
            server: address,
            timeout: Duration::from_secs(2),
            max_packet_size: 4096,
        };
        let response = client
            .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
            .unwrap();
        assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 53)]);
        assert!(task.join().unwrap().unwrap() > 2);
    }
}
