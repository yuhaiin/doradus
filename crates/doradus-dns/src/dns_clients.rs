//! Synchronous DNS clients.

use super::*;

#[derive(Debug, Clone)]
pub struct UdpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
}

pub trait DohTransport: Send + Sync {
    fn post_dns_message(&self, endpoint: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>>;
}

pub struct DohClient<T> {
    pub endpoint: String,
    pub timeout: Duration,
    pub transport: T,
}

impl<T: DohTransport> DohClient<T> {
    pub fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let response = self
            .transport
            .post_dns_message(&self.endpoint, packet, self.timeout)?;
        validate_response_packet(packet, &response)?;
        Ok(response)
    }

    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request)?;
        decode_response(&response, id, record_type)
    }
}

impl UdpDnsClient {
    pub fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let socket = if self.server.is_ipv4() {
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
        }
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP socket: {error}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        socket
            .send_to(packet, self.server)
            .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS query: {error}")))?;
        let mut response = vec![0; self.max_packet_size.max(512)];
        let size = socket.recv(&mut response).map_err(|error| {
            Error::new(ErrorKind::Timeout, format!("receive DNS response: {error}"))
        })?;
        validate_response_packet(packet, &response[..size])?;
        Ok(response[..size].to_vec())
    }

    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request)?;
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
                let v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                let v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                result.v4 = v4;
                result.v6 = v6;
            }
            ResolveStrategy::PreferIpv6 => {
                let v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                let v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                result.v6 = v6;
                result.v4 = v4;
            }
        }
        Ok(result)
    }
}
