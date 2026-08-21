//! DNS wire codec and a small UDP client/server boundary.
//!
//! Hickory handles DNS name compression, record encoding, and malformed packet
//! checks. The surrounding code owns timeout, routing, caching, and FakeIP
//! policy; this module deliberately does not hide those decisions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use futures_util::future::BoxFuture;
use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, Unknown,
};
use hickory_proto::rr::{
    Name, RData, RecordType,
    rdata::{A, AAAA, HTTPS, PTR, SVCB},
};

pub use crate::cache::{CachingDnsHandler, DnsCache};
use crate::{DomainName, Error, ErrorKind, IpSet, ResolveStrategy, Result};
pub use yuhaiin_types::dns::{
    AsyncDnsHandler, DnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding, DnsServiceParam,
};

trait DnsRecordTypeCodec {
    fn hickory(self) -> RecordType;
}

impl DnsRecordTypeCodec for DnsRecordType {
    fn hickory(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Ptr => RecordType::PTR,
            Self::Https => RecordType::HTTPS,
            Self::Svcb => RecordType::SVCB,
        }
    }
}

trait DnsServiceParamCodec {
    fn key(&self) -> u16;
    fn from_hickory(key: SvcParamKey, value: &SvcParamValue) -> Result<Self>
    where
        Self: Sized;
    fn to_hickory(&self) -> Result<(SvcParamKey, SvcParamValue)>;
}

impl DnsServiceParamCodec for DnsServiceParam {
    fn key(&self) -> u16 {
        match self {
            Self::Mandatory(_) => 0,
            Self::Alpn(_) => 1,
            Self::NoDefaultAlpn => 2,
            Self::Port(_) => 3,
            Self::Ipv4Hint(_) => 4,
            Self::Ech(_) => 5,
            Self::Ipv6Hint(_) => 6,
            Self::Unknown { key, .. } => *key,
        }
    }

    fn from_hickory(key: SvcParamKey, value: &SvcParamValue) -> Result<Self> {
        let parameter = match (key, value) {
            (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) => {
                Self::Mandatory(keys.iter().copied().map(u16::from).collect())
            }
            (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(values))) => Self::Alpn(values.clone()),
            (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn) => Self::NoDefaultAlpn,
            (SvcParamKey::Port, SvcParamValue::Port(port)) => Self::Port(*port),
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(values))) => {
                Self::Ipv4Hint(values.iter().map(|address| address.0).collect())
            }
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(EchConfigList(values))) => {
                Self::Ech(values.clone())
            }
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(values))) => {
                Self::Ipv6Hint(values.iter().map(|address| address.0).collect())
            }
            (
                key @ (SvcParamKey::Key(_) | SvcParamKey::Key65535 | SvcParamKey::Unknown(_)),
                SvcParamValue::Unknown(Unknown(values)),
            ) => Self::Unknown {
                key: key.into(),
                value: values.clone(),
            },
            (key, value) => {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "SVCB parameter {} has incompatible value {value:?}",
                        u16::from(key)
                    ),
                ));
            }
        };
        Ok(parameter)
    }

    fn to_hickory(&self) -> Result<(SvcParamKey, SvcParamValue)> {
        Ok(match self {
            Self::Mandatory(keys) => (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(
                    keys.iter().copied().map(SvcParamKey::from).collect(),
                )),
            ),
            Self::Alpn(values) => (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(values.clone()))),
            Self::NoDefaultAlpn => (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
            Self::Port(port) => (SvcParamKey::Port, SvcParamValue::Port(*port)),
            Self::Ipv4Hint(values) => (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(values.iter().copied().map(A).collect())),
            ),
            Self::Ech(values) => (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(values.clone())),
            ),
            Self::Ipv6Hint(values) => (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(values.iter().copied().map(AAAA).collect())),
            ),
            Self::Unknown { key, value } => {
                let key = SvcParamKey::from(*key);
                if matches!(
                    key,
                    SvcParamKey::Mandatory
                        | SvcParamKey::Alpn
                        | SvcParamKey::NoDefaultAlpn
                        | SvcParamKey::Port
                        | SvcParamKey::Ipv4Hint
                        | SvcParamKey::EchConfigList
                        | SvcParamKey::Ipv6Hint
                        | SvcParamKey::Key65535
                ) {
                    return Err(Error::invalid(
                        "SVCB unknown parameter key must not be a defined key",
                    ));
                }
                (key, SvcParamValue::Unknown(Unknown(value.clone())))
            }
        })
    }
}

fn service_binding_from_hickory(value: &SVCB) -> Result<DnsServiceBinding> {
    let target = value.target_name.to_ascii();
    let target = if target == "." {
        None
    } else {
        Some(DomainName::new(target.trim_end_matches('.'))?)
    };
    let params = value
        .svc_params
        .iter()
        .map(|(key, value)| <DnsServiceParam as DnsServiceParamCodec>::from_hickory(*key, value))
        .collect::<Result<Vec<_>>>()?;
    Ok(DnsServiceBinding {
        priority: value.svc_priority,
        target,
        params,
    })
}

fn service_binding_to_hickory(binding: &DnsServiceBinding) -> Result<SVCB> {
    let target = match &binding.target {
        Some(target) => Name::from_utf8(format!("{}.", target))
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?,
        None => Name::from_utf8(".")
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?,
    };
    let mut parameters = binding.params.clone();
    parameters.sort_by_key(|parameter| parameter.key());
    let mut params = parameters
        .iter()
        .map(|parameter| parameter.to_hickory())
        .collect::<Result<Vec<_>>>()?;
    params.sort_by_key(|(key, _)| u16::from(*key));
    if params
        .windows(2)
        .any(|window| u16::from(window[0].0) == u16::from(window[1].0))
    {
        return Err(Error::invalid("SVCB parameter keys must be unique"));
    }
    Ok(SVCB::new(binding.priority, target, params))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicy {
    Upstream,
    Empty,
    Block,
}

/// Small policy boundary kept outside the resolver transport.  This lets the
/// Router choose direct/proxy/drop DNS behavior without teaching UDP or DoH
/// codecs about route policy.
pub struct PolicyDnsHandler<H> {
    pub upstream: H,
    pub policy: DnsPolicy,
}

impl<H: DnsHandler> DnsHandler for PolicyDnsHandler<H> {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        match self.policy {
            DnsPolicy::Upstream => self.upstream.resolve(domain, record_type),
            DnsPolicy::Empty => Ok(DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(0),
            }),
            DnsPolicy::Block => Err(Error::new(
                ErrorKind::Closed,
                "DNS query blocked by route policy",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub id: u16,
    pub domain: DomainName,
    pub record_type: DnsRecordType,
}

pub fn encode_query(id: u16, domain: &DomainName, record_type: DnsRecordType) -> Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{}.", domain))
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type.hickory()));
    let mut edns = Edns::new();
    edns.set_max_payload(8192);
    message.set_edns(edns);
    message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Encode a DNS query for a QTYPE that is intentionally outside the typed
/// resolver model. This is primarily useful to packet-forwarding callers and
/// tests; address resolution should continue to use [`encode_query`].
pub fn encode_raw_query(id: u16, domain: &DomainName, record_type: u16) -> Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{}.", domain))
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(record_type)));
    let mut edns = Edns::new();
    edns.set_max_payload(8192);
    message.set_edns(edns);
    message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

pub fn decode_response(
    packet: &[u8],
    expected_id: u16,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.metadata.id != expected_id {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS transaction id mismatch",
        ));
    }
    let mut addresses = IpSet::default();
    let mut ptr_names = Vec::new();
    let mut service_bindings = Vec::new();
    let mut minimum_ttl = None;
    for record in &message.answers {
        let ttl = record.ttl;
        minimum_ttl = Some(minimum_ttl.map_or(ttl, |current: u32| current.min(ttl)));
        match (record_type, &record.data) {
            (DnsRecordType::A, RData::A(address)) => addresses.v4.push(address.0),
            (DnsRecordType::Aaaa, RData::AAAA(address)) => addresses.v6.push(address.0),
            (DnsRecordType::Ptr, RData::PTR(name)) => {
                ptr_names.push(DomainName::new(name.to_ascii().trim_end_matches('.'))?)
            }
            (DnsRecordType::Https, RData::HTTPS(binding)) => {
                service_bindings.push(service_binding_from_hickory(&binding.0)?)
            }
            (DnsRecordType::Svcb, RData::SVCB(binding)) => {
                service_bindings.push(service_binding_from_hickory(binding)?)
            }
            _ => {}
        }
    }
    Ok(DnsResponse {
        addresses,
        ptr_names,
        service_bindings,
        minimum_ttl,
    })
}

pub fn decode_query(packet: &[u8]) -> Result<DnsQuestion> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    let domain = DomainName::new(query.name().to_ascii().trim_end_matches('.'))?;
    let record_type = match query.query_type() {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::Aaaa,
        RecordType::PTR => DnsRecordType::Ptr,
        RecordType::HTTPS => DnsRecordType::Https,
        RecordType::SVCB => DnsRecordType::Svcb,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "DNS server currently supports only A, AAAA, PTR, HTTPS and SVCB",
            ));
        }
    };
    Ok(DnsQuestion {
        id: message.metadata.id,
        domain,
        record_type,
    })
}

/// Decode the cache key used by the raw resolver path. Unlike [`decode_query`]
/// this accepts every DNS QTYPE, because Go caches and forwards records that
/// the address-oriented API does not model.
pub fn decode_raw_query_key(packet: &[u8]) -> Result<(DomainName, u16)> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    Ok((
        DomainName::new(query.name().to_ascii().trim_end_matches('.'))?,
        u16::from(query.query_type()),
    ))
}

/// Rewrite a DNS transaction ID after serving a response from the raw cache.
pub fn rewrite_dns_transaction_id(mut packet: Vec<u8>, id: u16) -> Result<Vec<u8>> {
    if packet.len() < 2 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS response is shorter than its transaction id",
        ));
    }
    packet[..2].copy_from_slice(&id.to_be_bytes());
    Ok(packet)
}

/// Rebuild the caller-visible question and transaction ID on a cached DNS
/// response. Go's `dns.Msg.SetReply` does this before returning a raw cached
/// message; replacing only the ID would leak the first request's question
/// flags or name encoding to later callers.
pub fn rewrite_dns_response_for_query(response: Vec<u8>, query: &[u8]) -> Result<Vec<u8>> {
    let mut response_message = Message::from_vec(&response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query_message = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if query_message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    response_message.metadata.id = query_message.metadata.id;
    response_message.queries = query_message.queries;
    response_message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Apply the RFC 1035 UDP size limit to a response. Go keeps the complete
/// answer for TCP/DoH but strips sections and sets TC for an oversized UDP
/// response, allowing the client to retry over TCP.
pub fn truncate_dns_response(query: &[u8], response: &[u8]) -> Result<Vec<u8>> {
    let query_message = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut response_message = Message::from_vec(response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let client_buffer_size = query_message
        .edns
        .as_ref()
        .map(|edns| usize::from(edns.max_payload()))
        .unwrap_or(512)
        .max(512);
    if response.len() <= client_buffer_size {
        return Ok(response.to_vec());
    }
    response_message.metadata.truncation = true;
    response_message.answers.clear();
    response_message.authorities.clear();
    response_message.additionals.clear();
    response_message.signature = None;
    response_message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Validate a DNS query before handing it to a raw transport.
///
/// The typed resolver API intentionally models only records that yuhaiin
/// interprets locally.  Transport-facing callers still need to forward every
/// valid DNS question (for example MX, TXT, CNAME, NS and DNSSEC records), so
/// this helper validates the wire message without narrowing its QTYPE.
pub fn validate_query_packet(packet: &[u8]) -> Result<()> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    Ok(())
}

/// Check that a raw upstream response belongs to the original DNS query.
pub fn validate_response_packet(query: &[u8], response: &[u8]) -> Result<()> {
    let query = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let response_message = Message::from_vec(response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if response_message.metadata.id != query.metadata.id {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS transaction id mismatch",
        ));
    }
    if response_message.metadata.message_type != MessageType::Response {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS upstream returned a query instead of a response",
        ));
    }
    Ok(())
}

pub fn response_is_truncated(packet: &[u8]) -> Result<bool> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    Ok(message.metadata.truncation)
}

/// Build an empty response for any valid DNS QTYPE while retaining every
/// question from the request. Policy layers use this instead of the typed
/// encoder when they intentionally block a raw record query.
pub fn encode_empty_response(packet: &[u8]) -> Result<Vec<u8>> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    let mut response = Message::response(message.metadata.id, message.metadata.op_code);
    for query in &message.queries {
        response.add_query(query.clone());
    }
    response
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

pub fn encode_response(packet: &[u8], answer: &DnsResponse) -> Result<Vec<u8>> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    let record_type = match query.query_type() {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::Aaaa,
        RecordType::PTR => DnsRecordType::Ptr,
        RecordType::HTTPS => DnsRecordType::Https,
        RecordType::SVCB => DnsRecordType::Svcb,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "DNS server currently supports only A, AAAA, PTR, HTTPS and SVCB",
            ));
        }
    };
    let mut response = Message::response(message.metadata.id, message.metadata.op_code);
    response.add_query(query.clone());
    for address in answer.addresses.iter() {
        let rdata = match address {
            IpAddr::V4(address) if record_type == DnsRecordType::A => RData::A(address.into()),
            IpAddr::V6(address) if record_type == DnsRecordType::Aaaa => {
                RData::AAAA(address.into())
            }
            _ => continue,
        };
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            query.name().clone(),
            answer.minimum_ttl.unwrap_or(60),
            rdata,
        ));
    }
    if record_type == DnsRecordType::Ptr {
        for domain in &answer.ptr_names {
            let name = Name::from_utf8(format!("{}.", domain))
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                answer.minimum_ttl.unwrap_or(60),
                RData::PTR(PTR(name)),
            ));
        }
    }
    if matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb) {
        for binding in &answer.service_bindings {
            let binding = service_binding_to_hickory(binding)?;
            let rdata = if record_type == DnsRecordType::Https {
                RData::HTTPS(HTTPS(binding))
            } else {
                RData::SVCB(binding)
            };
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                answer.minimum_ttl.unwrap_or(60),
                rdata,
            ));
        }
    }
    response
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

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

pub struct AsyncPolicyDnsHandler<H> {
    pub upstream: H,
    pub policy: DnsPolicy,
}

impl<H: AsyncDnsHandler> AsyncDnsHandler for AsyncPolicyDnsHandler<H> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        match self.policy {
            DnsPolicy::Upstream => self.upstream.answer(packet),
            DnsPolicy::Block => Box::pin(async {
                Err(Error::new(
                    ErrorKind::Closed,
                    "DNS query blocked by route policy",
                ))
            }),
            DnsPolicy::Empty => Box::pin(async move { encode_empty_response(packet) }),
        }
    }
}

/// Decode one DNS query, invoke the injected resolver, and encode a response.
///
/// Keeping this operation independent from a socket makes it usable by both
/// the UDP server and the TUN DNS-hijack path.  The resolver remains a
/// synchronous boundary here; callers that perform network I/O should invoke
/// it on a blocking pool rather than inside the packet poll loop.
pub fn answer_query<H: DnsHandler + ?Sized>(packet: &[u8], handler: &H) -> Result<Vec<u8>> {
    let question = decode_query(packet)?;
    let answer = handler.resolve(&question.domain, question.record_type)?;
    encode_response(packet, &answer)
}

pub struct UdpDnsServer<H> {
    pub socket: UdpSocket,
    pub handler: H,
    pub max_packet_size: usize,
}

impl<H: DnsHandler> UdpDnsServer<H> {
    pub fn bind(address: SocketAddr, handler: H, max_packet_size: usize) -> Result<Self> {
        let socket = UdpSocket::bind(address)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP server: {error}")))?;
        Ok(Self {
            socket,
            handler,
            max_packet_size: max_packet_size.max(512),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn serve_once(&self) -> Result<usize> {
        let mut request = vec![0; self.max_packet_size.max(512)];
        let (size, peer) = self.socket.recv_from(&mut request).map_err(|error| {
            Error::new(ErrorKind::Timeout, format!("receive DNS request: {error}"))
        })?;
        let packet = answer_query(&request[..size], &self.handler)?;
        let packet = truncate_dns_response(&request[..size], &packet)?;
        let sent = self
            .socket
            .send_to(&packet, peer)
            .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS response: {error}")))?;
        Ok(sent)
    }
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip_preserves_id_and_addresses() {
        let domain = DomainName::new("example.com").unwrap();
        let query = encode_query(42, &domain, DnsRecordType::A).unwrap();
        let request = Message::from_vec(&query).unwrap();
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(request.queries[0].clone());
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            request.queries[0].name().clone(),
            30,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        let decoded = decode_response(&response.to_vec().unwrap(), 42, DnsRecordType::A).unwrap();
        assert_eq!(decoded.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(decoded.minimum_ttl, Some(30));
    }

    #[test]
    fn ptr_query_and_response_round_trip_preserves_names_and_ttl() {
        let reverse = DomainName::new("1.0.18.198.in-addr.arpa").unwrap();
        let packet = encode_query(43, &reverse, DnsRecordType::Ptr).unwrap();
        let question = decode_query(&packet).unwrap();
        assert_eq!(question.id, 43);
        assert_eq!(question.domain, reverse);
        assert_eq!(question.record_type, DnsRecordType::Ptr);

        let response = encode_response(
            &packet,
            &DnsResponse {
                addresses: IpSet::default(),
                ptr_names: vec![DomainName::new("host.example.com").unwrap()],
                service_bindings: Vec::new(),
                minimum_ttl: Some(17),
            },
        )
        .unwrap();
        let decoded = decode_response(&response, 43, DnsRecordType::Ptr).unwrap();
        assert_eq!(
            decoded.ptr_names,
            vec![DomainName::new("host.example.com").unwrap()]
        );
        assert_eq!(decoded.minimum_ttl, Some(17));
    }

    #[test]
    fn https_and_svcb_round_trip_preserves_targets_hints_and_unknown_params() {
        let binding = DnsServiceBinding {
            priority: 1,
            target: Some(DomainName::new("svc.example.com").unwrap()),
            params: vec![
                DnsServiceParam::Ipv6Hint(vec!["2001:db8::7".parse().unwrap()]),
                DnsServiceParam::Unknown {
                    key: 65_400,
                    value: vec![0xde, 0xad, 0xbe, 0xef],
                },
                DnsServiceParam::Alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]),
                DnsServiceParam::Port(8443),
                DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(192, 0, 2, 7)]),
                DnsServiceParam::Ech(vec![1, 2, 3, 4]),
                DnsServiceParam::Mandatory(vec![1, 3, 4]),
                DnsServiceParam::NoDefaultAlpn,
            ],
        };
        let mut expected = binding.clone();
        expected.params.sort_by_key(|parameter| parameter.key());
        let alias = DnsServiceBinding {
            priority: 0,
            target: None,
            params: Vec::new(),
        };
        for (id, record_type) in [(44, DnsRecordType::Https), (45, DnsRecordType::Svcb)] {
            let domain = DomainName::new("example.com").unwrap();
            let query = encode_query(id, &domain, record_type).unwrap();
            let response = encode_response(
                &query,
                &DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: Vec::new(),
                    service_bindings: vec![binding.clone(), alias.clone()],
                    minimum_ttl: Some(19),
                },
            )
            .unwrap();
            let decoded = decode_response(&response, id, record_type).unwrap();
            assert_eq!(
                decoded.service_bindings,
                vec![expected.clone(), alias.clone()]
            );
            assert_eq!(decoded.minimum_ttl, Some(19));
        }
    }

    #[test]
    fn malformed_packet_is_rejected() {
        assert!(decode_response(&[0, 1, 2], 1, DnsRecordType::A).is_err());
    }

    #[test]
    fn bounded_random_dns_wire_never_panics() {
        let mut state = 0x243f_6a88_u32;
        for length in 0..2048 {
            let mut packet = vec![0u8; length];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let _ = decode_query(&packet);
            let _ = decode_response(&packet, 7, DnsRecordType::A);
            let _ = decode_response(&packet, 7, DnsRecordType::Aaaa);
            let _ = decode_response(&packet, 7, DnsRecordType::Https);
            let _ = decode_response(&packet, 7, DnsRecordType::Svcb);
            let _ = answer_query(&packet, &RandomWireHandler);
        }
    }

    struct RandomWireHandler;

    impl DnsHandler for RandomWireHandler {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(1),
            })
        }
    }

    struct EchoTransport;

    impl DohTransport for EchoTransport {
        fn post_dns_message(
            &self,
            _endpoint: &str,
            body: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            let request = Message::from_vec(body)
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.add_query(request.queries[0].clone());
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                15,
                RData::A(Ipv4Addr::new(198, 51, 100, 1).into()),
            ));
            response
                .to_vec()
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
        }
    }

    #[test]
    fn doh_client_uses_transport_boundary_and_dns_codec() {
        let client = DohClient {
            endpoint: "https://resolver.example/dns-query".to_owned(),
            timeout: Duration::from_secs(1),
            transport: EchoTransport,
        };
        let result = client
            .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
            .unwrap();
        assert_eq!(result.addresses.v4, vec![Ipv4Addr::new(198, 51, 100, 1)]);
    }

    struct CountingResolver {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl DnsHandler for CountingResolver {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 8)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(60),
            })
        }
    }

    #[test]
    fn dns_cache_reuses_entries_and_evicts_by_capacity() {
        let cache = DnsCache::new(1).unwrap();
        let resolver = CountingResolver {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let handler = CachingDnsHandler {
            upstream: resolver,
            cache: cache.clone(),
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        handler.resolve(&first, DnsRecordType::A).unwrap();
        handler.resolve(&first, DnsRecordType::A).unwrap();
        assert_eq!(
            handler
                .upstream
                .calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        handler.resolve(&second, DnsRecordType::A).unwrap();
        assert_eq!(cache.len().unwrap(), 1);
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_none());
    }

    #[test]
    fn dns_cache_promotes_hits_before_evicting_the_least_recent_entry() {
        let cache = DnsCache::new(2).unwrap();
        let response = |address| DnsResponse {
            addresses: IpSet {
                v4: vec![address],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        let third = DomainName::new("third.example").unwrap();
        cache
            .insert(
                first.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 1)),
            )
            .unwrap();
        cache
            .insert(
                second.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 2)),
            )
            .unwrap();

        // A hit must move `first` to the MRU position. Inserting `third`
        // therefore evicts `second`, not the entry that was inserted first.
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
        cache
            .insert(
                third.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 3)),
            )
            .unwrap();
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
        assert!(cache.get(&second, DnsRecordType::A).unwrap().is_none());
        assert!(cache.get(&third, DnsRecordType::A).unwrap().is_some());
    }

    #[test]
    fn raw_dns_cache_has_the_same_lru_promotion_behavior() {
        let cache = DnsCache::new(2).unwrap();
        let packet = |id, domain: &DomainName, address| {
            let query = encode_query(id, domain, DnsRecordType::A).unwrap();
            encode_response(
                &query,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec![address],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(60),
                },
            )
            .unwrap()
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        let third = DomainName::new("third.example").unwrap();
        cache
            .insert_raw(
                first.clone(),
                1,
                packet(1, &first, Ipv4Addr::new(192, 0, 2, 1)),
            )
            .unwrap();
        cache
            .insert_raw(
                second.clone(),
                1,
                packet(2, &second, Ipv4Addr::new(192, 0, 2, 2)),
            )
            .unwrap();
        assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
        cache
            .insert_raw(
                third.clone(),
                1,
                packet(3, &third, Ipv4Addr::new(192, 0, 2, 3)),
            )
            .unwrap();
        assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
        assert!(cache.get_raw_optimistic(&second, 1).unwrap().is_none());
        assert!(cache.get_raw_optimistic(&third, 1).unwrap().is_some());
    }

    #[test]
    fn oversized_udp_dns_response_sets_truncation_without_returning_answers() {
        // A legacy client without EDNS advertises the RFC 1035 512-byte
        // limit. `encode_query` intentionally adds EDNS(0), so construct the
        // legacy form explicitly for this truncation test.
        let mut query_message =
            Message::new(0x1234, MessageType::Query, hickory_proto::op::OpCode::Query);
        query_message.add_query(Query::query(
            Name::from_utf8("large.example.").unwrap(),
            RecordType::A,
        ));
        let query = query_message.to_vec().unwrap();
        let answer = DnsResponse {
            addresses: IpSet {
                v4: (0..128)
                    .map(|index| Ipv4Addr::new(192, 0, 2, (index % 250) as u8))
                    .collect(),
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        };
        let response = encode_response(&query, &answer).unwrap();
        assert!(response.len() > 512);
        let truncated = truncate_dns_response(&query, &response).unwrap();
        assert!(response_is_truncated(&truncated).unwrap());
        assert!(Message::from_vec(&truncated).unwrap().answers.is_empty());
    }

    #[test]
    fn zero_capacity_dns_cache_is_rejected() {
        assert!(DnsCache::new(0).is_err());
    }

    struct StaticHandler;
    impl DnsHandler for StaticHandler {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    #[test]
    fn udp_dns_server_answers_local_client_and_policy_can_block() {
        let server =
            UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), StaticHandler, 128).unwrap();
        let address = server.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || server.serve_once().unwrap());
        let client = UdpDnsClient {
            server: address,
            timeout: Duration::from_secs(1),
            max_packet_size: 512,
        };
        let domain = DomainName::new("example.com").unwrap();
        let response = client.query(&domain, DnsRecordType::A).unwrap();
        assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(server_thread.join().unwrap(), 45);

        let blocked = PolicyDnsHandler {
            upstream: StaticHandler,
            policy: DnsPolicy::Block,
        };
        assert_eq!(
            blocked.resolve(&domain, DnsRecordType::A).unwrap_err().kind,
            ErrorKind::Closed
        );
        let empty = PolicyDnsHandler {
            upstream: StaticHandler,
            policy: DnsPolicy::Empty,
        };
        assert!(
            empty
                .resolve(&domain, DnsRecordType::A)
                .unwrap()
                .addresses
                .is_empty()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_dns_policy_is_cancellable_when_owner_drops_future() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PendingResolver {
            dropped: Arc<AtomicBool>,
        }
        impl AsyncDnsHandler for PendingResolver {
            fn answer<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
                let dropped = Arc::clone(&self.dropped);
                Box::pin(async move {
                    struct Guard(Arc<AtomicBool>);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            self.0.store(true, Ordering::Release);
                        }
                    }
                    let _guard = Guard(dropped);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok(Vec::new())
                })
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let resolver = AsyncPolicyDnsHandler {
            upstream: PendingResolver {
                dropped: Arc::clone(&dropped),
            },
            policy: DnsPolicy::Upstream,
        };
        let packet = encode_query(
            7,
            &DomainName::new("example.com").unwrap(),
            DnsRecordType::A,
        )
        .unwrap();
        let mut future = resolver.answer(&packet);
        tokio::select! {
            _ = &mut future => panic!("pending DNS resolver unexpectedly completed"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        drop(future);
        assert!(dropped.load(Ordering::Acquire));

        let blocked = AsyncPolicyDnsHandler {
            upstream: PendingResolver { dropped },
            policy: DnsPolicy::Block,
        };
        assert_eq!(
            blocked.answer(&packet).await.unwrap_err().kind,
            ErrorKind::Closed
        );
    }
}

mod async_udp {
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex, Weak};
    use std::time::Duration;

    use futures_util::future::BoxFuture;
    use futures_util::stream::{FuturesUnordered, StreamExt};
    use tokio::net::UdpSocket;
    use tokio::sync::{Notify, oneshot};

    use crate::dns::{
        AsyncDnsHandler, DnsRecordType, DnsResponse, decode_raw_query_key, decode_response,
        encode_query, truncate_dns_response, validate_query_packet, validate_response_packet,
    };
    use crate::transport::bind_udp_socket;
    use crate::{DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result};

    type PendingKey = (u16, DomainName, u16);

    struct AsyncUdpDnsClientState {
        socket: Mutex<Option<Arc<UdpSocket>>>,
        pending: Mutex<HashMap<PendingKey, oneshot::Sender<Result<Vec<u8>>>>>,
        shutdown: Arc<Notify>,
    }

    struct ReceiverCleanup {
        state: Weak<AsyncUdpDnsClientState>,
        socket: Arc<UdpSocket>,
    }

    impl Drop for ReceiverCleanup {
        fn drop(&mut self) {
            let Some(state) = self.state.upgrade() else {
                return;
            };
            if let Ok(mut stored) = state.socket.lock()
                && stored
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &self.socket))
            {
                *stored = None;
            }
        }
    }

    impl Default for AsyncUdpDnsClientState {
        fn default() -> Self {
            Self {
                socket: Mutex::new(None),
                pending: Mutex::new(HashMap::new()),
                shutdown: Arc::new(Notify::new()),
            }
        }
    }

    #[derive(Clone)]
    pub struct AsyncUdpDnsClient {
        pub server: SocketAddr,
        pub timeout: Duration,
        pub max_packet_size: usize,
        pub local_bind_addresses: Arc<[IpAddr]>,
        pub bind_interface: Option<String>,
        state: Arc<AsyncUdpDnsClientState>,
    }

    impl AsyncUdpDnsClient {
        pub fn new(
            server: SocketAddr,
            timeout: Duration,
            max_packet_size: usize,
            local_bind_addresses: Arc<[IpAddr]>,
            bind_interface: Option<String>,
        ) -> Self {
            Self {
                server,
                timeout,
                max_packet_size,
                local_bind_addresses,
                bind_interface,
                state: Arc::new(AsyncUdpDnsClientState::default()),
            }
        }

        async fn socket(&self) -> Result<Arc<UdpSocket>> {
            if let Some(socket) = self
                .state
                .socket
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP socket lock poisoned"))?
                .clone()
            {
                return Ok(socket);
            }

            let default_bind = if self.server.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            let bind_address = self
                .local_bind_addresses
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == self.server.is_ipv4())
                .map(|address| SocketAddr::new(address, 0))
                .unwrap_or(default_bind);
            let socket = Arc::new(
                bind_udp_socket(
                    bind_address,
                    self.server,
                    self.bind_interface.as_deref(),
                    "DNS",
                )
                .await?,
            );

            let mut stored = self
                .state
                .socket
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP socket lock poisoned"))?;
            if let Some(existing) = stored.as_ref() {
                return Ok(existing.clone());
            }
            *stored = Some(socket.clone());
            drop(stored);

            let state: Weak<AsyncUdpDnsClientState> = Arc::downgrade(&self.state);
            let shutdown = self.state.shutdown.clone();
            let server = self.server;
            let response_buffer_size = self.max_packet_size.max(512);
            let receiver_socket = socket.clone();
            tokio::spawn(async move {
                let _cleanup = ReceiverCleanup {
                    state: state.clone(),
                    socket: receiver_socket.clone(),
                };
                let mut response = vec![0; response_buffer_size];
                loop {
                    let result = tokio::select! {
                        _ = shutdown.notified() => return,
                        result = receiver_socket.recv_from(&mut response) => result,
                    };
                    let (size, peer) = match result {
                        Ok(value) => value,
                        Err(error) => {
                            let Some(state) = state.upgrade() else {
                                return;
                            };
                            if let Ok(mut stored) = state.socket.lock()
                                && stored
                                    .as_ref()
                                    .is_some_and(|current| Arc::ptr_eq(current, &receiver_socket))
                            {
                                *stored = None;
                            }
                            if let Ok(mut pending) = state.pending.lock() {
                                for (_, sender) in pending.drain() {
                                    let _ = sender.send(Err(Error::new(
                                        ErrorKind::Io,
                                        format!("receive DNS response: {error}"),
                                    )));
                                }
                            }
                            return;
                        }
                    };
                    if peer != server || size < 2 {
                        continue;
                    }
                    let packet = response[..size].to_vec();
                    let Ok((domain, record_type)) = decode_raw_query_key(&packet) else {
                        continue;
                    };
                    let key = (
                        u16::from_be_bytes([packet[0], packet[1]]),
                        domain,
                        record_type,
                    );
                    let Some(state) = state.upgrade() else {
                        return;
                    };
                    if let Ok(mut pending) = state.pending.lock()
                        && let Some(sender) = pending.remove(&key)
                    {
                        let _ = sender.send(Ok(packet));
                    }
                }
            });
            Ok(socket)
        }

        async fn query_packet_once(&self, packet: &[u8]) -> Result<Vec<u8>> {
            validate_query_packet(packet)?;
            let (domain, record_type) = decode_raw_query_key(packet)?;
            let request_id = u16::from_be_bytes([packet[0], packet[1]]);
            let key = (request_id, domain, record_type);
            let socket = self.socket().await?;
            let (sender, receiver) = oneshot::channel();
            self.state
                .pending
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP pending lock poisoned"))?
                .insert(key.clone(), sender);
            if let Err(error) = socket.send_to(packet, self.server).await {
                if let Ok(mut pending) = self.state.pending.lock() {
                    pending.remove(&key);
                }
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("send DNS query: {error}"),
                ));
            }
            match tokio::time::timeout(self.timeout, receiver).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(Error::new(
                    ErrorKind::Closed,
                    "DNS UDP response waiter closed",
                )),
                Err(_) => {
                    if let Ok(mut pending) = self.state.pending.lock() {
                        pending.remove(&key);
                    }
                    Err(Error::new(ErrorKind::Timeout, "DNS UDP query timed out"))
                }
            }
        }

        /// Send a complete DNS message without narrowing its QTYPE to the
        /// address-oriented resolver model. This is used for MX/TXT/CNAME and
        /// DNSSEC queries received by the runtime DNS server.
        pub async fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
            let response = self.query_packet_once(packet).await?;
            validate_response_packet(packet, &response)?;
            let message = hickory_proto::op::Message::from_vec(&response)
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            if message.metadata.truncation {
                let client = crate::dns_tcp::AsyncTcpDnsClient {
                    server: self.server,
                    timeout: self.timeout,
                    max_packet_size: self.max_packet_size,
                    local_bind_addresses: self.local_bind_addresses.clone(),
                    bind_interface: self.bind_interface.clone(),
                };
                return client.query_packet(packet).await;
            }
            Ok(response)
        }

        pub async fn query(
            &self,
            domain: &DomainName,
            record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            let id = next_transaction_id();
            let request = encode_query(id, domain, record_type)?;
            let response = self.query_packet(&request).await?;
            decode_response(&response, id, record_type)
        }

        pub async fn resolve(
            &self,
            domain: &DomainName,
            strategy: ResolveStrategy,
        ) -> Result<IpSet> {
            let mut result = IpSet::default();
            match strategy {
                ResolveStrategy::OnlyIpv4 => {
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                }
                ResolveStrategy::OnlyIpv6 => {
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                }
                ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                }
                ResolveStrategy::PreferIpv6 => {
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                }
            }
            Ok(result)
        }
    }

    impl Drop for AsyncUdpDnsClient {
        fn drop(&mut self) {
            // The receiver task intentionally keeps only a Weak reference to the
            // client state. Wake it when the last public client handle disappears
            // so reloads do not accumulate one task and socket per resolver.
            if Arc::strong_count(&self.state) == 1 {
                self.state.shutdown.notify_one();
            }
        }
    }

    pub struct AsyncUdpDnsHandler {
        pub client: AsyncUdpDnsClient,
    }

    impl AsyncUdpDnsHandler {
        pub fn new(client: AsyncUdpDnsClient) -> Self {
            Self { client }
        }
    }

    impl AsyncDnsHandler for AsyncUdpDnsHandler {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move { self.client.query_packet(packet).await })
        }
    }

    pub struct AsyncUdpDnsServer<H> {
        pub socket: UdpSocket,
        pub handler: H,
        pub max_packet_size: usize,
        pub max_inflight: usize,
    }

    impl<H: AsyncDnsHandler> AsyncUdpDnsServer<H> {
        pub async fn bind(address: SocketAddr, handler: H, max_packet_size: usize) -> Result<Self> {
            let socket = UdpSocket::bind(address).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind DNS UDP server: {error}"))
            })?;
            Ok(Self {
                socket,
                handler,
                max_packet_size: max_packet_size.max(512),
                max_inflight: 150,
            })
        }

        pub fn local_addr(&self) -> Result<SocketAddr> {
            self.socket
                .local_addr()
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
        }

        pub async fn serve_once(&self) -> Result<usize> {
            self.serve_once_from().await.map(|(size, _)| size)
        }

        pub async fn serve_once_from(&self) -> Result<(usize, SocketAddr)> {
            let mut request = vec![0; self.max_packet_size];
            let (size, peer) = self.socket.recv_from(&mut request).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("receive DNS request: {error}"))
            })?;
            let packet = self.handler.answer(&request[..size]).await?;
            let packet = truncate_dns_response(&request[..size], &packet)?;
            let sent = self.socket.send_to(&packet, peer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("send DNS response: {error}"))
            })?;
            Ok((sent, peer))
        }

        /// Serve requests until the owner signals shutdown.
        ///
        /// The handler is deliberately kept in the server instead of being moved
        /// into a spawned task, so dropping the returned future also cancels an
        /// in-flight upstream DNS query and releases the socket with the TUN
        /// runtime owner.
        pub async fn serve_until<S>(&self, shutdown: S) -> Result<()>
        where
            S: Future<Output = ()>,
        {
            tokio::pin!(shutdown);
            let mut pending = FuturesUnordered::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown => return Ok(()),
                    result = pending.next(), if !pending.is_empty() => {
                        // Go logs and drops an individual malformed/upstream
                        // request while keeping the listener alive.
                        let _ = result;
                    }
                    result = async {
                        let mut request = vec![0; self.max_packet_size];
                        let (size, peer) = self.socket.recv_from(&mut request).await
                            .map_err(|error| Error::new(ErrorKind::Io, format!("receive DNS request: {error}")))?;
                        Ok::<_, Error>((request[..size].to_vec(), peer))
                    } => {
                        let (request, peer) = result?;
                        if pending.len() >= self.max_inflight.max(1)
                            && let Some(result) = pending.next().await
                        {
                            let _ = result;
                        }
                        pending.push(self.serve_packet(request, peer));
                    }
                }
            }
        }

        fn serve_packet<'a>(
            &'a self,
            request: Vec<u8>,
            peer: SocketAddr,
        ) -> LocalBoxFuture<'a, Result<(usize, SocketAddr)>> {
            Box::pin(async move {
                let response = self.handler.answer(&request).await?;
                let response = truncate_dns_response(&request, &response)?;
                let sent = self
                    .socket
                    .send_to(&response, peer)
                    .await
                    .map_err(|error| {
                        Error::new(ErrorKind::Io, format!("send DNS response: {error}"))
                    })?;
                Ok((sent, peer))
            })
        }
    }

    fn next_transaction_id() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::dns::{decode_query, encode_query, encode_raw_query, encode_response};

        #[test]
        fn async_udp_client_and_handler_round_trip_with_original_transaction() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                struct StaticHandler;

                impl AsyncDnsHandler for StaticHandler {
                    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
                        Box::pin(async move {
                            encode_response(
                                packet,
                                &DnsResponse {
                                    addresses: IpSet {
                                        v4: vec!["192.0.2.55".parse().unwrap()],
                                        v6: Vec::new(),
                                    },
                                    ptr_names: Vec::new(),
                                    service_bindings: Vec::new(),
                                    minimum_ttl: Some(30),
                                },
                            )
                        })
                    }
                }

                let server =
                    AsyncUdpDnsServer::bind((Ipv4Addr::LOCALHOST, 0).into(), StaticHandler, 4096)
                        .await
                        .unwrap();
                let server_address = server.local_addr().unwrap();
                let server_future = async move {
                    let (_, first_peer) = server.serve_once_from().await.unwrap();
                    let (_, second_peer) = server.serve_once_from().await.unwrap();
                    assert_eq!(first_peer.ip(), IpAddr::V4("127.0.0.2".parse().unwrap()));
                    assert_eq!(second_peer.ip(), IpAddr::V4("127.0.0.2".parse().unwrap()));
                };

                let client = AsyncUdpDnsClient::new(
                    server_address,
                    Duration::from_secs(1),
                    4096,
                    Arc::from(vec!["127.0.0.2".parse::<IpAddr>().unwrap()].into_boxed_slice()),
                    None,
                );
                let domain = DomainName::new("example.com").unwrap();
                let client_future = async move {
                    let direct = client.query(&domain, DnsRecordType::A).await.unwrap();
                    assert_eq!(
                        direct.addresses.v4,
                        vec!["192.0.2.55".parse::<Ipv4Addr>().unwrap()]
                    );

                    let handler = AsyncUdpDnsHandler::new(client);
                    let request = encode_query(0x4a2b, &domain, DnsRecordType::A).unwrap();
                    let response = handler.answer(&request).await.unwrap();
                    let decoded = decode_response(&response, 0x4a2b, DnsRecordType::A).unwrap();
                    assert_eq!(
                        decoded.addresses.v4,
                        vec!["192.0.2.55".parse::<Ipv4Addr>().unwrap()]
                    );
                };
                tokio::join!(server_future, client_future);
            });
        }

        #[test]
        fn async_udp_client_forwards_unmodeled_qtypes_as_raw_packets() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime
                .block_on(async {
                    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                    let address = socket.local_addr().unwrap();
                    let server = tokio::spawn(async move {
                        let mut request = vec![0; 2048];
                        let (size, peer) = socket.recv_from(&mut request).await.unwrap();
                        let request = &request[..size];
                        assert_eq!(
                            decode_query(request).unwrap_err().kind,
                            ErrorKind::Unsupported
                        );
                        let mut response = request.to_vec();
                        response[2] |= 0x80;
                        socket.send_to(&response, peer).await.unwrap();
                    });

                    let client = AsyncUdpDnsClient::new(
                        address,
                        Duration::from_secs(1),
                        2048,
                        Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
                        None,
                    );
                    let query =
                        encode_raw_query(0x5a5a, &DomainName::new("example.com").unwrap(), 16)?;
                    let response = client.query_packet(&query).await?;
                    assert_eq!(&response[..2], &query[..2]);
                    server.await.unwrap();
                    Ok::<_, Error>(())
                })
                .unwrap();
        }

        #[test]
        fn async_udp_server_serve_until_stops_after_owner_signal() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                struct StaticHandler;

                impl AsyncDnsHandler for StaticHandler {
                    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
                        Box::pin(async move {
                            encode_response(
                                packet,
                                &DnsResponse {
                                    addresses: IpSet {
                                        v4: vec!["192.0.2.56".parse().unwrap()],
                                        v6: Vec::new(),
                                    },
                                    ptr_names: Vec::new(),
                                    service_bindings: Vec::new(),
                                    minimum_ttl: Some(30),
                                },
                            )
                        })
                    }
                }

                let server =
                    AsyncUdpDnsServer::bind((Ipv4Addr::LOCALHOST, 0).into(), StaticHandler, 4096)
                        .await
                        .unwrap();
                let server_address = server.local_addr().unwrap();
                let (stop, stop_signal) = tokio::sync::oneshot::channel();
                let server_future = async move {
                    server
                        .serve_until(async move {
                            let _ = stop_signal.await;
                        })
                        .await
                };
                let client = AsyncUdpDnsClient::new(
                    server_address,
                    Duration::from_secs(1),
                    4096,
                    Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
                    None,
                );
                let client_future = async {
                    let answer = client
                        .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
                        .await;
                    let _ = stop.send(());
                    answer
                };
                let (answer, server_result) = tokio::join!(client_future, server_future);
                answer.unwrap();
                server_result.unwrap();
            });
        }
    }
}

pub use async_udp::{AsyncUdpDnsClient, AsyncUdpDnsHandler, AsyncUdpDnsServer};
