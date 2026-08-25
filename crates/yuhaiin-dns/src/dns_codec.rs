//! DNS wire codec and policy boundary.

use super::*;

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

pub(super) trait DnsServiceParamCodec {
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

/// Cheap, allocation-free gate for the DNS interception path.
///
/// This intentionally only recognizes the wire shape and the QTYPEs handled
/// by [`decode_query`]. Full validation still belongs to `decode_query`; the
/// gate exists so ordinary UDP payloads do not make Hickory build a complete
/// `Message` just to answer a boolean question.
pub fn looks_like_supported_query(packet: &[u8]) -> bool {
    let Some(header) = packet.get(..12) else {
        return false;
    };
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let question_count = u16::from_be_bytes([header[4], header[5]]);

    // Responses and non-standard opcodes are not inbound queries.  The
    // decoder only consumes the first question, so additional questions do
    // not need to be walked by this fast path.
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 || question_count == 0 {
        return false;
    }

    let mut offset = 12usize;
    let mut labels = 0usize;
    loop {
        let Some(&length) = packet.get(offset) else {
            return false;
        };
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xc0 == 0xc0 {
            // The first question starts immediately after the header, so it
            // has no earlier domain name that a compression pointer could
            // legally reference. Reject this in the allocation-free gate;
            // packets sent to port 53 still go through the full decoder.
            return false;
        }
        if length & 0xc0 != 0 || length > 63 {
            return false;
        }
        let length = usize::from(length);
        let Some(next) = offset.checked_add(1 + length) else {
            return false;
        };
        if next > packet.len() {
            return false;
        }
        offset = next;
        labels += 1;
        if labels > 127 {
            return false;
        }
    }

    let Some(question_tail) = packet.get(offset..offset.saturating_add(4)) else {
        return false;
    };
    let qtype = u16::from_be_bytes([question_tail[0], question_tail[1]]);
    matches!(qtype, 1 | 28 | 12 | 65 | 64)
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
    // Match Go's netapi.NewDNSMsg for locally synthesized responses.  The
    // hickory response constructor defaults both recursion bits to false,
    // which makes recursive answers look like a non-recursive server to
    // clients such as nslookup.
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
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
    // Keep the typed/synthetic response header aligned with Go's
    // netapi.NewDNSMsg: RD=1 and RA=1.  Raw upstream responses take a
    // different path and retain the flags supplied by the upstream server.
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
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
