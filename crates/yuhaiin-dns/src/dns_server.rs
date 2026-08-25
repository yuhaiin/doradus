//! Synchronous DNS server and async policy boundary.

use super::*;

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
