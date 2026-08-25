//! Async DNS query traits.

use super::*;

/// Query-level variant whose future can safely cross a Tokio task boundary.
pub trait SendAsyncDnsQuery: Send + Sync {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>>;

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let answer = self
                .query_send(&question.domain, question.record_type)
                .await?;
            encode_response(packet, &answer)
        })
    }
}

impl<T: SendAsyncDnsQuery + ?Sized> SendAsyncDnsQuery for Box<T> {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        (**self).query_send(domain, record_type)
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        (**self).query_packet_send(packet)
    }
}

pub trait AsyncDnsQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>>;

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let answer = self.query(&question.domain, question.record_type).await?;
            encode_response(packet, &answer)
        })
    }
}

impl AsyncDnsQuery for AsyncUdpDnsClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncUdpDnsClient::query(self, domain, record_type).await })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

impl SendAsyncDnsQuery for AsyncUdpDnsClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncUdpDnsClient::query(self, domain, record_type).await })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

impl<T: AsyncDnsQuery + ?Sized> AsyncDnsQuery for Box<T> {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        (**self).query(domain, record_type)
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        (**self).query_packet(packet)
    }
}

#[cfg(feature = "http")]
impl<C: crate::dns_http::DnsOverHttpConnector> AsyncDnsQuery for crate::dns_http::DnsOverHttp<C> {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { crate::dns_http::DnsOverHttp::query(self, domain, record_type).await },
        )
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

#[cfg(feature = "http")]
impl<C: crate::dns_http::DnsOverHttpConnector> SendAsyncDnsQuery
    for crate::dns_http::DnsOverHttp<C>
{
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { crate::dns_http::DnsOverHttp::query(self, domain, record_type).await },
        )
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}
