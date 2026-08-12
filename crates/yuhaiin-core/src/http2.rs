//! Runtime-neutral HTTP/2 DoH client.
//!
//! TLS is intentionally injected through [`H2DohConnector`]. The core crate
//! therefore owns DNS message construction and HTTP/2 framing, while the
//! application chooses a certificate verifier and a pure-Rust crypto provider.

use bytes::Bytes;
use http::{Request, Uri, header};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "async-proxy")]
use crate::LocalBoxFuture;
#[cfg(feature = "async-proxy")]
use crate::dns::AsyncDnsHandler;
use crate::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, validate_query_packet,
    validate_response_packet,
};
use crate::{BoxFuture, DomainName, Error, ErrorKind, Result};

pub trait H2DohConnector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect<'a>(&'a self, uri: &'a Uri) -> BoxFuture<'a, Result<Self::Stream>>;
}
pub struct H2DohClient<C> {
    pub endpoint: Uri,
    pub connector: C,
}

/// Packet-level adapter that makes the HTTP/2 DoH client usable by the
/// asynchronous DNS/TUN pipeline. The upstream query gets a fresh internal
/// transaction ID, while the response is rebuilt from the original packet so
/// callers keep their own ID and question flags.
#[cfg(feature = "async-proxy")]
pub struct H2DohDnsHandler<C> {
    pub client: H2DohClient<C>,
}

#[cfg(feature = "async-proxy")]
impl<C> H2DohDnsHandler<C> {
    pub fn new(client: H2DohClient<C>) -> Self {
        Self { client }
    }
}

impl<C: H2DohConnector> H2DohClient<C> {
    pub async fn query(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let body = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&body).await?;
        decode_response(&response, id, record_type)
    }

    /// Send a complete RFC 8484 DNS message and return the upstream message
    /// unchanged. Keeping this boundary packet-oriented means DoH does not
    /// lose records, EDNS options or DNSSEC data that the typed resolver does
    /// not model.
    pub async fn query_packet(&self, query_packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(query_packet)?;
        let stream = self.connector.connect(&self.endpoint).await?;
        let (mut sender, connection) = h2::client::handshake(stream).await.map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("HTTP/2 handshake: {error}"))
        })?;

        let request = Request::builder()
            .method("POST")
            .uri(self.endpoint.clone())
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::ACCEPT, "application/dns-message")
            .body(())
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
        let (response, mut send_body) = sender
            // The DNS wire message is carried in the request body, so the
            // headers must not end the stream before `send_data` below.
            .send_request(request, false)
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP/2 request: {error}")))?;
        send_body
            .send_data(Bytes::copy_from_slice(query_packet), true)
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP/2 body: {error}")))?;

        let response_future = async {
            let response = response.await.map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("HTTP/2 response: {error}"))
            })?;
            if response.status() != http::StatusCode::OK {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!("DoH endpoint returned {}", response.status()),
                ));
            }
            if response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.starts_with("application/dns-message"))
            {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "DoH endpoint returned a non-DNS content type",
                ));
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("HTTP/2 response body: {error}"),
                    )
                })?;
                body.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|error| {
                        Error::new(ErrorKind::Protocol, format!("HTTP/2 flow control: {error}"))
                    })?;
                bytes.extend_from_slice(&chunk);
            }
            validate_response_packet(query_packet, &bytes)?;
            Ok(bytes)
        };

        // A DoH server normally keeps the HTTP/2 connection alive for reuse.
        // Waiting for the connection future with `join` would therefore wait
        // forever after the response body had arrived.  `select` still drives
        // the connection while the response is pending, then drops the
        // connection after this one-shot query has its complete body.
        let response_future = Box::pin(response_future);
        let connection = Box::pin(connection);
        match futures_util::future::select(response_future, connection).await {
            futures_util::future::Either::Left((result, _connection)) => result,
            futures_util::future::Either::Right((connection_result, _response)) => {
                connection_result
                    .map_err(|error| {
                        Error::new(ErrorKind::Protocol, format!("HTTP/2 connection: {error}"))
                    })
                    .and_then(|_| {
                        Err(Error::new(
                            ErrorKind::Protocol,
                            "HTTP/2 connection closed before the DoH response completed",
                        ))
                    })
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
impl<C: H2DohConnector> AsyncDnsHandler for H2DohDnsHandler<C> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.client.query_packet(packet).await })
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
    use crate::dns::encode_response;

    #[test]
    fn relative_uri_is_not_an_absolute_doh_endpoint() {
        let uri: Uri = "/dns-query".parse().unwrap();
        assert!(uri.scheme().is_none());
        assert!(uri.authority().is_none());
    }

    #[test]
    fn doh_query_returns_before_keep_alive_connection_closes() {
        use std::time::Duration;

        use crate::IpSet;
        use crate::dns::encode_response;
        use bytes::Bytes;
        use tokio::io::DuplexStream;

        #[derive(Clone, Copy)]
        struct KeepAliveConnector;

        impl H2DohConnector for KeepAliveConnector {
            type Stream = DuplexStream;

            fn connect<'a>(&'a self, _uri: &'a Uri) -> BoxFuture<'a, Result<Self::Stream>> {
                Box::pin(async {
                    let (client, server) = tokio::io::duplex(16 * 1024);
                    tokio::spawn(async move {
                        let mut connection = h2::server::handshake(server).await.unwrap();
                        let Some(Ok((request, mut respond))) = connection.accept().await else {
                            return;
                        };
                        let mut body = request.into_body();
                        let mut query = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            query.extend_from_slice(&chunk);
                        }
                        let response = encode_response(
                            &query,
                            &DnsResponse {
                                addresses: IpSet {
                                    v4: vec!["192.0.2.53".parse().unwrap()],
                                    v6: Vec::new(),
                                },
                                ptr_names: Vec::new(),
                                service_bindings: Vec::new(),
                                minimum_ttl: Some(30),
                            },
                        )
                        .unwrap();
                        let head = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(head, false).unwrap();
                        send.send_data(Bytes::from(response), true).unwrap();
                        // A normal DoH endpoint keeps the H2 connection alive
                        // after one response. The client query must not wait
                        // for this task or for the peer to send GOAWAY.
                        let _ = connection.accept().await;
                    });
                    Ok(client)
                })
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = H2DohClient {
                endpoint: "https://example.invalid/dns-query".parse().unwrap(),
                connector: KeepAliveConnector,
            };
            let domain = DomainName::new("example.com").unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                client.query(&domain, DnsRecordType::A),
            )
            .await
            .expect("DoH query must not wait for keep-alive close")
            .unwrap();
            assert_eq!(
                response.addresses.v4,
                vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
            );
        });
    }

    #[cfg(feature = "async-proxy")]
    #[test]
    fn async_doh_handler_preserves_the_original_dns_transaction() {
        use crate::IpSet;
        use crate::dns::{decode_response, encode_query};
        use bytes::Bytes;
        use tokio::io::DuplexStream;

        #[derive(Clone, Copy)]
        struct AdapterConnector;

        impl H2DohConnector for AdapterConnector {
            type Stream = DuplexStream;

            fn connect<'a>(&'a self, _uri: &'a Uri) -> BoxFuture<'a, Result<Self::Stream>> {
                Box::pin(async {
                    let (client, server) = tokio::io::duplex(16 * 1024);
                    tokio::spawn(async move {
                        let mut connection = h2::server::handshake(server).await.unwrap();
                        let Some(Ok((request, mut respond))) = connection.accept().await else {
                            return;
                        };
                        let mut body = request.into_body();
                        let mut query = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            query.extend_from_slice(&chunk);
                        }
                        let response = encode_response(
                            &query,
                            &DnsResponse {
                                addresses: IpSet {
                                    v4: vec!["192.0.2.54".parse().unwrap()],
                                    v6: Vec::new(),
                                },
                                ptr_names: Vec::new(),
                                service_bindings: Vec::new(),
                                minimum_ttl: Some(45),
                            },
                        )
                        .unwrap();
                        let head = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(head, false).unwrap();
                        send.send_data(Bytes::from(response), true).unwrap();
                        let _ = connection.accept().await;
                    });
                    Ok(client)
                })
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let handler = H2DohDnsHandler::new(H2DohClient {
                endpoint: "https://example.invalid/dns-query".parse().unwrap(),
                connector: AdapterConnector,
            });
            let domain = DomainName::new("example.com").unwrap();
            let request = encode_query(0x4a2a, &domain, DnsRecordType::A).unwrap();
            let response = handler.answer(&request).await.unwrap();
            let decoded = decode_response(&response, 0x4a2a, DnsRecordType::A).unwrap();
            assert_eq!(
                decoded.addresses.v4,
                vec!["192.0.2.54".parse::<std::net::Ipv4Addr>().unwrap()]
            );
            assert_eq!(decoded.minimum_ttl, Some(45));
        });
    }
}
