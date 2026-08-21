//! Runtime-neutral DNS over HTTP client.
//!
//! [`DnsOverHttp`] owns the RFC 8484 request and response semantics while
//! Hyper owns HTTP/1.1 and HTTP/2 framing, stream management, and flow
//! control. TLS, proxy dialing, and bootstrap policy are injected through
//! [`DnsOverHttpConnector`]. HTTP/3 remains a separate transport because it
//! uses QUIC rather than a TCP byte stream.

use bytes::Bytes;
use http::{Request, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::dns::AsyncDnsHandler;
use crate::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, validate_query_packet,
    validate_response_packet,
};
use crate::{BoxFuture, DomainName, Error, ErrorKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1,
    Http2,
}

pub struct HttpConnection<S> {
    pub stream: S,
    pub version: HttpVersion,
}

pub trait DnsOverHttpConnector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect<'a>(&'a self, uri: &'a Uri) -> BoxFuture<'a, Result<HttpConnection<Self::Stream>>>;
}

type RequestBody = Full<Bytes>;

enum HttpSender {
    Http1(http1::SendRequest<RequestBody>),
    Http2(http2::SendRequest<RequestBody>),
}

pub struct DnsOverHttp<C> {
    pub endpoint: Uri,
    pub connector: C,
    connection: Arc<Mutex<Option<HttpSender>>>,
}

/// Packet-level adapter that makes the DoH client usable by the asynchronous
/// DNS/TUN pipeline. The upstream query gets a fresh internal transaction ID,
/// while the response is rebuilt from the original packet so callers keep
/// their own ID and question flags.
pub struct DnsOverHttpHandler<C> {
    pub client: DnsOverHttp<C>,
}

impl<C> DnsOverHttpHandler<C> {
    pub fn new(client: DnsOverHttp<C>) -> Self {
        Self { client }
    }
}

impl<C: DnsOverHttpConnector> DnsOverHttp<C> {
    pub fn new(endpoint: Uri, connector: C) -> Self {
        Self {
            endpoint,
            connector,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    async fn open_sender(&self) -> Result<HttpSender> {
        let connection = self.connector.connect(&self.endpoint).await?;
        let io = TokioIo::new(connection.stream);

        match connection.version {
            HttpVersion::Http1 => {
                let (sender, driver) = http1::handshake(io).await.map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("HTTP/1.1 handshake: {error}"))
                })?;
                tokio::spawn(async move {
                    let _ = driver.await;
                });
                Ok(HttpSender::Http1(sender))
            }
            HttpVersion::Http2 => {
                let (sender, driver) =
                    http2::handshake(TokioExecutor::new(), io)
                        .await
                        .map_err(|error| {
                            Error::new(ErrorKind::Protocol, format!("HTTP/2 handshake: {error}"))
                        })?;
                tokio::spawn(async move {
                    let _ = driver.await;
                });
                Ok(HttpSender::Http2(sender))
            }
        }
    }

    async fn request(&self, request: Request<RequestBody>) -> Result<hyper::Response<Incoming>> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            *connection = Some(self.open_sender().await?);
        }

        let result = match connection.as_mut().expect("connection was initialized") {
            HttpSender::Http1(sender) => sender.send_request(request).await,
            HttpSender::Http2(sender) => sender.send_request(request).await,
        }
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("DoH HTTP request: {error}")));

        if result.is_err() {
            connection.take();
        }
        result
    }

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
        let authority = self
            .endpoint
            .authority()
            .ok_or_else(|| Error::invalid("DoH endpoint has no authority"))?;
        let target = self
            .endpoint
            .path_and_query()
            .map(ToString::to_string)
            .unwrap_or_else(|| "/".to_owned());
        let request = Request::builder()
            .method("POST")
            .uri(target)
            .header(header::HOST, authority.as_str())
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::ACCEPT, "application/dns-message")
            .body(Full::new(Bytes::copy_from_slice(query_packet)))
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;

        let response = self.request(request).await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.connection.lock().await.take();
                return Err(error);
            }
        };

        if !response.status().is_success() {
            self.connection.lock().await.take();
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
            self.connection.lock().await.take();
            return Err(Error::new(
                ErrorKind::Protocol,
                "DoH endpoint returned a non-DNS content type",
            ));
        }

        let body = match response.into_body().collect().await {
            Ok(body) => body,
            Err(error) => {
                self.connection.lock().await.take();
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!("DoH response body: {error}"),
                ));
            }
        };
        let bytes = body.to_bytes();
        if let Err(error) = validate_response_packet(query_packet, &bytes) {
            self.connection.lock().await.take();
            return Err(error);
        }
        Ok(bytes.to_vec())
    }
}

impl<C: DnsOverHttpConnector> AsyncDnsHandler for DnsOverHttpHandler<C> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
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
    use crate::{IpSet, dns::encode_query};
    use http_body_util::Full;
    use hyper::service::service_fn;
    use tokio::io::DuplexStream;

    #[derive(Clone, Copy)]
    struct TestConnector {
        version: HttpVersion,
    }

    impl DnsOverHttpConnector for TestConnector {
        type Stream = DuplexStream;

        fn connect<'a>(
            &'a self,
            _uri: &'a Uri,
        ) -> BoxFuture<'a, Result<HttpConnection<Self::Stream>>> {
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                let version = self.version;
                tokio::spawn(async move {
                    let service = service_fn(|request: hyper::Request<Incoming>| async move {
                        let query = request.into_body().collect().await.unwrap().to_bytes();
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
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(201)
                                .header(header::CONTENT_TYPE, "application/dns-message")
                                .body(Full::new(Bytes::from(response)))
                                .unwrap(),
                        )
                    });
                    let io = TokioIo::new(server);
                    match version {
                        HttpVersion::Http1 => {
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        }
                        HttpVersion::Http2 => {
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await;
                        }
                    }
                });
                Ok(HttpConnection {
                    stream: client,
                    version,
                })
            })
        }
    }

    #[tokio::test]
    async fn supports_http1_and_http2_with_one_doh_client() {
        for version in [HttpVersion::Http1, HttpVersion::Http2] {
            let client = DnsOverHttp::new(
                "https://example.invalid/dns-query".parse().unwrap(),
                TestConnector { version },
            );
            let domain = DomainName::new("example.com").unwrap();
            let response = client.query(&domain, DnsRecordType::A).await.unwrap();
            assert_eq!(
                response.addresses.v4,
                vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
            );
        }
    }

    #[tokio::test]
    async fn handler_preserves_the_original_dns_transaction() {
        let handler = DnsOverHttpHandler::new(DnsOverHttp::new(
            "https://example.invalid/dns-query".parse().unwrap(),
            TestConnector {
                version: HttpVersion::Http2,
            },
        ));
        let domain = DomainName::new("example.com").unwrap();
        let request = encode_query(0x4a2a, &domain, DnsRecordType::A).unwrap();
        let response = handler.answer(&request).await.unwrap();
        let decoded = decode_response(&response, 0x4a2a, DnsRecordType::A).unwrap();
        assert_eq!(
            decoded.addresses.v4,
            vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(decoded.minimum_ttl, Some(30));
    }
}
