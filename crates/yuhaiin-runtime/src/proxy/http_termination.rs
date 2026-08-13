//! Go-compatible `http_termination` outbound contract point.
//!
//! The Go implementation exposes a pipe as a TCP connection and runs a
//! reverse proxy on the other side of that pipe.  Keep the same boundary in
//! Rust: the inbound sees an ordinary byte stream, while each HTTP request is
//! opened through the already-built parent `AsyncProxy`.  Hyper owns HTTP
//! parsing, streaming bodies, keep-alive and HTTP/2 server negotiation; this
//! module only translates the Go contract into those primitives.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::proxy::{stream_local_addr, with_stream_local_addr};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_store::{GoProxyLayer, GoProxyRuntimeConfig};
use yuhaiin_trie::DomainTrie;

use super::http::parse_authority_with_default;

const PIPE_BUFFER_SIZE: usize = 128 * 1024;
type ResponseBody = BoxBody<Bytes, hyper::Error>;
type HeaderRules = DomainTrie<Vec<(HeaderName, HeaderValue)>>;

/// Build the wrapper from the preserved Go layer JSON.  The config is kept at
/// the runtime boundary so the public store/API structs do not grow a second
/// DTO just for this transport.
pub(crate) fn build(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
    tls_terminated: bool,
) -> Result<Arc<dyn AsyncProxy>> {
    let layer = config
        .layers
        .iter()
        .rev()
        .find(|layer| layer.kind.eq_ignore_ascii_case("http_termination"))
        .ok_or_else(|| Error::invalid("HTTP termination layer is missing"))?;
    let rules = parse_header_rules(layer)?;
    Ok(Arc::new(HttpTerminationProxy::new(
        upstream,
        rules,
        tls_terminated,
    )))
}

fn parse_header_rules(layer: &GoProxyLayer) -> Result<HeaderRules> {
    let mut rules = DomainTrie::new();
    let Some(headers) = layer.config.get("headers") else {
        return Ok(rules);
    };
    let headers = headers
        .as_object()
        .ok_or_else(|| Error::invalid("HTTP termination headers must be an object"))?;
    for (domain, value) in headers {
        let value = value
            .as_object()
            .ok_or_else(|| Error::invalid("HTTP termination header rules must be objects"))?;
        let entries = value
            .get("headers")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::invalid("HTTP termination header rule has no headers"))?;
        let mut compiled = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or_else(|| Error::invalid("HTTP termination header must be an object"))?;
            let key = entry
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("HTTP termination header key is missing"))?;
            let value = entry
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("HTTP termination header value is missing"))?;
            let key = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("HTTP termination header name {key:?}: {error}"),
                )
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("HTTP termination header value for {key}: {error}"),
                )
            })?;
            compiled.push((key, value));
        }
        rules.insert(domain, compiled).map_err(|error| {
            Error::invalid(format!("HTTP termination domain {domain:?}: {error}"))
        })?;
    }
    Ok(rules)
}

struct HttpTerminationProxy {
    upstream: Arc<dyn AsyncProxy>,
    headers: Arc<HeaderRules>,
    tls_terminated: bool,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl HttpTerminationProxy {
    fn new(upstream: Arc<dyn AsyncProxy>, headers: HeaderRules, tls_terminated: bool) -> Self {
        Self {
            upstream,
            headers: Arc::new(headers),
            tls_terminated,
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
        }
    }

    async fn serve_connection(
        server: tokio::io::DuplexStream,
        upstream: Arc<dyn AsyncProxy>,
        headers: Arc<HeaderRules>,
        base_context: FlowContext,
        tls_terminated: bool,
    ) {
        let service = service_fn(move |request| {
            let upstream = Arc::clone(&upstream);
            let headers = Arc::clone(&headers);
            let base_context = base_context.clone();
            async move {
                Ok::<_, Infallible>(
                    forward_request(request, upstream, headers, base_context, tls_terminated).await,
                )
            }
        });
        let builder = AutoBuilder::new(TokioExecutor::new());
        let _ = builder
            .serve_connection(TokioIo::new(server), service)
            .await;
    }

    async fn connect_stream(&self, context: &FlowContext) -> Result<BoxAsyncStream> {
        if context.network != Network::Tcp {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "HTTP termination requires a TCP flow",
            ));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "HTTP termination proxy is closed",
            ));
        }

        let (client, server) = tokio::io::duplex(PIPE_BUFFER_SIZE);
        let task = tokio::spawn(Self::serve_connection(
            server,
            Arc::clone(&self.upstream),
            Arc::clone(&self.headers),
            context.clone(),
            self.tls_terminated,
        ));
        let mut tasks = self.tasks.lock().await;
        if self.closed.load(Ordering::Acquire) {
            task.abort();
            return Err(Error::new(
                ErrorKind::Closed,
                "HTTP termination proxy is closed",
            ));
        }
        // A completed request no longer needs a shutdown handle. Reap it
        // before recording the next connection so a long-running reverse
        // proxy retains only active Hyper tasks instead of growing one handle
        // per request forever.
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(Box::new(client))
    }
}

impl AsyncProxy for HttpTerminationProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.connect_stream(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        self.upstream.open_datagram(context)
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<std::time::Duration>> {
        self.upstream.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.closed.store(true, Ordering::Release);
        let upstream = Arc::clone(&self.upstream);
        Box::pin(async move {
            let tasks = self.tasks.lock().await.drain(..).collect::<Vec<_>>();
            for task in tasks {
                task.abort();
            }
            upstream.close().await
        })
    }
}

async fn forward_request(
    request: Request<Incoming>,
    upstream: Arc<dyn AsyncProxy>,
    headers: Arc<HeaderRules>,
    base_context: FlowContext,
    tls_terminated: bool,
) -> Response<ResponseBody> {
    if request.method() == Method::CONNECT {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "HTTP termination does not tunnel CONNECT",
        );
    }
    let (destination, authority, target_uri, https) = match request_target(&request, tls_terminated)
    {
        Ok(target) => target,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
    };
    let context = target_context(&base_context, destination);
    let (mut parts, body) = request.into_parts();
    if let Some(rules) = lookup_headers(&headers, &context.destination) {
        apply_headers(&mut parts.headers, rules);
    }
    if !parts.headers.contains_key(header::HOST) {
        let value = match HeaderValue::from_str(&authority) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
        };
        parts.headers.insert(header::HOST, value);
    }
    remove_hop_by_hop(&mut parts.headers);
    parts.uri = target_uri;
    parts.version = Version::HTTP_11;
    let request = Request::from_parts(parts, body);

    let stream = match upstream.connect(&context).await {
        Ok(stream) => stream,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
    };
    let stream = if https {
        match wrap_https(stream, &context.destination).await {
            Ok(stream) => stream,
            Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
        }
    } else {
        stream
    };
    let io = TokioIo::new(stream);
    let (mut sender, connection) = match hyper::client::conn::http1::handshake(io).await {
        Ok(connection) => connection,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
    };
    let mut response = response.map(|body| body.boxed());
    remove_hop_by_hop(response.headers_mut());
    response
}

fn request_target<B>(
    request: &Request<B>,
    tls_terminated: bool,
) -> Result<(Endpoint, String, Uri, bool)> {
    let uri = request.uri();
    let scheme = uri.scheme_str();
    if let Some(scheme) = scheme
        && !scheme.eq_ignore_ascii_case("http")
        && !scheme.eq_ignore_ascii_case("https")
    {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("HTTP termination does not support URI scheme {scheme:?}"),
        ));
    }
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP request has no Host header"))?;
    let default_port =
        if tls_terminated || scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case("https")) {
            443
        } else {
            80
        };
    let destination = parse_authority_with_default(&authority, Network::Tcp, Some(default_port))?;
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let target_uri = path
        .parse::<Uri>()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP request path: {error}")))?;
    let https =
        scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case("https")) && !tls_terminated;
    Ok((destination, authority, target_uri, https))
}

#[cfg(feature = "doh-tls")]
async fn wrap_https(stream: BoxAsyncStream, destination: &Endpoint) -> Result<BoxAsyncStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let connector = tokio_rustls::TlsConnector::from(crate::doh_tls::client_config(roots)?);
    let name = destination
        .host()
        .map(|host| host.as_str().to_owned())
        .or_else(|| destination.addr().map(|addr| addr.ip().to_string()))
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "HTTPS target has no host"))?;
    let server_name = crate::doh_tls::tls_server_name(&name)?;
    let local_addr = stream_local_addr(&*stream);
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("HTTP termination HTTPS handshake: {error}"),
            )
        })?;
    Ok(with_stream_local_addr(Box::new(stream), local_addr))
}

#[cfg(not(feature = "doh-tls"))]
async fn wrap_https(_stream: BoxAsyncStream, _destination: &Endpoint) -> Result<BoxAsyncStream> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "HTTP termination HTTPS requires the doh-tls feature",
    ))
}

fn target_context(base: &FlowContext, destination: Endpoint) -> FlowContext {
    let mut context = base.clone();
    context.network = Network::Tcp;
    context.original_domain = destination.host().cloned();
    context.destination = destination;
    context.resolved_destination = None;
    context
}

fn lookup_headers<'a>(
    rules: &'a HeaderRules,
    destination: &Endpoint,
) -> Option<&'a [(HeaderName, HeaderValue)]> {
    let Endpoint::Domain { host, .. } = destination else {
        return None;
    };
    rules
        .search(host.as_str())
        .ok()
        .flatten()
        .map(Vec::as_slice)
}

fn apply_headers(headers: &mut HeaderMap, values: &[(HeaderName, HeaderValue)]) {
    for (name, value) in values {
        headers.remove(name);
        headers.insert(name.clone(), value.clone());
    }
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let connection_names = headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|connection| {
            connection
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for name in connection_names {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from(message.into()))
        .map_err(|never| -> hyper::Error { match never {} })
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static HTTP termination error response headers are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::proxy::{DirectAsyncProxy, FixedAsyncProxy};
    use yuhaiin_core::{DomainName, Network};

    fn rules(value: serde_json::Value) -> HeaderRules {
        parse_header_rules(&GoProxyLayer {
            kind: "http_termination".to_owned(),
            config: value,
        })
        .unwrap()
    }

    #[test]
    fn domain_rules_prefer_the_most_specific_wildcard() {
        let rules = rules(serde_json::json!({
            "headers": {
                "example.com": {"headers": [{"key": "x-route", "value": "parent"}]},
                "*.api.example.com": {"headers": [{"key": "x-route", "value": "api"}]}
            }
        }));
        let endpoint = Endpoint::domain(
            Network::Tcp,
            DomainName::new("edge.api.example.com").unwrap(),
            80,
        );
        let values = lookup_headers(&rules, &endpoint).unwrap();
        assert_eq!(values[0].0, HeaderName::from_static("x-route"));
        assert_eq!(values[0].1, HeaderValue::from_static("api"));
    }

    #[test]
    fn request_target_uses_tls_termination_default_port() {
        let request = Request::builder()
            .uri("/hello")
            .header(header::HOST, "example.com")
            .body(())
            .unwrap();
        let (destination, authority, uri, https) = request_target(&request, true).unwrap();
        assert_eq!(authority, "example.com");
        assert_eq!(destination.port(), Some(443));
        assert_eq!(uri, "/hello".parse::<Uri>().unwrap());
        assert!(!https);
    }

    #[test]
    fn request_target_uses_https_scheme_for_plain_http_termination() {
        let request = Request::builder()
            .uri("https://example.com/hello")
            .body(())
            .unwrap();
        let (destination, authority, uri, https) = request_target(&request, false).unwrap();
        assert_eq!(authority, "example.com");
        assert_eq!(destination.port(), Some(443));
        assert_eq!(uri, "/hello".parse::<Uri>().unwrap());
        assert!(https);
    }

    async fn proxy_response(request: &str) -> Vec<u8> {
        let parent: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        });
        let proxy = HttpTerminationProxy::new(parent, rules(serde_json::json!({})), false);
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 443)),
        ));
        let mut client = proxy.connect(&context).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        proxy.close().await.unwrap();
        response
    }

    #[tokio::test]
    async fn rejects_connect_missing_host_and_unsupported_scheme_requests() {
        let response = proxy_response(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 501 Not Implemented\r\n"));

        let response = proxy_response("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").await;
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(String::from_utf8_lossy(&response).contains("no Host header"));

        let response = proxy_response(
            "GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(String::from_utf8_lossy(&response).contains("does not support URI scheme"));
    }

    #[tokio::test]
    async fn returns_bad_gateway_when_https_target_handshake_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        });
        let proxy = HttpTerminationProxy::new(parent, rules(serde_json::json!({})), false);
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 443)),
        ));
        let mut client = proxy.connect(&context).await.unwrap();
        client
            .write_all(
                format!(
                    "GET https://127.0.0.1:{}/secure HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    address.port(),
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(String::from_utf8_lossy(&response).contains("HTTPS handshake"));
        proxy.close().await.unwrap();
        target.await.unwrap();
    }

    #[tokio::test]
    async fn forwards_streaming_http_through_parent_and_injects_domain_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /hello?x=1 HTTP/1.1\r\n"));
            let request_lower = request.to_ascii_lowercase();
            assert!(request_lower.contains("host: edge.api.example.com:80\r\n"));
            assert!(request_lower.contains("x-route: api\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: Duration::from_secs(1),
        });
        let proxy = HttpTerminationProxy::new(
            parent,
            rules(serde_json::json!({
                "headers": {
                    "*.api.example.com": {"headers": [{"key": "x-route", "value": "api"}]}
                }
            })),
            false,
        );
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 443)),
        ));
        let mut client = proxy.connect(&context).await.unwrap();
        client
            .write_all(b"GET /hello?x=1 HTTP/1.1\r\nHost: edge.api.example.com:80\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"hello"));
        proxy.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forwards_domain_http_through_direct_parent_without_pre_resolved_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /domain HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&format!("host: localhost:{}\r\n", address.port()))
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndomain",
                )
                .await
                .unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        });
        let proxy = HttpTerminationProxy::new(parent, rules(serde_json::json!({})), false);
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 443)),
        ));
        let mut client = proxy.connect(&context).await.unwrap();
        client
            .write_all(
                format!(
                    "GET /domain HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"domain"));
        proxy.close().await.unwrap();
        server.await.unwrap();
    }
}
