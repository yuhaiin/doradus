//! HTTP inbound server tests.

use super::*;
use base64::Engine;
use doradus_core::{DomainName, Network};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

#[test]
fn forward_target_accepts_absolute_and_origin_form() {
    let (absolute, absolute_path, absolute_https) = parse_forward_target(
        "http://example.com:8080/a?b=1",
        "GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: ignored\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        absolute,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 8080)
    );
    assert_eq!(absolute_path, "/a?b=1");
    assert!(!absolute_https);

    let (secure, secure_path, secure_https) = parse_forward_target(
        "HTTPS://example.com/secure",
        "GET HTTPS://example.com/secure HTTP/1.1\r\nHost: ignored\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        secure,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    );
    assert_eq!(secure_path, "/secure");
    assert!(secure_https);

    let (origin, origin_path, origin_https) = parse_forward_target(
        "/health",
        "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        origin,
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 80)
    );
    assert_eq!(origin_path, "/health");
    assert!(!origin_https);
}

#[test]
fn forward_target_rejects_non_http_absolute_schemes() {
    let error = parse_forward_target(
        "ftp://example.com/file",
        "GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn forward_request_rewrites_proxy_form_and_removes_proxy_credentials() {
    let rewritten = rewrite_forward_request_with_options(
        "GET",
        "/path",
        "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic secret\r\nTE: gzip, trailers\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nX-Remove: must-not-forward\r\nContent-Length: 0\r\n\r\n",
        false,
        false,
    )
    .unwrap();
    assert!(rewritten.starts_with("GET /path HTTP/1.1\r\n"));
    assert!(rewritten.contains("Host: example.com\r\n"));
    assert!(rewritten.contains("Content-Length: 0\r\n"));
    assert!(rewritten.contains("TE: trailers\r\n"));
    for removed in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-remove",
    ] {
        assert!(
            !rewritten.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case(removed))
            }),
            "hop-by-hop header {removed:?} leaked: {rewritten:?}"
        );
    }
}

#[test]
fn forward_request_removes_connection_tokens_case_insensitively() {
    let rewritten = rewrite_forward_request_with_options(
        "GET",
        "/",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nconnection: X-One, x-two\r\nX-One: 1\r\nX-Two: 2\r\nX-Keep: 3\r\n\r\n",
        false,
        false,
    )
    .unwrap();
    assert!(!rewritten.contains("X-One:"));
    assert!(!rewritten.contains("X-Two:"));
    assert!(rewritten.contains("X-Keep: 3\r\n"));
}

#[test]
fn forward_request_drops_non_trailer_te_values() {
    let rewritten = rewrite_forward_request_with_options(
        "GET",
        "/",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTE: gzip\r\n\r\n",
        false,
        false,
    )
    .unwrap();
    assert!(!rewritten.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("te"))
    }));
}

#[test]
fn expect_continue_is_detected_and_not_forwarded_upstream() {
    let headers = "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n";
    assert!(request_expects_continue(headers));
    let rewritten =
        rewrite_forward_request_with_options("POST", "/upload", headers, false, true).unwrap();
    assert!(!rewritten.contains("Expect:"));
    assert!(rewritten.contains("Content-Length: 4\r\n"));
}

#[test]
fn response_status_and_body_framing_follow_http_rules() {
    assert_eq!(
        response_status("HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"),
        Ok(103)
    );
    assert_eq!(
        body_framing("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"),
        Ok(BodyFraming::ContentLength(4))
    );
    assert_eq!(
        body_framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Ok(BodyFraming::Chunked)
    );
    assert_eq!(
        response_body_framing(
            "GET",
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        ),
        Ok(BodyFraming::None)
    );
    assert_eq!(
        response_body_framing("GET", "HTTP/1.1 200 OK\r\n\r\n"),
        Ok(BodyFraming::CloseDelimited)
    );
}

#[test]
fn response_rewrite_preserves_chunking_and_removes_hop_headers() {
    let rewritten = rewrite_forward_response(
        "HTTP/1.1 200 OK\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\nX-Remove: yes\r\nX-Keep: yes\r\n\r\n",
        BodyFraming::Chunked,
    )
    .unwrap();
    assert!(rewritten.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(rewritten.contains("Transfer-Encoding: chunked\r\n"));
    assert!(rewritten.contains("X-Keep: yes\r\n"));
    assert!(!rewritten.contains("Connection:"));
    assert!(!rewritten.contains("Keep-Alive:"));
    assert!(!rewritten.contains("X-Remove:"));
}

#[tokio::test]
async fn chunked_body_relay_copies_extensions_and_trailers() {
    let (mut source_writer, mut source_reader) = duplex(1024);
    let (mut destination_writer, mut destination_reader) = duplex(1024);
    source_writer
        .write_all(b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n")
        .await
        .unwrap();
    drop(source_writer);
    let copied = relay_http_body(
        &mut source_reader,
        &mut destination_writer,
        BodyFraming::Chunked,
    )
    .await
    .unwrap();
    assert_eq!(
        copied,
        b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n".len()
    );
    drop(destination_writer);
    let mut output = Vec::new();
    destination_reader.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n");
}

#[test]
fn basic_auth_is_case_insensitive_and_distinguishes_missing() {
    let token = base64::engine::general_purpose::STANDARD.encode("u:p");
    let headers = format!("GET / HTTP/1.1\r\nproxy-authorization: Basic {token}\r\n\r\n");
    assert_eq!(
        authorize_basic(&headers, "u", "p", None),
        HttpAuthorization::Allowed
    );
    assert_eq!(
        authorize_basic(&headers, "u", "wrong", None),
        HttpAuthorization::Invalid
    );
    assert_eq!(
        authorize_basic("GET / HTTP/1.1\r\n\r\n", "u", "p", None),
        HttpAuthorization::Missing
    );
}

#[tokio::test]
async fn connect_writes_success_before_shared_stream_handoff() {
    let (mut client, server) = duplex(4096);
    let received = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(TestHandler {
        received: Arc::clone(&received),
    });
    let task = tokio::spawn(async move {
        handle(
            server,
            "127.0.0.1:12345".parse().unwrap(),
            "",
            "",
            None,
            handler.as_ref(),
        )
        .await
    });
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\npayload")
        .await
        .unwrap();
    let mut response = vec![0; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(&*received.lock().unwrap(), b"payload");
}

struct TestHandler {
    received: Arc<Mutex<Vec<u8>>>,
}

impl InboundStreamHandler<DuplexStream> for TestHandler {
    fn handle_stream<'a>(
        &'a self,
        mut stream: DuplexStream,
        _peer: SocketAddr,
        _destination: Endpoint,
        _protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>> {
        let received = Arc::clone(&self.received);
        Box::pin(async move {
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.map_err(io_error)?;
            *received.lock().unwrap() = payload;
            Ok(())
        })
    }
}

impl HttpForwardHandler<DuplexStream> for TestHandler {
    type Outbound = DuplexStream;

    fn open_forward<'a>(
        &'a self,
        _peer: SocketAddr,
        _destination: Endpoint,
        _http_host: Option<String>,
        _https: bool,
    ) -> BoxFuture<'a, Result<Self::Outbound>> {
        Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "not a forward test")) })
    }

    fn record_bytes(
        &self,
        _connection: &Self::Outbound,
        _direction: HttpTrafficDirection,
        _bytes: usize,
    ) {
    }
}
