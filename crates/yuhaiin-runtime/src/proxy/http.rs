//! Runtime HTTP proxy adapter.
//!
//! HTTP/1.x framing and header rewriting live in `yuhaiin-protocol`; this
//! module applies runtime authentication, routing, TLS and flow accounting.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use tokio::io::AsyncWriteExt;

use yuhaiin_core::flow::FlowObserver;
use yuhaiin_core::flow::{Flow as TunFlow, FlowDirection as TunFlowDirection, FlowObserverGuard};
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_protocol::http_server::*;

use super::common::io_error;
use crate::inbound::{InboundAuth, InboundHandler};

pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec();
    let monitor = Arc::clone(inbound.monitor());
    loop {
        let Some(headers) = read_headers(&mut stream).await? else {
            return Ok(());
        };
        let request_line = headers
            .split_once("\r\n")
            .map(|(line, _)| line)
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP proxy request is empty"))?;
        let mut fields = request_line.split_whitespace();
        let method = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        let version = fields.next().unwrap_or("HTTP/1.1");
        if method.is_empty() || target.is_empty() {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP proxy request line is malformed",
            ));
        }
        match http_authorization(
            &headers,
            &spec.username,
            &spec.password,
            spec.auth.as_deref(),
        ) {
            HttpAuthorization::Allowed => {}
            HttpAuthorization::Missing => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .map_err(io_error)?;
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy authentication is required",
                ));
            }
            HttpAuthorization::Invalid => {
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(io_error)?;
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy authentication failed",
                ));
            }
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let destination = parse_authority(target, Network::Tcp)?;
            return serve_connect(stream, peer, Arc::clone(&inbound), destination).await;
        }

        let request_body = body_framing(&headers)?;
        let client_wants_close = request_wants_close(version, &headers);
        let (destination, origin_target, https) = parse_forward_target(target, &headers)?;
        let mut context = inbound.context(peer, Network::Tcp, destination.clone());
        context.http_host = yuhaiin_core::sniff::http_host(headers.as_bytes());
        let connection = inbound.connect("http", context).await?;
        let outbound = connection.outbound;
        let context = connection.context;
        let mut outbound = if https {
            #[cfg(feature = "doh-tls")]
            {
                let server_name = destination
                    .host()
                    .map(|host| host.as_str().to_owned())
                    .or_else(|| destination.addr().map(|addr| addr.ip().to_string()))
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "HTTPS target has no host")
                    })?;
                match crate::tls::wrap_system_tls_stream(&server_name, outbound).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP proxy HTTPS requests require the doh-tls feature",
                ));
            }
        } else {
            outbound
        };
        let flow = inbound.flow_key(&context, peer);
        let _observation = FlowObserverGuard::open(monitor.clone(), TunFlow { key: flow }, context);
        let request = rewrite_forward_request_with_options(
            method,
            &origin_target,
            &headers,
            matches!(request_body, BodyFraming::Chunked),
            request_expects_continue(&headers) && !matches!(request_body, BodyFraming::None),
        )?;
        outbound
            .write_all(request.as_bytes())
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Upload, request.len());
        if request_expects_continue(&headers) && !matches!(request_body, BodyFraming::None) {
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .map_err(io_error)?;
            monitor.bytes(flow, TunFlowDirection::Download, 25);
        }
        let uploaded = relay_http_body(&mut stream, &mut outbound, request_body)
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Upload, uploaded);

        let (response_headers, response_body) = loop {
            let Some(response_headers) = read_headers(&mut outbound).await? else {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy upstream closed before response headers",
                ));
            };
            let status = response_status(&response_headers)?;
            if status == 101 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP proxy upstream upgrade responses are unsupported",
                ));
            }
            let response_body = response_body_framing(method, &response_headers)?;
            if (100..200).contains(&status) {
                let response = rewrite_forward_response(&response_headers, BodyFraming::None)?;
                stream
                    .write_all(response.as_bytes())
                    .await
                    .map_err(io_error)?;
                monitor.bytes(flow, TunFlowDirection::Download, response.len());
                continue;
            }
            break (response_headers, response_body);
        };
        let response_close = response_wants_close(&response_headers)
            || matches!(response_body, BodyFraming::CloseDelimited);
        let response = rewrite_forward_response(&response_headers, response_body)?;
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Download, response.len());
        let downloaded = relay_http_body(&mut outbound, &mut stream, response_body)
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Download, downloaded);
        if client_wants_close || response_close {
            return Ok(());
        }
    }
}

async fn serve_connect(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
    destination: Endpoint,
) -> Result<()> {
    let connection = match inbound.open_stream("http", peer, destination).await {
        Ok(connection) => connection,
        Err(error) => {
            return Err(error);
        }
    };
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(io_error)?;
    inbound
        .relay(stream, connection, peer)
        .await
        .map_err(io_error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpAuthorization {
    Allowed,
    Missing,
    Invalid,
}

fn http_authorization(
    headers: &str,
    username: &str,
    password: &str,
    auth: Option<&InboundAuth>,
) -> HttpAuthorization {
    let central = auth.filter(|auth| auth.has_basic_users());
    if central.is_none() && username.is_empty() && password.is_empty() {
        return HttpAuthorization::Allowed;
    }
    let Some(token) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("Proxy-Authorization") {
            return None;
        }
        value.trim().strip_prefix("Basic ")
    }) else {
        return HttpAuthorization::Missing;
    };

    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
        return HttpAuthorization::Invalid;
    };
    let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
        return HttpAuthorization::Invalid;
    };
    let (actual_username, actual_password) = decoded.split_at(separator);
    let actual_password = &actual_password[1..];
    if let Some(auth) = central {
        if auth.authenticate_basic(actual_username, actual_password) {
            return HttpAuthorization::Allowed;
        }
        return HttpAuthorization::Invalid;
    }
    if decoded == format!("{username}:{password}").as_bytes() {
        HttpAuthorization::Allowed
    } else {
        HttpAuthorization::Invalid
    }
}

#[cfg(test)]
fn rewrite_forward_request(method: &str, target: &str, headers: &str) -> Result<String> {
    rewrite_forward_request_with_options(method, target, headers, false, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yuhaiin_core::DomainName;

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
        let rewritten = rewrite_forward_request(
            "GET",
            "/path",
            "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic secret\r\nTE: gzip, trailers\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nX-Remove: must-not-forward\r\nContent-Length: 0\r\n\r\n",
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
                !rewritten.lines().any(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| { name.eq_ignore_ascii_case(removed) })),
                "hop-by-hop header {removed:?} leaked: {rewritten:?}"
            );
        }
    }

    #[test]
    fn forward_request_removes_all_connection_tokens_case_insensitively() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nconnection: X-One, x-two\r\nX-One: 1\r\nX-Two: 2\r\nX-Keep: 3\r\n\r\n",
        )
        .unwrap();
        assert!(!rewritten.contains("X-One:"));
        assert!(!rewritten.contains("X-Two:"));
        assert!(rewritten.contains("X-Keep: 3\r\n"));
    }

    #[test]
    fn forward_request_drops_non_trailer_te_values() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTE: gzip\r\n\r\n",
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
    fn response_status_accepts_informational_responses() {
        assert_eq!(
            response_status("HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"),
            Ok(103)
        );
        assert_eq!(
            response_status("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Ok(200)
        );
    }

    #[test]
    fn request_and_response_framing_follow_http_one_point_one_rules() {
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
    fn response_rewrite_preserves_wire_chunking_and_removes_hop_headers() {
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
        let (mut source_writer, mut source_reader) = tokio::io::duplex(1024);
        let (mut destination_writer, mut destination_reader) = tokio::io::duplex(1024);
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
    fn header_value_preserves_host_for_connection_observability() {
        let headers = "GET / HTTP/1.1\r\n hOsT: example.com:8080 \r\n\r\n";
        assert_eq!(header_value(headers, "Host"), Some("example.com:8080"));
    }

    #[test]
    fn proxy_authorization_header_name_is_case_insensitive() {
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        let headers = format!("GET / HTTP/1.1\r\nproxy-authorization: Basic {token}\r\n\r\n");
        assert_eq!(
            http_authorization(&headers, "u", "p", None),
            HttpAuthorization::Allowed
        );
        assert_eq!(
            http_authorization(&headers, "u", "wrong", None),
            HttpAuthorization::Invalid
        );
    }

    #[test]
    fn central_inbound_users_replace_inline_http_credentials() {
        let auth = InboundAuth::from_users(vec![yuhaiin_store::GoUserRecord {
            id: "central-http".to_owned(),
            name: "central-http".to_owned(),
            enabled: true,
            origin: "manual".to_owned(),
            usage: "inbound".to_owned(),
            credential: yuhaiin_store::GoCredential {
                kind: "basic".to_owned(),
                basic: Some(yuhaiin_store::GoBasicCredential {
                    username: Some("central-user".to_owned()),
                    password: Some("central-password".to_owned()),
                    allow_any_username: false,
                    allow_any_password: false,
                }),
                uuid: None,
                token: None,
            },
            updated_at: 0,
        }]);
        let token =
            base64::engine::general_purpose::STANDARD.encode("central-user:central-password");
        let headers = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        assert_eq!(
            http_authorization(&headers, "legacy", "legacy", Some(&auth)),
            HttpAuthorization::Allowed
        );
        let wrong_token =
            base64::engine::general_purpose::STANDARD.encode("central-user:wrong-password");
        let wrong = headers.replace(&token, &wrong_token);
        assert_eq!(
            http_authorization(&wrong, "legacy", "legacy", Some(&auth)),
            HttpAuthorization::Invalid
        );
    }

    #[test]
    fn proxy_authorization_distinguishes_missing_from_invalid() {
        assert_eq!(
            http_authorization("GET / HTTP/1.1\r\n\r\n", "u", "p", None),
            HttpAuthorization::Missing
        );
    }
}
