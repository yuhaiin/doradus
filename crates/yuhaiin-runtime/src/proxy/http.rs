use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::AsyncProxySelector;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{io_error, relay_counted_with_buffer, relay_counted_with_prefix_and_buffer};
use crate::inbound::{InboundAuth, InboundSpec};
use crate::{ConnectionMonitor, RuntimeProxySelector};

const MAX_HEADERS: usize = 64 * 1024;

pub(crate) async fn serve<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let headers = read_headers(&mut stream).await?;
    let mut lines = headers.split("\r\n");
    let request = lines
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP proxy request is empty"))?;
    let mut fields = request.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
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
        let source = Endpoint::ip(Network::Tcp, peer);
        let mut context = FlowContext::new(destination.clone());
        context.source = Some(source);
        context.original_domain = destination.host().cloned();
        // The HTTP proxy consumes the CONNECT request before the shared relay
        // can sniff it, so preserve the application protocol explicitly.
        context.protocol = Some("http".to_owned());
        spec.annotate_context(&mut context);
        selector.route_context(&mut context);
        let proxy = selector.select(&context);
        let outbound = match proxy.connect(&context).await {
            Ok(outbound) => outbound,
            Err(error) => {
                monitor.record_failure("http", &destination.to_string(), &error.to_string());
                return Err(error);
            }
        };
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(io_error)?;
        return relay_counted_with_buffer(
            stream,
            outbound,
            TunFlowKey {
                network: Network::Tcp,
                source: peer,
                destination: destination
                    .addr()
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            },
            context,
            monitor,
            selector.relay_buffer_size(),
        )
        .await
        .map_err(io_error);
    }
    let (destination, origin_target) = parse_forward_target(target, &headers)?;
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    context.protocol = Some("http".to_owned());
    context.http_host = yuhaiin_core::sniff::http_host(headers.as_bytes());
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let outbound = match selector.select(&context).connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            monitor.record_failure("http", &destination.to_string(), &error.to_string());
            return Err(error);
        }
    };
    let request = rewrite_forward_request(method, &origin_target, &headers)?;
    relay_counted_with_prefix_and_buffer(
        stream,
        outbound,
        TunFlowKey {
            network: Network::Tcp,
            source: peer,
            destination: destination
                .addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        },
        context,
        monitor,
        request.as_bytes(),
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

async fn read_headers<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    while bytes.len() < MAX_HEADERS {
        stream.read_exact(&mut one).await.map_err(io_error)?;
        bytes.push(one[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("HTTP headers: {error}"))
            });
        }
    }
    Err(Error::new(ErrorKind::Protocol, "HTTP headers exceed limit"))
}

pub(crate) fn parse_authority(value: &str, network: Network) -> Result<Endpoint> {
    parse_authority_with_default(value, network, None)
}

pub(crate) fn parse_authority_with_default(
    value: &str,
    network: Network,
    default_port: Option<u16>,
) -> Result<Endpoint> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid bracketed authority"))?;
        let port = match rest {
            "" => default_port
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "authority has no port"))?,
            rest => rest
                .strip_prefix(':')
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid bracketed authority"))?
                .parse::<u16>()
                .map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("authority port: {error}"))
                })?,
        };
        (host, port)
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                port.parse::<u16>().map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("authority port: {error}"))
                })?,
            ),
            _ => (
                value,
                default_port
                    .ok_or_else(|| Error::new(ErrorKind::Protocol, "authority has no port"))?,
            ),
        }
    };
    if host.is_empty() {
        return Err(Error::new(ErrorKind::Protocol, "authority host is empty"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(Endpoint::ip(network, SocketAddr::new(ip, port)))
    } else {
        Ok(Endpoint::domain(network, DomainName::new(host)?, port))
    }
}

fn parse_forward_target(target: &str, headers: &str) -> Result<(Endpoint, String)> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        return Ok((
            parse_authority_with_default(authority, Network::Tcp, Some(80))?,
            if path.is_empty() {
                "/".to_owned()
            } else {
                format!("/{path}")
            },
        ));
    }
    if target.starts_with("https://") {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "HTTPS proxy requests must use CONNECT",
        ));
    }
    let host = header_value(headers, "host")
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP request has no Host header"))?;
    let destination = parse_authority_with_default(host, Network::Tcp, Some(80))?;
    let path = if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    };
    Ok((destination, path))
}

fn rewrite_forward_request(method: &str, target: &str, headers: &str) -> Result<String> {
    let version = headers
        .split_once("\r\n")
        .and_then(|(line, _)| line.split_whitespace().nth(2))
        .unwrap_or("HTTP/1.1");
    let mut request = format!("{method} {target} {version}\r\n");
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(Error::new(ErrorKind::Protocol, "malformed HTTP header"));
        };
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        request.push_str(line);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

fn header_value<'a>(headers: &'a str, wanted: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then_some(value.trim())
    })
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
        let Some((name, value)) = line.split_once(':') else {
            return None;
        };
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
mod tests {
    use super::*;

    #[test]
    fn forward_target_accepts_absolute_and_origin_form() {
        let (absolute, absolute_path) = parse_forward_target(
            "http://example.com:8080/a?b=1",
            "GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: ignored\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            absolute,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 8080)
        );
        assert_eq!(absolute_path, "/a?b=1");

        let (origin, origin_path) = parse_forward_target(
            "/health",
            "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            origin,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 80)
        );
        assert_eq!(origin_path, "/health");
    }

    #[test]
    fn forward_request_rewrites_proxy_form_and_removes_proxy_credentials() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/path",
            "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic secret\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(rewritten.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: example.com\r\n"));
        assert!(rewritten.contains("Content-Length: 0\r\n"));
        assert!(
            !rewritten
                .to_ascii_lowercase()
                .contains("proxy-authorization")
        );
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
