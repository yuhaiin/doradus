//! Small, bounded stream protocol sniffers shared by inbound adapters.
//!
//! Go's inbound path peeks at the first bytes of every stream before handing
//! it to the common handler.  This module deliberately only inspects bytes
//! already supplied by the caller: it owns no socket, timeout, or buffering
//! policy, so TUN, TCP inbound, and future transports can reuse the same
//! parsers without coupling core to Tokio.

const TLS_RECORD_HEADER: usize = 5;
const MAX_TLS_RECORD: usize = 16 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamMetadata {
    pub tls_server_name: Option<String>,
    pub http_host: Option<String>,
}

/// Inspect one bounded prefix using the same precedence as Go: TLS first,
/// then HTTP.  A malformed or incomplete prefix is simply not identified.
pub fn inspect(bytes: &[u8]) -> StreamMetadata {
    let tls_server_name = tls_server_name(bytes);
    let http_host = if tls_server_name.is_none() {
        http_host(bytes)
    } else {
        None
    };
    StreamMetadata {
        tls_server_name,
        http_host,
    }
}

/// Extract the SNI from a complete TLS ClientHello record.
pub fn tls_server_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < TLS_RECORD_HEADER || bytes[0] != 0x16 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if record_len == 0 || record_len > MAX_TLS_RECORD {
        return None;
    }
    let record_end = TLS_RECORD_HEADER.checked_add(record_len)?;
    if bytes.len() < record_end {
        return None;
    }
    let hello = &bytes[TLS_RECORD_HEADER..record_end];
    if hello.len() < 4 || hello[0] != 1 {
        return None;
    }
    let hello_len = read_u24(&hello[1..4])?;
    let hello_end = 4usize.checked_add(hello_len)?;
    if hello_end > hello.len() {
        return None;
    }
    let body = &hello[4..hello_end];
    let mut cursor = 0;
    take(&mut cursor, body, 2)?; // legacy version
    take(&mut cursor, body, 32)?; // random
    let session_len = usize::from(*take(&mut cursor, body, 1)?.first()?);
    take(&mut cursor, body, session_len)?;
    let cipher_len = usize::from(u16::from_be_bytes(array2(take(&mut cursor, body, 2)?)));
    take(&mut cursor, body, cipher_len)?;
    let compression_len = usize::from(*take(&mut cursor, body, 1)?.first()?);
    take(&mut cursor, body, compression_len)?;
    let extensions_len = usize::from(u16::from_be_bytes(array2(take(&mut cursor, body, 2)?)));
    let extensions = take(&mut cursor, body, extensions_len)?;

    let mut extension_cursor = 0;
    while extension_cursor + 4 <= extensions.len() {
        let extension_type =
            u16::from_be_bytes(array2(take(&mut extension_cursor, extensions, 2)?));
        let extension_len = usize::from(u16::from_be_bytes(array2(take(
            &mut extension_cursor,
            extensions,
            2,
        )?)));
        let extension = take(&mut extension_cursor, extensions, extension_len)?;
        if extension_type != 0 {
            continue;
        }
        let mut names_cursor = 0;
        let names_len = usize::from(u16::from_be_bytes(array2(take(
            &mut names_cursor,
            extension,
            2,
        )?)));
        let names = take(&mut names_cursor, extension, names_len)?;
        let mut name_cursor = 0;
        while name_cursor + 3 <= names.len() {
            let name_type = *take(&mut name_cursor, names, 1)?.first()?;
            let name_len = usize::from(u16::from_be_bytes(array2(take(
                &mut name_cursor,
                names,
                2,
            )?)));
            let name = take(&mut name_cursor, names, name_len)?;
            if name_type == 0 && !name.is_empty() {
                return std::str::from_utf8(name).ok().map(ToOwned::to_owned);
            }
        }
    }
    None
}

/// Extract the HTTP `Host` authority from a request prefix and return only
/// the host portion, matching Go's `net.SplitHostPort` based sniffer.
pub fn http_host(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?.split_whitespace().next()?;
    if !matches!(
        request,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" | "TRACE" | "PATCH"
    ) {
        return None;
    }
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("host") {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        return Some(strip_host_port(value));
    }
    None
}

fn strip_host_port(value: &str) -> String {
    if let Some(rest) = value.strip_prefix('[')
        && let Some((host, suffix)) = rest.split_once(']')
        && (suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok())
                .is_some())
    {
        return host.to_owned();
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return host.to_owned();
    }
    value.to_owned()
}

fn read_u24(bytes: &[u8]) -> Option<usize> {
    Some(
        (usize::from(*bytes.first()?) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]),
    )
}

fn array2(bytes: &[u8]) -> [u8; 2] {
    [bytes[0], bytes[1]]
}

fn take<'a>(cursor: &mut usize, bytes: &'a [u8], length: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_sniffer_accepts_methods_and_strips_authority_port() {
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            http_host(b"CONNECT / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n"),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n"),
            Some("2001:db8::1".to_owned())
        );
        assert!(http_host(b"hello\r\nHost: example.com\r\n\r\n").is_none());
    }

    #[test]
    fn tls_sniffer_extracts_client_hello_sni_and_rejects_truncation() {
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        let name = b"example.com";
        let mut server_names = vec![0, (name.len() + 3) as u8, 0, 0, name.len() as u8];
        server_names.extend_from_slice(name);
        let mut extension = vec![0, 0, 0, server_names.len() as u8];
        extension.extend_from_slice(&server_names);
        body.extend_from_slice(&[(extension.len() >> 8) as u8, extension.len() as u8]);
        body.extend_from_slice(&extension);
        let mut handshake = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut record = vec![
            0x16,
            3,
            1,
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);
        assert_eq!(tls_server_name(&record), Some("example.com".to_owned()));
        assert!(tls_server_name(&record[..record.len() - 1]).is_none());
    }

    #[test]
    fn inspect_prefers_tls_over_http() {
        let metadata = inspect(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(metadata.http_host, Some("example.com".to_owned()));
        assert_eq!(metadata.tls_server_name, None);
    }
}
