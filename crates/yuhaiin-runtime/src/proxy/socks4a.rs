//! SOCKS4/SOCKS4A inbound protocol.
//!
//! Go exposes SOCKS4A as a standalone inbound and also as one branch of the
//! mixed listener. The protocol has no UDP mode and no outbound node in the Go
//! contract. Wire framing lives in `yuhaiin-protocol`; this module feeds
//! successful CONNECT requests into the shared runtime selector.

use std::net::SocketAddr;
use std::sync::Arc;

use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_protocol::socks4a_server::{read_request, write_reply};

use super::super::inbound::InboundHandler;
use super::common::io_error;

/// Serve one SOCKS4/SOCKS4A connection.
pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, [0; 4], 0).await;
            return Err(error);
        }
    };

    let spec = inbound.spec();
    if !spec.username.is_empty() && !constant_time_eq(spec.username.as_bytes(), &request.user_id) {
        write_reply(&mut stream, 91, request.address, request.port).await?;
        return Err(Error::new(ErrorKind::Protocol, "SOCKS4A username mismatch"));
    }

    let destination = request.destination()?;
    let connection = match inbound.open_stream("socks4a", peer, destination).await {
        Ok(connection) => connection,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, request.address, request.port).await;
            return Err(error);
        }
    };

    // Preserve the original port/address bytes, including the 0.0.0.x marker
    // used by SOCKS4A domain requests, just like the Go server.
    write_reply(&mut stream, 90, request.address, request.port).await?;
    inbound
        .relay(stream, connection, peer)
        .await
        .map_err(io_error)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or(0))
            ^ usize::from(right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};
    use yuhaiin_protocol::socks4a_server::MAX_FIELD_LEN;

    #[test]
    fn parses_ipv4_and_socks4a_domain_requests() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut client, mut server) = duplex(1024);
            client
                .write_all(&[4, 1, 0, 53, 192, 0, 2, 10, b'u', 0])
                .await
                .unwrap();
            let request = read_request(&mut server).await.unwrap();
            assert_eq!(
                request.destination().unwrap().to_string(),
                "tcp://192.0.2.10:53"
            );

            let (mut client, mut server) = duplex(1024);
            client
                .write_all(&[
                    4, 1, 1, 187, 0, 0, 0, 1, b'u', 0, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                    b'.', b'c', b'o', b'm', 0,
                ])
                .await
                .unwrap();
            let request = read_request(&mut server).await.unwrap();
            assert_eq!(
                request.destination().unwrap().to_string(),
                "tcp://example.com:443"
            );
        });
    }

    #[test]
    fn rejects_non_connect_and_bounds_cstrings() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut client, mut server) = duplex(8192);
            client.write_all(&[4, 2, 0, 80, 1, 2, 3, 4]).await.unwrap();
            assert_eq!(
                read_request(&mut server).await.unwrap_err().kind,
                ErrorKind::Unsupported
            );

            let (mut client, mut server) = duplex(8192);
            client.write_all(&[4, 1, 0, 80, 1, 2, 3, 4]).await.unwrap();
            client
                .write_all(&vec![b'a'; MAX_FIELD_LEN + 1])
                .await
                .unwrap();
            assert_eq!(
                read_request(&mut server).await.unwrap_err().kind,
                ErrorKind::Protocol
            );
        });
    }

    #[test]
    fn username_compare_is_exact() {
        assert!(constant_time_eq(b"user", b"user"));
        assert!(!constant_time_eq(b"user", b"other"));
        assert!(!constant_time_eq(b"user", b"user\0"));
    }
}
