//! SOCKS4/SOCKS4A inbound protocol.
//!
//! Go exposes SOCKS4A as a standalone inbound and also as one branch of the
//! mixed listener. The protocol has no UDP mode and no outbound node in the Go
//! contract, so this module owns the server framing and feeds successful
//! CONNECT requests into the shared runtime selector.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::AsyncProxySelector;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{io_error, relay_counted_with_buffer};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

const VERSION: u8 = 4;
const CONNECT: u8 = 1;
const REQUEST_LEN: usize = 8;
const MAX_FIELD_LEN: usize = 4096;

/// Serve one SOCKS4/SOCKS4A connection.
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
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, [0; 4], 0).await;
            return Err(error);
        }
    };

    if !spec.username.is_empty() && !constant_time_eq(spec.username.as_bytes(), &request.user_id) {
        write_reply(&mut stream, 91, request.address, request.port).await?;
        return Err(Error::new(ErrorKind::Protocol, "SOCKS4A username mismatch"));
    }

    let destination = request.destination()?;
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let process = context.process.clone();

    let proxy = selector.select(&context);
    let outbound = match proxy.connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, request.address, request.port).await;
            monitor.record_failure_with_process(
                "socks4a",
                &destination.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
            return Err(error);
        }
    };

    // Preserve the original port/address bytes, including the 0.0.0.x marker
    // used by SOCKS4A domain requests, just like the Go server.
    write_reply(&mut stream, 90, request.address, request.port).await?;
    relay_counted_with_buffer(
        stream,
        outbound,
        TunFlowKey {
            network: Network::Tcp,
            source: peer,
            destination: destination
                .addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback address")),
        },
        context,
        monitor,
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    port: u16,
    address: [u8; 4],
    user_id: Vec<u8>,
    host: Option<String>,
}

impl Request {
    fn destination(&self) -> Result<Endpoint> {
        if let Some(host) = &self.host {
            return Ok(Endpoint::domain(
                Network::Tcp,
                DomainName::new(host)?,
                self.port,
            ));
        }
        Ok(Endpoint::ip(
            Network::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(self.address)), self.port),
        ))
    }
}

async fn read_request<S>(stream: &mut S) -> Result<Request>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; REQUEST_LEN];
    stream.read_exact(&mut header).await.map_err(io_error)?;
    if header[0] != VERSION {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("SOCKS4A version is not 4: {}", header[0]),
        ));
    }
    if header[1] != CONNECT {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("SOCKS4A command is not CONNECT: {}", header[1]),
        ));
    }

    let user_id = read_cstring(stream, "SOCKS4A user id").await?;
    let host =
        if header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0 {
            let bytes = read_cstring(stream, "SOCKS4A domain").await?;
            Some(String::from_utf8(bytes).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("SOCKS4A domain: {error}"))
            })?)
        } else {
            None
        };
    Ok(Request {
        port: u16::from_be_bytes([header[2], header[3]]),
        address: [header[4], header[5], header[6], header[7]],
        user_id,
        host,
    })
}

async fn read_cstring<S>(stream: &mut S, field: &str) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut value = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.map_err(io_error)?;
        if byte[0] == 0 {
            return Ok(value);
        }
        if value.len() == MAX_FIELD_LEN {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("{field} exceeds {MAX_FIELD_LEN} bytes"),
            ));
        }
        value.push(byte[0]);
    }
}

async fn write_reply<S>(stream: &mut S, status: u8, address: [u8; 4], port: u16) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = [0u8; REQUEST_LEN];
    reply[1] = status;
    reply[2..4].copy_from_slice(&port.to_be_bytes());
    reply[4..].copy_from_slice(&address);
    stream.write_all(&reply).await.map_err(io_error)
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
