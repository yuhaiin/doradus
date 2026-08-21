//! SOCKS4/SOCKS4A server-side wire protocol.
//!
//! Runtime code supplies authentication policy and outbound routing. This
//! module only parses CONNECT requests and writes the corresponding reply.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_types::InboundStreamHandler;

const VERSION: u8 = 4;
const CONNECT: u8 = 1;
const REQUEST_LEN: usize = 8;
pub const MAX_FIELD_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks4Request {
    pub port: u16,
    pub address: [u8; 4],
    pub user_id: Vec<u8>,
    pub host: Option<String>,
}

impl Socks4Request {
    pub fn destination(&self) -> Result<Endpoint> {
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

pub async fn read_request<S>(stream: &mut S) -> Result<Socks4Request>
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

    Ok(Socks4Request {
        port: u16::from_be_bytes([header[2], header[3]]),
        address: [header[4], header[5], header[6], header[7]],
        user_id,
        host,
    })
}

pub async fn write_reply<S>(stream: &mut S, status: u8, address: [u8; 4], port: u16) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = [0u8; REQUEST_LEN];
    reply[1] = status;
    reply[2..4].copy_from_slice(&port.to_be_bytes());
    reply[4..].copy_from_slice(&address);
    stream.write_all(&reply).await.map_err(io_error)
}

/// Serve one SOCKS4/SOCKS4A stream.
///
/// The server owns the handshake, credential check and SOCKS reply.  Once
/// the request is accepted, the application handler owns routing and relay.
/// This mirrors Go's `socks4a.Server` -> `netapi.Handler` boundary without
/// making this crate depend on the runtime's handler implementation.
pub async fn handle<S, H>(
    mut stream: S,
    peer: SocketAddr,
    username: &[u8],
    handler: &H,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: InboundStreamHandler<S> + ?Sized,
{
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, [0; 4], 0).await;
            return Err(error);
        }
    };

    if !username.is_empty() && !constant_time_eq(username, &request.user_id) {
        let _ = write_reply(&mut stream, 91, request.address, request.port).await;
        return Err(Error::new(ErrorKind::Protocol, "SOCKS4A username mismatch"));
    }

    let destination = match request.destination() {
        Ok(destination) => destination,
        Err(error) => {
            let _ = write_reply(&mut stream, 91, request.address, request.port).await;
            return Err(error);
        }
    };

    // Go acknowledges the SOCKS request before handing the stream to the
    // shared netapi handler. The handler is then responsible for dialing and
    // relaying the accepted stream.
    write_reply(&mut stream, 90, request.address, request.port).await?;
    handler
        .handle_stream(stream, peer, destination, "socks4a")
        .await
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

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
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

    #[tokio::test]
    async fn parses_ipv4_and_socks4a_domain_requests() {
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
                4, 1, 1, 187, 0, 0, 0, 1, b'u', 0, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                b'c', b'o', b'm', 0,
            ])
            .await
            .unwrap();
        let request = read_request(&mut server).await.unwrap();
        assert_eq!(
            request.destination().unwrap().to_string(),
            "tcp://example.com:443"
        );
    }

    #[tokio::test]
    async fn rejects_non_connect_and_bounds_cstrings() {
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
    }

    #[test]
    fn username_compare_is_exact() {
        assert!(constant_time_eq(b"user", b"user"));
        assert!(!constant_time_eq(b"user", b"other"));
        assert!(!constant_time_eq(b"user", b"user\0"));
    }
}
