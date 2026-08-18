//! SOCKS4/SOCKS4A server-side wire protocol.
//!
//! Runtime code supplies authentication policy and outbound routing. This
//! module only parses CONNECT requests and writes the corresponding reply.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, Network, Result};

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
