//! Trojan stream and UDP-over-stream framing.
//!
//! The implementation follows the wire format used by yuhaiin-go:
//! `hex(sha224(password)) + CRLF + command + SOCKS address + CRLF` for the
//! initial request, followed by `SOCKS address + u16 length + CRLF + payload`
//! for UDP associate frames.  The codec is deliberately independent of TLS;
//! TLS is another composable transport layer in the runtime.

use std::sync::Arc;

use crate::yuubinsya::{decode_endpoint, encode_endpoint};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::Mutex;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

pub const MAX_PACKET_SIZE: usize = 8 * 1024;
pub const PASSWORD_HASH_LENGTH: usize = 56;
pub const CRLF: [u8; 2] = *b"\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 1,
    Associate = 3,
    Mux = 0x7f,
}

impl Command {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Connect),
            3 => Ok(Self::Associate),
            0x7f => Ok(Self::Mux),
            _ => Err(Error::new(ErrorKind::Protocol, "unknown Trojan command")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub destination: Endpoint,
}

pub fn password_hash(password: &[u8]) -> [u8; PASSWORD_HASH_LENGTH] {
    let digest = Sha224::digest(password);
    let mut result = [0u8; PASSWORD_HASH_LENGTH];
    for (index, byte) in digest.iter().enumerate() {
        let hex = format!("{byte:02x}");
        result[index * 2..index * 2 + 2].copy_from_slice(hex.as_bytes());
    }
    result
}

pub fn encode_request(
    hash: &[u8; PASSWORD_HASH_LENGTH],
    command: Command,
    destination: &Endpoint,
) -> Result<Vec<u8>> {
    if destination.network() != Network::Tcp && command == Command::Connect {
        return Err(Error::invalid("Trojan CONNECT destination must be TCP"));
    }
    let mut output = Vec::with_capacity(PASSWORD_HASH_LENGTH + 2 + 1 + 260 + 2);
    output.extend_from_slice(hash);
    output.extend_from_slice(&CRLF);
    output.push(command as u8);
    encode_endpoint(destination, &mut output)?;
    output.extend_from_slice(&CRLF);
    Ok(output)
}

pub fn encode_udp_frame(destination: &Endpoint, payload: &[u8]) -> Result<Vec<u8>> {
    if destination.network() != Network::Udp {
        return Err(Error::invalid("Trojan UDP frame destination must be UDP"));
    }
    if payload.len() > MAX_PACKET_SIZE || payload.len() > usize::from(u16::MAX) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Trojan UDP payload is too large",
        ));
    }
    let mut output = Vec::with_capacity(260 + 4 + payload.len());
    encode_endpoint(destination, &mut output)?;
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(&CRLF);
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_udp_frame(packet: &[u8], payload: &mut [u8]) -> Result<(usize, Endpoint, usize)> {
    let mut cursor = 0;
    let destination = decode_endpoint(packet, &mut cursor, Network::Udp)?;
    let length = usize::from(u16::from_be_bytes(
        take(packet, &mut cursor, 2)?.try_into().unwrap(),
    ));
    if take(packet, &mut cursor, 2)? != CRLF {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Trojan UDP frame lacks CRLF",
        ));
    }
    let copied = length.min(payload.len());
    payload[..copied].copy_from_slice(take(packet, &mut cursor, copied)?);
    if length > copied {
        let _ = take(packet, &mut cursor, length - copied)?;
    }
    Ok((copied, destination, cursor))
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    hash: &[u8; PASSWORD_HASH_LENGTH],
    command: Command,
    destination: &Endpoint,
) -> Result<()> {
    writer
        .write_all(&encode_request(hash, command, destination)?)
        .await
        .map_err(io_error)
}

pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_hash: &[u8; PASSWORD_HASH_LENGTH],
) -> Result<Request> {
    read_request_any(reader, std::slice::from_ref(expected_hash)).await
}

/// Read a Trojan request while accepting a bounded set of central-user
/// password hashes. The wire format carries the hash before the command, so
/// the selected credential does not need to be retained after this request.
pub async fn read_request_any<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_hashes: &[[u8; PASSWORD_HASH_LENGTH]],
) -> Result<Request> {
    let mut hash = [0u8; PASSWORD_HASH_LENGTH];
    reader.read_exact(&mut hash).await.map_err(io_error)?;
    let mut matched = 0u8;
    for expected_hash in expected_hashes {
        matched |= u8::from(constant_time_eq(&hash, expected_hash));
    }
    if matched == 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Trojan password is incorrect",
        ));
    }
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.map_err(io_error)?;
    if crlf != CRLF {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Trojan password header lacks CRLF",
        ));
    }
    let command = Command::from_byte(reader.read_u8().await.map_err(io_error)?)?;
    let endpoint_bytes = read_endpoint_bytes(reader).await?;
    let mut cursor = 0;
    let destination = decode_endpoint(
        &endpoint_bytes,
        &mut cursor,
        match command {
            Command::Associate => Network::Udp,
            _ => Network::Tcp,
        },
    )?;
    reader.read_exact(&mut crlf).await.map_err(io_error)?;
    if crlf != CRLF {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Trojan request lacks trailing CRLF",
        ));
    }
    Ok(Request {
        command,
        destination,
    })
}

pub async fn read_udp_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload: &mut [u8],
) -> Result<(usize, Endpoint)> {
    let endpoint_bytes = read_endpoint_bytes(reader).await?;
    let mut cursor = 0;
    let destination = decode_endpoint(&endpoint_bytes, &mut cursor, Network::Udp)?;
    let length = usize::from(reader.read_u16().await.map_err(io_error)?);
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.map_err(io_error)?;
    if crlf != CRLF {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Trojan UDP frame lacks CRLF",
        ));
    }
    let copied = length.min(payload.len());
    reader
        .read_exact(&mut payload[..copied])
        .await
        .map_err(io_error)?;
    if length > copied {
        let mut remaining = vec![0u8; 1024];
        let mut left = length - copied;
        while left != 0 {
            let take = left.min(remaining.len());
            reader
                .read_exact(&mut remaining[..take])
                .await
                .map_err(io_error)?;
            left -= take;
        }
    }
    Ok((copied, destination))
}

pub async fn write_udp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    destination: &Endpoint,
    payload: &[u8],
) -> Result<()> {
    writer
        .write_all(&encode_udp_frame(destination, payload)?)
        .await
        .map_err(io_error)
}

/// Wrap an already-connected parent proxy with Trojan framing.
pub struct TrojanProxy {
    upstream: Arc<dyn AsyncProxy>,
    hash: [u8; PASSWORD_HASH_LENGTH],
}

impl TrojanProxy {
    pub fn new(upstream: Arc<dyn AsyncProxy>, password: impl AsRef<[u8]>) -> Self {
        Self {
            upstream,
            hash: password_hash(password.as_ref()),
        }
    }

    pub fn from_hash(upstream: Arc<dyn AsyncProxy>, hash: [u8; PASSWORD_HASH_LENGTH]) -> Self {
        Self { upstream, hash }
    }

    pub fn password_hash(&self) -> &[u8; PASSWORD_HASH_LENGTH] {
        &self.hash
    }
}

impl AsyncProxy for TrojanProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut stream = self.upstream.connect(context).await?;
            write_request(
                &mut stream,
                &self.hash,
                Command::Connect,
                &context.effective_destination(),
            )
            .await?;
            Ok(stream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let mut stream = self.upstream.connect(context).await?;
            write_request(
                &mut stream,
                &self.hash,
                Command::Associate,
                &context.effective_destination(),
            )
            .await?;
            let (reader, writer) = split(stream);
            Ok(Box::new(TrojanDatagram {
                reader: Mutex::new(reader),
                writer: Mutex::new(writer),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

struct TrojanDatagram {
    reader: Mutex<ReadHalf<BoxAsyncStream>>,
    writer: Mutex<WriteHalf<BoxAsyncStream>>,
}

impl AsyncDatagram for TrojanDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let frame = encode_udp_frame(&target, payload)?;
            self.writer
                .lock()
                .await
                .write_all(&frame)
                .await
                .map_err(io_error)?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move { read_udp_frame(&mut *self.reader.lock().await, buffer).await })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(Network::Udp, "0.0.0.0:0".parse().unwrap()))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.writer.lock().await.shutdown().await.map_err(io_error) })
    }
}

async fn read_endpoint_bytes<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut bytes = vec![reader.read_u8().await.map_err(io_error)?];
    let remaining = match bytes[0] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let length = reader.read_u8().await.map_err(io_error)?;
            bytes.push(length);
            usize::from(length) + 2
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown Trojan address type",
            ));
        }
    };
    let old_len = bytes.len();
    bytes.resize(old_len + remaining, 0);
    reader
        .read_exact(&mut bytes[old_len..])
        .await
        .map_err(io_error)?;
    Ok(bytes)
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "Trojan length overflow"))?;
    if end > packet.len() {
        return Err(Error::new(ErrorKind::Protocol, "Trojan frame is truncated"));
    }
    let result = &packet[*cursor..end];
    *cursor = end;
    Ok(result)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use yuhaiin_core::{DomainName, Endpoint, Network};

    fn tcp_domain() -> Endpoint {
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    }

    #[test]
    fn password_hash_matches_trojan_lowercase_sha224_contract() {
        assert_eq!(
            std::str::from_utf8(&password_hash(b"password")).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn request_and_udp_frames_preserve_domains_and_payloads() {
        let hash = password_hash(b"secret");
        let request = encode_request(&hash, Command::Connect, &tcp_domain()).unwrap();
        assert_eq!(&request[..PASSWORD_HASH_LENGTH], &hash);
        let udp = encode_udp_frame(
            &Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap()),
            b"dns",
        )
        .unwrap();
        let mut payload = [0u8; 16];
        let (length, destination, consumed) = decode_udp_frame(&udp, &mut payload).unwrap();
        assert_eq!(length, 3);
        assert_eq!(&payload[..length], b"dns");
        assert_eq!(
            destination,
            Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap())
        );
        assert_eq!(consumed, udp.len());
    }

    #[tokio::test]
    async fn async_request_reader_rejects_bad_password_and_accepts_valid_request() {
        let hash = password_hash(b"secret");
        let request = encode_request(&hash, Command::Connect, &tcp_domain()).unwrap();
        let parsed = read_request(&mut Cursor::new(request), &hash)
            .await
            .unwrap();
        assert_eq!(parsed.destination, tcp_domain());
        let error = read_request(
            &mut Cursor::new(
                encode_request(&password_hash(b"wrong"), Command::Connect, &tcp_domain()).unwrap(),
            ),
            &hash,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Protocol);
    }

    #[tokio::test]
    async fn async_request_reader_accepts_a_central_password_from_multiple_hashes() {
        let request = encode_request(
            &password_hash(b"central-password"),
            Command::Connect,
            &tcp_domain(),
        )
        .unwrap();
        let hashes = [
            password_hash(b"old-password"),
            password_hash(b"central-password"),
        ];
        let parsed = read_request_any(&mut Cursor::new(request), &hashes)
            .await
            .unwrap();
        assert_eq!(parsed.command, Command::Connect);
        assert_eq!(parsed.destination, tcp_domain());
    }
}
