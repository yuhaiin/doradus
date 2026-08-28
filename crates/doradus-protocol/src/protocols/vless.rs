//! VLESS request/response framing and async proxy adapters.
//!
//! doradus-go currently uses the deliberately small VLESS v0 wire format:
//! UUID-authenticated request, optional addon bytes, command, SOCKS-style
//! destination, then a two-byte response header. TCP payloads are raw after
//! the response; UDP payloads use a big-endian u16 length prefix.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result,
};
use doradus_types::{
    InboundStreamHandler, InboundUdpCodec, InboundUdpFlowId, InboundUdpRequest, InboundUdpResponse,
};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, split,
};
use tokio::sync::Mutex;

pub const VERSION: u8 = 0;
pub const MAX_ADDON_SIZE: usize = u8::MAX as usize;
pub const MAX_PACKET_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
}

impl Command {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(Error::new(ErrorKind::Protocol, "unknown VLESS command")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub uuid: [u8; 16],
    pub command: Command,
    pub destination: Endpoint,
    pub addons: Vec<u8>,
}

/// VLESS UDP-over-stream server codec.
///
/// VLESS v0 fixes the destination in the initial request.  Subsequent
/// packets are length-prefixed and do not repeat the destination.
pub struct UdpServer<R, W> {
    reader: R,
    writer: W,
    peer: std::net::SocketAddr,
    destination: Endpoint,
    packet: Vec<u8>,
}

impl<R, W> UdpServer<R, W> {
    pub fn new(
        reader: R,
        writer: W,
        peer: std::net::SocketAddr,
        destination: Endpoint,
        buffer_size: usize,
    ) -> Self {
        Self {
            reader,
            writer,
            peer,
            destination,
            packet: vec![0u8; buffer_size.max(512)],
        }
    }
}

/// Serve one VLESS inbound stream.
///
/// The protocol crate authenticates and parses the initial request, emits the
/// response header for TCP, and constructs the UDP framing codec.  Route
/// selection and UDP flow/session lifetime are supplied by the application
/// layer through the two handler ports.
pub async fn handle<S, H, U, F>(
    mut stream: S,
    peer: std::net::SocketAddr,
    uuid: &[u8; 16],
    udp_buffer_size: usize,
    handler: &H,
    udp_handler: U,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: InboundStreamHandler<S> + ?Sized,
    U: FnOnce(UdpServer<ReadHalf<S>, WriteHalf<S>>) -> F + Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let request = read_request(&mut stream, uuid).await?;
    match request.command {
        Command::Tcp => {
            write_response(&mut stream, &[]).await?;
            handler
                .handle_stream(stream, peer, request.destination, "vless")
                .await
        }
        Command::Udp => {
            let (reader, writer) = split(stream);
            udp_handler(UdpServer::new(
                reader,
                writer,
                peer,
                request.destination,
                udp_buffer_size,
            ))
            .await
        }
    }
}

impl<R, W> InboundUdpCodec for UdpServer<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let length = usize::from(self.reader.read_u16().await.map_err(io_error)?);
            if length > self.packet.len() {
                return Err(Error::invalid("VLESS UDP payload is too large"));
            }
            self.reader
                .read_exact(&mut self.packet[..length])
                .await
                .map_err(io_error)?;
            Ok(Some(InboundUdpRequest {
                id: InboundUdpFlowId {
                    peer: self.peer,
                    target: self.destination.clone(),
                    authentication: None,
                },
                peer: Endpoint::ip(Network::Udp, self.peer),
                target: self.destination.clone(),
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let length = u16::try_from(response.payload.len())
                .map_err(|_| Error::invalid("VLESS UDP response is too large"))?;
            self.writer.write_u16(length).await.map_err(io_error)?;
            self.writer
                .write_all(&response.payload)
                .await
                .map_err(io_error)
        })
    }
}

/// Parse the canonical VLESS UUID form. Hyphens are optional so both the
/// frontend's usual representation and legacy compact values can be read.
pub fn parse_uuid(value: &str) -> Result<[u8; 16]> {
    let mut compact = [0u8; 32];
    let mut length = 0;
    for byte in value.bytes() {
        if byte == b'-' {
            continue;
        }
        if length == compact.len() {
            return Err(Error::invalid("VLESS UUID has the wrong length"));
        }
        compact[length] = byte;
        length += 1;
    }
    if length != compact.len() {
        return Err(Error::invalid("VLESS UUID has the wrong length"));
    }
    let mut output = [0u8; 16];
    for (index, pair) in compact.as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(output)
}

pub fn encode_request(
    uuid: &[u8; 16],
    command: Command,
    destination: &Endpoint,
) -> Result<Vec<u8>> {
    if (command == Command::Tcp && destination.network() != Network::Tcp)
        || (command == Command::Udp && destination.network() != Network::Udp)
    {
        return Err(Error::invalid(
            "VLESS command and destination network differ",
        ));
    }
    let port = destination
        .port()
        .ok_or_else(|| Error::invalid("VLESS destination has no port"))?;
    let mut output = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 1 + 255);
    output.push(VERSION);
    output.extend_from_slice(uuid);
    output.push(0); // addon length; doradus-go sends no addon data
    output.push(command as u8);
    output.extend_from_slice(&port.to_be_bytes());
    encode_address(destination, &mut output)?;
    Ok(output)
}

pub fn decode_request(packet: &[u8], expected_uuid: &[u8; 16]) -> Result<Request> {
    let mut cursor = 0;
    if take(packet, &mut cursor, 1)?[0] != VERSION {
        return Err(Error::new(
            ErrorKind::Protocol,
            "unexpected VLESS request version",
        ));
    }
    let uuid = <[u8; 16]>::try_from(take(packet, &mut cursor, 16)?).unwrap();
    if !constant_time_eq(&uuid, expected_uuid) {
        return Err(Error::new(ErrorKind::Protocol, "VLESS UUID is incorrect"));
    }
    let addon_length = usize::from(take(packet, &mut cursor, 1)?[0]);
    let addons = take(packet, &mut cursor, addon_length)?.to_vec();
    let command = Command::from_byte(take(packet, &mut cursor, 1)?[0])?;
    let port = u16::from_be_bytes(take(packet, &mut cursor, 2)?.try_into().unwrap());
    let destination = decode_address(packet, &mut cursor, command, port)?;
    if cursor != packet.len() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "VLESS request has trailing bytes",
        ));
    }
    Ok(Request {
        uuid,
        command,
        destination,
        addons,
    })
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    uuid: &[u8; 16],
    command: Command,
    destination: &Endpoint,
) -> Result<()> {
    writer
        .write_all(&encode_request(uuid, command, destination)?)
        .await
        .map_err(io_error)
}

pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_uuid: &[u8; 16],
) -> Result<Request> {
    let mut prefix = [0u8; 22];
    reader.read_exact(&mut prefix).await.map_err(io_error)?;
    let address_type = prefix[21];
    let (address_length, domain_length) = match address_type {
        1 => (4, None),
        2 => {
            let length = usize::from(reader.read_u8().await.map_err(io_error)?);
            (length, Some(length))
        }
        3 => (16, None),
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown VLESS address type",
            ));
        }
    };
    let mut packet = prefix.to_vec();
    if let Some(length) = domain_length {
        packet.push(length as u8);
    }
    let mut address = vec![0u8; address_length];
    reader.read_exact(&mut address).await.map_err(io_error)?;
    packet.extend_from_slice(&address);
    decode_request(&packet, expected_uuid)
}

pub async fn write_response<W: AsyncWrite + Unpin>(writer: &mut W, addons: &[u8]) -> Result<()> {
    if addons.len() > MAX_ADDON_SIZE {
        return Err(Error::invalid("VLESS response addons are too large"));
    }
    writer
        .write_all(&[VERSION, addons.len() as u8])
        .await
        .map_err(io_error)?;
    writer.write_all(addons).await.map_err(io_error)
}

/// Read and validate the response header, discarding optional addon bytes.
pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let version = reader.read_u8().await.map_err(io_error)?;
    let addons = usize::from(reader.read_u8().await.map_err(io_error)?);
    if version != VERSION {
        return Err(Error::new(
            ErrorKind::Protocol,
            "unexpected VLESS response version",
        ));
    }
    if addons != 0 {
        let mut ignored = vec![0u8; addons];
        reader.read_exact(&mut ignored).await.map_err(io_error)?;
    }
    Ok(())
}

/// Wrap an already configured parent proxy with VLESS framing.
pub struct VlessProxy {
    upstream: Arc<dyn AsyncProxy>,
    uuid: [u8; 16],
}

impl VlessProxy {
    pub fn new(upstream: Arc<dyn AsyncProxy>, uuid: &str) -> Result<Self> {
        Ok(Self {
            upstream,
            uuid: parse_uuid(uuid)?,
        })
    }

    pub fn from_uuid(upstream: Arc<dyn AsyncProxy>, uuid: [u8; 16]) -> Self {
        Self { upstream, uuid }
    }

    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }
}

impl AsyncProxy for VlessProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut stream = self.upstream.connect(context).await?;
            write_request(
                &mut stream,
                &self.uuid,
                Command::Tcp,
                &context.effective_destination(),
            )
            .await?;
            Ok(Box::new(VlessStream::new(stream)) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let mut stream = self.upstream.connect(context).await?;
            let destination = context.effective_destination();
            write_request(&mut stream, &self.uuid, Command::Udp, &destination).await?;
            let (reader, writer) = split(stream);
            Ok(Box::new(VlessDatagram {
                reader: Mutex::new(VlessDatagramReader { reader }),
                writer: Mutex::new(writer),
                destination,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

struct VlessStream {
    inner: BoxAsyncStream,
    response_header: [u8; 2],
    response_header_read: usize,
    response_addons: usize,
    response_checked: bool,
    response_done: bool,
}

impl VlessStream {
    fn new(inner: BoxAsyncStream) -> Self {
        Self {
            inner,
            response_header: [0; 2],
            response_header_read: 0,
            response_addons: 0,
            response_checked: false,
            response_done: false,
        }
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.response_header_read < self.response_header.len() {
                let mut read = ReadBuf::new(&mut self.response_header[self.response_header_read..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => {
                        let count = read.filled().len();
                        if count == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated VLESS response header",
                            )));
                        }
                        self.response_header_read += count;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            if !self.response_checked {
                if self.response_header[0] != VERSION {
                    return Poll::Ready(Err(invalid_frame("unexpected VLESS response version")));
                }
                self.response_addons = usize::from(self.response_header[1]);
                self.response_checked = true;
            }
            if self.response_addons != 0 {
                let mut ignored = [0u8; MAX_ADDON_SIZE];
                let count = self.response_addons.min(ignored.len());
                let mut read = ReadBuf::new(&mut ignored[..count]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => {
                        let read_count = read.filled().len();
                        if read_count == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated VLESS response addons",
                            )));
                        }
                        self.response_addons -= read_count;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            self.response_done = true;
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.response_done {
            match self.poll_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct VlessDatagramReader {
    reader: tokio::io::ReadHalf<BoxAsyncStream>,
}

struct VlessDatagram {
    reader: Mutex<VlessDatagramReader>,
    writer: Mutex<tokio::io::WriteHalf<BoxAsyncStream>>,
    destination: Endpoint,
}

impl AsyncDatagram for VlessDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if payload.len() > MAX_PACKET_SIZE {
                return Err(Error::invalid("VLESS UDP payload is too large"));
            }
            let mut writer = self.writer.lock().await;
            writer
                .write_u16(payload.len() as u16)
                .await
                .map_err(io_error)?;
            writer.write_all(payload).await.map_err(io_error)?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            let length = usize::from(reader.reader.read_u16().await.map_err(io_error)?);
            let mut payload = vec![0u8; length];
            reader
                .reader
                .read_exact(&mut payload)
                .await
                .map_err(io_error)?;
            let copied = length.min(buffer.len());
            buffer[..copied].copy_from_slice(&payload[..copied]);
            Ok((copied, self.destination.clone()))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(Network::Udp, "0.0.0.0:0".parse().unwrap()))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.writer.lock().await.shutdown().await.map_err(io_error) })
    }
}

fn encode_address(endpoint: &Endpoint, output: &mut Vec<u8>) -> Result<()> {
    match endpoint {
        Endpoint::Ip { addr, .. } if addr.ip().is_ipv4() => {
            output.push(1);
            match addr.ip() {
                std::net::IpAddr::V4(value) => output.extend_from_slice(&value.octets()),
                std::net::IpAddr::V6(_) => unreachable!(),
            }
        }
        Endpoint::Ip { addr, .. } => {
            output.push(3);
            match addr.ip() {
                std::net::IpAddr::V6(value) => output.extend_from_slice(&value.octets()),
                std::net::IpAddr::V4(_) => unreachable!(),
            }
        }
        Endpoint::Domain { host, .. } => {
            if host.as_str().len() > 255 {
                return Err(Error::invalid("VLESS domain is too long"));
            }
            output.push(2);
            output.push(host.as_str().len() as u8);
            output.extend_from_slice(host.as_str().as_bytes());
        }
    }
    Ok(())
}

fn decode_address(
    packet: &[u8],
    cursor: &mut usize,
    command: Command,
    port: u16,
) -> Result<Endpoint> {
    let network = match command {
        Command::Tcp => Network::Tcp,
        Command::Udp => Network::Udp,
    };
    match take(packet, cursor, 1)?[0] {
        1 => Ok(Endpoint::ip(
            network,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(take(packet, cursor, 4)?).unwrap(),
                )),
                port,
            ),
        )),
        2 => {
            let length = usize::from(take(packet, cursor, 1)?[0]);
            let host = std::str::from_utf8(take(packet, cursor, length)?)
                .map_err(|_| Error::new(ErrorKind::Protocol, "VLESS domain is not UTF-8"))?;
            Ok(Endpoint::domain(network, DomainName::new(host)?, port))
        }
        3 => Ok(Endpoint::ip(
            network,
            std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(take(packet, cursor, 16)?).unwrap(),
                )),
                port,
            ),
        )),
        _ => Err(Error::new(
            ErrorKind::Protocol,
            "unknown VLESS address type",
        )),
    }
}

fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Error::invalid("VLESS UUID contains non-hex characters")),
    }
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "VLESS length overflow"))?;
    if end > packet.len() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "VLESS request is truncated",
        ));
    }
    let result = &packet[*cursor..end];
    *cursor = end;
    Ok(result)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn invalid_frame(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

    fn target(network: Network) -> Endpoint {
        Endpoint::domain(network, DomainName::new("example.com").unwrap(), 443)
    }

    #[test]
    fn uuid_and_request_round_trip_cover_all_address_kinds() {
        let uuid = parse_uuid(UUID).unwrap();
        assert_eq!(
            parse_uuid("00112233445566778899aabbccddeeff").unwrap(),
            uuid
        );
        for destination in [
            target(Network::Tcp),
            Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()),
            Endpoint::ip(Network::Tcp, "[2001:db8::1]:443".parse().unwrap()),
        ] {
            let packet = encode_request(&uuid, Command::Tcp, &destination).unwrap();
            assert_eq!(
                decode_request(&packet, &uuid).unwrap().destination,
                destination
            );
        }
    }

    #[tokio::test]
    async fn stream_waits_for_response_before_exposing_payload() {
        let uuid = parse_uuid(UUID).unwrap();
        let destination = target(Network::Tcp);
        let expected_destination = destination.clone();
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_request(&mut server, &uuid).await.unwrap();
            assert_eq!(request.destination, expected_destination);
            write_response(&mut server, b"").await.unwrap();
            server.write_all(b"reply").await.unwrap();
        });
        let mut stream = VlessStream::new(Box::new(client));
        // The request is tested independently here; the stream only owns the
        // already connected transport and must not reorder response/payload.
        write_request(&mut stream, &uuid, Command::Tcp, &destination)
            .await
            .unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn datagram_uses_length_prefixed_packets_without_response_header() {
        let uuid = parse_uuid(UUID).unwrap();
        let destination = target(Network::Udp);
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_request(&mut server, &uuid).await.unwrap();
            assert_eq!(request.command, Command::Udp);
            let length = usize::from(server.read_u16().await.unwrap());
            let mut packet = vec![0u8; length];
            server.read_exact(&mut packet).await.unwrap();
            assert_eq!(packet, b"udp-ping");
            server.write_u16(8).await.unwrap();
            server.write_all(b"udp-pong").await.unwrap();
        });
        let (reader, mut writer) = split(Box::new(client) as BoxAsyncStream);
        writer
            .write_all(&encode_request(&uuid, Command::Udp, &destination).unwrap())
            .await
            .unwrap();
        let datagram = VlessDatagram {
            reader: Mutex::new(VlessDatagramReader { reader }),
            writer: Mutex::new(writer),
            destination: destination.clone(),
        };
        datagram
            .send_to(b"udp-ping", destination.clone())
            .await
            .unwrap();
        let mut payload = [0u8; 32];
        let (length, actual) = datagram.recv_from(&mut payload).await.unwrap();
        assert_eq!(&payload[..length], b"udp-pong");
        assert_eq!(actual, destination);
        server_task.await.unwrap();
    }

    #[test]
    fn malformed_uuid_and_command_fail_closed() {
        assert!(parse_uuid("not-a-uuid").is_err());
        let uuid = parse_uuid(UUID).unwrap();
        let error = encode_request(
            &uuid,
            Command::Tcp,
            &Endpoint::ip(Network::Udp, "127.0.0.1:53".parse().unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }
}
