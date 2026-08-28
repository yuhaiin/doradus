//! Yuubinsya TCP and persistent ping sessions.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use super::super::{YuubinsyaHeader, YuubinsyaProtocol, decode_header, encode_header};
use super::common::{io_error, read_header_bytes, write_ping_reply};
use doradus_core::{Endpoint, Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A Yuubinsya TCP stream after the authenticated destination header has been
/// sent. The remaining bytes are transparent TCP payload.
pub struct AsyncYuubinsyaTcpSession<S> {
    pub(super) stream: S,
    pub(super) password_hash: [u8; 32],
    pub(super) write_shutdown: bool,
}

/// Persistent Yuubinsya ping session.  The first response is produced after
/// the Ping header; later requests are eight-byte probes on the same stream.
pub struct AsyncYuubinsyaPingSession<S> {
    stream: S,
    write_shutdown: bool,
}

/// Server-side Ping boundary.  The actual dial/latency probe is injected by
/// the caller; this type only owns authentication, header validation and the
/// persistent probe wire format.
pub struct AsyncYuubinsyaPingServerSession<S> {
    pub(super) stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaPingSession<S> {
    pub async fn connect(
        mut stream: S,
        password_hash: [u8; 32],
        destination: Endpoint,
    ) -> Result<(Self, Duration)> {
        let started = std::time::Instant::now();
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::Ping,
                migrate_id: None,
                destination: Some(destination),
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.map_err(io_error)?;
        if response == [0xff; 8] {
            return Err(Error::new(ErrorKind::Closed, "Yuubinsya ping failed"));
        }
        Ok((
            Self {
                stream,
                write_shutdown: false,
            },
            started.elapsed(),
        ))
    }

    pub async fn ping(&mut self) -> Result<Duration> {
        let started = std::time::Instant::now();
        self.stream
            .write_all(&0u64.to_be_bytes())
            .await
            .map_err(io_error)?;
        self.stream.flush().await.map_err(io_error)?;
        let mut response = [0u8; 8];
        self.stream
            .read_exact(&mut response)
            .await
            .map_err(io_error)?;
        if response == [0xff; 8] {
            return Err(Error::new(ErrorKind::Closed, "Yuubinsya ping failed"));
        }
        Ok(started.elapsed())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.write_shutdown {
            return Ok(());
        }
        self.stream.shutdown().await.map_err(io_error)?;
        self.write_shutdown = true;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaPingServerSession<S> {
    pub async fn accept(mut stream: S, password_hash: [u8; 32]) -> Result<(Self, Endpoint)> {
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _) = decode_header(&password_hash, &header_bytes)?;
        if header.protocol != YuubinsyaProtocol::Ping {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya Ping server received a non-Ping protocol",
            ));
        }
        let destination = header.destination.ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "Yuubinsya Ping header has no destination",
            )
        })?;
        Ok((Self { stream }, destination))
    }

    /// Reply to the initial Ping and exactly one follow-up probe.  A failed
    /// probe is represented by the protocol's all-ones sentinel; the caller
    /// decides how to measure the destination.
    pub async fn serve_one_probe(
        &mut self,
        initial: Result<Duration>,
        follow_up: Result<Duration>,
    ) -> Result<()> {
        write_ping_reply(&mut self.stream, initial).await?;
        let mut probe = [0u8; 8];
        self.stream.read_exact(&mut probe).await.map_err(io_error)?;
        if probe != [0; 8] {
            return Err(Error::new(
                ErrorKind::Protocol,
                "Yuubinsya Ping probe is not zero",
            ));
        }
        write_ping_reply(&mut self.stream, follow_up).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncYuubinsyaTcpSession<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncYuubinsyaTcpSession<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaTcpSession<S> {
    pub async fn connect(
        mut stream: S,
        password_hash: [u8; 32],
        destination: Endpoint,
    ) -> Result<Self> {
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::Tcp,
                migrate_id: None,
                destination: Some(destination),
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
            write_shutdown: false,
        })
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.stream.read(buffer).await.map_err(io_error)
    }

    pub async fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        self.stream.read_exact(buffer).await.map_err(io_error)?;
        Ok(())
    }

    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        self.stream.write_all(buffer).await.map_err(io_error)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.write_shutdown {
            return Ok(());
        }
        self.stream.shutdown().await.map_err(io_error)?;
        self.write_shutdown = true;
        Ok(())
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn transport(&self) -> &S {
        &self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}
