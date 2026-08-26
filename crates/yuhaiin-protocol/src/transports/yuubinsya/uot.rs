//! Yuubinsya UDP-over-TCP client and server frame sessions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::{
    YuubinsyaHeader, YuubinsyaProtocol, decode_header, decode_uot_frame, encode_header,
    encode_uot_frame,
};
use super::common::{
    MAX_UOT_COALESCE_BYTES, MAX_UOT_COALESCE_FRAMES, UOT_COALESCE_FLUSH_DELAY, io_error,
    read_header_bytes, read_uot_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, Notify};
use yuhaiin_core::{Endpoint, Error, ErrorKind, Result};

/// Yuubinsya UDP-over-TCP session. A session starts with the migrate-ID
/// handshake and then carries `[address][u16 length][payload]` frames.
pub struct AsyncYuubinsyaUotSession<S> {
    reader: Option<Mutex<ReadHalf<S>>>,
    pub(super) writer: Option<Arc<Mutex<AsyncYuubinsyaUotWriter<S>>>>,
    coalescer: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    coalesce_notify: Arc<Notify>,
    password_hash: [u8; 32],
    pub migrate_id: u64,
    pub udp_coalesce: bool,
    local_addr: Option<SocketAddr>,
    closed: AtomicBool,
}

pub(super) struct AsyncYuubinsyaUotWriter<S> {
    stream: WriteHalf<S>,
    pending: Vec<u8>,
    pub(super) pending_frames: usize,
}

/// Server-side UOT session.  It owns only the authenticated migration
/// handshake and frame codec; destination dispatch remains injected by the
/// caller.
pub struct AsyncYuubinsyaUotServerSession<S> {
    pub(super) stream: S,
    pub(super) password_hash: [u8; 32],
    pub migrate_id: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaUotSession<S> {
    /// Perform the UOT migration handshake and return independent read/write
    /// halves. Direct-UOT uses this to hand the halves to its concurrent
    /// datagram session without briefly serializing both directions.
    pub async fn connect_split(
        mut stream: S,
        password_hash: [u8; 32],
        migrate_id: u64,
    ) -> Result<(ReadHalf<S>, WriteHalf<S>, u64)> {
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::UdpWithMigrateId,
                migrate_id: Some(migrate_id),
                destination: None,
            },
        )?;
        stream.write_all(&header).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        let mut assigned = [0u8; 8];
        stream.read_exact(&mut assigned).await.map_err(io_error)?;
        let (reader, writer) = split(stream);
        Ok((reader, writer, u64::from_be_bytes(assigned)))
    }

    pub async fn connect(
        stream: S,
        password_hash: [u8; 32],
        migrate_id: u64,
        udp_coalesce: bool,
    ) -> Result<Self>
    where
        S: Send + 'static,
    {
        Self::connect_with_local_addr(stream, password_hash, migrate_id, udp_coalesce, None).await
    }

    pub async fn connect_with_local_addr(
        stream: S,
        password_hash: [u8; 32],
        migrate_id: u64,
        udp_coalesce: bool,
        local_addr: Option<SocketAddr>,
    ) -> Result<Self>
    where
        S: Send + 'static,
    {
        let (reader, writer, assigned_migrate_id) =
            Self::connect_split(stream, password_hash, migrate_id).await?;
        let writer = Arc::new(Mutex::new(AsyncYuubinsyaUotWriter {
            stream: writer,
            pending: Vec::new(),
            pending_frames: 0,
        }));
        let coalesce_notify = Arc::new(Notify::new());
        let coalescer = if udp_coalesce {
            let writer = Arc::downgrade(&writer);
            let notify = Arc::clone(&coalesce_notify);
            Some(tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    tokio::time::sleep(UOT_COALESCE_FLUSH_DELAY).await;
                    let Some(writer) = writer.upgrade() else {
                        return;
                    };
                    let mut writer = writer.lock().await;
                    if flush_async_uot_writer(&mut writer).await.is_err() {
                        return;
                    }
                }
            }))
        } else {
            None
        };
        Ok(Self {
            reader: Some(Mutex::new(reader)),
            writer: Some(writer),
            coalescer: StdMutex::new(coalescer),
            coalesce_notify,
            password_hash,
            migrate_id: assigned_migrate_id,
            udp_coalesce,
            local_addr,
            closed: AtomicBool::new(false),
        })
    }

    pub async fn send_to(&self, destination: &Endpoint, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UDP session is closed",
            ));
        }
        let frame = encode_uot_frame(destination, payload)?;
        let mut writer = self
            .writer
            .as_ref()
            .expect("UOT writer missing")
            .lock()
            .await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UDP session is closed",
            ));
        }
        if !self.udp_coalesce {
            writer.stream.write_all(&frame).await.map_err(io_error)?;
            return writer.stream.flush().await.map_err(io_error);
        }
        if frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending.len() + frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending_frames >= MAX_UOT_COALESCE_FRAMES
        {
            flush_async_uot_writer(&mut writer).await?;
        }
        writer.pending.extend_from_slice(&frame);
        writer.pending_frames += 1;
        if writer.pending_frames >= MAX_UOT_COALESCE_FRAMES {
            flush_async_uot_writer(&mut writer).await?;
        }
        drop(writer);
        self.coalesce_notify.notify_one();
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Endpoint, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UDP session is closed",
            ));
        }
        self.flush().await?;
        let mut reader = self
            .reader
            .as_ref()
            .expect("UOT reader missing")
            .lock()
            .await;
        let frame = read_uot_frame(&mut *reader).await?;
        let (destination, payload, _) = decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    /// Flush all queued UOT frames as one bounded byte batch.
    pub async fn flush(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UDP session is closed",
            ));
        }
        self.flush_writer().await
    }

    async fn flush_writer(&self) -> Result<()> {
        let mut writer = self
            .writer
            .as_ref()
            .expect("UOT writer missing")
            .lock()
            .await;
        flush_async_uot_writer(&mut writer).await
    }

    async fn stop_coalescer(&self) {
        let task = self.coalescer.lock().ok().and_then(|mut task| task.take());
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.stop_coalescer().await;
        self.flush_writer().await?;
        self.writer
            .as_ref()
            .expect("UOT writer missing")
            .lock()
            .await
            .stream
            .shutdown()
            .await
            .map_err(io_error)?;
        Ok(())
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Consume the session after the handshake and return independent halves.
    /// No UOT frame can be pending immediately after `connect`, so this is
    /// safe for adapters that install their own concurrent writer/reader.
    pub async fn into_split(mut self) -> (ReadHalf<S>, WriteHalf<S>) {
        self.stop_coalescer().await;
        let writer = Arc::try_unwrap(self.writer.take().expect("UOT writer missing"))
            .ok()
            .expect("UOT coalescer still owns writer")
            .into_inner();
        debug_assert!(writer.pending.is_empty());
        (
            self.reader.take().expect("UOT reader missing").into_inner(),
            writer.stream,
        )
    }
}

impl<S> Drop for AsyncYuubinsyaUotSession<S> {
    fn drop(&mut self) {
        if let Ok(mut task) = self.coalescer.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

async fn flush_async_uot_writer<S: AsyncWrite + Unpin>(
    writer: &mut AsyncYuubinsyaUotWriter<S>,
) -> Result<()> {
    if writer.pending.is_empty() {
        return Ok(());
    }
    writer
        .stream
        .write_all(&writer.pending)
        .await
        .map_err(io_error)?;
    writer.stream.flush().await.map_err(io_error)?;
    writer.pending.clear();
    writer.pending_frames = 0;
    Ok(())
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncYuubinsyaUotServerSession<S> {
    pub async fn accept(
        mut stream: S,
        password_hash: [u8; 32],
        assigned_migrate_id: u64,
    ) -> Result<Self> {
        if assigned_migrate_id == 0 {
            return Err(Error::invalid(
                "Yuubinsya server migrate id must be non-zero",
            ));
        }
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _) = decode_header(&password_hash, &header_bytes)?;
        if header.protocol != YuubinsyaProtocol::UdpWithMigrateId {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya UOT server received a non-UOT protocol",
            ));
        }
        let migrate_id = header.migrate_id.unwrap_or(0);
        let migrate_id = if migrate_id == 0 {
            assigned_migrate_id
        } else {
            migrate_id
        };
        stream
            .write_all(&migrate_id.to_be_bytes())
            .await
            .map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
            migrate_id,
        })
    }

    pub async fn recv_from(&mut self) -> Result<(Endpoint, Vec<u8>)> {
        let frame = read_uot_frame(&mut self.stream).await?;
        let (destination, payload, _) = decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    pub async fn send_to(&mut self, destination: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = encode_uot_frame(destination, payload)?;
        self.stream.write_all(&frame).await.map_err(io_error)?;
        self.stream.flush().await.map_err(io_error)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await.map_err(io_error)
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }
}
