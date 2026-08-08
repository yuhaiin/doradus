//! TCP stream framing and lifecycle for the direct Yuubinsya UOT adapter.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify, watch};
use yuhaiin_core::yuubinsya::{decode_uot_frame, encode_uot_frame};
use yuhaiin_core::{Endpoint, Error, ErrorKind, Result};

const MAX_COALESCE_BYTES: usize = 64 * 1024;
const MAX_COALESCE_FRAMES: usize = 32;

pub(crate) struct DirectUotSession {
    reader: Mutex<ReadHalf<TcpStream>>,
    writer: Mutex<DirectUotWriter>,
    coalescer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    notify: Arc<Notify>,
    closed: AtomicBool,
    shutdown: watch::Sender<bool>,
}

struct DirectUotWriter {
    stream: WriteHalf<TcpStream>,
    udp_coalesce: bool,
    pending: Vec<u8>,
    pending_frames: usize,
}

impl DirectUotSession {
    pub(crate) fn new(
        reader: ReadHalf<TcpStream>,
        writer: WriteHalf<TcpStream>,
        udp_coalesce: bool,
    ) -> Arc<Self> {
        let session = Arc::new(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(DirectUotWriter {
                stream: writer,
                udp_coalesce,
                pending: Vec::new(),
                pending_frames: 0,
            }),
            coalescer: std::sync::Mutex::new(None),
            notify: Arc::new(Notify::new()),
            closed: AtomicBool::new(false),
            shutdown: watch::channel(false).0,
        });
        if udp_coalesce {
            let weak = Arc::downgrade(&session);
            let notify = Arc::clone(&session.notify);
            let task = tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    tokio::task::yield_now().await;
                    let Some(session) = weak.upgrade() else {
                        return;
                    };
                    if session.flush().await.is_err() {
                        return;
                    }
                }
            });
            if let Ok(mut slot) = session.coalescer.lock() {
                *slot = Some(task);
            } else {
                task.abort();
            }
        }
        session
    }

    pub(crate) async fn send_to(&self, target: &Endpoint, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let frame = encode_uot_frame(target, payload)?;
        let mut writer = self.writer.lock().await;
        if !writer.udp_coalesce {
            writer.stream.write_all(&frame).await.map_err(io_error)?;
            return writer.stream.flush().await.map_err(io_error);
        }
        if frame.len() > MAX_COALESCE_BYTES
            || writer.pending.len() + frame.len() > MAX_COALESCE_BYTES
            || writer.pending_frames >= MAX_COALESCE_FRAMES
        {
            flush_writer(&mut writer).await?;
        }
        writer.pending.extend_from_slice(&frame);
        writer.pending_frames += 1;
        if writer.pending_frames >= MAX_COALESCE_FRAMES {
            flush_writer(&mut writer).await?;
        }
        drop(writer);
        self.notify.notify_one();
        Ok(())
    }

    pub(crate) async fn recv_from(&self) -> Result<(Endpoint, Vec<u8>)> {
        self.flush().await?;
        let mut reader = self.reader.lock().await;
        let mut shutdown = self.shutdown.subscribe();
        tokio::select! {
            result = read_uot_frame(&mut *reader) => {
                let frame = result?;
                let (target, payload, _) = decode_uot_frame(&frame)?;
                Ok((target, payload.to_vec()))
            }
            changed = shutdown.changed() => {
                let _ = changed;
                Err(closed_error())
            }
        }
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        flush_writer(&mut writer).await
    }

    pub(crate) async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _ = self.shutdown.send(true);
        let _ = self.flush().await;
        if let Ok(mut slot) = self.coalescer.lock()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
        let mut writer = self.writer.lock().await;
        writer.stream.shutdown().await.map_err(io_error)
    }
}

impl Drop for DirectUotSession {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.coalescer.lock()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
    }
}

async fn flush_writer(writer: &mut DirectUotWriter) -> Result<()> {
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

async fn read_uot_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(260 + 2);
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind).await.map_err(io_error)?;
    frame.push(kind[0]);
    let address_length = match kind[0] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            frame.push(length[0]);
            usize::from(length[0]) + 2
        }
        _ => return Err(Error::new(ErrorKind::Protocol, "invalid UOT address type")),
    };
    let start = frame.len();
    frame.resize(start + address_length, 0);
    stream
        .read_exact(&mut frame[start..])
        .await
        .map_err(io_error)?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.map_err(io_error)?;
    frame.extend_from_slice(&length);
    let payload_length = usize::from(u16::from_be_bytes(length));
    let start = frame.len();
    frame.resize(start + payload_length, 0);
    stream
        .read_exact(&mut frame[start..])
        .await
        .map_err(io_error)?;
    Ok(frame)
}

pub(crate) fn closed_error() -> Error {
    Error::new(ErrorKind::Closed, "Yuubinsya direct UOT session is closed")
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
