//! Tokio byte-stream adapter for a WebSocket transport.
//!
//! The Go implementation puts WebSocket between a lower dialer/listener and
//! the actual protocol (HTTP, SOCKS5, HTTP/2, Yuubinsya, ...).  The rest of
//! the Rust stack speaks `AsyncRead`/`AsyncWrite`, so this module owns the
//! framing boundary and keeps protocol handlers unaware of WebSocket frames.

use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const MAX_QUEUED_FRAMES: usize = 64;

/// A WebSocket connection exposed as a bounded byte stream.
///
/// Binary messages are preferred, while text messages are accepted for
/// compatibility with permissive peers. Ping frames are answered with Pong;
/// control frames never enter the protocol byte stream.
pub struct WebSocketIo<S> {
    stream: WebSocketStream<S>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    outgoing: VecDeque<Message>,
    write_inflight: Option<usize>,
}

impl<S> WebSocketIo<S> {
    pub fn new(stream: WebSocketStream<S>) -> Self {
        Self {
            stream,
            read_buffer: Vec::new(),
            read_offset: 0,
            outgoing: VecDeque::new(),
            write_inflight: None,
        }
    }

    fn queue_control(&mut self, message: Message) -> IoResult<()> {
        if self.outgoing.len() >= MAX_QUEUED_FRAMES {
            return Err(IoError::new(
                IoErrorKind::WouldBlock,
                "WebSocket control queue is full",
            ));
        }
        self.outgoing.push_back(message);
        Ok(())
    }

    fn poll_outgoing(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut this = self;
        loop {
            let Some(_) = this.outgoing.front() else {
                return match Sink::poll_flush(Pin::new(&mut this.stream), cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(websocket_io_error(error))),
                    Poll::Pending => Poll::Pending,
                };
            };
            match Sink::poll_ready(Pin::new(&mut this.stream), cx) {
                Poll::Ready(Ok(())) => {
                    let message = this
                        .outgoing
                        .pop_front()
                        .expect("outgoing message exists after front check");
                    if let Err(error) = Sink::start_send(Pin::new(&mut this.stream), message) {
                        return Poll::Ready(Err(websocket_io_error(error)));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(websocket_io_error(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncRead for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        if self.read_offset < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_offset..];
            let length = remaining.len().min(destination.remaining());
            destination.put_slice(&remaining[..length]);
            self.read_offset += length;
            if self.read_offset == self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match Stream::poll_next(Pin::new(&mut self.stream), cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    if data.is_empty() {
                        continue;
                    }
                    let length = data.len().min(destination.remaining());
                    destination.put_slice(&data[..length]);
                    if length < data.len() {
                        self.read_buffer.extend_from_slice(&data[length..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Text(data)))) => {
                    let data = data.as_bytes();
                    if data.is_empty() {
                        continue;
                    }
                    let length = data.len().min(destination.remaining());
                    destination.put_slice(&data[..length]);
                    if length < data.len() {
                        self.read_buffer.extend_from_slice(&data[length..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Ping(data)))) => {
                    if let Err(error) = self.queue_control(Message::Pong(data)) {
                        return Poll::Ready(Err(error));
                    }
                    match self.as_mut().poll_outgoing(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Poll::Ready(Some(Ok(Message::Pong(_))))
                | Poll::Ready(Some(Ok(Message::Frame(_)))) => {}
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(websocket_io_error(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<IoResult<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(length) = self.write_inflight {
            match Sink::poll_flush(Pin::new(&mut self.stream), cx) {
                Poll::Ready(Ok(())) => {
                    self.write_inflight = None;
                    return Poll::Ready(Ok(length));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(websocket_io_error(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        match self.as_mut().poll_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Sink::poll_ready(Pin::new(&mut self.stream), cx) {
            Poll::Ready(Ok(())) => {
                if let Err(error) =
                    Sink::start_send(Pin::new(&mut self.stream), Message::binary(bytes.to_vec()))
                {
                    Poll::Ready(Err(websocket_io_error(error)))
                } else {
                    match Sink::poll_flush(Pin::new(&mut self.stream), cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(bytes.len())),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(websocket_io_error(error))),
                        Poll::Pending => {
                            self.write_inflight = Some(bytes.len());
                            Poll::Pending
                        }
                    }
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(websocket_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if self.write_inflight.is_some() {
            match Sink::poll_flush(Pin::new(&mut self.stream), cx) {
                Poll::Ready(Ok(())) => self.write_inflight = None,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(websocket_io_error(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.as_mut().poll_outgoing(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if self.write_inflight.is_some() {
            match Sink::poll_flush(Pin::new(&mut self.stream), cx) {
                Poll::Ready(Ok(())) => self.write_inflight = None,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(websocket_io_error(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        match self.as_mut().poll_outgoing(cx) {
            Poll::Ready(Ok(())) => match Sink::poll_close(Pin::new(&mut self.stream), cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(websocket_io_error(error))),
                Poll::Pending => Poll::Pending,
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn websocket_io_error(error: tokio_tungstenite::tungstenite::Error) -> IoError {
    IoError::new(IoErrorKind::Other, format!("WebSocket: {error}"))
}
