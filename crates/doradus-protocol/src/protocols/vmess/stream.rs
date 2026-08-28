//! VMess stream and symmetric-target UDP proxy.

use std::sync::Arc;

use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::sync::Mutex;

use super::body::{
    body_payload_size, read_body_frame, read_response_header, response_key_for, write_body_frame,
};
use super::codec::{
    CMD_TCP, CMD_UDP, MAX_ALTER_ID, Security, alter_id_users, encode_legacy_request,
    encode_request, io_error,
};

pub struct VmessProxy {
    upstream: Arc<dyn AsyncProxy>,
    uuid: [u8; 16],
    users: Vec<[u8; 16]>,
    security: Security,
}

impl VmessProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        uuid: &str,
        security: &str,
        alter_id: u32,
    ) -> Result<Self> {
        if alter_id > MAX_ALTER_ID {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("VMess alter_id exceeds the safety limit of {MAX_ALTER_ID}"),
            ));
        }
        let uuid = crate::vless::parse_uuid(uuid)?;
        let users = alter_id_users(uuid, alter_id)?;
        Ok(Self {
            upstream,
            uuid,
            users,
            security: Security::parse(security)?,
        })
    }

    pub fn from_uuid(upstream: Arc<dyn AsyncProxy>, uuid: [u8; 16], security: Security) -> Self {
        Self {
            upstream,
            uuid,
            users: vec![uuid],
            security,
        }
    }

    fn random_user(&self) -> [u8; 16] {
        let index = rand::random::<u64>() as usize % self.users.len();
        self.users[index]
    }
}

impl AsyncProxy for VmessProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut upstream = self.upstream.connect(context).await?;
            let destination = context.effective_destination();
            let user_uuid = self.random_user();
            let (request, state) = if self.users.len() == 1 {
                encode_request(&self.uuid, self.security, CMD_TCP, &destination)?
            } else {
                encode_legacy_request(&self.uuid, &user_uuid, self.security, CMD_TCP, &destination)?
            };
            upstream.write_all(&request).await.map_err(io_error)?;

            let (client, relay) = tokio::io::duplex(64 * 1024);
            let (local_reader, local_writer) = split(relay);
            let (remote_reader, remote_writer) = split(upstream);
            tokio::spawn(relay_remote_to_local(
                remote_reader,
                local_writer,
                response_key_for(&state.body_key, state.legacy),
                response_key_for(&state.body_iv, state.legacy),
                state.response_v,
                state.security,
                state.legacy,
            ));
            tokio::spawn(relay_local_to_remote(
                local_reader,
                remote_writer,
                state.body_key,
                state.body_iv,
                state.security,
            ));
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let mut upstream = self.upstream.connect(context).await?;
            let destination = context.effective_destination();
            let user_uuid = self.random_user();
            let (request, state) = if self.users.len() == 1 {
                encode_request(&self.uuid, self.security, CMD_UDP, &destination)?
            } else {
                encode_legacy_request(&self.uuid, &user_uuid, self.security, CMD_UDP, &destination)?
            };
            upstream.write_all(&request).await.map_err(io_error)?;
            let (reader, writer) = split(upstream);
            Ok(Box::new(VmessDatagram {
                reader: Mutex::new(VmessDatagramReader {
                    reader,
                    response_key: response_key_for(&state.body_key, state.legacy),
                    response_iv: response_key_for(&state.body_iv, state.legacy),
                    response_v: state.response_v,
                    security: state.security,
                    legacy: state.legacy,
                    count: 0,
                    response_read: false,
                    destination: destination.clone(),
                }),
                writer: Mutex::new(VmessDatagramWriter {
                    writer,
                    key: state.body_key,
                    iv: state.body_iv,
                    security: state.security,
                    count: 0,
                    destination,
                }),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

pub(crate) struct VmessDatagramReader {
    pub(crate) reader: tokio::io::ReadHalf<BoxAsyncStream>,
    pub(crate) response_key: [u8; 16],
    pub(crate) response_iv: [u8; 16],
    pub(crate) response_v: u8,
    pub(crate) security: Security,
    pub(crate) legacy: bool,
    pub(crate) count: u16,
    pub(crate) response_read: bool,
    pub(crate) destination: Endpoint,
}

pub(crate) struct VmessDatagramWriter {
    pub(crate) writer: tokio::io::WriteHalf<BoxAsyncStream>,
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
    pub(crate) security: Security,
    pub(crate) count: u16,
    pub(crate) destination: Endpoint,
}

pub(crate) struct VmessDatagram {
    pub(crate) reader: Mutex<VmessDatagramReader>,
    pub(crate) writer: Mutex<VmessDatagramWriter>,
}

impl AsyncDatagram for VmessDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let mut writer = self.writer.lock().await;
            if target != writer.destination {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "VMess UDP only supports the symmetric target used at open",
                ));
            }
            let key = writer.key;
            let iv = writer.iv;
            let security = writer.security;
            let count = writer.count;
            write_body_frame(&mut writer.writer, &key, &iv, security, count, payload)
                .await
                .map_err(io_error)?;
            writer.count = writer.count.wrapping_add(1);
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            let response_key = reader.response_key;
            let response_iv = reader.response_iv;
            let response_v = reader.response_v;
            let legacy = reader.legacy;
            if !reader.response_read {
                read_response_header(
                    &mut reader.reader,
                    &response_key,
                    &response_iv,
                    response_v,
                    legacy,
                )
                .await
                .map_err(io_error)?;
                reader.response_read = true;
            }
            let security = reader.security;
            let count = reader.count;
            let payload = read_body_frame(
                &mut reader.reader,
                &response_key,
                &response_iv,
                security,
                count,
            )
            .await
            .map_err(io_error)?
            .ok_or_else(|| Error::new(ErrorKind::Closed, "VMess UDP stream ended"))?;
            if payload.len() > buffer.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "VMess UDP payload buffer is too small",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            reader.count = reader.count.wrapping_add(1);
            Ok((payload.len(), reader.destination.clone()))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "VMess UDP has no local endpoint",
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async {
            let mut writer = self.writer.lock().await;
            writer.writer.shutdown().await.map_err(io_error)
        })
    }
}

async fn relay_remote_to_local<R, W>(
    mut remote: R,
    mut local: W,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    response_v: u8,
    security: Security,
    legacy: bool,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if read_response_header(&mut remote, &body_key, &body_iv, response_v, legacy)
        .await
        .is_err()
    {
        let _ = local.shutdown().await;
        return;
    }
    let mut count = 0u16;
    loop {
        match read_body_frame(&mut remote, &body_key, &body_iv, security, count).await {
            Ok(Some(payload)) => {
                count = count.wrapping_add(1);
                if local.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(None) | Err(_) => {
                let _ = local.shutdown().await;
                return;
            }
        }
    }
}

async fn relay_local_to_remote<R, W>(
    mut local: R,
    mut remote: W,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    security: Security,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_payload = body_payload_size(security);
    let mut payload = vec![0u8; max_payload];
    let mut count = 0u16;
    loop {
        match local.read(&mut payload).await {
            Ok(0) => {
                let _ = remote.shutdown().await;
                return;
            }
            Ok(length) => {
                if write_body_frame(
                    &mut remote,
                    &body_key,
                    &body_iv,
                    security,
                    count,
                    &payload[..length],
                )
                .await
                .is_err()
                {
                    return;
                }
                count = count.wrapping_add(1);
            }
            Err(_) => return,
        }
    }
}
