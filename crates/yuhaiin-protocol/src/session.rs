//! Yuubinsya session protocol boundaries.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::yuubinsya::{
    YuubinsyaHeader, YuubinsyaProtocol, decode_header, decode_header_any, decode_uot_frame,
    encode_header, encode_uot_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, Notify, mpsc};
use yuhaiin_core::flow::{Flow, FlowDirection, FlowKey, FlowObserver, FlowObserverGuard};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Result};
use yuhaiin_types::{InboundDnsHandler, InboundStreamHandler};

pub const MAX_UOT_COALESCE_BYTES: usize = 64 * 1024;
pub const MAX_UOT_COALESCE_FRAMES: usize = 32;
const UOT_COALESCE_FLUSH_DELAY: Duration = Duration::from_micros(100);
const SERVER_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SERVER_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DNS_TCP_PACKET: usize = 4096;

#[path = "yuubinsya_proxy.rs"]
mod yuubinsya_proxy;
#[path = "yuubinsya_tcp.rs"]
mod yuubinsya_tcp;
#[path = "yuubinsya_uot.rs"]
mod yuubinsya_uot;

pub use yuubinsya_proxy::YuubinsyaServerProxy;
pub use yuubinsya_tcp::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
};
pub use yuubinsya_uot::{AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession};

pub async fn read_uot_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut endpoint = read_endpoint_bytes(stream).await?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.map_err(io_error)?;
    let payload_length = usize::from(u16::from_be_bytes(length));
    let mut payload = vec![0u8; payload_length];
    stream.read_exact(&mut payload).await.map_err(io_error)?;
    endpoint.extend_from_slice(&length);
    endpoint.extend_from_slice(&payload);
    Ok(endpoint)
}

async fn read_header_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(io_error)?;
    let protocol = YuubinsyaProtocol::from_byte(first[0])?;
    let mut packet = vec![first[0]];
    if protocol == YuubinsyaProtocol::UdpWithMigrateId {
        let mut migrate_id = [0u8; 8];
        stream.read_exact(&mut migrate_id).await.map_err(io_error)?;
        packet.extend_from_slice(&migrate_id);
    }
    let mut password = [0u8; 32];
    stream.read_exact(&mut password).await.map_err(io_error)?;
    packet.extend_from_slice(&password);
    if matches!(protocol, YuubinsyaProtocol::Tcp | YuubinsyaProtocol::Ping) {
        packet.extend_from_slice(&read_endpoint_bytes(stream).await?);
    }
    Ok(packet)
}

async fn write_ping_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    result: Result<Duration>,
) -> Result<()> {
    let value = result
        .map(|elapsed| elapsed.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(u64::MAX);
    stream
        .write_all(&value.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.flush().await.map_err(io_error)
}

async fn read_endpoint_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(io_error)?;
    let mut output = vec![first[0]];
    match first[0] {
        1 => {
            output.resize(1 + 4 + 2, 0);
            stream
                .read_exact(&mut output[1..])
                .await
                .map_err(io_error)?;
        }
        4 => {
            output.resize(1 + 16 + 2, 0);
            stream
                .read_exact(&mut output[1..])
                .await
                .map_err(io_error)?;
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            let domain_length = usize::from(length[0]);
            output.push(length[0]);
            output.resize(output.len() + domain_length + 2, 0);
            stream
                .read_exact(&mut output[2..])
                .await
                .map_err(io_error)?;
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown Yuubinsya UOT address type",
            ));
        }
    }
    Ok(output)
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
