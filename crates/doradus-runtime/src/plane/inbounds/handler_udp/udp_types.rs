//! Shared messages and keys for inbound UDP session and flow ownership.

use std::net::SocketAddr;
use tokio::sync::{mpsc, watch};

use crate::inbound::adapters::common::UdpFlowId;
use doradus_core::Endpoint;
use doradus_core::flow::FlowKey as TunFlowKey;
use doradus_types::InboundUdpResponse;

/// A source-owned UDP flow. The destination is deliberately absent from the
/// key so one client can use one full-cone datagram for multiple targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct UdpSourceKey {
    pub(super) inbound_id: String,
    pub(super) session_id: u64,
    pub(super) source: SocketAddr,
    pub(super) authentication: Option<[u8; 32]>,
}

pub(super) struct UdpIngress {
    pub(super) session_id: u64,
    pub(super) session_cancel_rx: watch::Receiver<bool>,
    pub(super) id: UdpFlowId,
    pub(super) peer: Endpoint,
    pub(super) target: Endpoint,
    pub(super) payload: Vec<u8>,
    pub(super) reply_tx: mpsc::Sender<InboundUdpResponse>,
    pub(super) event_tx: mpsc::Sender<InboundUdpSessionEvent>,
}

impl UdpIngress {
    pub(super) fn source_key(&self, inbound_id: &str) -> Option<UdpSourceKey> {
        Some(UdpSourceKey {
            inbound_id: inbound_id.to_owned(),
            session_id: self.session_id,
            source: self.peer.addr()?,
            authentication: self.id.authentication,
        })
    }
}

pub(super) enum InboundUdpSessionEvent {
    FlowOpened(TunFlowKey),
    FlowClosed(TunFlowKey),
}

pub(super) enum UdpManagerCommand {
    CloseFlow { session_id: u64, flow: TunFlowKey },
    CloseSession(u64),
}

pub(super) struct UdpFlowHandle {
    pub(super) generation: u64,
    pub(super) data_tx: mpsc::Sender<UdpIngress>,
    pub(super) cancel_tx: watch::Sender<bool>,
    pub(super) join: tokio::task::JoinHandle<()>,
    pub(super) flow: Option<TunFlowKey>,
    pub(super) session_id: u64,
}

pub(super) enum UdpFlowEvent {
    Opened {
        key: UdpSourceKey,
        generation: u64,
        flow: TunFlowKey,
    },
    Closed {
        key: UdpSourceKey,
        generation: u64,
    },
}
