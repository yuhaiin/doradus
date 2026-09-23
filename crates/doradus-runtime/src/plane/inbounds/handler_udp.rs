//! Protocol-independent inbound UDP flow manager and session facade.

use super::*;

pub(crate) use doradus_types::{InboundUdpCodec, InboundUdpRequest, InboundUdpResponse};

#[path = "handler_udp/udp_types.rs"]
mod udp_types;
#[cfg(test)]
use udp_types::{InboundUdpSessionEvent, UdpFlowEvent, UdpIngress, UdpSourceKey};
#[path = "handler_udp/udp_manager.rs"]
mod udp_manager;
pub(crate) use udp_manager::InboundUdpManager;
#[cfg(test)]
use udp_manager::{opening_worker_key, run_udp_manager, spawn_udp_flow};
#[path = "handler_udp/udp_session.rs"]
mod udp_session;
#[path = "handler_udp/udp_worker.rs"]
mod udp_worker;
pub(crate) use udp_session::InboundUdpSession;
#[cfg(test)]
use udp_worker::UdpFlowWorker;

#[cfg(test)]
#[path = "handler_udp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "handler_udp_slow_send_tests.rs"]
mod slow_send_tests;
