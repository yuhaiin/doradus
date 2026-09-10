//! VLESS inbound adapter.
//!
//! Wire parsing and response framing live in `doradus-protocol`; this module
//! only authenticates the configured UUID and routes the resulting TCP or
//! UDP-over-TCP flow through the shared runtime selector.

use crate::inbound::{
    InboundUdpCodec, InboundUdpFlowPolicy, InboundUdpRequest, InboundUdpResponse,
};
use doradus_core::proxy::BoxAsyncStream;
use doradus_core::{BoxFuture, Result};
use tokio::io::{ReadHalf, WriteHalf};

pub(crate) struct VlessUdpCodec {
    pub(crate) server:
        doradus_protocol::vless::UdpServer<ReadHalf<BoxAsyncStream>, WriteHalf<BoxAsyncStream>>,
}

impl InboundUdpCodec for VlessUdpCodec {
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        self.server.recv()
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        self.server.send(response)
    }
}

impl InboundUdpFlowPolicy for VlessUdpCodec {
    fn close_on_flow_end(&self) -> bool {
        true
    }
}
