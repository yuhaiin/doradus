//! VLESS inbound adapter.
//!
//! Wire parsing and response framing live in `yuhaiin-protocol`; this module
//! only authenticates the configured UUID and routes the resulting TCP or
//! UDP-over-TCP flow through the shared runtime selector.

use crate::inbound::{
    InboundUdpCodec, InboundUdpFlowPolicy, InboundUdpRequest, InboundUdpResponse,
};
use tokio::io::{ReadHalf, WriteHalf};
use yuhaiin_core::flow::FlowKey as TunFlowKey;
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, Result};

pub(crate) struct VlessUdpCodec {
    pub(crate) server:
        yuhaiin_protocol::vless::UdpServer<ReadHalf<BoxAsyncStream>, WriteHalf<BoxAsyncStream>>,
    pub(crate) flow_key: Option<TunFlowKey>,
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
    fn note_flow(&mut self, flow: TunFlowKey) {
        self.flow_key = Some(flow);
    }

    fn owns_flow(&self, flow: TunFlowKey) -> bool {
        self.flow_key == Some(flow)
    }
}
