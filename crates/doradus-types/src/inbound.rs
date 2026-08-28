//! Inbound capability contracts independent of listener implementations.

use std::net::SocketAddr;

use crate::{BoxFuture, Endpoint, Result};

/// Shared DNS interception policy for socket and packet inbounds.
pub trait InboundDnsHandler: Send + Sync {
    fn should_hijack(&self, destination_port: Option<u16>, packet: &[u8]) -> bool;

    /// Return `Some(Ok(answer))` to intercept, `None` to forward the original
    /// TCP/UOT payload, or `Some(Err(error))` to abort the protocol session.
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Option<Result<Vec<u8>>>>;
}

/// Basic-credential verifier supplied by the application layer.
pub trait InboundBasicAuth: Send + Sync {
    fn has_basic_users(&self) -> bool;
    fn authenticate_basic(&self, username: &[u8], password: &[u8]) -> bool;
}

/// The protocol-facing representation of one HTTP proxy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundHttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: String,
}

/// Port from an inbound protocol server into the application/router layer.
///
/// Protocol crates own the bytes on the wire: authentication, handshakes,
/// protocol replies and framing.  They must not depend on a concrete route
/// selector or relay implementation just to hand an accepted stream to the
/// application.  The stream type is generic so this contract remains free of
/// Tokio (or any other async-runtime) dependency.
pub trait InboundStreamHandler<S>: Send + Sync {
    fn handle_stream<'a>(
        &'a self,
        stream: S,
        peer: SocketAddr,
        destination: Endpoint,
        protocol: &'static str,
    ) -> BoxFuture<'a, Result<()>>;
}

/// Identifies a UDP flow at an inbound protocol boundary.
///
/// This deliberately contains only wire-facing identity.  Runtime flow
/// accounting (for example a TUN flow key) belongs to the application layer,
/// not to a reusable protocol codec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InboundUdpFlowId {
    pub peer: SocketAddr,
    pub target: Endpoint,
    /// Native Yuubinsya UDP uses this to select the password for replies when
    /// one socket serves several inbound credentials.
    pub authentication: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct InboundUdpRequest {
    pub id: InboundUdpFlowId,
    pub peer: Endpoint,
    pub target: Endpoint,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InboundUdpResponse {
    pub id: InboundUdpFlowId,
    pub peer: Endpoint,
    pub target: Endpoint,
    pub payload: Vec<u8>,
}

/// Contract implemented by protocol-side inbound UDP servers.
///
/// The associated message types keep the contract independent from a
/// particular runtime's flow manager.  Tokio is intentionally absent from
/// this crate; the returned future is the shared runtime-neutral `BoxFuture`.
pub trait InboundUdpCodec: Send {
    type Request: Send;
    type Response: Send;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<Self::Request>>>;

    fn send<'a>(&'a mut self, response: Self::Response) -> BoxFuture<'a, Result<()>>;
}
