mod support;

use base64::Engine;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use doradus_chain::{AsyncYuubinsyaTcpSession, AsyncYuubinsyaUotSession};
use doradus_core::proxy::AsyncDatagram;
use doradus_core::{DomainName, Endpoint, Network};
use doradus_protocol::websocket::WebSocketIo;
use doradus_protocol::yuubinsya::derive_salt;
use doradus_protocol::yuubinsya_udp::YuubinsyaUdpDatagram;
use doradus_protocol::{trojan, vless, vmess};
use http::Request;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use support::{
    ConnectFixture, H2FinalProtocol, H2ProtocolFixture, H2YuubinsyaFixture, ServiceProcess,
    Socks5Fixture, YUUBINSYA_PASSWORD, add_mixed_udp_inbound, add_reverse_inbounds,
    add_socks5_inbound, add_trojan_inbound, add_trojan_udp_inbound, add_vless_inbound,
    add_vless_udp_inbound, add_yuubinsya_inbound, add_yuubinsya_udp_inbound, api_json,
    configure_aead_h2_http_inbound, configure_direct_http_inbound, configure_h2_http_chain,
    configure_h2_http_inbound, configure_h2_socks5_chain, configure_http_chain,
    configure_http_chain_with_transport, configure_network_split_http_chain,
    configure_socks5_chain, configure_tls_aead_h2_http_inbound, configure_tls_auto_http_inbound,
    configure_tls_h2_http_inbound, configure_tls_h2_yuubinsya_chain, configure_tls_http_inbound,
    connect_loopback, connect_tls_h2_loopback, connect_tls_loopback,
    connect_tls_loopback_without_sni, integration_dir, seed_empty_database, tls_server_acceptor,
    tls_termination_certificate, wait_for_connection,
};

#[cfg(target_os = "linux")]
use support::configure_http_process_inbound_chain;

#[path = "service_chain/auth_helpers.rs"]
mod auth_helpers;
use auth_helpers::*;
#[path = "service_chain/connection_wait.rs"]
mod connection_wait;
use connection_wait::*;
#[path = "service_chain/protocol_runtime.rs"]
mod protocol_runtime;
use protocol_runtime::*;
#[path = "service_chain/protocol_server.rs"]
mod protocol_server;
use protocol_server::*;
#[path = "service_chain/auth_routes.rs"]
mod auth_routes;
#[path = "service_chain/http_forwarding.rs"]
mod http_forwarding;
#[path = "service_chain/http_runtime.rs"]
mod http_runtime;
#[path = "service_chain/protocol_inbounds.rs"]
mod protocol_inbounds;
#[path = "service_chain/protocol_outbounds.rs"]
mod protocol_outbounds;
#[path = "service_chain/reverse_inbounds.rs"]
mod reverse_inbounds;
#[path = "service_chain/transport_inbounds.rs"]
mod transport_inbounds;
use transport_inbounds::yuubinsya_auth_is_rejected;
