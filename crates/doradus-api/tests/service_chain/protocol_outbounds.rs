use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_http_router() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::VlessTlsWebsocket,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::VmessTlsWebsocket,
        ProtocolOutboundKind::Trojan,
        ProtocolOutboundKind::TrojanWebsocket,
        ProtocolOutboundKind::TrojanTlsWebsocket,
    ] {
        run_protocol_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_ipv6_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_outbound_chain_on_host(kind, "::1").await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_udp_outbounds_round_trip_through_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_udp_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_mixed_udp_router() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::VlessTlsWebsocket,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::VmessTlsWebsocket,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_udp_outbound_chain(kind).await;
    }
}
