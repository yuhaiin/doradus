use super::process::settle_runtime_reload;
use super::*;

pub async fn configure_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_http_chain_with_transport(service, inbound, outbound, "http-chain-in", "normal")
        .await;
}

/// Configure an HTTP proxy inbound whose selected outbound is the runtime's
/// direct connector. This is intentionally separate from the local HTTP
/// CONNECT fixture: absolute-form HTTPS requests must perform origin TLS
/// after this selected outbound has connected.
pub async fn configure_direct_http_inbound(service: &ServiceProcess, inbound: SocketAddr) {
    let node = json!({
        "id":"direct-http-out",
        "name":"Direct HTTP inbound outbound",
        "group":"integration",
        "enabled":true,
        "chain":[{"type":"direct","direct":{}}]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/direct-http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"direct-http-in",
        "name":"Direct HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_http_chain_with_transport(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    inbound_id: &str,
    transport_type: &str,
) {
    let node = json!({
        "id":"http-out",
        "name":"HTTP test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    let default_node = json!({
        "id":"http-default",
        "name":"HTTP default fallback",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":1}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&default_node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/http-default/use",
        None,
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::PUT,
        "/api/v2/route/tags/integration",
        Some(&json!({"type":"node","hash":"http-out"})),
    )
    .await;

    let mut transport = json!({"type":transport_type});
    transport[transport_type] = json!({});
    let inbound = json!({
        "id":inbound_id,
        "name":"HTTP chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[transport],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure the Go `network_split` shape with a real HTTP proxy on the TCP
/// branch.  The fixed parent is intentional: Go builds the split branches
/// around the already-built prefix, so this helper exercises both the store
/// parser and the runtime parent/branch composition.
pub async fn configure_network_split_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"network-split-http-out",
        "name":"Network split HTTP outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"network_split","network_split":{
                "tcp":{"type":"http","http":{"user":"","password":""}},
                "udp":{"type":"drop","drop":{}}
            }}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::PUT,
        "/api/v2/route/tags/integration",
        Some(&json!({"type":"node","hash":"network-split-http-out"})),
    )
    .await;

    let inbound = json!({
        "id":"network-split-http-in",
        "name":"NetworkSplit HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"network-split-http-rule",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure an HTTP inbound whose route is selected only when the runtime
/// can recover both the real client process and the inbound name. This keeps
/// the integration test on the persisted Go-shaped route-list/rule contract.
pub async fn configure_http_process_inbound_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    process_path: &str,
) {
    let node = json!({
        "id":"http-process-out",
        "name":"HTTP process matcher outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/http-process-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"http-process-in",
        "name":"HTTP process matcher inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let list = json!({
        "name":"process-current",
        "type":"process",
        "source":{"type":"local","local":{"lists":[process_path]}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/lists",
        Some(&list),
    )
    .await;

    let rule = json!({
        "name":"proxy-process-inbound",
        "mode":"proxy",
        "rules":[{"type":"all","all":[
            {"type":"process","process":{"list":"process-current"}},
            {"type":"inbound","inbound":{"names":["HTTP process matcher inbound"]}},
            {"type":"network","network":{"network":"tcp"}}
        ]}],
        "tag":"process-inbound-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure the smallest real TLS-termination inbound: TLS transport,
/// HTTP proxy protocol, and the built-in direct outbound. Keeping this in the
/// shared process fixture makes it reusable for future TLS/SOCKS5 and
/// TLS/HTTP2 inbound matrix tests.
pub async fn configure_tls_http_inbound(service: &ServiceProcess, inbound: SocketAddr) {
    let node = json!({
        "id":"tls-inbound-direct",
        "name":"TLS inbound direct outbound",
        "group":"integration",
        "enabled":true,
        "chain":[{"type":"direct","direct":{}}]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/tls-inbound-direct/use",
        None,
    )
    .await;

    let certificate = base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM);
    let private_key = base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM);
    let inbound = json!({
        "id":"tls-http-in",
        "name":"TLS HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{
            "type":"tls",
            "tls":{"tls":{
                "certificates":[{"certBase64":certificate,"keyBase64":private_key}],
                "nextProtos":[]
            }}
        }],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure the dynamic-SNI TLS-auto variant of the smallest real TLS/HTTP
/// inbound. The node and protocol remain identical to the static TLS helper;
/// only the listener transport is replaced so the process test isolates the
/// certificate resolver boundary.
pub async fn configure_tls_auto_http_inbound(service: &ServiceProcess, inbound: SocketAddr) {
    let node = json!({
        "id":"tls-auto-inbound-direct",
        "name":"TLS-auto inbound direct outbound",
        "group":"integration",
        "enabled":true,
        "chain":[{"type":"direct","direct":{}}]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/tls-auto-inbound-direct/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"tls-auto-http-in",
        "name":"TLS-auto HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[tls_auto_transport()],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure a prior-knowledge HTTP/2 inbound over the same runtime owner as
/// the other socket inbounds. The selected outbound is an HTTP CONNECT proxy
/// so the process test proves that the H2 transport, router, and outbound
/// protocol are all part of one data-plane chain.
pub async fn configure_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"h2-inbound-http-out",
        "name":"HTTP/2 inbound HTTP outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/h2-inbound-http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"h2-http-in",
        "name":"HTTP/2 HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"http2","http2":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-h2-inbound",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure an AEAD-wrapped prior-knowledge HTTP/2 inbound. The AEAD layer
/// is intentionally outside the H2 handshake, matching the Go transport
/// composition used by legacy inbound configurations.
pub async fn configure_aead_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"aead-h2-inbound-http-out",
        "name":"AEAD HTTP/2 inbound HTTP outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes/aead-h2-inbound-http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"aead-h2-http-in",
        "name":"AEAD HTTP/2 inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[
            {"type":"aead","aead":{"password":"runtime-aead-password","cryptoMethod":"XChacha20Poly1305"}},
            {"type":"http2","http2":{}}
        ],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-aead-h2-inbound",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure TLS termination followed by HTTP/2 prior-knowledge framing.
/// The selected outbound is fixed → HTTP CONNECT so this fixture exercises
/// TLS ALPN negotiation, H2 stream handling, router selection, and proxy-side
/// domain authority in one process-level chain.
pub async fn configure_tls_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_tls_h2_http_inbound_with_transports(
        service,
        inbound,
        outbound,
        "tls-h2-inbound-http-out",
        "TLS HTTP/2 inbound HTTP outbound",
        "tls-h2-http-in",
        "TLS HTTP/2 inbound",
        "proxy-example-test-over-tls-h2-inbound",
        json!([
            {"type":"tls","tls":{"tls":{
                "certificates":[{"certBase64":base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM),"keyBase64":base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)}],
                "nextProtos":[]
            }}},
            {"type":"http2","http2":{}}
        ]),
    )
    .await;
}

/// Configure TLS followed by AEAD and HTTP/2. The declaration order is
/// intentional: the runtime must unwrap TLS first, then AEAD, before handing
/// the stream to the prior-knowledge H2 server.
pub async fn configure_tls_aead_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_tls_h2_http_inbound_with_transports(
        service,
        inbound,
        outbound,
        "tls-aead-h2-inbound-http-out",
        "TLS AEAD HTTP/2 inbound HTTP outbound",
        "tls-aead-h2-http-in",
        "TLS AEAD HTTP/2 inbound",
        "proxy-example-test-over-tls-aead-h2-inbound",
        json!([
            {"type":"tls","tls":{"tls":{
                "certificates":[{"certBase64":base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM),"keyBase64":base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)}],
                "nextProtos":[]
            }}},
            {"type":"aead","aead":{"password":"runtime-aead-password","cryptoMethod":"XChacha20Poly1305"}},
            {"type":"http2","http2":{}}
        ]),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn configure_tls_h2_http_inbound_with_transports(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    node_id: &str,
    node_name: &str,
    inbound_id: &str,
    inbound_name: &str,
    rule_name: &str,
    transports: Value,
) {
    let node = json!({
        "id":node_id,
        "name":node_name,
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    let node_use_path = format!("/api/v2/nodes/{node_id}/use");
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        &node_use_path,
        None,
    )
    .await;

    let inbound = json!({
        "id":inbound_id,
        "name":inbound_name,
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":transports,
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":rule_name,
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}
