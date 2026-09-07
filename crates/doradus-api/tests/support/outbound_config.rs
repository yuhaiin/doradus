use super::process::settle_runtime_reload;
use super::*;

pub async fn configure_socks5_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"socks5-out",
        "name":"SOCKS5 test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"socks5","socks5":{"username":"","password":""}}
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
        "/api/v2/nodes/socks5-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"socks5-chain-in",
        "name":"SOCKS5 outbound chain inbound",
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
        "name":"proxy-example-test-over-socks5",
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

pub async fn configure_h2_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_h2_protocol_chain(
        service,
        inbound,
        outbound,
        "h2-http-out",
        "h2-http-chain-in",
        "proxy-example-test-over-h2-http",
        json!({"type":"http","http":{"user":"user","password":"pass"}}),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_h2_socks5_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_h2_protocol_chain(
        service,
        inbound,
        outbound,
        "h2-socks5-out",
        "h2-socks5-chain-in",
        "proxy-example-test-over-h2-socks5",
        json!({
            "type":"socks5",
            "socks5":{"user":"user","password":"pass","hostname":"","override_port":0}
        }),
    )
    .await;
    settle_runtime_reload().await;
}

async fn configure_h2_protocol_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    node_id: &str,
    inbound_id: &str,
    rule_name: &str,
    final_node: Value,
) {
    let node = json!({
        "id":node_id,
        "name":"HTTP/2 protocol test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http2","http2":{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}},
            final_node
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
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound = json!({
        "id":inbound_id,
        "name":"HTTP/2 protocol chain inbound",
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

pub async fn configure_tls_h2_yuubinsya_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"tls-h2-yuubinsya-out",
        "name":"TLS H2 Yuubinsya test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"tls","tls":{
                "enable":true,
                "insecure_skip_verify":true,
                "servernames":["localhost"],
                "next_protos":["h2"],
                "ca_cert":[]
            }},
            {"type":"http2","http2":{
                "concurrency":1,
                "max_streams":16,
                "idle_timeout_secs":30
            }},
            {"type":"yuubinsya","yuubinsya":{
                "password":YUUBINSYA_PASSWORD,
                "udp_over_stream":true,
                "udp_coalesce":false
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
        Method::POST,
        "/api/v2/nodes/tls-h2-yuubinsya-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"tls-h2-yuubinsya-in",
        "name":"TLS H2 Yuubinsya chain inbound",
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
        "name":"proxy-example-test-over-yuubinsya",
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

pub async fn add_mixed_udp_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr) {
    let inbound = json!({
        "id":id,
        "name":"TLS H2 Yuubinsya UDP chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"enabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"mixed","mixed":{"username":"","password":""}}
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

pub async fn add_socks5_inbound(
    service: &ServiceProcess,
    id: &str,
    listen: SocketAddr,
    username: &str,
    password: &str,
) {
    let inbound = json!({
        "id":id,
        "name":"SOCKS5 integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"socks5","socks5":{"username":username,"password":password}}
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

pub async fn add_yuubinsya_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr) {
    let inbound = json!({
        "id":id,
        "name":"Yuubinsya integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"yuubinsya","yuubinsya":{"password":YUUBINSYA_PASSWORD,"udp":false}}
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

pub async fn add_yuubinsya_udp_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr) {
    add_protocol_inbound(
        service,
        id,
        "Yuubinsya UDP integration inbound",
        listen,
        json!({
            "type":"yuubinsya",
            "yuubinsya":{"password":YUUBINSYA_PASSWORD,"udp":true}
        }),
        true,
    )
    .await;
}

pub async fn add_vless_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr, uuid: &str) {
    add_protocol_inbound(
        service,
        id,
        "VLESS integration inbound",
        listen,
        json!({"type":"vless","vless":{"uuid":uuid,"udp":false}}),
        false,
    )
    .await;
}

pub async fn add_vless_udp_inbound(
    service: &ServiceProcess,
    id: &str,
    listen: SocketAddr,
    uuid: &str,
) {
    add_protocol_inbound(
        service,
        id,
        "VLESS UDP integration inbound",
        listen,
        json!({"type":"vless","vless":{"uuid":uuid,"udp":true}}),
        true,
    )
    .await;
}

pub async fn add_trojan_inbound(
    service: &ServiceProcess,
    id: &str,
    listen: SocketAddr,
    password: &str,
) {
    add_protocol_inbound(
        service,
        id,
        "Trojan integration inbound",
        listen,
        json!({"type":"trojan","trojan":{"password":password,"udp":false}}),
        false,
    )
    .await;
}

pub async fn add_trojan_udp_inbound(
    service: &ServiceProcess,
    id: &str,
    listen: SocketAddr,
    password: &str,
) {
    add_protocol_inbound(
        service,
        id,
        "Trojan UDP integration inbound",
        listen,
        json!({"type":"trojan","trojan":{"password":password,"udp":true}}),
        true,
    )
    .await;
}

async fn add_protocol_inbound(
    service: &ServiceProcess,
    id: &str,
    name: &str,
    listen: SocketAddr,
    protocol: Value,
    udp: bool,
) {
    let inbound = json!({
        "id":id,
        "name":name,
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":if udp { "enabled" } else { "disabled" }}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":protocol
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

/// Configure both Go-compatible reverse inbound forms against the built-in
/// direct outbound. Keeping the pair in one process fixture exercises the
/// persisted inbound contract and the shared listener supervisor together.
pub async fn add_reverse_inbounds(
    service: &ServiceProcess,
    reverse_tcp_listen: SocketAddr,
    reverse_tcp_target: SocketAddr,
    reverse_http_listen: SocketAddr,
    reverse_http_url: &str,
) {
    let node = json!({
        "id":"reverse-direct",
        "name":"Reverse integration direct outbound",
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
        "/api/v2/nodes/reverse-direct/use",
        None,
    )
    .await;

    let reverse_tcp = json!({
        "id":"reverse-tcp-in",
        "name":"Reverse TCP integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":reverse_tcp_listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"reverse_tcp","reverse_tcp":{"host":reverse_tcp_target.to_string()}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&reverse_tcp),
    )
    .await;

    let reverse_http = json!({
        "id":"reverse-http-in",
        "name":"Reverse HTTP integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":reverse_http_listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"reverse_http","reverse_http":{"url":reverse_http_url}}
    });
    api_json(
        &service.client,
        &service.base_url,
        Method::POST,
        "/api/v2/inbounds",
        Some(&reverse_http),
    )
    .await;
    settle_runtime_reload().await;
}
