use super::*;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tower::ServiceExt;
use yuhaiin_core::dns::{DnsResponse, encode_response};
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_runtime::{RuntimeBuilder, RuntimeController};
use yuhaiin_store::ConfigStore;

#[test]
fn stun_latency_outer_timeout_covers_nat_behavior_requests() {
    let udp = LatencyRequest {
        probe_type: "stun".to_owned(),
        ..LatencyRequest::default()
    };
    assert_eq!(
        latency_probe_outer_timeout(&udp, Duration::from_secs(10)),
        Duration::from_secs(40)
    );

    let tcp = LatencyRequest {
        probe_type: "stun".to_owned(),
        tcp: true,
        ..LatencyRequest::default()
    };
    assert_eq!(
        latency_probe_outer_timeout(&tcp, Duration::from_secs(10)),
        Duration::from_secs(30)
    );

    let http = LatencyRequest {
        probe_type: "http".to_owned(),
        ..LatencyRequest::default()
    };
    assert_eq!(
        latency_probe_outer_timeout(&http, Duration::from_secs(10)),
        Duration::from_secs(10)
    );
}

#[test]
fn node_public_json_hides_go_internal_user_ids_without_mutating_unknown_json() {
    let value = node_json(yuhaiin_store::GoNodeRecord {
            id: "node-1".to_owned(),
            name: "Node 1".to_owned(),
            group_name: "group".to_owned(),
            origin: "manual".to_owned(),
            enabled: true,
            chain_types_json: b"[\"yuubinsya\"]".to_vec(),
            updated_at: 0,
            data_json: br#"{
                "hash":"legacy-hash",
                "id":"raw-id",
                "futureField":"preserve-for-compatibility",
                "chain":[
                    {"type":"simple","simple":{"host":"127.0.0.1","port":1080,"alternate_host":[],"network_interface":""}},
                    {"type":"socks5","socks5":{"hostname":"127.0.0.1","user":"","password":"","override_port":0}},
                    {"type":"yuubinsya","yuubinsya":{"userId":"runtime-only"}}
                ]
            }"#
            .to_vec(),
        });
    assert_eq!(value["id"], "node-1");
    assert_eq!(value["name"], "Node 1");
    assert_eq!(value["futureField"], "preserve-for-compatibility");
    assert!(value.get("hash").is_none());
    assert!(value["chain"][0]["simple"].get("alternate_host").is_none());
    assert!(
        value["chain"][0]["simple"]
            .get("network_interface")
            .is_none()
    );
    assert!(value["chain"][1]["socks5"].get("override_port").is_none());
    assert!(value["chain"][2]["yuubinsya"].get("userId").is_none());
}

#[test]
fn resolver_public_json_uses_go_omitzero_shape() {
    let value = resolver_json(yuhaiin_store::GoResolverRecord {
        id: "direct".to_owned(),
        resolver_type: "doh".to_owned(),
        host: "223.5.5.5".to_owned(),
        updated_at: 0,
        data_json: br#"{
                "id":"legacy-id",
                "type":"doh",
                "host":"223.5.5.5",
                "subnet":"",
                "tlsServerName":"",
                "tls_servername":""
            }"#
        .to_vec(),
    });
    assert_eq!(value["id"], "direct");
    assert_eq!(value["type"], "doh");
    assert_eq!(value["host"], "223.5.5.5");
    assert!(value.get("subnet").is_none());
    assert!(value.get("tlsServerName").is_none());
    assert!(value.get("tls_servername").is_none());
}

#[test]
fn settings_contract_uses_go_defaults_and_ignores_backup_payload() {
    let value = canonical_settings_value(&json!({
        "ipv6": true,
        "pprof": false,
        "logcat": {"level": "info"},
        "advanced": {"udpBufferSize": 65536},
        "backup": {"instanceName": "must-not-be-in-settings"},
        "unknown": true,
    }));
    assert_eq!(value["ipv6"], true);
    assert_eq!(value["pprof"], false);
    assert_eq!(value["advanced"]["udpBufferSize"], 65536);
    assert_eq!(value["backup"]["instanceName"], "");
    assert!(value.get("unknown").is_none());

    let rows = settings_kv_from_contract(&value);
    assert!(rows.iter().any(|row| {
        row.section == "advanced" && row.key == "udp_buffer_size" && row.value_json == "65536"
    }));
    assert_eq!(settings_value_from_go_kv(&rows)["logcat"]["level"], "info");
}

#[tokio::test]
async fn settings_and_backup_rpc_round_trip_go_storage_shapes() {
    let app = router(state().await);
    let settings_response = app
            .clone()
            .oneshot(
                Request::post("/api/v2/rpc/settings.put")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"ipv6":true,"advanced":{"udpBufferSize":65536},"backup":{"instanceName":"ignored"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(settings_response.status(), StatusCode::OK);
    let settings: Value = serde_json::from_slice(
        &to_bytes(settings_response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(settings["advanced"]["udpBufferSize"], 65536);
    assert_eq!(settings["backup"]["instanceName"], "");

    let generated = app
        .clone()
        .oneshot(
            Request::post("/api/v2/rpc/backup.config.get")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(generated.status(), StatusCode::OK);
    let generated: Value =
        serde_json::from_slice(&to_bytes(generated.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let generated_id = generated["instanceName"].as_str().unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(generated_id)
            .unwrap()
            .get_version_num(),
        4
    );

    let second_read = app
        .clone()
        .oneshot(
            Request::post("/api/v2/rpc/backup.config.get")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let second_read: Value = serde_json::from_slice(
        &to_bytes(second_read.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second_read["instanceName"], generated_id);

    let backup = json!({
        "instanceName":"rust-instance",
        "s3":{"enabled":true,"bucket":"bucket"},
        "interval":3600,
        "lastBackupHash":"hash"
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v2/rpc/backup.config.put")
                .header("content-type", "application/json")
                .body(Body::from(backup.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::post("/api/v2/rpc/backup.config.get")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let persisted: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(persisted["instanceName"], "rust-instance");
    assert_eq!(persisted["s3"]["bucket"], "bucket");
}

async fn read_s3_test_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0);
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0);
        bytes.extend_from_slice(&chunk[..length]);
    }
    bytes
}

#[tokio::test]
async fn backup_run_rejects_disabled_s3_before_creating_a_snapshot() {
    let error = run_backup_value(&state().await)
        .await
        .expect_err("disabled S3 backup must not report success");
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "bad_request");
    assert_eq!(error.message, "backup.run requires enabled S3 backup");
}

#[tokio::test]
async fn backup_run_and_empty_restore_use_the_go_s3_object_contract() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let uploaded = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let uploaded_server = Arc::clone(&uploaded);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_s3_test_request(&mut stream).await;
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            let is_put = request.starts_with(b"PUT ");
            let body = if is_put {
                request[header_end..].to_vec()
            } else {
                uploaded_server.lock().await.clone()
            };
            if is_put {
                *uploaded_server.lock().await = body.clone();
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                if is_put { 0 } else { body.len() }
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            if !is_put {
                stream.write_all(&body).await.unwrap();
            }
        }
    });

    let (shutdown, _shutdown_rx) = watch::channel(false);
    let state = state().await.with_shutdown(shutdown);
    let _ = backup_config_put_value(
        &state,
        json!({
            "instanceName":"api-test",
            "s3":{
                "enabled":true,
                "accessKey":"access",
                "secretKey":"secret",
                "bucket":"bucket",
                "region":"us-east-1",
                "endpointUrl":endpoint,
                "usePathStyle":true,
                "storageClass":"STANDARD"
            },
            "interval":0,
            "lastBackupHash":""
        }),
    )
    .await
    .unwrap();

    let _ = run_backup_value(&state).await.unwrap();
    let config = load_backup_config_value(&state).await.unwrap();
    assert!(string_or(&config, "lastBackupHash", "").len() == 64);
    assert!(!uploaded.lock().await.is_empty());

    let response = restore_backup_value(&state, &json!({})).await.unwrap();
    assert_eq!(response.0["accepted"], true);
    assert_eq!(response.0["restart"], true);
    server.await.unwrap();
}

#[test]
fn backup_hash_matches_go_blake2b_and_object_name_contract() {
    let s3 = S3Config {
        enabled: true,
        access_key: "a".to_owned(),
        secret_key: "b".to_owned(),
        bucket: "bucket".to_owned(),
        region: "us-east-1".to_owned(),
        endpoint_url: String::new(),
        use_path_style: false,
        storage_class: String::new(),
    };
    assert_eq!(
        backup_hash(b"state", &s3).unwrap(),
        "47a09b4d4dcab1042d455793b5ea98a8cc8a4175ee526ae276b5e63ce2b3dc1d"
    );
    assert_eq!(
        backup_object_name(&json!({"instanceName":"desktop"})).unwrap(),
        "desktop-state.db"
    );
    assert!(backup_object_name(&json!({"instanceName":""})).is_err());
}

#[tokio::test]
async fn health_endpoint_is_public_even_when_management_api_is_authenticated() {
    let app = router(state().await.with_auth("alice", "secret"));
    let response = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn state() -> ApiState {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    ApiState::new(controller)
}

#[tokio::test]
async fn external_web_root_serves_assets_and_react_fallback_without_hiding_api() {
    let root = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust")
        .join(format!("api-web-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), "<html>rust-ui</html>").unwrap();
    std::fs::write(root.join("app.js"), "console.log('rust-ui');").unwrap();

    let app = router(state().await.with_external_web(&root));
    let asset = app
        .clone()
        .oneshot(Request::get("/app.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(asset.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .as_ref(),
        b"console.log('rust-ui');"
    );

    let fallback = app
        .clone()
        .oneshot(Request::get("/dashboard").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(fallback.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(fallback.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .as_ref(),
        b"<html>rust-ui</html>"
    );

    let api = app
        .oneshot(Request::get("/api/v2/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(api.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn node_rpc_round_trips_frontend_shape_and_publishes_reload() {
    let state = state().await;
    let value = json!({"id":"direct","name":"Direct","group":"","enabled":true,"chain":[{"type":"direct","direct":{}}]});
    let saved = save_node_value(&state, value.clone(), None).await.unwrap();
    assert_eq!(saved.0["id"], "direct");
    assert_eq!(saved.0["group"], "");
    assert_eq!(saved.0["origin"], "manual");
    let listed = nodes_get_value(&state, &json!({"page":1,"page_size":0}))
        .await
        .unwrap();
    assert_eq!(listed.0["items"][0]["chain"][0]["type"], "direct");
    assert_eq!(listed.0["items"][0]["origin"], "manual");
    let stored = state
        .controller
        .store()
        .repository()
        .list_go_nodes()
        .await
        .unwrap()
        .into_iter()
        .find(|node| node.id == "direct")
        .unwrap();
    let stored_json: Value = serde_json::from_slice(&stored.data_json).unwrap();
    assert_eq!(stored_json["origin"], "manual");
    assert_eq!(state.controller.handle().revision(), 1);
}

#[tokio::test]
async fn inbound_save_returns_persisted_contract_and_resolver_storage_normalizes_system() {
    let state = state().await;
    let inbound = json!({
        "id": "api-tun",
        "name": "API TUN",
        "enabled": false,
        "network": {"type": "empty", "empty": {}},
        "transports": [],
        "protocol": {
            "type": "tun",
            "tun": {
                "name": "tun://api-tun",
                "mtu": 9000,
                "portal": "198.18.0.1/15",
                "portalV6": "fc00::1/18",
                "skipMulticast": true,
                "driver": "gvisor",
                "routes": [],
                "excludes": []
            }
        }
    });
    let saved = save_inbound_value(&state, inbound, None).await.unwrap();
    assert_eq!(saved.0["id"], "api-tun");
    assert_eq!(saved.0["name"], "API TUN");
    assert_eq!(saved.0["protocol"]["type"], "tun");

    let response = save_resolver_value(
        &state,
        json!({"id": " system ", "type": "system", "host": ""}),
        None,
    )
    .await
    .unwrap();
    // The Go controller returns the request contract from SaveContract;
    // normalization is observable through List/Get afterward.
    assert_eq!(response.0["id"], " system ");
    let listed = resolvers_get_value(&state, &json!({"page": 1, "page_size": 0}))
        .await
        .unwrap();
    let system = listed.0["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "system")
        .unwrap();
    assert_eq!(system["type"], "system");
    assert_eq!(system["host"], "system default");
    assert_eq!(system["system"], true);
}

#[tokio::test]
async fn node_selection_keeps_go_tcp_udp_contract_and_use_updates_both() {
    let state = state().await;
    for id in ["tcp-node", "udp-node"] {
        let _ = save_node_value(
            &state,
            json!({
                "id": id,
                "name": id,
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();
    }

    state
        .controller
        .store()
        .put_config(SELECTED_TCP_NODE_KEY, br#"{"id":"tcp-node"}"#)
        .await
        .unwrap();
    state
        .controller
        .store()
        .put_config(SELECTED_UDP_NODE_KEY, br#"{"id":"udp-node"}"#)
        .await
        .unwrap();

    let selected = selected_nodes_value(&state).await.unwrap();
    assert_eq!(selected.0["tcp"]["id"], "tcp-node");
    assert_eq!(selected.0["udp"]["id"], "udp-node");

    let used = select_node_value(&state, "udp-node".to_owned())
        .await
        .unwrap();
    assert_eq!(used.0, json!({}));
    let selected = selected_nodes_value(&state).await.unwrap();
    assert_eq!(selected.0["tcp"]["id"], "udp-node");
    assert_eq!(selected.0["udp"]["id"], "udp-node");
}

#[tokio::test]
async fn node_selection_reads_and_updates_go_metadata_strings() {
    let state = state().await;
    for id in ["tcp-node", "udp-node"] {
        let _ = save_node_value(
            &state,
            json!({
                "id": id,
                "name": id,
                "enabled": true,
                "chain": [{"type":"direct","direct":{}}]
            }),
            None,
        )
        .await
        .unwrap();
    }

    state
        .controller
        .store()
        .repository()
        .put_go_selected_node_ids("tcp-node")
        .await
        .unwrap();
    let selected = selected_nodes_value(&state).await.unwrap();
    assert_eq!(selected.0["tcp"]["id"], "tcp-node");
    assert_eq!(selected.0["udp"]["id"], "tcp-node");

    let _ = select_node_value(&state, "udp-node".to_owned())
        .await
        .unwrap();
    let repository = state.controller.store().repository();
    assert_eq!(
        repository
            .get_go_selected_node_id(SELECTED_TCP_NODE_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some("udp-node")
    );
    assert_eq!(
        repository
            .get_go_selected_node_id(SELECTED_UDP_NODE_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some("udp-node")
    );
}

#[tokio::test]
async fn direct_node_latency_resolves_domain_before_async_socket_connect() {
    let state = state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte)
                .await
                .unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    });

    let _ = save_node_value(
        &state,
        json!({
            "id": "direct-latency",
            "name": "Direct latency",
            "enabled": true,
            "chain": [{"type":"direct","direct":{}}]
        }),
        None,
    )
    .await
    .unwrap();

    let response = node_latency_value(
        &state,
        &json!({
            "id": "direct-latency",
            "type": "tcp",
            "url": format!("http://localhost:{}/health", address.port())
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        response.0["ok"], true,
        "direct latency response: {}",
        response.0
    );
    server.await.unwrap();
}

#[tokio::test]
async fn direct_node_latency_dns_uses_the_selected_proxy_datagram() {
    let state = state().await;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut query = [0u8; 4096];
        let (length, peer) = server.recv_from(&mut query).await.unwrap();
        let response = encode_response(
            &query[..length],
            &DnsResponse {
                addresses: yuhaiin_core::IpSet {
                    v4: vec!["192.0.2.77".parse().unwrap()],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            },
        )
        .unwrap();
        server.send_to(&response, peer).await.unwrap();
    });

    let _ = save_node_value(
        &state,
        json!({
            "id": "direct-dns-latency",
            "name": "Direct DNS latency",
            "enabled": true,
            "chain": [{"type":"direct","direct":{}}]
        }),
        None,
    )
    .await
    .unwrap();

    let response = node_latency_value(
        &state,
        &json!({
            "id": "direct-dns-latency",
            "type": "dns",
            "host": address.to_string(),
            "targetDomain": "example.com"
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        response.0["ok"], true,
        "DNS latency response: {}",
        response.0
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn active_nodes_reports_live_proxy_slots_not_all_enabled_rows() {
    let state = state().await;
    let _ = save_node_value(
        &state,
        json!({
            "id": "active-node",
            "name": "active-node",
            "enabled": true,
            "chain": [{"type":"direct","direct":{}}]
        }),
        None,
    )
    .await
    .unwrap();
    let _ = save_node_value(
        &state,
        json!({
            "id": "idle-node",
            "name": "idle-node",
            "enabled": true,
            "chain": [{"type":"direct","direct":{}}]
        }),
        None,
    )
    .await
    .unwrap();

    let initially_active = active_nodes_value(&state).await.unwrap();
    assert!(initially_active.0["items"].as_array().unwrap().is_empty());

    let selector = state
        .controller
        .build_proxy_selector("", "active-node", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let active = active_nodes_value(&state).await.unwrap();
    assert_eq!(active.0["items"].as_array().unwrap().len(), 1);
    assert_eq!(active.0["items"][0]["id"], "active-node");

    drop(selector);
    let after_drop = active_nodes_value(&state).await.unwrap();
    assert!(after_drop.0["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn inbound_config_uses_go_shape_and_reload_updates_sniff_policy() {
    let state = state().await;
    let app = router(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v2/inbounds/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let initial: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(initial["hijackDns"], true);
    assert_eq!(initial["hijackDnsFakeIp"], true);
    assert_eq!(initial["sniff"], true);

    let response = app
        .oneshot(
            Request::put("/api/v2/inbounds/config")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"hijackDns":false,"hijackDnsFakeIp":false,"sniff":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!state.controller.handle().load().inbound_settings.hijack_dns);
    assert!(
        !state
            .controller
            .handle()
            .load()
            .inbound_settings
            .hijack_dns_fakeip
    );
    assert!(!state.controller.monitor().sniff_enabled());
    let saved = state
        .controller
        .store()
        .repository()
        .get_inbound_settings()
        .await
        .unwrap();
    assert_eq!(
        saved,
        InboundSettings {
            hijack_dns: false,
            hijack_dns_fakeip: false,
            sniff: false,
        }
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rust_pprof_index_follows_runtime_setting() {
    let state = state().await;
    let app = router(state.clone());
    let enabled = app
        .clone()
        .oneshot(Request::get("/debug/pprof/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(enabled.status(), StatusCode::OK);
    assert_eq!(
        enabled.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let profile = app
        .clone()
        .oneshot(
            Request::get("/debug/pprof/profile?seconds=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    assert_eq!(
        profile.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(
        !to_bytes(profile.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap()
            .is_empty()
    );

    #[cfg(not(windows))]
    {
        let heap = app
            .clone()
            .oneshot(
                Request::get("/debug/pprof/heap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(heap.status(), StatusCode::OK);
        assert_eq!(
            heap.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert!(
            !to_bytes(heap.into_body(), 16 * 1024 * 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }

    state
        .controller
        .store()
        .put_config("settings", br#"{"pprof":false}"#)
        .await
        .unwrap();
    state.controller.reload().await.unwrap();
    let disabled = router(state)
        .oneshot(Request::get("/debug/pprof/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_priority_and_test_endpoints_use_persisted_rules() {
    let state = state().await;
    let _ = save_route_rule_value(
        &state,
        json!({
            "name":"allow-example",
            "mode":"direct",
            "match":{"domain":"example.com"}
        }),
        None,
    )
    .await
    .unwrap();
    let _ = save_route_rule_value(
        &state,
        json!({
            "name":"drop-example",
            "mode":"drop",
            "match":{"domain":"example.com"}
        }),
        None,
    )
    .await
    .unwrap();
    let pending = route_activation_value(&state).await.unwrap();
    assert!(pending.0["ruleApplyAt"].as_i64().unwrap_or_default() > unix_millis());

    let priority = router(state.clone())
            .oneshot(
                Request::post("/api/v2/route/rules/priority")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"source":{"name":"drop-example","index":1},"target":{"name":"allow-example","index":0},"operate":"insert_before"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(priority.status(), StatusCode::OK);

    let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
        .await
        .unwrap();
    assert_eq!(
        listed.0["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "drop-example")
            .unwrap()["name"],
        "drop-example"
    );

    let tested = router(state.clone())
        .oneshot(
            Request::post("/api/v2/route/rules/test")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"host":"example.com:443"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tested.status(), StatusCode::OK);
    let body = to_bytes(tested.into_body(), 1024 * 1024).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["mode"], "drop");
    assert_eq!(value["afterAddr"], "example.com:443");
    let match_result = value["matchResult"].as_array().unwrap();
    let selected = match_result
        .iter()
        .find(|entry| entry["ruleName"] == "drop-example")
        .expect("selected route rule must be present in match history");
    assert!(selected["history"].is_array());

    let _ = route_apply_value(&state).await.unwrap();
    let applied = route_activation_value(&state).await.unwrap();
    assert_eq!(applied.0["hostIndexRefreshAt"], 0);
    assert_eq!(applied.0["ruleApplyAt"], 0);
}

#[tokio::test]
async fn route_activation_expiry_matches_go_timer_lifecycle() {
    let state = state().await;
    state
        .controller
        .store()
        .put_config(
            ROUTE_ACTIVATION_KEY,
            &serde_json::to_vec(&json!({
                "hostIndexRefreshAt": 0,
                "ruleApplyAt": unix_millis() - 1,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    state
        .controller
        .store()
        .put_config(
            ROUTE_LIST_ACTIVATION_KEY,
            &serde_json::to_vec(&json!({
                "hostIndexRefreshAt": unix_millis() - 1,
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let expired_rules = route_activation_value(&state).await.unwrap();
    assert_eq!(expired_rules.0["hostIndexRefreshAt"], 0);
    assert_eq!(expired_rules.0["ruleApplyAt"], 0);
    let expired_lists = route_lists_activation_value(&state).await.unwrap();
    assert_eq!(expired_lists.0["hostIndexRefreshAt"], 0);

    state
        .controller
        .store()
        .put_config(
            ROUTE_ACTIVATION_KEY,
            &serde_json::to_vec(&pending_route_rule_activation()).unwrap(),
        )
        .await
        .unwrap();
    let pending = route_activation_value(&state).await.unwrap();
    assert!(pending.0["ruleApplyAt"].as_i64().unwrap() > unix_millis());
}

#[tokio::test]
async fn route_rule_url_index_does_not_create_duplicate_rules() {
    let state = state().await;
    let app = router(state.clone());
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/v2/route/rules")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"name":"browser","mode":"direct","match":{"domain":"example.com"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);

    let updated = app
        .clone()
        .oneshot(
            Request::put("/api/v2/route/rules/browser/999")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"mode":"drop","match":{"domain":"example.com"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);

    let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
        .await
        .unwrap();
    let browser_rules = listed.0["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["name"] == "browser")
        .collect::<Vec<_>>();
    assert_eq!(browser_rules.len(), 1);
    assert_eq!(browser_rules[0]["index"], 2);

    let fetched = app
        .clone()
        .oneshot(
            Request::get("/api/v2/route/rules/browser/0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let fetched: Value =
        serde_json::from_slice(&to_bytes(fetched.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(fetched["mode"], "drop");

    let deleted = app
        .oneshot(
            Request::delete("/api/v2/route/rules/browser/123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let listed = route_rules_get_value(&state, &json!({"page":1,"pageSize":20}))
        .await
        .unwrap();
    assert!(
        !listed.0["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == "browser")
    );
}

#[tokio::test]
async fn route_list_api_reports_loaded_local_items_after_reload() {
    let state = state().await;
    let _ = save_route_list_value(
        &state,
        json!({
            "name":"local-domains",
            "type":"host",
            "source":{"type":"local","local":{"lists":["example.test","api.example.test"]}}
        }),
        None,
    )
    .await
    .unwrap();
    let list_pending = route_lists_activation_value(&state).await.unwrap();
    assert!(
        list_pending.0["hostIndexRefreshAt"]
            .as_i64()
            .unwrap_or_default()
            > unix_millis()
    );
    let combined_pending = route_activation_value(&state).await.unwrap();
    assert!(
        combined_pending.0["hostIndexRefreshAt"]
            .as_i64()
            .unwrap_or_default()
            > unix_millis()
    );
    let listed = route_lists_get_value(&state, &json!({"page":1,"pageSize":20}))
        .await
        .unwrap();
    let local = listed.0["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "local-domains")
        .unwrap();
    assert_eq!(local["name"], "local-domains");
    assert_eq!(local["itemCount"], 2);
    assert_eq!(local["errorCount"], 0);
    assert!(local["preview"].as_str().unwrap().contains("example.test"));
}

#[tokio::test]
async fn route_list_refresh_downloads_remote_content_and_reloads_runtime_snapshot() {
    let state = state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}/rules.txt");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 2048];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        let body = b"remote.example\n";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, body)
            .await
            .unwrap();
    });

    let list_name = format!("remote-http-{}", std::process::id());
    let _ = save_route_list_value(
        &state,
        json!({
            "name":list_name,
            "type":"host",
            "source":{"type":"remote","remote":{"urls":[url]}}
        }),
        None,
    )
    .await
    .unwrap();
    let _ = route_lists_refresh_value(&state).await.unwrap();
    server.await.unwrap();
    let report = route_lists_activation_value(&state).await.unwrap();
    assert_eq!(report.0["refreshed"], 1);
    assert_eq!(report.0["errors"], json!({}));

    let snapshot = state.controller.handle().load();
    assert_eq!(
        snapshot.route_lists.values(&list_name).unwrap(),
        &["remote.example".to_owned()][..]
    );
    let detail = get_route_list_value(&state, list_name.clone())
        .await
        .unwrap();
    assert_eq!(detail.0["errorMsgs"], json!([]));

    let cache_path = yuhaiin_runtime::route_list_cache_path(&url);
    let _ = std::fs::remove_file(cache_path);
}

#[test]
fn route_list_refresh_interval_matches_go_minutes_and_zero_disables() {
    assert_eq!(
        route_list_refresh_duration(&json!({"refreshInterval":"3600"})),
        Some(Duration::from_secs(3600 * 60))
    );
    assert_eq!(
        route_list_refresh_duration(&json!({"refreshInterval":0})),
        None
    );
    assert_eq!(
        route_list_refresh_duration(&json!({"refreshInterval":"not-a-number"})),
        None
    );
}

#[test]
fn route_list_refresh_guard_matches_go_single_flight_error_and_release() {
    let refreshing = Arc::new(AtomicBool::new(false));
    let guard = RouteListRefreshGuard::acquire(&refreshing).unwrap();
    let error = match RouteListRefreshGuard::acquire(&refreshing) {
        Ok(_) => panic!("a second route-list refresh must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, "internal_error");
    assert_eq!(error.message, "refreshing");
    drop(guard);
    assert!(RouteListRefreshGuard::acquire(&refreshing).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn scheduled_route_list_refresh_reloads_and_stops_with_service() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let state = state().await;
            let _ = route_lists_config_put_value(
                &state,
                json!({
                    "refreshInterval":"1",
                    "hostIndexDisk":false,
                    "maxMindDbGeoIp":{"downloadUrl":""}
                }),
            )
            .await
            .unwrap();
            let (shutdown, receiver) = watch::channel(false);
            let task = tokio::task::spawn_local(run_route_list_refresh_loop_inner(
                state.clone(),
                receiver,
                Some(Duration::from_millis(1)),
            ));

            tokio::time::sleep(Duration::from_millis(20)).await;
            let config = state
                .controller
                .store()
                .get_config("route.lists.config")
                .await
                .unwrap()
                .map(|bytes| raw_json(&bytes, Value::Null))
                .unwrap();
            let last_refresh_time = config["lastRefreshTime"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap();
            let now = unix_seconds();
            assert!(last_refresh_time >= now.saturating_sub(2));
            assert!(last_refresh_time <= now.saturating_add(2));

            shutdown.send(true).unwrap();
            task.await.unwrap();
        })
        .await;
}

#[tokio::test]
async fn route_detail_gets_return_go_store_normalized_contracts() {
    let state = state().await;
    let _ = save_route_list_value(&state, json!({"name":"normalized-list", "source":{}}), None)
        .await
        .unwrap();
    let list = get_route_list_value(&state, "normalized-list".to_owned())
        .await
        .unwrap();
    assert_eq!(list.0["name"], "normalized-list");
    assert_eq!(list.0["type"], "host");
    assert_eq!(list.0["source"]["type"], "local");
    assert!(list.0["source"]["local"].is_object());
    assert!(list.0["source"].get("remote").is_none());

    let _ = save_route_rule_value(
        &state,
        json!({
            "name":"normalized-rule",
            "mode":"",
            "match":{"domain":"normalized.example"}
        }),
        None,
    )
    .await
    .unwrap();
    let rule = get_route_rule_value(&state, "normalized-rule".to_owned(), 999)
        .await
        .unwrap();
    assert_eq!(rule.0["name"], "normalized-rule");
    assert_eq!(rule.0["mode"], "bypass");
    assert!(rule.0.get("match").is_none());
}

#[test]
fn route_list_refresh_errors_are_persisted_only_for_remote_lists() {
    let remote = GoRouteListRecord {
        name: "remote".to_owned(),
        list_type: "host".to_owned(),
        source_type: "remote".to_owned(),
        updated_at: 7,
        data_json: serde_json::to_vec(&json!({
            "name":"remote",
            "type":"host",
            "source":{"type":"remote","remote":{"urls":["https://rules.example/list"]}},
            "errorMsgs":["stale"]
        }))
        .unwrap(),
    };
    let local = GoRouteListRecord {
        name: "local".to_owned(),
        list_type: "host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 8,
        data_json: serde_json::to_vec(&json!({
            "name":"local",
            "type":"host",
            "source":{"type":"local","local":{"lists":["local.example"]}}
        }))
        .unwrap(),
    };

    let updated = route_list_record_with_refresh_errors(
        &remote,
        &["https://rules.example/list: timeout".to_owned()],
    )
    .unwrap();
    assert_eq!(updated.name, remote.name);
    assert_eq!(updated.updated_at, remote.updated_at);
    assert_eq!(
        raw_json(&updated.data_json, Value::Null)["errorMsgs"][0],
        "https://rules.example/list: timeout"
    );
    assert!(route_list_record_with_refresh_errors(&local, &[]).is_none());
}

#[tokio::test]
async fn route_list_refresh_downloads_geoip_through_runtime_and_persists_metadata() {
    let state = state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture: &'static [u8] =
        include_bytes!("../../yuhaiin-geo/tests/fixtures/GeoLite2-Country-Test.mmdb");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 2048];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            fixture.len()
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, fixture)
            .await
            .unwrap();
    });

    let unique_path = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("yuhaiin-rust")
        .join("geo-tests")
        .join(format!("api-{}.mmdb", std::process::id()));
    let _ = route_lists_config_put_value(
        &state,
        json!({
            "refreshInterval":"0",
            "lastRefreshTime":"0",
            "error":"",
            "hostIndexDisk":true,
            "maxMindDbGeoIp":{"downloadUrl":format!("http://{address}/Country.mmdb"),"error":""}
        }),
    )
    .await
    .unwrap();
    state
        .controller
        .store()
        .repository()
        .put_maxmind_metadata(&MaxMindMetadataRecord {
            id: "geoip".to_owned(),
            path: unique_path.to_string_lossy().into_owned(),
            sha256: Vec::new(),
            size: 0,
            updated_at: 0,
        })
        .await
        .unwrap();

    let _ = route_lists_refresh_value(&state).await.unwrap();
    server.await.unwrap();

    let activation = route_lists_activation_value(&state).await.unwrap();
    assert!(
        activation.0["hostIndexRefreshAt"]
            .as_i64()
            .unwrap_or_default()
            > unix_millis()
    );

    let metadata = state
        .controller
        .store()
        .repository()
        .list_maxmind_metadata()
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].size, fixture.len() as i64);
    assert_eq!(metadata[0].sha256.len(), 32);
    assert_eq!(
        state
            .controller
            .handle()
            .load()
            .geo
            .as_ref()
            .unwrap()
            .country_code("2.125.160.217".parse().unwrap())
            .unwrap(),
        Some("GB".to_owned())
    );
    let config = state
        .controller
        .store()
        .get_config("route.lists.config")
        .await
        .unwrap()
        .map(|bytes| raw_json(&bytes, default_route_list_config()))
        .unwrap();
    assert_eq!(config["maxMindDbGeoIp"]["error"], "");
    let _ = std::fs::remove_file(unique_path);
}

#[tokio::test]
async fn route_list_config_matches_go_canonical_settings_and_contract() {
    let state = state().await;
    let canonical = route_list_config_from_go_settings(&[
            GoSettingsKvRecord {
                section: "route_extra".to_owned(),
                key: "refresh_config".to_owned(),
                value_json: r#"{"refresh_interval":3600,"last_refresh_time":42,"error":"old","host_index_disk":true}"#.to_owned(),
            },
            GoSettingsKvRecord {
                section: "route_extra".to_owned(),
                key: "maxminddb_geoip".to_owned(),
                value_json: r#"{"download_url":"https://geo.example/Country.mmdb","error":""}"#.to_owned(),
            },
        ])
        .unwrap();
    assert_eq!(canonical["refreshInterval"], "3600");
    assert_eq!(canonical["lastRefreshTime"], "42");
    assert_eq!(canonical["hostIndexDisk"], true);
    assert_eq!(
        canonical["maxMindDbGeoIp"]["downloadUrl"],
        "https://geo.example/Country.mmdb"
    );

    state
            .controller
            .store()
            .repository()
            .put_go_settings_kv(&[
                GoSettingsKvRecord {
                    section: "route_extra".to_owned(),
                    key: "refresh_config".to_owned(),
                    value_json: r#"{"refresh_interval":3600,"last_refresh_time":42,"error":"old","host_index_disk":false}"#.to_owned(),
                },
                GoSettingsKvRecord {
                    section: "route_extra".to_owned(),
                    key: "maxminddb_geoip".to_owned(),
                    value_json: r#"{"download_url":"https://geo.example/Country.mmdb","error":"geo-old"}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

    let saved = route_lists_config_put_value(
        &state,
        json!({
            "refreshInterval":"7200",
            "lastRefreshTime":"not-a-number",
            "error":"",
            "hostIndexDisk":true,
            "maxMindDbGeoIp":{"downloadUrl":"https://geo.example/Country.mmdb","error":""},
            "unknown":"discarded"
        }),
    )
    .await
    .unwrap();
    assert_eq!(saved.0["refreshInterval"], "7200");
    assert_eq!(saved.0["lastRefreshTime"], "42");
    assert_eq!(saved.0["error"], "");
    assert_eq!(saved.0["maxMindDbGeoIp"]["error"], "geo-old");
    assert!(saved.0.get("unknown").is_none());
    assert_eq!(
        route_lists_config_get_value(&state).await.unwrap().0,
        saved.0
    );

    let changed_url = route_lists_config_put_value(
            &state,
            json!({
                "refreshInterval":"7200",
                "hostIndexDisk":true,
                "maxMindDbGeoIp":{"downloadUrl":"https://geo.example/new.mmdb","error":"client-error-is-discarded"}
            }),
        )
        .await
        .unwrap();
    assert_eq!(changed_url.0["lastRefreshTime"], "42");
    assert_eq!(changed_url.0["maxMindDbGeoIp"]["error"], "");
}

#[tokio::test]
async fn direct_subscription_tools_and_node_close_routes_match_frontend_contracts() {
    let state = state().await;
    let app = router(state);

    let saved = app
            .clone()
            .oneshot(
                Request::put("/api/v2/subscriptions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"items":[{"name":"prod","url":"https://example.test/sub","type":"base64","future":true}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);

    let listed = app
        .clone()
        .oneshot(
            Request::get("/api/v2/subscriptions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(listed["items"][0]["name"], "prod");
    assert_eq!(listed["items"][0]["future"], true);

    let refresh_all = app
        .clone()
        .oneshot(
            Request::post("/api/v2/subscriptions/update")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_all.status(), StatusCode::OK);

    let refresh_named = app
        .clone()
        .oneshot(
            Request::post("/api/v2/subscriptions/update")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"names":["prod"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_named.status(), StatusCode::SERVICE_UNAVAILABLE);

    let preview = app
        .clone()
        .oneshot(
            Request::post("/api/v2/subscriptions/delete-preview")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"names":["prod"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview: Value =
        serde_json::from_slice(&to_bytes(preview.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(preview, json!({"nodes": 0, "users": 0}));

    let interfaces = app
        .clone()
        .oneshot(
            Request::get("/api/v2/tools/interfaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(interfaces.status(), StatusCode::OK);
    let interfaces: Value =
        serde_json::from_slice(&to_bytes(interfaces.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(interfaces["interfaces"].is_array());

    let closed = app
        .oneshot(
            Request::post("/api/v2/nodes/prod/close")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(closed.status(), StatusCode::OK);
}

#[tokio::test]
async fn connections_close_rejects_non_numeric_ids_like_go() {
    let state = state().await;
    let response = router(state)
        .oneshot(
            Request::post("/api/v2/connections/close")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ids":["not-a-number"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn connection_statistics_require_go_compatible_ranges_and_limits() {
    let state = state().await;
    let app = router(state);

    let missing_range = app
        .clone()
        .oneshot(
            Request::get("/api/v2/connections/traffic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_range.status(), StatusCode::BAD_REQUEST);

    let invalid_range = app
        .clone()
        .oneshot(
            Request::get(
                "/api/v2/connections/traffic?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_range.status(), StatusCode::BAD_REQUEST);

    let invalid_limit = app
            .oneshot(
                Request::get("/api/v2/connections/telemetry?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&limit=51")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(invalid_limit.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn publishes_read_native_go_rows_and_preserve_resolve_semantics() {
    let state = state().await;
    state
        .controller
        .store()
        .repository()
        .put_go_publish(&GoPublishRecord {
            name: "public".to_owned(),
            updated_at: 1,
            data_json: br#"{"points":[],"path":"feed","password":"secret"}"#.to_vec(),
        })
        .await
        .unwrap();
    let app = router(state);

    let list = app
        .clone()
        .oneshot(
            Request::get("/api/v2/publishes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list: Value =
        serde_json::from_slice(&to_bytes(list.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(list["items"][0]["name"], "public");
    assert_eq!(list["items"][0]["points"], json!([]));

    let resolved = app
        .clone()
        .oneshot(
            Request::post("/api/v2/publishes/public/resolve")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"feed","password":"secret"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resolved.status(), StatusCode::OK);
    let resolved: Value =
        serde_json::from_slice(&to_bytes(resolved.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(resolved["points"], json!([]));

    let mismatch = app
        .clone()
        .oneshot(
            Request::post("/api/v2/publishes/public/resolve")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"wrong","password":"secret"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::OK);
    let mismatch: Value =
        serde_json::from_slice(&to_bytes(mismatch.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(mismatch["points"].is_null());
}

#[tokio::test]
async fn direct_legacy_management_routes_are_wired_to_shared_value_handlers() {
    let state = state().await;
    let app = router(state);

    let request = |method: axum::http::Method, uri: &str, body: &'static str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };

    let response = app
        .clone()
        .oneshot(request(
            axum::http::Method::POST,
            "/api/v2/nodes",
            r#"{"id":"direct","name":"Direct","chain":[{"type":"direct","direct":{}}]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for uri in [
        "/api/v2/nodes/selected",
        "/api/v2/nodes/active",
        "/api/v2/inbounds/config",
        "/api/v2/route/lists/config",
        "/api/v2/route/lists/activation",
        "/api/v2/publishes",
        "/api/v2/users",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    }

    let response = app
        .clone()
        .oneshot(request(
            axum::http::Method::POST,
            "/api/v2/nodes/direct/use",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for (uri, body) in [
        (
            "/api/v2/inbounds/config",
            r#"{"hijackDns":true,"hijackDnsFakeIp":true,"sniff":true}"#,
        ),
        (
            "/api/v2/route/lists/config",
            r#"{"refreshInterval":"3600"}"#,
        ),
        (
            "/api/v2/route/tags/mobile",
            r#"{"type":"node","hash":"abc"}"#,
        ),
        ("/api/v2/publishes/public", r#"{"points":["direct"]}"#),
        (
            "/api/v2/users",
            r#"{"name":"Alice","enabled":true,"usage":"outbound","credential":{"type":"token","token":{"token":"secret"}}}"#,
        ),
    ] {
        let method = if uri == "/api/v2/users" {
            axum::http::Method::POST
        } else {
            axum::http::Method::PUT
        };
        let response = app
            .clone()
            .oneshot(request(method, uri, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "PUT/POST {uri}");
    }

    let response = app
        .clone()
        .oneshot(request(
            axum::http::Method::POST,
            "/api/v2/publishes/public/resolve",
            r#"{"name":"public"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for uri in [
        "/api/v2/route/tags",
        "/api/v2/route/tags/mobile",
        "/api/v2/publishes/public",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(if uri.ends_with("mobile") || uri.ends_with("public") {
                        axum::http::Method::DELETE
                    } else {
                        axum::http::Method::GET
                    })
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET/DELETE {uri}");
    }

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v2/route/lists/refresh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::post("/api/v2/update/check")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"channel":"stable"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // The route remains valid when the host has no release-service
    // connectivity; in that case the network error is intentionally
    // surfaced as 503 instead of returning a fabricated update result.
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
    ));
}

#[tokio::test]
async fn route_tags_use_go_node_tags_contract_and_filter_fields() {
    let state = state().await;

    let response = tag_put_value(&state, json!({"tag":" mobile ","type":"","hash":"abc"}))
        .await
        .unwrap();
    assert_eq!(response.0, json!({}));

    let listed = tags_get_value(&state, &json!({"page":1,"page_size":20}))
        .await
        .unwrap();
    assert_eq!(listed.0["items"][0]["name"], "mobile");
    assert_eq!(listed.0["items"][0]["type"], "node");
    assert_eq!(listed.0["items"][0]["hash"], json!(["abc"]));
    assert_eq!(listed.0["page"]["total"], 1);

    let filtered = tags_get_value(&state, &json!({"query":"abc"}))
        .await
        .unwrap();
    assert_eq!(filtered.0["page"]["total"], 1);
    let unmatched = tags_get_value(&state, &json!({"query":"mirror"}))
        .await
        .unwrap();
    assert_eq!(unmatched.0["page"]["total"], 0);

    let _ = tag_delete_value(&state, "mobile".to_owned()).await.unwrap();
    let empty = tags_get_value(&state, &json!({})).await.unwrap();
    assert_eq!(empty.0["page"]["total"], 0);
    assert!(tag_delete_value(&state, "mobile".to_owned()).await.is_err());
}

#[tokio::test]
async fn logs_and_route_activation_are_live_management_state() {
    let state = state().await;
    let monitor = state.controller.monitor();
    state
        .controller
        .monitor()
        .logs()
        .push_raw("time=2026-01-01T00:00:00Z level=INFO msg=\"boot\"\n");
    let app = router(state);

    let logs = app
        .clone()
        .oneshot(
            Request::post("/api/v2/rpc/tools.logs")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logs.status(), StatusCode::OK);
    let logs: Value =
        serde_json::from_slice(&to_bytes(logs.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        logs["log"][0],
        "time=2026-01-01T00:00:00Z level=INFO msg=\"boot\""
    );

    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v2/tools/logs/v2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("boot"));
    monitor.logs().push_raw("live-log\n");
    let second = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(String::from_utf8_lossy(&second).contains("live-log"));

    let refreshed = app
        .clone()
        .oneshot(
            Request::post("/api/v2/route/lists/refresh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    let activation = app
        .oneshot(
            Request::get("/api/v2/route/lists/activation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let activation: Value =
        serde_json::from_slice(&to_bytes(activation.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(activation["lastRefreshAt"].as_i64().unwrap_or_default() > 0);
}

#[tokio::test]
async fn resolver_and_route_config_use_the_same_mutation_reload_boundary() {
    let state = state().await;
    let _ = save_resolver_value(
        &state,
        json!({"id":"lan","type":"udp","host":"127.0.0.1:5353"}),
        None,
    )
    .await
    .unwrap();
    let _ = route_config_put_value(&state, json!({"directResolver":"lan","proxyResolver":"lan","resolveLocally":true,"udpProxyFqdnStrategy":"resolve"})).await.unwrap();
    let route = route_config_get_value(&state).await.unwrap();
    assert_eq!(route.0["directResolver"], "lan");
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_settings()
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, 1);
    assert_eq!(state.controller.handle().revision(), 2);
}

#[test]
fn frontend_page_query_is_camel_case_compatible() {
    let value = page(
        vec![json!({"id":"a"}), json!({"id":"b"})],
        &json!({"page":2,"pageSize":1}),
    );
    assert_eq!(value["items"][0]["id"], "b");
    assert_eq!(value["page"]["pageSize"], 1);
}

#[test]
fn list_query_filters_match_go_field_contracts() {
    assert!(node_matches_query(
        &json!({"id":"n1", "chain":[{"type":"tls"}]}),
        "tls"
    ));
    assert!(!node_matches_query(
        &json!({"id":"n1", "description":"tls"}),
        "tls"
    ));
    assert!(inbound_matches_query(
        &json!({"id":"i1", "network":{"type":"tcp"}, "protocol":{"type":"http"}}),
        "http"
    ));
    assert!(!inbound_matches_query(
        &json!({"id":"i1", "listen":"http://127.0.0.1"}),
        "http"
    ));
    assert!(resolver_matches_query(
        &json!({"id":"r1", "type":"doh", "host":"dns.example"}),
        "example"
    ));
    assert!(!resolver_matches_query(
        &json!({"id":"r1", "description":"doh"}),
        "doh"
    ));
    assert!(route_list_matches_query(
        &json!({"name":"blocklist", "preview":"ads.example"}),
        "ads"
    ));
    assert!(route_rule_matches_query(
        &json!({"name":"rule", "mode":"proxy", "tag":"work"}),
        "work"
    ));
    assert!(!route_rule_matches_query(
        &json!({"name":"rule", "comment":"proxy"}),
        "proxy"
    ));
}

#[test]
fn list_query_filters_trim_and_paginate_after_filtering() {
    let value = page_with_filter(
        vec![
            json!({"name":"direct"}),
            json!({"name":"proxy"}),
            json!({"name":"proxy backup"}),
        ],
        &json!({"query":"  PROXY ", "page":2, "pageSize":1}),
        |value, query| field_contains(value, "name", query),
    );
    assert_eq!(value["page"]["total"], 2);
    assert_eq!(value["items"][0]["name"], "proxy backup");
}

#[test]
fn core_errors_use_go_rpc_status_categories() {
    let cases = [
        (
            yuhaiin_core::ErrorKind::InvalidInput,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            yuhaiin_core::ErrorKind::Unsupported,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            yuhaiin_core::ErrorKind::NotFound,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            yuhaiin_core::ErrorKind::Conflict,
            StatusCode::CONFLICT,
            "user_referenced",
        ),
        (
            yuhaiin_core::ErrorKind::Timeout,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            yuhaiin_core::ErrorKind::Closed,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            yuhaiin_core::ErrorKind::Storage,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
    ];
    for (kind, status, code) in cases {
        let error = ApiError::from(yuhaiin_core::Error::new(kind, "contract error"));
        assert_eq!(error.status, status);
        assert_eq!(error.code, code);
        assert_eq!(error.message, "contract error");
    }
}

#[test]
fn go_typed_request_zero_values_preserve_missing_fields_but_reject_wrong_types() {
    assert_eq!(go_request_string(&json!({}), "id").unwrap(), "");
    assert_eq!(go_request_string(&json!({"id": null}), "id").unwrap(), "");
    assert_eq!(
        go_request_string(&json!({"id": "node-1"}), "id").unwrap(),
        "node-1"
    );
    assert!(go_request_string(&json!({"id": 1}), "id").is_err());

    assert_eq!(go_request_number(&json!({}), "index").unwrap(), 0);
    assert_eq!(
        go_request_number(&json!({"index": null}), "index").unwrap(),
        0
    );
    assert_eq!(go_request_number(&json!({"index": 3}), "index").unwrap(), 3);
    assert!(go_request_number(&json!({"index": -1}), "index").is_err());
    assert!(go_request_number(&json!({"index": "0"}), "index").is_err());
}

#[tokio::test]
async fn rpc_router_accepts_the_real_frontend_request_shape() {
    let state = state().await;
    let response = router(state)
            .oneshot(
                Request::post("/api/v2/rpc/nodes.post")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"api-direct","name":"API Direct","group":"test","enabled":true,"chain":[{"type":"direct","direct":{}}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["id"], "api-direct");
}

#[tokio::test]
async fn every_generated_frontend_rpc_operation_has_a_route() {
    // Keep this inventory synchronized with yuhaiin-react/src/api/generated.ts.
    // The generated operation inventory also contains connections.events;
    // its useful transport is GET/SSE, but the JSON-RPC route must still
    // remain registered so the frontend operation set has one boundary.
    const OPERATIONS: &[&str] = &[
        "backup.config.get",
        "backup.config.put",
        "backup.restore",
        "backup.run",
        "connections",
        "connections.close",
        "connections.events",
        "connections.failed_history",
        "connections.history",
        "connections.telemetry",
        "connections.total",
        "connections.traffic",
        "inbound.delete",
        "inbound.get",
        "inbound.put",
        "inbounds.config.get",
        "inbounds.config.put",
        "inbounds.get",
        "inbounds.post",
        "info",
        "node.close",
        "node.delete",
        "node.get",
        "node.latency",
        "node.put",
        "node.use",
        "nodes.active",
        "nodes.get",
        "nodes.post",
        "nodes.selected",
        "publish.delete",
        "publish.put",
        "publish.resolve",
        "publishes",
        "resolver.delete",
        "resolver.fakedns.get",
        "resolver.fakedns.put",
        "resolver.get",
        "resolver.hosts.get",
        "resolver.hosts.put",
        "resolver.put",
        "resolver.server.get",
        "resolver.server.put",
        "resolvers.get",
        "resolvers.post",
        "route.activation",
        "route.apply",
        "route.config.get",
        "route.config.put",
        "route.list.delete",
        "route.list.get",
        "route.list.put",
        "route.lists.activation",
        "route.lists.config.get",
        "route.lists.config.put",
        "route.lists.get",
        "route.lists.post",
        "route.lists.refresh",
        "route.rule.delete",
        "route.rule.get",
        "route.rule.put",
        "route.rules.block_history",
        "route.rules.get",
        "route.rules.post",
        "route.rules.priority",
        "route.rules.test",
        "route.tag.delete",
        "route.tag.put",
        "route.tags.get",
        "settings.get",
        "settings.put",
        "subscriptions.delete",
        "subscriptions.delete_preview",
        "subscriptions.get",
        "subscriptions.put",
        "subscriptions.update",
        "tools.interfaces",
        "tools.licenses",
        "tools.logs",
        "tools.logs.v2",
        "update.apply",
        "update.check",
        "update.status",
        "user.delete",
        "user.get",
        "user.put",
        "users.get",
        "users.post",
    ];
    assert_eq!(OPERATIONS.len(), 88);

    let app = router(state().await);
    for operation in OPERATIONS {
        if *operation == "connections.events" {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/api/v2/connections/events")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "generated frontend streaming operation {operation} is not routed",
            );
            continue;
        }
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v2/rpc/{operation}"))
                    .header("content-type", "application/json")
                    // Use a non-object probe so registered handlers
                    // stop at the shared request-shape check with
                    // 400. `{}` would legitimately reach 404 for Go
                    // typed detail requests whose zero-value ID is
                    // not present in the store.
                    .body(Body::from("[]"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "generated frontend operation {operation} is not routed",
        );
    }

    for (path, expected_content_type) in [
        ("/api/v2/connections/events", "text/event-stream"),
        ("/api/v2/tools/logs", "text/event-stream"),
        ("/api/v2/tools/logs/v2", "text/event-stream"),
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "SSE route {path}");
        assert_eq!(response.headers()["content-type"], expected_content_type);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(response.headers()[header::CONNECTION], "keep-alive");
    }
}

#[tokio::test]
async fn management_auth_matches_go_basic_and_eventsource_query_token() {
    let state = state().await.with_auth("alice", "secret");
    let app = router(state);

    let unauthorized = app
        .clone()
        .oneshot(Request::get("/api/v2/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let wrong = app
        .clone()
        .oneshot(
            Request::get("/api/v2/info")
                .header("authorization", "Basic YWxpY2U6d3Jvbmc=")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    let authorized = app
        .clone()
        .oneshot(
            Request::get("/api/v2/info")
                .header("authorization", format!("Basic {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let eventsource = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v2/info?token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eventsource.status(), StatusCode::OK);

    let preflight = app
        .oneshot(
            Request::options("/api/v2/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(preflight.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn connections_event_stream_starts_with_go_snapshot_event() {
    let app = router(state().await);
    let response = app
        .oneshot(
            Request::get("/api/v2/connections/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let first = String::from_utf8_lossy(&first);
    assert!(first.contains("event: connections_added"));
    assert!(first.contains(r#""connections":[]"#));
}

#[tokio::test]
async fn connections_event_stream_delivers_live_add_and_remove_events() {
    let state = state().await;
    let monitor = state.controller.monitor();
    let app = router(state);
    let response = app
        .oneshot(
            Request::get("/api/v2/connections/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("event: connections_added"));

    let flow = yuhaiin_core::flow::Flow {
        key: yuhaiin_core::flow::FlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41000".parse().unwrap(),
            destination: "127.0.0.1:443".parse().unwrap(),
        },
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.key.destination));
    yuhaiin_core::flow::FlowObserver::opened(monitor.as_ref(), flow, context);
    let added = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let added = String::from_utf8_lossy(&added);
    assert!(added.contains("event: connections_added"));
    assert!(added.contains(r#""id":"1""#));

    yuhaiin_core::flow::FlowObserver::closed(monitor.as_ref(), flow.key);
    let removed = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let removed = String::from_utf8_lossy(&removed);
    assert!(removed.contains("event: connections_removed"));
    assert!(removed.contains(r#""ids":["1"]"#));
}
