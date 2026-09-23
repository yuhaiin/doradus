use super::*;

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
                addresses: doradus_core::IpSet {
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
