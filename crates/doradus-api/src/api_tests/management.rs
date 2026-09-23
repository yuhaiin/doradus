use super::*;

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

    let flow = doradus_core::flow::Flow {
        key: doradus_core::flow::FlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41000".parse().unwrap(),
            destination: "127.0.0.1:443".parse().unwrap(),
        },
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.key.destination));
    doradus_core::flow::FlowObserver::opened(monitor.as_ref(), flow, context);
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

    doradus_core::flow::FlowObserver::closed(monitor.as_ref(), flow.key);
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
