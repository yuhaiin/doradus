use super::*;

#[tokio::test]
async fn external_web_root_serves_assets_and_react_fallback_without_hiding_api() {
    let root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("doradus")
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
async fn favicon_serves_the_doradus_brand_asset() {
    let response = router(state().await)
        .oneshot(Request::get("/favicon.svg").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "image/svg+xml"
    );
    assert_eq!(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .as_ref(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/icon.svg"
        ))
    );
}

#[tokio::test]
async fn embedded_web_serves_assets_and_react_fallback_by_default() {
    let app = router(state().await);
    let index = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    if embedded_web::asset("index.html").is_none() {
        assert_eq!(index.status(), StatusCode::NOT_FOUND);
        return;
    }

    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(
        index.headers()[axum::http::header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let index_body = to_bytes(index.into_body(), 1024 * 1024).await.unwrap();
    assert!(
        index_body
            .windows(b"<title>".len())
            .any(|window| window == b"<title>")
    );

    let fallback = app
        .oneshot(
            Request::get("/inbounds/detail")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fallback.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(fallback.into_body(), 1024 * 1024).await.unwrap(),
        index_body,
    );
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
    // Keep this inventory synchronized with doradus-react/src/api/generated.ts.
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
        "inbounds.status",
        "inbound.events",
        "inbound.retry",
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
    assert_eq!(OPERATIONS.len(), 91);

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
