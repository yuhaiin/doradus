use super::*;
use axum::middleware;
use axum::routing::{get, post, put};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

pub(super) fn build(state: ApiState) -> Router {
    let auth = state.auth.clone();
    let web_root = state.web_root.clone();
    let router = Router::new()
        .route("/health", get(health))
        .route("/api/v2/info", get(info))
        .route("/api/v2/update/check", post(update_check))
        .route("/api/v2/update/apply", post(update_apply))
        .route("/api/v2/update/status", get(update_status))
        .route("/api/v2/settings", get(settings_get).put(settings_put))
        .route(
            "/api/v2/backup/config",
            get(backup_config_get).put(backup_config_put),
        )
        .route("/api/v2/backup/run", post(backup_run))
        .route("/api/v2/backup/restore", post(backup_restore))
        .route("/api/v2/tools/logs", get(tools_logs))
        .route("/api/v2/nodes", get(nodes_get).post(nodes_post))
        .route("/api/v2/nodes/selected", get(nodes_selected))
        .route("/api/v2/nodes/active", get(nodes_active))
        .route(
            "/api/v2/nodes/{id}",
            get(node_get).put(node_put).delete(node_delete),
        )
        .route("/api/v2/nodes/{id}/use", post(node_use))
        .route("/api/v2/nodes/{id}/latency", post(node_latency))
        .route("/api/v2/nodes/{id}/close", post(node_close))
        .route("/api/v2/inbounds", get(inbounds_get).post(inbounds_post))
        .route("/api/v2/inbounds/status", get(inbounds_status))
        .route("/api/v2/inbounds/{id}/events", get(inbound_events))
        .route("/api/v2/inbounds/{id}/retry", post(inbound_retry))
        .route(
            "/api/v2/inbounds/{id}",
            get(inbound_get).put(inbound_put).delete(inbound_delete),
        )
        .route("/api/v2/resolvers", get(resolvers_get).post(resolvers_post))
        .route(
            "/api/v2/resolvers/{id}",
            get(resolver_get).put(resolver_put).delete(resolver_delete),
        )
        .route("/api/v2/connections", get(connections_get))
        .route("/api/v2/connections/total", get(connections_total))
        .route("/api/v2/connections/traffic", get(connections_traffic))
        .route("/api/v2/connections/telemetry", get(connections_telemetry))
        .route("/api/v2/connections/events", get(connections_events))
        .route("/api/v2/connections/close", post(connections_close))
        .route(
            "/api/v2/connections/failed-history",
            get(connections_failed_history),
        )
        .route("/api/v2/connections/history", get(connections_history))
        .route("/api/v2/tools/interfaces", get(tools_interfaces))
        .route("/api/v2/tools/licenses", get(tools_licenses))
        .route("/api/v2/tools/logs/v2", get(tools_logs_v2))
        .route("/debug/pprof/", get(pprof_index))
        .route("/debug/pprof/profile", get(pprof_profile))
        .route(
            "/api/v2/subscriptions",
            get(subscriptions_get)
                .put(subscriptions_put)
                .delete(subscriptions_delete),
        )
        .route(
            "/api/v2/subscriptions/delete-preview",
            post(subscriptions_delete_preview),
        )
        .route("/api/v2/subscriptions/update", post(subscriptions_update))
        .route("/api/v2/publishes", get(publishes))
        .route(
            "/api/v2/publishes/{name}",
            put(publish_put).delete(publish_delete),
        )
        .route("/api/v2/publishes/{name}/resolve", post(publish_resolve))
        .route(
            "/api/v2/inbounds/config",
            get(inbounds_config_get).put(inbounds_config_put),
        )
        .route("/api/v2/users", get(users_get).post(users_post))
        .route(
            "/api/v2/users/{id}",
            get(user_get).put(user_put).delete(user_delete),
        )
        .route(
            "/api/v2/route/config",
            get(route_config_get).put(route_config_put),
        )
        .route(
            "/api/v2/route/lists",
            get(route_lists_get).post(route_lists_post),
        )
        .route(
            "/api/v2/route/lists/{id}",
            get(route_list_get)
                .put(route_list_put)
                .delete(route_list_delete),
        )
        .route(
            "/api/v2/route/lists/config",
            get(route_lists_config_get).put(route_lists_config_put),
        )
        .route("/api/v2/route/lists/refresh", post(route_lists_refresh))
        .route(
            "/api/v2/route/lists/activation",
            get(route_lists_activation),
        )
        .route(
            "/api/v2/route/rules",
            get(route_rules_get).post(route_rules_post),
        )
        .route(
            "/api/v2/route/rules/{name}/{index}",
            get(route_rule_get)
                .put(route_rule_put)
                .delete(route_rule_delete),
        )
        .route("/api/v2/route/rules/priority", post(route_rules_priority))
        .route("/api/v2/route/rules/test", post(route_rules_test))
        .route(
            "/api/v2/route/rules/block-history",
            get(route_rules_block_history),
        )
        .route("/api/v2/route/tags", get(tags_get))
        .route("/api/v2/route/tags/{tag}", put(tag_put).delete(tag_delete))
        .route("/api/v2/route/apply", post(route_apply))
        .route("/api/v2/route/activation", get(route_activation))
        .route("/api/v2/resolver/hosts", get(hosts_get).put(hosts_put))
        .route(
            "/api/v2/resolver/fakedns",
            get(fakedns_get).put(fakedns_put),
        )
        .route(
            "/api/v2/resolver/server",
            get(resolver_server_get).put(resolver_server_put),
        )
        .route("/api/v2/rpc/{operation}", post(rpc))
        .layer(CorsLayer::very_permissive())
        .layer(middleware::from_fn(move |request, next| {
            let auth = auth.clone();
            async move { authenticate(auth, request, next).await }
        }));
    #[cfg(all(not(windows), not(target_os = "android")))]
    let router = router
        .route("/debug/pprof/heap", get(pprof_heap))
        .route("/debug/pprof/allocs", get(pprof_heap));
    let router = router.with_state(state);
    if let Some(root) = web_root {
        let index = root.join("index.html");
        router.fallback_service(ServeDir::new(root).fallback(ServeFile::new(index)))
    } else {
        router.fallback(embedded_web_fallback)
    }
}

async fn embedded_web_fallback(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let asset = embedded_web::asset(path).or_else(|| embedded_web::asset("index.html"));
    match asset {
        Some((bytes, content_type)) => (
            [(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(content_type),
            )],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
