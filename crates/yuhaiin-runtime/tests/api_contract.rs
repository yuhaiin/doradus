#![allow(dead_code)]

mod support;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use support::{ServiceProcess, integration_dir, seed_empty_database};

async fn request_json(
    service: &ServiceProcess,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = service
        .client
        .request(method, format!("{}{}", service.base_url, path));
    let response = match body {
        Some(body) => request.json(&body).send().await.unwrap(),
        None => request.send().await.unwrap(),
    };
    let status = response.status();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{path} returned invalid JSON: {error}: {text}"));
    (status, value)
}

async fn expect_ok(
    service: &ServiceProcess,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Value {
    let (status, value) = request_json(service, method, path, body).await;
    assert!(status.is_success(), "{path} returned {status}: {value}");
    value
}

async fn expect_empty(service: &ServiceProcess, method: Method, path: &str, body: Option<Value>) {
    let value = expect_ok(service, method, path, body).await;
    assert!(
        value.is_object(),
        "{path} must return a JSON object: {value}"
    );
}

async fn expect_sse(service: &ServiceProcess, path: &str) {
    let response = service
        .client
        .get(format!("{}{}", service.base_url, path))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "GET {path} content type"
    );
}

async fn wait_for_active_node(service: &ServiceProcess, id: &str) -> Value {
    let mut last = Value::Null;
    for _ in 0..100 {
        let active = expect_ok(&service, Method::GET, "/api/v2/nodes/active", None).await;
        last = active.clone();
        if active["items"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["id"] == id))
        {
            return active;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let logs = expect_ok(
        service,
        Method::POST,
        "/api/v2/rpc/tools.logs",
        Some(json!({})),
    )
    .await;
    let inbounds = expect_ok(
        service,
        Method::GET,
        "/api/v2/inbounds?page=1&page_size=100",
        None,
    )
    .await;
    panic!(
        "node {id:?} did not become active; last={last}; inbounds={inbounds}; logs={logs}; stderr={}",
        service.diagnostics()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_api_round_trips_frontend_contracts_in_one_process() {
    let root = integration_dir("management-api-contract");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;

    let info = expect_ok(&service, Method::GET, "/api/v2/info", None).await;
    assert!(info["version"].is_string());
    assert_eq!(info["compiler"], "rustc");

    let settings = expect_ok(&service, Method::GET, "/api/v2/settings", None).await;
    assert!(settings["ipv6"].is_boolean());
    assert!(settings["systemProxy"].is_object());
    assert_eq!(
        expect_ok(
            &service,
            Method::PUT,
            "/api/v2/settings",
            Some(json!({"ipv6":true,"advanced":{"udpBufferSize":65536},"backup":{"instanceName":"ignored"}})),
        )
        .await["backup"]["instanceName"],
        ""
    );

    let backup = expect_ok(&service, Method::GET, "/api/v2/backup/config", None).await;
    assert!(backup["s3"].is_object());
    let backup = expect_ok(
        &service,
        Method::PUT,
        "/api/v2/backup/config",
        Some(json!({"instanceName":"contract","interval":3600,"s3":{"enabled":false}})),
    )
    .await;
    assert_eq!(backup["instanceName"], "contract");

    let hosts = expect_ok(
        &service,
        Method::PUT,
        "/api/v2/resolver/hosts",
        Some(json!({"hosts":{"contract.example":"127.0.0.1"}})),
    )
    .await;
    assert_eq!(hosts["hosts"]["contract.example"], "127.0.0.1");
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/resolver/hosts", None).await["hosts"]["contract.example"],
        "127.0.0.1"
    );
    let fakedns = expect_ok(
        &service,
        Method::PUT,
        "/api/v2/resolver/fakedns",
        Some(json!({"enabled":false,"ipv4Range":"198.18.0.0/15","ipv6Range":"fc00::/18","whitelist":[],"skipCheckList":[]})),
    )
    .await;
    assert_eq!(fakedns["enabled"], false);
    let server = expect_ok(&service, Method::GET, "/api/v2/resolver/server", None).await;
    assert!(server["server"].is_string());

    let resolver = expect_ok(
        &service,
        Method::POST,
        "/api/v2/resolvers",
        Some(json!({"id":"contract-resolver","type":"system","host":""})),
    )
    .await;
    assert_eq!(resolver["id"], "contract-resolver");
    let resolver = expect_ok(
        &service,
        Method::GET,
        "/api/v2/resolvers/contract-resolver",
        None,
    )
    .await;
    assert_eq!(resolver["type"], "system");
    assert_eq!(resolver["host"], "system default");
    assert_eq!(resolver["system"], true);
    let resolvers = expect_ok(
        &service,
        Method::GET,
        "/api/v2/resolvers?page=1&page_size=100&query=contract",
        None,
    )
    .await;
    assert_eq!(resolvers["page"]["total"], 1);
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/resolvers/contract-resolver",
        None,
    )
    .await;

    let inbound = expect_ok(
        &service,
        Method::POST,
        "/api/v2/inbounds",
        Some(json!({
            "id":"contract-inbound",
            "name":"Contract inbound",
            "enabled":true,
            "network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:0","udp":"disabled"}},
            "transports":[{"type":"normal","normal":{}}],
            "protocol":{"type":"http","http":{"username":"","password":""}}
        })),
    )
    .await;
    assert_eq!(inbound["id"], "contract-inbound");
    assert_eq!(
        expect_ok(
            &service,
            Method::GET,
            "/api/v2/inbounds/contract-inbound",
            None,
        )
        .await["protocol"]["type"],
        "http"
    );
    let inbound_config = expect_ok(&service, Method::GET, "/api/v2/inbounds/config", None).await;
    assert!(inbound_config["sniff"].is_boolean());

    let node = expect_ok(
        &service,
        Method::POST,
        "/api/v2/nodes",
        Some(json!({
            "id":"contract-direct",
            "name":"Contract direct",
            "enabled":true,
            "chain":[{"type":"direct","direct":{}}]
        })),
    )
    .await;
    assert_eq!(node["origin"], "manual");
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/nodes/contract-direct", None).await["id"],
        "contract-direct"
    );
    let nodes = expect_ok(
        &service,
        Method::GET,
        "/api/v2/nodes?page=1&page_size=100&query=contract",
        None,
    )
    .await;
    assert_eq!(nodes["page"]["total"], 1);
    expect_empty(
        &service,
        Method::POST,
        "/api/v2/nodes/contract-direct/use",
        None,
    )
    .await;
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/nodes/selected", None).await["tcp"]["id"],
        "contract-direct"
    );
    let _active = wait_for_active_node(&service, "contract-direct").await;
    expect_empty(
        &service,
        Method::PUT,
        "/api/v2/inbounds/contract-inbound",
        Some(json!({
            "name":"Contract inbound updated",
            "enabled":false,
            "network":{"type":"empty","empty":{}},
            "transports":[],
            "protocol":{"type":"none","none":{}}
        })),
    )
    .await;
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/inbounds/contract-inbound",
        None,
    )
    .await;

    let user = expect_ok(
        &service,
        Method::POST,
        "/api/v2/users",
        Some(json!({
            "id":"contract-user",
            "name":"Contract user",
            "enabled":true,
            "origin":"manual",
            "usage":"0",
            "credential":{"type":"token","token":{"token":"secret"}}
        })),
    )
    .await;
    assert_eq!(user["id"], "contract-user");
    assert_eq!(user["credential"]["type"], "token");
    assert_eq!(user["credential"]["hasSecret"], true);
    expect_ok(
        &service,
        Method::PUT,
        "/api/v2/users/contract-user",
        Some(json!({"name":"Contract user updated","enabled":false,"usage":"12"})),
    )
    .await;
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/users/contract-user", None).await["enabled"],
        false
    );
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/users/contract-user",
        None,
    )
    .await;

    let publish = expect_ok(
        &service,
        Method::PUT,
        "/api/v2/publishes/contract-publish",
        Some(json!({"points":["contract-direct"],"path":"","password":"","address":"","insecure":false})),
    )
    .await;
    assert_eq!(publish, json!({}));
    let publish = expect_ok(&service, Method::GET, "/api/v2/publishes", None).await;
    assert_eq!(publish["items"][0]["name"], "contract-publish");
    let resolved = expect_ok(
        &service,
        Method::POST,
        "/api/v2/publishes/contract-publish/resolve",
        Some(json!({"password":"","path":""})),
    )
    .await;
    assert_eq!(resolved["points"][0]["id"], "contract-direct");

    let subscription = expect_ok(
        &service,
        Method::PUT,
        "/api/v2/subscriptions",
        Some(json!({"items":[{"name":"contract-link","url":"https://example.test/sub","type":"base64"}]})),
    )
    .await;
    assert_eq!(subscription, json!({}));
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/subscriptions", None).await["items"][0]["name"],
        "contract-link"
    );
    let impact = expect_ok(
        &service,
        Method::POST,
        "/api/v2/subscriptions/delete-preview",
        Some(json!({"names":["contract-link"]})),
    )
    .await;
    assert_eq!(impact, json!({"nodes":0,"users":0}));
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/subscriptions",
        Some(json!({"names":["contract-link"]})),
    )
    .await;

    let route_config = expect_ok(&service, Method::GET, "/api/v2/route/config", None).await;
    assert!(route_config["directResolver"].is_string());
    expect_ok(
        &service,
        Method::PUT,
        "/api/v2/route/config",
        Some(json!({"directResolver":"","proxyResolver":"","resolveLocally":true,"udpProxyFqdnStrategy":"resolve"})),
    )
    .await;
    let list = json!({
        "name":"contract-list",
        "type":"host",
        "source":{"type":"local","local":{"lists":["contract"]}}
    });
    expect_ok(
        &service,
        Method::POST,
        "/api/v2/route/lists",
        Some(list.clone()),
    )
    .await;
    assert_eq!(
        expect_ok(
            &service,
            Method::GET,
            "/api/v2/route/lists/contract-list",
            None
        )
        .await["name"],
        "contract-list"
    );
    let lists = expect_ok(
        &service,
        Method::GET,
        "/api/v2/route/lists?page=1&page_size=100&query=contract",
        None,
    )
    .await;
    assert_eq!(lists["page"]["total"], 1);
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/route/lists/contract-list",
        None,
    )
    .await;

    let rule = json!({"name":"contract-rule","mode":"direct","tag":"default","match":{"domain":"contract.example"}});
    expect_ok(&service, Method::POST, "/api/v2/route/rules", Some(rule)).await;
    let rule = expect_ok(
        &service,
        Method::GET,
        "/api/v2/route/rules/contract-rule/0",
        None,
    )
    .await;
    assert_eq!(rule["name"], "contract-rule");
    let test = expect_ok(
        &service,
        Method::POST,
        "/api/v2/route/rules/test",
        Some(json!({"host":"contract.example:443"})),
    )
    .await;
    assert_eq!(test["mode"], "direct");
    let rules = expect_ok(
        &service,
        Method::GET,
        "/api/v2/route/rules?page=1&page_size=100&query=contract",
        None,
    )
    .await;
    assert_eq!(rules["page"]["total"], 1);
    expect_empty(
        &service,
        Method::PUT,
        "/api/v2/route/tags/contract-tag",
        Some(json!({"type":"node","hash":"contract-direct"})),
    )
    .await;
    assert_eq!(
        expect_ok(
            &service,
            Method::GET,
            "/api/v2/route/tags?query=contract",
            None
        )
        .await["page"]["total"],
        1
    );
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/route/tags/contract-tag",
        None,
    )
    .await;
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/route/rules/contract-rule/0",
        None,
    )
    .await;
    expect_empty(&service, Method::POST, "/api/v2/route/apply", None).await;
    assert_eq!(
        expect_ok(&service, Method::GET, "/api/v2/route/activation", None).await["ruleApplyAt"],
        0
    );

    let now = OffsetDateTime::now_utc();
    let from = (now - time::Duration::hours(1)).format(&Rfc3339).unwrap();
    let to = (now + time::Duration::hours(1)).format(&Rfc3339).unwrap();
    let total = expect_ok(&service, Method::GET, "/api/v2/connections/total", None).await;
    assert!(total["upload"].is_string());
    assert!(
        expect_ok(
            &service,
            Method::GET,
            &format!("/api/v2/connections/traffic?interval=hour&from={from}&to={to}"),
            None,
        )
        .await["items"]
            .is_array()
    );
    assert!(
        expect_ok(
            &service,
            Method::GET,
            &format!("/api/v2/connections/telemetry?from={from}&to={to}&limit=6"),
            None,
        )
        .await["groups"]
            .is_array()
    );
    assert!(
        expect_ok(&service, Method::GET, "/api/v2/connections", None).await["connections"]
            .is_array()
    );
    assert!(
        expect_ok(&service, Method::GET, "/api/v2/connections/history", None,).await["items"]
            .is_array()
    );
    assert!(
        expect_ok(
            &service,
            Method::GET,
            "/api/v2/connections/failed-history",
            None,
        )
        .await["items"]
            .is_array()
    );
    expect_empty(
        &service,
        Method::POST,
        "/api/v2/connections/close",
        Some(json!({"ids":[]})),
    )
    .await;

    let interfaces = expect_ok(&service, Method::GET, "/api/v2/tools/interfaces", None).await;
    assert!(interfaces["interfaces"].is_array());
    assert!(
        expect_ok(&service, Method::GET, "/api/v2/tools/licenses", None).await["yuhaiin"]
            .is_array()
    );
    expect_sse(&service, "/api/v2/tools/logs/v2").await;
    expect_sse(&service, "/api/v2/connections/events").await;

    let (status, error) = request_json(&service, Method::GET, "/api/v2/nodes/missing", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error["error"]["code"], "not_found");

    expect_empty(
        &service,
        Method::POST,
        "/api/v2/nodes/contract-direct/close",
        None,
    )
    .await;
    expect_empty(
        &service,
        Method::DELETE,
        "/api/v2/nodes/contract-direct",
        None,
    )
    .await;

    service.shutdown().await;
}
