use super::*;

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
    let value = node_json(doradus_store::GoNodeRecord {
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
    let value = resolver_json(doradus_store::GoResolverRecord {
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

#[tokio::test]
async fn metrics_endpoint_requires_auth_and_exposes_prometheus_text() {
    let app = router(state().await.with_auth("alice", "secret"));
    let unauthorized = app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    let response = app
        .oneshot(
            Request::get("/metrics")
                .header("authorization", format!("Basic {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );

    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("# HELP doradus_build Doradus build information."));
    assert!(body.contains("# TYPE doradus_build info"));
    assert!(body.contains("doradus_build_info{version="));
}
