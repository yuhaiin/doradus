use super::*;

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

    let cache_path = doradus_runtime::route_list_cache_path(&url);
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
        include_bytes!("../../../doradus-geo/tests/fixtures/GeoLite2-Country-Test.mmdb");
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

    let unique_path = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("doradus")
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
