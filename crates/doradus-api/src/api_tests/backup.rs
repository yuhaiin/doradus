use super::*;

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
