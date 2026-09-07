use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn central_basic_user_authenticates_http_inbound_chain() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-central-http-auth");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, fixture.outbound).await;

    let user = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/users",
        Some(&json!({
            "id":"central-http-user",
            "name":"Central HTTP user",
            "enabled":true,
            "origin":"manual",
            "usage":"inbound",
            "credential":{
                "type":"basic",
                "basic":{
                    "username":"central-user",
                    "password":"central-password"
                }
            }
        })),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let user_path = format!("/api/v2/users/{user_id}");

    let good_token =
        base64::engine::general_purpose::STANDARD.encode("central-user:central-password");
    let bad_token = base64::engine::general_purpose::STANDARD.encode("central-user:wrong");
    let authority = format!("example.test:{}", fixture.target.port());
    let mut central_auth_ready = false;
    let mut last_probe_headers = Vec::new();
    for _ in 0..100 {
        let Ok((mut probe, response)) =
            http_connect_with_auth(inbound, &authority, Some(&bad_token)).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let rejected = response.starts_with("HTTP/1.1 403");
        last_probe_headers = response.into_bytes();
        let _ = probe.shutdown().await;
        if rejected {
            central_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        central_auth_ready,
        "central inbound auth snapshot did not reload; headers={:?}; logs={}",
        String::from_utf8_lossy(&last_probe_headers),
        service.diagnostics()
    );

    let (mut client, response) = http_connect_with_auth(inbound, &authority, Some(&good_token))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));

    let payload = b"central-auth-http-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "HTTP chain inbound")
        .expect("central-auth HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test")
    }));

    client.shutdown().await.unwrap();

    api_json(
        &service.client,
        &service.base_url,
        http::Method::PUT,
        &user_path,
        Some(&json!({
            "name":"Central HTTP user updated",
            "enabled":true,
            "usage":"inbound",
            "credential":{
                "type":"basic",
                "basic":{
                    "username":"central-user-v2",
                    "password":"central-password-v2"
                }
            }
        })),
    )
    .await;
    let old_token = good_token;
    let new_token =
        base64::engine::general_purpose::STANDARD.encode("central-user-v2:central-password-v2");
    let mut updated = false;
    for _ in 0..100 {
        let Ok((mut probe, response)) =
            http_connect_with_auth(inbound, &authority, Some(&old_token)).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let rejected = response.starts_with("HTTP/1.1 403");
        let _ = probe.shutdown().await;
        if rejected {
            updated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(updated, "updated central user credential did not reload");
    let (mut updated_client, response) =
        http_connect_with_auth(inbound, &authority, Some(&new_token))
            .await
            .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    updated_client
        .write_all(b"central-auth-http-updated-payload")
        .await
        .unwrap();
    let mut updated_echo = vec![0u8; b"central-auth-http-updated-payload".len()];
    updated_client.read_exact(&mut updated_echo).await.unwrap();
    assert_eq!(&updated_echo, b"central-auth-http-updated-payload");
    updated_client.shutdown().await.unwrap();

    api_json(
        &service.client,
        &service.base_url,
        http::Method::DELETE,
        &user_path,
        None,
    )
    .await;
    let mut deleted = false;
    for _ in 0..100 {
        let Ok((mut probe, response)) = http_connect_with_auth(inbound, &authority, None).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let available = response.starts_with("HTTP/1.1 200");
        let _ = probe.shutdown().await;
        if available {
            deleted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(deleted, "deleted central user auth did not reload");

    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn central_basic_user_authenticates_socks5_and_yuubinsya_inbounds() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_inbound = http_listener.local_addr().unwrap();
    drop(http_listener);
    let socks5_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_inbound = socks5_listener.local_addr().unwrap();
    drop(socks5_listener);
    let yuubinsya_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let yuubinsya_inbound = yuubinsya_listener.local_addr().unwrap();
    drop(yuubinsya_listener);

    let root = integration_dir("service-central-required-inbound-auth");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, http_inbound, fixture.outbound).await;
    add_socks5_inbound(
        &service,
        "central-auth-socks5-in",
        socks5_inbound,
        "inline-user",
        "inline-password",
    )
    .await;
    add_yuubinsya_inbound(&service, "central-auth-yuubinsya-in", yuubinsya_inbound).await;

    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/users",
        Some(&json!({
            "id":"central-required-user",
            "name":"Central required inbound user",
            "enabled":true,
            "origin":"manual",
            "usage":"inbound",
            "credential":{
                "type":"basic",
                "basic":{
                    "username":"central-user",
                    "password":"central-password"
                }
            }
        })),
    )
    .await;

    let mut socks5_auth_ready = false;
    for _ in 0..100 {
        if socks5_auth_probe(socks5_inbound, "central-user", "wrong-password")
            .await
            .is_ok_and(|reply| reply == [1, 1])
        {
            socks5_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        socks5_auth_ready,
        "central SOCKS5 auth snapshot did not reload; logs={}",
        service.diagnostics()
    );

    let mut yuubinsya_auth_ready = false;
    for _ in 0..100 {
        if yuubinsya_auth_is_rejected(
            yuubinsya_inbound,
            YUUBINSYA_PASSWORD,
            "example.test",
            fixture.target.port(),
        )
        .await
        {
            yuubinsya_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        yuubinsya_auth_ready,
        "central Yuubinsya auth snapshot did not reload; logs={}",
        service.diagnostics()
    );

    let mut socks5 = connect_socks5_with_auth(
        socks5_inbound,
        "central-user",
        "central-password",
        "example.test",
        fixture.target.port(),
    )
    .await;
    let socks5_payload = b"central-socks5-auth-payload";
    socks5.write_all(socks5_payload).await.unwrap();
    let mut socks5_echo = vec![0u8; socks5_payload.len()];
    socks5.read_exact(&mut socks5_echo).await.unwrap();
    assert_eq!(&socks5_echo, socks5_payload);

    let yuubinsya_stream = connect_loopback(yuubinsya_inbound).await;
    let mut yuubinsya = AsyncYuubinsyaTcpSession::connect(
        yuubinsya_stream,
        derive_salt(b"central-password"),
        Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.test").unwrap(),
            fixture.target.port(),
        ),
    )
    .await
    .unwrap();
    let yuubinsya_payload = b"central-yuubinsya-auth-payload";
    yuubinsya.write_all(yuubinsya_payload).await.unwrap();
    let mut yuubinsya_echo = vec![0u8; yuubinsya_payload.len()];
    yuubinsya.read_exact(&mut yuubinsya_echo).await.unwrap();
    assert_eq!(&yuubinsya_echo, yuubinsya_payload);

    let mut connections = None;
    for _ in 0..100 {
        let current = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = current["connections"].as_array().unwrap();
        if items
            .iter()
            .any(|item| item["inboundName"] == "SOCKS5 integration inbound")
            && items
                .iter()
                .any(|item| item["inboundName"] == "Yuubinsya integration inbound")
        {
            connections = Some(current);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let connections = connections.expect("both centrally authenticated inbounds must be visible");
    let items = connections["connections"].as_array().unwrap();
    for (inbound_name, inbound_address) in [
        ("SOCKS5 integration inbound", socks5_inbound),
        ("Yuubinsya integration inbound", yuubinsya_inbound),
    ] {
        let item = items
            .iter()
            .find(|item| item["inboundName"] == inbound_name)
            .unwrap_or_else(|| panic!("connection for {inbound_name} is missing"));
        assert_eq!(item["inbound"], inbound_address.to_string());
        assert_eq!(item["outbound"], fixture.outbound.to_string());
        assert_eq!(item["mode"], "proxy");
        assert!(item["matchHistory"].as_array().is_some_and(|history| {
            history
                .iter()
                .any(|entry| entry["ruleName"] == "proxy-example-test")
        }));
    }

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}
