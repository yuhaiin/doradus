mod support;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{
    ConnectFixture, ServiceProcess, api_json, configure_http_chain, connect_loopback,
    integration_dir, reserve_loopback, seed_empty_database,
};

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        headers.push(byte[0]);
        assert!(
            headers.len() <= 64 * 1024,
            "HTTP headers exceeded the limit"
        );
    }
    headers
}

async fn assert_json_success(client: &reqwest::Client, url: &str) -> Result<(), String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("GET {url}: {error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("read {url}: {error}"))?;
    if !status.is_success() {
        return Err(format!("GET {url} returned {status}: {body}"));
    }
    serde_json::from_str::<Value>(&body)
        .map(|_| ())
        .map_err(|error| format!("GET {url} returned invalid JSON: {error}: {body}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_stats_readers_survive_flow_updates_and_restart() {
    let fixture = ConnectFixture::start().await;
    let inbound = reserve_loopback().await;
    let root = integration_dir("stats-concurrency");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;

    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, fixture.outbound).await;
    let mut client = connect_loopback(inbound).await;
    client
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                fixture.target, fixture.target
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let headers = read_headers(&mut client).await;
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let range_end = OffsetDateTime::now_utc();
    let range_start = (range_end - time::Duration::hours(1))
        .format(&Rfc3339)
        .unwrap();
    let range_end = (range_end + time::Duration::hours(1))
        .format(&Rfc3339)
        .unwrap();
    let urls = [
        format!("{}/api/v2/connections", service.base_url),
        format!("{}/api/v2/connections/total", service.base_url),
        format!(
            "{}/api/v2/connections/traffic?interval=hour&from={range_start}&to={range_end}",
            service.base_url
        ),
        format!(
            "{}/api/v2/connections/telemetry?from={range_start}&to={range_end}&limit=8",
            service.base_url
        ),
        format!("{}/api/v2/connections/history", service.base_url),
        format!("{}/api/v2/connections/failed-history", service.base_url),
    ];

    let mut readers = Vec::new();
    for reader_id in 0..8 {
        let urls = urls.clone();
        readers.push(tokio::spawn(async move {
            let http = reqwest::Client::new();
            for round in 0..40 {
                let url = &urls[(reader_id + round) % urls.len()];
                assert_json_success(&http, url).await?;
            }
            Ok::<(), String>(())
        }));
    }

    let payload = vec![b's'; 16 * 1024];
    for _ in 0..64 {
        client.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }
    drop(client);

    for reader in readers {
        reader.await.unwrap().unwrap();
    }

    service.shutdown().await;
    let restarted = ServiceProcess::start(&database).await;
    let total = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert!(total["upload"].as_str().is_some_and(|value| value != "0"));
    let history = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/history",
        None,
    )
    .await;
    assert!(
        history["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    restarted.shutdown().await;
    fixture.shutdown().await;
}
