use super::*;

pub(super) async fn wait_for_named_connection(
    service: &support::ServiceProcess,
    inbound_name: &str,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..500 {
        let current = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        last = current.clone();
        if current["connections"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["inboundName"] == inbound_name))
        {
            return current;
        }
        // The protocol UDP fixtures deliberately close their one-shot
        // UDP-over-stream session after echoing the packet. The runtime moves
        // that flow to history, so an active-only wait would race the normal
        // close path and report a false failure.
        let history = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections/history",
            None,
        )
        .await;
        if let Some(connection) = history["items"].as_array().and_then(|items| {
            items.iter().find_map(|item| {
                (item["connection"]["inboundName"] == inbound_name)
                    .then(|| item["connection"].clone())
            })
        }) {
            return json!({"connections": [connection]});
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let history = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        "/api/v2/connections/history",
        None,
    )
    .await;
    let total = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    panic!(
        "connection {inbound_name:?} did not become visible; last={last}; history={history}; total={total}; diagnostics={}",
        service.diagnostics()
    );
}
