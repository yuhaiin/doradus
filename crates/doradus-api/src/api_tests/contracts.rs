use super::*;

#[test]
fn frontend_page_query_is_camel_case_compatible() {
    let value = page(
        vec![json!({"id":"a"}), json!({"id":"b"})],
        &json!({"page":2,"pageSize":1}),
    );
    assert_eq!(value["items"][0]["id"], "b");
    assert_eq!(value["page"]["pageSize"], 1);
}

#[test]
fn list_query_filters_match_go_field_contracts() {
    assert!(node_matches_query(
        &json!({"id":"n1", "chain":[{"type":"tls"}]}),
        "tls"
    ));
    assert!(!node_matches_query(
        &json!({"id":"n1", "description":"tls"}),
        "tls"
    ));
    assert!(inbound_matches_query(
        &json!({"id":"i1", "network":{"type":"tcp"}, "protocol":{"type":"http"}}),
        "http"
    ));
    assert!(!inbound_matches_query(
        &json!({"id":"i1", "listen":"http://127.0.0.1"}),
        "http"
    ));
    assert!(resolver_matches_query(
        &json!({"id":"r1", "type":"doh", "host":"dns.example"}),
        "example"
    ));
    assert!(!resolver_matches_query(
        &json!({"id":"r1", "description":"doh"}),
        "doh"
    ));
    assert!(route_list_matches_query(
        &json!({"name":"blocklist", "preview":"ads.example"}),
        "ads"
    ));
    assert!(route_rule_matches_query(
        &json!({"name":"rule", "mode":"proxy", "tag":"work"}),
        "work"
    ));
    assert!(!route_rule_matches_query(
        &json!({"name":"rule", "comment":"proxy"}),
        "proxy"
    ));
}

#[test]
fn list_query_filters_trim_and_paginate_after_filtering() {
    let value = page_with_filter(
        vec![
            json!({"name":"direct"}),
            json!({"name":"proxy"}),
            json!({"name":"proxy backup"}),
        ],
        &json!({"query":"  PROXY ", "page":2, "pageSize":1}),
        |value, query| field_contains(value, "name", query),
    );
    assert_eq!(value["page"]["total"], 2);
    assert_eq!(value["items"][0]["name"], "proxy backup");
}

#[test]
fn core_errors_use_go_rpc_status_categories() {
    let cases = [
        (
            doradus_core::ErrorKind::InvalidInput,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            doradus_core::ErrorKind::Unsupported,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            doradus_core::ErrorKind::NotFound,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            doradus_core::ErrorKind::Conflict,
            StatusCode::CONFLICT,
            "user_referenced",
        ),
        (
            doradus_core::ErrorKind::Timeout,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            doradus_core::ErrorKind::Closed,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            doradus_core::ErrorKind::Storage,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
    ];
    for (kind, status, code) in cases {
        let error = ApiError::from(doradus_core::Error::new(kind, "contract error"));
        assert_eq!(error.status, status);
        assert_eq!(error.code, code);
        assert_eq!(error.message, "contract error");
    }
}

#[test]
fn go_typed_request_zero_values_preserve_missing_fields_but_reject_wrong_types() {
    assert_eq!(go_request_string(&json!({}), "id").unwrap(), "");
    assert_eq!(go_request_string(&json!({"id": null}), "id").unwrap(), "");
    assert_eq!(
        go_request_string(&json!({"id": "node-1"}), "id").unwrap(),
        "node-1"
    );
    assert!(go_request_string(&json!({"id": 1}), "id").is_err());

    assert_eq!(go_request_number(&json!({}), "index").unwrap(), 0);
    assert_eq!(
        go_request_number(&json!({"index": null}), "index").unwrap(),
        0
    );
    assert_eq!(go_request_number(&json!({"index": 3}), "index").unwrap(), 3);
    assert!(go_request_number(&json!({"index": -1}), "index").is_err());
    assert!(go_request_number(&json!({"index": "0"}), "index").is_err());
}
