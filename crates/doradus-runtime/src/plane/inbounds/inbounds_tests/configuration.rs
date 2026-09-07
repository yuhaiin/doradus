use super::*;

#[test]
fn inbound_transport_allowlist_matches_go_transparent_wrappers() {
    for transport in [
        "normal",
        "TLS",
        "http2",
        "websocket",
        "aead",
        "proxy",
        "HTTP_MOCK",
    ] {
        assert!(
            is_supported_inbound_transport(transport),
            "transport {transport} should use the shared listener path"
        );
    }

    for transport in ["mux", "reality", "quic", "unknown"] {
        assert!(
            !is_supported_inbound_transport(transport),
            "transport {transport} must remain explicitly deferred"
        );
    }
    assert!(is_supported_inbound_transport("tls_auto"));
}

#[test]
fn inbound_stream_wrappers_unwrap_in_go_accept_order() {
    let names = |values: &[&str]| -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    };

    // Go wraps listeners in declaration order, therefore Accept unwraps
    // the first declared stream wrapper before the later one.
    assert!(!aead_before_tls(&names(&["tls", "aead", "http2"])));
    assert!(aead_before_tls(&names(&["aead", "tls", "http2"])));
    assert!(aead_before_tls(&names(&["aead", "tls_auto", "websocket"])));
    assert!(!aead_before_tls(&names(&["websocket", "aead"])));
}
