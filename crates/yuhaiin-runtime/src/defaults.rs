//! Go-compatible defaults for a brand-new configuration database.
//!
//! These defaults are deliberately kept as typed repository records instead
//! of being mixed into the runtime fallback code.  That gives the API and the
//! listener supervisor one source of truth, while the marker makes the
//! initialization safe for users who intentionally remove every default row.

use serde_json::{Value, json};
use yuhaiin_store::{
    ConfigStore, GoInboundRecord, GoResolverRecord, GoRouteListRecord, GoRouteRuleRecord,
    GoRouteSettingsRecord,
};

use crate::Result;

const INIT_MARKER: &str = "runtime.go_defaults.v1";
const INITIALIZING: &[u8] = b"initializing";
const COMPLETE: &[u8] = b"complete";
const LAN_LIST: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.1/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/29",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "localhost",
];

/// Populate the Go default object graph exactly once for a fresh store.
///
/// A partially configured/imported store is left alone.  This is important
/// for migrations: missing one optional table must not cause the Rust runtime
/// to overwrite a user's existing inbound or route choices.  The marker is
/// written even when the store is non-empty, so deleting a configuration row
/// later remains a user action rather than an invitation to recreate it.
pub(crate) async fn ensure_go_defaults(store: &ConfigStore) -> Result<()> {
    let repository = store.repository();
    let marker = store.get_config(INIT_MARKER).await?;
    if marker.as_deref() == Some(COMPLETE) {
        return Ok(());
    }

    // A failed process can leave only part of the default graph behind.  The
    // staging marker identifies those rows as ours, so the next startup can
    // remove that incomplete attempt and retry rather than treating it as a
    // user-owned partial configuration.
    if marker.is_some() {
        clear_default_rows(&repository).await?;
    } else {
        let is_fresh = repository.list_go_inbounds().await?.is_empty()
            && repository.list_go_resolvers().await?.is_empty()
            && repository.list_go_route_settings().await?.is_empty()
            && repository.list_go_route_rules().await?.is_empty()
            && repository.list_go_route_lists().await?.is_empty();
        if !is_fresh {
            return store.put_config(INIT_MARKER, COMPLETE).await;
        }
    }

    // Mark before the first row is written.  If the process is force-stopped
    // in the middle of this sequence, the next build enters the cleanup path.
    store.put_config(INIT_MARKER, INITIALIZING).await?;
    for record in default_inbounds() {
        repository.put_go_inbound(&record).await?;
    }
    repository.put_go_resolver(&default_resolver()).await?;
    repository
        .put_go_route_settings(&default_route_settings())
        .await?;
    repository.put_go_route_list(&default_lan_list()).await?;
    repository.put_go_route_rule(&default_lan_rule()).await?;

    store.put_config(INIT_MARKER, COMPLETE).await
}

async fn clear_default_rows(repository: &yuhaiin_store::ConfigRepository) -> Result<()> {
    for id in ["mixed", "tun", "yuubinsya"] {
        repository.delete_go_inbound(id).await?;
    }
    repository.delete_go_resolver("bootstrap").await?;
    repository.delete_go_route_settings(1).await?;
    repository.delete_go_route_list("LAN").await?;
    repository.delete_go_route_rule("LAN").await?;
    Ok(())
}

fn default_inbounds() -> [GoInboundRecord; 3] {
    [
        default_mixed_inbound(),
        default_tun_inbound(),
        default_yuubinsya_inbound(),
    ]
}

fn default_mixed_inbound() -> GoInboundRecord {
    let transport = json!([{"type":"normal","normal":{}}]);
    let data = json!({
        "id": "mixed",
        "name": "mixed",
        "enabled": true,
        "network": {"type":"tcp_udp", "tcp_udp":{"host":"127.0.0.1:1080", "udp":"enabled"}},
        "transports": transport,
        "protocol": {"type":"mixed", "mixed":{"username":"", "password":""}}
    });
    inbound_record("mixed", true, "tcp_udp", "mixed", transport, data)
}

fn default_tun_inbound() -> GoInboundRecord {
    let transport = json!([]);
    let tun_name = format!("tun://{}", default_tun_name());
    let data = json!({
        "id": "tun",
        "name": "tun",
        "enabled": false,
        "network": {"type":"empty", "empty":{}},
        "transports": transport,
        "protocol": {
            "type":"tun",
            "tun": {
                "name": tun_name,
                "mtu": 9000,
                "portal":"198.18.0.1/15",
                "portalV6":"fc00::1/18",
                "skipMulticast":true,
                "driver":"gvisor",
                "routes":["198.18.0.0/15", "fc00::/18"],
                "excludes":[]
            }
        }
    });
    inbound_record("tun", false, "empty", "tun", transport, data)
}

fn default_yuubinsya_inbound() -> GoInboundRecord {
    let transport = json!([{"type":"normal","normal":{}}]);
    let data = json!({
        "id": "yuubinsya",
        "name": "yuubinsya",
        "enabled": false,
        "network": {"type":"tcp_udp", "tcp_udp":{"host":"127.0.0.1:40501", "udp":"disabled"}},
        "transports": transport,
        "protocol": {"type":"yuubinsya", "yuubinsya":{"password":"password", "udp":false}}
    });
    inbound_record("yuubinsya", false, "tcp_udp", "yuubinsya", transport, data)
}

fn inbound_record(
    id: &str,
    enabled: bool,
    network_type: &str,
    protocol_type: &str,
    transport: Value,
    data: Value,
) -> GoInboundRecord {
    GoInboundRecord {
        id: id.to_owned(),
        name: id.to_owned(),
        enabled,
        network_type: network_type.to_owned(),
        protocol_type: protocol_type.to_owned(),
        transport_types_json: serde_json::to_vec(&transport).expect("default transport JSON"),
        updated_at: 0,
        data_json: serde_json::to_vec(&data).expect("default inbound JSON"),
    }
}

fn default_resolver() -> GoResolverRecord {
    let data = json!({"id":"bootstrap", "type":"udp", "host":"8.8.8.8"});
    GoResolverRecord {
        id: "bootstrap".to_owned(),
        resolver_type: "udp".to_owned(),
        host: "8.8.8.8".to_owned(),
        updated_at: 0,
        data_json: serde_json::to_vec(&data).expect("default resolver JSON"),
    }
}

fn default_route_settings() -> GoRouteSettingsRecord {
    GoRouteSettingsRecord {
        id: 1,
        direct_resolver: "bootstrap".to_owned(),
        proxy_resolver: "bootstrap".to_owned(),
        resolve_locally: false,
        udp_proxy_fqdn: 0,
    }
}

fn default_lan_list() -> GoRouteListRecord {
    let lists = Value::Array(
        LAN_LIST
            .iter()
            .map(|value| Value::String((*value).to_owned()))
            .collect(),
    );
    let data = json!({
        "name":"LAN",
        "type":"host",
        "source":{"type":"local", "local":{"lists":lists}}
    });
    GoRouteListRecord {
        name: "LAN".to_owned(),
        list_type: "host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 0,
        data_json: serde_json::to_vec(&data).expect("default route list JSON"),
    }
}

fn default_lan_rule() -> GoRouteRuleRecord {
    let data = json!({
        "name":"LAN",
        "mode":"direct",
        "tag":"LAN",
        "rules":[{"type":"host", "host":{"list":"LAN"}}]
    });
    GoRouteRuleRecord {
        id: "LAN".to_owned(),
        name: "LAN".to_owned(),
        priority: 0,
        disabled: false,
        action_mode: "direct".to_owned(),
        match_type: "all".to_owned(),
        tag: "LAN".to_owned(),
        updated_at: 0,
        data_json: serde_json::to_vec(&data).expect("default route rule JSON"),
    }
}

fn default_tun_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "tun0"
    }
    #[cfg(target_os = "macos")]
    {
        "utun"
    }
    #[cfg(target_os = "windows")]
    {
        "yuhaiin"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "tun0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_store::ConfigStore;

    #[tokio::test]
    async fn defaults_are_valid_and_idempotent() {
        let store = ConfigStore::open_memory().await.unwrap();
        ensure_go_defaults(&store).await.unwrap();

        let repository = store.repository();
        let inbounds = repository.list_go_inbounds().await.unwrap();
        assert_eq!(inbounds.len(), 3);
        assert!(
            inbounds
                .iter()
                .any(|record| record.id == "mixed" && record.enabled)
        );
        assert!(
            inbounds
                .iter()
                .any(|record| record.id == "tun" && !record.enabled)
        );
        assert_eq!(repository.list_go_resolvers().await.unwrap().len(), 1);
        assert_eq!(repository.list_go_route_settings().await.unwrap().len(), 1);
        assert_eq!(repository.list_go_route_lists().await.unwrap().len(), 1);
        assert_eq!(repository.list_go_route_rules().await.unwrap().len(), 1);

        ensure_go_defaults(&store).await.unwrap();
        assert_eq!(repository.list_go_inbounds().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn non_empty_store_is_not_modified_and_marker_prevents_recreation() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .repository()
            .put_go_route_list(&GoRouteListRecord {
                name: "custom".to_owned(),
                list_type: "host".to_owned(),
                source_type: "local".to_owned(),
                updated_at: 0,
                data_json: br#"{"source":{"local":{"lists":["custom.test"]}}}"#.to_vec(),
            })
            .await
            .unwrap();

        ensure_go_defaults(&store).await.unwrap();
        assert!(
            store
                .repository()
                .list_go_inbounds()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.get_config(INIT_MARKER).await.unwrap().as_deref(),
            Some(COMPLETE)
        );
    }

    #[tokio::test]
    async fn interrupted_default_write_is_cleaned_up_before_retry() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .repository()
            .put_go_inbound(&default_mixed_inbound())
            .await
            .unwrap();
        store.put_config(INIT_MARKER, INITIALIZING).await.unwrap();

        ensure_go_defaults(&store).await.unwrap();
        let inbounds = store.repository().list_go_inbounds().await.unwrap();
        assert_eq!(inbounds.len(), 3);
        assert!(
            inbounds
                .iter()
                .any(|record| record.id == "mixed" && record.enabled)
        );
        assert_eq!(
            store.get_config(INIT_MARKER).await.unwrap().as_deref(),
            Some(COMPLETE)
        );
    }
}
