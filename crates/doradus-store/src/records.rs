//! Typed records shared by the SQLite repository and runtime compatibility
//! layers.
//!
//! Keeping these data contracts separate from connection lifecycle, schema
//! migration, and backup installation makes the store root a storage facade
//! instead of a second DTO module.

use serde::{Deserialize, Serialize};

use super::DEFAULT_NAT_IDLE_TIMEOUT_MS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyNodeRecord {
    pub id: String,
    pub kind: String,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRuleRecord {
    pub id: String,
    pub pattern: String,
    pub action: String,
    pub priority: i64,
    pub geo_country: Option<String>,
    pub resolver_policy: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolverRecord {
    pub id: String,
    pub kind: String,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfigRecord {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatConfigRecord {
    pub key: String,
    pub full_cone: bool,
    pub idle_timeout_ms: i64,
}

impl Default for NatConfigRecord {
    fn default() -> Self {
        Self {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: DEFAULT_NAT_IDLE_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxMindMetadataRecord {
    pub id: String,
    pub path: String,
    pub sha256: Vec<u8>,
    pub size: i64,
    pub updated_at: i64,
}

/// Typed persistence boundary for one FakeIP mapping. `family` is 4 or 6,
/// `prefix` is the canonical pool identity, and `ip` is stored in network
/// byte order (4 bytes for IPv4, 16 bytes for IPv6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpEntryRecord {
    pub family: i64,
    pub prefix: String,
    pub domain: String,
    pub ip: Vec<u8>,
    pub created_at: i64,
    pub last_used_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpCursorRecord {
    pub family: i64,
    pub prefix: String,
    pub cursor_ip: Vec<u8>,
    pub cursor_idx: i64,
    pub updated_at: i64,
}

/// Read-only views over the Go v6 plain-contract tables. The known columns
/// are typed for migration/runtime code, while `data_json` remains byte-for-
/// byte recoverable so fields unknown to Rust are not discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoInboundRecord {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub network_type: String,
    pub protocol_type: String,
    pub transport_types_json: Vec<u8>,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// Scalar settings preserved by Go's `settings_kv` table. The Rust runtime
/// reads known keys while leaving unknown platform/application keys in the
/// source table for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSettingsKvRecord {
    pub section: String,
    pub key: String,
    pub value_json: String,
}

/// The single-row Go `backup_settings` contract. Keep the original JSON so
/// Rust can round-trip S3 fields it does not actively use yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoBackupSettingsRecord {
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoNodeRecord {
    pub id: String,
    pub name: String,
    pub group_name: String,
    pub origin: String,
    pub enabled: bool,
    pub chain_types_json: Vec<u8>,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoNodeTagRecord {
    pub id: String,
    pub name: String,
    pub members_json: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoResolverRecord {
    pub id: String,
    pub resolver_type: String,
    pub host: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// A Go `dns_hosts` row kept as a small compatibility record. The runtime
/// can parse an IP `target` into `doradus_core::dns_hosts::HostsTable` without
/// making the store depend on a resolver implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsHostRecord {
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsSettingsRecord {
    pub id: i64,
    pub server: String,
    pub fakedns_enabled: bool,
    pub fakedns_ipv4_range: String,
    pub fakedns_ipv6_range: String,
}

/// Settings shared by every inbound owner. JSON names are the frontend
/// contract; serde aliases also accept older Rust/Go snake_case overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSettings {
    #[serde(rename = "hijackDns", alias = "hijack_dns", default = "default_true")]
    pub hijack_dns: bool,
    #[serde(
        rename = "hijackDnsFakeIp",
        alias = "hijack_dns_fakeip",
        default = "default_true"
    )]
    pub hijack_dns_fakeip: bool,
    #[serde(rename = "sniff", alias = "sniff_enabled", default = "default_true")]
    pub sniff: bool,
}

fn default_true() -> bool {
    true
}

impl Default for InboundSettings {
    fn default() -> Self {
        Self {
            hijack_dns: true,
            hijack_dns_fakeip: true,
            sniff: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsFakednsListRecord {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteSettingsRecord {
    pub id: i64,
    pub direct_resolver: String,
    pub proxy_resolver: String,
    pub resolve_locally: bool,
    /// Go stores this as an integer enum: 0=default, 1=resolve,
    /// 2=skip_resolve. Keep the numeric value until compatibility parsing.
    pub udp_proxy_fqdn: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteRuleRecord {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub disabled: bool,
    pub action_mode: String,
    pub match_type: String,
    pub tag: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteListRecord {
    pub name: String,
    pub list_type: String,
    pub source_type: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// A subscription link stored in Go's `subscriptions` table. Canonical fields
/// are exposed for validation while `data_json` preserves future fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSubscriptionLinkRecord {
    pub name: String,
    pub url: String,
    pub link_type: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// Raw Go `publishes` row. The HTTP contract is decoded at the API boundary,
/// while the original JSON is retained here for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoPublishRecord {
    pub name: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSnapshotInstallReport {
    pub source_bytes: u64,
    pub destination_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseFileReport {
    pub source_bytes: u64,
    pub destination_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSnapshotManifest {
    pub format_version: i64,
    pub tool: String,
    pub tool_version: String,
    pub source_schema_version: String,
    pub snapshot_sha256: String,
    pub snapshot_bytes: u64,
    pub fakeip_rows: i64,
    #[serde(default, deserialize_with = "deserialize_manifest_string_vec")]
    pub removed_virtual_tables: Vec<String>,
}

fn deserialize_manifest_string_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}
