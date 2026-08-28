//! Persistent FakeIP allocation and reverse lookup.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use doradus_core::dns::{DnsRecordType, DnsResponse, DnsServiceParam};
use doradus_core::{DomainName, Error, ErrorKind, IpSet, Result};
pub use doradus_dns::{
    FakeIpConfig, FakeIpPoolOptions, FakeIpV6Config, FakeIpView, FakeIpViewStore,
    reverse_name_to_ip,
};
use futures_util::lock::Mutex;
use serde::Deserialize;

use doradus_core::BoxFuture;
use doradus_core::dns::{AsyncDnsHandler, decode_query, encode_response};

use crate::{ConfigStore, FakeIpCursorRecord, FakeIpEntryRecord};

const NEXT_KEY: &str = "fakeip/next";
const MAP_PREFIX: &str = "fakeip/map/";
const NEXT_V6_KEY: &str = "fakeip/ipv6/next";
const MAP_V6_PREFIX: &str = "fakeip/ipv6/map/";
const IMPORT_MARKER_PREFIX: &str = "fakeip/legacy-import/";

#[path = "fakeip_legacy.rs"]
mod legacy;
#[path = "fakeip_pool_v4.rs"]
mod pool_v4;
#[path = "fakeip_pool_v6.rs"]
mod pool_v6;
#[path = "fakeip_transform.rs"]
mod transform;

pub use legacy::{
    LegacyFakeIpEntry, LegacyFakeIpExport, LegacyFakeIpSnapshot, LegacyFakeIpV6Entry,
    LegacyFakeIpV6Export, LegacyFakeIpV6Snapshot,
};
pub use pool_v4::FakeIpPool;
pub use pool_v6::FakeIpV6Pool;
pub use transform::{
    AsyncDomainResolver, FakeIpAnswerTransform, FakeIpAsyncDnsHandler,
    FakeIpDualStackAnswerTransform, FakeIpPtrTransform, FakeIpResponseTransform,
    FakeIpV6AnswerTransform,
};

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn expired_at(last_used_at: i64, now: i64, ttl_seconds: i64) -> bool {
    now >= last_used_at && now - last_used_at >= ttl_seconds
}

fn config_contains(config: FakeIpConfig, address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    value >= u32::from(config.start) && value <= u32::from(config.end)
}

fn config_contains_v6(config: FakeIpV6Config, address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    value >= u128::from(config.start) && value <= u128::from(config.end)
}

fn normalize_next_v4(next: &mut u32, config: FakeIpConfig) {
    if !config_contains(config, Ipv4Addr::from(*next)) {
        *next = u32::from(config.start);
    }
}

fn normalize_next_v6(next: &mut u128, config: FakeIpV6Config) {
    if !config_contains_v6(config, Ipv6Addr::from(*next)) {
        *next = u128::from(config.start);
    }
}

async fn load_legacy_keys(store: &ConfigStore, prefix: &str) -> Result<Vec<String>> {
    Ok(store
        .list_config(prefix)
        .await?
        .into_iter()
        .map(|(key, _)| key)
        .collect())
}

async fn load_legacy_v4(
    store: &ConfigStore,
    config: FakeIpConfig,
    prefix: &str,
    now: i64,
) -> Result<Vec<FakeIpEntryRecord>> {
    let mut entries = Vec::new();
    let mut addresses = HashMap::new();
    for (key, value) in store.list_config(MAP_PREFIX).await? {
        if value.len() != 4 {
            continue;
        }
        let Some(domain) = key.strip_prefix(MAP_PREFIX) else {
            continue;
        };
        let Ok(domain) = DomainName::new(domain) else {
            continue;
        };
        let address = Ipv4Addr::from(<[u8; 4]>::try_from(value).unwrap());
        if !config_contains(config, address) || addresses.contains_key(&address) {
            continue;
        }
        addresses.insert(address, domain.clone());
        entries.push(FakeIpEntryRecord {
            family: 4,
            prefix: prefix.to_owned(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        });
    }
    Ok(entries)
}

async fn load_legacy_v6(
    store: &ConfigStore,
    config: FakeIpV6Config,
    prefix: &str,
    now: i64,
) -> Result<Vec<FakeIpEntryRecord>> {
    let mut entries = Vec::new();
    let mut addresses = HashMap::new();
    for (key, value) in store.list_config(MAP_V6_PREFIX).await? {
        if value.len() != 16 {
            continue;
        }
        let Some(domain) = key.strip_prefix(MAP_V6_PREFIX) else {
            continue;
        };
        let Ok(domain) = DomainName::new(domain) else {
            continue;
        };
        let address = Ipv6Addr::from(<[u8; 16]>::try_from(value).unwrap());
        if !config_contains_v6(config, address) || addresses.contains_key(&address) {
            continue;
        }
        addresses.insert(address, domain.clone());
        entries.push(FakeIpEntryRecord {
            family: 6,
            prefix: prefix.to_owned(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        });
    }
    Ok(entries)
}

#[cfg(test)]
#[path = "fakeip_tests.rs"]
mod tests;
