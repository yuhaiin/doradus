//! Disk-backed HostTrie tests.

use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn domain(value: &str) -> Endpoint {
    Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        DomainName::new(value).unwrap(),
        443,
    )
}

fn ip(value: &str) -> Endpoint {
    Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        value.parse::<SocketAddr>().unwrap(),
    )
}

#[test]
fn disk_index_matches_parent_and_wildcard_domains() {
    let index = HostTrie::from_patterns([
        "example.com".to_owned(),
        "*.blocked.example".to_owned(),
        "api.*.example.net".to_owned(),
    ])
    .unwrap();
    assert!(index.is_on_disk());
    assert!(index.search_parent(&domain("example.com")).is_some());
    assert!(index.search_parent(&domain("www.example.com")).is_some());
    assert!(
        index
            .search_parent(&domain("www.blocked.example"))
            .is_some()
    );
    assert!(index.search_parent(&domain("blocked.example")).is_some());
    assert!(
        index
            .search_parent(&domain("api.edge.example.net"))
            .is_some()
    );
    assert!(index.search_parent(&domain("other.net")).is_none());
    assert!(index.search(&domain("www.blocked.example")).is_some());
    assert!(index.search(&domain("blocked.example")).is_some());
    assert!(index.search(&domain("www.example.com")).is_none());
}

#[test]
fn disk_index_matches_ipv4_and_ipv6_prefixes() {
    let index =
        HostTrie::from_patterns(["192.0.2.0/24".to_owned(), "2001:db8::/32".to_owned()]).unwrap();
    assert!(index.search_parent(&ip("192.0.2.9:443")).is_some());
    assert!(index.search_parent(&ip("192.0.3.9:443")).is_none());
    assert!(index.search_parent(&ip("[2001:db8::1]:443")).is_some());
    assert!(index.search_parent(&ip("[2001:db9::1]:443")).is_none());
}

#[test]
fn disk_index_can_be_reopened_and_validates_files() {
    let dir = std::env::temp_dir().join(format!(
        "yuhaiin-trie-test-{}",
        NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let index = HostTrie::build_at(&dir, ["example.com", "203.0.113.0/24"]).unwrap();
    assert!(index.search_parent(&domain("www.example.com")).is_some());
    drop(index);
    let reopened = HostTrie::open_at(&dir).unwrap();
    assert!(reopened.search_parent(&domain("www.example.com")).is_some());
    assert!(reopened.search_parent(&ip("203.0.113.7:443")).is_some());
    drop(reopened);
    let mut corrupt = OpenOptions::new()
        .write(true)
        .open(dir.join("domains.idx"))
        .unwrap();
    corrupt.write_all(b"corrupt").unwrap();
    assert!(HostTrie::open_at(&dir).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn disk_index_validates_the_small_root_index_without_scanning_the_table() {
    let dir = std::env::temp_dir().join(format!(
        "yuhaiin-trie-root-test-{}",
        NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let index = HostTrie::build_at(&dir, ["example.com"]).unwrap();
    drop(index);
    let mut corrupt = OpenOptions::new()
        .write(true)
        .open(dir.join("domains.roots"))
        .unwrap();
    corrupt.write_all(b"corrupt").unwrap();
    assert!(HostTrie::open_at(&dir).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn memory_host_trie_keeps_incremental_api() {
    let mut index = HostTrie::new();
    index.insert("example.com", ()).unwrap();
    assert!(index.search(&domain("example.com")).is_some());
    index.remove("example.com").unwrap();
    assert!(index.search(&domain("example.com")).is_none());
    index.insert("192.0.2.0/24", ()).unwrap();
    assert!(index.search_parent(&ip("192.0.2.1:443")).is_some());
    index.remove("192.0.2.0/24").unwrap();
    assert!(index.search_parent(&ip("192.0.2.1:443")).is_none());
}

#[test]
fn disk_index_rejects_invalid_patterns() {
    assert!(HostTrie::from_patterns(["not a domain"]).is_err());
    assert!(HostTrie::from_patterns(["192.0.2.1/33"]).is_err());
    assert!(HostTrie::from_patterns(["2001:db8::1/129"]).is_err());
}

#[test]
fn disk_index_supports_incremental_mutation_by_rebuilding_bounded_files() {
    let mut index = HostTrie::from_patterns(["example.com"]).unwrap();
    assert_eq!(index.insert("new.example", ()).unwrap(), None);
    assert!(index.search(&domain("new.example")).is_some());
    assert_eq!(index.insert("NEW.EXAMPLE.", ()).unwrap(), Some(()));
    assert_eq!(index.remove("example.com").unwrap(), Some(()));
    assert_eq!(index.remove("missing.example").unwrap(), None);
    assert!(index.search(&domain("example.com")).is_none());
    assert!(index.search(&domain("new.example")).is_some());

    assert_eq!(index.insert("192.0.2.99/24", ()).unwrap(), None);
    assert!(index.search_parent(&ip("192.0.2.1:443")).is_some());
    assert_eq!(index.remove("192.0.2.0/24").unwrap(), Some(()));
    assert!(index.search_parent(&ip("192.0.2.1:443")).is_none());
}

#[test]
fn disk_index_external_sort_handles_more_than_one_sort_chunk() {
    let index = HostTrie::from_patterns(
        (0..40_000)
            .map(|index| format!("domain{index}.example.com"))
            .chain((0..10).map(|_| "domain0.example.com".to_owned())),
    )
    .unwrap();
    assert!(index.search(&domain("domain39999.example.com")).is_some());
    assert!(index.search(&domain("domain40000.example.com")).is_none());
}

#[test]
fn disk_and_memory_indexes_agree_on_supported_queries() {
    let patterns = [
        "example.com",
        "*.blocked.example",
        "198.51.100.0/24",
        "2001:db8::/32",
    ];
    let mut memory = HostTrie::new();
    for pattern in patterns {
        memory.insert(pattern, ()).unwrap();
    }
    let disk = HostTrie::from_patterns(patterns).unwrap();
    for endpoint in [
        domain("example.com"),
        domain("www.example.com"),
        domain("blocked.example"),
        domain("www.blocked.example"),
        domain("other.example"),
        ip("198.51.100.7:443"),
        ip("198.51.101.7:443"),
        ip("[2001:db8::7]:443"),
        ip("[2001:db9::7]:443"),
    ] {
        assert_eq!(
            memory.search(&endpoint).is_some(),
            disk.search(&endpoint).is_some(),
            "search mismatch for {endpoint:?}"
        );
        assert_eq!(
            memory.search_parent(&endpoint).is_some(),
            disk.search_parent(&endpoint).is_some(),
            "parent search mismatch for {endpoint:?}"
        );
    }
}

#[test]
fn cidr_keys_are_canonicalized() {
    let index = HostTrie::from_patterns(["192.0.2.99/24"]).unwrap();
    assert!(index.search_parent(&ip("192.0.2.1:443")).is_some());
    assert_eq!(
        mask_address("192.0.2.99".parse().unwrap(), 24),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))
    );
    assert_eq!(
        mask_address("2001:db8::1234".parse().unwrap(), 64),
        IpAddr::V6("2001:db8::".parse().unwrap())
    );
}
