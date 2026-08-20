use super::*;
use std::future::Future;
use std::path::PathBuf;
use std::task::{Context, Poll, Waker};
use yuhaiin_core::dns::DnsServiceBinding;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn config() -> FakeIpConfig {
    FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 3)).unwrap()
}

fn v6_config() -> FakeIpV6Config {
    FakeIpV6Config::new("fc00::1".parse().unwrap(), "fc00::3".parse().unwrap()).unwrap()
}

fn test_database_path() -> PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .expect("a cache directory is required for the persistence test");
    let directory = cache.join("yuhaiin-rust-check");
    std::fs::create_dir_all(&directory).unwrap();
    directory.join(format!("fakeip-{}.db", std::process::id()))
}

fn remove_test_database_artifacts(path: &std::path::Path) {
    for suffix in [
        "",
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-gate",
        "-fsqlite-ns-use",
        "-yuhaiin-write-lock",
    ] {
        let target = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        let _ = std::fs::remove_file(target);
    }
}

#[test]
fn allocation_is_stable_and_reversible() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open(store, config())).unwrap();
    let domain = DomainName::new("example.com").unwrap();
    let first = block_on(pool.allocate(domain.clone())).unwrap();
    assert_eq!(block_on(pool.allocate(domain.clone())).unwrap(), first);
    assert_eq!(block_on(pool.lookup_domain(first)), Some(domain.clone()));
    assert_eq!(block_on(pool.lookup_ip(&domain)), Some(first));
    assert!(pool.contains(first));
    assert_eq!(block_on(pool.len()), 1);
    assert!(block_on(pool.release(&domain)).unwrap());
    assert_eq!(block_on(pool.lookup_domain(first)), None);
}

#[test]
fn randomized_cursor_release_cycles_keep_forward_and_reverse_indexes_consistent() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let config =
        FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 32)).unwrap();
    let pool = block_on(FakeIpPool::open(store, config)).unwrap();
    let domains: Vec<_> = (0..48)
        .map(|index| DomainName::new(&format!("host-{index}.example.com")).unwrap())
        .collect();
    let mut active = HashMap::new();
    let mut state = 0x517c_c1b7_u32;

    for step in 0..1024usize {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let domain = domains[(state as usize) % domains.len()].clone();
        if active.contains_key(&domain) && step % 3 == 0 {
            assert!(block_on(pool.release(&domain)).unwrap());
            active.remove(&domain);
        } else if !active.contains_key(&domain) {
            if active.len() == 32 {
                let release = active.keys().next().cloned().unwrap();
                assert!(block_on(pool.release(&release)).unwrap());
                active.remove(&release);
            }
            let address = block_on(pool.allocate(domain.clone())).unwrap();
            assert!(pool.contains(address));
            assert!(active.insert(domain, address).is_none());
        }

        assert_eq!(block_on(pool.len()), active.len());
        for (domain, address) in &active {
            assert_eq!(block_on(pool.lookup_ip(domain)), Some(*address));
            assert_eq!(block_on(pool.lookup_domain(*address)), Some(domain.clone()));
        }
        let view = block_on(pool.snapshot());
        for (domain, address) in &active {
            assert_eq!(view.lookup_domain(*address), Some(domain.clone()));
        }
    }
}

#[test]
fn reopen_ignores_duplicate_address_without_a_reverse_ghost() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.put_config(
        "fakeip/map/duplicate.example",
        &Ipv4Addr::new(198, 18, 0, 1).octets(),
    ))
    .unwrap();
    block_on(store.put_config(
        "fakeip/map/other.example",
        &Ipv4Addr::new(198, 18, 0, 1).octets(),
    ))
    .unwrap();

    let pool = block_on(FakeIpPool::open(store, config())).unwrap();
    let duplicate = DomainName::new("duplicate.example").unwrap();
    let other = DomainName::new("other.example").unwrap();
    assert_eq!(
        block_on(pool.lookup_ip(&duplicate)),
        Some(Ipv4Addr::new(198, 18, 0, 1))
    );
    assert_eq!(block_on(pool.lookup_ip(&other)), None);
    assert_eq!(
        block_on(pool.lookup_domain(Ipv4Addr::new(198, 18, 0, 1))),
        Some(duplicate)
    );
    assert_eq!(block_on(pool.len()), 1);
}

#[test]
fn release_is_persisted_before_reopen_and_does_not_leave_reverse_mapping() {
    let path = {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap()
            .join("yuhaiin-rust-check");
        std::fs::create_dir_all(&cache).unwrap();
        cache.join(format!(
            "fakeip-release-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    };
    let domain = DomainName::new("release.example.com").unwrap();
    let address;
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open(store, config())).unwrap();
        address = block_on(pool.allocate(domain.clone())).unwrap();
        assert!(block_on(pool.release(&domain)).unwrap());
        assert_eq!(block_on(pool.lookup_domain(address)), None);
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open(store, config())).unwrap();
        assert_eq!(block_on(pool.lookup_ip(&domain)), None);
        assert_eq!(block_on(pool.lookup_domain(address)), None);
    }
    let _ = std::fs::remove_file(&path);
    for suffix in ["-journal", "-wal", "-shm", "-wal-fec"] {
        let artifact = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(artifact);
    }
}

#[test]
fn pool_exhaustion_and_persistence_are_explicit() {
    let path = test_database_path();
    let base = unix_now();
    let domain_a = DomainName::new("a.example.com").unwrap();
    let domain_b = DomainName::new("b.example.com").unwrap();
    let domain_c = DomainName::new("c.example.com").unwrap();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open(store, config())).unwrap();
        assert_eq!(
            block_on(pool.allocate_at(domain_a.clone(), base)).unwrap(),
            Ipv4Addr::new(198, 18, 0, 1)
        );
        assert_eq!(
            block_on(pool.allocate_at(domain_b.clone(), base + 1)).unwrap(),
            Ipv4Addr::new(198, 18, 0, 2)
        );
        assert_eq!(
            block_on(pool.allocate_at(domain_c.clone(), base + 2)).unwrap(),
            Ipv4Addr::new(198, 18, 0, 3)
        );
        let domain_d = DomainName::new("d.example.com").unwrap();
        assert_eq!(
            block_on(pool.allocate_at(domain_d.clone(), base + 3)).unwrap(),
            Ipv4Addr::new(198, 18, 0, 1)
        );
        assert_eq!(block_on(pool.lookup_ip(&domain_a)), None);
        assert_eq!(
            block_on(pool.lookup_ip(&domain_d)),
            Some(Ipv4Addr::new(198, 18, 0, 1))
        );
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open(store, config())).unwrap();
        assert_eq!(
            block_on(pool.lookup_ip(&domain_b)),
            Some(Ipv4Addr::new(198, 18, 0, 2))
        );
        assert_eq!(block_on(pool.len()), 3);
    }
    let _ = std::fs::remove_file(&path);
    for suffix in ["-journal", "-wal", "-shm", "-wal-fec"] {
        let artifact = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(artifact);
    }
}

#[test]
fn typed_fakeip_schema_persists_cursor_and_mapping_atomically() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open_with_prefix(
        store,
        config(),
        "198.18.0.0/15",
        FakeIpPoolOptions::new(3, 600).unwrap(),
    ))
    .unwrap();
    let domain = DomainName::new("typed.example.com").unwrap();
    let now = unix_now();
    let address = block_on(pool.allocate_at(domain.clone(), now)).unwrap();
    let entries = block_on(pool.store.list_fakeip_entries(4, "198.18.0.0/15")).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].domain, domain.to_string());
    assert_eq!(entries[0].ip, address.octets());
    assert_eq!(entries[0].created_at, now);
    let cursor = block_on(pool.store.get_fakeip_cursor(4, "198.18.0.0/15"))
        .unwrap()
        .unwrap();
    assert_eq!(cursor.cursor_ip.len(), 4);
    assert_eq!(cursor.updated_at, now);
}

#[test]
fn ttl_capacity_and_lru_reuse_bound_long_running_pool() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let options = FakeIpPoolOptions::new(2, 10)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let pool = block_on(FakeIpPool::open_with_options(store, config(), options)).unwrap();
    let first = DomainName::new("first.example.com").unwrap();
    let second = DomainName::new("second.example.com").unwrap();
    let third = DomainName::new("third.example.com").unwrap();
    let base = unix_now();
    let first_ip = block_on(pool.allocate_at(first.clone(), base)).unwrap();
    let second_ip = block_on(pool.allocate_at(second.clone(), base + 1)).unwrap();
    assert_eq!(
        block_on(pool.allocate_at(first.clone(), base + 2)),
        Ok(first_ip)
    );

    // The pool is at capacity, so the older live mapping is reused even
    // though another address is free. This keeps memory and SQLite rows
    // bounded for long-running DNS traffic.
    let third_ip = block_on(pool.allocate_at(third.clone(), base + 3)).unwrap();
    assert_eq!(third_ip, second_ip);
    assert_eq!(block_on(pool.lookup_ip(&second)), None);
    assert_eq!(block_on(pool.lookup_ip(&third)), Some(second_ip));

    // After the TTL, a hit is no longer allowed to preserve the mapping;
    // the next allocation gets a fresh last-used timestamp.
    block_on(pool.allocate_at(first.clone(), base + 5)).unwrap();
    let refreshed = block_on(pool.allocate_at(third.clone(), base + 14)).unwrap();
    assert_ne!(refreshed, third_ip);
    assert_eq!(block_on(pool.len()), 2);
}

#[test]
fn delayed_touch_flush_persists_without_per_query_wal_growth() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let options = FakeIpPoolOptions::new(3, 1_000)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let pool = block_on(FakeIpPool::open_with_options(store, config(), options)).unwrap();
    let domain = DomainName::new("touch.example.com").unwrap();
    let base = unix_now();
    block_on(pool.allocate_at(domain.clone(), base)).unwrap();
    block_on(pool.allocate_at(domain.clone(), base + 10)).unwrap();
    let before = block_on(pool.store.list_fakeip_entries(4, &pool.prefix)).unwrap();
    assert_eq!(before[0].last_used_at, base);
    assert_eq!(block_on(pool.flush_touches()).unwrap(), 1);
    let after = block_on(pool.store.list_fakeip_entries(4, &pool.prefix)).unwrap();
    assert_eq!(after[0].last_used_at, base + 10);
}

#[test]
fn startup_reclaims_expired_typed_rows_before_exposing_reverse_view() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-expiry-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let domain = DomainName::new("expired.example.com").unwrap();
    let config = config();
    let options = FakeIpPoolOptions::new(3, 10).unwrap();
    let old = unix_now().saturating_sub(100);
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_options(store, config, options)).unwrap();
        block_on(pool.allocate_at(domain.clone(), old)).unwrap();
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_options(
            store.clone(),
            config,
            options,
        ))
        .unwrap();
        assert_eq!(block_on(pool.lookup_ip(&domain)), None);
        assert!(
            block_on(store.list_fakeip_entries(4, &pool.prefix))
                .unwrap()
                .is_empty()
        );
    }
    remove_test_database_artifacts(&path);
}

#[test]
fn deterministic_touch_soak_keeps_one_mapping_and_bounded_file_state() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-soak-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let domain = DomainName::new("soak.example.com").unwrap();
    let options = FakeIpPoolOptions::new(3, 1_000_000)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let base = unix_now();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_options(store, config(), options)).unwrap();
        let address = block_on(pool.allocate_at(domain.clone(), base)).unwrap();
        for second in 1..=10_000i64 {
            assert_eq!(
                block_on(pool.allocate_at(domain.clone(), base + second)),
                Ok(address)
            );
        }
        assert_eq!(block_on(pool.flush_touches()).unwrap(), 1);
    }
    let database_bytes = std::fs::metadata(&path).unwrap().len();
    let wal_bytes = std::fs::metadata(format!("{}-wal", path.display()))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        database_bytes + wal_bytes < 16 * 1024 * 1024,
        "touch soak grew unexpectedly: db={database_bytes} wal={wal_bytes}"
    );
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let rows = block_on(store.list_fakeip_entries(4, &config().range_prefix())).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].last_used_at, base + 10_000);
    remove_test_database_artifacts(&path);
}

#[test]
fn allocate_release_soak_keeps_persistent_state_bounded() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-allocate-release-soak-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let config =
        FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 64)).unwrap();
    let options = FakeIpPoolOptions::new(8, 1_000_000)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let base = unix_now();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_options(store, config, options)).unwrap();
        for index in 0..4_096i64 {
            let domain = DomainName::new(&format!("cycle-{index}.example.com")).unwrap();
            let address = block_on(pool.allocate_at(domain.clone(), base + index)).unwrap();
            assert_eq!(block_on(pool.lookup_domain(address)), Some(domain.clone()));
            assert!(block_on(pool.release(&domain)).unwrap());
            assert_eq!(block_on(pool.lookup_domain(address)), None);
        }
        assert_eq!(block_on(pool.len()), 0);
    }

    let database_bytes = std::fs::metadata(&path).unwrap().len();
    let wal_bytes = std::fs::metadata(format!("{}-wal", path.display()))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        database_bytes + wal_bytes < 64 * 1024 * 1024,
        "allocate/release soak grew unexpectedly: db={database_bytes} wal={wal_bytes}"
    );
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_options(store, config, options)).unwrap();
        assert_eq!(block_on(pool.len()), 0);
        assert!(
            block_on(pool.store.list_fakeip_entries(4, &pool.prefix))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(pool.store.get_fakeip_cursor(4, &pool.prefix))
                .unwrap()
                .is_some()
        );
    }
    remove_test_database_artifacts(&path);
}

#[test]
fn dual_stack_allocate_release_soak_keeps_family_namespaces_independent() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-dual-stack-soak-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let v4_config = config();
    let v6_config = v6_config();
    let options = FakeIpPoolOptions::new(3, 1_000_000)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let base = unix_now();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let ipv4 = block_on(FakeIpPool::open_with_options(
            store.clone(),
            v4_config,
            options,
        ))
        .unwrap();
        let ipv6 = block_on(FakeIpV6Pool::open_with_options(store, v6_config, options)).unwrap();

        for index in 0..1_024i64 {
            let domain = DomainName::new(&format!("dual-{index}.example.com")).unwrap();
            let v4 = block_on(ipv4.allocate_at(domain.clone(), base + index)).unwrap();
            let v6 = block_on(ipv6.allocate_at(domain.clone(), base + index)).unwrap();
            assert_eq!(block_on(ipv4.lookup_ip(&domain)), Some(v4));
            assert_eq!(block_on(ipv6.lookup_ip(&domain)), Some(v6));
            assert_eq!(block_on(ipv4.lookup_domain(v4)), Some(domain.clone()));
            assert_eq!(block_on(ipv6.lookup_domain(v6)), Some(domain.clone()));
            assert!(block_on(ipv4.release(&domain)).unwrap());
            assert!(block_on(ipv6.release(&domain)).unwrap());
            assert_eq!(block_on(ipv4.lookup_ip(&domain)), None);
            assert_eq!(block_on(ipv6.lookup_ip(&domain)), None);
        }

        assert_eq!(block_on(ipv4.len()), 0);
        assert_eq!(block_on(ipv6.len()), 0);
    }

    let database_bytes = std::fs::metadata(&path).unwrap().len();
    let wal_bytes = std::fs::metadata(format!("{}-wal", path.display()))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        database_bytes + wal_bytes < 64 * 1024 * 1024,
        "dual-stack allocate/release soak grew unexpectedly: db={database_bytes} wal={wal_bytes}"
    );

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let ipv4 = block_on(FakeIpPool::open_with_options(
        store.clone(),
        v4_config,
        options,
    ))
    .unwrap();
    let ipv6 = block_on(FakeIpV6Pool::open_with_options(
        store.clone(),
        v6_config,
        options,
    ))
    .unwrap();
    assert_eq!(block_on(ipv4.len()), 0);
    assert_eq!(block_on(ipv6.len()), 0);
    assert!(
        block_on(store.get_fakeip_cursor(4, &v4_config.range_prefix()))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get_fakeip_cursor(6, &v6_config.range_prefix()))
            .unwrap()
            .is_some()
    );
    remove_test_database_artifacts(&path);
}

#[test]
#[ignore = "long dual-stack FakeIP persistence soak; run explicitly"]
fn long_dual_stack_allocate_release_reopen_soak_keeps_state_bounded() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-long-dual-stack-soak-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let v4_config = config();
    let v6_config = v6_config();
    let options = FakeIpPoolOptions::new(3, 1_000_000)
        .unwrap()
        .with_touch_interval(300)
        .unwrap();
    let base = unix_now();

    for chunk in 0..16i64 {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let ipv4 = block_on(FakeIpPool::open_with_options(
            store.clone(),
            v4_config,
            options,
        ))
        .unwrap();
        let ipv6 = block_on(FakeIpV6Pool::open_with_options(
            store.clone(),
            v6_config,
            options,
        ))
        .unwrap();

        for offset in 0..512i64 {
            let index = chunk * 512 + offset;
            let domain = DomainName::new(&format!("long-dual-{index}.example.com")).unwrap();
            let v4 = block_on(ipv4.allocate_at(domain.clone(), base + index)).unwrap();
            let v6 = block_on(ipv6.allocate_at(domain.clone(), base + index)).unwrap();
            assert_eq!(block_on(ipv4.lookup_domain(v4)), Some(domain.clone()));
            assert_eq!(block_on(ipv6.lookup_domain(v6)), Some(domain.clone()));
            assert!(block_on(ipv4.release(&domain)).unwrap());
            assert!(block_on(ipv6.release(&domain)).unwrap());
            assert_eq!(block_on(ipv4.lookup_ip(&domain)), None);
            assert_eq!(block_on(ipv6.lookup_ip(&domain)), None);
        }

        assert_eq!(block_on(ipv4.len()), 0);
        assert_eq!(block_on(ipv6.len()), 0);
    }

    let database_bytes = std::fs::metadata(&path).unwrap().len();
    let wal_bytes = std::fs::metadata(format!("{}-wal", path.display()))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        database_bytes + wal_bytes < 128 * 1024 * 1024,
        "long dual-stack soak grew unexpectedly: db={database_bytes} wal={wal_bytes}"
    );

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let ipv4 = block_on(FakeIpPool::open_with_options(
        store.clone(),
        v4_config,
        options,
    ))
    .unwrap();
    let ipv6 = block_on(FakeIpV6Pool::open_with_options(
        store.clone(),
        v6_config,
        options,
    ))
    .unwrap();
    assert_eq!(block_on(ipv4.len()), 0);
    assert_eq!(block_on(ipv6.len()), 0);
    assert!(
        block_on(store.get_fakeip_cursor(4, &v4_config.range_prefix()))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get_fakeip_cursor(6, &v6_config.range_prefix()))
            .unwrap()
            .is_some()
    );
    remove_test_database_artifacts(&path);
}

#[test]
fn production_shaped_fakeip_rows_are_loaded_by_prefix_and_family() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-production-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    {
        let connection = crate::sqlite::Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
    }
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let options = FakeIpPoolOptions::new(3, i64::MAX / 4).unwrap();
    let pool = block_on(FakeIpPool::open_with_prefix(
        store,
        FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 3)).unwrap(),
        "198.18.0.0/15",
        options,
    ))
    .unwrap();
    let domain = DomainName::new("legacy.example").unwrap();
    assert_eq!(
        block_on(pool.lookup_ip(&domain)),
        Some(Ipv4Addr::new(198, 18, 0, 1))
    );
    assert_eq!(
        block_on(pool.lookup_domain(Ipv4Addr::new(198, 18, 0, 1))),
        Some(domain)
    );
    let v6_pool = block_on(FakeIpV6Pool::open_with_prefix(
        pool.store.clone(),
        v6_config(),
        "fc00::/18",
        options,
    ))
    .unwrap();
    let domain_v6 = DomainName::new("legacy6.example").unwrap();
    let address_v6 = "fc00::1".parse::<Ipv6Addr>().unwrap();
    assert_eq!(block_on(v6_pool.lookup_ip(&domain_v6)), Some(address_v6));
    assert_eq!(block_on(v6_pool.lookup_domain(address_v6)), Some(domain_v6));
    assert_eq!(
        block_on(v6_pool.allocate(DomainName::new("new6-production.example").unwrap())).unwrap(),
        "fc00::2".parse::<Ipv6Addr>().unwrap()
    );
    let _ = std::fs::remove_file(&path);
    for suffix in [
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-gate",
        "-fsqlite-ns-use",
        "-yuhaiin-write-lock",
    ] {
        let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
    }
}

#[test]
fn v6_edge_snapshot_reclaims_expired_rows_and_preserves_dual_cursors() {
    let path = test_database_path().with_file_name(format!(
        "fakeip-v6-edge-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    {
        let connection = crate::sqlite::Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../tests/fixtures/go_sqlite_v6_fakeip_edge_snapshot.sql"
            ))
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let options = FakeIpPoolOptions::new(3, 10).unwrap();
    let ipv4 = block_on(FakeIpPool::open_with_prefix(
        store.clone(),
        config(),
        "198.18.0.0/15",
        options,
    ))
    .unwrap();
    let ipv6 = block_on(FakeIpV6Pool::open_with_prefix(
        store.clone(),
        v6_config(),
        "fc00::/18",
        options,
    ))
    .unwrap();

    assert_eq!(block_on(ipv4.len()), 0);
    assert_eq!(block_on(ipv6.len()), 0);
    assert_eq!(
        block_on(ipv4.allocate(DomainName::new("after-expiry-v4.example").unwrap())).unwrap(),
        Ipv4Addr::new(198, 18, 0, 2)
    );
    assert_eq!(
        block_on(ipv6.allocate(DomainName::new("after-expiry-v6.example").unwrap())).unwrap(),
        "fc00::2".parse::<Ipv6Addr>().unwrap()
    );
    assert!(
        block_on(store.get_fakeip_cursor(4, "198.18.0.0/15"))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get_fakeip_cursor(6, "fc00::/18"))
            .unwrap()
            .is_some()
    );
    remove_test_database_artifacts(&path);
}

#[test]
fn legacy_import_is_atomic_and_idempotent() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open(store, config())).unwrap();
    let domain = DomainName::new("legacy.example.com").unwrap();
    let snapshot = LegacyFakeIpSnapshot {
        entries: vec![LegacyFakeIpEntry {
            domain: domain.clone(),
            address: Ipv4Addr::new(198, 18, 0, 2),
        }],
        next: Some(Ipv4Addr::new(198, 18, 0, 3)),
    };
    assert!(block_on(pool.import_legacy("pebble-v1", snapshot.clone())).unwrap());
    assert_eq!(
        block_on(pool.lookup_ip(&domain)),
        Some(Ipv4Addr::new(198, 18, 0, 2))
    );
    assert!(!block_on(pool.import_legacy("pebble-v1", snapshot.clone())).unwrap());

    let conflicting_domain = DomainName::new("conflicting.example.com").unwrap();
    let conflicting_snapshot = LegacyFakeIpSnapshot {
        entries: vec![LegacyFakeIpEntry {
            domain: conflicting_domain.clone(),
            address: Ipv4Addr::new(198, 18, 0, 3),
        }],
        next: Some(Ipv4Addr::new(198, 18, 0, 3)),
    };
    assert!(!block_on(pool.import_legacy("pebble-v1", conflicting_snapshot)).unwrap());
    assert_eq!(
        block_on(pool.lookup_ip(&domain)),
        Some(Ipv4Addr::new(198, 18, 0, 2))
    );
    assert_eq!(block_on(pool.lookup_ip(&conflicting_domain)), None);
}

#[test]
fn versioned_go_pebble_ndjson_imports_entries_and_cursor() {
    let export = LegacyFakeIpExport::parse_ndjson(include_str!(
        "../tests/fixtures/go_pebble_fakeip_v1.ndjson"
    ))
    .unwrap();
    assert_eq!(export.version, 1);
    assert_eq!(export.family, 4);
    assert_eq!(export.prefix, "198.18.0.0/15");
    assert_eq!(export.snapshot.entries.len(), 2);
    assert_eq!(export.snapshot.next, Some(Ipv4Addr::new(198, 18, 0, 12)));

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let options = FakeIpPoolOptions::new(64, 1_000).unwrap();
    let pool = block_on(FakeIpPool::open_with_prefix(
        store,
        FakeIpConfig::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 64)).unwrap(),
        export.prefix.clone(),
        options,
    ))
    .unwrap();
    assert!(block_on(pool.import_legacy("go-pebble-v1", export.snapshot)).unwrap());
    assert_eq!(
        block_on(pool.lookup_ip(&DomainName::new("legacy.example.com").unwrap())),
        Some(Ipv4Addr::new(198, 18, 0, 10))
    );
    assert_eq!(
        block_on(pool.lookup_domain(Ipv4Addr::new(198, 18, 0, 11))),
        Some(DomainName::new("legacy.example.net").unwrap())
    );
    assert_eq!(
        block_on(pool.allocate(DomainName::new("new.example.com").unwrap())).unwrap(),
        Ipv4Addr::new(198, 18, 0, 12)
    );
    assert!(
        !block_on(pool.import_legacy("go-pebble-v1", LegacyFakeIpSnapshot::default())).unwrap()
    );
}

#[test]
fn versioned_go_pebble_ndjson_rejects_mixed_pool_metadata() {
    let error = LegacyFakeIpExport::parse_ndjson(
            r#"{"version":1,"family":4,"prefix":"198.18.0.0/15","kind":"entry","domain":"a.example","address":"198.18.0.1"}
{"version":1,"family":4,"prefix":"198.19.0.0/16","kind":"cursor","next":"198.19.0.2"}"#,
        )
        .unwrap_err();
    assert!(error.message.contains("mixes pool prefixes"));
}

#[test]
fn versioned_go_pebble_ndjson_rejects_unknown_fields_and_conflict_snapshot_is_atomic() {
    let empty = LegacyFakeIpExport::parse_ndjson(include_str!(
        "../tests/fixtures/go_pebble_fakeip_v1_empty_v4.ndjson"
    ))
    .unwrap();
    assert!(empty.snapshot.entries.is_empty());
    assert_eq!(empty.snapshot.next, Some(Ipv4Addr::new(198, 18, 0, 2)));

    let error = LegacyFakeIpExport::parse_ndjson(include_str!(
        "../tests/fixtures/go_pebble_fakeip_v1_unknown_v4.ndjson"
    ))
    .unwrap_err();
    assert!(error.message.contains("invalid FakeIP legacy NDJSON line"));

    let export = LegacyFakeIpExport::parse_ndjson(include_str!(
        "../tests/fixtures/go_pebble_fakeip_v1_conflict_v4.ndjson"
    ))
    .unwrap();
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open_with_prefix(
        store,
        config(),
        export.prefix.clone(),
        FakeIpPoolOptions::new(3, 1_000).unwrap(),
    ))
    .unwrap();
    let error = block_on(pool.import_legacy("go-pebble-v1-conflict", export.snapshot)).unwrap_err();
    assert!(error.message.contains("duplicate addresses"));
    assert_eq!(block_on(pool.len()), 0);
}

#[test]
fn versioned_go_pebble_v6_ndjson_imports_entries_and_cursor() {
    let export = LegacyFakeIpV6Export::parse_ndjson(include_str!(
        "../tests/fixtures/go_pebble_fakeip_v1_v6.ndjson"
    ))
    .unwrap();
    assert_eq!(export.version, 1);
    assert_eq!(export.family, 6);
    assert_eq!(export.prefix, "fc00::/18");
    assert_eq!(export.snapshot.entries.len(), 1);
    assert_eq!(export.snapshot.next, Some("fc00::3".parse().unwrap()));

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpV6Pool::open_with_prefix(
        store,
        v6_config(),
        export.prefix.clone(),
        FakeIpPoolOptions::new(3, 1_000).unwrap(),
    ))
    .unwrap();
    assert!(block_on(pool.import_legacy("go-pebble-v1-v6", export.snapshot)).unwrap());
    let domain = DomainName::new("legacy6.example.com").unwrap();
    let address = "fc00::2".parse::<Ipv6Addr>().unwrap();
    assert_eq!(block_on(pool.lookup_ip(&domain)), Some(address));
    assert_eq!(block_on(pool.lookup_domain(address)), Some(domain));
    assert_eq!(
        block_on(pool.allocate(DomainName::new("new6.example.com").unwrap())).unwrap(),
        "fc00::3".parse::<Ipv6Addr>().unwrap()
    );
    assert!(
        !block_on(pool.import_legacy("go-pebble-v1-v6", LegacyFakeIpV6Snapshot::default()))
            .unwrap()
    );
}

#[test]
fn legacy_v6_import_rejects_duplicate_address_without_partial_state() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpV6Pool::open(store, v6_config())).unwrap();
    let address = "fc00::2".parse::<Ipv6Addr>().unwrap();
    let snapshot = LegacyFakeIpV6Snapshot {
        entries: vec![
            LegacyFakeIpV6Entry {
                domain: DomainName::new("first6.example.com").unwrap(),
                address,
            },
            LegacyFakeIpV6Entry {
                domain: DomainName::new("second6.example.com").unwrap(),
                address,
            },
        ],
        next: Some("fc00::3".parse().unwrap()),
    };

    let error = block_on(pool.import_legacy("duplicate-address-v6", snapshot)).unwrap_err();
    assert!(error.message.contains("duplicate addresses"));
    assert_eq!(block_on(pool.len()), 0);
    assert!(
        block_on(
            pool.store
                .get_config(&format!("{IMPORT_MARKER_PREFIX}duplicate-address-v6"))
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn legacy_v6_import_rejects_existing_domain_conflict_without_overwrite() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpV6Pool::open(store, v6_config())).unwrap();
    let domain = DomainName::new("existing6.example.com").unwrap();
    let existing_address = block_on(pool.allocate(domain.clone())).unwrap();
    let incoming_address = "fc00::3".parse::<Ipv6Addr>().unwrap();
    let snapshot = LegacyFakeIpV6Snapshot {
        entries: vec![LegacyFakeIpV6Entry {
            domain: domain.clone(),
            address: incoming_address,
        }],
        next: Some("fc00::1".parse().unwrap()),
    };

    let error = block_on(pool.import_legacy("existing-domain-v6", snapshot)).unwrap_err();
    assert!(error.message.contains("domain conflicts"));
    assert_eq!(block_on(pool.lookup_ip(&domain)), Some(existing_address));
    assert_eq!(block_on(pool.len()), 1);
}

#[test]
fn legacy_import_rejects_duplicate_address_without_partial_state() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open(store, config())).unwrap();
    let snapshot = LegacyFakeIpSnapshot {
        entries: vec![
            LegacyFakeIpEntry {
                domain: DomainName::new("first.example.com").unwrap(),
                address: Ipv4Addr::new(198, 18, 0, 2),
            },
            LegacyFakeIpEntry {
                domain: DomainName::new("second.example.com").unwrap(),
                address: Ipv4Addr::new(198, 18, 0, 2),
            },
        ],
        next: Some(Ipv4Addr::new(198, 18, 0, 3)),
    };

    let error = block_on(pool.import_legacy("duplicate-address", snapshot)).unwrap_err();
    assert!(error.message.contains("duplicate addresses"));
    assert_eq!(block_on(pool.len()), 0);
    assert!(
        block_on(
            pool.store
                .get_config(&format!("{IMPORT_MARKER_PREFIX}duplicate-address"))
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn legacy_import_rejects_existing_address_conflict_without_overwrite() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = block_on(FakeIpPool::open(store, config())).unwrap();
    let existing = DomainName::new("existing.example.com").unwrap();
    let address = block_on(pool.allocate(existing.clone())).unwrap();
    let snapshot = LegacyFakeIpSnapshot {
        entries: vec![LegacyFakeIpEntry {
            domain: DomainName::new("incoming.example.com").unwrap(),
            address,
        }],
        next: Some(Ipv4Addr::new(198, 18, 0, 3)),
    };

    let error = block_on(pool.import_legacy("existing-conflict", snapshot)).unwrap_err();
    assert!(error.message.contains("conflicts with current mapping"));
    assert_eq!(block_on(pool.len()), 1);
    assert_eq!(block_on(pool.lookup_domain(address)), Some(existing));
    assert_eq!(
        block_on(pool.lookup_ip(&DomainName::new("incoming.example.com").unwrap())),
        None
    );
}

#[test]
fn dns_answer_transform_replaces_ipv4_and_persists_reverse_mapping() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = Arc::new(block_on(FakeIpPool::open(store, config())).unwrap());
    let transform = FakeIpAnswerTransform {
        pool: Arc::clone(&pool),
    };
    let domain = DomainName::new("example.com").unwrap();
    let response = block_on(transform.apply(
        &domain,
        DnsRecordType::A,
        DnsResponse {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(20),
        },
    ))
    .unwrap();
    assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(198, 18, 0, 1)]);
    assert_eq!(
        block_on(pool.lookup_domain(response.addresses.v4[0])),
        Some(domain.clone())
    );
    let view = block_on(pool.snapshot());
    assert_eq!(view.lookup_domain(response.addresses.v4[0]), Some(domain));
    assert_eq!(response.minimum_ttl, Some(20));
}

#[test]
fn ipv6_pool_is_stable_reversible_and_uses_a_separate_namespace() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let v4 = block_on(FakeIpPool::open(store.clone(), config())).unwrap();
    let v6 = block_on(FakeIpV6Pool::open(store, v6_config())).unwrap();
    let v4_domain = DomainName::new("v4.example.com").unwrap();
    let v6_domain = DomainName::new("v6.example.com").unwrap();
    let v4_address = block_on(v4.allocate(v4_domain.clone())).unwrap();
    let v6_address = block_on(v6.allocate(v6_domain.clone())).unwrap();

    assert_eq!(v4_address, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(v6_address, "fc00::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(block_on(v6.allocate(v6_domain.clone())), Ok(v6_address));
    assert_eq!(
        block_on(v6.lookup_domain(v6_address)),
        Some(v6_domain.clone())
    );
    assert_eq!(block_on(v6.lookup_ip(&v6_domain)), Some(v6_address));
    assert_eq!(
        block_on(v6.lookup_domain(v6_address)),
        Some(v6_domain.clone())
    );
    assert_eq!(block_on(v4.lookup_domain(v4_address)), Some(v4_domain));

    let view = block_on(v6.snapshot());
    assert_eq!(
        view.lookup_domain_ip(IpAddr::V6(v6_address)),
        Some(v6_domain.clone())
    );
    assert_eq!(view.lookup_domain(v4_address), None);
    assert!(block_on(v6.release(&v6_domain)).unwrap());
    assert_eq!(block_on(v6.lookup_domain(v6_address)), None);
}

#[test]
fn overlapping_prefixes_quarantine_live_address_reuse_for_both_families() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let options = FakeIpPoolOptions::new(3, 24 * 60 * 60).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let legacy_v4 = block_on(FakeIpPool::open_with_prefix(
        store.clone(),
        config(),
        "legacy-v4",
        options,
    ))
    .unwrap();
    let legacy_v4_address =
        block_on(legacy_v4.allocate_at(DomainName::new("legacy-v4.example").unwrap(), now))
            .unwrap();
    let current_v4 = block_on(FakeIpPool::open_with_prefix(
        store.clone(),
        config(),
        "current-v4",
        options,
    ))
    .unwrap();
    let current_v4_address =
        block_on(current_v4.allocate_at(DomainName::new("current-v4.example").unwrap(), now + 1))
            .unwrap();
    assert_eq!(legacy_v4_address, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(current_v4_address, Ipv4Addr::new(198, 18, 0, 2));

    let legacy_v6 = block_on(FakeIpV6Pool::open_with_prefix(
        store.clone(),
        v6_config(),
        "legacy-v6",
        options,
    ))
    .unwrap();
    let legacy_v6_address =
        block_on(legacy_v6.allocate_at(DomainName::new("legacy-v6.example").unwrap(), now))
            .unwrap();
    let current_v6 = block_on(FakeIpV6Pool::open_with_prefix(
        store,
        v6_config(),
        "current-v6",
        options,
    ))
    .unwrap();
    let current_v6_address =
        block_on(current_v6.allocate_at(DomainName::new("current-v6.example").unwrap(), now + 1))
            .unwrap();
    assert_eq!(legacy_v6_address, "fc00::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(current_v6_address, "fc00::2".parse::<Ipv6Addr>().unwrap());
}

#[test]
fn overlapping_prefixes_quarantine_an_existing_conflicting_row() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let options = FakeIpPoolOptions::new(3, 24 * 60 * 60).unwrap();
    let now = unix_now();
    let legacy_prefix = "legacy-v6";
    let current_prefix = "current-v6";
    let conflicting_address = "fc00::1".parse::<Ipv6Addr>().unwrap();
    let legacy_domain = DomainName::new("legacy-v6.example").unwrap();
    let current_domain = DomainName::new("current-v6.example").unwrap();

    let legacy = block_on(FakeIpV6Pool::open_with_prefix(
        store.clone(),
        v6_config(),
        legacy_prefix,
        options,
    ))
    .unwrap();
    assert_eq!(
        block_on(legacy.allocate_at(legacy_domain, now)).unwrap(),
        conflicting_address
    );

    block_on(store.replace_fakeip_entry(
        &FakeIpEntryRecord {
            family: 6,
            prefix: current_prefix.to_owned(),
            domain: current_domain.to_string(),
            ip: conflicting_address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        },
        &FakeIpCursorRecord {
            family: 6,
            prefix: current_prefix.to_owned(),
            cursor_ip: "fc00::2".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
            cursor_idx: 1,
            updated_at: now,
        },
        None,
    ))
    .unwrap();

    let current = block_on(FakeIpV6Pool::open_with_prefix(
        store,
        v6_config(),
        current_prefix,
        options,
    ))
    .unwrap();
    assert_eq!(block_on(current.lookup_domain(conflicting_address)), None);
    assert_eq!(
        block_on(current.allocate_at(current_domain, now + 1)).unwrap(),
        "fc00::2".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn ipv6_pool_reopens_with_mapping_and_cursor() {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .expect("a cache directory is required for the persistence test")
        .join("yuhaiin-rust-check");
    std::fs::create_dir_all(&cache).unwrap();
    let path = cache.join(format!(
        "fakeip-v6-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let first_domain = DomainName::new("first-v6.example.com").unwrap();
    let second_domain = DomainName::new("second-v6.example.com").unwrap();
    let first_address;
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpV6Pool::open(store, v6_config())).unwrap();
        first_address = block_on(pool.allocate(first_domain.clone())).unwrap();
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpV6Pool::open(store, v6_config())).unwrap();
        assert_eq!(block_on(pool.lookup_ip(&first_domain)), Some(first_address));
        assert_eq!(
            block_on(pool.allocate(second_domain)),
            Ok("fc00::2".parse::<Ipv6Addr>().unwrap())
        );
    }
    for suffix in [
        "",
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-gate",
        "-fsqlite-ns-use",
        "-yuhaiin-write-lock",
    ] {
        let artifact = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(artifact);
    }
}

#[test]
fn ipv6_answer_transform_replaces_aaaa_and_preserves_ttl() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = Arc::new(block_on(FakeIpV6Pool::open(store, v6_config())).unwrap());
    let transform = FakeIpV6AnswerTransform {
        pool: Arc::clone(&pool),
    };
    let domain = DomainName::new("ipv6.example.com").unwrap();
    let response = block_on(transform.apply(
        &domain,
        DnsRecordType::Aaaa,
        DnsResponse {
            addresses: IpSet {
                v4: Vec::new(),
                v6: vec!["2001:db8::7".parse().unwrap()],
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(30),
        },
    ))
    .unwrap();
    assert_eq!(response.addresses.v4, Vec::<Ipv4Addr>::new());
    assert_eq!(
        response.addresses.v6,
        vec!["fc00::1".parse::<Ipv6Addr>().unwrap()]
    );
    assert_eq!(response.minimum_ttl, Some(30));
    assert_eq!(
        block_on(pool.lookup_domain(response.addresses.v6[0])),
        Some(domain)
    );
}

#[test]
fn https_and_svcb_hints_use_fakeip_without_losing_service_metadata() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let ipv4 = Arc::new(block_on(FakeIpPool::open(store.clone(), config())).unwrap());
    let ipv6 = Arc::new(block_on(FakeIpV6Pool::open(store, v6_config())).unwrap());
    let domain = DomainName::new("https.example.com").unwrap();
    let response = DnsResponse {
        addresses: IpSet::default(),
        ptr_names: Vec::new(),
        service_bindings: vec![DnsServiceBinding {
            priority: 1,
            target: Some(DomainName::new("svc.example.com").unwrap()),
            params: vec![
                DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(203, 0, 113, 7)]),
                DnsServiceParam::Ipv6Hint(vec!["2001:db8::7".parse().unwrap()]),
                DnsServiceParam::Alpn(vec!["h2".to_owned()]),
                DnsServiceParam::Unknown {
                    key: 65_400,
                    value: vec![7, 8, 9],
                },
            ],
        }],
        minimum_ttl: Some(23),
    };
    let response = block_on(
        FakeIpDualStackAnswerTransform {
            ipv4: Arc::clone(&ipv4),
            ipv6: Arc::clone(&ipv6),
        }
        .apply(&domain, DnsRecordType::Https, response),
    )
    .unwrap();

    assert_eq!(response.minimum_ttl, Some(23));
    assert_eq!(response.service_bindings.len(), 1);
    assert_eq!(
        response.service_bindings[0].target,
        Some(DomainName::new("svc.example.com").unwrap())
    );
    assert_eq!(
        response.service_bindings[0].params,
        vec![
            DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(198, 18, 0, 1)]),
            DnsServiceParam::Ipv6Hint(vec!["fc00::1".parse().unwrap()]),
            DnsServiceParam::Alpn(vec!["h2".to_owned()]),
            DnsServiceParam::Unknown {
                key: 65_400,
                value: vec![7, 8, 9],
            },
        ]
    );
    assert_eq!(
        block_on(ipv4.lookup_domain(Ipv4Addr::new(198, 18, 0, 1))),
        Some(domain.clone())
    );
    assert_eq!(
        block_on(ipv6.lookup_domain("fc00::1".parse().unwrap())),
        Some(domain)
    );
}

#[test]
fn ptr_transform_answers_local_ipv4_and_ipv6_hits_before_upstream() {
    use yuhaiin_core::dns::{AsyncDnsHandler, DnsRecordType, decode_response, encode_query};

    struct NeverUpstream;
    impl AsyncDomainResolver for NeverUpstream {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Closed,
                    "local FakeIP PTR should not call upstream",
                ))
            })
        }
    }

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let ipv4 = Arc::new(block_on(FakeIpPool::open(store.clone(), config())).unwrap());
    let ipv6 = Arc::new(block_on(FakeIpV6Pool::open(store, v6_config())).unwrap());
    let ipv4_domain = DomainName::new("ptr-v4.example.com").unwrap();
    let ipv6_domain = DomainName::new("ptr-v6.example.com").unwrap();
    let ipv4_address = block_on(ipv4.allocate(ipv4_domain.clone())).unwrap();
    let ipv6_address = block_on(ipv6.allocate(ipv6_domain.clone())).unwrap();
    let transform = FakeIpPtrTransform { ipv4, ipv6 };
    let handler = FakeIpAsyncDnsHandler {
        upstream: NeverUpstream,
        transform,
    };

    let v4_octets = ipv4_address.octets();
    let v4_reverse = DomainName::new(&format!(
        "{}.{}.{}.{}.in-addr.arpa",
        v4_octets[3], v4_octets[2], v4_octets[1], v4_octets[0]
    ))
    .unwrap();
    let v6_reverse_text = format!("{:032x}", u128::from(ipv6_address))
        .chars()
        .rev()
        .map(|nibble| nibble.to_string())
        .collect::<Vec<_>>()
        .join(".");
    let v6_reverse = DomainName::new(&format!("{v6_reverse_text}.ip6.arpa")).unwrap();

    for (id, reverse, expected) in [(51, v4_reverse, ipv4_domain), (52, v6_reverse, ipv6_domain)] {
        let packet = encode_query(id, &reverse, DnsRecordType::Ptr).unwrap();
        let response = block_on(handler.answer(&packet)).unwrap();
        let response = decode_response(&response, id, DnsRecordType::Ptr).unwrap();
        assert_eq!(response.ptr_names, vec![expected]);
        assert_eq!(response.minimum_ttl, Some(60));
    }
}

#[test]
fn ptr_transform_falls_back_to_upstream_for_unknown_mapping() {
    use yuhaiin_core::dns::{AsyncDnsHandler, DnsRecordType, decode_response, encode_query};

    struct Fallback;
    impl AsyncDomainResolver for Fallback {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Ok(DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: vec![DomainName::new("upstream.example.com").unwrap()],
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(12),
                })
            })
        }
    }

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let transform = FakeIpPtrTransform {
        ipv4: Arc::new(block_on(FakeIpPool::open(store.clone(), config())).unwrap()),
        ipv6: Arc::new(block_on(FakeIpV6Pool::open(store, v6_config())).unwrap()),
    };
    let handler = FakeIpAsyncDnsHandler {
        upstream: Fallback,
        transform,
    };
    let reverse = DomainName::new("7.113.0.203.in-addr.arpa").unwrap();
    let packet = encode_query(53, &reverse, DnsRecordType::Ptr).unwrap();
    let response = block_on(handler.answer(&packet)).unwrap();
    let response = decode_response(&response, 53, DnsRecordType::Ptr).unwrap();
    assert_eq!(
        response.ptr_names,
        vec![DomainName::new("upstream.example.com").unwrap()]
    );
    assert_eq!(response.minimum_ttl, Some(12));
}

#[test]
fn async_dns_handler_runs_upstream_then_fakeip_transform() {
    use yuhaiin_core::dns::{AsyncDnsHandler, DnsRecordType, decode_response, encode_query};

    struct Resolver;
    impl AsyncDomainResolver for Resolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Ok(DnsResponse {
                    addresses: IpSet {
                        v4: vec![Ipv4Addr::new(203, 0, 113, 8)],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(25),
                })
            })
        }
    }

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = Arc::new(block_on(FakeIpPool::open(store, config())).unwrap());
    let handler = FakeIpAsyncDnsHandler {
        upstream: Resolver,
        transform: FakeIpAnswerTransform {
            pool: Arc::clone(&pool),
        },
    };
    let packet = encode_query(
        12,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::A,
    )
    .unwrap();
    let response = block_on(handler.answer(&packet)).unwrap();
    let response = decode_response(&response, 12, DnsRecordType::A).unwrap();
    assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(198, 18, 0, 1)]);
}

#[test]
fn async_dns_handler_supports_ipv6_aaaa_transform() {
    use yuhaiin_core::dns::{AsyncDnsHandler, DnsRecordType, decode_response, encode_query};

    struct Resolver;
    impl AsyncDomainResolver for Resolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Ok(DnsResponse {
                    addresses: IpSet {
                        v4: Vec::new(),
                        v6: vec!["2001:db8::9".parse().unwrap()],
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(35),
                })
            })
        }
    }

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = Arc::new(block_on(FakeIpV6Pool::open(store, v6_config())).unwrap());
    let handler = FakeIpAsyncDnsHandler {
        upstream: Resolver,
        transform: FakeIpV6AnswerTransform {
            pool: Arc::clone(&pool),
        },
    };
    let packet = encode_query(
        13,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::Aaaa,
    )
    .unwrap();
    let response = block_on(handler.answer(&packet)).unwrap();
    let response = decode_response(&response, 13, DnsRecordType::Aaaa).unwrap();
    assert_eq!(
        response.addresses.v6,
        vec!["fc00::1".parse::<Ipv6Addr>().unwrap()]
    );
    assert_eq!(response.minimum_ttl, Some(35));
}

#[test]
fn async_dns_handler_supports_https_hint_transform() {
    use yuhaiin_core::dns::{AsyncDnsHandler, DnsRecordType, decode_response, encode_query};

    struct Resolver;
    impl AsyncDomainResolver for Resolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Ok(DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: Vec::new(),
                    service_bindings: vec![DnsServiceBinding {
                        priority: 1,
                        target: Some(DomainName::new("svc.example.com").unwrap()),
                        params: vec![DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(
                            203, 0, 113, 8,
                        )])],
                    }],
                    minimum_ttl: Some(40),
                })
            })
        }
    }

    let store = block_on(ConfigStore::open_memory()).unwrap();
    let pool = Arc::new(block_on(FakeIpPool::open(store, config())).unwrap());
    let handler = FakeIpAsyncDnsHandler {
        upstream: Resolver,
        transform: FakeIpAnswerTransform {
            pool: Arc::clone(&pool),
        },
    };
    let packet = encode_query(
        14,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::Https,
    )
    .unwrap();
    let response = block_on(handler.answer(&packet)).unwrap();
    let response = decode_response(&response, 14, DnsRecordType::Https).unwrap();
    assert_eq!(response.minimum_ttl, Some(40));
    assert_eq!(
        response.service_bindings[0].params,
        vec![DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(
            198, 18, 0, 1
        )])]
    );
    assert_eq!(
        block_on(pool.lookup_domain(Ipv4Addr::new(198, 18, 0, 1))),
        Some(DomainName::new("example.com").unwrap())
    );
}
