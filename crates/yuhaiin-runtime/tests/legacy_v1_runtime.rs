use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_runtime::{RuntimeBuilder, RuntimeController};
use yuhaiin_store::ConfigStore;

fn cache_root() -> PathBuf {
    std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache/yuhaiin-rust"))
}

fn remove_database_artifacts(path: &std::path::Path) {
    for suffix in [
        "",
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
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

#[tokio::test]
#[ignore = "requires YUHAIIN_GO_LEGACY_PRODUCTION_DB pointing to a copied Go v1 state.db"]
async fn real_go_v1_snapshot_builds_the_shared_runtime_snapshot() {
    let source = std::env::var_os("YUHAIIN_GO_LEGACY_PRODUCTION_DB")
        .map(PathBuf::from)
        .expect("YUHAIIN_GO_LEGACY_PRODUCTION_DB must point to a Go v1 snapshot");
    assert!(source.is_file(), "Go v1 snapshot does not exist");

    let directory = cache_root().join("integration/legacy-v1-runtime");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!(
        "state-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::copy(&source, &path).expect("copy Go v1 snapshot");

    let store = ConfigStore::open(&path).await.unwrap();
    let inbound_records = store.repository().list_go_inbounds().await.unwrap();
    for expected in ["mixed", "tun", "yuubinsya"] {
        assert!(
            inbound_records.iter().any(|record| record.id == expected),
            "legacy runtime snapshot lost inbound {expected}"
        );
    }
    let node_records = store.repository().list_go_nodes().await.unwrap();
    assert!(
        !node_records.is_empty(),
        "legacy runtime snapshot lost nodes"
    );

    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .expect("real Go v1 snapshot must build a runtime snapshot");
    let snapshot = controller.handle().load();
    assert!(
        !snapshot.proxies.is_empty(),
        "runtime snapshot has no proxy nodes"
    );
    assert!(
        snapshot
            .proxies
            .iter()
            .any(|proxy| proxy.id == node_records[0].id),
        "runtime snapshot did not publish the imported legacy node"
    );
    // Loading the handle proves that the resolver, route compiler, FakeIP
    // state and proxy selector were assembled as one immutable snapshot. The
    // old database currently has no route rules, so there is no rule-specific
    // assertion here.

    controller.persist_monitor().await.unwrap();
    remove_database_artifacts(&path);
}
