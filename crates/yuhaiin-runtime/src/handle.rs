use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use yuhaiin_core::{Error, ErrorKind, Result};

use crate::{RuntimeBuilder, RuntimeSnapshot};

/// Shared owner for the currently published runtime snapshot.
///
/// A flow takes one `Arc` with [`RuntimeHandle::load`] and can keep using that
/// snapshot while a reload builds and publishes another one.  HTTP handlers,
/// TUN dispatchers and proxy construction therefore share the same persisted
/// records without introducing a second DTO or holding a database lock.
#[derive(Clone)]
pub struct RuntimeHandle {
    snapshot: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    revision: Arc<AtomicU64>,
}

impl RuntimeHandle {
    pub fn new(snapshot: RuntimeSnapshot) -> Self {
        Self::from_arc(Arc::new(snapshot))
    }

    pub fn from_arc(snapshot: Arc<RuntimeSnapshot>) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(snapshot)),
            revision: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Monotonic snapshot revision for HTTP/reload callers.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Load a stable snapshot reference for one flow or request.
    pub fn load(&self) -> Arc<RuntimeSnapshot> {
        recover_read(&self.snapshot).clone()
    }

    /// Load the revision and snapshot under the same read lock.  HTTP status
    /// responses can therefore report a self-consistent version without
    /// creating a management DTO or racing a concurrent publish.
    pub fn load_with_revision(&self) -> (u64, Arc<RuntimeSnapshot>) {
        let guard = recover_read(&self.snapshot);
        let revision = self.revision.load(Ordering::Acquire);
        (revision, guard.clone())
    }

    /// Publish only after the caller has completely built and validated the
    /// next snapshot.  The returned old snapshot remains usable by existing
    /// flows and can be dropped after their last `Arc` is released.
    pub fn publish(&self, snapshot: RuntimeSnapshot) -> Arc<RuntimeSnapshot> {
        self.replace(Arc::new(snapshot))
    }

    /// Publish only when no newer snapshot was installed after the caller
    /// loaded `expected_revision`.  This prevents two concurrent HTTP reloads
    /// from letting the slower, stale build replace the newer configuration.
    pub fn publish_if_revision(
        &self,
        expected_revision: u64,
        snapshot: RuntimeSnapshot,
    ) -> Result<Arc<RuntimeSnapshot>> {
        self.publish_arc_if_revision(expected_revision, Arc::new(snapshot))
    }

    pub(crate) fn publish_arc_if_revision(
        &self,
        expected_revision: u64,
        next: Arc<RuntimeSnapshot>,
    ) -> Result<Arc<RuntimeSnapshot>> {
        let mut guard = recover_write(&self.snapshot);
        let actual_revision = self.revision.load(Ordering::Acquire);
        if actual_revision != expected_revision {
            return Err(Error::new(
                ErrorKind::Closed,
                format!(
                    "runtime reload superseded: expected revision {expected_revision}, current revision {actual_revision}"
                ),
            ));
        }
        let old = std::mem::replace(&mut *guard, next);
        self.revision
            .store(actual_revision.wrapping_add(1), Ordering::Release);
        Ok(old)
    }

    /// Rebuild from the current store and publish atomically on success.
    /// Build errors leave the previous snapshot untouched.
    pub async fn rebuild(&self, builder: &RuntimeBuilder) -> Result<Arc<RuntimeSnapshot>> {
        let expected_revision = self.revision();
        let next = Arc::new(builder.build().await?);
        self.publish_arc_if_revision(expected_revision, next.clone())
            .map(|_| next)
    }

    fn replace(&self, next: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        let mut guard = recover_write(&self.snapshot);
        let old = std::mem::replace(&mut *guard, next);
        self.revision.fetch_add(1, Ordering::Release);
        old
    }
}

fn recover_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn recover_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_store::ConfigStore;

    fn empty_snapshot() -> RuntimeSnapshot {
        futures_block_on(async {
            RuntimeBuilder::new(
                ConfigStore::open_memory().await.unwrap(),
                Arc::new(SystemAsyncIpResolver),
            )
            .build()
            .await
            .unwrap()
        })
    }

    #[test]
    fn publish_keeps_old_arc_usable_and_returns_it() {
        let mut first = empty_snapshot();
        first.proxies.push(yuhaiin_store::GoProxyRuntimeConfig {
            id: "first".to_owned(),
            name: "first".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: yuhaiin_store::GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        });
        let handle = RuntimeHandle::new(first);
        let old = handle.load();

        let mut second = empty_snapshot();
        second.proxies.push(yuhaiin_store::GoProxyRuntimeConfig {
            id: "second".to_owned(),
            name: "second".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: yuhaiin_store::GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        });
        let returned = handle.publish(second);

        assert_eq!(returned.proxies[0].id, "first");
        assert_eq!(old.proxies[0].id, "first");
        assert_eq!(handle.load().proxies[0].id, "second");
    }

    #[test]
    fn rebuild_failure_does_not_replace_previous_snapshot() {
        let store = futures_block_on(ConfigStore::open_memory()).unwrap();
        let builder = RuntimeBuilder::new(store.clone(), Arc::new(SystemAsyncIpResolver));
        let handle = RuntimeHandle::new(futures_block_on(builder.build()).unwrap());
        let before = handle.load();

        futures_block_on(async {
            store
                .repository()
                .put_maxmind_metadata(&yuhaiin_store::MaxMindMetadataRecord {
                    id: "broken-geo".to_owned(),
                    path: ".cache/yuhaiin-rust/missing.mmdb".to_owned(),
                    sha256: Vec::new(),
                    size: 0,
                    updated_at: 0,
                })
                .await
                .unwrap();
        });

        assert!(futures_block_on(handle.rebuild(&builder)).is_err());
        assert!(handle.load().proxies.is_empty());
        assert!(Arc::ptr_eq(&before, &handle.load()));
    }

    #[test]
    fn conditional_publish_rejects_a_stale_reload_without_replacing_snapshot() {
        let handle = RuntimeHandle::new(empty_snapshot());
        let expected = handle.revision();
        let mut current = empty_snapshot();
        current.proxies.push(yuhaiin_store::GoProxyRuntimeConfig {
            id: "current".to_owned(),
            name: "current".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: yuhaiin_store::GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        });
        handle.publish(current);
        let revision_after_current = handle.revision();

        let stale = empty_snapshot();
        let error = match handle.publish_if_revision(expected, stale) {
            Ok(_) => panic!("stale reload must not replace a newer snapshot"),
            Err(error) => error,
        };

        assert_eq!(error.kind, ErrorKind::Closed);
        assert_eq!(handle.revision(), revision_after_current);
        assert_eq!(handle.load().proxies[0].id, "current");
    }

    #[test]
    fn load_with_revision_returns_a_consistent_pair_for_management_readers() {
        let handle = RuntimeHandle::new(empty_snapshot());
        let (initial_revision, initial_snapshot) = handle.load_with_revision();
        assert_eq!(initial_revision, 0);
        assert!(initial_snapshot.proxies.is_empty());

        let mut next = empty_snapshot();
        next.proxies.push(yuhaiin_store::GoProxyRuntimeConfig {
            id: "published".to_owned(),
            name: "published".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: yuhaiin_store::GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        });
        handle.publish(next);

        let (revision, snapshot) = handle.load_with_revision();
        assert_eq!(revision, 1);
        assert_eq!(snapshot.proxies[0].id, "published");
    }

    fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }
}
