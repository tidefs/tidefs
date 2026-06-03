//! Concrete adapter implementations for the replication dispatch traits.
//!
//! Provides feature-gated [`ObjectWriteTarget`] implementations for
//! [`tidefs_local_object_store::LocalObjectStore`] and a simple static
//! [`PlacementResolver`] that bridges to placement-runtime decisions.

#[cfg(feature = "local-store-adapter")]
use crate::dispatcher::ObjectWriteTarget;
use crate::dispatcher::PlacementResolver;
use tidefs_replication_model::{PlacementEntry, ReplicationIntent};

// ---------------------------------------------------------------------------
// LocalObjectStoreTarget (feature = "local-store-adapter")
// ---------------------------------------------------------------------------

/// An [`ObjectWriteTarget`] backed by a [`tidefs_local_object_store::LocalObjectStore`].
///
/// Each call to [`put_object`](ObjectWriteTarget::put_object) derives an
/// [`ObjectKey`] from the key bytes via BLAKE3 content-addressing, calls
/// `LocalObjectStore::put`, and returns the BLAKE3 digest of the payload.
#[cfg(feature = "local-store-adapter")]
pub struct LocalObjectStoreTarget<'a> {
    store: &'a mut tidefs_local_object_store::LocalObjectStore,
}

#[cfg(feature = "local-store-adapter")]
impl<'a> LocalObjectStoreTarget<'a> {
    /// Wrap a mutable reference to a [`LocalObjectStore`].
    #[must_use]
    pub fn new(store: &'a mut tidefs_local_object_store::LocalObjectStore) -> Self {
        Self { store }
    }
}

#[cfg(feature = "local-store-adapter")]
impl ObjectWriteTarget for LocalObjectStoreTarget<'_> {
    fn put_object(
        &mut self,
        _device_id: u64,
        key: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], String> {
        // Derive a content-addressed ObjectKey from the caller-provided key
        // bytes, matching LocalObjectStore::put_content_addressed semantics.
        let obj_key = tidefs_local_object_store::ObjectKey::from_content(key);
        self.store
            .put(obj_key, payload)
            .map_err(|e| format!("local-object-store put failed: {e}"))?;
        Ok(*blake3::hash(payload).as_bytes())
    }
}

// ---------------------------------------------------------------------------
// StaticPlacementResolver
// ---------------------------------------------------------------------------

/// A [`PlacementResolver`] that returns a fixed set of placement entries.
///
/// Useful for testing, single-node operation, or when placement decisions
/// are made externally and injected via configuration. For production
/// multi-node placement, implement `PlacementResolver` against
/// `tidefs_placement_runtime`.
pub struct StaticPlacementResolver {
    entries: Vec<PlacementEntry>,
}

impl StaticPlacementResolver {
    /// Create a resolver that always returns the given entries, regardless
    /// of the intent.
    #[must_use]
    pub fn new(entries: Vec<PlacementEntry>) -> Self {
        Self { entries }
    }
}

impl PlacementResolver for StaticPlacementResolver {
    fn resolve(&self, _intent: &ReplicationIntent) -> Result<Vec<PlacementEntry>, String> {
        Ok(self.entries.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "local-store-adapter")]
    use crate::dispatcher::{ObjectStoreRegistry, ReplicationDispatcher};

    #[test]
    fn static_placement_resolver_returns_configured_entries() {
        let entries = vec![
            PlacementEntry::new(0, 1, 10, 100),
            PlacementEntry::new(1, 2, 20, 200),
        ];
        let resolver = StaticPlacementResolver::new(entries.clone());
        let intent =
            ReplicationIntent::new_mirror(2, tidefs_replication_model::FailureDomain::Node)
                .unwrap();
        let resolved = resolver.resolve(&intent).unwrap();
        assert_eq!(resolved, entries);
    }

    #[test]
    fn static_placement_resolver_ignores_intent() {
        let entries = vec![PlacementEntry::new(0, 1, 10, 100)];
        let resolver = StaticPlacementResolver::new(entries.clone());

        // Same entries returned regardless of intent
        let mirror =
            ReplicationIntent::new_mirror(2, tidefs_replication_model::FailureDomain::Node)
                .unwrap();
        let ec = ReplicationIntent::new_erasure_coded(
            4,
            2,
            tidefs_replication_model::FailureDomain::Rack,
        )
        .unwrap();

        assert_eq!(resolver.resolve(&mirror).unwrap(), entries);
        assert_eq!(resolver.resolve(&ec).unwrap(), entries);
    }

    #[cfg(feature = "local-store-adapter")]
    #[test]
    fn local_store_target_put_and_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();

        let options = tidefs_local_object_store::StoreOptions::default();
        let mut store =
            tidefs_local_object_store::LocalObjectStore::open_with_options(&root, options)
                .expect("open store");
        let mut target = LocalObjectStoreTarget::new(&mut store);

        let digest = target
            .put_object(1, b"test-key-001", b"hello adapter")
            .expect("put_object");
        let expected: [u8; 32] = blake3::hash(b"hello adapter").into();
        assert_eq!(digest, expected);
    }

    #[cfg(feature = "local-store-adapter")]
    #[test]
    fn local_store_target_different_keys_produce_same_digest_for_same_payload() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();

        let options = tidefs_local_object_store::StoreOptions::default();
        let mut store =
            tidefs_local_object_store::LocalObjectStore::open_with_options(&root, options)
                .expect("open store");
        let mut target = LocalObjectStoreTarget::new(&mut store);

        let d1 = target
            .put_object(1, b"key-a", b"same payload")
            .expect("put_object key-a");
        let d2 = target
            .put_object(1, b"key-b", b"same payload")
            .expect("put_object key-b");
        assert_eq!(d1, d2);
    }

    #[cfg(feature = "local-store-adapter")]
    #[test]
    fn local_store_target_roundtrip_through_dispatcher() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();

        let options = tidefs_local_object_store::StoreOptions::default();
        let mut store =
            tidefs_local_object_store::LocalObjectStore::open_with_options(&root, options)
                .expect("open store");

        // Inline registry that wraps a single store
        struct SingleStoreRegistry<'a> {
            store: LocalObjectStoreTarget<'a>,
        }
        impl ObjectStoreRegistry for SingleStoreRegistry<'_> {
            fn get_target_mut(&mut self, _device_id: u64) -> Option<&mut dyn ObjectWriteTarget> {
                Some(&mut self.store)
            }
        }
        impl<'a> SingleStoreRegistry<'a> {
            fn new(store: LocalObjectStoreTarget<'a>) -> Self {
                Self { store }
            }
        }

        let target = LocalObjectStoreTarget::new(&mut store);
        let registry = SingleStoreRegistry::new(target);
        let entries = vec![PlacementEntry::new(0, 1, 10, 100)];
        let resolver = StaticPlacementResolver::new(entries);

        let mut dispatcher = ReplicationDispatcher::new(resolver, registry);
        let intent =
            ReplicationIntent::new_mirror(1, tidefs_replication_model::FailureDomain::Device)
                .unwrap();

        let outcome = dispatcher.dispatch(&intent, b"integration-key", b"integration payload");
        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 1);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.digests_consistent);
        let expected: [u8; 32] = blake3::hash(b"integration payload").into();
        assert_eq!(outcome.successful_digests[0], expected);
    }
}
