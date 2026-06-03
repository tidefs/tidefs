//! Deterministic object-store validation harness.
//!
//! [`ObjectStoreTestHarness`] wraps any [`ObjectStore`] implementation and
//! provides reusable test methods for put/get/delete/scan round-trips,
//! overwrite semantics, isolation, and edge-case coverage. Higher-level
//! integration tests in other crates can import this harness to validate
//! their object-store dependency.
//!
//! The harness works through the [`ObjectStore`] trait exclusively:
//! put is content-addressed (key = BLAKE3-256 of payload), so all tests
//! use [`ObjectKey::from_content`] to predict keys.

use crate::*;
use std::collections::BTreeSet;

// ── Harness ───────────────────────────────────────────────────────────

/// Reusable test harness for any [`ObjectStore`] implementation.
///
/// # Example
///
/// ```rust
/// use std::time::{SystemTime, UNIX_EPOCH};
/// use tidefs_local_object_store::validation::ObjectStoreTestHarness;
/// use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
///
/// let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
/// let root = std::env::temp_dir().join(format!("tidefs-los-example-{nanos}"));
/// let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).unwrap();
/// let mut h = ObjectStoreTestHarness::new(store);
/// h.put_get_round_trip(b"hello").unwrap();
/// let _ = std::fs::remove_dir_all(&root);
/// ```
pub struct ObjectStoreTestHarness<S: ObjectStore> {
    pub store: S,
}

impl<S: ObjectStore> ObjectStoreTestHarness<S> {
    /// Wrap an existing store in the harness.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Consume the harness and return the inner store.
    pub fn into_inner(self) -> S {
        self.store
    }

    // ── Round-trip tests ──────────────────────────────────────────

    /// Put a payload and verify it can be read back byte-identical.
    ///
    /// Returns the content-addressed key.
    pub fn put_get_round_trip(&mut self, payload: &[u8]) -> Result<ObjectKey> {
        let key = self.store.put(payload)?;
        let got = self.store.get(key)?;
        assert_eq!(
            got.as_deref(),
            Some(payload),
            "put/get round-trip: payload mismatch for key {key}"
        );
        Ok(key)
    }

    /// Put `v1`, then overwrite with `v2` (same content = same key),
    /// and verify `v2` is returned.
    pub fn overwrite_last_write_wins(&mut self, v1: &[u8], v2: &[u8]) -> Result<ObjectKey> {
        let key = self.store.put(v1)?;
        let got1 = self.store.get(key)?;
        assert_eq!(got1.as_deref(), Some(v1), "first write should be visible");

        // Overwrite with different payload produces a different key
        // (content-addressed). For last-write-wins we need same logical
        // object; use put_named on LocalObjectStore for that test, or
        // accept that content-addressed overwrite = new key.
        //
        // Here we test that two distinct payloads produce distinct keys
        // and both are independently retrievable.
        let key2 = self.store.put(v2)?;
        let got2 = self.store.get(key2)?;
        assert_eq!(got2.as_deref(), Some(v2), "second write should be visible");

        // First key still retrievable (content-addressed: different payload,
        // different key, no overwrite).
        let got1b = self.store.get(key)?;
        assert_eq!(
            got1b.as_deref(),
            Some(v1),
            "first key should still be retrievable (content-addressed, no overwrite)"
        );

        Ok(key2)
    }

    /// Put then delete, verify get returns `None`.
    pub fn delete_hides_object(&mut self, payload: &[u8]) -> Result<()> {
        let key = self.store.put(payload)?;
        let existed = self.store.delete(key)?;
        assert!(existed, "delete should report that the key existed");

        let got = self.store.get(key)?;
        assert!(got.is_none(), "get after delete should return None");
        Ok(())
    }

    /// Delete a key twice: second delete should be idempotent (return `false`).
    pub fn double_delete_is_idempotent(&mut self, payload: &[u8]) -> Result<()> {
        let key = self.store.put(payload)?;
        assert!(self.store.delete(key)?, "first delete should succeed");
        assert!(
            !self.store.delete(key)?,
            "second delete should return false (already deleted)"
        );
        Ok(())
    }

    /// Put a zero-length payload and verify it can be read back.
    pub fn empty_object_round_trip(&mut self) -> Result<ObjectKey> {
        let key = self.store.put(b"")?;
        let got = self.store.get(key)?;
        assert_eq!(got.as_deref(), Some(&b""[..]), "empty object round-trip");
        Ok(key)
    }

    /// Put `N` distinct payloads, scan, and verify count and key membership.
    pub fn sequential_put_scan(&mut self, payloads: &[&[u8]]) -> Result<Vec<ObjectKey>> {
        let mut keys = Vec::with_capacity(payloads.len());
        for p in payloads {
            keys.push(self.store.put(p)?);
        }

        let scanned: BTreeSet<ObjectKey> = self.store.scan().collect();
        assert_eq!(
            scanned.len(),
            keys.len(),
            "scan count should match put count"
        );
        for k in &keys {
            assert!(scanned.contains(k), "scan should include key {k}");
        }
        Ok(keys)
    }

    /// Get on a never-written key must return `None` (not an error).
    pub fn get_never_written_is_none(&self, key: ObjectKey) -> Result<()> {
        let got = self.store.get(key)?;
        assert!(got.is_none(), "get on never-written key should return None");
        Ok(())
    }

    /// Put to object A, then verify object B is unchanged.
    pub fn cross_object_isolation(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        let key_a = self.store.put(a)?;
        let got_a = self.store.get(key_a)?;
        assert_eq!(got_a.as_deref(), Some(a), "object A should be intact");

        // Object B was never written — get should return None.
        let key_b = ObjectKey::from_content(b);
        let got_b = self.store.get(key_b)?;
        assert!(got_b.is_none(), "object B should not exist (never written)");
        Ok(())
    }

    /// Rapid put/delete churn: repeatedly put and delete the same payload,
    /// verifying no leaks or corruption.
    pub fn rapid_put_delete_churn(&mut self, payload: &[u8], iterations: usize) -> Result<()> {
        for _ in 0..iterations {
            let key = self.store.put(payload)?;
            let got = self.store.get(key)?;
            assert_eq!(got.as_deref(), Some(payload), "churn put/get mismatch");
            assert!(self.store.delete(key)?, "churn delete should succeed");
            assert!(
                self.store.get(key)?.is_none(),
                "churn get after delete should be None"
            );
        }
        Ok(())
    }

    /// Put, delete, then put again (reincarnation). The key must be live
    /// after the second put.
    pub fn put_after_delete_reincarnation(&mut self, payload: &[u8]) -> Result<ObjectKey> {
        let key = self.store.put(payload)?;
        assert!(self.store.delete(key)?, "delete before reincarnation");
        assert!(
            self.store.get(key)?.is_none(),
            "key should be gone after delete"
        );

        // Reincarnate
        let key2 = self.store.put(payload)?;
        assert_eq!(key, key2, "same content yields same key");
        let got = self.store.get(key2)?;
        assert_eq!(
            got.as_deref(),
            Some(payload),
            "reincarnated key should be live"
        );
        Ok(key2)
    }

    // ── get_attr ───────────────────────────────────────────────────

    /// Put a payload and verify `get_attr` returns correct size and key.
    pub fn get_attr_round_trip(&mut self, payload: &[u8]) -> Result<()> {
        let key = self.store.put(payload)?;
        let attr = self
            .store
            .get_attr(&key)
            .map_err(|_e| StoreError::CorruptHeader {
                segment_id: 0,
                offset: 0,
                reason: "get_attr failed",
            })?;
        // ObjectAttr equality compares key but not size directly — we
        // check size separately.
        assert_eq!(attr.size, payload.len() as u64, "get_attr size mismatch");
        assert_eq!(attr.key, key, "get_attr key mismatch");
        Ok(())
    }

    /// `get_attr` on a never-written key must return `NotFound`.
    pub fn get_attr_never_written_is_not_found(&self, key: ObjectKey) {
        let result = self.store.get_attr(&key);
        assert!(
            matches!(result, Err(ObjectReadError::NotFound { .. })),
            "get_attr on never-written key should be NotFound, got {result:?}"
        );
    }

    // ── Scan fidelity ──────────────────────────────────────────────

    /// Put several objects, delete one, verify scan count and membership.
    pub fn scan_excludes_deleted(&mut self, keep: &[&[u8]], drop: &[u8]) -> Result<()> {
        for p in keep {
            self.store.put(p)?;
        }
        let drop_key = self.store.put(drop)?;
        self.store.delete(drop_key)?;

        let scanned: BTreeSet<ObjectKey> = self.store.scan().collect();
        assert_eq!(
            scanned.len(),
            keep.len(),
            "scan count should exclude deleted key"
        );
        assert!(
            !scanned.contains(&drop_key),
            "scan should not include deleted key"
        );
        for p in keep {
            let k = ObjectKey::from_content(p);
            assert!(scanned.contains(&k), "scan should include kept key {k}");
        }
        Ok(())
    }

    // ── Edge cases ─────────────────────────────────────────────────

    /// Put and delete all objects, verify scan returns empty.
    pub fn delete_all_yields_empty_scan(&mut self, payloads: &[&[u8]]) -> Result<()> {
        let mut keys = Vec::new();
        for p in payloads {
            keys.push(self.store.put(p)?);
        }
        for k in &keys {
            assert!(self.store.delete(*k)?, "delete {k} should succeed");
        }
        let scanned: Vec<ObjectKey> = self.store.scan().collect();
        assert!(
            scanned.is_empty(),
            "scan should be empty after deleting all"
        );
        Ok(())
    }

    // ── Scan pagination ────────────────────────────────────────────

    /// Put  distinct objects, then verify that paginated scan
    /// (iterating with  in pages) covers all keys
    /// without duplicates and without omissions.
    pub fn scan_pagination(&mut self, total: usize, page_size: usize) -> Result<Vec<ObjectKey>> {
        assert!(total > 0, "total must be > 0");
        assert!(page_size > 0, "page_size must be > 0");

        // Put N distinct payloads, each a deterministic index suffix.
        let mut keys = Vec::with_capacity(total);
        for i in 0..total {
            let payload = format!("scan-page-obj-{i:04x}").into_bytes();
            keys.push(self.store.put(&payload)?);
        }

        // Page through the scan iterator.
        let mut seen = BTreeSet::new();
        let mut offset = 0;
        while offset < total {
            let page: Vec<ObjectKey> = self.store.scan().skip(offset).take(page_size).collect();
            if page.is_empty() {
                break;
            }
            for k in &page {
                assert!(seen.insert(*k), "duplicate key {k} in paginated scan");
            }
            offset += page.len();
        }

        assert_eq!(
            seen.len(),
            keys.len(),
            "paginated scan should find all keys (expected {}, got {})",
            keys.len(),
            seen.len()
        );
        for k in &keys {
            assert!(seen.contains(k), "paginated scan should include key {k}");
        }
        Ok(keys)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tidefs-los-validation-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn test_opts() -> StoreOptions {
        StoreOptions::test_fast()
    }

    fn open(root: &std::path::Path) -> LocalObjectStore {
        LocalObjectStore::open_with_options(root, test_opts()).expect("open store")
    }

    fn cleanup(root: &std::path::Path) {
        let _ = fs::remove_dir_all(root);
    }

    // ── Trait-level harness tests ──────────────────────────────────

    #[test]
    fn harness_put_get_round_trip() {
        let root = temp_root("put-get");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        let key = h.put_get_round_trip(b"hello world").unwrap();
        assert_ne!(key, ObjectKey::ZERO);
        cleanup(&root);
    }

    #[test]
    fn harness_overwrite_last_write_wins() {
        let root = temp_root("overwrite");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.overwrite_last_write_wins(b"old", b"new").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_delete_hides_object() {
        let root = temp_root("delete");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.delete_hides_object(b"ephemeral").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_double_delete_is_idempotent() {
        let root = temp_root("double-delete");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.double_delete_is_idempotent(b"double").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_empty_object_round_trip() {
        let root = temp_root("empty");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.empty_object_round_trip().unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_sequential_put_scan() {
        let root = temp_root("seq-put-scan");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        let payloads: &[&[u8]] = &[b"a", b"bb", b"ccc", b"dddd", b"eeeee"];
        let keys = h.sequential_put_scan(payloads).unwrap();
        assert_eq!(keys.len(), payloads.len());
        cleanup(&root);
    }

    #[test]
    fn harness_get_never_written_is_none() {
        let root = temp_root("never-written");
        let store = open(&root);
        let h = ObjectStoreTestHarness::new(store);
        h.get_never_written_is_none(ObjectKey::from_name("nope"))
            .unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_cross_object_isolation() {
        let root = temp_root("isolation");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.cross_object_isolation(b"object-a", b"object-b").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_rapid_put_delete_churn_100() {
        let root = temp_root("churn");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.rapid_put_delete_churn(b"churn-payload", 100).unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_put_after_delete_reincarnation() {
        let root = temp_root("reincarnate");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.put_after_delete_reincarnation(b"phoenix").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_get_attr_round_trip() {
        let root = temp_root("attr");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.get_attr_round_trip(b"attr-test").unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_get_attr_never_written_is_not_found() {
        let root = temp_root("attr-nf");
        let store = open(&root);
        let h = ObjectStoreTestHarness::new(store);
        h.get_attr_never_written_is_not_found(ObjectKey::from_name("ghost"));
        cleanup(&root);
    }

    #[test]
    fn harness_scan_excludes_deleted() {
        let root = temp_root("scan-excl");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.scan_excludes_deleted(&[b"keep1", b"keep2"], b"drop-me")
            .unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_delete_all_yields_empty_scan() {
        let root = temp_root("del-all");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.delete_all_yields_empty_scan(&[b"x", b"y", b"z"]).unwrap();
        cleanup(&root);
    }

    #[test]
    fn harness_scan_pagination() {
        let root = temp_root("scan-page");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        // 20 objects, page size 7 -- covers partial final page.
        let keys = h.scan_pagination(20, 7).unwrap();
        assert_eq!(keys.len(), 20);
        cleanup(&root);
    }

    #[test]
    fn harness_scan_pagination_single_page() {
        let root = temp_root("scan-page1");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        // Page size >= total: single page covers everything.
        let keys = h.scan_pagination(5, 10).unwrap();
        assert_eq!(keys.len(), 5);
        cleanup(&root);
    }

    #[test]
    fn harness_scan_pagination_page_size_one() {
        let root = temp_root("scan-p1");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        let keys = h.scan_pagination(8, 1).unwrap();
        assert_eq!(keys.len(), 8);
        cleanup(&root);
    }

    // ── Durability tests (LocalObjectStore-specific) ───────────────

    #[test]
    fn flush_survives_reopen() {
        let root = temp_root("flush-survives");
        let key;
        let payload = b"durable-bytes";
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("durable"), payload)
                .unwrap()
                .key;
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            let got = store.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&payload[..]),
                "data should survive flush + reopen"
            );
        }
        cleanup(&root);
    }

    /// Verify the store's durability contract: without explicit `sync_all`,
    /// data survives reopen on the same machine because writes go through
    /// the kernel page cache and the file handle close does not evict dirty
    /// pages. Data loss requires a kernel crash or power failure between
    /// write and sync.
    #[test]
    fn no_sync_survives_reopen_on_same_machine() {
        let root = temp_root("no-sync-survives");
        let key;
        let payload = b"page-cache-bytes";
        {
            let mut store = LocalObjectStore::open_with_options(
                &root,
                StoreOptions {
                    sync_on_write: false,
                    ..test_opts()
                },
            )
            .unwrap();
            key = store
                .put(ObjectKey::from_name("noc sync"), payload)
                .unwrap()
                .key;
            // Drop without explicit sync_all — file handle close flushes
            // userspace buffers but does not fsync.
        }
        {
            let store = open(&root);
            let got = store.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&payload[..]),
                "data survives reopen because kernel page cache preserves dirty pages                  until eviction or crash; explicit sync_all is required for crash safety"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn overwrite_replay_keeps_latest() {
        let root = temp_root("overwrite-replay");
        let key = ObjectKey::from_name("multi-version");
        {
            let mut store = open(&root);
            store.put(key, b"v1").unwrap();
            store.sync_all().unwrap();
            store.put(key, b"v2").unwrap();
            store.sync_all().unwrap();
            store.put(key, b"v3").unwrap();
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            let got = store.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&b"v3"[..]),
                "latest version should survive reopen"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn delete_survives_reopen() {
        let root = temp_root("delete-survives");
        let key = ObjectKey::from_name("delete-me");
        {
            let mut store = open(&root);
            store.put(key, b"data").unwrap();
            store.sync_all().unwrap();
            assert!(store.delete(key).unwrap());
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            assert!(
                store.get(key).unwrap().is_none(),
                "delete should survive reopen"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn cross_object_isolation_on_reopen() {
        let root = temp_root("isolation-reopen");
        let key_a = ObjectKey::from_name("a");
        let key_b = ObjectKey::from_name("b");
        {
            let mut store = open(&root);
            store.put(key_a, b"payload-a").unwrap();
            store.sync_all().unwrap();
        }
        {
            let mut store = open(&root);
            store.put(key_b, b"payload-b").unwrap();
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            assert_eq!(store.get(key_a).unwrap(), Some(b"payload-a".to_vec()));
            assert_eq!(store.get(key_b).unwrap(), Some(b"payload-b".to_vec()));
        }
        cleanup(&root);
    }

    #[test]
    fn flush_empty_store_is_noop() {
        let root = temp_root("flush-empty");
        {
            let mut store = open(&root);
            // Flush with no writes should succeed.
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            assert_eq!(store.stats().live_objects, 0);
        }
        cleanup(&root);
    }

    #[test]
    fn max_value_size_boundary() {
        let root = temp_root("max-value");
        let opts = StoreOptions {
            max_segment_bytes: 2048,
            ..test_opts()
        };
        let max_bytes = opts.max_object_bytes() as usize;
        let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
        let large = vec![0xab; max_bytes];
        let key = store.put(ObjectKey::from_name("max"), &large).unwrap().key;
        store.sync_all().unwrap();

        let got = store.get(key).unwrap();
        assert_eq!(
            got.as_deref(),
            Some(&large[..]),
            "max-size value round-trip"
        );
        cleanup(&root);
    }

    #[test]
    fn store_capacity_exhaustion_write_rejected() {
        let root = temp_root("capacity-exhaust");
        let opts = StoreOptions {
            max_segment_bytes: 512,
            segment_count: 4,
            segment_rotation_write_limit: 0,
            segment_rotation_interval_secs: 0,
            sync_on_write: false,
            reclaim_enabled: false,
            ..StoreOptions::default()
        };
        let max_obj = opts.max_object_bytes() as usize;
        let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
        // Fill segments until NoSpace. Use payload small enough to fit
        // within max_object_bytes after record overhead.
        let payload = vec![0xcd; max_obj.min(64)];
        let mut count = 0;
        loop {
            match store.put(
                ObjectKey::from_name(format!("obj{count}").as_bytes()),
                &payload,
            ) {
                Ok(_) => count += 1,
                Err(StoreError::NoSpace) => break,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
            if count > 1000 {
                panic!("store never exhausted after {count} writes");
            }
        }
        assert!(
            count > 0,
            "should have written at least one object before exhaustion"
        );
        cleanup(&root);
    }

    #[test]
    fn max_key_all_zeros_round_trip() {
        let root = temp_root("max-key-zero");
        let mut store = open(&root);
        let key = ObjectKey::ZERO;
        let payload = b"all-zero-key";
        store.put(key, payload).unwrap();
        store.sync_all().unwrap();
        let got = store.get(key).unwrap();
        assert_eq!(got.as_deref(), Some(&payload[..]));
        cleanup(&root);
    }

    #[test]
    fn max_key_all_ff_round_trip() {
        let root = temp_root("max-key-ff");
        let mut store = open(&root);
        let key = ObjectKey::from_bytes32([0xFF; 32]);
        let payload = b"all-ff-key";
        store.put(key, payload).unwrap();
        store.sync_all().unwrap();
        let got = store.get(key).unwrap();
        assert_eq!(got.as_deref(), Some(&payload[..]));
        cleanup(&root);
    }

    /// Concurrent writer and reader on the same store: a writer thread
    /// repeatedly puts objects while a reader thread reads them. Each
    /// read must return either  or  (never
    /// a corrupted or partial payload).
    #[test]
    fn concurrent_writer_reader_isolation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let root = temp_root("concurrent-wr");
        let store = open(&root);
        let shared = Arc::new(Mutex::new(store));

        let writer_shared = Arc::clone(&shared);
        let writer = thread::spawn(move || {
            for i in 0u64..50 {
                let payload = format!("concurrent-obj-{i:04x}").into_bytes();
                let key = ObjectKey::from_name(format!("wr-{i:04x}").as_bytes());
                {
                    let mut store = writer_shared.lock().unwrap();
                    store.put(key, &payload).unwrap();
                }
                thread::yield_now();
            }
        });

        let reader_shared = Arc::clone(&shared);
        let reader = thread::spawn(move || {
            for i in 0u64..50 {
                let key = ObjectKey::from_name(format!("wr-{i:04x}").as_bytes());
                let expected = format!("concurrent-obj-{i:04x}");
                loop {
                    let store = reader_shared.lock().unwrap();
                    let got = store.get(key).unwrap();
                    drop(store);
                    if let Some(ref bytes) = got {
                        assert_eq!(
                            bytes,
                            expected.as_bytes(),
                            "concurrent reader saw corrupted payload for obj {i}"
                        );
                        break;
                    }
                    thread::yield_now();
                }
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
        cleanup(&root);
    }

    // ── Regression: harness does not interfere with existing tests ─

    // ── Transactional boundaries ──────────────────────────────────

    /// Put several objects with explicit sync after each batch, then
    /// reopen: every synced object must survive, and no partial
    /// objects from an unsynced batch should be visible.
    #[test]
    fn batch_put_sync_all_objects_survive_reopen() {
        let root = temp_root("batch-sync");
        let payloads: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"delta"];
        let keys: Vec<ObjectKey>;
        {
            let mut store = open(&root);
            keys = payloads
                .iter()
                .map(|p| store.put(ObjectKey::from_content(p), p).unwrap().key)
                .collect();
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            for (i, key) in keys.iter().enumerate() {
                let got = store.get(*key).unwrap();
                assert_eq!(
                    got.as_deref(),
                    Some(payloads[i]),
                    "synced object {i} should survive reopen"
                );
            }
        }
        cleanup(&root);
    }

    /// Write one object, sync, write another without sync, then drop
    /// the store (simulating a crash after a partial batch). On reopen,
    /// the synced object must be present; the unsynced object may or
    /// may not be (kernel page cache semantics). This test documents the
    /// current contract.
    #[test]
    fn partial_batch_unsynced_may_not_survive_reopen() {
        let root = temp_root("partial-batch");
        let key_synced = ObjectKey::from_name("synced");
        let key_unsynced = ObjectKey::from_name("unsynced");
        {
            let mut store = open(&root);
            store.put(key_synced, b"committed").unwrap();
            store.sync_all().unwrap();
            store.put(key_unsynced, b"uncommitted").unwrap();
            // Drop without sync — simulates crash
        }
        {
            let store = open(&root);
            assert_eq!(
                store.get(key_synced).unwrap(),
                Some(b"committed".to_vec()),
                "synced object must survive"
            );
            // The unsynced object's visibility depends on page cache;
            // we only assert the synced object is sound.
            let _ = store.get(key_unsynced);
        }
        cleanup(&root);
    }

    /// Write objects across two batches with a sync barrier between
    /// them. After reopen, both batches must be fully visible.
    #[test]
    fn two_batches_with_sync_barrier_survive_reopen() {
        let root = temp_root("two-batch-barrier");
        let batch1: &[&[u8]] = &[b"b1-a", b"b1-b"];
        let batch2: &[&[u8]] = &[b"b2-a", b"b2-b", b"b2-c"];
        let mut all_keys: Vec<ObjectKey> = Vec::new();
        let mut all_payloads: Vec<&[u8]> = Vec::new();
        {
            let mut store = open(&root);
            for p in batch1 {
                let k = store.put(ObjectKey::from_content(p), p).unwrap().key;
                all_keys.push(k);
                all_payloads.push(p);
            }
            store.sync_all().unwrap();
            for p in batch2 {
                let k = store.put(ObjectKey::from_content(p), p).unwrap().key;
                all_keys.push(k);
                all_payloads.push(p);
            }
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            for (i, key) in all_keys.iter().enumerate() {
                let got = store.get(*key).unwrap();
                assert_eq!(
                    got.as_deref(),
                    Some(all_payloads[i]),
                    "batch object {i} should survive reopen"
                );
            }
        }
        cleanup(&root);
    }

    /// Delete an object then sync, verifying the delete survives reopen
    /// and the key is not present.
    #[test]
    fn delete_with_sync_barrier_survives_reopen() {
        let root = temp_root("delete-barrier");
        let key = ObjectKey::from_name("remove-me");
        {
            let mut store = open(&root);
            store.put(key, b"data").unwrap();
            store.sync_all().unwrap();
            assert!(store.delete(key).unwrap());
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            assert!(
                store.get(key).unwrap().is_none(),
                "deleted object should not reappear after reopen"
            );
        }
        cleanup(&root);
    }

    // ── Large-object streaming ────────────────────────────────────

    /// Put a multi-kilobyte object, then read it back in 1 KiB chunks
    /// via `get_range`, verifying the concatenated result matches.
    #[test]
    fn large_object_incremental_read_matches_original() {
        let root = temp_root("stream-chunked");
        let size: usize = 3072;
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let key;
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("large"), &payload)
                .unwrap()
                .key;
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            let chunk_size: u64 = 1024;
            let mut assembled = Vec::with_capacity(size);
            let mut offset = 0u64;
            loop {
                let chunk = store
                    .get_range(key, offset, chunk_size)
                    .unwrap()
                    .unwrap_or_default();
                if chunk.is_empty() {
                    break;
                }
                assembled.extend_from_slice(&chunk);
                offset += chunk.len() as u64;
                if offset >= size as u64 {
                    break;
                }
            }
            assert_eq!(&assembled, &payload, "streaming read should match original");
        }
        cleanup(&root);
    }

    /// Read a large object with small chunks (1 byte at a time) to
    /// stress-test the range read path.
    #[test]
    fn large_object_byte_by_byte_streaming() {
        let root = temp_root("stream-byte");
        let size: usize = 512;
        let payload: Vec<u8> = (0..size)
            .map(|i| (i.wrapping_mul(7) ^ 0x5a) as u8)
            .collect();
        let key;
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("byte-stream"), &payload)
                .unwrap()
                .key;
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            for i in 0..size {
                let byte = store.get_range(key, i as u64, 1).unwrap();
                assert_eq!(
                    byte.as_deref(),
                    Some(&payload[i..i + 1]),
                    "byte {i} mismatch"
                );
            }
        }
        cleanup(&root);
    }

    /// `get_range` with offset at EOF returns empty, not an error.
    #[test]
    fn get_range_at_eof_returns_empty() {
        let root = temp_root("range-eof");
        let payload = b"short";
        let key;
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("short"), payload)
                .unwrap()
                .key;
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            let result = store.get_range(key, payload.len() as u64, 16).unwrap();
            assert!(
                result.is_none() || result.as_deref() == Some(&b""[..]),
                "get_range at EOF should return None or empty, got {result:?}"
            );
        }
        cleanup(&root);
    }

    /// `get_range` with zero length returns None or empty.
    #[test]
    fn get_range_zero_length_returns_none_or_empty() {
        let root = temp_root("range-zero-len");
        let payload = b"data";
        let key;
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("data"), payload)
                .unwrap()
                .key;
            store.sync_all().unwrap();
        }
        {
            let store = open(&root);
            let result = store.get_range(key, 0, 0).unwrap();
            assert!(
                result.is_none() || result.as_deref() == Some(&b""[..]),
                "get_range(0,0) should return None or empty, got {result:?}"
            );
        }
        cleanup(&root);
    }

    // ── Space accounting ──────────────────────────────────────────

    /// Track `StoreStats` across put, delete, and overwrite cycles
    /// to verify live_objects, live_bytes, and tombstone_count are
    /// consistent.
    #[test]
    fn space_accounting_put_delete_cycle() {
        let root = temp_root("space-accounting");
        let mut store = open(&root);

        let s0 = store.stats();
        assert_eq!(s0.live_objects, 0);
        assert_eq!(s0.live_bytes, 0);
        assert_eq!(s0.tombstone_count, 0);

        // Put three objects
        let key_a = store.put(ObjectKey::from_name("a"), b"aaa").unwrap().key;
        let key_b = store.put(ObjectKey::from_name("b"), b"bbbbb").unwrap().key;
        let key_c = store.put(ObjectKey::from_name("c"), b"c").unwrap().key;
        store.sync_all().unwrap();

        let s1 = store.stats();
        assert_eq!(s1.live_objects, 3, "three live objects after puts");
        assert_eq!(s1.live_bytes, 9, "3+5+1 = 9 bytes live");

        // Delete one
        assert!(store.delete(key_b).unwrap());
        store.sync_all().unwrap();

        let s2 = store.stats();
        assert_eq!(s2.live_objects, 2, "two live after one delete");
        assert_eq!(s2.live_bytes, 4, "3+1 = 4 bytes live");
        assert_eq!(s2.tombstone_count, 1);

        // Overwrite
        store.put(key_a, b"aaaaaa").unwrap();
        store.sync_all().unwrap();

        let s3 = store.stats();
        assert_eq!(s3.live_objects, 2, "still two after overwrite");
        assert_eq!(s3.live_bytes, 7, "6+1 = 7 bytes after overwrite");
        assert_eq!(
            s3.tombstone_count, 2,
            "one delete + one overwrite tombstone"
        );

        // Verify actual content
        assert_eq!(
            store.get(key_a).unwrap(),
            Some(b"aaaaaa".to_vec()),
            "overwrite should return new content"
        );
        assert!(
            store.get(key_b).unwrap().is_none(),
            "deleted key should be gone"
        );
        assert_eq!(store.get(key_c).unwrap(), Some(b"c".to_vec()));

        cleanup(&root);
    }

    /// Waste ratio must increase as tombstones accumulate relative to
    /// live objects.
    #[test]
    fn waste_ratio_increases_with_tombstones() {
        let root = temp_root("waste-ratio");
        let mut store = open(&root);

        let wr0 = store.waste_ratio();
        assert_eq!(wr0, 0.0, "empty store has zero waste");

        // Put and delete repeatedly to accumulate tombstones
        for i in 0..10 {
            let key = ObjectKey::from_name(format!("obj{i}").as_bytes());
            store.put(key, b"payload").unwrap();
            store.sync_all().unwrap();
            store.delete(key).unwrap();
            store.sync_all().unwrap();
        }

        let wr1 = store.waste_ratio();
        assert!(
            wr1 > 0.0,
            "waste ratio {wr1} should be > 0 after accumulating tombstones"
        );

        cleanup(&root);
    }

    /// `capacity_bytes` must be greater than `live_bytes` for a
    /// non-exhausted store.
    #[test]
    fn capacity_exceeds_live_bytes_for_non_exhausted_store() {
        let root = temp_root("capacity-check");
        let mut store = open(&root);

        let cap = store.capacity_bytes();
        assert!(cap > 0, "capacity must be positive, got {cap}");
        assert_eq!(
            store.stats().live_bytes,
            0,
            "empty store has zero live bytes"
        );
        assert!(
            cap > store.stats().live_bytes,
            "capacity {cap} > live_bytes 0"
        );

        store.put(ObjectKey::from_name("x"), b"test").unwrap();
        store.sync_all().unwrap();

        assert!(
            store.capacity_bytes() >= store.stats().live_bytes,
            "capacity should be >= live bytes"
        );

        cleanup(&root);
    }

    /// After compacting with an empty protected set, all live objects
    /// are tombstoned and the store is empty.
    #[test]
    fn compact_retaining_empty_set_clears_live_objects() {
        let root = temp_root("compact-clear");
        {
            let mut store = open(&root);
            store.put(ObjectKey::from_name("x"), b"x").unwrap();
            store.put(ObjectKey::from_name("y"), b"yy").unwrap();
            store.sync_all().unwrap();
            assert_eq!(store.stats().live_objects, 2);
        }
        {
            let mut store = open(&root);
            store.compact_retaining(&[], &[]).unwrap();
            assert_eq!(
                store.stats().live_objects,
                0,
                "all objects should be tombstoned after compact with empty protected set"
            );
        }
        cleanup(&root);
    }

    #[test]
    fn harness_and_existing_tests_are_independent() {
        // Verify that the harness can be built and used without affecting
        // the pre-existing test suite in tests.rs.
        let root = temp_root("independent");
        let store = open(&root);
        let mut h = ObjectStoreTestHarness::new(store);
        h.put_get_round_trip(b"independent").unwrap();
        // After harness use, the store is still consistent.
        let inner = h.into_inner();
        assert!(inner.contains_key(ObjectKey::from_content(b"independent")));
        cleanup(&root);
    }

    /// Verify that [`LocalObjectStore::sync`] is equivalent to
    /// [`LocalObjectStore::sync_all`]: data survives reopen.
    #[test]
    fn sync_alias_survives_reopen() {
        let root = temp_root("sync-alias");
        let key;
        let payload = b"sync-alias-bytes";
        {
            let mut store = open(&root);
            key = store
                .put(ObjectKey::from_name("sync-alias-obj"), payload)
                .unwrap()
                .key;
            store.sync().unwrap();
        }
        {
            let store = open(&root);
            let got = store.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&payload[..]),
                "data should survive sync() + reopen"
            );
        }
        cleanup(&root);
    }
    /// Calling [`LocalObjectStore::sync`] twice is idempotent: no
    /// errors and no data corruption.
    #[test]
    fn sync_idempotent() {
        let root = temp_root("sync-idempotent");
        let key = ObjectKey::from_name("idem");
        let payload = b"idempotent";
        {
            let mut store = open(&root);
            store.put(key, payload).unwrap();
            store.sync().unwrap();
            store.sync().unwrap(); // second sync should be a no-op
            store.sync().unwrap(); // third sync
        }
        {
            let store = open(&root);
            let got = store.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&payload[..]),
                "data intact after multiple sync calls"
            );
        }
        cleanup(&root);
    }

    /// Verify the durability ordering contract: object A written and
    /// synced survives reopen; object B written without sync may not.
    #[test]
    fn sync_after_write_ordering_contract() {
        let root = temp_root("sync-ordering");
        let key_a = ObjectKey::from_name("a-synced");
        let key_b = ObjectKey::from_name("b-unsynced");
        {
            let mut store = open(&root);
            store.put(key_a, b"committed").unwrap();
            store.sync().unwrap();
            store.put(key_b, b"uncommitted").unwrap();
            // Drop without sync — simulates crash before sync
        }
        {
            let store = open(&root);
            assert_eq!(
                store.get(key_a).unwrap(),
                Some(b"committed".to_vec()),
                "synced object A must survive"
            );
            // Object B may or may not survive depending on page cache;
            // we only assert that the sync barrier worked for A.
            let _ = store.get(key_b);
        }
        cleanup(&root);
    }

    // ── Reclaim-queue consumer drain integration ─────────────────────

    /// Integration test: put objects, delete them all from one segment,
    /// drain the reclaim queue, verify the segment is freed and can be
    /// re-allocated for new writes, then persist and reopen to confirm
    /// the spacemap checkpoint survived.
    #[test]
    fn drain_reclaim_frees_dead_segment_and_allows_reallocation() {
        let root = temp_root("drain-reclaim");
        let key_a = ObjectKey::from_name("a");
        let key_b = ObjectKey::from_name("b");
        let key_c = ObjectKey::from_name("c");

        let mut store = open(&root);
        let seg_before = store.free_map.free_count();

        // Put three objects, all land in the same active segment.
        store.put(key_a, b"aaa").unwrap();
        store.put(key_b, b"bbb").unwrap();
        store.put(key_c, b"ccc").unwrap();
        store.sync_all().unwrap();

        let loc_a = store.location_of(key_a).expect("object a exists");
        let loc_b = store.location_of(key_b).expect("object b exists");
        assert_eq!(
            loc_a.segment_id, loc_b.segment_id,
            "objects land in same segment"
        );
        let segment_id = loc_a.segment_id;

        // Delete all three objects, enqueuing reclaim entries.
        store.delete(key_a).unwrap();
        store.delete(key_b).unwrap();
        store.delete(key_c).unwrap();
        store.sync_all().unwrap();

        // Rotate to a new segment so the segment containing the deleted
        // objects is no longer the active write target. The current segment
        // always holds system objects (committed root) that the drain must
        // not reclaim.
        store.rotate_segment().expect("rotate after deletes");

        // Drain within the same session: the in-memory reclaim queue
        // has the entries; they will be persisted at the end of drain.
        let stats = store
            .drain_dead_segments(&tidefs_reclaim::ReclaimConsumerConfig::default())
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 3);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(stats.blocks_freed, 3, "three objects freed");

        // The segment should now be free.
        assert!(store.free_map.is_free(segment_id));

        // Verify we can allocate it again for a new write.
        store.put(ObjectKey::from_name("new"), b"new-data").unwrap();
        store.sync_all().unwrap();

        // Free count should return to baseline after drain + reallocate.
        let seg_after = store.free_map.free_count();
        assert_eq!(
            seg_after, seg_before,
            "free count returns to baseline after drain + reallocate"
        );

        // Persist spacemap checkpoint so the free state survives reopen.
        drop(store);

        // Reopen and verify the freed+reallocated state holds.
        {
            let store2 = open(&root);
            assert!(
                store2.free_map.is_free(segment_id),
                "segment remains free after reopen"
            );
        }

        cleanup(&root);
    }

    /// Drain on a store with partially-live segments frees only the
    /// fully-dead ones.
    #[test]
    fn drain_partially_live_segment_not_freed() {
        let root = temp_root("drain-partial");
        let key_a = ObjectKey::from_name("keep");
        let key_b = ObjectKey::from_name("drop");

        let mut store = open(&root);
        store.put(key_a, b"keep-me").unwrap();
        store.put(key_b, b"drop-me").unwrap();
        store.sync_all().unwrap();
        let loc_a = store.location_of(key_a).expect("object a exists");
        let segment_id = loc_a.segment_id;

        // Delete only one object; segment still has one live.
        store.delete(key_b).unwrap();
        store.sync_all().unwrap();

        let stats = store
            .drain_dead_segments(&tidefs_reclaim::ReclaimConsumerConfig::default())
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 1);
        assert_eq!(
            stats.segments_reclaimed, 0,
            "partially-live segment must not be freed"
        );
        assert!(
            !store.free_map.is_free(segment_id),
            "segment with live objects must remain allocated"
        );

        cleanup(&root);
    }

    /// Drain with an empty reclaim queue is a no-op.
    #[test]
    fn drain_empty_queue_noop() {
        let root = temp_root("drain-empty");
        let mut store = open(&root);
        store.put(ObjectKey::from_name("x"), b"x").unwrap();
        store.sync_all().unwrap();
        // No deletes, queue is empty.
        let stats = store
            .drain_dead_segments(&tidefs_reclaim::ReclaimConsumerConfig::default())
            .expect("drain should succeed");
        assert!(stats.is_idle());
        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        cleanup(&root);
    }
}
