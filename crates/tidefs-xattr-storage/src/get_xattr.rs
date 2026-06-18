// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified get_xattr from persistent storage.
//!
//! [`XattrGetStore`] provides persistent `get_xattr` that:
//!
//! 1. Looks up the sealed [`XattrRecord`] blob by its named key
//!    (`__xattr:{inode}:{generation}:{namespace}:{name}`) in the local
//!    object store.
//! 2. Verifies the BLAKE3-256 domain-separated digest embedded in the
//!    blob.
//! 3. Returns the verified xattr value bytes.
//!
//! Read-only operations never mutate the intent-log buffer. The store
//! only requires a [`LocalObjectStore`] handle.
//!
//! Enabled via the `persistence` feature flag.

#[cfg(not(any(test, feature = "persistence")))]
compile_error!("get_xattr requires the persistence feature or test");

use std::sync::{Arc, Mutex};

use tidefs_local_object_store::LocalObjectStore;

use crate::persistent::{xattr_value_key, PersistentXattrError, XattrOwner, MAX_XATTR_NAME_LEN};
use crate::xattr_record::{XattrNamespace, XattrRecord};

// ---------------------------------------------------------------------------
// XattrGetStore
// ---------------------------------------------------------------------------

/// Persistent xattr read store backed by a [`LocalObjectStore`].
///
/// Reads are lock-free beyond the object-store mutex and do not interact
/// with the intent-log buffer.
///
/// # Thread safety
///
/// The inner [`LocalObjectStore`] is wrapped in an `Arc<Mutex<_>>` so
/// that the store can be shared across threads. Read operations acquire
/// the lock briefly.
#[derive(Clone)]
pub struct XattrGetStore {
    object_store: Arc<Mutex<LocalObjectStore>>,
}

impl XattrGetStore {
    /// Create a new persistent xattr read store.
    #[must_use]
    pub fn new(object_store: Arc<Mutex<LocalObjectStore>>) -> Self {
        Self { object_store }
    }

    /// Get the value of an extended attribute owned by `owner`.
    ///
    /// Returns `Ok(None)` when the attribute does not exist, or
    /// `Ok(Some(value))` with the BLAKE3-verified value bytes.
    ///
    /// # Arguments
    ///
    /// * `owner` — Inode number plus generation evidence.
    /// * `namespace` — Linux xattr namespace (`user`, `system`,
    ///   `security`, `trusted`).
    /// * `name` — Attribute name bytes (without namespace prefix).
    ///
    /// # Errors
    ///
    /// Returns [`PersistentXattrError`] on validation failure, internal
    /// storage error, or BLAKE3 verification failure.
    pub fn get_xattr(
        &self,
        owner: XattrOwner,
        namespace: &str,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, PersistentXattrError> {
        // ── Validation ───────────────────────────────────────────

        if owner.inode == 0 || owner.generation == 0 {
            return Err(PersistentXattrError::InvalidOwner);
        }

        // namespace
        if namespace.is_empty() || namespace.contains(':') || namespace.len() > 64 {
            return Err(PersistentXattrError::InvalidNamespace);
        }
        // Only accept well-known Linux xattr namespaces.
        let expected_namespace = match namespace {
            "security" => XattrNamespace::Security,
            "system" => XattrNamespace::System,
            "trusted" => XattrNamespace::Trusted,
            "user" => XattrNamespace::User,
            _ => return Err(PersistentXattrError::InvalidNamespace),
        };

        // name
        if name.is_empty() || name.contains(&0) {
            return Err(PersistentXattrError::InvalidName);
        }
        if name.len() > MAX_XATTR_NAME_LEN {
            return Err(PersistentXattrError::NameTooLong);
        }

        // ── Lookup and verify ───────────────────────────────────

        let store = self
            .object_store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let value_key = xattr_value_key(owner, namespace, name);

        let blob = store
            .get_named(&value_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store read: {e}")))?;

        match blob {
            Some(data) => {
                let record = XattrRecord::verify(&data).map_err(|e| {
                    PersistentXattrError::Internal(format!(
                        "xattr record BLAKE3 verification failed: {e:?}"
                    ))
                })?;
                if record.inode != owner.inode
                    || record.inode_generation != owner.generation
                    || record.namespace != expected_namespace
                    || record.name != name
                {
                    return Err(PersistentXattrError::Internal(
                        "xattr record owner/key mismatch".to_string(),
                    ));
                }
                Ok(Some(record.value))
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    use crate::persistent::{encode_dir, xattr_dir_key, xattr_full_name_bytes};
    use crate::xattr_record::{XattrNamespace, XattrRecord};

    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_store() -> (XattrGetStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-get-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");
        let xgs = XattrGetStore::new(Arc::new(Mutex::new(store)));
        (xgs, dir)
    }

    fn owner(inode: u64) -> XattrOwner {
        XattrOwner::new(inode, 11)
    }

    /// Helper: write a sealed XattrRecord blob into the object store
    /// and add it to the per-inode directory, mimicking what
    /// [`XattrSetStore::set_xattr`] does.
    fn put_xattr_record(
        store: &Arc<Mutex<LocalObjectStore>>,
        owner: XattrOwner,
        namespace: &str,
        name: &[u8],
        value: &[u8],
        txg_id: u64,
    ) {
        put_xattr_record_with_record_owner(store, owner, owner, namespace, name, value, txg_id);
    }

    fn put_xattr_record_with_record_owner(
        store: &Arc<Mutex<LocalObjectStore>>,
        key_owner: XattrOwner,
        record_owner: XattrOwner,
        namespace: &str,
        name: &[u8],
        value: &[u8],
        txg_id: u64,
    ) {
        let ns = match namespace {
            "security" => XattrNamespace::Security,
            "system" => XattrNamespace::System,
            "trusted" => XattrNamespace::Trusted,
            "user" => XattrNamespace::User,
            _ => panic!("bad namespace in test helper"),
        };
        let record = XattrRecord::new(
            record_owner.inode,
            record_owner.generation,
            ns,
            name.to_vec(),
            value.to_vec(),
            txg_id,
        );
        let blob = record.seal();
        let mut s = store.lock().unwrap();

        // Store by named key
        let value_key = xattr_value_key(key_owner, namespace, name);
        s.put_named(&value_key, &blob).expect("put_named");

        // Update per-inode directory
        let dir_key = xattr_dir_key(key_owner);
        let existing = s.get_named(&dir_key).ok().flatten();
        let mut dir: std::collections::BTreeSet<Vec<u8>> = match existing {
            Some(data) => crate::persistent::decode_dir(&data).unwrap_or_default(),
            None => std::collections::BTreeSet::new(),
        };
        dir.insert(xattr_full_name_bytes(namespace, name));
        let dir_blob = encode_dir(&dir);
        s.put_named(&dir_key, &dir_blob).expect("put_named dir");
    }

    #[test]
    fn get_returns_stored_value() {
        let (xgs, _dir) = make_store();
        put_xattr_record(&xgs.object_store, owner(1), "user", b"comment", b"hello", 1);

        let val = xgs
            .get_xattr(owner(1), "user", b"comment")
            .expect("get_xattr");
        assert_eq!(val, Some(b"hello".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let (xgs, _dir) = make_store();
        let val = xgs
            .get_xattr(owner(1), "user", b"missing")
            .expect("get_xattr");
        assert_eq!(val, None);
    }

    #[test]
    fn get_with_binary_value() {
        let (xgs, _dir) = make_store();
        let bin_val = vec![0x00, 0xFF, 0x42, 0x99];
        put_xattr_record(&xgs.object_store, owner(42), "user", b"binary", &bin_val, 1);

        let val = xgs
            .get_xattr(owner(42), "user", b"binary")
            .expect("get_xattr");
        assert_eq!(val, Some(bin_val));
    }

    #[test]
    fn get_empty_value() {
        let (xgs, _dir) = make_store();
        put_xattr_record(&xgs.object_store, owner(1), "user", b"empty", b"", 1);

        let val = xgs
            .get_xattr(owner(1), "user", b"empty")
            .expect("get_xattr");
        assert_eq!(val, Some(vec![]));
    }

    #[test]
    fn get_rejects_tampered_blob() {
        let (xgs, _dir) = make_store();
        // Write a proper record, then tamper it in-place.
        {
            put_xattr_record(&xgs.object_store, owner(1), "user", b"tamper", b"val", 1);
            let mut s = xgs.object_store.lock().unwrap();
            let value_key = xattr_value_key(owner(1), "user", b"tamper");
            let mut blob = s.get_named(&value_key).unwrap().unwrap();
            // Flip a byte in the value region.
            blob[30] ^= 0xFF;
            s.put_named(&value_key, &blob).expect("put tampered");
        }

        let result = xgs.get_xattr(owner(1), "user", b"tamper");
        match result {
            Err(PersistentXattrError::Internal(msg)) => {
                assert!(
                    msg.contains("BLAKE3 verification"),
                    "expected BLAKE3 error, got: {msg}"
                );
            }
            other => panic!("expected Internal(BLAKE3 verification), got: {other:?}"),
        }
    }

    #[test]
    fn get_all_four_namespaces() {
        let (xgs, _dir) = make_store();
        put_xattr_record(&xgs.object_store, owner(1), "user", b"key", b"user-val", 1);
        put_xattr_record(&xgs.object_store, owner(1), "system", b"key", b"sys-val", 1);
        put_xattr_record(
            &xgs.object_store,
            owner(1),
            "security",
            b"key",
            b"sec-val",
            1,
        );
        put_xattr_record(&xgs.object_store, owner(1), "trusted", b"key", b"tr-val", 1);

        assert_eq!(
            xgs.get_xattr(owner(1), "user", b"key").unwrap(),
            Some(b"user-val".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "system", b"key").unwrap(),
            Some(b"sys-val".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "security", b"key").unwrap(),
            Some(b"sec-val".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "trusted", b"key").unwrap(),
            Some(b"tr-val".to_vec())
        );
    }

    #[test]
    fn get_multiple_inodes_independent() {
        let (xgs, _dir) = make_store();
        put_xattr_record(&xgs.object_store, owner(10), "user", b"a", b"v10", 1);
        put_xattr_record(&xgs.object_store, owner(20), "user", b"a", b"v20", 1);

        assert_eq!(
            xgs.get_xattr(owner(10), "user", b"a").unwrap(),
            Some(b"v10".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(owner(20), "user", b"a").unwrap(),
            Some(b"v20".to_vec())
        );
        // Wrong inode should return None for the name
        assert_eq!(xgs.get_xattr(owner(10), "user", b"b").unwrap(), None);
    }

    #[test]
    fn get_generation_isolates_reused_inode_number() {
        let (xgs, _dir) = make_store();
        let old_owner = XattrOwner::new(7, 1);
        let new_owner = XattrOwner::new(7, 2);

        put_xattr_record(&xgs.object_store, old_owner, "user", b"same", b"old", 1);
        put_xattr_record(&xgs.object_store, new_owner, "user", b"same", b"new", 2);

        assert_eq!(
            xgs.get_xattr(new_owner, "user", b"same").unwrap(),
            Some(b"new".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(old_owner, "user", b"same").unwrap(),
            Some(b"old".to_vec())
        );
    }

    #[test]
    fn get_rejects_misfiled_record_generation() {
        let (xgs, _dir) = make_store();
        let stale_owner = XattrOwner::new(8, 1);
        let current_owner = XattrOwner::new(8, 2);

        put_xattr_record_with_record_owner(
            &xgs.object_store,
            current_owner,
            stale_owner,
            "user",
            b"key",
            b"stale",
            1,
        );

        let result = xgs.get_xattr(current_owner, "user", b"key");
        match result {
            Err(PersistentXattrError::Internal(msg)) => {
                assert!(
                    msg.contains("owner/key mismatch"),
                    "expected owner mismatch, got: {msg}"
                );
            }
            other => panic!("expected owner mismatch error, got: {other:?}"),
        }
    }

    #[test]
    fn validation_rejects_invalid_namespace() {
        let (xgs, _dir) = make_store();
        assert_eq!(
            xgs.get_xattr(owner(1), "custom", b"foo"),
            Err(PersistentXattrError::InvalidNamespace)
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "", b"foo"),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn validation_rejects_invalid_name() {
        let (xgs, _dir) = make_store();
        assert_eq!(
            xgs.get_xattr(owner(1), "user", b""),
            Err(PersistentXattrError::InvalidName)
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "user", b"bad\0nul"),
            Err(PersistentXattrError::InvalidName)
        );
    }

    #[test]
    fn large_value_roundtrip() {
        // Use a store with larger segments for big values.
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-get-large-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let opts = StoreOptions {
            max_segment_bytes: 256 * 1024,
            ..StoreOptions::test_fast()
        };
        let store = LocalObjectStore::open_with_options(&dir, opts).expect("open large store");
        let xgs = XattrGetStore::new(Arc::new(Mutex::new(store)));
        let big = vec![0xABu8; 8192];
        put_xattr_record(&xgs.object_store, owner(1), "user", b"big", &big, 1);
        let val = xgs
            .get_xattr(owner(1), "user", b"big")
            .unwrap()
            .expect("value exists");
        assert_eq!(val, big);
    }

    #[test]
    fn namespace_qualified_names_are_independent() {
        let (xgs, _dir) = make_store();
        put_xattr_record(&xgs.object_store, owner(1), "user", b"key", b"user-v", 1);
        put_xattr_record(
            &xgs.object_store,
            owner(1),
            "trusted",
            b"key",
            b"trusted-v",
            1,
        );

        assert_eq!(
            xgs.get_xattr(owner(1), "user", b"key").unwrap(),
            Some(b"user-v".to_vec())
        );
        assert_eq!(
            xgs.get_xattr(owner(1), "trusted", b"key").unwrap(),
            Some(b"trusted-v".to_vec())
        );
    }
}
