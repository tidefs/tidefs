//! BLAKE3-verified remove_xattr with intent-log crash safety.
//!
//! [`XattrRemoveStore`] provides persistent `remove_xattr` that:
//!
//! 1. Validates the owner evidence, namespace, and name.
//! 2. Reads the owner-versioned directory to check existence.
//! 3. Records an [`IntentLogRecord::XattrRemove`] tombstone in the
//!    intent-log buffer for crash-safe replay.
//! 4. Deletes the xattr value blob from the local object store.
//! 5. Removes the entry from the owner-versioned xattr directory.
//!
//! Returns `Ok(true)` when the attribute existed and was removed,
//! `Ok(false)` when it did not exist (idempotent no-op).
//!
//! Enabled via the `persistence` feature flag.

#[cfg(not(any(test, feature = "persistence")))]
compile_error!("remove_xattr requires the persistence feature or test");

use std::sync::{Arc, Mutex};

use blake3;
use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
use tidefs_local_object_store::LocalObjectStore;

use crate::persistent::{
    decode_dir, encode_dir, xattr_dir_key, xattr_full_name_bytes, xattr_value_key,
    PersistentXattrError, XattrOwner, MAX_XATTR_NAME_LEN,
};
use crate::xattr_record::XattrNamespace;

// ---------------------------------------------------------------------------
// Namespace helpers
// ---------------------------------------------------------------------------

fn parse_namespace_from_str(ns: &str) -> Result<XattrNamespace, PersistentXattrError> {
    match ns {
        "security" => Ok(XattrNamespace::Security),
        "system" => Ok(XattrNamespace::System),
        "trusted" => Ok(XattrNamespace::Trusted),
        "user" => Ok(XattrNamespace::User),
        _ => Err(PersistentXattrError::InvalidNamespace),
    }
}

fn to_intent_log_namespace(ns: XattrNamespace) -> tidefs_intent_log::XattrNamespace {
    match ns {
        XattrNamespace::Security => tidefs_intent_log::XattrNamespace::Security,
        XattrNamespace::System => tidefs_intent_log::XattrNamespace::System,
        XattrNamespace::Trusted => tidefs_intent_log::XattrNamespace::Trusted,
        XattrNamespace::User => tidefs_intent_log::XattrNamespace::User,
    }
}

// ---------------------------------------------------------------------------
// XattrRemoveStore
// ---------------------------------------------------------------------------

/// Persistent xattr remove store with intent-log crash safety.
///
/// Wraps a [`LocalObjectStore`] for BLAKE3-verified xattr value removal
/// and an [`IntentLogBuffer`] for crash-safe operation recording.
///
/// # Thread safety
///
/// The inner stores are wrapped in `Arc<Mutex<_>>` so that the store
/// can be shared across threads. Write operations hold the object-store
/// lock for the duration of the mutation.
#[derive(Clone)]
pub struct XattrRemoveStore {
    object_store: Arc<Mutex<LocalObjectStore>>,
    intent_log: Arc<IntentLogBuffer>,
}

impl XattrRemoveStore {
    /// Create a new persistent xattr remove store.
    #[must_use]
    pub fn new(
        object_store: Arc<Mutex<LocalObjectStore>>,
        intent_log: Arc<IntentLogBuffer>,
    ) -> Self {
        Self {
            object_store,
            intent_log,
        }
    }

    /// Remove an extended attribute from `owner`.
    ///
    /// Returns `Ok(true)` when the attribute existed and was removed,
    /// `Ok(false)` when it did not exist (idempotent no-op).
    ///
    /// # Arguments
    ///
    /// * `owner` — Inode number plus generation evidence.
    /// * `namespace` — Linux xattr namespace (`user`, `system`,
    ///   `security`, `trusted`).
    /// * `name` — Attribute name bytes (without namespace prefix).
    /// * `txg_id` — Transaction group identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PersistentXattrError`] on validation failure or internal
    /// storage error.
    pub fn remove_xattr(
        &self,
        owner: XattrOwner,
        namespace: &str,
        name: &[u8],
        txg_id: u64,
    ) -> Result<bool, PersistentXattrError> {
        // ── Validation ─────────────────────────────────────────────

        if owner.inode == 0 || owner.generation == 0 {
            return Err(PersistentXattrError::InvalidOwner);
        }

        if namespace.is_empty() || namespace.contains(':') || namespace.len() > 64 {
            return Err(PersistentXattrError::InvalidNamespace);
        }
        let record_ns = parse_namespace_from_str(namespace)?;

        if name.is_empty() || name.contains(&0) {
            return Err(PersistentXattrError::InvalidName);
        }
        if name.len() > MAX_XATTR_NAME_LEN {
            return Err(PersistentXattrError::NameTooLong);
        }

        // ── Lock and check existence ───────────────────────────────

        let mut store = self
            .object_store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let mut dir = self.read_dir(&store, owner)?;
        let full_name = xattr_full_name_bytes(namespace, name);

        if !dir.remove(&full_name) {
            // Attribute does not exist — idempotent no-op.
            return Ok(false);
        }

        // ── Delete value blob ─────────────────────────────────────

        let value_key = xattr_value_key(owner, namespace, name);
        store
            .delete_named(&value_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store delete: {e}")))?;

        // ── Record intent-log tombstone ───────────────────────────

        let key_hash: [u8; 32] = blake3::hash(name).into();
        let intent_ns = to_intent_log_namespace(record_ns);
        let _frame = self.intent_log.append(
            IntentLogRecord::XattrRemove {
                ino: owner.inode,
                namespace: intent_ns,
                key_hash,
            },
            txg_id,
        );

        // ── Update per-inode directory ─────────────────────────────

        self.write_dir(&mut store, owner, &dir)?;

        Ok(true)
    }

    // ------------------------------------------------------------------
    // Directory helpers
    // ------------------------------------------------------------------

    fn read_dir(
        &self,
        store: &LocalObjectStore,
        owner: XattrOwner,
    ) -> Result<std::collections::BTreeSet<Vec<u8>>, PersistentXattrError> {
        let dir_key = xattr_dir_key(owner);
        let data = store
            .get_named(&dir_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store read: {e}")))?;
        match data {
            Some(blob) => decode_dir(&blob).ok_or_else(|| {
                PersistentXattrError::Internal("corrupt xattr directory blob".to_string())
            }),
            None => Ok(std::collections::BTreeSet::new()),
        }
    }

    fn write_dir(
        &self,
        store: &mut LocalObjectStore,
        owner: XattrOwner,
        dir: &std::collections::BTreeSet<Vec<u8>>,
    ) -> Result<(), PersistentXattrError> {
        let dir_key = xattr_dir_key(owner);
        if dir.is_empty() {
            let _ = store
                .delete_named(&dir_key)
                .map_err(|e| PersistentXattrError::Internal(format!("object store delete: {e}")))?;
        } else {
            let blob = encode_dir(dir);
            store
                .put_named(&dir_key, &blob)
                .map_err(|e| PersistentXattrError::Internal(format!("object store write: {e}")))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    use crate::persistent::{encode_dir, xattr_dir_key, xattr_full_name_bytes};

    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_store() -> (XattrRemoveStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-remove-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");
        let intent_log = Arc::new(IntentLogBuffer::new());
        let xrs = XattrRemoveStore::new(Arc::new(Mutex::new(store)), intent_log);
        (xrs, dir)
    }

    fn owner(inode: u64) -> XattrOwner {
        XattrOwner::new(inode, 11)
    }

    /// Helper: pre-populate an xattr entry so tests can remove it.
    fn put_xattr_entry(
        store: &Arc<Mutex<LocalObjectStore>>,
        owner: XattrOwner,
        namespace: &str,
        name: &[u8],
        value: &[u8],
    ) {
        let mut s = store.lock().unwrap();
        // Store the value blob
        let value_key = xattr_value_key(owner, namespace, name);
        s.put_named(&value_key, value).expect("put value");

        // Add to directory
        let dir_key = xattr_dir_key(owner);
        let existing = s.get_named(&dir_key).ok().flatten();
        let mut dir: BTreeSet<Vec<u8>> = match existing {
            Some(data) => decode_dir(&data).unwrap_or_default(),
            None => BTreeSet::new(),
        };
        dir.insert(xattr_full_name_bytes(namespace, name));
        let blob = if dir.is_empty() {
            return;
        } else {
            encode_dir(&dir)
        };
        s.put_named(&dir_key, &blob).expect("put dir");
    }

    #[test]
    fn remove_existing_returns_true() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(1), "user", b"key", b"val");

        let removed = xrs
            .remove_xattr(owner(1), "user", b"key", 1)
            .expect("remove_xattr");
        assert!(removed, "expected true for existing attribute");
    }

    #[test]
    fn remove_missing_returns_false() {
        let (xrs, _dir) = make_store();
        // No pre-populated entry.
        let removed = xrs
            .remove_xattr(owner(1), "user", b"missing", 1)
            .expect("remove_xattr");
        assert!(!removed, "expected false for missing attribute");
    }

    #[test]
    fn remove_deletes_value_blob() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(1), "user", b"del", b"to-delete");

        xrs.remove_xattr(owner(1), "user", b"del", 1).unwrap();

        let s = xrs.object_store.lock().unwrap();
        let value_key = xattr_value_key(owner(1), "user", b"del");
        let blob = s.get_named(&value_key).ok().flatten();
        assert!(blob.is_none(), "value blob should be deleted");
    }

    #[test]
    fn remove_updates_directory() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(10), "user", b"a", b"1");
        put_xattr_entry(&xrs.object_store, owner(10), "user", b"b", b"2");

        xrs.remove_xattr(owner(10), "user", b"a", 1).unwrap();

        let s = xrs.object_store.lock().unwrap();
        let dir_key = xattr_dir_key(owner(10));
        let blob = s.get_named(&dir_key).unwrap().unwrap();
        let dir = decode_dir(&blob).unwrap();
        assert_eq!(dir.len(), 1);
        assert!(dir.contains(b"user:b".as_slice()));
        assert!(!dir.contains(b"user:a".as_slice()));
    }

    #[test]
    fn remove_last_entry_deletes_directory_object() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(5), "user", b"lonely", b"v");

        xrs.remove_xattr(owner(5), "user", b"lonely", 1).unwrap();

        let s = xrs.object_store.lock().unwrap();
        let dir_key = xattr_dir_key(owner(5));
        let data = s.get_named(&dir_key).ok().flatten();
        assert!(data.is_none(), "empty directory should be removed");
    }

    #[test]
    fn remove_records_intent_log_tombstone() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(42), "security", b"selinux", b"ctx");

        xrs.remove_xattr(owner(42), "security", b"selinux", 7)
            .unwrap();

        let frames = xrs.intent_log.drain_since(0);
        let remove_frames: Vec<_> = frames
            .iter()
            .filter(|f| matches!(f.record, IntentLogRecord::XattrRemove { .. }))
            .collect();
        assert_eq!(remove_frames.len(), 1);

        if let IntentLogRecord::XattrRemove {
            ino,
            namespace,
            key_hash,
        } = &remove_frames[0].record
        {
            assert_eq!(*ino, 42);
            assert_eq!(*namespace, tidefs_intent_log::XattrNamespace::Security);
            let expected_key_hash: [u8; 32] = blake3::hash(b"selinux").into();
            assert_eq!(*key_hash, expected_key_hash);
        } else {
            panic!("expected XattrRemove variant");
        }
    }

    #[test]
    fn remove_missing_does_not_record_intent_log() {
        let (xrs, _dir) = make_store();

        xrs.remove_xattr(owner(99), "user", b"nope", 1).unwrap();

        let frames = xrs.intent_log.drain_since(0);
        assert!(frames.is_empty(), "no intent-log for missing attr");
    }

    #[test]
    fn remove_idempotent_twice() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(1), "user", b"twice", b"v");

        let first = xrs
            .remove_xattr(owner(1), "user", b"twice", 1)
            .expect("first remove");
        assert!(first);

        let second = xrs
            .remove_xattr(owner(1), "user", b"twice", 2)
            .expect("second remove");
        assert!(!second);
    }

    #[test]
    fn remove_independent_across_inodes() {
        let (xrs, _dir) = make_store();
        put_xattr_entry(&xrs.object_store, owner(10), "user", b"shared", b"v10");
        put_xattr_entry(&xrs.object_store, owner(20), "user", b"shared", b"v20");

        let r10 = xrs.remove_xattr(owner(10), "user", b"shared", 1).unwrap();
        assert!(r10);

        // 20 should still exist
        let s = xrs.object_store.lock().unwrap();
        let value_key = xattr_value_key(owner(20), "user", b"shared");
        let blob = s.get_named(&value_key).unwrap().unwrap();
        assert_eq!(blob, b"v20");
    }

    #[test]
    fn remove_generation_isolates_reused_inode_number() {
        let (xrs, _dir) = make_store();
        let old_owner = XattrOwner::new(6, 1);
        let new_owner = XattrOwner::new(6, 2);

        put_xattr_entry(&xrs.object_store, old_owner, "user", b"shared", b"old");
        put_xattr_entry(&xrs.object_store, new_owner, "user", b"shared", b"new");

        assert!(xrs
            .remove_xattr(old_owner, "user", b"shared", 1)
            .expect("remove old"));

        let s = xrs.object_store.lock().unwrap();
        assert!(s
            .get_named(&xattr_value_key(old_owner, "user", b"shared"))
            .unwrap()
            .is_none());
        assert_eq!(
            s.get_named(&xattr_value_key(new_owner, "user", b"shared"))
                .unwrap(),
            Some(b"new".to_vec())
        );
        assert!(s.get_named(&xattr_dir_key(old_owner)).unwrap().is_none());
        assert!(s.get_named(&xattr_dir_key(new_owner)).unwrap().is_some());
    }

    #[test]
    fn validation_rejects_empty_name() {
        let (xrs, _dir) = make_store();
        assert_eq!(
            xrs.remove_xattr(owner(1), "user", b"", 1),
            Err(PersistentXattrError::InvalidName)
        );
    }

    #[test]
    fn validation_rejects_bad_namespace() {
        let (xrs, _dir) = make_store();
        assert_eq!(
            xrs.remove_xattr(owner(1), "custom", b"foo", 1),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn validation_rejects_invalid_owner() {
        let (xrs, _dir) = make_store();
        assert_eq!(
            xrs.remove_xattr(XattrOwner::new(0, 1), "user", b"key", 1),
            Err(PersistentXattrError::InvalidOwner)
        );
        assert_eq!(
            xrs.remove_xattr(XattrOwner::new(1, 0), "user", b"key", 1),
            Err(PersistentXattrError::InvalidOwner)
        );
    }
}
