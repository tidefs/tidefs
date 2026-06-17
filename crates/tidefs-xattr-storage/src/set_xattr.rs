//! BLAKE3-verified set_xattr with intent-log crash safety.
//!
//! [`XattrSetStore`] provides persistent `set_xattr` that:
//!
//! 1. Validates the namespace, name, value, and POSIX flags.
//! 2. BLAKE3-hashes the name and value for the intent-log record.
//! 3. Creates an [`XattrRecord`], seals it with a BLAKE3-256
//!    domain-separated digest, and stores it in the local object store
//!    under the owner-versioned named key.
//! 4. Records an [`IntentLogRecord::XattrSet`] in the intent-log buffer.
//! 5. Updates the owner-versioned xattr directory for enumeration.
//!
//! Enabled via the `persistence` feature flag.

#[cfg(not(any(test, feature = "persistence")))]
compile_error!("set_xattr requires the persistence feature or test");

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use blake3;
use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
use tidefs_local_object_store::LocalObjectStore;

use crate::persistent::{
    decode_dir, encode_dir, xattr_dir_key, xattr_full_name_bytes, xattr_value_key,
    PersistentXattrError, XattrOwner, MAX_XATTR_COUNT, MAX_XATTR_NAME_LEN, MAX_XATTR_VALUE_LEN,
    XATTR_CREATE, XATTR_REPLACE,
};
use crate::xattr_record::{XattrNamespace, XattrRecord};

// ---------------------------------------------------------------------------
// Namespace helpers
// ---------------------------------------------------------------------------

/// Map a string namespace to the record-level [`XattrNamespace`].
///
/// Only the four well-known Linux xattr namespaces are accepted.
fn parse_namespace(ns: &str) -> Result<XattrNamespace, PersistentXattrError> {
    match ns {
        "security" => Ok(XattrNamespace::Security),
        "system" => Ok(XattrNamespace::System),
        "trusted" => Ok(XattrNamespace::Trusted),
        "user" => Ok(XattrNamespace::User),
        _ => Err(PersistentXattrError::InvalidNamespace),
    }
}

/// Convert from record-level [`XattrNamespace`] to intent-log
/// [`tidefs_intent_log::XattrNamespace`].
fn to_intent_log_namespace(ns: XattrNamespace) -> tidefs_intent_log::XattrNamespace {
    match ns {
        XattrNamespace::Security => tidefs_intent_log::XattrNamespace::Security,
        XattrNamespace::System => tidefs_intent_log::XattrNamespace::System,
        XattrNamespace::Trusted => tidefs_intent_log::XattrNamespace::Trusted,
        XattrNamespace::User => tidefs_intent_log::XattrNamespace::User,
    }
}

// ---------------------------------------------------------------------------
// XattrSetStore
// ---------------------------------------------------------------------------

/// Persistent xattr set store with intent-log crash safety.
///
/// Wraps a [`LocalObjectStore`] for BLAKE3-verified xattr value
/// persistence and an [`IntentLogBuffer`] for crash-safe operation
/// recording.
///
/// # Thread safety
///
/// The inner stores are wrapped in `Arc<Mutex<_>>` so that the store
/// can be shared across threads. Write operations hold the object-store
/// lock for the duration of the mutation.
#[derive(Clone)]
pub struct XattrSetStore {
    object_store: Arc<Mutex<LocalObjectStore>>,
    intent_log: Arc<IntentLogBuffer>,
}

impl XattrSetStore {
    /// Create a new persistent xattr set store.
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

    /// Set an extended attribute for `owner` with intent-log crash safety.
    ///
    /// # Arguments
    ///
    /// * `owner` — Inode number plus generation evidence.
    /// * `namespace` — Linux xattr namespace (`user`, `system`,
    ///   `security`, `trusted`).
    /// * `name` — Attribute name bytes (without namespace prefix).
    /// * `value` — Attribute value bytes.
    /// * `flags` — POSIX setxattr flags: 0 (upsert), [`XATTR_CREATE`],
    ///   or [`XATTR_REPLACE`].
    /// * `txg_id` — Transaction group identifier assigned by the
    ///   [`TxgCoordinator`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistentXattrError`] on validation failure, flag
    /// precondition violation, count-limit exhaustion, or internal
    /// storage error.
    pub fn set_xattr(
        &self,
        owner: XattrOwner,
        namespace: &str,
        name: &[u8],
        value: &[u8],
        flags: u32,
        txg_id: u64,
    ) -> Result<(), PersistentXattrError> {
        // ── Validation ─────────────────────────────────────────────

        if owner.inode == 0 || owner.generation == 0 {
            return Err(PersistentXattrError::InvalidOwner);
        }

        // namespace
        if namespace.is_empty() || namespace.contains(':') || namespace.len() > 64 {
            return Err(PersistentXattrError::InvalidNamespace);
        }
        let record_ns = parse_namespace(namespace)?;

        // name
        if name.is_empty() || name.contains(&0) {
            return Err(PersistentXattrError::InvalidName);
        }
        if name.len() > MAX_XATTR_NAME_LEN {
            return Err(PersistentXattrError::NameTooLong);
        }

        // value
        if value.len() > MAX_XATTR_VALUE_LEN {
            return Err(PersistentXattrError::ValueTooLarge);
        }

        // flags
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(PersistentXattrError::InvalidFlags);
        }

        // ── Lock and check preconditions ───────────────────────────

        let mut store = self
            .object_store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let mut dir = self.read_dir(&store, owner)?;
        let full_name = xattr_full_name_bytes(namespace, name);

        match flags {
            XATTR_CREATE => {
                if dir.contains(&full_name) {
                    return Err(PersistentXattrError::AttrExists);
                }
                if dir.len() >= MAX_XATTR_COUNT {
                    return Err(PersistentXattrError::InodeXattrLimit);
                }
            }
            XATTR_REPLACE => {
                if !dir.contains(&full_name) {
                    return Err(PersistentXattrError::AttrNotFound);
                }
            }
            _ => {
                if !dir.contains(&full_name) && dir.len() >= MAX_XATTR_COUNT {
                    return Err(PersistentXattrError::InodeXattrLimit);
                }
            }
        }

        // ── BLAKE3 hashes for intent-log ───────────────────────────

        // key_hash: BLAKE3-256 of the raw xattr name (matching
        // local-filesystem convention). The namespace is a separate
        // field in the intent-log record.
        let key_hash: [u8; 32] = blake3::hash(name).into();

        // value_hash: BLAKE3-256 of the raw xattr value.
        let value_hash: [u8; 32] = blake3::hash(value).into();

        // ── Create and persist XattrRecord blob ────────────────────

        let record = XattrRecord::new(
            owner.inode,
            owner.generation,
            record_ns,
            name.to_vec(),
            value.to_vec(),
            txg_id,
        );

        // Store the sealed blob keyed by its content hash so reads
        // can BLAKE3-verify the on-disk record.
        let content_hash = record.content_hash();
        let blob = record.seal();
        let blob_key = format!("__xattr_blob:{}", hex::encode(&content_hash));
        store
            .put_named(&blob_key, &blob)
            .map_err(|e| PersistentXattrError::Internal(format!("object store write: {e}")))?;

        // Also store by named key for lookup by inode:namespace:name.
        let value_key = xattr_value_key(owner, namespace, name);
        store
            .put_named(&value_key, &blob)
            .map_err(|e| PersistentXattrError::Internal(format!("object store write: {e}")))?;

        // ── Record intent-log entry ────────────────────────────────

        let intent_ns = to_intent_log_namespace(record_ns);
        let _frame = self.intent_log.append(
            IntentLogRecord::XattrSet {
                ino: owner.inode,
                namespace: intent_ns,
                key_hash,
                value_hash,
            },
            txg_id,
        );

        // ── Update per-inode directory ─────────────────────────────

        dir.insert(full_name);
        self.write_dir(&mut store, owner, &dir)?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Directory helpers (mirrors persistent.rs pattern)
    // ------------------------------------------------------------------

    /// Read the per-inode directory set, returning an empty set when
    /// no directory object exists yet.
    fn read_dir(
        &self,
        store: &LocalObjectStore,
        owner: XattrOwner,
    ) -> Result<BTreeSet<Vec<u8>>, PersistentXattrError> {
        let dir_key = xattr_dir_key(owner);
        let data = store
            .get_named(&dir_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store read: {e}")))?;
        match data {
            Some(blob) => decode_dir(&blob).ok_or_else(|| {
                PersistentXattrError::Internal("corrupt xattr directory blob".to_string())
            }),
            None => Ok(BTreeSet::new()),
        }
    }

    /// Write the per-inode directory set. Deletes the key when the set
    /// is empty.
    fn write_dir(
        &self,
        store: &mut LocalObjectStore,
        owner: XattrOwner,
        dir: &BTreeSet<Vec<u8>>,
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
// hex encode helper (minimal, no_std-compatible)
// ---------------------------------------------------------------------------

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
        }
        s
    }

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_store() -> (XattrSetStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-set-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");
        let intent_log = Arc::new(IntentLogBuffer::new());
        let xss = XattrSetStore::new(Arc::new(Mutex::new(store)), intent_log);
        (xss, dir)
    }

    fn owner(inode: u64) -> XattrOwner {
        XattrOwner::new(inode, 11)
    }

    #[test]
    fn set_get_roundtrip_via_object_store() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(1), "user", b"key1", b"val1", 0, 1)
            .expect("set_xattr");

        // Verify the blob was stored under the named key.
        let store = xss.object_store.lock().unwrap();
        let value_key = xattr_value_key(owner(1), "user", b"key1");
        let blob = store.get_named(&value_key).expect("get").expect("exists");
        let record = XattrRecord::verify(&blob).expect("verify");
        assert_eq!(record.inode, 1);
        assert_eq!(record.inode_generation, 11);
        assert_eq!(record.namespace, XattrNamespace::User);
        assert_eq!(record.name, b"key1".to_vec());
        assert_eq!(record.value, b"val1".to_vec());
    }

    #[test]
    fn intent_log_has_xattr_set_record() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(42), "security", b"selinux", b"ctx", 0, 7)
            .expect("set_xattr");

        // Drain the intent-log buffer and check for XattrSet.
        let frames = xss.intent_log.drain_since(0);
        let xattr_frames: Vec<_> = frames
            .iter()
            .filter(|f| matches!(f.record, IntentLogRecord::XattrSet { .. }))
            .collect();
        assert_eq!(xattr_frames.len(), 1);

        if let IntentLogRecord::XattrSet {
            ino,
            namespace,
            key_hash,
            value_hash,
        } = &xattr_frames[0].record
        {
            assert_eq!(*ino, 42);
            assert_eq!(*namespace, tidefs_intent_log::XattrNamespace::Security);
            // key_hash must match blake3::hash(b"selinux")
            let expected_key_hash: [u8; 32] = blake3::hash(b"selinux").into();
            assert_eq!(*key_hash, expected_key_hash);
            // value_hash must match blake3::hash(b"ctx")
            let expected_value_hash: [u8; 32] = blake3::hash(b"ctx").into();
            assert_eq!(*value_hash, expected_value_hash);
        } else {
            panic!("expected XattrSet variant");
        }
    }

    #[test]
    fn create_flag_succeeds_on_new() {
        let (xss, _dir) = make_store();
        assert!(xss
            .set_xattr(owner(1), "user", b"newkey", b"val", XATTR_CREATE, 1)
            .is_ok());
    }

    #[test]
    fn create_flag_fails_on_existing() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(1), "user", b"dup", b"first", 0, 1)
            .expect("first set");
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"dup", b"second", XATTR_CREATE, 2),
            Err(PersistentXattrError::AttrExists)
        );
    }

    #[test]
    fn replace_flag_succeeds_on_existing() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(1), "user", b"rep", b"old", 0, 1)
            .expect("first set");
        assert!(xss
            .set_xattr(owner(1), "user", b"rep", b"new", XATTR_REPLACE, 2)
            .is_ok());
    }

    #[test]
    fn replace_flag_fails_on_missing() {
        let (xss, _dir) = make_store();
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"missing", b"val", XATTR_REPLACE, 1),
            Err(PersistentXattrError::AttrNotFound)
        );
    }

    #[test]
    fn invalid_flags_rejected() {
        let (xss, _dir) = make_store();
        assert_eq!(
            xss.set_xattr(
                owner(1),
                "user",
                b"key",
                b"val",
                XATTR_CREATE | XATTR_REPLACE,
                1
            ),
            Err(PersistentXattrError::InvalidFlags)
        );
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"key", b"val", 4, 1),
            Err(PersistentXattrError::InvalidFlags)
        );
    }

    #[test]
    fn directory_tracks_entries() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(1), "user", b"a", b"1", 0, 1)
            .expect("set a");
        xss.set_xattr(owner(1), "user", b"b", b"2", 0, 2)
            .expect("set b");
        xss.set_xattr(owner(1), "system", b"c", b"3", 0, 3)
            .expect("set c");

        let store = xss.object_store.lock().unwrap();
        let dir = xss.read_dir(&store, owner(1)).expect("read_dir");
        assert_eq!(dir.len(), 3);
        assert!(dir.contains(b"user:a".as_slice()));
        assert!(dir.contains(b"user:b".as_slice()));
        assert!(dir.contains(b"system:c".as_slice()));
    }

    #[test]
    fn count_limit_enforced() {
        let (xss, _dir) = make_store();
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("key{i}");
            xss.set_xattr(owner(1), "user", name.as_bytes(), b"val", 0, i as u64)
                .expect("set within limit");
        }
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"overlimit", b"val", 0, 999),
            Err(PersistentXattrError::InodeXattrLimit)
        );
    }

    #[test]
    fn validation_rejects_empty_name() {
        let (xss, _dir) = make_store();
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"", b"val", 0, 1),
            Err(PersistentXattrError::InvalidName)
        );
    }

    #[test]
    fn validation_rejects_bad_namespace() {
        let (xss, _dir) = make_store();
        assert_eq!(
            xss.set_xattr(owner(1), "custom", b"foo", b"val", 0, 1),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn validation_rejects_value_too_large() {
        let (xss, _dir) = make_store();
        let big = vec![0xCC; MAX_XATTR_VALUE_LEN + 1];
        assert_eq!(
            xss.set_xattr(owner(1), "user", b"big", &big, 0, 1),
            Err(PersistentXattrError::ValueTooLarge)
        );
    }

    #[test]
    fn upsert_replaces_and_intent_log_reflects_latest() {
        let (xss, _dir) = make_store();
        // Initial set
        xss.set_xattr(owner(1), "user", b"key", b"old", 0, 1)
            .expect("first set");
        // Drain to skip first record
        let _ = xss.intent_log.drain_since(0);

        // Upsert
        xss.set_xattr(owner(1), "user", b"key", b"new", 0, 2)
            .expect("upsert");

        // Check the blob was updated
        let store = xss.object_store.lock().unwrap();
        let value_key = xattr_value_key(owner(1), "user", b"key");
        let blob = store.get_named(&value_key).expect("get").expect("exists");
        let record = XattrRecord::verify(&blob).expect("verify");
        assert_eq!(record.value, b"new".to_vec());

        // Intent log has second record
        let frames = xss.intent_log.drain_since(0);
        let xattr_frames: Vec<_> = frames
            .iter()
            .filter(|f| matches!(f.record, IntentLogRecord::XattrSet { .. }))
            .collect();
        assert_eq!(xattr_frames.len(), 1);
    }

    #[test]
    fn multiple_inodes_independent() {
        let (xss, _dir) = make_store();
        xss.set_xattr(owner(1), "user", b"key1", b"v1", 0, 1)
            .expect("set 1");
        xss.set_xattr(owner(2), "user", b"key2", b"v2", 0, 2)
            .expect("set 2");

        let store = xss.object_store.lock().unwrap();
        let dir1 = xss.read_dir(&store, owner(1)).expect("dir1");
        let dir2 = xss.read_dir(&store, owner(2)).expect("dir2");
        assert_eq!(dir1.len(), 1);
        assert_eq!(dir2.len(), 1);
    }

    #[test]
    fn generation_isolates_reused_inode_number() {
        let (xss, _dir) = make_store();
        let old_owner = XattrOwner::new(9, 1);
        let new_owner = XattrOwner::new(9, 2);

        xss.set_xattr(old_owner, "user", b"key", b"old", 0, 1)
            .expect("old set");
        xss.set_xattr(new_owner, "user", b"key", b"new", XATTR_CREATE, 2)
            .expect("new set");

        let store = xss.object_store.lock().unwrap();
        let old_blob = store
            .get_named(&xattr_value_key(old_owner, "user", b"key"))
            .expect("old get")
            .expect("old exists");
        let new_blob = store
            .get_named(&xattr_value_key(new_owner, "user", b"key"))
            .expect("new get")
            .expect("new exists");
        let old_record = XattrRecord::verify(&old_blob).expect("old verify");
        let new_record = XattrRecord::verify(&new_blob).expect("new verify");

        assert_eq!(old_record.inode_generation, old_owner.generation);
        assert_eq!(old_record.value, b"old".to_vec());
        assert_eq!(new_record.inode_generation, new_owner.generation);
        assert_eq!(new_record.value, b"new".to_vec());
        assert_eq!(xss.read_dir(&store, old_owner).unwrap().len(), 1);
        assert_eq!(xss.read_dir(&store, new_owner).unwrap().len(), 1);
    }

    #[test]
    fn validation_rejects_invalid_owner() {
        let (xss, _dir) = make_store();
        assert_eq!(
            xss.set_xattr(XattrOwner::new(0, 1), "user", b"key", b"val", 0, 1),
            Err(PersistentXattrError::InvalidOwner)
        );
        assert_eq!(
            xss.set_xattr(XattrOwner::new(1, 0), "user", b"key", b"val", 0, 1),
            Err(PersistentXattrError::InvalidOwner)
        );
    }
}
