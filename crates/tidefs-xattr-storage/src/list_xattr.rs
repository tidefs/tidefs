//! BLAKE3-verified list_xattr from persistent storage.
//!
//! [`XattrListStore`] provides persistent `list_xattr` that:
//!
//! 1. Reads the per-inode xattr directory blob from the local object
//!    store.
//! 2. Decodes it with BLAKE3-256 integrity verification (the V1
//!    directory format carries an `XDIR` magic, format version, entry
//!    payload, and trailing BLAKE3-256 digest).
//! 3. Returns `(namespace, name)` pairs for each xattr on the inode,
//!    or an empty list when the inode has no xattrs.
//!
//! Read-only; does not interact with the intent-log buffer.
//!
//! Enabled via the `persistence` feature flag.

#[cfg(not(any(test, feature = "persistence")))]
compile_error!("list_xattr requires the persistence feature or test");

use std::sync::{Arc, Mutex};

use tidefs_local_object_store::LocalObjectStore;

use crate::persistent::{decode_dir, split_full_name, xattr_dir_key, PersistentXattrError};

// ---------------------------------------------------------------------------
// XattrListStore
// ---------------------------------------------------------------------------

/// Persistent xattr list store backed by a [`LocalObjectStore`].
///
/// Read-only; acquires the object-store lock briefly per call.
///
/// # Thread safety
///
/// The inner [`LocalObjectStore`] is wrapped in an `Arc<Mutex<_>>` so that
/// the store can be shared across threads.
#[derive(Clone)]
pub struct XattrListStore {
    object_store: Arc<Mutex<LocalObjectStore>>,
}

impl XattrListStore {
    /// Create a new persistent xattr list store.
    #[must_use]
    pub fn new(object_store: Arc<Mutex<LocalObjectStore>>) -> Self {
        Self { object_store }
    }

    /// List all extended attributes for `inode`.
    ///
    /// Returns `Ok(entries)` where each entry is a `(namespace, name)`
    /// pair. The namespace is a `String` (e.g. `"user"`), and the name
    /// is the raw attribute name bytes *without* the namespace prefix.
    ///
    /// Returns an empty vector when the inode has no xattrs.
    ///
    /// # Arguments
    ///
    /// * `inode` — Inode number.
    ///
    /// # Errors
    ///
    /// Returns [`PersistentXattrError`] on internal storage error or
    /// corrupted-directory detection.
    pub fn list_xattr(&self, inode: u64) -> Result<Vec<(String, Vec<u8>)>, PersistentXattrError> {
        let store = self
            .object_store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let dir_key = xattr_dir_key(inode);
        let data = store
            .get_named(&dir_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store read: {e}")))?;

        match data {
            Some(blob) => {
                let dir = decode_dir(&blob).ok_or_else(|| {
                    PersistentXattrError::Internal("corrupt xattr directory blob".to_string())
                })?;
                let mut result = Vec::with_capacity(dir.len());
                for entry in &dir {
                    if let Some((ns, name)) = split_full_name(entry) {
                        result.push((ns.to_string(), name.to_vec()));
                    }
                }
                Ok(result)
            }
            None => Ok(Vec::new()),
        }
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

    use crate::persistent::{encode_dir, xattr_full_name_bytes};

    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_store() -> (XattrListStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-list-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");
        let xls = XattrListStore::new(Arc::new(Mutex::new(store)));
        (xls, dir)
    }

    /// Helper: write a per-inode directory with the given namespace:name
    /// entries.  This mimics what [`XattrSetStore::set_xattr`] does to
    /// the directory object.
    fn put_dir_entries(
        store: &Arc<Mutex<LocalObjectStore>>,
        inode: u64,
        entries: &[(&str, &[u8])],
    ) {
        let mut dir = BTreeSet::new();
        for (ns, name) in entries {
            dir.insert(xattr_full_name_bytes(ns, name));
        }
        let dir_key = xattr_dir_key(inode);
        let blob = if dir.is_empty() {
            // Delete any existing dir
            let mut s = store.lock().unwrap();
            let _ = s.delete_named(&dir_key);
            return;
        } else {
            encode_dir(&dir)
        };
        let mut s = store.lock().unwrap();
        s.put_named(&dir_key, &blob).expect("put_named dir");
    }

    #[test]
    fn list_returns_entries() {
        let (xls, _dir) = make_store();
        put_dir_entries(
            &xls.object_store,
            1,
            &[("user", b"a"), ("user", b"b"), ("system", b"c")],
        );

        let entries = xls.list_xattr(1).expect("list_xattr");
        assert_eq!(entries.len(), 3);
        assert!(entries.contains(&("user".to_string(), b"a".to_vec())));
        assert!(entries.contains(&("user".to_string(), b"b".to_vec())));
        assert!(entries.contains(&("system".to_string(), b"c".to_vec())));
    }

    #[test]
    fn list_empty_inode_returns_empty() {
        let (xls, _dir) = make_store();
        let entries = xls.list_xattr(99).expect("list_xattr");
        assert!(entries.is_empty());
    }

    #[test]
    fn list_after_removing_last_entry() {
        let (xls, _dir) = make_store();
        put_dir_entries(&xls.object_store, 42, &[("user", b"lonely")]);
        let entries = xls.list_xattr(42).expect("first list");
        assert_eq!(entries.len(), 1);

        // Remove the entry by writing an empty directory
        put_dir_entries(&xls.object_store, 42, &[]);
        let entries2 = xls.list_xattr(42).expect("second list");
        assert!(entries2.is_empty());
    }

    #[test]
    fn list_multiple_inodes_independent() {
        let (xls, _dir) = make_store();
        put_dir_entries(&xls.object_store, 10, &[("user", b"a")]);
        put_dir_entries(
            &xls.object_store,
            20,
            &[("trusted", b"b"), ("security", b"c")],
        );

        let e10 = xls.list_xattr(10).expect("list 10");
        let e20 = xls.list_xattr(20).expect("list 20");
        assert_eq!(e10.len(), 1);
        assert_eq!(e20.len(), 2);
    }

    #[test]
    fn list_all_four_namespaces() {
        let (xls, _dir) = make_store();
        put_dir_entries(
            &xls.object_store,
            1,
            &[
                ("user", b"u"),
                ("system", b"s"),
                ("security", b"sec"),
                ("trusted", b"t"),
            ],
        );

        let entries = xls.list_xattr(1).expect("list");
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn list_returns_corrupt_directory_as_error() {
        let (xls, _dir) = make_store();
        // Write a corrupt blob directly into the store.
        {
            let mut s = xls.object_store.lock().unwrap();
            let dir_key = xattr_dir_key(1);
            s.put_named(&dir_key, b"not a real directory")
                .expect("put corrupt");
        }

        let result = xls.list_xattr(1);
        match result {
            Err(PersistentXattrError::Internal(msg)) => {
                assert!(
                    msg.contains("corrupt"),
                    "expected corrupt error, got: {msg}"
                );
            }
            other => panic!("expected Internal(corrupt ...), got: {other:?}"),
        }
    }

    #[test]
    fn list_detects_tampered_directory() {
        let (xls, _dir) = make_store();
        put_dir_entries(&xls.object_store, 1, &[("user", b"tamper")]);

        // Tamper the directory blob in place.
        {
            let mut s = xls.object_store.lock().unwrap();
            let dir_key = xattr_dir_key(1);
            let mut blob = s.get_named(&dir_key).unwrap().expect("dir exists");
            // Flip a byte in the payload region (after magic + version).
            blob[6] ^= 0xFF;
            s.put_named(&dir_key, &blob).expect("put tampered");
        }

        let result = xls.list_xattr(1);
        assert!(result.is_err(), "expected error on tampered dir");
    }
}
