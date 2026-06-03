//! Persistent xattr store backed by [`tidefs_local_object_store::LocalObjectStore`].
//!
//! Provides [`ObjXattrStore`], an [`XattrStore`]
//! implementation that stores per-inode extended attributes as a single
//! binary blob keyed by `xattr:<ino>` in the local object store.
//!
//! # On-disk format
//!
//! Each per-inode xattr blob is a binary record:
//!
//! ```text
//! Offset  Size  Field
//! 0       4     count: u32 LE (number of entries)
//! 4       var   entries...
//!
//! Each entry:
//!   name_len:  u16 LE
//!   name:      [u8; name_len]
//!   value_len: u32 LE
//!   value:     [u8; value_len]
//! ```
//!
//! An empty set encodes as count=0 (four zero bytes). When all xattrs
//! for an inode are removed, the object-store key is deleted.
//!
//! # Read-modify-write
//!
//! Every mutation reads the current blob from the object store,
//! deserializes it, applies the change, serializes, and writes back.
//! The store uses `Arc<Mutex<LocalObjectStore>>` for interior
//! mutability so the [`XattrStore`] trait methods can take `&self`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

use crate::xattr::{XattrError, XattrKey, XattrStore, XattrValue, XATTR_CREATE, XATTR_REPLACE};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Key prefix for per-inode xattr blobs in the named object-store API.
const XATTR_KEY_PREFIX: &str = "xattr:";

/// Maximum number of extended attributes per inode.
pub const MAX_XATTR_COUNT: usize = 256;

/// Maximum size of a single extended attribute value (64 KiB).
pub const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Binary serialization
// ---------------------------------------------------------------------------

/// Encode a per-inode xattr map into a binary blob.
fn encode_xattrs(xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(xattrs.len() as u32).to_le_bytes());
    for (name, value) in xattrs {
        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        buf.extend_from_slice(name);
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value);
    }
    buf
}

/// Decode a binary xattr blob back into a per-inode map.
///
/// Returns `None` when the data is corrupt or truncated.
fn decode_xattrs(data: &[u8]) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut xattrs = BTreeMap::new();
    let mut pos = 0;
    if data.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;

    for _ in 0..count {
        if pos + 2 > data.len() {
            return None;
        }
        let name_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + name_len + 4 > data.len() {
            return None;
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        let value_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + value_len > data.len() {
            return None;
        }
        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;
        xattrs.insert(name, value);
    }
    Some(xattrs)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Build the named key for a per-inode xattr blob.
fn xattr_key(ino: u64) -> String {
    format!("{XATTR_KEY_PREFIX}{ino}")
}

// ---------------------------------------------------------------------------
// ObjXattrStore
// ---------------------------------------------------------------------------

/// A persistent [`XattrStore`] backed by a
/// [`tidefs_local_object_store::LocalObjectStore`].
///
/// Each inode's extended attributes are stored as a single binary blob
/// under the key `xattr:<ino>`. Mutations use read-modify-write.
///
/// # Examples
///
/// ```rust
/// use tidefs_inode_attributes::xattr::{XattrStore, XATTR_CREATE, XATTR_REPLACE};
/// use tidefs_inode_attributes::obj_xattr_store::ObjXattrStore;
/// use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
///
/// let dir = tempfile::tempdir().unwrap();
/// let store = LocalObjectStore::open_with_options(
///     dir.path(),
///     StoreOptions::test_fast(),
/// ).unwrap();
/// let xattrs = ObjXattrStore::new(store);
/// xattrs.set(1, b"user.mykey", b"myvalue", 0).unwrap();
/// assert_eq!(xattrs.get(1, b"user.mykey").unwrap(), b"myvalue");
/// ```
#[derive(Debug)]
pub struct ObjXattrStore {
    store: Arc<Mutex<LocalObjectStore>>,
}

impl ObjXattrStore {
    /// Create a new [`ObjXattrStore`] wrapping `store`.
    #[must_use]
    pub fn new(store: LocalObjectStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Open a store at `root` with `options`.
    pub fn open(
        root: impl AsRef<std::path::Path>,
        options: StoreOptions,
    ) -> Result<Self, tidefs_local_object_store::StoreError> {
        let store = LocalObjectStore::open_with_options(root, options)?;
        Ok(Self::new(store))
    }

    /// Return a reference to the underlying [`LocalObjectStore`]'s `Arc`.
    #[must_use]
    pub fn store_arc(&self) -> &Arc<Mutex<LocalObjectStore>> {
        &self.store
    }

    // ── internal helpers ──────────────────────────────────────────────

    /// Read the deserialized xattr map for `ino` from the object store.
    ///
    /// Returns an empty map when no blob has been written yet.
    fn read_xattrs(&self, ino: u64) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, XattrError> {
        let store = self.store.lock().expect("Mutex poisoned");
        let key = xattr_key(ino);
        let data = store
            .get_named(&key)
            .map_err(|e| XattrError::Internal(format!("object store read: {e}")))?;
        match data {
            Some(blob) => decode_xattrs(&blob)
                .ok_or_else(|| XattrError::Internal("corrupt xattr blob".to_string())),
            None => Ok(BTreeMap::new()),
        }
    }

    /// Write the xattr map for `ino` to the object store.
    ///
    /// When the map is empty, the key is deleted from the store.
    fn write_xattrs(
        &self,
        ino: u64,
        xattrs: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), XattrError> {
        let mut store = self.store.lock().expect("Mutex poisoned");
        let key = xattr_key(ino);
        if xattrs.is_empty() {
            // Delete the key to free space; ignore missing-key errors.
            let _ = store
                .delete_named(&key)
                .map_err(|e| XattrError::Internal(format!("object store delete: {e}")))?;
        } else {
            let blob = encode_xattrs(xattrs);
            store
                .put_named(&key, &blob)
                .map_err(|e| XattrError::Internal(format!("object store write: {e}")))?;
        }
        Ok(())
    }
}

impl XattrStore for ObjXattrStore {
    fn get(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, XattrError> {
        let _key = XattrKey::new(name)?;
        let xattrs = self.read_xattrs(ino)?;
        xattrs.get(name).cloned().ok_or(XattrError::AttrNotFound)
    }

    fn set(&self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), XattrError> {
        // Validate key and value.
        let _key = XattrKey::new(name)?;
        let _value = XattrValue::new(value.to_vec())?;

        // Reject invalid flag combinations.
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(XattrError::InvalidName);
        }

        // Enforce per-inode count and per-value size limits.
        if value.len() > MAX_XATTR_VALUE_LEN {
            return Err(XattrError::ValueTooLarge);
        }

        let mut xattrs = self.read_xattrs(ino)?;

        match flags {
            XATTR_CREATE => {
                if xattrs.contains_key(name) {
                    return Err(XattrError::AttrExists);
                }
                if xattrs.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
            XATTR_REPLACE => {
                if !xattrs.contains_key(name) {
                    return Err(XattrError::AttrNotFound);
                }
            }
            _ => {
                // flags == 0: create or replace.
                if !xattrs.contains_key(name) && xattrs.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
        }

        xattrs.insert(name.to_vec(), value.to_vec());
        self.write_xattrs(ino, &xattrs)
    }

    fn list(&self, ino: u64) -> Result<Vec<u8>, XattrError> {
        let xattrs = self.read_xattrs(ino)?;
        let mut buf = Vec::new();
        for name in xattrs.keys() {
            buf.extend_from_slice(name);
            buf.push(0);
        }
        Ok(buf)
    }

    fn remove(&self, ino: u64, name: &[u8]) -> Result<(), XattrError> {
        let _key = XattrKey::new(name)?;
        let mut xattrs = self.read_xattrs(ino)?;
        if xattrs.remove(name).is_none() {
            return Err(XattrError::AttrNotFound);
        }
        self.write_xattrs(ino, &xattrs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xattr::{XATTR_CREATE, XATTR_REPLACE};

    /// Create a store with durable options (large segment size) so
    /// tests with 64 KiB values don't hit the segment limit.
    fn make_store() -> (ObjXattrStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::durable())
            .expect("open store");
        (ObjXattrStore::new(store), dir)
    }

    // ── basic get/set round-trip ──────────────────────────────────────

    #[test]
    fn obj_set_get_roundtrip() {
        let (store, _dir) = make_store();
        store.set(1, b"user.key1", b"val1", 0).expect("set");
        let val = store.get(1, b"user.key1").expect("get");
        assert_eq!(val, b"val1");
    }

    #[test]
    fn obj_get_missing_returns_not_found() {
        let (store, _dir) = make_store();
        assert_eq!(store.get(1, b"user.missing"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn obj_get_missing_inode() {
        let (store, _dir) = make_store();
        assert_eq!(store.get(42, b"user.any"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn obj_overwrite_with_flag_zero() {
        let (store, _dir) = make_store();
        store.set(1, b"user.key", b"first", 0).expect("set");
        store.set(1, b"user.key", b"second", 0).expect("overwrite");
        assert_eq!(store.get(1, b"user.key").unwrap(), b"second");
    }

    #[test]
    fn obj_empty_value_roundtrip() {
        let (store, _dir) = make_store();
        store.set(1, b"user.empty", b"", 0).expect("set empty");
        let val = store.get(1, b"user.empty").expect("get empty");
        assert!(val.is_empty());
    }

    // ── create / replace flags ────────────────────────────────────────

    #[test]
    fn obj_create_flag_succeeds_on_new() {
        let (store, _dir) = make_store();
        assert_eq!(store.set(1, b"user.newkey", b"val", XATTR_CREATE), Ok(()));
    }

    #[test]
    fn obj_create_flag_fails_on_existing() {
        let (store, _dir) = make_store();
        store.set(1, b"user.dup", b"first", 0).expect("set");
        assert_eq!(
            store.set(1, b"user.dup", b"second", XATTR_CREATE),
            Err(XattrError::AttrExists)
        );
    }

    #[test]
    fn obj_replace_flag_succeeds_on_existing() {
        let (store, _dir) = make_store();
        store.set(1, b"user.rep", b"old", 0).expect("set");
        assert_eq!(store.set(1, b"user.rep", b"new", XATTR_REPLACE), Ok(()));
        assert_eq!(store.get(1, b"user.rep").unwrap(), b"new");
    }

    #[test]
    fn obj_replace_flag_fails_on_missing() {
        let (store, _dir) = make_store();
        assert_eq!(
            store.set(1, b"user.missing", b"val", XATTR_REPLACE),
            Err(XattrError::AttrNotFound)
        );
    }

    // ── remove ────────────────────────────────────────────────────────

    #[test]
    fn obj_remove_existing() {
        let (store, _dir) = make_store();
        store.set(1, b"user.del", b"val", 0).expect("set");
        assert_eq!(store.remove(1, b"user.del"), Ok(()));
        assert_eq!(store.get(1, b"user.del"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn obj_remove_missing_returns_not_found() {
        let (store, _dir) = make_store();
        store.set(1, b"user.key", b"val", 0).expect("set");
        assert_eq!(
            store.remove(1, b"user.missing"),
            Err(XattrError::AttrNotFound)
        );
    }

    #[test]
    fn obj_remove_missing_inode() {
        let (store, _dir) = make_store();
        assert_eq!(store.remove(42, b"user.any"), Err(XattrError::AttrNotFound));
    }

    // ── list ──────────────────────────────────────────────────────────

    #[test]
    fn obj_list_returns_all_keys() {
        let (store, _dir) = make_store();
        store.set(1, b"user.a", b"1", 0).expect("set a");
        store.set(1, b"user.b", b"2", 0).expect("set b");

        let list = store.list(1).expect("list");
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".as_slice()));
        assert!(names.contains(&b"user.b".as_slice()));
    }

    #[test]
    fn obj_list_empty_inode_no_attrs() {
        let (store, _dir) = make_store();
        assert_eq!(store.list(99), Ok(Vec::new()));
    }

    #[test]
    fn obj_list_after_removing_last_attr() {
        let (store, _dir) = make_store();
        store.set(1, b"user.key", b"val", 0).expect("set");
        store.remove(1, b"user.key").expect("remove");
        let list = store.list(1).expect("list");
        assert!(list.is_empty());
    }

    // ── count limit ───────────────────────────────────────────────────

    #[test]
    fn obj_count_limit_enforced() {
        let (store, _dir) = make_store();
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("user.key{i}");
            store
                .set(1, name.as_bytes(), b"val", 0)
                .expect("set within limit");
        }
        // The (N+1)th set must fail.
        let err = store.set(1, b"user.overlimit", b"val", 0).unwrap_err();
        assert_eq!(err, XattrError::InodeXattrLimit);
    }

    #[test]
    fn obj_count_limit_with_create_flag() {
        let (store, _dir) = make_store();
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("user.key{i}");
            store
                .set(1, name.as_bytes(), b"val", XATTR_CREATE)
                .expect("set create");
        }
        let err = store
            .set(1, b"user.overlimit", b"val", XATTR_CREATE)
            .unwrap_err();
        assert_eq!(err, XattrError::InodeXattrLimit);
    }

    // ── value size limit ──────────────────────────────────────────────

    #[test]
    fn obj_value_size_limit_enforced() {
        let (store, _dir) = make_store();
        let big = vec![0xCC; MAX_XATTR_VALUE_LEN + 1];
        let err = store.set(1, b"user.big", &big, 0).unwrap_err();
        assert_eq!(err, XattrError::ValueTooLarge);
    }

    #[test]
    fn obj_value_at_exact_max_allowed() {
        let (store, _dir) = make_store();
        let exact = vec![0xBB; MAX_XATTR_VALUE_LEN];
        store.set(1, b"user.max", &exact, 0).expect("set at max");
        assert_eq!(store.get(1, b"user.max").unwrap(), exact);
    }

    // ── namespace-prefixed names ──────────────────────────────────────

    #[test]
    fn obj_namespaced_names_roundtrip() {
        let (store, _dir) = make_store();
        let cases = [
            b"user.mykey".as_slice(),
            b"system.posix_acl_access".as_slice(),
            b"security.selinux".as_slice(),
            b"trusted.overlay.upper".as_slice(),
        ];
        for name in cases {
            let value = format!("val_for_{}", String::from_utf8_lossy(name));
            store.set(1, name, value.as_bytes(), 0).expect("set");
            let got = store.get(1, name).expect("get");
            assert_eq!(got, value.as_bytes());
        }
    }

    // ── multiple inodes independent ───────────────────────────────────

    #[test]
    fn obj_multiple_inodes_independent() {
        let (store, _dir) = make_store();
        store.set(1, b"user.inode1", b"a", 0).expect("set 1");
        store.set(2, b"user.inode2", b"b", 0).expect("set 2");

        assert_eq!(store.get(1, b"user.inode1").unwrap(), b"a");
        assert_eq!(store.get(2, b"user.inode2").unwrap(), b"b");
        assert_eq!(store.get(1, b"user.inode2"), Err(XattrError::AttrNotFound));
        assert_eq!(store.get(2, b"user.inode1"), Err(XattrError::AttrNotFound));
    }

    // ── invalid names ─────────────────────────────────────────────────

    #[test]
    fn obj_rejects_invalid_names() {
        let (store, _dir) = make_store();
        assert_eq!(store.set(1, b"", b"val", 0), Err(XattrError::InvalidName));
        assert_eq!(
            store.set(1, b"bad.prefix", b"val", 0),
            Err(XattrError::UnsupportedNamespace)
        );
        assert_eq!(
            store.set(1, b"user.bad\0byte", b"val", 0),
            Err(XattrError::InvalidName)
        );
    }

    #[test]
    fn obj_rejects_invalid_flags() {
        let (store, _dir) = make_store();
        assert_eq!(
            store.set(1, b"user.key", b"val", XATTR_CREATE | XATTR_REPLACE),
            Err(XattrError::InvalidName)
        );
        assert_eq!(
            store.set(1, b"user.key", b"val", 4),
            Err(XattrError::InvalidName)
        );
    }

    // ── persistence across store instances ────────────────────────────

    #[test]
    fn obj_persistence_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();

        // Write through one store instance.
        {
            let store = LocalObjectStore::open_with_options(&path, StoreOptions::test_fast())
                .expect("open");
            let xattrs = ObjXattrStore::new(store);
            xattrs.set(1, b"user.persist", b"survives", 0).expect("set");
            xattrs.set(1, b"user.also", b"here", 0).expect("set");
        }

        // Read through a fresh instance on the same directory.
        {
            let store = LocalObjectStore::open_with_options(&path, StoreOptions::test_fast())
                .expect("reopen");
            let xattrs = ObjXattrStore::new(store);
            assert_eq!(xattrs.get(1, b"user.persist").unwrap(), b"survives");
            assert_eq!(xattrs.get(1, b"user.also").unwrap(), b"here");

            let list = xattrs.list(1).expect("list");
            let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
            assert_eq!(names.len(), 2);
        }
    }

    #[test]
    fn obj_persistence_delete_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();

        {
            let store = LocalObjectStore::open_with_options(&path, StoreOptions::test_fast())
                .expect("open");
            let xattrs = ObjXattrStore::new(store);
            xattrs.set(1, b"user.todel", b"x", 0).expect("set");
            xattrs.remove(1, b"user.todel").expect("remove");
        }

        {
            let store = LocalObjectStore::open_with_options(&path, StoreOptions::test_fast())
                .expect("reopen");
            let xattrs = ObjXattrStore::new(store);
            assert_eq!(xattrs.get(1, b"user.todel"), Err(XattrError::AttrNotFound));
        }
    }

    // ── large value round-trip ────────────────────────────────────────

    #[test]
    fn obj_large_value_roundtrip() {
        let (store, _dir) = make_store();
        let large = vec![0xDE; 64 * 1024];
        store.set(1, b"user.large", &large, 0).expect("set large");
        let got = store.get(1, b"user.large").expect("get large");
        assert_eq!(got, large);
    }

    // ── many keys across multiple inodes ──────────────────────────────

    #[test]
    fn obj_many_keys_many_inodes() {
        let (store, _dir) = make_store();
        for ino in 1u64..=10 {
            for i in 0..10u32 {
                let name = format!("user.ino{ino}_key{i}");
                let val = format!("val_{ino}_{i}");
                store
                    .set(ino, name.as_bytes(), val.as_bytes(), 0)
                    .expect("set");
            }
        }
        // Spot-check
        assert_eq!(store.get(3, b"user.ino3_key7").unwrap(), b"val_3_7");
        assert_eq!(
            store.get(3, b"user.ino3_key99"),
            Err(XattrError::AttrNotFound)
        );
        assert_eq!(
            store
                .list(5)
                .expect("list")
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .count(),
            10
        );
    }

    // ── InodeXattrLimit raw_os_error mapping ──────────────────────────

    #[test]
    fn obj_inode_xattr_limit_maps_to_enospc() {
        assert_eq!(XattrError::InodeXattrLimit.raw_os_error(), libc::ENOSPC);
    }
}
