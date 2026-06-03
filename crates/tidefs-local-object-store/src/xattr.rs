//! Per-inode extended attribute storage via the local object store.
//!
//! Provides [`XattrError`], flag constants, and four xattr methods on
//! [`LocalObjectStore`]: `set_xattr`, `get_xattr`,
//! `list_xattr`, and `remove_xattr`. Each inode's xattrs are stored as a
//! single binary blob under the key `xattr:{ino}` in the named store API.
//!
//! # On-disk format
//!
//! Each per-inode xattr blob is encoded as:
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
//! for an inode are removed, the blob key is deleted.

use std::collections::BTreeMap;

use crate::LocalObjectStore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Key prefix for per-inode xattr blobs in the named object-store API.
const XATTR_KEY_PREFIX: &str = "xattr:";

/// Maximum number of extended attributes per inode.
pub const MAX_XATTR_COUNT: usize = 256;

/// Maximum size of a single extended attribute value in bytes (64 KiB).
pub const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;

/// `XATTR_CREATE`: fail if the attribute already exists.
pub const XATTR_CREATE: u32 = 1;

/// `XATTR_REPLACE`: fail if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

// ---------------------------------------------------------------------------
// XattrError
// ---------------------------------------------------------------------------

/// Errors returned by xattr operations on the local object store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XattrError {
    /// The xattr name is empty or contains a NUL byte.
    InvalidName,
    /// The xattr name exceeds the maximum length (255 bytes).
    NameTooLong,
    /// The xattr value exceeds the maximum size (64 KiB).
    ValueTooLarge,
    /// The namespace prefix is not recognised (not user/system/security/trusted).
    UnsupportedNamespace,
    /// The requested attribute does not exist.
    AttrNotFound,
    /// The attribute already exists (for `XATTR_CREATE`).
    AttrExists,
    /// Per-inode xattr count limit exceeded.
    InodeXattrLimit,
    /// An internal storage error occurred (e.g. I/O failure).
    Internal(String),
}

impl XattrError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn raw_os_error(self) -> i32 {
        match self {
            Self::InvalidName | Self::NameTooLong => 22,
            Self::ValueTooLarge => 7,
            Self::UnsupportedNamespace => 95,
            Self::AttrNotFound => 61,
            Self::AttrExists => 17,
            Self::InodeXattrLimit => 28,
            Self::Internal(_) => 5,
        }
    }
}

impl std::fmt::Display for XattrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid xattr name"),
            Self::NameTooLong => write!(f, "xattr name too long"),
            Self::ValueTooLarge => write!(f, "xattr value too large"),
            Self::UnsupportedNamespace => write!(f, "unsupported xattr namespace"),
            Self::AttrNotFound => write!(f, "xattr not found"),
            Self::AttrExists => write!(f, "xattr already exists"),
            Self::InodeXattrLimit => write!(f, "per-inode xattr count limit exceeded"),
            Self::Internal(msg) => write!(f, "internal xattr store error: {msg}"),
        }
    }
}

impl std::error::Error for XattrError {}

// ---------------------------------------------------------------------------
// Binary encoding / decoding
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
// Namespace validation
// ---------------------------------------------------------------------------

/// Recognised Linux extended-attribute namespace prefixes.
const KNOWN_PREFIXES: &[&[u8]] = &[b"user.", b"system.", b"security.", b"trusted."];

/// Validate an xattr name: non-empty, no NUL, valid namespace prefix,
/// not too long.
fn validate_name(name: &[u8]) -> Result<(), XattrError> {
    if name.is_empty() || name.contains(&0) {
        return Err(XattrError::InvalidName);
    }
    if name.len() > 255 {
        return Err(XattrError::NameTooLong);
    }
    let has_known_prefix = KNOWN_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix) && name.len() > prefix.len());
    if !has_known_prefix {
        return Err(XattrError::UnsupportedNamespace);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Xattr methods on LocalObjectStore
// ---------------------------------------------------------------------------

impl LocalObjectStore {
    /// Get the value of an extended attribute for `ino`.
    ///
    /// Returns `Ok(None)` when the attribute is not present.
    /// Returns `Err(XattrError::AttrNotFound)` when the inode has no xattrs at all.
    pub fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Option<Vec<u8>>, XattrError> {
        validate_name(name)?;
        let xattrs = self.read_xattrs(ino)?;
        Ok(xattrs.get(name).cloned())
    }

    /// Set an extended attribute on `ino`.
    ///
    /// `flags` is one of: 0 (create or replace), [`XATTR_CREATE`], or
    /// [`XATTR_REPLACE`].
    pub fn set_xattr(
        &mut self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), XattrError> {
        validate_name(name)?;
        if value.len() > MAX_XATTR_VALUE_LEN {
            return Err(XattrError::ValueTooLarge);
        }
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(XattrError::InvalidName);
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
                if !xattrs.contains_key(name) && xattrs.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
        }

        xattrs.insert(name.to_vec(), value.to_vec());

        self.write_xattrs(ino, &xattrs)
    }

    /// List all extended attribute names for `ino`.
    ///
    /// Returns a vector of xattr names (without null terminators).
    /// Returns an empty vector when the inode has no xattrs.
    pub fn list_xattr(&self, ino: u64) -> Result<Vec<Vec<u8>>, XattrError> {
        let xattrs = self.read_xattrs(ino)?;
        Ok(xattrs.keys().cloned().collect())
    }

    /// Remove an extended attribute from `ino`.
    ///
    /// Returns `Ok(true)` if the attribute existed and was removed,
    /// `Ok(false)` if it did not exist.
    pub fn remove_xattr(&mut self, ino: u64, name: &[u8]) -> Result<bool, XattrError> {
        validate_name(name)?;
        let mut xattrs = self.read_xattrs(ino)?;
        let existed = xattrs.remove(name).is_some();
        if existed {
            self.write_xattrs(ino, &xattrs)?;
        }
        Ok(existed)
    }

    // ── internal helpers ──────────────────────────────────────────────

    /// Read the deserialized xattr map for `ino`.
    /// Returns an empty map when no blob exists.
    fn read_xattrs(&self, ino: u64) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, XattrError> {
        let key = xattr_key(ino);
        let data = self
            .get_named(&key)
            .map_err(|e| XattrError::Internal(format!("object store read: {e}")))?;
        match data {
            Some(blob) => decode_xattrs(&blob)
                .ok_or_else(|| XattrError::Internal("corrupt xattr blob".to_string())),
            None => Ok(BTreeMap::new()),
        }
    }

    /// Append an xattr mutation to the intent-log for crash recovery.
    ///
    /// Opens a new transaction if none is active, then appends the
    /// appropriate intent-log record (XattrSet or XattrRemove).
    /// Does nothing when the namespace cannot be determined.
    /// Write the xattr map for `ino`.
    /// Deletes the key when the map is empty.
    fn write_xattrs(
        &mut self,
        ino: u64,
        xattrs: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), XattrError> {
        let key = xattr_key(ino);
        if xattrs.is_empty() {
            let _ = self
                .delete_named(&key)
                .map_err(|e| XattrError::Internal(format!("object store delete: {e}")))?;
        } else {
            let blob = encode_xattrs(xattrs);
            self.put_named(&key, &blob)
                .map_err(|e| XattrError::Internal(format!("object store write: {e}")))?;
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
    fn make_store() -> (LocalObjectStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-los-xattr-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, crate::StoreOptions::test_fast())
            .expect("open store");
        (store, dir)
    }

    fn make_store_large() -> (LocalObjectStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-los-xattr-large-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let opts = crate::StoreOptions {
            max_segment_bytes: 256 * 1024,
            ..crate::StoreOptions::test_fast()
        };
        let store = LocalObjectStore::open_with_options(&dir, opts).expect("open large store");
        (store, dir)
    }

    // ── basic get/set round-trip ──────────────────────────────────────

    #[test]
    fn set_get_roundtrip() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.key1", b"val1", 0).expect("set");
        let val = store.get_xattr(1, b"user.key1").expect("get");
        assert_eq!(val, Some(b"val1".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let (store, _dir) = make_store();
        assert_eq!(store.get_xattr(1, b"user.missing").unwrap(), None);
    }

    #[test]
    fn overwrite_with_flag_zero() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.key", b"first", 0).expect("set");
        store
            .set_xattr(1, b"user.key", b"second", 0)
            .expect("overwrite");
        assert_eq!(
            store.get_xattr(1, b"user.key").unwrap(),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn empty_value_roundtrip() {
        let (mut store, _dir) = make_store();
        store
            .set_xattr(1, b"user.empty", b"", 0)
            .expect("set empty");
        let val = store.get_xattr(1, b"user.empty").expect("get empty");
        assert_eq!(val, Some(vec![]));
    }

    // ── create / replace flags ────────────────────────────────────────

    #[test]
    fn create_flag_succeeds_on_new() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"user.newkey", b"val", XATTR_CREATE),
            Ok(())
        );
    }

    #[test]
    fn create_flag_fails_on_existing() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.dup", b"first", 0).expect("set");
        assert_eq!(
            store.set_xattr(1, b"user.dup", b"second", XATTR_CREATE),
            Err(XattrError::AttrExists)
        );
    }

    #[test]
    fn replace_flag_succeeds_on_existing() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.rep", b"old", 0).expect("set");
        assert_eq!(
            store.set_xattr(1, b"user.rep", b"new", XATTR_REPLACE),
            Ok(())
        );
        assert_eq!(
            store.get_xattr(1, b"user.rep").unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn replace_flag_fails_on_missing() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"user.missing", b"val", XATTR_REPLACE),
            Err(XattrError::AttrNotFound)
        );
    }

    // ── remove ────────────────────────────────────────────────────────

    #[test]
    fn remove_existing() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.del", b"val", 0).expect("set");
        assert_eq!(store.remove_xattr(1, b"user.del"), Ok(true));
        assert_eq!(store.get_xattr(1, b"user.del").unwrap(), None);
    }

    #[test]
    fn remove_missing_returns_false() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.key", b"val", 0).expect("set");
        assert_eq!(store.remove_xattr(1, b"user.missing"), Ok(false));
    }

    // ── list ──────────────────────────────────────────────────────────

    #[test]
    fn list_returns_all_keys() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.a", b"1", 0).expect("set a");
        store.set_xattr(1, b"user.b", b"2", 0).expect("set b");

        let names = store.list_xattr(1).expect("list");
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".to_vec()));
        assert!(names.contains(&b"user.b".to_vec()));
    }

    #[test]
    fn list_empty_inode_no_attrs() {
        let (store, _dir) = make_store();
        let names = store.list_xattr(99).expect("list");
        assert!(names.is_empty());
    }

    #[test]
    fn list_after_removing_last_attr() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.key", b"val", 0).expect("set");
        store.remove_xattr(1, b"user.key").expect("remove");
        let names = store.list_xattr(1).expect("list");
        assert!(names.is_empty());
    }

    // ── count limit ───────────────────────────────────────────────────

    #[test]
    fn count_limit_enforced() {
        let (mut store, _dir) = make_store_large();
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("user.key{i}");
            store
                .set_xattr(1, name.as_bytes(), b"val", 0)
                .expect("set within limit");
        }
        let err = store
            .set_xattr(1, b"user.overlimit", b"val", 0)
            .unwrap_err();
        assert_eq!(err, XattrError::InodeXattrLimit);
    }

    // ── value size limit ──────────────────────────────────────────────

    #[test]
    fn value_size_limit_enforced() {
        let (mut store, _dir) = make_store_large();
        let big = vec![0xCC; MAX_XATTR_VALUE_LEN + 1];
        let err = store.set_xattr(1, b"user.big", &big, 0).unwrap_err();
        assert_eq!(err, XattrError::ValueTooLarge);
    }

    #[test]
    fn value_at_exact_max_allowed() {
        let (mut store, _dir) = make_store_large();
        let exact = vec![0xBB; MAX_XATTR_VALUE_LEN];
        store
            .set_xattr(1, b"user.max", &exact, 0)
            .expect("set at max");
        assert_eq!(store.get_xattr(1, b"user.max").unwrap(), Some(exact));
    }

    // ── multiple inodes independent ───────────────────────────────────

    #[test]
    fn multiple_inodes_independent() {
        let (mut store, _dir) = make_store();
        store.set_xattr(1, b"user.inode1", b"a", 0).expect("set 1");
        store.set_xattr(2, b"user.inode2", b"b", 0).expect("set 2");

        assert_eq!(
            store.get_xattr(1, b"user.inode1").unwrap(),
            Some(b"a".to_vec())
        );
        assert_eq!(
            store.get_xattr(2, b"user.inode2").unwrap(),
            Some(b"b".to_vec())
        );
        assert_eq!(store.get_xattr(1, b"user.inode2").unwrap(), None);
        assert_eq!(store.get_xattr(2, b"user.inode1").unwrap(), None);
    }

    // ── invalid names ─────────────────────────────────────────────────

    #[test]
    fn rejects_empty_name() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"", b"val", 0),
            Err(XattrError::InvalidName)
        );
    }

    #[test]
    fn rejects_nul_in_name() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"user.bad\0byte", b"val", 0),
            Err(XattrError::InvalidName)
        );
    }

    #[test]
    fn rejects_unknown_namespace() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"custom.foo", b"val", 0),
            Err(XattrError::UnsupportedNamespace)
        );
    }

    #[test]
    fn accepts_known_namespaces() {
        let (mut store, _dir) = make_store();
        assert!(store.set_xattr(1, b"user.foo", b"val", 0).is_ok());
        assert!(store.set_xattr(1, b"system.bar", b"val", 0).is_ok());
        assert!(store.set_xattr(1, b"security.baz", b"val", 0).is_ok());
        assert!(store.set_xattr(1, b"trusted.qux", b"val", 0).is_ok());
    }

    #[test]
    fn rejects_invalid_flags() {
        let (mut store, _dir) = make_store();
        assert_eq!(
            store.set_xattr(1, b"user.key", b"val", XATTR_CREATE | XATTR_REPLACE),
            Err(XattrError::InvalidName)
        );
        assert_eq!(
            store.set_xattr(1, b"user.key", b"val", 4),
            Err(XattrError::InvalidName)
        );
    }

    // ── persistence across store instances ────────────────────────────

    #[test]
    fn persistence_across_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-los-xattr-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir;

        // Write through one store instance.
        {
            let mut store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("open");
            store
                .set_xattr(1, b"user.persist", b"survives", 0)
                .expect("set");
            store.set_xattr(1, b"user.also", b"here", 0).expect("set");
            store.sync().expect("sync");
        }

        // Read through a fresh instance on the same directory.
        {
            let store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("reopen");
            assert_eq!(
                store.get_xattr(1, b"user.persist").unwrap(),
                Some(b"survives".to_vec())
            );
            assert_eq!(
                store.get_xattr(1, b"user.also").unwrap(),
                Some(b"here".to_vec())
            );

            let names = store.list_xattr(1).expect("list");
            assert_eq!(names.len(), 2);
        }
    }

    #[test]
    fn persistence_delete_across_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-los-xattr-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir;

        {
            let mut store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("open");
            store.set_xattr(1, b"user.todel", b"x", 0).expect("set");
            store.remove_xattr(1, b"user.todel").expect("remove");
            store.sync().expect("sync");
        }

        {
            let store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("reopen");
            assert_eq!(store.get_xattr(1, b"user.todel").unwrap(), None);
        }
    }

    // ── flush (sync) then reload round-trip ───────────────────────────

    #[test]
    fn flush_inode_xattrs_survives_reopen() {
        // Store a user.test xattr, flush (sync), reload, verify byte-identical retrieval.
        let dir = std::env::temp_dir().join(format!(
            "tidefs-los-xattr-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir;

        let test_val = b"hello xattr world";
        {
            let mut store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("open");
            store.set_xattr(1, b"user.test", test_val, 0).expect("set");
            store.sync().expect("flush");
        }

        {
            let store =
                LocalObjectStore::open_with_options(&path, crate::StoreOptions::test_fast())
                    .expect("reopen");
            let val = store.get_xattr(1, b"user.test").expect("get");
            assert_eq!(val, Some(test_val.to_vec()));
        }
    }

    // ── binary (non-UTF-8) name and value ─────────────────────────────

    #[test]
    fn binary_name_and_value_roundtrip() {
        let (mut store, _dir) = make_store();
        let name = b"user.bin\x01\x02\x03\x04";
        let value = vec![0x00, 0xFF, 0x7F, 0x80, 0xFE];
        store.set_xattr(1, name, &value, 0).expect("set binary");
        assert_eq!(store.get_xattr(1, name).unwrap(), Some(value));
    }

    // ── XattrError raw_os_error mapping ───────────────────────────────

    #[test]
    fn xattr_error_maps_to_posix_errno() {
        assert_eq!(XattrError::InvalidName.raw_os_error(), 22);
        assert_eq!(XattrError::ValueTooLarge.raw_os_error(), 7);
        assert_eq!(XattrError::UnsupportedNamespace.raw_os_error(), 95);
        assert_eq!(XattrError::AttrNotFound.raw_os_error(), 61);
        assert_eq!(XattrError::AttrExists.raw_os_error(), 17);
        assert_eq!(XattrError::InodeXattrLimit.raw_os_error(), 28);
        assert_eq!(XattrError::Internal("oops".into()).raw_os_error(), 5);
    }

    // ── encode / decode ───────────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let mut xattrs = BTreeMap::new();
        xattrs.insert(b"user.key1".to_vec(), b"val1".to_vec());
        xattrs.insert(b"user.key2".to_vec(), b"hello world".to_vec());
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert_eq!(decoded, xattrs);
    }

    #[test]
    fn encode_decode_empty() {
        let xattrs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_corrupt_truncated() {
        assert!(decode_xattrs(&[0x01]).is_none());
        assert!(decode_xattrs(&[]).is_none());
    }

    #[test]
    fn decode_corrupt_truncated_name() {
        let mut data = vec![1, 0, 0, 0]; // count=1
        data.extend_from_slice(&[10, 0]); // name_len=10
        data.extend_from_slice(b"short"); // only 5 bytes
        assert!(decode_xattrs(&data).is_none());
    }

    #[test]
    fn decode_corrupt_truncated_value() {
        let mut data = vec![1, 0, 0, 0]; // count=1
        data.extend_from_slice(&[4, 0]); // name_len=4
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[100, 0, 0, 0]); // value_len=100
        data.extend_from_slice(&[0u8; 50]); // only 50 bytes
        assert!(decode_xattrs(&data).is_none());
    }
}
