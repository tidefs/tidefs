//! Persistent xattr storage backed by [`tidefs_local_object_store::LocalObjectStore`].
//!
//! Stores each xattr as a separate named object under the key
//! `__xattr:{inode}:{namespace}:{name}` and maintains a per-inode
//! directory at `__xattr_dir:{inode}` for enumeration.
//!
//! Enabled via the `persistence` feature flag (brings in std).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tidefs_binary_schema_core::{U16Le, U32Le};
use tidefs_local_object_store::LocalObjectStore;

use tidefs_binary_schema_checksum::{blake3_domain_digest, blake3_domain_verify};
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

// ---------------------------------------------------------------------------
// Key prefixes
// ---------------------------------------------------------------------------

/// Prefix for per-xattr value objects.
const XATTR_KEY_PREFIX: &str = "__xattr:";
/// Prefix for per-inode xattr directory objects.
const XATTR_DIR_PREFIX: &str = "__xattr_dir:";

// ---------------------------------------------------------------------------
// POSIX xattr flags
// ---------------------------------------------------------------------------

/// `XATTR_CREATE`: fail if the attribute already exists.
pub const XATTR_CREATE: u32 = 1;
/// `XATTR_REPLACE`: fail if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by persistent xattr storage operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistentXattrError {
    /// The xattr name is empty or contains a NUL byte.
    InvalidName,
    /// The xattr name exceeds the maximum length (255 bytes).
    NameTooLong,
    /// The xattr value exceeds the maximum size (64 KiB).
    ValueTooLarge,
    /// The namespace is empty, contains a colon, or is not a recognised
    /// Linux xattr namespace.
    InvalidNamespace,
    /// The requested attribute does not exist.
    AttrNotFound,
    /// The attribute already exists (for `XATTR_CREATE`).
    AttrExists,
    /// Flags combine XATTR_CREATE|XATTR_REPLACE or contain unknown bits.
    InvalidFlags,
    /// Per-inode xattr count limit exceeded.
    InodeXattrLimit,
    /// An internal storage error occurred (wraps the store error message).
    Internal(String),
}

impl PersistentXattrError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn raw_os_error(&self) -> i32 {
        match self {
            Self::InvalidName | Self::NameTooLong => 22,
            Self::ValueTooLarge => 7,
            Self::InvalidNamespace => 95,
            Self::AttrNotFound => 61,
            Self::AttrExists => 17,
            Self::InvalidFlags => 22,
            Self::InodeXattrLimit => 28,
            Self::Internal(_) => 5,
        }
    }
}

impl std::fmt::Display for PersistentXattrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid xattr name"),
            Self::NameTooLong => write!(f, "xattr name too long"),
            Self::ValueTooLarge => write!(f, "xattr value too large"),
            Self::InvalidNamespace => write!(f, "invalid xattr namespace"),
            Self::AttrNotFound => write!(f, "xattr not found"),
            Self::AttrExists => write!(f, "xattr already exists"),
            Self::InvalidFlags => write!(f, "invalid setxattr flags"),
            Self::InodeXattrLimit => write!(f, "per-inode xattr count limit exceeded"),
            Self::Internal(msg) => write!(f, "internal storage error: {msg}"),
        }
    }
}

impl std::error::Error for PersistentXattrError {}

// ---------------------------------------------------------------------------
// Directory encoding constants
// ---------------------------------------------------------------------------

/// Magic bytes for xattr directory blob: "XDIR"
const XATTR_DIR_MAGIC: [u8; 4] = [0x58, 0x44, 0x49, 0x52]; // "XDIR"
/// Current xattr directory format version.
const XATTR_DIR_FORMAT_VERSION: u8 = 1;
/// Minimum directory blob size: magic(4) + version(1) + count(4) + digest(32)
const XATTR_DIR_MIN_BLOB_LEN: usize = 4 + 1 + U32Le::BYTES + 32;

/// Schema type ID for xattr directory objects (200 = xattr directory).
const XATTR_DIR_TYPE_ID: SchemaTypeId = SchemaTypeId(200);
/// Schema version for xattr directory format v1.
const XATTR_DIR_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Maximum number of extended attributes per inode.
pub const MAX_XATTR_COUNT: usize = 256;

/// Maximum size of a single extended attribute value in bytes (64 KiB).
pub const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;

/// Maximum length of an xattr name in bytes.
pub const MAX_XATTR_NAME_LEN: usize = 255;

/// Maximum length of a namespace component.
pub const MAX_NAMESPACE_LEN: usize = 64;

// ---------------------------------------------------------------------------
// PersistentXattrStore
// ---------------------------------------------------------------------------

/// Persistent xattr store backed by a [`LocalObjectStore`] handle.
///
/// Each xattr value is stored as a separate named object keyed by
/// `__xattr:{inode}:{namespace}:{name}`. A per-inode directory object at
/// `__xattr_dir:{inode}` tracks which xattrs exist so that `list()` can
/// enumerate them without a native prefix-scan capability.
///
/// # Thread safety
///
/// The inner [`LocalObjectStore`] is wrapped in an `Arc<Mutex<_>>` so
/// that the store can be shared across threads. Read-only operations
/// (`get`, `list`) acquire the lock briefly; write operations (`set`,
/// `remove`) hold the lock for the duration of the mutation.
#[derive(Clone)]
pub struct PersistentXattrStore {
    store: Arc<Mutex<LocalObjectStore>>,
}

impl PersistentXattrStore {
    /// Create a new persistent xattr store backed by `store`.
    ///
    /// The store handle is shared; the caller is responsible for
    /// opening and closing the underlying object store.
    #[must_use]
    pub fn new(store: Arc<Mutex<LocalObjectStore>>) -> Self {
        Self { store }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get the value of an xattr on `inode`.
    ///
    /// Returns `Ok(None)` when the attribute does not exist, or
    /// `Ok(Some(value))` with the raw value bytes.
    pub fn get(
        &self,
        inode: u64,
        namespace: &str,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, PersistentXattrError> {
        self.validate_namespace(namespace)?;
        self.validate_name(name)?;
        let key = xattr_value_key(inode, namespace, name);
        let store = self
            .store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;
        store
            .get_named(&key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store read: {e}")))
    }

    /// Set an xattr on `inode`.
    ///
    /// `flags` is one of: 0 (create or replace), [`XATTR_CREATE`], or
    /// [`XATTR_REPLACE`]. The namespace must be one of the well-known
    /// Linux xattr namespaces: `user`, `system`, `security`, `trusted`.
    pub fn set(
        &self,
        inode: u64,
        namespace: &str,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), PersistentXattrError> {
        self.validate_namespace(namespace)?;
        self.validate_name(name)?;
        if value.len() > MAX_XATTR_VALUE_LEN {
            return Err(PersistentXattrError::ValueTooLarge);
        }
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(PersistentXattrError::InvalidFlags);
        }

        let mut store = self
            .store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let mut dir = self.read_dir_locked(&store, inode)?;
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

        let value_key = xattr_value_key(inode, namespace, name);
        store
            .put_named(&value_key, value)
            .map_err(|e| PersistentXattrError::Internal(format!("object store write: {e}")))?;

        dir.insert(full_name);
        self.write_dir_locked(&mut store, inode, &dir)?;

        Ok(())
    }

    /// List all xattr (namespace, name) pairs for `inode`.
    ///
    /// Returns an empty vector when the inode has no xattrs.
    /// Each entry is `(namespace, name_bytes)`.
    pub fn list(&self, inode: u64) -> Result<Vec<(String, Vec<u8>)>, PersistentXattrError> {
        let store = self
            .store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;
        let dir = self.read_dir_locked(&store, inode)?;
        let mut result = Vec::with_capacity(dir.len());
        for entry in &dir {
            if let Some((ns, name)) = split_full_name(entry) {
                result.push((ns.to_string(), name.to_vec()));
            }
        }
        Ok(result)
    }

    /// Remove an xattr from `inode`.
    ///
    /// Returns `Ok(true)` when the attribute existed and was removed,
    /// `Ok(false)` when it did not exist.
    pub fn remove(
        &self,
        inode: u64,
        namespace: &str,
        name: &[u8],
    ) -> Result<bool, PersistentXattrError> {
        self.validate_namespace(namespace)?;
        self.validate_name(name)?;

        let mut store = self
            .store
            .lock()
            .map_err(|e| PersistentXattrError::Internal(format!("lock poisoned: {e}")))?;

        let mut dir = self.read_dir_locked(&store, inode)?;
        let full_name = xattr_full_name_bytes(namespace, name);

        if !dir.remove(&full_name) {
            return Ok(false);
        }

        let value_key = xattr_value_key(inode, namespace, name);
        store
            .delete_named(&value_key)
            .map_err(|e| PersistentXattrError::Internal(format!("object store delete: {e}")))?;

        self.write_dir_locked(&mut store, inode, &dir)?;

        Ok(true)
    }

    // ------------------------------------------------------------------
    // Validation helpers
    // ------------------------------------------------------------------

    fn validate_namespace(&self, ns: &str) -> Result<(), PersistentXattrError> {
        if ns.is_empty() || ns.contains(':') {
            return Err(PersistentXattrError::InvalidNamespace);
        }
        if ns.len() > MAX_NAMESPACE_LEN {
            return Err(PersistentXattrError::InvalidNamespace);
        }
        // Only allow well-known Linux xattr namespaces
        match ns {
            "user" | "system" | "security" | "trusted" => Ok(()),
            _ => Err(PersistentXattrError::InvalidNamespace),
        }
    }

    fn validate_name(&self, name: &[u8]) -> Result<(), PersistentXattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(PersistentXattrError::InvalidName);
        }
        if name.len() > MAX_XATTR_NAME_LEN {
            return Err(PersistentXattrError::NameTooLong);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Directory (per-inode index) helpers
    // ------------------------------------------------------------------

    /// Read the per-inode directory set, returning an empty set when
    /// no directory object exists yet.
    fn read_dir_locked(
        &self,
        store: &LocalObjectStore,
        inode: u64,
    ) -> Result<BTreeSet<Vec<u8>>, PersistentXattrError> {
        let dir_key = xattr_dir_key(inode);
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

    /// Write the per-inode directory set. Deletes the key when the set is empty.
    fn write_dir_locked(
        &self,
        store: &mut LocalObjectStore,
        inode: u64,
        dir: &BTreeSet<Vec<u8>>,
    ) -> Result<(), PersistentXattrError> {
        let dir_key = xattr_dir_key(inode);
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
// Key construction helpers
// ---------------------------------------------------------------------------

/// Build the named key for a single xattr value object.
pub(crate) fn xattr_value_key(inode: u64, namespace: &str, name: &[u8]) -> String {
    format!(
        "{}{}:{}:{}",
        XATTR_KEY_PREFIX,
        inode,
        namespace,
        String::from_utf8_lossy(name)
    )
}

/// Build the named key for a per-inode xattr directory object.
pub(crate) fn xattr_dir_key(inode: u64) -> String {
    format!("{XATTR_DIR_PREFIX}{inode}")
}

/// Build a full xattr name from namespace and name for directory storage.
pub(crate) fn xattr_full_name_bytes(namespace: &str, name: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(namespace.len() + 1 + name.len());
    full.extend_from_slice(namespace.as_bytes());
    full.push(b':');
    full.extend_from_slice(name);
    full
}

/// Split a full xattr name back into (namespace, name).
pub(crate) fn split_full_name(full: &[u8]) -> Option<(&str, &[u8])> {
    let colon_pos = full.iter().position(|&b| b == b':')?;
    let ns = std::str::from_utf8(&full[..colon_pos]).ok()?;
    let name = &full[colon_pos + 1..];
    Some((ns, name))
}

// ---------------------------------------------------------------------------
// Directory encoding
// ---------------------------------------------------------------------------

/// Encode a per-inode xattr directory into a BLAKE3-verified binary blob.
///
/// Format:
/// ```text
/// [u8; 4]   magic          "XDIR"
/// u8        format_version 1
/// U32Le: entry_count
/// for each entry:
///   U16Le: name_len
///   [u8; name_len]: full name bytes (namespace:name)
/// [u8; 32]  BLAKE3-256 digest over all preceding bytes
/// ```
pub(crate) fn encode_dir(dir: &BTreeSet<Vec<u8>>) -> Vec<u8> {
    let mut payload = Vec::new();
    let count = U32Le::from_le(dir.len() as u32);
    payload.extend_from_slice(&count.encode());
    for name in dir {
        let name_len = U16Le::from_le(name.len() as u16);
        payload.extend_from_slice(&name_len.encode());
        payload.extend_from_slice(name);
    }

    // Build the header + payload for BLAKE3 domain-separated hashing.
    let mut blob = Vec::with_capacity(XATTR_DIR_MAGIC.len() + 1 + payload.len() + 32);
    blob.extend_from_slice(&XATTR_DIR_MAGIC);
    blob.push(XATTR_DIR_FORMAT_VERSION);
    blob.extend_from_slice(&payload);

    // Compute BLAKE3-256 domain-separated digest over everything written so far.
    let digest = blake3_domain_digest(
        &blob,
        SchemaFamilyId::BINARY_SCHEMA,
        XATTR_DIR_TYPE_ID,
        XATTR_DIR_VERSION,
        DomainTag::SectionBody,
    );
    blob.extend_from_slice(&digest);
    blob
}

/// Decode a BLAKE3-verified binary directory blob into a set of full names.
///
/// Handles both the BLAKE3-verified V1 format (magic "XDIR") and legacy
/// unverified format (raw U32Le count).
pub(crate) fn decode_dir(data: &[u8]) -> Option<BTreeSet<Vec<u8>>> {
    // Try v1 format first (magic "XDIR").
    if data.len() >= XATTR_DIR_MIN_BLOB_LEN && data[..4] == XATTR_DIR_MAGIC {
        return decode_dir_v1(data);
    }
    // Fall back to legacy format (raw U32Le count).
    decode_dir_legacy(data)
}

/// Decode the BLAKE3-verified V1 format directory blob.
pub(crate) fn decode_dir_v1(data: &[u8]) -> Option<BTreeSet<Vec<u8>>> {
    // Verify format version.
    if data[4] != XATTR_DIR_FORMAT_VERSION {
        return None;
    }

    // Split: blob content (up to last 32 bytes) and BLAKE3 digest (last 32 bytes).
    let content_end = data.len() - 32;
    let blob_content = &data[..content_end];
    let expected_digest: &[u8; 32] = data[content_end..].try_into().ok()?;

    // Verify BLAKE3 domain-separated digest.
    if blake3_domain_verify(
        blob_content,
        expected_digest,
        SchemaFamilyId::BINARY_SCHEMA,
        XATTR_DIR_TYPE_ID,
        XATTR_DIR_VERSION,
        DomainTag::SectionBody,
    )
    .is_err()
    {
        return None;
    }

    // Decode the payload (skip magic + version = 5 bytes).
    decode_dir_legacy(&data[5..content_end])
}

/// Decode a legacy-format directory blob (raw U32Le count, no magic/version/digest).
pub(crate) fn decode_dir_legacy(data: &[u8]) -> Option<BTreeSet<Vec<u8>>> {
    let mut dir = BTreeSet::new();
    let mut pos = 0;
    if data.len() < U32Le::BYTES {
        return None;
    }
    let count =
        U32Le::from_le_bytes(data[pos..pos + U32Le::BYTES].try_into().ok()?).as_raw() as usize;
    pos += U32Le::BYTES;

    for _ in 0..count {
        if pos + U16Le::BYTES > data.len() {
            return None;
        }
        let name_len =
            U16Le::from_le_bytes(data[pos..pos + U16Le::BYTES].try_into().ok()?).as_raw() as usize;
        pos += U16Le::BYTES;
        if pos + name_len > data.len() {
            return None;
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        dir.insert(name);
    }
    Some(dir)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    /// Shared counter for unique test store directories.
    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a temporary store and persistent xattr store for testing.
    fn make_store() -> (PersistentXattrStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-persistent-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");
        let pxs = PersistentXattrStore::new(Arc::new(Mutex::new(store)));
        (pxs, dir)
    }

    /// Helper: build a path and a make function for persistence tests.
    fn make_persist_path() -> (std::path::PathBuf, impl Fn() -> PersistentXattrStore) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tidefs-xattr-persist-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::create_dir_all(&path);
        let path_clone = path.clone();
        let make = move || {
            let store = LocalObjectStore::open_with_options(&path_clone, StoreOptions::test_fast())
                .expect("open store");
            PersistentXattrStore::new(Arc::new(Mutex::new(store)))
        };
        (path, make)
    }

    /// Create a store with a larger segment size for big-value tests.
    fn make_store_large() -> (PersistentXattrStore, std::path::PathBuf) {
        let n = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-xattr-persistent-large-{}-{}",
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
        let pxs = PersistentXattrStore::new(Arc::new(Mutex::new(store)));
        (pxs, dir)
    }

    // ── Basic get/set round-trip ──────────────────────────────────────

    #[test]
    fn set_get_roundtrip() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"key1", b"val1", 0).expect("set");
        let val = pxs.get(1, "user", b"key1").expect("get");
        assert_eq!(val, Some(b"val1".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let (pxs, _dir) = make_store();
        assert_eq!(pxs.get(1, "user", b"missing").unwrap(), None);
    }

    #[test]
    fn overwrite_with_flag_zero() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"key", b"first", 0).expect("set");
        pxs.set(1, "user", b"key", b"second", 0).expect("overwrite");
        assert_eq!(
            pxs.get(1, "user", b"key").unwrap(),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn empty_value_roundtrip() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"empty", b"", 0).expect("set empty");
        let val = pxs.get(1, "user", b"empty").expect("get empty");
        assert_eq!(val, Some(vec![]));
    }

    #[test]
    fn large_value_roundtrip() {
        let (pxs, _dir) = make_store_large();
        let big = vec![0xABu8; 8192];
        pxs.set(1, "user", b"big", &big, 0).expect("set big");
        assert_eq!(pxs.get(1, "user", b"big").unwrap(), Some(big));
    }

    #[test]
    fn binary_name_roundtrip() {
        let (pxs, _dir) = make_store();
        let name = vec![0x01, 0x02, 0x03, 0x04];
        pxs.set(1, "user", &name, b"binary-val", 0)
            .expect("set binary");
        assert_eq!(
            pxs.get(1, "user", &name).unwrap(),
            Some(b"binary-val".to_vec())
        );
    }

    // ── All four namespaces ───────────────────────────────────────────

    #[test]
    fn all_namespaces_roundtrip() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"a", b"ua", 0).expect("user");
        pxs.set(1, "system", b"b", b"sb", 0).expect("system");
        pxs.set(1, "security", b"c", b"sc", 0).expect("security");
        pxs.set(1, "trusted", b"d", b"td", 0).expect("trusted");

        assert_eq!(pxs.get(1, "user", b"a").unwrap(), Some(b"ua".to_vec()));
        assert_eq!(pxs.get(1, "system", b"b").unwrap(), Some(b"sb".to_vec()));
        assert_eq!(pxs.get(1, "security", b"c").unwrap(), Some(b"sc".to_vec()));
        assert_eq!(pxs.get(1, "trusted", b"d").unwrap(), Some(b"td".to_vec()));
    }

    // ── Create / Replace flags ────────────────────────────────────────

    #[test]
    fn create_flag_succeeds_on_new() {
        let (pxs, _dir) = make_store();
        assert!(pxs.set(1, "user", b"newkey", b"val", XATTR_CREATE).is_ok());
    }

    #[test]
    fn create_flag_fails_on_existing() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"dup", b"first", 0).expect("set");
        assert_eq!(
            pxs.set(1, "user", b"dup", b"second", XATTR_CREATE),
            Err(PersistentXattrError::AttrExists)
        );
    }

    #[test]
    fn replace_flag_succeeds_on_existing() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"rep", b"old", 0).expect("set");
        assert_eq!(pxs.set(1, "user", b"rep", b"new", XATTR_REPLACE), Ok(()));
        assert_eq!(pxs.get(1, "user", b"rep").unwrap(), Some(b"new".to_vec()));
    }

    #[test]
    fn replace_flag_fails_on_missing() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "user", b"missing", b"val", XATTR_REPLACE),
            Err(PersistentXattrError::AttrNotFound)
        );
    }

    #[test]
    fn invalid_flags_rejected() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "user", b"key", b"val", XATTR_CREATE | XATTR_REPLACE),
            Err(PersistentXattrError::InvalidFlags)
        );
        assert_eq!(
            pxs.set(1, "user", b"key", b"val", 4),
            Err(PersistentXattrError::InvalidFlags)
        );
    }

    // ── Remove ────────────────────────────────────────────────────────

    #[test]
    fn remove_existing() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"del", b"val", 0).expect("set");
        assert_eq!(pxs.remove(1, "user", b"del"), Ok(true));
        assert_eq!(pxs.get(1, "user", b"del").unwrap(), None);
    }

    #[test]
    fn remove_missing_returns_false() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"key", b"val", 0).expect("set");
        assert_eq!(pxs.remove(1, "user", b"missing"), Ok(false));
    }

    #[test]
    fn remove_then_re_add_works() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"cycle", b"a", 0).expect("set a");
        assert_eq!(pxs.remove(1, "user", b"cycle"), Ok(true));
        pxs.set(1, "user", b"cycle", b"b", 0).expect("set b");
        assert_eq!(pxs.get(1, "user", b"cycle").unwrap(), Some(b"b".to_vec()));
    }

    // ── List ──────────────────────────────────────────────────────────

    #[test]
    fn list_returns_all_entries() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"a", b"1", 0).expect("set a");
        pxs.set(1, "user", b"b", b"2", 0).expect("set b");
        pxs.set(1, "system", b"c", b"3", 0).expect("set c");

        let entries = pxs.list(1).expect("list");
        assert_eq!(entries.len(), 3);
        assert!(entries.contains(&("user".to_string(), b"a".to_vec())));
        assert!(entries.contains(&("user".to_string(), b"b".to_vec())));
        assert!(entries.contains(&("system".to_string(), b"c".to_vec())));
    }

    #[test]
    fn list_empty_inode_returns_empty() {
        let (pxs, _dir) = make_store();
        let entries = pxs.list(99).expect("list");
        assert!(entries.is_empty());
    }

    #[test]
    fn list_after_removing_last_attr() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"key", b"val", 0).expect("set");
        pxs.remove(1, "user", b"key").expect("remove");
        let entries = pxs.list(1).expect("list");
        assert!(entries.is_empty());
    }

    // ── Multiple inodes ───────────────────────────────────────────────

    #[test]
    fn multiple_inodes_independent() {
        let (pxs, _dir) = make_store();
        pxs.set(1, "user", b"inode1key", b"a", 0).expect("set 1");
        pxs.set(2, "user", b"inode2key", b"b", 0).expect("set 2");

        assert_eq!(
            pxs.get(1, "user", b"inode1key").unwrap(),
            Some(b"a".to_vec())
        );
        assert_eq!(
            pxs.get(2, "user", b"inode2key").unwrap(),
            Some(b"b".to_vec())
        );
        assert_eq!(pxs.get(1, "user", b"inode2key").unwrap(), None);
        assert_eq!(pxs.get(2, "user", b"inode1key").unwrap(), None);

        let entries1 = pxs.list(1).expect("list 1");
        assert_eq!(entries1.len(), 1);
        let entries2 = pxs.list(2).expect("list 2");
        assert_eq!(entries2.len(), 1);
    }

    // ── Validation ────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_name() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "user", b"", b"val", 0),
            Err(PersistentXattrError::InvalidName)
        );
    }

    #[test]
    fn rejects_nul_in_name() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "user", b"bad\0byte", b"val", 0),
            Err(PersistentXattrError::InvalidName)
        );
    }

    #[test]
    fn rejects_unknown_namespace() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "custom", b"foo", b"val", 0),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn rejects_empty_namespace() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "", b"foo", b"val", 0),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn rejects_namespace_with_colon() {
        let (pxs, _dir) = make_store();
        assert_eq!(
            pxs.set(1, "usr:evil", b"foo", b"val", 0),
            Err(PersistentXattrError::InvalidNamespace)
        );
    }

    #[test]
    fn rejects_value_too_large() {
        let (pxs, _dir) = make_store_large();
        let big = vec![0xCC; MAX_XATTR_VALUE_LEN + 1];
        assert_eq!(
            pxs.set(1, "user", b"big", &big, 0),
            Err(PersistentXattrError::ValueTooLarge)
        );
    }

    #[test]
    fn value_at_exact_max_allowed() {
        let (pxs, _dir) = make_store_large();
        let exact = vec![0xBB; MAX_XATTR_VALUE_LEN];
        pxs.set(1, "user", b"max", &exact, 0).expect("set at max");
        assert_eq!(pxs.get(1, "user", b"max").unwrap(), Some(exact));
    }

    // ── Count limit ───────────────────────────────────────────────────

    #[test]
    fn count_limit_enforced() {
        let (pxs, _dir) = make_store();
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("key{i}");
            pxs.set(1, "user", name.as_bytes(), b"val", 0)
                .expect("set within limit");
        }
        assert_eq!(
            pxs.set(1, "user", b"overlimit", b"val", 0),
            Err(PersistentXattrError::InodeXattrLimit)
        );
    }

    // ── Persistence round-trip ────────────────────────────────────────

    #[test]
    fn persistence_across_reopen() {
        let (_path, make) = make_persist_path();

        // Write through one store instance.
        let pxs = make();
        pxs.set(1, "user", b"persist", b"survives", 0)
            .expect("set persist");
        pxs.set(1, "user", b"also", b"here", 0).expect("set also");
        // Drop the store to flush and close.
        drop(pxs);

        // Re-open and verify.
        let pxs2 = make();
        assert_eq!(
            pxs2.get(1, "user", b"persist").unwrap(),
            Some(b"survives".to_vec())
        );
        assert_eq!(
            pxs2.get(1, "user", b"also").unwrap(),
            Some(b"here".to_vec())
        );

        let entries = pxs2.list(1).expect("list");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn persistence_delete_across_reopen() {
        let (_path, make) = make_persist_path();

        {
            let pxs = make();
            pxs.set(1, "user", b"todel", b"x", 0).expect("set");
            assert_eq!(pxs.remove(1, "user", b"todel"), Ok(true));
        }

        {
            let pxs2 = make();
            assert_eq!(pxs2.get(1, "user", b"todel").unwrap(), None);
            let entries = pxs2.list(1).expect("list");
            assert!(entries.is_empty());
        }
    }

    // ── Directory encoding BLAKE3-verified round-trip ──────────────────

    #[test]
    fn dir_encode_decode_roundtrip() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:key1".to_vec());
        dir.insert(b"system:key2".to_vec());
        dir.insert(b"trusted:key3".to_vec());
        let encoded = encode_dir(&dir);
        // Verify the encoded blob starts with "XDIR" magic.
        assert_eq!(&encoded[..4], &XATTR_DIR_MAGIC);
        assert_eq!(encoded[4], XATTR_DIR_FORMAT_VERSION);
        let decoded = decode_dir(&encoded).expect("decode should succeed");
        assert_eq!(decoded, dir);
    }

    #[test]
    fn dir_encode_decode_empty() {
        let dir: BTreeSet<Vec<u8>> = BTreeSet::new();
        let encoded = encode_dir(&dir);
        assert_eq!(&encoded[..4], &XATTR_DIR_MAGIC);
        let decoded = decode_dir(&encoded).expect("decode should succeed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn dir_blake3_digest_detects_tampering() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:tamper".to_vec());
        let mut encoded = encode_dir(&dir);
        // Flip a byte in the payload region (after magic + version, before digest).
        encoded[6] ^= 0xFF;
        assert!(decode_dir(&encoded).is_none());
    }

    #[test]
    fn dir_blake3_rejects_wrong_magic() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:a".to_vec());
        let mut encoded = encode_dir(&dir);
        encoded[0] ^= 0xFF; // corrupt magic
        assert!(decode_dir(&encoded).is_none());
    }

    #[test]
    fn dir_blake3_rejects_unknown_version() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:a".to_vec());
        let mut encoded = encode_dir(&dir);
        encoded[4] = 99; // unknown version
        assert!(decode_dir(&encoded).is_none());
    }

    #[test]
    fn dir_blake3_rejects_truncated_blob() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:a".to_vec());
        let encoded = encode_dir(&dir);
        // Truncate to remove part of the digest.
        let truncated = &encoded[..encoded.len() - 4];
        assert!(decode_dir(truncated).is_none());
    }

    #[test]
    fn dir_blake3_rejects_corrupt_digest() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:a".to_vec());
        let mut encoded = encode_dir(&dir);
        // Corrupt a byte in the digest region.
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(decode_dir(&encoded).is_none());
    }

    // ── Legacy directory format backward compatibility ─────────────────

    #[test]
    fn dir_decode_legacy_format_still_works() {
        let mut dir = BTreeSet::new();
        dir.insert(b"user:oldkey".to_vec());
        // Manually construct legacy blob (raw U32Le + entries, no magic/digest).
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&1_u32.to_le_bytes()); // count=1
        legacy.extend_from_slice(&(b"user:oldkey".len() as u16).to_le_bytes());
        legacy.extend_from_slice(b"user:oldkey");
        let decoded = decode_dir(&legacy).expect("legacy decode should succeed");
        assert_eq!(decoded, dir);
    }

    // ── Legacy error cases still detected ─────────────────────────────

    #[test]
    fn dir_decode_corrupt_truncated() {
        assert!(decode_dir(&[0x01]).is_none());
        assert!(decode_dir(&[]).is_none());
    }

    #[test]
    fn dir_decode_corrupt_truncated_entry() {
        let mut data = vec![1, 0, 0, 0]; // count=1
        data.extend_from_slice(&[10, 0]); // name_len=10
        data.extend_from_slice(b"short"); // only 5 bytes
        assert!(decode_dir(&data).is_none());
    }

    // ── Error POSIX mapping ───────────────────────────────────────────

    #[test]
    fn error_posix_mapping() {
        assert_eq!(PersistentXattrError::InvalidName.raw_os_error(), 22);
        assert_eq!(PersistentXattrError::ValueTooLarge.raw_os_error(), 7);
        assert_eq!(PersistentXattrError::InvalidNamespace.raw_os_error(), 95);
        assert_eq!(PersistentXattrError::AttrNotFound.raw_os_error(), 61);
        assert_eq!(PersistentXattrError::AttrExists.raw_os_error(), 17);
        assert_eq!(
            PersistentXattrError::Internal("oops".to_string()).raw_os_error(),
            5
        );
    }
}
