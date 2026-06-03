//! Extended attribute store trait and types.
//!
//! Provides [`XattrKey`], [`XattrValue`], and the [`XattrStore`] trait for
//! get/set/list/remove of extended attributes. Ships with
//! [`MemXattrStore`], a default in-memory implementation backed
//! by `BTreeMap` + `RwLock`.
//!
//! The trait is designed so callers (inode-table, namespace, FUSE adapter)
//! can swap in a persistent on-disk store without changing the attribute
//! contract.

use std::collections::BTreeMap;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Xattr namespace
// ---------------------------------------------------------------------------

/// Recognised Linux extended-attribute namespaces.
///
/// TideFS currently supports `user`, `system`, `security`, and `trusted`
/// namespaces.  Unknown prefixes are rejected with `EOPNOTSUPP`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum XattrNamespace {
    /// `user.*` — owned by unprivileged users.
    User,
    /// `system.*` — kernel-managed (e.g. `system.posix_acl_access`).
    System,
    /// `security.*` — LSM-managed (SELinux, SMACK, AppArmor).
    Security,
    /// `trusted.*` — requires `CAP_SYS_ADMIN` (uid 0).
    Trusted,
}

impl XattrNamespace {
    /// Return the dot-terminated prefix for this namespace.
    #[must_use]
    pub const fn prefix(self) -> &'static [u8] {
        match self {
            Self::User => b"user.",
            Self::System => b"system.",
            Self::Security => b"security.",
            Self::Trusted => b"trusted.",
        }
    }

    /// Return the prefix length in bytes.
    #[must_use]
    pub const fn prefix_len(self) -> usize {
        self.prefix().len()
    }

    /// Return the display label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
            Self::Security => "security",
            Self::Trusted => "trusted",
        }
    }

    /// Parse a namespace from a prefix.  Returns `None` when the prefix
    /// is not recognised.
    #[must_use]
    pub fn from_prefix(name: &[u8]) -> Option<Self> {
        if name.starts_with(b"user.") && name.len() > b"user.".len() {
            Some(Self::User)
        } else if name.starts_with(b"system.") && name.len() > b"system.".len() {
            Some(Self::System)
        } else if name.starts_with(b"security.") && name.len() > b"security.".len() {
            Some(Self::Security)
        } else if name.starts_with(b"trusted.") && name.len() > b"trusted.".len() {
            Some(Self::Trusted)
        } else {
            None
        }
    }

    /// Return `true` when this namespace requires root (uid 0).
    #[must_use]
    pub const fn requires_root(self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// Return the suffix (the name portion after the prefix) when the
    /// given name matches this namespace.  Returns `None` when the prefix
    /// doesn't match or the suffix is empty.
    #[must_use]
    pub fn suffix(self, name: &[u8]) -> Option<&[u8]> {
        let prefix = self.prefix();
        if name.starts_with(prefix) && name.len() > prefix.len() {
            Some(&name[prefix.len()..])
        } else {
            None
        }
    }
}

impl std::fmt::Display for XattrNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

// ---------------------------------------------------------------------------
// XattrKey
// ---------------------------------------------------------------------------

/// A validated extended-attribute key: namespace prefix plus
/// attribute name.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct XattrKey {
    /// The dot-terminated namespace (e.g. `"user."`).
    namespace: XattrNamespace,
    /// Full wire-format name including the namespace prefix.
    full_name: Vec<u8>,
}

impl XattrKey {
    /// Maximum length of the full xattr name in bytes (Linux limit).
    pub const MAX_NAME_LEN: usize = 255;

    /// Create a validated [`XattrKey`] from a raw name.
    ///
    /// Returns `Err` when the name is empty, contains NUL, exceeds the
    /// maximum length, or has an unrecognised namespace prefix.
    pub fn new(name: &[u8]) -> Result<Self, XattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > Self::MAX_NAME_LEN {
            return Err(XattrError::NameTooLong);
        }
        let namespace =
            XattrNamespace::from_prefix(name).ok_or(XattrError::UnsupportedNamespace)?;
        Ok(Self {
            namespace,
            full_name: name.to_vec(),
        })
    }

    /// Return the namespace component.
    #[must_use]
    pub const fn namespace(&self) -> XattrNamespace {
        self.namespace
    }

    /// Return the full wire-format name (namespace prefix + suffix).
    #[must_use]
    pub fn full_name(&self) -> &[u8] {
        &self.full_name
    }

    /// Return the suffix (the part after the namespace prefix).
    #[must_use]
    pub fn suffix(&self) -> &[u8] {
        &self.full_name[self.namespace.prefix_len()..]
    }

    /// Return `true` when this key requires root to read or write.
    #[must_use]
    pub const fn requires_root(&self) -> bool {
        self.namespace.requires_root()
    }
}

// ---------------------------------------------------------------------------
// XattrValue
// ---------------------------------------------------------------------------

/// An opaque extended-attribute value with a size limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrValue {
    data: Vec<u8>,
}

impl XattrValue {
    /// Maximum permitted xattr value size (64 KiB, Linux limit).
    pub const MAX_VALUE_LEN: usize = 64 * 1024;

    /// Create a new [`XattrValue`] from arbitrary bytes.
    ///
    /// Returns `Err(XattrError::ValueTooLarge)` when the value exceeds
    /// [`Self::MAX_VALUE_LEN`].
    pub fn new(data: Vec<u8>) -> Result<Self, XattrError> {
        if data.len() > Self::MAX_VALUE_LEN {
            return Err(XattrError::ValueTooLarge);
        }
        Ok(Self { data })
    }

    /// Return the value as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the length of the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` when the value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Consume and return the inner bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by xattr-store operations.
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
    /// The caller lacks permission (e.g. non-root accessing `trusted.*`).
    PermissionDenied,
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
            Self::InvalidName | Self::NameTooLong => libc::EINVAL,
            Self::ValueTooLarge => libc::E2BIG,
            Self::UnsupportedNamespace => libc::EOPNOTSUPP,
            Self::AttrNotFound => libc::ENODATA,
            Self::AttrExists => libc::EEXIST,
            Self::PermissionDenied => libc::EPERM,
            Self::InodeXattrLimit => libc::ENOSPC,
            Self::Internal(_) => libc::EIO,
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
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::InodeXattrLimit => write!(f, "per-inode xattr count limit exceeded"),
            Self::Internal(msg) => write!(f, "internal xattr store error: {msg}"),
        }
    }
}

impl std::error::Error for XattrError {}

// ---------------------------------------------------------------------------
// XattrStore trait
// ---------------------------------------------------------------------------

/// Trait for extended-attribute storage and manipulation.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// threads (e.g. behind an `Arc` in a FUSE daemon).
pub trait XattrStore: Send + Sync {
    /// Get the value of `name`, or return [`XattrError::AttrNotFound`].
    fn get(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, XattrError>;

    /// Set the value of `name`.
    ///
    /// `flags` is one of: 0 (create or replace), [`XATTR_CREATE`], or
    /// [`XATTR_REPLACE`].
    fn set(&self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), XattrError>;

    /// List all attribute names for `ino`, returning null-separated
    /// (`\0`) name bytes terminated by a final null (Linux convention).
    fn list(&self, ino: u64) -> Result<Vec<u8>, XattrError>;

    /// Remove the attribute `name`.
    ///
    /// Returns [`XattrError::AttrNotFound`] when the name does not exist.
    fn remove(&self, ino: u64, name: &[u8]) -> Result<(), XattrError>;
}

/// `XATTR_CREATE`: fail if the attribute already exists.
pub const XATTR_CREATE: u32 = 1;

/// `XATTR_REPLACE`: fail if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

/// Maximum number of extended attributes per inode (Linux limit).
pub const MAX_XATTR_COUNT: usize = 256;

/// Maximum size of a single extended attribute value in bytes (64 KiB, Linux limit).
pub const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Default in-memory implementation
// ---------------------------------------------------------------------------

/// A per-inode map of attribute name → value.
type PerInodeXattrs = BTreeMap<Vec<u8>, Vec<u8>>;

/// Default in-memory xattr store backed by `BTreeMap<u64, BTreeMap>` +
/// `RwLock`.
///
/// Suitable for testing and single-node use. The trait boundary allows
/// replacement with an on-disk store later.
#[derive(Debug, Default)]
pub struct MemXattrStore {
    inner: RwLock<BTreeMap<u64, PerInodeXattrs>>,
}

impl MemXattrStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
        }
    }

    /// Return the number of inodes with at least one xattr.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().expect("RwLock poisoned").len()
    }

    /// Return `true` when the store has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("RwLock poisoned").is_empty()
    }

    /// Remove all xattrs for an inode (used on inode deletion).
    pub fn remove_inode(&self, ino: u64) {
        self.inner.write().expect("RwLock poisoned").remove(&ino);
    }
}

impl XattrStore for MemXattrStore {
    fn get(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, XattrError> {
        // Validate the key first.
        let _key = XattrKey::new(name)?;
        let map = self.inner.read().expect("RwLock poisoned");
        let per_inode = map.get(&ino).ok_or(XattrError::AttrNotFound)?;
        per_inode.get(name).cloned().ok_or(XattrError::AttrNotFound)
    }

    fn set(&self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), XattrError> {
        // Validate key and value.
        let _key = XattrKey::new(name)?;
        let _value = XattrValue::new(value.to_vec())?;

        // Reject invalid flag combinations.
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(XattrError::InvalidName); // maps to EINVAL
        }

        let mut map = self.inner.write().expect("RwLock poisoned");
        let per_inode = map.entry(ino).or_default();

        match flags {
            XATTR_CREATE => {
                if per_inode.contains_key(name) {
                    return Err(XattrError::AttrExists);
                }
                if per_inode.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
            XATTR_REPLACE => {
                if !per_inode.contains_key(name) {
                    return Err(XattrError::AttrNotFound);
                }
            }
            _ => {
                if !per_inode.contains_key(name) && per_inode.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
        }

        per_inode.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    fn list(&self, ino: u64) -> Result<Vec<u8>, XattrError> {
        let map = self.inner.read().expect("RwLock poisoned");
        let per_inode = match map.get(&ino) {
            Some(p) => p,
            None => return Ok(Vec::new()), // inode has no xattrs → empty list
        };
        let mut buf = Vec::new();
        for name in per_inode.keys() {
            buf.extend_from_slice(name);
            buf.push(0);
        }
        Ok(buf)
    }

    fn remove(&self, ino: u64, name: &[u8]) -> Result<(), XattrError> {
        let _key = XattrKey::new(name)?;
        let mut map = self.inner.write().expect("RwLock poisoned");
        let per_inode = map.get_mut(&ino).ok_or(XattrError::AttrNotFound)?;
        if per_inode.remove(name).is_none() {
            return Err(XattrError::AttrNotFound);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── XattrNamespace ─────────────────────────────────────────────────
    #[test]
    fn namespace_parsing_roundtrip() {
        let cases: [(&[u8], XattrNamespace); 4] = [
            (b"user.myattr", XattrNamespace::User),
            (b"system.posix_acl_access", XattrNamespace::System),
            (b"security.selinux", XattrNamespace::Security),
            (b"trusted.overlay.upper", XattrNamespace::Trusted),
        ];
        for (prefix, expected) in cases {
            let ns = XattrNamespace::from_prefix(prefix).expect("parse namespace");
            assert_eq!(ns, expected);
            assert!(prefix.starts_with(ns.prefix()));
        }
    }

    #[test]
    fn namespace_rejects_empty_and_nul() {
        assert!(XattrNamespace::from_prefix(b"").is_none());
        // from_prefix only parses the namespace prefix; NUL validation happens in XattrKey::new
        assert!(XattrNamespace::from_prefix(b"user. bad").is_some());
        assert!(XattrNamespace::from_prefix(b"bad.prefix").is_none());
        assert!(XattrNamespace::from_prefix(b"user.").is_none()); // no suffix
    }

    #[test]
    fn namespace_requires_root() {
        assert!(!XattrNamespace::User.requires_root());
        assert!(!XattrNamespace::System.requires_root());
        assert!(!XattrNamespace::Security.requires_root());
        assert!(XattrNamespace::Trusted.requires_root());
    }

    #[test]
    fn namespace_suffix_extraction() {
        let ns = XattrNamespace::User;
        assert_eq!(ns.suffix(b"user.mykey"), Some(b"mykey".as_slice()));
        assert_eq!(ns.suffix(b"user."), None);
        assert_eq!(ns.suffix(b"trusted.mykey"), None);
        assert_eq!(ns.suffix(b"user"), None);
    }

    // ── XattrKey ───────────────────────────────────────────────────────

    #[test]
    fn xattr_key_valid() {
        let key = XattrKey::new(b"user.test").expect("valid key");
        assert_eq!(key.namespace(), XattrNamespace::User);
        assert_eq!(key.suffix(), b"test");
        assert_eq!(key.full_name(), b"user.test");
    }

    #[test]
    fn xattr_key_rejects_empty() {
        assert_eq!(XattrKey::new(b""), Err(XattrError::InvalidName));
    }

    #[test]
    fn xattr_key_rejects_nul() {
        assert_eq!(XattrKey::new(b"user.bad\0"), Err(XattrError::InvalidName));
    }

    #[test]
    fn xattr_key_rejects_too_long() {
        let long = vec![b'a'; XattrKey::MAX_NAME_LEN + 1];
        assert_eq!(XattrKey::new(&long), Err(XattrError::NameTooLong));
    }

    #[test]
    fn xattr_key_rejects_unknown_namespace() {
        assert_eq!(
            XattrKey::new(b"custom.myattr"),
            Err(XattrError::UnsupportedNamespace)
        );
        assert_eq!(
            XattrKey::new(b"user"), // no dot
            Err(XattrError::UnsupportedNamespace)
        );
    }

    // ── XattrValue ─────────────────────────────────────────────────────

    #[test]
    fn xattr_value_roundtrip() {
        let val = XattrValue::new(b"hello".to_vec()).expect("valid value");
        assert_eq!(val.as_bytes(), b"hello");
        assert_eq!(val.len(), 5);
        assert!(!val.is_empty());
        assert_eq!(val.into_bytes(), b"hello");
    }

    #[test]
    fn xattr_value_empty() {
        let val = XattrValue::new(vec![]).expect("empty value");
        assert!(val.is_empty());
        assert_eq!(val.len(), 0);
    }

    #[test]
    fn xattr_value_rejects_oversized() {
        let big = vec![0xAA; XattrValue::MAX_VALUE_LEN + 1];
        assert_eq!(XattrValue::new(big), Err(XattrError::ValueTooLarge));
    }

    #[test]
    fn xattr_value_accepts_exact_max() {
        let exact = vec![0xBB; XattrValue::MAX_VALUE_LEN];
        let val = XattrValue::new(exact).expect("exact max");
        assert_eq!(val.len(), XattrValue::MAX_VALUE_LEN);
    }

    // ── XattrError ─────────────────────────────────────────────────────

    #[test]
    fn xattr_error_maps_to_posix_errno() {
        assert_eq!(XattrError::InvalidName.raw_os_error(), libc::EINVAL);
        assert_eq!(XattrError::NameTooLong.raw_os_error(), libc::EINVAL);
        assert_eq!(XattrError::ValueTooLarge.raw_os_error(), libc::E2BIG);
        assert_eq!(
            XattrError::UnsupportedNamespace.raw_os_error(),
            libc::EOPNOTSUPP
        );
        assert_eq!(XattrError::AttrNotFound.raw_os_error(), libc::ENODATA);
        assert_eq!(XattrError::AttrExists.raw_os_error(), libc::EEXIST);
        assert_eq!(XattrError::PermissionDenied.raw_os_error(), libc::EPERM);
    }

    // ── MemXattrStore ──────────────────────────────────────────────────

    #[test]
    fn mem_store_set_get_roundtrip() {
        let store = MemXattrStore::new();
        store.set(1, b"user.key1", b"val1", 0).expect("set");
        let val = store.get(1, b"user.key1").expect("get");
        assert_eq!(val, b"val1");
    }

    #[test]
    fn mem_store_get_missing_returns_not_found() {
        let store = MemXattrStore::new();
        assert_eq!(store.get(1, b"user.missing"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn mem_store_get_missing_inode() {
        let store = MemXattrStore::new();
        assert_eq!(store.get(42, b"user.any"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn mem_store_overwrite_with_flag_zero() {
        let store = MemXattrStore::new();
        store.set(1, b"user.key", b"first", 0).expect("set");
        store.set(1, b"user.key", b"second", 0).expect("overwrite");
        assert_eq!(store.get(1, b"user.key").unwrap(), b"second");
    }

    #[test]
    fn mem_store_create_flag_succeeds_on_new() {
        let store = MemXattrStore::new();
        assert_eq!(store.set(1, b"user.newkey", b"val", XATTR_CREATE), Ok(()));
    }

    #[test]
    fn mem_store_create_flag_fails_on_existing() {
        let store = MemXattrStore::new();
        store.set(1, b"user.dup", b"first", 0).expect("set");
        assert_eq!(
            store.set(1, b"user.dup", b"second", XATTR_CREATE),
            Err(XattrError::AttrExists)
        );
    }

    #[test]
    fn mem_store_replace_flag_succeeds_on_existing() {
        let store = MemXattrStore::new();
        store.set(1, b"user.rep", b"old", 0).expect("set");
        assert_eq!(store.set(1, b"user.rep", b"new", XATTR_REPLACE), Ok(()));
        assert_eq!(store.get(1, b"user.rep").unwrap(), b"new");
    }

    #[test]
    fn mem_store_replace_flag_fails_on_missing() {
        let store = MemXattrStore::new();
        assert_eq!(
            store.set(1, b"user.missing", b"val", XATTR_REPLACE),
            Err(XattrError::AttrNotFound)
        );
    }

    #[test]
    fn mem_store_list_returns_keys() {
        let store = MemXattrStore::new();
        store.set(1, b"user.a", b"1", 0).expect("set a");
        store.set(1, b"user.b", b"2", 0).expect("set b");

        let list = store.list(1).expect("list");
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".as_slice()));
        assert!(names.contains(&b"user.b".as_slice()));
    }

    #[test]
    fn mem_store_list_ends_with_null() {
        let store = MemXattrStore::new();
        store.set(1, b"user.zzz", b"x", 0).expect("set");
        let list = store.list(1).expect("list");
        assert_eq!(list.last(), Some(&0));
    }

    #[test]
    fn mem_store_list_empty_inode_no_attrs() {
        let store = MemXattrStore::new();
        // An inode that has never had any xattrs set returns an empty list.
        assert_eq!(store.list(99), Ok(Vec::new()));
    }

    #[test]
    fn mem_store_list_inode_with_no_attrs_after_removal() {
        let store = MemXattrStore::new();
        store.set(1, b"user.key", b"val", 0).expect("set");
        store.remove(1, b"user.key").expect("remove");
        // After removing the last attr, list should return empty (trailing null only).
        let list = store.list(1).expect("list");
        assert!(list.is_empty());
    }

    #[test]
    fn mem_store_remove_existing() {
        let store = MemXattrStore::new();
        store.set(1, b"user.del", b"val", 0).expect("set");
        assert_eq!(store.remove(1, b"user.del"), Ok(()));
        assert_eq!(store.get(1, b"user.del"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn mem_store_remove_missing() {
        let store = MemXattrStore::new();
        store.set(1, b"user.key", b"val", 0).expect("set");
        assert_eq!(
            store.remove(1, b"user.missing"),
            Err(XattrError::AttrNotFound)
        );
    }

    #[test]
    fn mem_store_remove_missing_inode() {
        let store = MemXattrStore::new();
        assert_eq!(store.remove(42, b"user.any"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn mem_store_rejects_invalid_names() {
        let store = MemXattrStore::new();
        assert_eq!(store.set(1, b"", b"val", 0), Err(XattrError::InvalidName));
        assert_eq!(
            store.set(1, b"bad.prefix", b"val", 0),
            Err(XattrError::UnsupportedNamespace)
        );
    }

    #[test]
    fn mem_store_rejects_oversized_value() {
        let store = MemXattrStore::new();
        let big = vec![0xCC; XattrValue::MAX_VALUE_LEN + 1];
        assert_eq!(
            store.set(1, b"user.big", &big, 0),
            Err(XattrError::ValueTooLarge)
        );
    }

    #[test]
    fn mem_store_rejects_invalid_flags() {
        let store = MemXattrStore::new();
        assert_eq!(
            store.set(1, b"user.key", b"val", XATTR_CREATE | XATTR_REPLACE),
            Err(XattrError::InvalidName)
        );
        assert_eq!(
            store.set(1, b"user.key", b"val", 4),
            Err(XattrError::InvalidName)
        );
    }

    #[test]
    fn mem_store_multiple_inodes_independent() {
        let store = MemXattrStore::new();
        store.set(1, b"user.inode1", b"a", 0).expect("set 1");
        store.set(2, b"user.inode2", b"b", 0).expect("set 2");

        assert_eq!(store.get(1, b"user.inode1").unwrap(), b"a");
        assert_eq!(store.get(2, b"user.inode2").unwrap(), b"b");
        assert_eq!(store.get(1, b"user.inode2"), Err(XattrError::AttrNotFound));
        assert_eq!(store.get(2, b"user.inode1"), Err(XattrError::AttrNotFound));
    }

    #[test]
    fn mem_store_len_and_is_empty() {
        let store = MemXattrStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.set(1, b"user.key", b"val", 0).expect("set");
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn mem_store_remove_inode_clears_all() {
        let store = MemXattrStore::new();
        store.set(1, b"user.a", b"1", 0).expect("set a");
        store.set(1, b"user.b", b"2", 0).expect("set b");
        assert_eq!(store.len(), 1);
        store.remove_inode(1);
        assert!(store.is_empty());
        assert_eq!(store.get(1, b"user.a"), Err(XattrError::AttrNotFound));
    }
}
