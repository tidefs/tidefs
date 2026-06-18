// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(any(test, feature = "persistence")), no_std)]
#![forbid(unsafe_code)]
//! Runtime polymorphic xattr storage.
//!
//! Wraps [`XattrStorage`] from [`tidefs_types_polymorphic_xattr_core`]
//! and provides get, set, remove, and list operations with
//! hysteresis-driven representation switching between inline bundle
//! (O(n), n ≤ 16) and B+tree (O(log n), any size).
//!
//! This is an in-memory runtime crate (Phase 2 of the polymorphic
//! xattr storage design). Persistence through the locator table and
//! Review debt TFR-002/TFR-013 covers on-disk B+tree page serialization.

#[cfg(any(test, feature = "persistence"))]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use tidefs_btree::BPlusTree;
pub use tidefs_types_polymorphic_xattr_core::DatasetXattrPolicy;
use tidefs_types_polymorphic_xattr_core::{
    should_use_inline_from_tree, should_use_tree, LocatorId, XattrBtreeLeafEntry, XattrBtreeRootV1,
    XattrBundleV1, XattrStorage, XattrStorageKind,
};

// ---------------------------------------------------------------------------
// XattrStoreError
// ---------------------------------------------------------------------------

/// Errors returned by xattr storage operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrStoreError {
    /// Remove attempted but no entry with this name was found.
    EntryNotFound,
}

/// Errors returned while building a POSIX `listxattr` name buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNameListError {
    /// A name is empty and cannot be represented as a POSIX xattr name.
    EmptyName,
    /// A name contains an interior NUL byte and cannot be represented in the
    /// NUL-delimited POSIX name-list format.
    NameContainsNul,
    /// A single xattr name exceeds the POSIX/Linux name length limit.
    NameTooLong { len: usize, max: usize },
    /// The input contains the same xattr name more than once.
    DuplicateName,
    /// The packed name list would overflow addressable memory.
    NameListTooLarge,
}

/// Action a POSIX `listxattr` buffer request should take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNameListBufferAction {
    /// Return the required packed name-list size without copying bytes.
    ReportRequiredSize,
    /// Copy the packed name-list bytes into the caller-provided buffer.
    CopyNames,
}

/// Pure POSIX `listxattr` buffer-size plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrNameListBufferPlan {
    pub requested_size: usize,
    pub required_size: usize,
    pub action: XattrNameListBufferAction,
}

impl XattrNameListBufferPlan {
    /// Return true when the caller requested a size-only probe.
    #[must_use]
    pub const fn reports_size_only(self) -> bool {
        matches!(self.action, XattrNameListBufferAction::ReportRequiredSize)
    }

    /// Return true when the plan can return packed name bytes.
    #[must_use]
    pub const fn copies_names(self) -> bool {
        matches!(self.action, XattrNameListBufferAction::CopyNames)
    }
}

/// Errors returned while planning POSIX `listxattr` buffer handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNameListBufferError {
    /// The caller supplied a non-zero buffer that cannot fit the packed names.
    /// POSIX callers should map this condition to `ERANGE`.
    BufferTooSmall {
        requested_size: usize,
        required_size: usize,
    },
}

/// Errors returned while reading POSIX `listxattr` bytes with buffer semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNameListReadError {
    /// Stored names cannot be represented as a POSIX name list.
    InvalidNameList(XattrNameListError),
    /// The caller supplied a non-zero buffer that cannot fit the packed names.
    /// POSIX callers should map this condition to `ERANGE`.
    BufferTooSmall {
        requested_size: usize,
        required_size: usize,
    },
}

impl From<XattrNameListBufferError> for XattrNameListReadError {
    fn from(err: XattrNameListBufferError) -> Self {
        match err {
            XattrNameListBufferError::BufferTooSmall {
                requested_size,
                required_size,
            } => XattrNameListReadError::BufferTooSmall {
                requested_size,
                required_size,
            },
        }
    }
}

/// POSIX `listxattr` read result for a requested buffer size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrNameListRead {
    pub plan: XattrNameListBufferPlan,
    pub bytes: Vec<u8>,
}

/// Action a POSIX `getxattr` value buffer request should take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrValueBufferAction {
    /// Return the required value size without copying bytes.
    ReportRequiredSize,
    /// Copy the xattr value bytes into the caller-provided buffer.
    CopyValue,
}

/// Pure POSIX `getxattr` value buffer-size plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrValueBufferPlan {
    pub requested_size: usize,
    pub required_size: usize,
    pub action: XattrValueBufferAction,
}

impl XattrValueBufferPlan {
    /// Return true when the caller requested a size-only probe.
    #[must_use]
    pub const fn reports_size_only(self) -> bool {
        matches!(self.action, XattrValueBufferAction::ReportRequiredSize)
    }

    /// Return true when the plan can return value bytes.
    #[must_use]
    pub const fn copies_value(self) -> bool {
        matches!(self.action, XattrValueBufferAction::CopyValue)
    }
}

/// Errors returned while planning POSIX `getxattr` value buffer handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrValueBufferError {
    /// The caller supplied a non-zero buffer that cannot fit the value.
    /// POSIX callers should map this condition to `ERANGE`.
    BufferTooSmall {
        requested_size: usize,
        required_size: usize,
    },
}

/// Errors returned while reading POSIX `getxattr` values with buffer semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrValueReadError {
    /// The requested name is not valid for POSIX xattr operations.
    InvalidName(XattrNameValidationError),
    /// No entry exists with the requested xattr name.
    EntryNotFound,
    /// The caller supplied a non-zero buffer that cannot fit the value.
    /// POSIX callers should map this condition to `ERANGE`.
    BufferTooSmall {
        requested_size: usize,
        required_size: usize,
    },
}

impl From<XattrValueBufferError> for XattrValueReadError {
    fn from(err: XattrValueBufferError) -> Self {
        match err {
            XattrValueBufferError::BufferTooSmall {
                requested_size,
                required_size,
            } => XattrValueReadError::BufferTooSmall {
                requested_size,
                required_size,
            },
        }
    }
}

/// POSIX `getxattr` read result for a requested buffer size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrValueRead {
    pub plan: XattrValueBufferPlan,
    pub value: Vec<u8>,
}

/// Maximum POSIX/Linux xattr name length, including the namespace prefix.
pub const POSIX_XATTR_NAME_MAX: usize = 255;

/// Maximum POSIX/Linux xattr value length in bytes.
pub const POSIX_XATTR_VALUE_MAX: usize = 65_536;

/// Recognised POSIX/Linux xattr namespace prefixes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixXattrNamespace {
    /// `security.*` attributes.
    Security,
    /// `system.*` attributes.
    System,
    /// `trusted.*` attributes.
    Trusted,
    /// `user.*` attributes.
    User,
}

/// Errors returned while validating a POSIX xattr name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNameValidationError {
    /// The name is empty.
    EmptyName,
    /// The name contains an interior NUL byte.
    NameContainsNul,
    /// The name exceeds [`POSIX_XATTR_NAME_MAX`].
    NameTooLong { len: usize, max: usize },
}

/// Errors returned while validating a POSIX xattr value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrValueValidationError {
    /// The value exceeds [`POSIX_XATTR_VALUE_MAX`].
    ValueTooLong { len: usize, max: usize },
}

/// Pure POSIX xattr name validation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrNameValidation {
    pub len: usize,
    pub namespace: Option<PosixXattrNamespace>,
}

/// Pure POSIX xattr value validation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrValueValidation {
    pub len: usize,
}

/// Linux/POSIX `XATTR_CREATE`: fail if the xattr already exists.
pub const POSIX_XATTR_CREATE: u32 = 0x01;

/// Linux/POSIX `XATTR_REPLACE`: fail if the xattr does not exist.
pub const POSIX_XATTR_REPLACE: u32 = 0x02;

/// Errors returned while planning POSIX `setxattr` flag handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrSetPlanError {
    /// The xattr name is not valid for POSIX xattr operations.
    InvalidName(XattrNameValidationError),
    /// The xattr value is not valid for POSIX xattr operations.
    InvalidValue(XattrValueValidationError),
    /// Flags include unsupported bits or request both create and replace.
    InvalidFlags { flags: u32 },
    /// `XATTR_CREATE` was requested but the xattr already exists.
    EntryExists,
    /// `XATTR_REPLACE` was requested but the xattr is absent.
    EntryNotFound,
}

/// Normalized xattr set mode derived from POSIX `setxattr` flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrSetMode {
    /// No existence precondition; create or replace.
    Upsert,
    /// `XATTR_CREATE`: fail if the xattr already exists.
    CreateOnly,
    /// `XATTR_REPLACE`: fail if the xattr does not exist.
    ReplaceOnly,
}

/// Pure POSIX `setxattr` flag plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrSetPlan {
    pub flags: u32,
    pub exists: bool,
    pub mode: XattrSetMode,
}

impl XattrSetPlan {
    /// Return true when this plan requires the xattr to be absent.
    #[must_use]
    pub const fn requires_absent(self) -> bool {
        matches!(self.mode, XattrSetMode::CreateOnly)
    }

    /// Return true when this plan requires the xattr to exist.
    #[must_use]
    pub const fn requires_existing(self) -> bool {
        matches!(self.mode, XattrSetMode::ReplaceOnly)
    }
}

/// Parse a recognised POSIX/Linux xattr namespace prefix.
///
/// Prefix-only names such as `user.` are left unclassified so callers can
/// decide whether namespace membership is a storage concern or a policy check.
#[must_use]
pub fn parse_posix_xattr_namespace(name: &[u8]) -> Option<PosixXattrNamespace> {
    if name.starts_with(b"user.") && name.len() > b"user.".len() {
        Some(PosixXattrNamespace::User)
    } else if name.starts_with(b"system.") && name.len() > b"system.".len() {
        Some(PosixXattrNamespace::System)
    } else if name.starts_with(b"security.") && name.len() > b"security.".len() {
        Some(PosixXattrNamespace::Security)
    } else if name.starts_with(b"trusted.") && name.len() > b"trusted.".len() {
        Some(PosixXattrNamespace::Trusted)
    } else {
        None
    }
}

/// Validate a POSIX/Linux xattr name without mutating storage.
pub fn validate_posix_xattr_name(
    name: &[u8],
) -> Result<XattrNameValidation, XattrNameValidationError> {
    if name.is_empty() {
        return Err(XattrNameValidationError::EmptyName);
    }
    if name.contains(&0) {
        return Err(XattrNameValidationError::NameContainsNul);
    }
    if name.len() > POSIX_XATTR_NAME_MAX {
        return Err(XattrNameValidationError::NameTooLong {
            len: name.len(),
            max: POSIX_XATTR_NAME_MAX,
        });
    }

    Ok(XattrNameValidation {
        len: name.len(),
        namespace: parse_posix_xattr_namespace(name),
    })
}

/// Validate a POSIX/Linux xattr value without mutating storage.
pub fn validate_posix_xattr_value(
    value: &[u8],
) -> Result<XattrValueValidation, XattrValueValidationError> {
    if value.len() > POSIX_XATTR_VALUE_MAX {
        return Err(XattrValueValidationError::ValueTooLong {
            len: value.len(),
            max: POSIX_XATTR_VALUE_MAX,
        });
    }

    Ok(XattrValueValidation { len: value.len() })
}

/// Plan POSIX `setxattr` create/replace flag handling without mutating storage.
pub fn plan_posix_xattr_set(flags: u32, exists: bool) -> Result<XattrSetPlan, XattrSetPlanError> {
    let mode = match flags {
        0 => XattrSetMode::Upsert,
        POSIX_XATTR_CREATE => XattrSetMode::CreateOnly,
        POSIX_XATTR_REPLACE => XattrSetMode::ReplaceOnly,
        _ => return Err(XattrSetPlanError::InvalidFlags { flags }),
    };

    match mode {
        XattrSetMode::CreateOnly if exists => Err(XattrSetPlanError::EntryExists),
        XattrSetMode::ReplaceOnly if !exists => Err(XattrSetPlanError::EntryNotFound),
        _ => Ok(XattrSetPlan {
            flags,
            exists,
            mode,
        }),
    }
}

/// Pack xattr names as a deterministic NUL-delimited POSIX `listxattr` buffer.
pub fn pack_posix_xattr_name_list(names: &[Vec<u8>]) -> Result<Vec<u8>, XattrNameListError> {
    let mut sorted_names = names.to_vec();
    sorted_names.sort_unstable();

    let mut total_len = 0usize;
    for (index, name) in sorted_names.iter().enumerate() {
        if index > 0 && sorted_names[index - 1].as_slice() == name.as_slice() {
            return Err(XattrNameListError::DuplicateName);
        }

        validate_posix_xattr_name(name).map_err(|err| match err {
            XattrNameValidationError::EmptyName => XattrNameListError::EmptyName,
            XattrNameValidationError::NameContainsNul => XattrNameListError::NameContainsNul,
            XattrNameValidationError::NameTooLong { len, max } => {
                XattrNameListError::NameTooLong { len, max }
            }
        })?;
        total_len = total_len
            .checked_add(name.len())
            .and_then(|len| len.checked_add(1))
            .ok_or(XattrNameListError::NameListTooLarge)?;
    }

    let mut packed = Vec::with_capacity(total_len);
    for name in sorted_names {
        packed.extend_from_slice(&name);
        packed.push(0);
    }
    Ok(packed)
}

/// Plan POSIX `listxattr` buffer handling from a packed name-list size.
pub fn plan_posix_xattr_name_list_buffer(
    required_size: usize,
    requested_size: usize,
) -> Result<XattrNameListBufferPlan, XattrNameListBufferError> {
    if requested_size == 0 {
        return Ok(XattrNameListBufferPlan {
            requested_size,
            required_size,
            action: XattrNameListBufferAction::ReportRequiredSize,
        });
    }

    if requested_size < required_size {
        return Err(XattrNameListBufferError::BufferTooSmall {
            requested_size,
            required_size,
        });
    }

    Ok(XattrNameListBufferPlan {
        requested_size,
        required_size,
        action: XattrNameListBufferAction::CopyNames,
    })
}

/// Plan POSIX `getxattr` value buffer handling from a stored value size.
pub fn plan_posix_xattr_value_buffer(
    required_size: usize,
    requested_size: usize,
) -> Result<XattrValueBufferPlan, XattrValueBufferError> {
    if requested_size == 0 {
        return Ok(XattrValueBufferPlan {
            requested_size,
            required_size,
            action: XattrValueBufferAction::ReportRequiredSize,
        });
    }

    if requested_size < required_size {
        return Err(XattrValueBufferError::BufferTooSmall {
            requested_size,
            required_size,
        });
    }

    Ok(XattrValueBufferPlan {
        requested_size,
        required_size,
        action: XattrValueBufferAction::CopyValue,
    })
}

// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Deterministic 64-bit hash of an xattr name (FNV-1a).
///
/// This is an in-memory hash for B+tree keying. Collision-resilience
/// is provided by full-name verification in get/remove and per-bucket
/// entry vectors in the B+tree.
fn name_hash(name: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET;
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// XattrStore
// ---------------------------------------------------------------------------

/// Runtime polymorphic xattr store for a single inode.
#[derive(Clone, Debug)]
pub struct XattrStore {
    storage: XattrStorage,
    policy: DatasetXattrPolicy,
    btree: Option<BPlusTree<u64, Vec<XattrBtreeLeafEntry>, 128, 128>>,
    version: u64,
}

impl XattrStore {
    /// Create a new, empty xattr store.
    #[must_use]
    pub const fn new(policy: DatasetXattrPolicy) -> Self {
        XattrStore {
            storage: XattrStorage::Inline(XattrBundleV1::new(0)),
            policy,
            btree: None,
            version: 0,
        }
    }

    /// Create a new empty store with the ACL flag set.
    #[must_use]
    pub const fn new_with_acl(policy: DatasetXattrPolicy) -> Self {
        XattrStore {
            storage: XattrStorage::Inline(XattrBundleV1::new(0x01)),
            policy,
            btree: None,
            version: 0,
        }
    }

    // ------------------------------------------------------------------
    // Inspection
    // ------------------------------------------------------------------

    /// Returns the current storage representation kind.
    #[must_use]
    pub fn representation(&self) -> XattrStorageKind {
        self.storage.kind()
    }

    /// Returns the configured dataset policy.
    #[must_use]
    pub fn policy(&self) -> DatasetXattrPolicy {
        self.policy
    }

    /// Returns the total entry count regardless of representation.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.storage.entry_count()
    }

    /// Returns `true` if the store has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Monotonic version counter, bumped on every mutation.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` if the ACL flag is set.
    #[must_use]
    pub fn has_acl(&self) -> bool {
        self.storage.contains_acl()
    }

    /// Set or clear the ACL flag.
    pub fn set_has_acl(&mut self, acl: bool) {
        match &mut self.storage {
            XattrStorage::Inline(bundle) => {
                if acl {
                    bundle.flags |= 0x01;
                } else {
                    bundle.flags &= !0x01;
                }
            }
            XattrStorage::External(root) => {
                if acl {
                    root.flags |= 0x01;
                } else {
                    root.flags &= !0x01;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Get / Contains
    // ------------------------------------------------------------------

    /// Look up an xattr by name. Returns the value bytes if found.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<Vec<u8>> {
        match &self.storage {
            XattrStorage::Inline(bundle) => {
                for entry in &bundle.entries {
                    if entry.name == name {
                        return Some(entry.value.clone());
                    }
                }
                None
            }
            XattrStorage::External(_) => {
                let tree = self
                    .btree
                    .as_ref()
                    .expect("btree must exist for External storage");
                let hash = name_hash(name);
                if let Some(bucket) = tree.get(&hash) {
                    for entry in bucket {
                        if entry.name == name {
                            return Some(entry.value.clone());
                        }
                    }
                }
                None
            }
        }
    }

    /// Return a POSIX `getxattr` value using caller buffer-size semantics.
    pub fn get_posix_xattr_value_for_size(
        &self,
        name: &[u8],
        requested_size: usize,
    ) -> Result<XattrValueRead, XattrValueReadError> {
        validate_posix_xattr_name(name).map_err(XattrValueReadError::InvalidName)?;
        let value = self.get(name).ok_or(XattrValueReadError::EntryNotFound)?;
        let plan = plan_posix_xattr_value_buffer(value.len(), requested_size)?;
        let value = if plan.copies_value() {
            value
        } else {
            Vec::new()
        };

        Ok(XattrValueRead { plan, value })
    }

    /// Returns `true` if an entry with the given name exists.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.get(name).is_some()
    }

    // ------------------------------------------------------------------
    // Set (upsert)
    // ------------------------------------------------------------------

    /// Set an xattr entry. If an entry with this name already exists,
    /// its value is replaced. Returns the previous value if replaced.
    pub fn set(&mut self, name: &[u8], value: &[u8], flags: u8) -> Option<Vec<u8>> {
        let prev = self.get(name);
        if prev.is_some() {
            self.remove_inner(name);
        }
        self.insert_inner(name, value, flags);
        self.version += 1;
        self.check_and_switch();
        prev
    }

    /// Set an xattr entry using POSIX create/replace flags.
    ///
    /// Returns the previous value if an entry was replaced. Invalid flags or
    /// unmet existence preconditions are returned before any mutation.
    pub fn set_with_posix_flags(
        &mut self,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<Option<Vec<u8>>, XattrSetPlanError> {
        validate_posix_xattr_name(name).map_err(XattrSetPlanError::InvalidName)?;
        validate_posix_xattr_value(value).map_err(XattrSetPlanError::InvalidValue)?;
        plan_posix_xattr_set(flags, self.contains(name))?;
        Ok(self.set(name, value, 0))
    }

    fn insert_inner(&mut self, name: &[u8], value: &[u8], flags: u8) {
        let value_len = value.len() as u64;
        match &mut self.storage {
            XattrStorage::Inline(bundle) => {
                bundle.entry_count += 1;
                bundle.total_value_bytes += value_len as u32;
                bundle
                    .entries
                    .push(tidefs_types_polymorphic_xattr_core::XattrInlineEntry {
                        name_len: name.len() as u16,
                        value_len: value.len() as u32,
                        name: name.to_vec(),
                        value: value.to_vec(),
                    });
            }
            XattrStorage::External(root) => {
                let tree = self
                    .btree
                    .as_mut()
                    .expect("btree must exist for External storage");
                let hash = name_hash(name);
                let leaf_entry = XattrBtreeLeafEntry {
                    name_len: name.len() as u16,
                    value_len: value.len() as u32,
                    flags,
                    reserved: 0,
                    name: name.to_vec(),
                    value: value.to_vec(),
                };

                let exists = tree.contains_key(&hash);
                if exists {
                    tree.update(&hash, |bucket| {
                        bucket.push(leaf_entry);
                    });
                } else {
                    tree.insert(hash, alloc::vec![leaf_entry]);
                }
                root.entry_count += 1;
                root.total_value_bytes += value_len;
            }
        }
    }

    // ------------------------------------------------------------------
    // Remove
    // ------------------------------------------------------------------

    /// Remove an xattr entry by name.
    ///
    /// Returns `Ok(())` if removed, `Err(XattrStoreError::EntryNotFound)` if
    /// no entry with this name exists.
    pub fn remove(&mut self, name: &[u8]) -> Result<(), XattrStoreError> {
        if !self.contains(name) {
            return Err(XattrStoreError::EntryNotFound);
        }
        self.remove_inner(name);
        self.version += 1;
        self.check_and_switch();
        Ok(())
    }

    fn remove_inner(&mut self, name: &[u8]) {
        match &mut self.storage {
            XattrStorage::Inline(bundle) => {
                if let Some(pos) = bundle.entries.iter().position(|e| e.name == name) {
                    bundle.total_value_bytes -= bundle.entries[pos].value_len;
                    bundle.entries.remove(pos);
                    bundle.entry_count -= 1;
                }
            }
            XattrStorage::External(root) => {
                let tree = self
                    .btree
                    .as_mut()
                    .expect("btree must exist for External storage");
                let hash = name_hash(name);
                if let Some(bucket) = tree.get(&hash) {
                    let mut value_len: u64 = 0;
                    let mut bucket_clone: Vec<XattrBtreeLeafEntry> = Vec::new();
                    for entry in bucket {
                        if entry.name != name {
                            bucket_clone.push(entry.clone());
                        } else {
                            value_len = entry.value_len as u64;
                        }
                    }
                    if bucket_clone.is_empty() {
                        tree.delete(&hash);
                    } else {
                        tree.insert(hash, bucket_clone);
                    }
                    root.entry_count -= 1;
                    root.total_value_bytes -= value_len;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // List
    // ------------------------------------------------------------------

    /// Return all (name, value) pairs in the store.
    #[must_use]
    pub fn list(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        match &self.storage {
            XattrStorage::Inline(bundle) => bundle
                .entries
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect(),
            XattrStorage::External(_) => {
                let tree = self
                    .btree
                    .as_ref()
                    .expect("btree must exist for External storage");
                let mut out = Vec::new();
                for (_hash, bucket) in tree.entries() {
                    for entry in &bucket {
                        out.push((entry.name.clone(), entry.value.clone()));
                    }
                }
                out
            }
        }
    }

    /// Return only the xattr names (keys) in the store.
    #[must_use]
    pub fn list_names(&self) -> Vec<Vec<u8>> {
        match &self.storage {
            XattrStorage::Inline(bundle) => bundle.entries.iter().map(|e| e.name.clone()).collect(),
            XattrStorage::External(_) => {
                let tree = self
                    .btree
                    .as_ref()
                    .expect("btree must exist for External storage");
                let mut out = Vec::new();
                for (_hash, bucket) in tree.entries() {
                    for entry in &bucket {
                        out.push(entry.name.clone());
                    }
                }
                out
            }
        }
    }

    /// Return xattr names as deterministic POSIX `listxattr` buffer bytes.
    pub fn list_posix_name_bytes(&self) -> Result<Vec<u8>, XattrNameListError> {
        let names = self.list_names();
        pack_posix_xattr_name_list(&names)
    }

    /// Return POSIX `listxattr` bytes using caller buffer-size semantics.
    pub fn list_posix_name_bytes_for_size(
        &self,
        requested_size: usize,
    ) -> Result<XattrNameListRead, XattrNameListReadError> {
        let bytes = self
            .list_posix_name_bytes()
            .map_err(XattrNameListReadError::InvalidNameList)?;
        let plan = plan_posix_xattr_name_list_buffer(bytes.len(), requested_size)?;
        let bytes = if plan.copies_names() {
            bytes
        } else {
            Vec::new()
        };

        Ok(XattrNameListRead { plan, bytes })
    }

    // ------------------------------------------------------------------
    // Total value bytes
    // ------------------------------------------------------------------

    /// Returns the total sum of all value lengths.
    #[must_use]
    pub fn total_value_bytes(&self) -> u64 {
        self.storage.total_value_bytes()
    }

    // ------------------------------------------------------------------
    // Hysteresis switching
    // ------------------------------------------------------------------

    /// Evaluate switching thresholds and migrate representation if needed.
    pub fn check_and_switch(&mut self) {
        let cnt = self.storage.entry_count();
        let nbytes = self.storage.total_value_bytes();
        match &self.storage {
            XattrStorage::Inline(_) => {
                if should_use_tree(cnt, nbytes, &self.policy) {
                    self.promote_to_btree();
                }
            }
            XattrStorage::External(_) => {
                if should_use_inline_from_tree(cnt, nbytes, &self.policy) {
                    self.demote_to_inline();
                }
            }
        }
    }

    /// Migrate all entries from inline bundle to B+tree.
    fn promote_to_btree(&mut self) {
        let bundle = match &self.storage {
            XattrStorage::Inline(ref b) => b,
            _ => return,
        };
        let mut tree: BPlusTree<u64, Vec<XattrBtreeLeafEntry>, 128, 128> = BPlusTree::new();
        let cnt = bundle.entry_count as u64;
        let nbytes = bundle.total_value_bytes as u64;
        let acl = bundle.contains_acl();

        for entry in &bundle.entries {
            let h = name_hash(&entry.name);
            let leaf = XattrBtreeLeafEntry {
                name_len: entry.name_len,
                value_len: entry.value_len,
                flags: 0,
                reserved: 0,
                name: entry.name.clone(),
                value: entry.value.clone(),
            };
            if tree.contains_key(&h) {
                tree.update(&h, |bucket| bucket.push(leaf));
            } else {
                tree.insert(h, alloc::vec![leaf]);
            }
        }

        let mut root = XattrBtreeRootV1::new(cnt, nbytes, LocatorId::EMPTY);
        if acl {
            root.flags |= 0x01;
        }

        self.btree = Some(tree);
        self.storage = XattrStorage::External(root);
    }

    /// Migrate all entries from B+tree back to inline bundle.
    fn demote_to_inline(&mut self) {
        let root = match &self.storage {
            XattrStorage::External(ref r) => r,
            _ => return,
        };
        let tree = self
            .btree
            .as_ref()
            .expect("btree must exist for External storage");

        let mut bundle = XattrBundleV1::new(if root.contains_acl() { 0x01 } else { 0 });
        for (_hash, bucket) in tree.entries() {
            for entry in bucket {
                bundle.add_entry(entry.name.clone(), entry.value.clone());
            }
        }

        self.btree = None;
        self.storage = XattrStorage::Inline(bundle);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> DatasetXattrPolicy {
        DatasetXattrPolicy::DEFAULT
    }

    // -- Construction --

    #[test]
    fn new_is_inline_and_empty() {
        let s = XattrStore::new(default_policy());
        assert_eq!(s.representation(), XattrStorageKind::INLINE);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.version(), 0);
        assert!(!s.has_acl());
        assert_eq!(s.total_value_bytes(), 0);
    }

    #[test]
    fn new_with_acl() {
        let s = XattrStore::new_with_acl(default_policy());
        assert!(s.has_acl());
    }

    // -- Get / Set / Contains --

    #[test]
    fn get_missing_returns_none() {
        let s = XattrStore::new(default_policy());
        assert!(s.get(b"nonexistent").is_none());
    }

    #[test]
    fn set_and_get_roundtrip() {
        let mut s = XattrStore::new(default_policy());
        assert!(s.set(b"user.key", b"hello", 0).is_none());
        assert_eq!(s.len(), 1);
        assert!(s.contains(b"user.key"));
        assert_eq!(s.get(b"user.key"), Some(b"hello".to_vec()));
        assert_eq!(s.version(), 1);
    }

    #[test]
    fn set_upsert_replaces_value() {
        let mut s = XattrStore::new(default_policy());
        let prev = s.set(b"key", b"v1", 0);
        assert!(prev.is_none());
        assert_eq!(s.get(b"key"), Some(b"v1".to_vec()));

        let prev = s.set(b"key", b"v2", 0);
        assert_eq!(prev, Some(b"v1".to_vec()));
        assert_eq!(s.get(b"key"), Some(b"v2".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), 2);
    }

    #[test]
    fn set_multiple_entries() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"a", b"1", 0);
        s.set(b"b", b"22", 0);
        s.set(b"c", b"333", 0);
        assert_eq!(s.len(), 3);
        assert_eq!(s.get(b"a"), Some(b"1".to_vec()));
        assert_eq!(s.get(b"b"), Some(b"22".to_vec()));
        assert_eq!(s.get(b"c"), Some(b"333".to_vec()));
        assert_eq!(s.total_value_bytes(), 6); // 1 + 2 + 3
    }

    #[test]
    fn set_updates_total_value_bytes_correctly_on_upsert() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"k", b"bigvalue", 0);
        assert_eq!(s.total_value_bytes(), 8);
        s.set(b"k", b"sm", 0);
        assert_eq!(s.total_value_bytes(), 2);
    }

    #[test]
    fn parse_posix_xattr_namespace_is_deterministic() {
        assert_eq!(
            parse_posix_xattr_namespace(b"user.comment"),
            Some(PosixXattrNamespace::User)
        );
        assert_eq!(
            parse_posix_xattr_namespace(b"system.posix_acl_access"),
            Some(PosixXattrNamespace::System)
        );
        assert_eq!(
            parse_posix_xattr_namespace(b"security.selinux"),
            Some(PosixXattrNamespace::Security)
        );
        assert_eq!(
            parse_posix_xattr_namespace(b"trusted.overlay"),
            Some(PosixXattrNamespace::Trusted)
        );
        assert_eq!(parse_posix_xattr_namespace(b"user."), None);
        assert_eq!(parse_posix_xattr_namespace(b"custom.name"), None);
    }

    #[test]
    fn validate_posix_xattr_name_accepts_bounded_non_utf8_names() {
        let name = alloc::vec![b'u', b's', b'e', b'r', b'.', 0xFF];

        assert_eq!(
            validate_posix_xattr_name(&name),
            Ok(XattrNameValidation {
                len: name.len(),
                namespace: Some(PosixXattrNamespace::User),
            })
        );
    }

    #[test]
    fn validate_posix_xattr_name_rejects_empty_nul_and_too_long_names() {
        assert_eq!(
            validate_posix_xattr_name(b""),
            Err(XattrNameValidationError::EmptyName)
        );
        assert_eq!(
            validate_posix_xattr_name(b"user.bad\0name"),
            Err(XattrNameValidationError::NameContainsNul)
        );

        let too_long = alloc::vec![b'a'; POSIX_XATTR_NAME_MAX + 1];
        assert_eq!(
            validate_posix_xattr_name(&too_long),
            Err(XattrNameValidationError::NameTooLong {
                len: POSIX_XATTR_NAME_MAX + 1,
                max: POSIX_XATTR_NAME_MAX,
            })
        );
    }

    #[test]
    fn validate_posix_xattr_value_accepts_empty_and_max_sized_values() {
        assert_eq!(
            validate_posix_xattr_value(b""),
            Ok(XattrValueValidation { len: 0 })
        );

        let max_value = alloc::vec![0xA5; POSIX_XATTR_VALUE_MAX];
        assert_eq!(
            validate_posix_xattr_value(&max_value),
            Ok(XattrValueValidation {
                len: POSIX_XATTR_VALUE_MAX,
            })
        );
    }

    #[test]
    fn validate_posix_xattr_value_rejects_oversized_values() {
        let oversized = alloc::vec![0xA5; POSIX_XATTR_VALUE_MAX + 1];

        assert_eq!(
            validate_posix_xattr_value(&oversized),
            Err(XattrValueValidationError::ValueTooLong {
                len: POSIX_XATTR_VALUE_MAX + 1,
                max: POSIX_XATTR_VALUE_MAX,
            })
        );
    }

    #[test]
    fn plan_posix_xattr_set_normalizes_valid_modes() {
        assert_eq!(
            plan_posix_xattr_set(0, false),
            Ok(XattrSetPlan {
                flags: 0,
                exists: false,
                mode: XattrSetMode::Upsert,
            })
        );
        assert_eq!(
            plan_posix_xattr_set(POSIX_XATTR_CREATE, false),
            Ok(XattrSetPlan {
                flags: POSIX_XATTR_CREATE,
                exists: false,
                mode: XattrSetMode::CreateOnly,
            })
        );
        assert_eq!(
            plan_posix_xattr_set(POSIX_XATTR_REPLACE, true),
            Ok(XattrSetPlan {
                flags: POSIX_XATTR_REPLACE,
                exists: true,
                mode: XattrSetMode::ReplaceOnly,
            })
        );
    }

    #[test]
    fn plan_posix_xattr_set_rejects_invalid_or_unmet_preconditions() {
        assert_eq!(
            plan_posix_xattr_set(POSIX_XATTR_CREATE | POSIX_XATTR_REPLACE, false),
            Err(XattrSetPlanError::InvalidFlags {
                flags: POSIX_XATTR_CREATE | POSIX_XATTR_REPLACE,
            })
        );
        assert_eq!(
            plan_posix_xattr_set(0x04, false),
            Err(XattrSetPlanError::InvalidFlags { flags: 0x04 })
        );
        assert_eq!(
            plan_posix_xattr_set(POSIX_XATTR_CREATE, true),
            Err(XattrSetPlanError::EntryExists)
        );
        assert_eq!(
            plan_posix_xattr_set(POSIX_XATTR_REPLACE, false),
            Err(XattrSetPlanError::EntryNotFound)
        );
    }

    #[test]
    fn set_with_posix_flags_create_only_succeeds_when_missing() {
        let mut s = XattrStore::new(default_policy());

        assert_eq!(
            s.set_with_posix_flags(b"user.new", b"value", POSIX_XATTR_CREATE),
            Ok(None)
        );

        assert_eq!(s.get(b"user.new"), Some(b"value".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), 1);
    }

    #[test]
    fn set_with_posix_flags_create_only_rejects_existing_without_mutation() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.existing", b"old", 0);
        let version = s.version();
        let total_value_bytes = s.total_value_bytes();

        assert_eq!(
            s.set_with_posix_flags(b"user.existing", b"new", POSIX_XATTR_CREATE),
            Err(XattrSetPlanError::EntryExists)
        );

        assert_eq!(s.get(b"user.existing"), Some(b"old".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), version);
        assert_eq!(s.total_value_bytes(), total_value_bytes);
    }

    #[test]
    fn set_with_posix_flags_replace_only_succeeds_when_existing() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.replace", b"old", 0);

        assert_eq!(
            s.set_with_posix_flags(b"user.replace", b"new", POSIX_XATTR_REPLACE),
            Ok(Some(b"old".to_vec()))
        );

        assert_eq!(s.get(b"user.replace"), Some(b"new".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), 2);
    }

    #[test]
    fn set_with_posix_flags_replace_only_rejects_missing_without_mutation() {
        let mut s = XattrStore::new(default_policy());

        assert_eq!(
            s.set_with_posix_flags(b"user.missing", b"value", POSIX_XATTR_REPLACE),
            Err(XattrSetPlanError::EntryNotFound)
        );

        assert_eq!(s.get(b"user.missing"), None);
        assert_eq!(s.len(), 0);
        assert_eq!(s.version(), 0);
        assert_eq!(s.total_value_bytes(), 0);
    }

    #[test]
    fn set_with_posix_flags_upsert_creates_and_replaces() {
        let mut s = XattrStore::new(default_policy());

        assert_eq!(s.set_with_posix_flags(b"user.key", b"v1", 0), Ok(None));
        assert_eq!(
            s.set_with_posix_flags(b"user.key", b"v2", 0),
            Ok(Some(b"v1".to_vec()))
        );

        assert_eq!(s.get(b"user.key"), Some(b"v2".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), 2);
        assert_eq!(s.total_value_bytes(), 2);
    }

    #[test]
    fn set_with_posix_flags_rejects_invalid_names_without_mutation() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.good", b"original", 0);
        let version = s.version();
        let total_value_bytes = s.total_value_bytes();

        assert_eq!(
            s.set_with_posix_flags(b"", b"value", 0),
            Err(XattrSetPlanError::InvalidName(
                XattrNameValidationError::EmptyName
            ))
        );
        assert_eq!(
            s.set_with_posix_flags(b"user.bad\0name", b"value", 0),
            Err(XattrSetPlanError::InvalidName(
                XattrNameValidationError::NameContainsNul
            ))
        );

        let too_long = alloc::vec![b'a'; POSIX_XATTR_NAME_MAX + 1];
        assert_eq!(
            s.set_with_posix_flags(&too_long, b"value", 0),
            Err(XattrSetPlanError::InvalidName(
                XattrNameValidationError::NameTooLong {
                    len: POSIX_XATTR_NAME_MAX + 1,
                    max: POSIX_XATTR_NAME_MAX,
                }
            ))
        );

        assert_eq!(s.get(b"user.good"), Some(b"original".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), version);
        assert_eq!(s.total_value_bytes(), total_value_bytes);
    }

    #[test]
    fn set_with_posix_flags_accepts_max_sized_values() {
        let mut s = XattrStore::new(default_policy());
        let max_value = alloc::vec![0x5A; POSIX_XATTR_VALUE_MAX];

        assert_eq!(s.set_with_posix_flags(b"user.max", &max_value, 0), Ok(None));

        assert_eq!(s.get(b"user.max"), Some(max_value));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), 1);
        assert_eq!(s.total_value_bytes(), POSIX_XATTR_VALUE_MAX as u64);
    }

    #[test]
    fn set_with_posix_flags_rejects_oversized_values_without_mutation() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.good", b"original", 0);
        let version = s.version();
        let total_value_bytes = s.total_value_bytes();
        let oversized = alloc::vec![0xA5; POSIX_XATTR_VALUE_MAX + 1];

        assert_eq!(
            s.set_with_posix_flags(b"user.good", &oversized, 0),
            Err(XattrSetPlanError::InvalidValue(
                XattrValueValidationError::ValueTooLong {
                    len: POSIX_XATTR_VALUE_MAX + 1,
                    max: POSIX_XATTR_VALUE_MAX,
                }
            ))
        );

        assert_eq!(s.get(b"user.good"), Some(b"original".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.version(), version);
        assert_eq!(s.total_value_bytes(), total_value_bytes);
    }

    #[test]
    fn set_with_posix_flags_rejects_oversized_values_before_create() {
        let mut s = XattrStore::new(default_policy());
        let oversized = alloc::vec![0xA5; POSIX_XATTR_VALUE_MAX + 1];

        assert_eq!(
            s.set_with_posix_flags(b"user.new", &oversized, POSIX_XATTR_CREATE),
            Err(XattrSetPlanError::InvalidValue(
                XattrValueValidationError::ValueTooLong {
                    len: POSIX_XATTR_VALUE_MAX + 1,
                    max: POSIX_XATTR_VALUE_MAX,
                }
            ))
        );

        assert_eq!(s.get(b"user.new"), None);
        assert_eq!(s.len(), 0);
        assert_eq!(s.version(), 0);
        assert_eq!(s.total_value_bytes(), 0);
    }

    #[test]
    fn set_with_posix_flags_replace_works_in_external_storage() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        s.set(b"user.replace", b"old", 0);
        s.set(b"user.a", b"a", 0);
        s.set(b"user.b", b"bb", 0);
        s.set(b"user.c", b"ccc", 0);
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);

        assert_eq!(
            s.set_with_posix_flags(b"user.replace", b"new-value", POSIX_XATTR_REPLACE),
            Ok(Some(b"old".to_vec()))
        );

        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.len(), 4);
        assert_eq!(s.get(b"user.replace"), Some(b"new-value".to_vec()));
        assert_eq!(
            s.list_names()
                .iter()
                .filter(|name| name.as_slice() == b"user.replace")
                .count(),
            1
        );
    }

    // -- Remove --

    #[test]
    fn remove_existing_entry() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"k", b"v", 0);
        assert_eq!(s.len(), 1);
        assert!(s.remove(b"k").is_ok());
        assert!(s.is_empty());
        assert!(s.get(b"k").is_none());
        assert_eq!(s.version(), 2);
        assert_eq!(s.total_value_bytes(), 0);
    }

    #[test]
    fn remove_not_found_is_error() {
        let mut s = XattrStore::new(default_policy());
        assert_eq!(s.remove(b"nope"), Err(XattrStoreError::EntryNotFound));
    }

    #[test]
    fn remove_updates_total_value_bytes() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"a", b"123", 0);
        s.set(b"b", b"45", 0);
        assert_eq!(s.total_value_bytes(), 5);
        s.remove(b"a").unwrap();
        assert_eq!(s.total_value_bytes(), 2);
    }

    // -- List --

    #[test]
    fn list_returns_all_entries() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"z", b"last", 0);
        s.set(b"a", b"first", 0);
        let entries = s.list();
        assert_eq!(entries.len(), 2);
        // Order is insertion order for inline
        assert_eq!(entries[0], (b"z".to_vec(), b"last".to_vec()));
        assert_eq!(entries[1], (b"a".to_vec(), b"first".to_vec()));
    }

    #[test]
    fn list_names_returns_names_only() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.x", b"vx", 0);
        s.set(b"user.y", b"vy", 0);
        let names = s.list_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.x".to_vec()));
        assert!(names.contains(&b"user.y".to_vec()));
    }

    #[test]
    fn pack_posix_xattr_name_list_sorts_and_terminates_names() {
        let names = alloc::vec![
            b"user.z".to_vec(),
            b"security.selinux".to_vec(),
            b"user.a".to_vec(),
        ];

        assert_eq!(
            pack_posix_xattr_name_list(&names),
            Ok(b"security.selinux\0user.a\0user.z\0".to_vec())
        );
    }

    #[test]
    fn pack_posix_xattr_name_list_allows_empty_list() {
        assert_eq!(pack_posix_xattr_name_list(&[]), Ok(Vec::new()));
    }

    #[test]
    fn pack_posix_xattr_name_list_rejects_duplicate_names() {
        let names = alloc::vec![b"user.a".to_vec(), b"user.a".to_vec()];

        assert_eq!(
            pack_posix_xattr_name_list(&names),
            Err(XattrNameListError::DuplicateName)
        );
    }

    #[test]
    fn pack_posix_xattr_name_list_rejects_embedded_nul_names() {
        let names = alloc::vec![b"user.\0bad".to_vec()];

        assert_eq!(
            pack_posix_xattr_name_list(&names),
            Err(XattrNameListError::NameContainsNul)
        );
    }

    #[test]
    fn pack_posix_xattr_name_list_rejects_empty_and_too_long_names() {
        assert_eq!(
            pack_posix_xattr_name_list(&[Vec::new()]),
            Err(XattrNameListError::EmptyName)
        );

        let too_long = alloc::vec![b'a'; POSIX_XATTR_NAME_MAX + 1];
        assert_eq!(
            pack_posix_xattr_name_list(&[too_long]),
            Err(XattrNameListError::NameTooLong {
                len: POSIX_XATTR_NAME_MAX + 1,
                max: POSIX_XATTR_NAME_MAX,
            })
        );
    }

    #[test]
    fn list_posix_name_bytes_is_deterministic_for_inline_storage() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.z", b"vz", 0);
        s.set(b"user.a", b"va", 0);

        assert_eq!(s.list_posix_name_bytes(), Ok(b"user.a\0user.z\0".to_vec()));
    }

    #[test]
    fn list_posix_name_bytes_is_deterministic_for_btree_storage() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        s.set(b"user.z", b"vz", 0);
        s.set(b"user.a", b"va", 0);
        s.set(b"user.m", b"vm", 0);
        s.set(b"user.q", b"vq", 0);
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);

        assert_eq!(
            s.list_posix_name_bytes(),
            Ok(b"user.a\0user.m\0user.q\0user.z\0".to_vec())
        );
    }

    #[test]
    fn list_posix_name_bytes_rejects_unrepresentable_nul_name() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.\0bad", b"value", 0);

        assert_eq!(
            s.list_posix_name_bytes(),
            Err(XattrNameListError::NameContainsNul)
        );
    }

    #[test]
    fn list_posix_name_bytes_rejects_empty_and_oversized_raw_names() {
        let mut empty_name_store = XattrStore::new(default_policy());
        empty_name_store.set(b"", b"value", 0);
        assert_eq!(
            empty_name_store.list_posix_name_bytes(),
            Err(XattrNameListError::EmptyName)
        );

        let mut oversized_name_store = XattrStore::new(default_policy());
        let too_long = alloc::vec![b'a'; POSIX_XATTR_NAME_MAX + 1];
        oversized_name_store.set(&too_long, b"value", 0);
        assert_eq!(
            oversized_name_store.list_posix_name_bytes(),
            Err(XattrNameListError::NameTooLong {
                len: POSIX_XATTR_NAME_MAX + 1,
                max: POSIX_XATTR_NAME_MAX,
            })
        );
    }

    #[test]
    fn plan_posix_xattr_name_list_buffer_distinguishes_probe_and_copy() {
        assert_eq!(
            plan_posix_xattr_name_list_buffer(14, 0),
            Ok(XattrNameListBufferPlan {
                requested_size: 0,
                required_size: 14,
                action: XattrNameListBufferAction::ReportRequiredSize,
            })
        );

        let exact = plan_posix_xattr_name_list_buffer(14, 14).unwrap();
        assert_eq!(
            exact,
            XattrNameListBufferPlan {
                requested_size: 14,
                required_size: 14,
                action: XattrNameListBufferAction::CopyNames,
            }
        );
        assert!(!exact.reports_size_only());
        assert!(exact.copies_names());

        assert_eq!(
            plan_posix_xattr_name_list_buffer(14, 32),
            Ok(XattrNameListBufferPlan {
                requested_size: 32,
                required_size: 14,
                action: XattrNameListBufferAction::CopyNames,
            })
        );
    }

    #[test]
    fn plan_posix_xattr_name_list_buffer_rejects_undersized_buffer() {
        assert_eq!(
            plan_posix_xattr_name_list_buffer(14, 13),
            Err(XattrNameListBufferError::BufferTooSmall {
                requested_size: 13,
                required_size: 14,
            })
        );
    }

    #[test]
    fn list_posix_name_bytes_for_size_reports_required_size_without_bytes() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.z", b"vz", 0);
        s.set(b"user.a", b"va", 0);

        let read = s.list_posix_name_bytes_for_size(0).unwrap();

        assert_eq!(
            read.plan,
            XattrNameListBufferPlan {
                requested_size: 0,
                required_size: b"user.a\0user.z\0".len(),
                action: XattrNameListBufferAction::ReportRequiredSize,
            }
        );
        assert!(read.plan.reports_size_only());
        assert!(!read.plan.copies_names());
        assert!(read.bytes.is_empty());
    }

    #[test]
    fn list_posix_name_bytes_for_size_copies_exact_and_oversized_buffers() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.z", b"vz", 0);
        s.set(b"user.a", b"va", 0);
        let expected = b"user.a\0user.z\0".to_vec();

        let exact = s.list_posix_name_bytes_for_size(expected.len()).unwrap();
        assert_eq!(exact.plan.required_size, expected.len());
        assert_eq!(exact.plan.requested_size, expected.len());
        assert!(exact.plan.copies_names());
        assert_eq!(exact.bytes, expected);

        let oversized = s
            .list_posix_name_bytes_for_size(exact.plan.required_size + 8)
            .unwrap();
        assert_eq!(oversized.plan.required_size, exact.plan.required_size);
        assert_eq!(oversized.plan.requested_size, exact.plan.required_size + 8);
        assert!(oversized.plan.copies_names());
        assert_eq!(oversized.bytes, exact.bytes);
    }

    #[test]
    fn list_posix_name_bytes_for_size_returns_erange_for_undersized_buffer() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.z", b"vz", 0);
        s.set(b"user.a", b"va", 0);
        let required_size = b"user.a\0user.z\0".len();

        assert_eq!(
            s.list_posix_name_bytes_for_size(required_size - 1),
            Err(XattrNameListReadError::BufferTooSmall {
                requested_size: required_size - 1,
                required_size,
            })
        );
    }

    #[test]
    fn list_posix_name_bytes_for_size_propagates_invalid_names() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.\0bad", b"value", 0);

        assert_eq!(
            s.list_posix_name_bytes_for_size(1024),
            Err(XattrNameListReadError::InvalidNameList(
                XattrNameListError::NameContainsNul
            ))
        );
    }

    #[test]
    fn getxattr_value_buffer_plan_distinguishes_probe_and_copy() {
        assert_eq!(
            plan_posix_xattr_value_buffer(5, 0),
            Ok(XattrValueBufferPlan {
                requested_size: 0,
                required_size: 5,
                action: XattrValueBufferAction::ReportRequiredSize,
            })
        );

        let exact = plan_posix_xattr_value_buffer(5, 5).unwrap();
        assert_eq!(
            exact,
            XattrValueBufferPlan {
                requested_size: 5,
                required_size: 5,
                action: XattrValueBufferAction::CopyValue,
            }
        );
        assert!(!exact.reports_size_only());
        assert!(exact.copies_value());

        assert_eq!(
            plan_posix_xattr_value_buffer(5, 9),
            Ok(XattrValueBufferPlan {
                requested_size: 9,
                required_size: 5,
                action: XattrValueBufferAction::CopyValue,
            })
        );
    }

    #[test]
    fn getxattr_value_buffer_plan_reports_empty_value_size() {
        let probe = plan_posix_xattr_value_buffer(0, 0).unwrap();
        assert_eq!(
            probe,
            XattrValueBufferPlan {
                requested_size: 0,
                required_size: 0,
                action: XattrValueBufferAction::ReportRequiredSize,
            }
        );
        assert!(probe.reports_size_only());
        assert!(!probe.copies_value());

        assert_eq!(
            plan_posix_xattr_value_buffer(0, 1),
            Ok(XattrValueBufferPlan {
                requested_size: 1,
                required_size: 0,
                action: XattrValueBufferAction::CopyValue,
            })
        );
    }

    #[test]
    fn getxattr_value_buffer_plan_rejects_undersized_buffer() {
        assert_eq!(
            plan_posix_xattr_value_buffer(5, 4),
            Err(XattrValueBufferError::BufferTooSmall {
                requested_size: 4,
                required_size: 5,
            })
        );
    }

    #[test]
    fn getxattr_value_for_size_reports_required_size_without_value() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.comment", b"hello", 0);

        let read = s
            .get_posix_xattr_value_for_size(b"user.comment", 0)
            .unwrap();

        assert_eq!(
            read.plan,
            XattrValueBufferPlan {
                requested_size: 0,
                required_size: 5,
                action: XattrValueBufferAction::ReportRequiredSize,
            }
        );
        assert!(read.plan.reports_size_only());
        assert!(!read.plan.copies_value());
        assert!(read.value.is_empty());
    }

    #[test]
    fn getxattr_value_for_size_copies_exact_and_oversized_buffers() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.comment", b"hello", 0);

        let exact = s
            .get_posix_xattr_value_for_size(b"user.comment", 5)
            .unwrap();
        assert_eq!(
            exact.plan,
            XattrValueBufferPlan {
                requested_size: 5,
                required_size: 5,
                action: XattrValueBufferAction::CopyValue,
            }
        );
        assert_eq!(exact.value, b"hello".to_vec());

        let oversized = s
            .get_posix_xattr_value_for_size(b"user.comment", 16)
            .unwrap();
        assert_eq!(
            oversized.plan,
            XattrValueBufferPlan {
                requested_size: 16,
                required_size: 5,
                action: XattrValueBufferAction::CopyValue,
            }
        );
        assert_eq!(oversized.value, b"hello".to_vec());
    }

    #[test]
    fn getxattr_value_for_size_returns_erange_for_undersized_buffer_without_mutation() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.comment", b"hello", 0);
        let version = s.version();
        let total_value_bytes = s.total_value_bytes();

        assert_eq!(
            s.get_posix_xattr_value_for_size(b"user.comment", 4),
            Err(XattrValueReadError::BufferTooSmall {
                requested_size: 4,
                required_size: 5,
            })
        );

        assert_eq!(s.get(b"user.comment"), Some(b"hello".to_vec()));
        assert_eq!(s.version(), version);
        assert_eq!(s.total_value_bytes(), total_value_bytes);
    }

    #[test]
    fn getxattr_value_for_size_reports_missing_attribute() {
        let s = XattrStore::new(default_policy());

        assert_eq!(
            s.get_posix_xattr_value_for_size(b"user.missing", 0),
            Err(XattrValueReadError::EntryNotFound)
        );
    }

    #[test]
    fn getxattr_value_for_size_propagates_invalid_names_before_lookup() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.good", b"original", 0);

        assert_eq!(
            s.get_posix_xattr_value_for_size(b"", 0),
            Err(XattrValueReadError::InvalidName(
                XattrNameValidationError::EmptyName
            ))
        );
        assert_eq!(
            s.get_posix_xattr_value_for_size(b"user.bad\0name", 0),
            Err(XattrValueReadError::InvalidName(
                XattrNameValidationError::NameContainsNul
            ))
        );

        let too_long = alloc::vec![b'a'; POSIX_XATTR_NAME_MAX + 1];
        assert_eq!(
            s.get_posix_xattr_value_for_size(&too_long, 0),
            Err(XattrValueReadError::InvalidName(
                XattrNameValidationError::NameTooLong {
                    len: POSIX_XATTR_NAME_MAX + 1,
                    max: POSIX_XATTR_NAME_MAX,
                }
            ))
        );

        assert_eq!(s.get(b"user.good"), Some(b"original".to_vec()));
    }

    // -- ACL flag --

    #[test]
    fn acl_flag_set_and_clear_inline() {
        let mut s = XattrStore::new(default_policy());
        assert!(!s.has_acl());
        s.set_has_acl(true);
        assert!(s.has_acl());
        s.set_has_acl(false);
        assert!(!s.has_acl());
    }

    // -- Hysteresis: promotion --

    #[test]
    fn promote_on_excessive_count() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        for i in 0..4 {
            s.set(alloc::format!("k{i}").as_bytes(), b"v", 0);
        }
        // 4 > 3 inline_max_count → promoted
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn promote_on_excessive_bytes() {
        let policy = DatasetXattrPolicy::new(100, 10, 1, 5);
        let mut s = XattrStore::new(policy);
        s.set(b"k", &[0u8; 11], 0);
        // 11 > 10 inline_max_bytes → promoted
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
    }

    // -- Hysteresis: demotion --

    #[test]
    fn demote_after_promotion() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        // Promote
        for i in 0..4 {
            s.set(alloc::format!("k{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Remove down to 1 (<= downshift_count of 1)
        s.remove(b"k1").unwrap();
        s.remove(b"k2").unwrap();
        s.remove(b"k3").unwrap();
        assert_eq!(s.representation(), XattrStorageKind::INLINE);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn demote_only_when_both_count_and_bytes_below_threshold() {
        let policy = DatasetXattrPolicy::new(3, 100, 2, 50);
        let mut s = XattrStore::new(policy);
        // Promote with 4 entries at 10 bytes each = 40 bytes
        for i in 0..4 {
            s.set(alloc::format!("k{i}").as_bytes(), &[0u8; 10], 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Remove 2 entries — count=2 (<= downshift_count=2), bytes=20 (<= downshift_bytes=50)
        s.remove(b"k0").unwrap();
        s.remove(b"k1").unwrap();
        assert_eq!(s.representation(), XattrStorageKind::INLINE);
    }

    #[test]
    fn hysteresis_band_no_flapping() {
        let policy = DatasetXattrPolicy::new(5, 1000, 2, 500);
        let mut s = XattrStore::new(policy);
        // Insert 6 entries → promoted
        for i in 0..6 {
            s.set(alloc::format!("k{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Remove 3 → count=3 (3 <= 5 so inline would be fine, but 3 > downshift_count=2)
        s.remove(b"k3").unwrap();
        s.remove(b"k4").unwrap();
        s.remove(b"k5").unwrap();
        // Should remain external (hysteresis band)
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Remove 1 more → count=2 which meets downshift_count=2
        s.remove(b"k2").unwrap();
        assert_eq!(s.representation(), XattrStorageKind::INLINE);
    }

    // -- Btree mode operations --

    #[test]
    fn btree_get_set_remove_roundtrip() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        // Promotes to btree
        for i in 0..10 {
            s.set(
                alloc::format!("key{i:02}").as_bytes(),
                alloc::format!("val{i}").as_bytes(),
                0,
            );
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.len(), 10);
        // Get works in btree mode
        assert_eq!(s.get(b"key05"), Some(b"val5".to_vec()));
        assert!(s.get(b"missing").is_none());
        // Remove in btree mode
        s.remove(b"key05").unwrap();
        assert_eq!(s.len(), 9);
        assert!(s.get(b"key05").is_none());
    }

    #[test]
    fn btree_list_preserves_all_entries() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        let mut expected = Vec::new();
        for i in 0..10 {
            let key = alloc::format!("k{i:02}").into_bytes();
            let val = alloc::format!("v{i:02}").into_bytes();
            s.set(&key, &val, 0);
            expected.push((key, val));
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        let listed = s.list();
        assert_eq!(listed.len(), 10);
        for (k, v) in &expected {
            assert!(
                listed.iter().any(|(lk, lv)| lk == k && lv == v),
                "missing entry {:?}",
                core::str::from_utf8(k).unwrap()
            );
        }
    }

    #[test]
    fn btree_acl_flag_survives_promotion() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        s.set_has_acl(true);
        for i in 0..4 {
            s.set(alloc::format!("k{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert!(s.has_acl());
    }

    #[test]
    fn acl_flag_survives_demotion() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        s.set_has_acl(true);
        for i in 0..4 {
            s.set(alloc::format!("k{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Demote
        s.remove(b"k1").unwrap();
        s.remove(b"k2").unwrap();
        s.remove(b"k3").unwrap();
        assert_eq!(s.representation(), XattrStorageKind::INLINE);
        assert!(s.has_acl());
    }

    // -- Namespace and boundary regressions --

    #[test]
    fn namespace_prefixed_names_are_distinct_storage_keys() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"user.comment", b"u", 0);
        s.set(b"trusted.overlay", b"t", 0);
        s.set(b"security.selinux", b"s", 0);
        s.set(b"system.posix_acl_access", b"acl", 0);

        assert_eq!(s.len(), 4);
        assert_eq!(s.get(b"user.comment"), Some(b"u".to_vec()));
        assert_eq!(s.get(b"trusted.overlay"), Some(b"t".to_vec()));
        assert_eq!(s.get(b"security.selinux"), Some(b"s".to_vec()));
        assert_eq!(s.get(b"system.posix_acl_access"), Some(b"acl".to_vec()));
        assert_eq!(
            s.list_posix_name_bytes(),
            Ok(
                b"security.selinux\0system.posix_acl_access\0trusted.overlay\0user.comment\0"
                    .to_vec()
            )
        );

        s.remove(b"trusted.overlay").unwrap();
        assert_eq!(s.get(b"trusted.overlay"), None);
        assert_eq!(s.get(b"user.comment"), Some(b"u".to_vec()));
        assert_eq!(s.get(b"security.selinux"), Some(b"s".to_vec()));
        assert_eq!(s.get(b"system.posix_acl_access"), Some(b"acl".to_vec()));
        assert_eq!(
            s.list_posix_name_bytes(),
            Ok(b"security.selinux\0system.posix_acl_access\0user.comment\0".to_vec())
        );
    }

    #[test]
    fn external_upsert_replaces_without_duplicate_name() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        s.set(b"user.replace", b"old", 0);
        s.set(b"user.a", b"a", 0);
        s.set(b"user.b", b"bb", 0);
        s.set(b"user.c", b"ccc", 0);
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.len(), 4);
        assert_eq!(s.total_value_bytes(), 9);

        let previous = s.set(b"user.replace", b"new-value", 0);

        assert_eq!(previous, Some(b"old".to_vec()));
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.len(), 4);
        assert_eq!(s.version(), 5);
        assert_eq!(s.total_value_bytes(), 15);
        assert_eq!(s.get(b"user.replace"), Some(b"new-value".to_vec()));
        assert_eq!(
            s.list_names()
                .iter()
                .filter(|name| name.as_slice() == b"user.replace")
                .count(),
            1
        );
    }

    #[test]
    fn external_missing_key_read_and_remove_do_not_mutate_store() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        for i in 0..4 {
            s.set(alloc::format!("user.key{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        let version = s.version();
        let len = s.len();
        let total_value_bytes = s.total_value_bytes();

        assert_eq!(s.get(b"user.missing"), None);
        assert_eq!(
            s.remove(b"user.missing"),
            Err(XattrStoreError::EntryNotFound)
        );

        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.version(), version);
        assert_eq!(s.len(), len);
        assert_eq!(s.total_value_bytes(), total_value_bytes);
        assert_eq!(
            s.list_posix_name_bytes(),
            Ok(b"user.key0\0user.key1\0user.key2\0user.key3\0".to_vec())
        );
    }

    // -- Edge cases --

    #[test]
    fn empty_store_list() {
        let s = XattrStore::new(default_policy());
        assert!(s.list().is_empty());
        assert!(s.list_names().is_empty());
    }

    #[test]
    fn version_bumps_on_mutation() {
        let mut s = XattrStore::new(default_policy());
        assert_eq!(s.version(), 0);
        s.set(b"k", b"v", 0);
        assert_eq!(s.version(), 1);
        s.set(b"k2", b"v2", 0);
        assert_eq!(s.version(), 2);
        s.remove(b"k").unwrap();
        assert_eq!(s.version(), 3);
    }

    #[test]
    fn zero_length_value() {
        let mut s = XattrStore::new(default_policy());
        s.set(b"empty", b"", 0);
        assert_eq!(s.get(b"empty"), Some(b"".to_vec()));
        assert_eq!(s.total_value_bytes(), 0);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn large_value_roundtrip() {
        let mut s = XattrStore::new(default_policy());
        let big = alloc::vec![0xABu8; 8192];
        s.set(b"big", &big, 0);
        assert_eq!(s.get(b"big"), Some(big));
        assert_eq!(s.total_value_bytes(), 8192);
    }

    #[test]
    fn non_utf8_names() {
        let mut s = XattrStore::new(default_policy());
        let name = alloc::vec![0x00, 0xFF, 0x42];
        s.set(&name, b"val", 0);
        assert_eq!(s.get(&name), Some(b"val".to_vec()));
        s.remove(&name).unwrap();
        assert!(s.get(&name).is_none());
    }

    // -- Collision handling --

    #[test]
    fn collision_handling_same_hash_different_name() {
        let policy = DatasetXattrPolicy::new(3, 65536, 1, 32768);
        let mut s = XattrStore::new(policy);
        // Force promotion for collision testing
        for i in 0..4 {
            s.set(alloc::format!("a{i}").as_bytes(), b"v", 0);
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        // Insert more entries that might hash-collide; all should be retrievable
        for i in 0..20 {
            s.set(
                alloc::format!("entry-{i:03}").as_bytes(),
                alloc::format!("val-{i}").as_bytes(),
                0,
            );
        }
        assert_eq!(s.representation(), XattrStorageKind::EXTERNAL);
        for i in 0..20 {
            let key = alloc::format!("entry-{i:03}").into_bytes();
            let expected = alloc::format!("val-{i}").into_bytes();
            assert_eq!(s.get(&key), Some(expected), "missing entry-{i:03}");
        }
        assert_eq!(s.len(), 24); // 4 + 20
    }
}

// ── Persistent storage backend (feature = "persistence") ────────────

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod xattr_record;
#[cfg(any(test, feature = "persistence"))]
pub use xattr_record::XattrRecord;
#[cfg(any(test, feature = "persistence"))]
pub use xattr_record::{XattrNamespace, XattrRecordError};

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod set_xattr;
#[cfg(any(test, feature = "persistence"))]
pub use set_xattr::XattrSetStore;

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod get_xattr;
#[cfg(any(test, feature = "persistence"))]
pub use get_xattr::XattrGetStore;

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod list_xattr;
#[cfg(any(test, feature = "persistence"))]
pub use list_xattr::XattrListStore;

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod remove_xattr;
#[cfg(any(test, feature = "persistence"))]
pub use remove_xattr::XattrRemoveStore;

#[cfg(any(test, feature = "persistence"))]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub mod persistent;
#[cfg(any(test, feature = "persistence"))]
pub use persistent::PersistentXattrStore;
#[cfg(any(test, feature = "persistence"))]
pub use persistent::{
    PersistentXattrError, XattrOwner, XATTR_CREATE as PERSISTENT_XATTR_CREATE,
    XATTR_REPLACE as PERSISTENT_XATTR_REPLACE,
};
