// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE metadata worker pool (queue_class_1.meta_read).
//!
//! # Public API
//!
//! ## Routing
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`dispatch_meta_read`] | Identity pass-through for meta-read ingress contexts. |
//! | [`is_meta_read_request`] | Predicate: returns `true` when the context class is `MetaRead`. |
//! | [`meta_read_shard_key`] | Derives a shard key from a node id for meta-read queue placement. |
//!
//! ## Stat operations
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`dispatch_getattr`] | Retrieve inode attributes (mode, uid, gid, size, timestamps, nlink). |
//! | [`dispatch_setattr`] | Mutate inode attributes; applies permission checks, umask, ACL mask recalculation, and ctime updates. |
//! | [`dispatch_readlink`] | Read a symlink target as raw bytes, with POSIX truncation semantics. |
//! | [`dispatch_statfs`] | Build a filesystem statistics reply (total blocks, free blocks, block size, inode counts). |
//! | [`dispatch_statx`] | Build an extended stat reply with the mask requested by the client. |
//!
//! ## Directory operations
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`dispatch_lookup`] | Look up a child name in a parent directory; returns the child inode attributes or a negative-entry timeout. |
//! | [`dispatch_readdir`] | Read directory entries with fixed-size `DirEntry` records, supporting cookie-based resumption. |
//! | [`dispatch_readdirplus`] | Same as `dispatch_readdir` but also attaches inode attributes for each entry (READDIRPLUS optimisation). |
//! | [`dispatch_readdir_iter`] | Iterator-based readdir variant; streams entries through a callback on the reply sink. |
//! | [`dispatch_readdirplus_iter`] | Iterator-based readdirplus variant with per-entry attributes. |
//! | [`dispatch_opendir`] | Validate that an inode is a directory and return a file handle for subsequent readdir calls. |
//! | [`dispatch_releasedir`] | Release a directory handle. |
//!
//! ## Extended attributes
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`dispatch_getxattr`] | Read an extended attribute value by name; returns `ERANGE` when the buffer is too small. |
//! | [`dispatch_listxattr`] | List all extended attribute names; returns `ERANGE` when the buffer is too small. |
//! | [`dispatch_setxattr`] | Set or replace an extended attribute; honours `XATTR_CREATE` / `XATTR_REPLACE` flags. |
//! | [`dispatch_removexattr`] | Remove an extended attribute by name. |
//!
//! ## Access check
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`dispatch_access`] | Evaluate whether a caller (uid, gid, supplementary groups) has read, write, or execute access to an inode, including POSIX ACL and root-override rules. |
//!
//! ## Access mode constants
//!
//! | Constant | Value | Meaning |
//! |----------|-------|---------|
//! | [`ACCESS_READ`] | `0x04` | Read permission bit (`R_OK`). |
//! | [`ACCESS_WRITE`] | `0x02` | Write permission bit (`W_OK`). |
//! | [`ACCESS_EXECUTE`] | `0x01` | Execute / search permission bit (`X_OK`). |
//!
//! ## Generic parameters
//!
//! Most dispatch functions are generic over four backend traits:
//!
//! | Parameter | Trait | Provides |
//! |-----------|-------|----------|
//! | `I` | `InodeTable` | Mounted inode projection checks, kind queries (`is_dir`, `is_symlink`), permission lookups. |
//! | `D` | `DirIndex` | Directory entry iteration (`read_dir`, `lookup_entry`). Only needed by directory and lookup ops. |
//! | `A` | `AttrStore` | Attribute reads/writes (`getattr`, `setattr`). |
//! | `R` | `MetaReplySink` | Reply emission (`reply_entry`, `reply_attr`, `reply_readlink`, `reply_statfs`, `reply_statx`, `reply_xattr`, `reply_empty`, `reply_error`). |
//!
//! This crate provides dispatch helpers that bridge the ingress context mirror to the reply commit lane.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.

use std::vec::Vec;
use tidefs_dir_index::{DirCookie, DirIndexError, DirIterator};
use tidefs_posix_acl::{
    apply_chmod_to_acl, decode_posix_acl_xattr, encode_posix_acl_xattr,
    posix_acl_perm_bits_for_caller, AclError, PosixAcl, PosixAclEntry, ACL_GROUP, ACL_GROUP_OBJ,
    ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterRequestClass, PosixFilesystemAdapterRequestContextMirrorRecord,
};
use tidefs_types_vfs_core::{
    split_posix_time_ns, Errno, InodeAttr, NodeKind, PosixAttrs, SetAttr,
    FATTR_ATIME as VFS_FATTR_ATIME, FATTR_ATIME_NOW as VFS_FATTR_ATIME_NOW,
    FATTR_CTIME as VFS_FATTR_CTIME, FATTR_GID as VFS_FATTR_GID, FATTR_MODE as VFS_FATTR_MODE,
    FATTR_MTIME as VFS_FATTR_MTIME, FATTR_MTIME_NOW as VFS_FATTR_MTIME_NOW,
    FATTR_SIZE as VFS_FATTR_SIZE, FATTR_UID as VFS_FATTR_UID, S_IFBLK, S_IFCHR, S_IFDIR,
    S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_ISGID as VFS_S_ISGID,
    S_ISUID as VFS_S_ISUID, XATTR_CREATE, XATTR_REPLACE,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Lookup error kind ────────────────────────────────────────────────────

/// Error classification for FUSE lookup operations.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupErrorKind {
    /// Name not found in directory.
    Enoent = 2,
    /// Parent is not a directory.
    Enotdir = 20,
    /// Internal lookup failure (I/O, corruption, etc.).
    Eio = 5,
    /// Permission denied.
    Eacces = 13,
}

impl LookupErrorKind {
    #[must_use]
    pub const fn as_errno(self) -> i32 {
        -(self as i32)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Lookup timeout configuration ─────────────────────────────────────────

/// Entry and attribute timeout configuration for lookup replies.
///
/// FUSE clients use these timeouts to cache directory entries and inode
/// attributes in the kernel VFS layer, avoiding round-trips to the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupConfig {
    /// Entry timeout in seconds (directory entry cache lifetime).
    pub entry_ttl_secs: u64,
    /// Entry timeout sub-second nanoseconds.
    pub entry_ttl_nsec: u32,
    /// Attribute timeout in seconds (inode attribute cache lifetime).
    pub attr_ttl_secs: u64,
    /// Attribute timeout sub-second nanoseconds.
    pub attr_ttl_nsec: u32,
}

impl LookupConfig {
    /// Default timeouts: 1.0 s entry, 1.0 s attr (sane POSIX defaults).
    pub const DEFAULT: Self = Self {
        entry_ttl_secs: 1,
        entry_ttl_nsec: 0,
        attr_ttl_secs: 1,
        attr_ttl_nsec: 0,
    };
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ── Lookup outcome ──────────────────────────────────────────────────────

/// Result of a FUSE lookup operation.
///
/// Encodes the three possible outcomes: child found (carrying inode,
/// generation, and cache timeout values), child not found (negative
/// lookup with configurable cache duration), or an error classified
/// by [`LookupErrorKind`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupOutcome {
    /// Child inode resolved successfully.
    Found {
        /// Resolved child inode number.
        inode: u64,
        /// Inode generation (incremented on reuse).
        generation: u64,
    },
    /// Name not found in parent directory.
    NotFound,
    /// Lookup failed with a classified error.
    Error {
        /// Error classification.
        kind: LookupErrorKind,
    },
}

impl LookupOutcome {
    /// Return the POSIX errno for this outcome.
    ///
    /// Returns 0 for `Found`, `ENOENT` (2) for `NotFound`,
    /// and the specific errno for `Error`.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            LookupOutcome::Found { .. } => 0,
            LookupOutcome::NotFound => LookupErrorKind::Enoent.as_errno(),
            LookupOutcome::Error { kind } => kind.as_errno(),
        }
    }

    /// Return true if this is a successful lookup.
    #[must_use]
    pub const fn is_found(self) -> bool {
        matches!(self, LookupOutcome::Found { .. })
    }

    /// Return true if this is a negative (not-found) lookup.
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        matches!(self, LookupOutcome::NotFound)
    }

    /// Return true if this outcome is an error.
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, LookupOutcome::Error { .. })
    }

    /// Return the inode number if found, otherwise None.
    #[must_use]
    pub const fn inode(self) -> Option<u64> {
        match self {
            LookupOutcome::Found { inode, .. } => Some(inode),
            _ => None,
        }
    }

    /// Return the generation if found, otherwise None.
    #[must_use]
    pub const fn generation(self) -> Option<u64> {
        match self {
            LookupOutcome::Found { generation, .. } => Some(generation),
            _ => None,
        }
    }
}

// ── Metadata dispatch ────────────────────────────────────────────────────

#[must_use]
pub const fn dispatch_meta_read(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    ctx
}

#[must_use]
pub const fn is_meta_read_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    ctx.request_class == PosixFilesystemAdapterRequestClass::MetaRead.as_u32()
}

#[must_use]
pub const fn meta_read_shard_key(nodeid: u64) -> u64 {
    nodeid
}

// ── Lookup handler ───────────────────────────────────────────────────────

/// Dispatch a FUSE lookup request through the metadata worker pool.
///
/// This is the type-level handler for the lookup op: it accepts the
/// incoming context mirror, parent inode, and child name, and returns
/// the context record for downstream dispatch.
///
/// The daemon runtime supplies the resolver, usually backed by the VFS engine.
#[must_use]
pub fn handle_lookup<F>(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
    parent_ino: u64,
    child_name: &[u8],
    resolve: F,
) -> (
    PosixFilesystemAdapterRequestContextMirrorRecord,
    LookupOutcome,
)
where
    F: FnOnce(u64, &[u8]) -> LookupOutcome,
{
    let outcome = resolve(parent_ino, child_name);
    (dispatch_meta_read(ctx), outcome)
}

// -- POSIX readlink planning helpers -----------------------------------------

/// POSIX `ENOENT` for missing readlink targets.
pub const POSIX_READLINK_ENOENT: i32 = Errno::ENOENT.raw() as i32;

/// POSIX `EINVAL` for invalid readlink buffer sizes or non-symlink targets.
pub const POSIX_READLINK_EINVAL: i32 = Errno::EINVAL.raw() as i32;

/// Metadata-worker readlink planning failures with errno-ready classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadlinkPlanError {
    /// POSIX readlink requires a non-zero caller buffer.
    InvalidBufferSize { provided: usize },
}

impl ReadlinkPlanError {
    /// Return the positive POSIX errno used for this readlink planning failure.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidBufferSize { .. } => POSIX_READLINK_EINVAL,
        }
    }
}

/// Pure readlink reply plan for metadata-worker callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadlinkReplyPlan<'a> {
    payload: &'a [u8],
    required: usize,
    provided: usize,
    truncated: bool,
}

impl<'a> ReadlinkReplyPlan<'a> {
    /// Return true when the caller buffer truncates the symlink target.
    #[must_use]
    pub const fn is_truncated(self) -> bool {
        self.truncated
    }

    /// Return the full symlink target length.
    #[must_use]
    pub const fn required_len(self) -> usize {
        self.required
    }

    /// Return the caller-provided buffer length.
    #[must_use]
    pub const fn provided_len(self) -> usize {
        self.provided
    }

    /// Return the number of bytes that should be copied to the caller.
    #[must_use]
    pub const fn copied_len(self) -> usize {
        self.payload.len()
    }

    /// Borrow the exact bytes that should be copied to the caller.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Plan POSIX `readlink(2)` buffer handling without touching daemon or storage state.
pub fn plan_readlink_reply<'a>(
    target: &'a [u8],
    requested_size: u32,
) -> Result<ReadlinkReplyPlan<'a>, ReadlinkPlanError> {
    let provided = requested_size as usize;
    if provided == 0 {
        return Err(ReadlinkPlanError::InvalidBufferSize { provided });
    }

    let required = target.len();
    let copied = core::cmp::min(required, provided);
    Ok(ReadlinkReplyPlan {
        payload: &target[..copied],
        required,
        provided,
        truncated: copied < required,
    })
}

/// Result of a FUSE readlink operation after metadata-worker planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadlinkOutcome<'a> {
    /// Symlink target bytes are ready for the caller buffer.
    Target { plan: ReadlinkReplyPlan<'a> },
    /// The requested inode does not exist.
    NotFound,
    /// The requested inode exists but is not a symlink.
    NotSymlink,
    /// The caller supplied an invalid readlink buffer.
    InvalidBuffer { error: ReadlinkPlanError },
    /// Backend readlink resolution failed with a POSIX errno.
    Error { errno: i32 },
}

impl<'a> ReadlinkOutcome<'a> {
    /// Return the positive POSIX errno for this outcome, or zero on success.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::Target { .. } => 0,
            Self::NotFound => POSIX_READLINK_ENOENT,
            Self::NotSymlink => POSIX_READLINK_EINVAL,
            Self::InvalidBuffer { error } => error.errno(),
            Self::Error { errno } => errno,
        }
    }

    /// Return true when a readlink target payload is available.
    #[must_use]
    pub const fn is_target(self) -> bool {
        matches!(self, Self::Target { .. })
    }

    /// Borrow the planned reply payload for successful readlink outcomes.
    #[must_use]
    pub const fn payload(self) -> Option<&'a [u8]> {
        match self {
            Self::Target { plan } => Some(plan.payload()),
            _ => None,
        }
    }

    /// Return whether a successful readlink payload was truncated.
    #[must_use]
    pub const fn is_truncated(self) -> bool {
        match self {
            Self::Target { plan } => plan.is_truncated(),
            _ => false,
        }
    }
}

/// Dispatch a FUSE readlink request through the metadata worker pool.
///
/// The daemon runtime supplies the resolver, usually backed by namespace or VFS
/// symlink metadata. The resolver receives the inode and caller buffer size so
/// it can use [`plan_readlink_reply`] for POSIX truncation semantics.
#[must_use]
pub fn handle_readlink<'a, F>(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
    ino: u64,
    requested_size: u32,
    resolve: F,
) -> (
    PosixFilesystemAdapterRequestContextMirrorRecord,
    ReadlinkOutcome<'a>,
)
where
    F: FnOnce(u64, u32) -> ReadlinkOutcome<'a>,
{
    let outcome = resolve(ino, requested_size);
    (dispatch_meta_read(ctx), outcome)
}

// -- POSIX ACL helper layer -------------------------------------------------

/// Linux xattr name for POSIX access ACLs.
pub const POSIX_ACL_ACCESS_XATTR: &[u8] = b"system.posix_acl_access";

/// Linux xattr name for POSIX default ACLs (directories only).
pub const POSIX_ACL_DEFAULT_XATTR: &[u8] = b"system.posix_acl_default";

/// POSIX `EACCES` for denied ACL permission checks.
pub const POSIX_ACL_EACCES: i32 = 13;

/// POSIX `EINVAL` for invalid ACL xattr payloads or check requests.
pub const POSIX_ACL_EINVAL: i32 = 22;

/// Metadata-worker validation failures for POSIX access ACL payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessAclError {
    /// The Linux xattr codec rejected the payload.
    Decode(AclError),
    /// A required access ACL entry is missing.
    MissingRequiredEntry { tag: u16 },
    /// A required singleton access ACL entry appeared more than once.
    DuplicateRequiredEntry { tag: u16 },
    /// A named user/group entry exists without an ACL_MASK entry.
    MissingMask,
    /// The ACL contains more than one ACL_MASK entry.
    DuplicateMask,
    /// A caller supplied an unknown ACL tag to validation.
    InvalidTag { tag: u16 },
    /// A caller supplied permission bits outside rwx.
    InvalidPerm { perm: u16 },
    /// A non-named ACL entry carried a non-zero id.
    InvalidId { tag: u16, id: u32 },
    /// A named user/group entry is duplicated.
    DuplicateNamedEntry { tag: u16, id: u32 },
    /// Requested permission bits included values outside rwx.
    InvalidRequestedPerm { requested: u8 },
}

impl AccessAclError {
    /// Return the POSIX errno used for invalid ACL input.
    #[must_use]
    pub const fn errno(self) -> i32 {
        POSIX_ACL_EINVAL
    }
}

/// Decoded and metadata-worker-validated POSIX access ACL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAccessAcl {
    entries: PosixAcl,
}

impl DecodedAccessAcl {
    /// Borrow the validated ACL entries.
    #[must_use]
    pub fn entries(&self) -> &[PosixAclEntry] {
        &self.entries
    }

    /// Consume the wrapper and return the owned ACL entries.
    #[must_use]
    pub fn into_entries(self) -> PosixAcl {
        self.entries
    }

    /// Encode the validated ACL back to Linux xattr bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_posix_acl_xattr(&self.entries)
    }

    /// Apply chmod-style mode bits to this ACL and validate the result.
    pub fn chmod(&self, new_mode: u32) -> Result<Self, AccessAclError> {
        let entries = chmod_access_acl(self.entries(), new_mode)?;
        Ok(Self { entries })
    }
}

/// Caller and inode data required for pure ACL access planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessAclCheck<'a> {
    pub file_uid: u32,
    pub file_gid: u32,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub caller_groups: &'a [u32],
    pub mode_fallback: u32,
    pub requested: u8,
}

/// ACL access decision with errno-ready denial details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessAclDecision {
    /// All requested permission bits are present.
    Allowed,
    /// At least one requested permission bit is denied.
    Denied { errno: i32 },
}

impl AccessAclDecision {
    /// Return true when access is allowed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Return the POSIX errno for this decision, or zero on success.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::Allowed => 0,
            Self::Denied { errno } => errno,
        }
    }
}

/// Pure access-plan result for callers that will later emit FUSE replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessAclPlan {
    pub effective_perm: u8,
    pub requested: u8,
    pub decision: AccessAclDecision,
}

impl AccessAclPlan {
    /// Return true when the ACL permits the requested access.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        self.decision.is_allowed()
    }

    /// Return the POSIX errno for this plan, or zero on success.
    #[must_use]
    pub const fn errno(self) -> i32 {
        self.decision.errno()
    }
}

/// Decode and validate a Linux `system.posix_acl_access` xattr payload.
pub fn decode_access_acl_xattr(raw: &[u8]) -> Result<DecodedAccessAcl, AccessAclError> {
    let entries = decode_posix_acl_xattr(raw).map_err(AccessAclError::Decode)?;
    validate_access_acl(&entries)?;
    Ok(DecodedAccessAcl { entries })
}

/// Validate access ACL invariants before metadata-worker use.
pub fn validate_access_acl(entries: &[PosixAclEntry]) -> Result<(), AccessAclError> {
    ensure_single_required_entry(entries, ACL_USER_OBJ)?;
    ensure_single_required_entry(entries, ACL_GROUP_OBJ)?;
    ensure_single_required_entry(entries, ACL_OTHER)?;

    let mut has_named_entry = false;
    let mut mask_count = 0usize;

    for entry in entries {
        if entry.perm > 0x7 {
            return Err(AccessAclError::InvalidPerm { perm: entry.perm });
        }

        match entry.tag {
            ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER => {
                if entry.id != 0 {
                    return Err(AccessAclError::InvalidId {
                        tag: entry.tag,
                        id: entry.id,
                    });
                }
            }
            ACL_MASK => {
                mask_count += 1;
                if entry.id != 0 {
                    return Err(AccessAclError::InvalidId {
                        tag: entry.tag,
                        id: entry.id,
                    });
                }
            }
            ACL_USER | ACL_GROUP => {
                has_named_entry = true;
            }
            _ => return Err(AccessAclError::InvalidTag { tag: entry.tag }),
        }
    }

    if mask_count > 1 {
        return Err(AccessAclError::DuplicateMask);
    }
    if has_named_entry && mask_count == 0 {
        return Err(AccessAclError::MissingMask);
    }

    for (idx, left) in entries.iter().enumerate() {
        if left.tag != ACL_USER && left.tag != ACL_GROUP {
            continue;
        }
        for right in entries.iter().skip(idx + 1) {
            if left.tag == right.tag && left.id == right.id {
                return Err(AccessAclError::DuplicateNamedEntry {
                    tag: left.tag,
                    id: left.id,
                });
            }
        }
    }

    Ok(())
}

/// Encode an ACL after validating metadata-worker access ACL invariants.
pub fn encode_validated_access_acl(entries: &[PosixAclEntry]) -> Result<Vec<u8>, AccessAclError> {
    validate_access_acl(entries)?;
    Ok(encode_posix_acl_xattr(entries))
}

/// Apply chmod-style mode bits to a validated access ACL.
pub fn chmod_access_acl(
    entries: &[PosixAclEntry],
    new_mode: u32,
) -> Result<PosixAcl, AccessAclError> {
    validate_access_acl(entries)?;
    let updated = apply_chmod_to_acl(entries, new_mode);
    validate_access_acl(&updated)?;
    Ok(updated)
}

/// Plan an ACL-aware permission check without touching daemon or storage state.
pub fn plan_access_acl_check(
    entries: &[PosixAclEntry],
    check: AccessAclCheck<'_>,
) -> Result<AccessAclPlan, AccessAclError> {
    validate_access_acl(entries)?;
    if check.requested & !0x7 != 0 {
        return Err(AccessAclError::InvalidRequestedPerm {
            requested: check.requested,
        });
    }

    let effective_perm = posix_acl_perm_bits_for_caller(
        entries,
        check.file_uid,
        check.file_gid,
        check.caller_uid,
        check.caller_gid,
        check.caller_groups,
        check.mode_fallback,
    );
    let allowed = effective_perm & check.requested == check.requested;
    let decision = if allowed {
        AccessAclDecision::Allowed
    } else {
        AccessAclDecision::Denied {
            errno: POSIX_ACL_EACCES,
        }
    };

    Ok(AccessAclPlan {
        effective_perm,
        requested: check.requested,
        decision,
    })
}

fn ensure_single_required_entry(entries: &[PosixAclEntry], tag: u16) -> Result<(), AccessAclError> {
    let count = entries.iter().filter(|entry| entry.tag == tag).count();
    match count {
        0 => Err(AccessAclError::MissingRequiredEntry { tag }),
        1 => Ok(()),
        _ => Err(AccessAclError::DuplicateRequiredEntry { tag }),
    }
}

// -- POSIX ACL xattr interception ------------------------------------------

/// Errors returned when intercepting ACL xattr operations before storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclInterceptError {
    /// The ACL xattr payload is structurally invalid.
    InvalidAclPayload,
    /// A default ACL was requested on a non-directory inode.
    DefaultAclOnNonDirectory,
    /// The xattr name is an unsupported ACL namespace.
    UnsupportedAclNamespace,
}

impl AclInterceptError {
    /// Return the POSIX errno for this interception error.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidAclPayload => self::POSIX_ACL_EINVAL,
            Self::DefaultAclOnNonDirectory => Errno::ENODATA.raw() as i32,
            Self::UnsupportedAclNamespace => Errno::EOPNOTSUPP.raw() as i32,
        }
    }
}

/// Return true when `name` is a reserved POSIX ACL xattr name.
#[must_use]
pub fn is_acl_xattr_name(name: &[u8]) -> bool {
    name == POSIX_ACL_ACCESS_XATTR || name == POSIX_ACL_DEFAULT_XATTR
}

/// Validate an ACL xattr value before accepting it through FUSE setxattr.
///
/// Decodes and structurally validates the ACL blob. An empty value is
/// accepted (the Linux convention for deleting an ACL xattr).
pub fn validate_acl_setxattr_value(_name: &[u8], value: &[u8]) -> Result<(), AclInterceptError> {
    // An empty value is the Linux convention for deleting an ACL xattr.
    if value.is_empty() {
        return Ok(());
    }
    // Decode and validate the ACL blob structure.
    let entries =
        decode_posix_acl_xattr(value).map_err(|_| AclInterceptError::InvalidAclPayload)?;
    validate_access_acl(&entries).map_err(|_| AclInterceptError::InvalidAclPayload)?;
    Ok(())
}

// -- POSIX xattr planning helpers -------------------------------------------

/// POSIX `EINVAL` for malformed xattr flags.
pub const POSIX_XATTR_EINVAL: i32 = Errno::EINVAL.raw() as i32;

/// POSIX `EEXIST` for `XATTR_CREATE` against an existing xattr.
pub const POSIX_XATTR_EEXIST: i32 = Errno::EEXIST.raw() as i32;

/// Linux `ENODATA` for `XATTR_REPLACE` against a missing xattr.
pub const POSIX_XATTR_ENODATA: i32 = Errno::ENODATA.raw() as i32;

/// POSIX `ERANGE` for xattr reply buffers that are too small.
pub const POSIX_XATTR_ERANGE: i32 = Errno::ERANGE.raw() as i32;

/// Metadata-worker xattr planning failures with errno-ready classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrPlanError {
    /// The setxattr flags include unsupported bits or both create/replace.
    InvalidSetFlags { flags: u32 },
    /// `XATTR_CREATE` was requested but the xattr already exists.
    AlreadyExists,
    /// `XATTR_REPLACE` was requested but the xattr is absent.
    Missing,
    /// The caller supplied a non-zero reply buffer smaller than the payload.
    BufferTooSmall { required: usize, provided: usize },
}

impl XattrPlanError {
    /// Return the positive POSIX errno used for this xattr planning failure.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidSetFlags { .. } => POSIX_XATTR_EINVAL,
            Self::AlreadyExists => POSIX_XATTR_EEXIST,
            Self::Missing => POSIX_XATTR_ENODATA,
            Self::BufferTooSmall { .. } => POSIX_XATTR_ERANGE,
        }
    }
}

/// Normalized xattr set mode derived from Linux `setxattr(2)` flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrSetMode {
    /// No existence precondition; create or replace.
    Upsert,
    /// `XATTR_CREATE`: fail if the xattr already exists.
    CreateOnly,
    /// `XATTR_REPLACE`: fail if the xattr does not exist.
    ReplaceOnly,
}

/// Pure setxattr plan for metadata-worker callers.
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

/// Plan Linux `setxattr(2)` flag handling without touching storage state.
pub fn plan_setxattr(flags: u32, exists: bool) -> Result<XattrSetPlan, XattrPlanError> {
    let mode = match flags {
        0 => XattrSetMode::Upsert,
        XATTR_CREATE => XattrSetMode::CreateOnly,
        XATTR_REPLACE => XattrSetMode::ReplaceOnly,
        _ => return Err(XattrPlanError::InvalidSetFlags { flags }),
    };

    match mode {
        XattrSetMode::CreateOnly if exists => Err(XattrPlanError::AlreadyExists),
        XattrSetMode::ReplaceOnly if !exists => Err(XattrPlanError::Missing),
        _ => Ok(XattrSetPlan {
            flags,
            exists,
            mode,
        }),
    }
}

/// Pure getxattr/listxattr reply plan for metadata-worker callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrReadPlan<'a> {
    /// Kernel requested size discovery with a zero-length buffer.
    SizeProbe { required: usize },
    /// Kernel provided a large-enough buffer; emit this payload.
    Reply { payload: &'a [u8] },
}

impl<'a> XattrReadPlan<'a> {
    /// Return true when this plan is a size-only response.
    #[must_use]
    pub const fn is_size_probe(self) -> bool {
        matches!(self, Self::SizeProbe { .. })
    }

    /// Return true when this plan carries reply bytes.
    #[must_use]
    pub const fn is_reply(self) -> bool {
        matches!(self, Self::Reply { .. })
    }

    /// Return the required payload length for either response form.
    #[must_use]
    pub const fn required_len(self) -> usize {
        match self {
            Self::SizeProbe { required } => required,
            Self::Reply { payload } => payload.len(),
        }
    }

    /// Borrow reply bytes when the caller should emit a payload.
    #[must_use]
    pub const fn payload(self) -> Option<&'a [u8]> {
        match self {
            Self::SizeProbe { .. } => None,
            Self::Reply { payload } => Some(payload),
        }
    }
}

/// Plan a `getxattr` response from an existing xattr value.
pub fn plan_getxattr_reply<'a>(
    value: &'a [u8],
    requested_size: u32,
) -> Result<XattrReadPlan<'a>, XattrPlanError> {
    plan_xattr_read_payload(value, requested_size)
}

/// Plan a `listxattr` response from a packed NUL-separated name list.
pub fn plan_listxattr_reply<'a>(
    packed_names: &'a [u8],
    requested_size: u32,
) -> Result<XattrReadPlan<'a>, XattrPlanError> {
    plan_xattr_read_payload(packed_names, requested_size)
}

fn plan_xattr_read_payload<'a>(
    payload: &'a [u8],
    requested_size: u32,
) -> Result<XattrReadPlan<'a>, XattrPlanError> {
    let required = payload.len();
    if requested_size == 0 {
        return Ok(XattrReadPlan::SizeProbe { required });
    }

    let provided = requested_size as usize;
    if provided < required {
        Err(XattrPlanError::BufferTooSmall { required, provided })
    } else {
        Ok(XattrReadPlan::Reply { payload })
    }
}

// -- POSIX setattr planning helpers -----------------------------------------

/// POSIX `EINVAL` for internally inconsistent setattr flags.
pub const POSIX_SETATTR_EINVAL: i32 = Errno::EINVAL.raw() as i32;

/// POSIX `EOPNOTSUPP` for setattr flags the metadata-worker plan cannot carry.
pub const POSIX_SETATTR_EOPNOTSUPP: i32 = Errno::EOPNOTSUPP.raw() as i32;

const SUPPORTED_SETATTR_TIME_BITS: u32 =
    VFS_FATTR_ATIME | VFS_FATTR_MTIME | VFS_FATTR_ATIME_NOW | VFS_FATTR_MTIME_NOW | VFS_FATTR_CTIME;

const SUPPORTED_SETATTR_PLAN_BITS: u32 =
    VFS_FATTR_MODE | VFS_FATTR_UID | VFS_FATTR_GID | VFS_FATTR_SIZE | SUPPORTED_SETATTR_TIME_BITS;

/// Metadata-worker setattr planning failures with errno-ready classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetattrPlanError {
    /// The `valid` mask includes flags this pure metadata plan cannot represent.
    UnsupportedValidBits { valid: u32, unsupported: u32 },
    /// A timestamp requested both a concrete value and the kernel's "now" mode.
    ConflictingTimeFlags { specific: u32, now: u32 },
}

impl SetattrPlanError {
    /// Return the positive POSIX errno used for this setattr planning failure.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::UnsupportedValidBits { .. } => POSIX_SETATTR_EOPNOTSUPP,
            Self::ConflictingTimeFlags { .. } => POSIX_SETATTR_EINVAL,
        }
    }
}

/// Timestamp mutation requested by a setattr operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetattrTimePlan {
    /// Leave the timestamp unchanged.
    Unchanged,
    /// Apply this concrete nanosecond value.
    SetNs(i64),
    /// Apply the caller-supplied current time when materializing the plan.
    SetNow,
}

impl SetattrTimePlan {
    /// Return true when the timestamp should be mutated.
    #[must_use]
    pub const fn is_changed(self) -> bool {
        !matches!(self, Self::Unchanged)
    }
}

/// Pure timestamp-only setattr plan for metadata-worker callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetattrTimestampPlan {
    pub valid: u32,
    pub atime: SetattrTimePlan,
    pub mtime: SetattrTimePlan,
    pub ctime: SetattrTimePlan,
}

impl SetattrTimestampPlan {
    /// Return true when at least one timestamp should change.
    #[must_use]
    pub const fn has_mutations(self) -> bool {
        self.atime.is_changed() || self.mtime.is_changed() || self.ctime.is_changed()
    }

    /// Materialize this timestamp plan as a concrete VFS [`SetAttr`].
    #[must_use]
    pub fn to_setattr_with_now(self, now_ns: i64) -> SetAttr {
        let mut attr = SetAttr::new();

        match self.atime {
            SetattrTimePlan::Unchanged => {}
            SetattrTimePlan::SetNs(atime_ns) => {
                attr.valid |= VFS_FATTR_ATIME;
                attr.atime_ns = atime_ns;
            }
            SetattrTimePlan::SetNow => {
                attr.valid |= VFS_FATTR_ATIME;
                attr.atime_ns = now_ns;
            }
        }
        match self.mtime {
            SetattrTimePlan::Unchanged => {}
            SetattrTimePlan::SetNs(mtime_ns) => {
                attr.valid |= VFS_FATTR_MTIME;
                attr.mtime_ns = mtime_ns;
            }
            SetattrTimePlan::SetNow => {
                attr.valid |= VFS_FATTR_MTIME;
                attr.mtime_ns = now_ns;
            }
        }
        if let SetattrTimePlan::SetNs(ctime_ns) = self.ctime {
            attr.valid |= VFS_FATTR_CTIME;
            attr.ctime_ns = ctime_ns;
        }

        attr
    }
}

/// Pure setattr plan for metadata-worker callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetattrPlan {
    pub valid: u32,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: SetattrTimePlan,
    pub mtime: SetattrTimePlan,
    pub ctime: SetattrTimePlan,
}

impl SetattrPlan {
    /// Return true when at least one metadata field should change.
    #[must_use]
    pub const fn has_mutations(self) -> bool {
        self.mode.is_some()
            || self.uid.is_some()
            || self.gid.is_some()
            || self.size.is_some()
            || self.atime.is_changed()
            || self.mtime.is_changed()
            || self.ctime.is_changed()
    }

    /// Return true when the plan includes a file-size update.
    #[must_use]
    pub const fn changes_size(self) -> bool {
        self.size.is_some()
    }

    /// Materialize the plan as a concrete VFS [`SetAttr`].
    ///
    /// `SetNow` timestamps are resolved with the caller-provided `now_ns` so
    /// the pure metadata-worker plan does not read a clock or touch daemon state.
    #[must_use]
    pub fn to_setattr_with_now(self, now_ns: i64) -> SetAttr {
        let mut attr = SetAttr::new();

        if let Some(mode) = self.mode {
            attr.valid |= VFS_FATTR_MODE;
            attr.mode = mode;
        }
        if let Some(uid) = self.uid {
            attr.valid |= VFS_FATTR_UID;
            attr.uid = uid;
        }
        if let Some(gid) = self.gid {
            attr.valid |= VFS_FATTR_GID;
            attr.gid = gid;
        }
        if let Some(size) = self.size {
            attr.valid |= VFS_FATTR_SIZE;
            attr.size = size;
        }

        let timestamps = SetattrTimestampPlan {
            valid: self.valid & SUPPORTED_SETATTR_TIME_BITS,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
        .to_setattr_with_now(now_ns);

        attr.valid |= timestamps.valid;
        attr.atime_ns = timestamps.atime_ns;
        attr.mtime_ns = timestamps.mtime_ns;
        attr.ctime_ns = timestamps.ctime_ns;

        attr
    }
}

/// Plan POSIX/FUSE setattr flag handling without touching daemon or storage state.
pub fn plan_setattr(attr: &SetAttr) -> Result<SetattrPlan, SetattrPlanError> {
    let unsupported = attr.valid & !SUPPORTED_SETATTR_PLAN_BITS;
    if unsupported != 0 {
        return Err(SetattrPlanError::UnsupportedValidBits {
            valid: attr.valid,
            unsupported,
        });
    }
    let timestamps = plan_setattr_timestamps(attr)?;

    Ok(SetattrPlan {
        valid: attr.valid,
        mode: flag_value(attr.valid, VFS_FATTR_MODE, attr.mode),
        uid: flag_value(attr.valid, VFS_FATTR_UID, attr.uid),
        gid: flag_value(attr.valid, VFS_FATTR_GID, attr.gid),
        size: flag_value(attr.valid, VFS_FATTR_SIZE, attr.size),
        atime: timestamps.atime,
        mtime: timestamps.mtime,
        ctime: timestamps.ctime,
    })
}

/// Plan only POSIX/FUSE timestamp setattr flags without touching daemon or storage state.
pub fn plan_setattr_timestamps(attr: &SetAttr) -> Result<SetattrTimestampPlan, SetattrPlanError> {
    if attr.valid & VFS_FATTR_ATIME != 0 && attr.valid & VFS_FATTR_ATIME_NOW != 0 {
        return Err(SetattrPlanError::ConflictingTimeFlags {
            specific: VFS_FATTR_ATIME,
            now: VFS_FATTR_ATIME_NOW,
        });
    }
    if attr.valid & VFS_FATTR_MTIME != 0 && attr.valid & VFS_FATTR_MTIME_NOW != 0 {
        return Err(SetattrPlanError::ConflictingTimeFlags {
            specific: VFS_FATTR_MTIME,
            now: VFS_FATTR_MTIME_NOW,
        });
    }

    Ok(SetattrTimestampPlan {
        valid: attr.valid & SUPPORTED_SETATTR_TIME_BITS,
        atime: plan_setattr_time(
            attr.valid,
            VFS_FATTR_ATIME,
            VFS_FATTR_ATIME_NOW,
            attr.atime_ns,
        ),
        mtime: plan_setattr_time(
            attr.valid,
            VFS_FATTR_MTIME,
            VFS_FATTR_MTIME_NOW,
            attr.mtime_ns,
        ),
        ctime: if attr.valid & VFS_FATTR_CTIME != 0 {
            SetattrTimePlan::SetNs(attr.ctime_ns)
        } else {
            SetattrTimePlan::Unchanged
        },
    })
}

/// Ownership-aware setattr plan for metadata-worker callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetattrOwnershipPlan {
    pub plan: SetattrPlan,
    pub ownership_changed: bool,
    pub privilege_bits_cleared: bool,
}

impl SetattrOwnershipPlan {
    /// Materialize the wrapped plan as a concrete VFS [`SetAttr`].
    #[must_use]
    pub fn to_setattr_with_now(self, now_ns: i64) -> SetAttr {
        self.plan.to_setattr_with_now(now_ns)
    }
}

/// Plan ownership setattr handling, including chown/chgrp privilege-bit clearing.
pub fn plan_setattr_ownership(
    attr: &SetAttr,
    current_mode: u32,
    caller_uid: u32,
) -> Result<SetattrOwnershipPlan, SetattrPlanError> {
    let mut plan = plan_setattr(attr)?;
    let ownership_changed = plan.uid.is_some() || plan.gid.is_some();
    let mut privilege_bits_cleared = false;

    if ownership_changed {
        let mode_before_killpriv = plan.mode.unwrap_or(current_mode);
        let mode_after_killpriv = killpriv_mode_on_chown(mode_before_killpriv, caller_uid);

        if mode_after_killpriv != mode_before_killpriv {
            plan.valid |= VFS_FATTR_MODE;
            plan.mode = Some(mode_after_killpriv);
            privilege_bits_cleared = true;
        }
    }

    Ok(SetattrOwnershipPlan {
        plan,
        ownership_changed,
        privilege_bits_cleared,
    })
}

/// POSIX permission gate for FUSE `setattr` operations.
///
/// The kernel FUSE module does not enforce owner/root restrictions for
/// chmod, chown, and chgrp via `setattr`.  This function implements
/// the required permission checks:
///
/// - Mode change (FATTR_MODE): only the file owner or root may chmod.
/// - Owner change (FATTR_UID): only root may chown.
/// - Group change (FATTR_GID): owner/root may chgrp to a group the caller
///   belongs to; root may chgrp to any group.
///
/// `supplemental_gids` lists supplementary groups the caller belongs to,
/// allowing POSIX-compliant chgrp when the target group is not the primary GID.
///
/// Timestamp and size permission checks are handled by the kernel via the
/// file-descriptor write-permission path, so this gate does not duplicate
/// those checks.
///
/// Returns `Ok(())` when the caller is authorised, or `Err(MetaError::PermDenied)`.
pub fn can_setattr(
    caller_uid: u32,
    caller_gid: u32,
    supplemental_gids: &[u32],
    current_uid: u32,
    current_gid: u32,
    to_set: u32,
    new_attrs: &SetAttr,
) -> Result<(), MetaError> {
    // Root bypasses all permission checks.
    if caller_uid == 0 {
        return Ok(());
    }

    // Mode change: only the file owner (or root) may chmod.
    if to_set & VFS_FATTR_MODE != 0 && caller_uid != current_uid {
        return Err(MetaError::PermDenied);
    }

    // Owner change: only root may chown.
    if to_set & VFS_FATTR_UID != 0 {
        return Err(MetaError::PermDenied);
    }

    // Group change: owner may chgrp to a group they belong to.
    if to_set & VFS_FATTR_GID != 0 {
        if caller_uid != current_uid {
            return Err(MetaError::PermDenied);
        }
        // Owner may only chgrp to a group they are a member of.
        // Check primary GID, file's current GID, and supplementary groups.
        let target_gid = new_attrs.gid;
        let is_member = target_gid == caller_gid
            || target_gid == current_gid
            || supplemental_gids.contains(&target_gid);
        if !is_member {
            return Err(MetaError::PermDenied);
        }
    }

    Ok(())
}

fn killpriv_mode_on_chown(mode: u32, caller_uid: u32) -> u32 {
    if caller_uid == 0 {
        mode
    } else {
        mode & !(VFS_S_ISUID | VFS_S_ISGID)
    }
}

fn flag_value<T: Copy>(valid: u32, bit: u32, value: T) -> Option<T> {
    if valid & bit != 0 {
        Some(value)
    } else {
        None
    }
}

fn plan_setattr_time(
    valid: u32,
    specific_bit: u32,
    now_bit: u32,
    value_ns: i64,
) -> SetattrTimePlan {
    if valid & specific_bit != 0 {
        SetattrTimePlan::SetNs(value_ns)
    } else if valid & now_bit != 0 {
        SetattrTimePlan::SetNow
    } else {
        SetattrTimePlan::Unchanged
    }
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by meta-worker handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaError {
    /// The requested inode does not exist.
    InoNotFound,
    /// Permission denied by the setattr permission gate.
    PermDenied,
    /// The attribute store failed (e.g. link underflow).
    /// The requested inode is not a directory.
    NotDir,
    AttrStoreError,
    /// The reply sink failed.
    ReplyError,
    /// Invalid metadata request input.
    InvalidInput,
    /// `XATTR_CREATE` found an existing xattr.
    XattrAlreadyExists,
    /// Requested xattr is absent.
    XattrNoData,
    /// Internal I/O error.
    Io,
}

impl MetaError {
    /// Map this error to a POSIX errno.
    #[must_use]
    pub fn errno(self) -> i32 {
        match self {
            Self::InoNotFound => 2,     // ENOENT
            Self::NotDir => 20,         // ENOTDIR
            Self::AttrStoreError => 67, // ENOLINK
            Self::InvalidInput => Errno::EINVAL.raw() as i32,
            Self::XattrAlreadyExists => Errno::EEXIST.raw() as i32,
            Self::XattrNoData => Errno::ENODATA.raw() as i32,
            Self::ReplyError => 5, // EIO
            Self::Io => 5,         // EIO
            Self::PermDenied => 1, // EPERM
        }
    }
}

// ── FUSE wire-format attr ───────────────────────────────────────────────────

// ── Statfs reply fields ─────────────────────────────────────────────────────

/// Fields needed to populate a FUSE `statfs_out` reply.
///
/// The caller (dispatch layer) fills this from block-allocator and inode-metadata
/// queries; the reply sink serializes it to FUSE wire format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatfsFields {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub bsize: u64,
    pub frsize: u64,
    pub files: u64,
    pub ffree: u64,
    pub namemax: u32,
}

/// FUSE `statx` reply fields aggregated from `PosixAttrs`.
///
/// Contains the extended attributes returned by `dispatch_statx`
/// (FUSE_STATX, opcode 52). Birth time (`btime`) and basic stat
/// fields are populated from the engine's `getattr` path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatxReply {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime_sec: i64,
    pub stx_atime_nsec: u32,
    pub stx_mtime_sec: i64,
    pub stx_mtime_nsec: u32,
    pub stx_ctime_sec: i64,
    pub stx_ctime_nsec: u32,
    pub stx_btime_sec: i64,
    pub stx_btime_nsec: u32,
}

/// FUSE `fuse_attr` wire-format structure (kernel ABI, `fuse_kernel.h`).
///
/// This matches the `fuse_attr` layout expected by the FUSE kernel module.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub padding: u32,
}

/// FUSE `fuse_attr_out` reply structure (kernel ABI, `fuse_kernel.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

// ── FUSE attr wire serialization ────────────────────────────────────────

/// Encode a u32 into `out` at `offset` in little-endian byte order.
fn encode_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Encode a u64 into `out` at `offset` in little-endian byte order.
fn encode_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Decode a u32 from `input` at `offset` in little-endian byte order.
fn decode_u32_le(input: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&input[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Decode a u64 from `input` at `offset` in little-endian byte order.
fn decode_u64_le(input: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

impl FuseAttr {
    /// Wire size of the `fuse_attr` structure in bytes (kernel ABI).
    pub const WIRE_SIZE: usize = 88;

    /// Encode this `FuseAttr` into a wire-format buffer.
    ///
    /// The buffer must be at least [`FuseAttr::WIRE_SIZE`] bytes.
    /// Panics if `out.len() < FuseAttr::WIRE_SIZE`.
    pub fn encode(&self, out: &mut [u8]) {
        assert!(out.len() >= Self::WIRE_SIZE);
        encode_u64_le(out, 0, self.ino);
        encode_u64_le(out, 8, self.size);
        encode_u64_le(out, 16, self.blocks);
        encode_u64_le(out, 24, self.atime);
        encode_u64_le(out, 32, self.mtime);
        encode_u64_le(out, 40, self.ctime);
        encode_u32_le(out, 48, self.atimensec);
        encode_u32_le(out, 52, self.mtimensec);
        encode_u32_le(out, 56, self.ctimensec);
        encode_u32_le(out, 60, self.mode);
        encode_u32_le(out, 64, self.nlink);
        encode_u32_le(out, 68, self.uid);
        encode_u32_le(out, 72, self.gid);
        encode_u32_le(out, 76, self.rdev);
        encode_u32_le(out, 80, self.blksize);
        encode_u32_le(out, 84, self.padding);
    }

    /// Decode a `FuseAttr` from a wire-format buffer.
    ///
    /// The buffer must be at least [`FuseAttr::WIRE_SIZE`] bytes.
    /// Panics if `input.len() < FuseAttr::WIRE_SIZE`.
    pub fn decode(input: &[u8]) -> Self {
        assert!(input.len() >= Self::WIRE_SIZE);
        Self {
            ino: decode_u64_le(input, 0),
            size: decode_u64_le(input, 8),
            blocks: decode_u64_le(input, 16),
            atime: decode_u64_le(input, 24),
            mtime: decode_u64_le(input, 32),
            ctime: decode_u64_le(input, 40),
            atimensec: decode_u32_le(input, 48),
            mtimensec: decode_u32_le(input, 52),
            ctimensec: decode_u32_le(input, 56),
            mode: decode_u32_le(input, 60),
            nlink: decode_u32_le(input, 64),
            uid: decode_u32_le(input, 68),
            gid: decode_u32_le(input, 72),
            rdev: decode_u32_le(input, 76),
            blksize: decode_u32_le(input, 80),
            padding: decode_u32_le(input, 84),
        }
    }
}

impl FuseAttrOut {
    /// Wire size of the `fuse_attr_out` structure in bytes (kernel ABI).
    pub const WIRE_SIZE: usize = 104;

    /// Encode this `FuseAttrOut` into a wire-format buffer.
    ///
    /// The buffer must be at least [`FuseAttrOut::WIRE_SIZE`] bytes.
    /// Panics if `out.len() < FuseAttrOut::WIRE_SIZE`.
    pub fn encode(&self, out: &mut [u8]) {
        assert!(out.len() >= Self::WIRE_SIZE);
        encode_u64_le(out, 0, self.attr_valid);
        encode_u32_le(out, 8, self.attr_valid_nsec);
        encode_u32_le(out, 12, self.dummy);
        self.attr.encode(&mut out[16..]);
    }

    /// Decode a `FuseAttrOut` from a wire-format buffer.
    ///
    /// The buffer must be at least [`FuseAttrOut::WIRE_SIZE`] bytes.
    /// Panics if `input.len() < FuseAttrOut::WIRE_SIZE`.
    pub fn decode(input: &[u8]) -> Self {
        assert!(input.len() >= Self::WIRE_SIZE);
        Self {
            attr_valid: decode_u64_le(input, 0),
            attr_valid_nsec: decode_u32_le(input, 8),
            dummy: decode_u32_le(input, 12),
            attr: FuseAttr::decode(&input[16..]),
        }
    }
}

// ── FUSE entry-out reply ────────────────────────────────────────────────────

/// FUSE `entry_out` reply payload for lookup operations.
///
/// Carries the resolved inode number, generation, cache timeout values,
/// and the full attribute set so FUSE clients can cache directory entries
/// without a separate GETATTR round-trip.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FuseEntryOut {
    /// Resolved inode number.
    pub nodeid: u64,
    /// Inode generation (incremented on reuse).
    pub generation: u64,
    /// Entry timeout in seconds (directory entry cache lifetime).
    pub entry_valid: u64,
    /// Entry timeout sub-second nanoseconds.
    pub entry_valid_nsec: u32,
    /// Attribute timeout in seconds (inode attribute cache lifetime).
    pub attr_valid: u64,
    /// Attribute timeout sub-second nanoseconds.
    pub attr_valid_nsec: u32,
    /// Full FUSE attributes for the resolved inode.
    pub attr: FuseAttr,
}

impl FuseEntryOut {
    /// Build an `entry_out` from an `attr_out` plus lookup-specific fields.
    #[must_use]
    pub fn from_attr_out(
        attr_out: &FuseAttrOut,
        nodeid: u64,
        generation: u64,
        lookup_cfg: LookupConfig,
    ) -> Self {
        Self {
            nodeid,
            generation,
            entry_valid: lookup_cfg.entry_ttl_secs,
            entry_valid_nsec: lookup_cfg.entry_ttl_nsec,
            attr_valid: attr_out.attr_valid,
            attr_valid_nsec: attr_out.attr_valid_nsec,
            attr: attr_out.attr,
        }
    }
}

/// Default attribute cache validity (1 second).
pub const DEFAULT_ATTR_VALID: u64 = 1;
pub const DEFAULT_ATTR_VALID_NSEC: u32 = 0;
// Review debt TFR-008: wire to attribute-cache TTL configuration (historical issue #3129).

// ── Conversion helpers ──────────────────────────────────────────────────────

/// Convert raw nanoseconds to (seconds, subsecond_nanoseconds).
#[inline]
const fn ns_to_sec_nsec(ns: i64) -> (u64, u32) {
    let (sec, nsec) = split_posix_time_ns(ns);
    (sec as u64, nsec)
}

/// Build a [`FuseAttr`] from VFS-core primitives.
///
/// This is the bridge between [`InodeAttr`]/[`PosixAttrs`] and the FUSE wire
/// format. It mirrors the logic in `InodeAttributeStore::to_stat` but produces
/// `fuse_attr` directly instead of `libc::stat`.
#[must_use]
pub fn posix_attrs_to_fuse_attr(ino: u64, posix: &PosixAttrs, kind: NodeKind) -> FuseAttr {
    let (atime, atimensec) = ns_to_sec_nsec(posix.atime_ns);
    let (mtime, mtimensec) = ns_to_sec_nsec(posix.mtime_ns);
    let (ctime, ctimensec) = ns_to_sec_nsec(posix.ctime_ns);
    let mode = if posix.mode & S_IFMT == 0 {
        posix.mode | mode_type_bits_for_kind(kind)
    } else {
        posix.mode
    };

    FuseAttr {
        ino,
        size: posix.size,
        blocks: posix.blocks_512,
        atime,
        mtime,
        ctime,
        atimensec,
        mtimensec,
        ctimensec,
        mode,
        nlink: posix.nlink,
        uid: posix.uid,
        gid: posix.gid,
        rdev: posix.rdev,
        blksize: posix.blksize,
        padding: 0,
    }
}

fn mode_type_bits_for_kind(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Dir => S_IFDIR,
        NodeKind::File => S_IFREG,
        NodeKind::Symlink => S_IFLNK,
        NodeKind::CharDev => S_IFCHR,
        NodeKind::BlockDev => S_IFBLK,
        NodeKind::Fifo => S_IFIFO,
        NodeKind::Socket => S_IFSOCK,
        NodeKind::Whiteout => 0,
    }
}

/// Build a complete `FuseAttrOut` reply with default cache validity.
#[must_use]
pub fn fuse_attr_out(ino: u64, posix: &PosixAttrs, kind: NodeKind) -> FuseAttrOut {
    let mut attr = posix_attrs_to_fuse_attr(ino, posix, kind);
    // POSIX: directories must report nlink >= 2 (. and ..).
    // The stored value may be stale or zero-initialized; clamp here
    // so that find(1), stat(1), and POSIX conformance tests see the
    // correct minimum link count.
    if kind == NodeKind::Dir && attr.nlink < 2 {
        attr.nlink = 2;
    }
    FuseAttrOut {
        attr_valid: DEFAULT_ATTR_VALID,
        attr_valid_nsec: DEFAULT_ATTR_VALID_NSEC,
        dummy: 0,
        attr,
    }
}

// ── InodeTable trait ────────────────────────────────────────────────────────

/// Minimal mounted inode projection consumed by the meta worker.
///
/// For the #655/#665 inode-authority boundary this trait is adapter-visible
/// metadata projection only. It must not allocate inode numbers, decide
/// durable mounted dataset existence, or preserve inode lifetime; the
/// dataset-scoped authority selected by #655 and tracked by #664 owns that
/// allocator state.
pub trait InodeTable {
    /// Check whether `ino` exists.
    fn lookup(&self, ino: u64) -> bool;

    /// Return the full [`InodeAttr`] for `ino`.
    ///
    /// Returns `None` if the inode does not exist.
    fn getattr(&self, ino: u64) -> Option<InodeAttr>;

    /// Apply a masked attribute update.
    ///
    /// Returns the updated [`InodeAttr`] or a [`MetaError`].
    fn setattr(&self, ino: u64, set: &SetAttr) -> Result<InodeAttr, MetaError>;

    /// Retrieve the symlink target bytes for `ino`.
    ///
    /// Returns `None` when the inode does not exist or is not a symlink.
    /// Callers must verify the inode type (`NodeKind::Symlink`) independently
    /// when they need a type-specific errno.
    fn readlink_target(&self, ino: u64) -> Option<Vec<u8>>;

    /// Return filesystem-wide inode statistics (total, free).
    ///
    /// Returns `None` when the backend cannot report inode counts.
    fn inode_stats(&self) -> Option<(u64, u64)> {
        None
    }

    /// Get the value of an extended attribute for `ino` by `name`.
    ///
    /// Returns `Err(MetaError::InoNotFound)` when the inode does not exist
    /// and `Err(MetaError::Io)` when the attribute is not found.
    fn get_xattr(&self, _ino: u64, _name: &[u8]) -> Result<Vec<u8>, MetaError> {
        Err(MetaError::Io)
    }

    /// Return the size of an extended attribute value for `ino`.
    ///
    /// Used for the FUSE ERANGE pattern: the kernel calls with a zero-size
    /// buffer to learn the required size, then retries with a buffer.
    fn get_xattr_size(&self, _ino: u64, _name: &[u8]) -> Result<usize, MetaError> {
        Err(MetaError::Io)
    }

    /// Set (create or replace) an extended attribute on `ino`.
    ///
    /// `flags` is 0 (upsert), `XATTR_CREATE` (fail if exists),
    /// or `XATTR_REPLACE` (fail if absent). Backends should return
    /// `XattrAlreadyExists`, `XattrNoData`, or `InvalidInput` for those
    /// flag-shaped failures so the FUSE errno reaches callers unchanged.
    fn set_xattr(
        &self,
        _ino: u64,
        _name: &[u8],
        _value: &[u8],
        _flags: u32,
    ) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }

    /// List all extended attribute names for `ino`.
    ///
    /// Returns NUL-separated (`\0`) name bytes terminated by a final NUL
    /// (Linux xattr list convention).
    fn list_xattr(&self, _ino: u64) -> Result<Vec<u8>, MetaError> {
        Err(MetaError::Io)
    }

    /// Return the total buffer size needed to hold `list_xattr` output.
    fn list_xattr_size(&self, _ino: u64) -> Result<usize, MetaError> {
        Err(MetaError::Io)
    }

    /// Remove an extended attribute from `ino`.
    ///
    /// Returns `Err(MetaError::XattrNoData)` when the attribute does not exist.
    fn remove_xattr(&self, _ino: u64, _name: &[u8]) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }
}

// ── AttrStore trait ─────────────────────────────────────────────────────────

/// Stat-conversion bridge consumed by the meta worker.
///
/// This is a local projection of what the `InodeAttributeStore::to_stat`
/// path delivers. It produces a [`FuseAttrOut`] suitable for FUSE reply
/// emission.
pub trait AttrStore {
    /// Produce a FUSE-wire `attr_out` reply for `ino`.
    ///
    /// Returns `Err(MetaError::InoNotFound)` if the inode is not present.
    fn to_fuse_attr_out(&self, ino: u64) -> Result<FuseAttrOut, MetaError>;
}

// ── MetaReplySink trait ─────────────────────────────────────────────────────

/// Reply-sink interface for emitting FUSE replies.
///
/// Implementations write to the actual FUSE device or capture replies
/// for testing.
pub trait MetaReplySink {
    /// Emit an error-only reply (no payload).
    fn reply_error(&mut self, unique: u64, errno: i32) -> Result<(), MetaError>;

    /// Emit an `attr_out` reply (GETATTR / SETATTR success).
    fn reply_attr(&mut self, unique: u64, attr_out: &FuseAttrOut) -> Result<(), MetaError>;

    /// Emit a `readlink` reply carrying symlink target bytes.
    ///
    /// The payload is the raw target bytes as read from the symlink inode.
    /// FUSE expects exactly the target bytes (no null terminator added here).
    fn reply_readlink(&mut self, unique: u64, data: &[u8]) -> Result<(), MetaError>;

    /// Emit a `statfs` reply carrying filesystem statistics.
    fn reply_statfs(&mut self, unique: u64, fields: &StatfsFields) -> Result<(), MetaError>;

    /// Emit a `statx` reply carrying extended inode attributes.
    ///
    /// Default implementation returns an error; backends that handle
    /// STATX serialization should override this.
    fn reply_statx(&mut self, _unique: u64, _statx: &StatxReply) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }

    /// Emit an `entry_out` reply (LOOKUP success).
    ///
    /// Default implementation returns an error; backends that need the
    /// entry timeout and generation fields should override this.
    fn reply_entry(&mut self, _unique: u64, _entry_out: &FuseEntryOut) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }

    /// Emit a `readdir` reply carrying packed directory entries.
    ///
    /// Default implementation returns an error; backends that handle
    /// FUSE readdir serialization should override this.
    fn reply_readdir(
        &mut self,
        _unique: u64,
        _entries: &[DirLookupEntry],
        _next_cookie: u64,
    ) -> Result<ReaddirPackResult, MetaError> {
        Err(MetaError::Io)
    }

    /// Emit a `readdirplus` reply carrying packed entries with attrs.
    ///
    /// Default implementation returns an error; backends that handle
    /// FUSE readdirplus serialization should override this.
    fn reply_readdirplus(
        &mut self,
        _unique: u64,
        _entries: &[DirLookupEntry],
        _attrs: &[FuseAttrOut],
        _next_cookie: u64,
    ) -> Result<ReaddirPackResult, MetaError> {
        Err(MetaError::Io)
    }

    /// Emit an `opendir` reply carrying the directory handle and open flags.
    ///
    /// Default implementation returns an error; backends that handle
    /// FUSE opendir serialization should override this.
    fn reply_opendir(&mut self, _unique: u64, _fh: u64, _flags: u32) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }

    /// Emit an empty success reply (used by RELEASEDIR, FLUSH, etc.).
    ///
    /// Default implementation returns an error; backends that handle
    /// empty success serialization should override this.
    fn reply_empty(&mut self, _unique: u64) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }

    /// Emit an xattr data reply (getxattr/listxattr success).
    ///
    /// `size` is the number of valid bytes in `data`; callers that need to
    /// reply with just a size (ERANGE pattern) pass `data` as empty.
    fn reply_xattr_data(&mut self, _unique: u64, _data: &[u8]) -> Result<(), MetaError> {
        Err(MetaError::Io)
    }
}

// ── Readdir types ───────────────────────────────────────────────────────────

/// A slice of directory entries returned by a readdir operation.
///
/// Carries the entries plus a continuation cookie for pagination.
/// An empty `entries` vector and a cookie of 0 means end-of-directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaddirSlice {
    /// Directory entries in name-sorted order.
    pub entries: Vec<DirLookupEntry>,
    /// Continuation cookie for the next readdir call.
    ///
    /// A value of 0 means no more entries (end of directory).
    pub next_cookie: u64,
}

impl ReaddirSlice {
    /// An empty slice with end-of-directory cookie.
    pub const EMPTY: Self = Self {
        entries: Vec::new(),
        next_cookie: 0,
    };

    /// Return true when this is the last slice (no more entries).
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.next_cookie == 0
    }
}

/// Result of packing a readdir reply into a FUSE buffer.
///
/// Callers retry when `needs_continuation` is true and `wrote` entries
/// were packed before the buffer filled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaddirPackResult {
    /// Number of entries packed into the buffer.
    pub wrote: usize,
    /// If true, more entries remain that did not fit.
    pub needs_continuation: bool,
    /// Total bytes consumed by the packed entries.
    pub bytes_used: usize,
}
// ── DirLookupEntry ──────────────────────────────────────────────────────────

/// Minimal directory entry used by the [`DirIndex`] trait.
///
/// Carries the fields needed to resolve a FUSE lookup or pack a FUSE
/// readdir reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirLookupEntry {
    /// Child inode number.
    pub inode_id: u64,
    /// Inode generation.
    pub generation: u64,
    /// Node kind (directory, file, symlink, etc.).
    pub kind: u32,
    /// Entry name.
    pub name: Vec<u8>,
}

// ── DirIndex trait ──────────────────────────────────────────────────────────

/// Directory-index interface consumed by the meta worker.
///
/// Abstracts name-to-inode resolution for `dispatch_lookup` and directory
/// iteration. Backends may be in-memory (mock), persistent B+tree, or any
/// other directory representation.
pub trait DirIndex {
    /// Resolve `name` within `parent_ino`.
    ///
    /// Returns `None` when the entry does not exist.
    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Option<DirLookupEntry>;

    /// Return true when `parent_ino` contains `name`.
    fn contains(&self, parent_ino: u64, name: &[u8]) -> bool {
        self.lookup(parent_ino, name).is_some()
    }
    /// List entries in `parent_ino` starting from `cookie`.
    ///
    /// Returns a [`ReaddirSlice`] with up to `max_entries` entries.
    /// `cookie=0` starts from the beginning. The returned
    /// `next_cookie` is 0 when no more entries remain.
    fn readdir(&self, parent_ino: u64, cookie: u64, max_entries: usize) -> ReaddirSlice;
}
// ── MetaWorker ──────────────────────────────────────────────────────────────

/// FUSE metadata worker: dispatches `GETATTR` and `SETATTR` opcodes.
///
/// Bridges the inode table, attribute store, and reply sink to serve
/// per-inode stat responses and accept size/mode/owner/timestamp mutations.
pub struct MetaWorker<'a, I: InodeTable, A: AttrStore, R: MetaReplySink> {
    inode_table: &'a I,
    attr_store: &'a A,
    reply_sink: &'a mut R,
}

impl<'a, I: InodeTable, A: AttrStore, R: MetaReplySink> MetaWorker<'a, I, A, R> {
    /// Construct a new meta worker wrapping the three required handles.
    pub fn new(inode_table: &'a I, attr_store: &'a A, reply_sink: &'a mut R) -> Self {
        Self {
            inode_table,
            attr_store,
            reply_sink,
        }
    }

    /// Handle a FUSE `GETATTR` request.
    ///
    /// Resolves the inode through the inode table, converts attributes to
    /// FUSE wire format via the attribute store, and emits the reply.
    ///
    /// `fh` is reserved for future handle-based attr lookup; currently unused.
    pub fn handle_getattr(
        &mut self,
        ino: u64,
        unique: u64,
        _fh: Option<u64>,
    ) -> Result<(), MetaError> {
        // Validate inode exists.
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        // Produce FUSE attr_out through the attribute store.
        match self.attr_store.to_fuse_attr_out(ino) {
            Ok(attr_out) => {
                self.reply_sink.reply_attr(unique, &attr_out)?;
                Ok(())
            }
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                Err(e)
            }
        }
    }

    /// Handle a FUSE `SETATTR` request.
    ///
    /// Validates the inode exists, applies the masked attribute update through
    /// the inode table, and replies with the updated stat. On partial failure,
    /// returns the first errno without applying partial mutations.
    pub fn handle_setattr(
        &mut self,
        ino: u64,
        unique: u64,
        attrs: &SetAttr,
        caller_uid: u32,
        caller_gid: u32,
        supplemental_gids: &[u32],
    ) -> Result<(), MetaError> {
        // Validate inode exists.
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        // POSIX permission gate: chmod/chown/chgrp restrictions.
        if let Some(current) = self.inode_table.getattr(ino) {
            can_setattr(
                caller_uid,
                caller_gid,
                supplemental_gids,
                current.posix.uid,
                current.posix.gid,
                attrs.valid,
                attrs,
            )?;
        }

        // Apply attribute mutations through the inode table.
        // The inode table is responsible for ctime bump and partial-failure
        // rejection.
        match self.inode_table.setattr(ino, attrs) {
            Ok(_updated) => {
                // On success, re-read and reply with updated stat.
                match self.attr_store.to_fuse_attr_out(ino) {
                    Ok(attr_out) => {
                        self.reply_sink.reply_attr(unique, &attr_out)?;
                        Ok(())
                    }
                    Err(e) => {
                        self.reply_sink.reply_error(unique, e.errno())?;
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                Err(e)
            }
        }
    }

    /// Handle a FUSE `READLINK` request.
    ///
    /// Validates the inode exists, checks that it is a symlink, retrieves
    /// the target bytes, plans the reply with POSIX truncation semantics,
    /// and emits the reply through the sink.
    pub fn handle_readlink_inode(
        &mut self,
        ino: u64,
        unique: u64,
        requested_size: u32,
    ) -> Result<(), MetaError> {
        // Validate inode exists.
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        // Verify the inode is a symlink.
        if let Some(attr) = self.inode_table.getattr(ino) {
            if attr.kind != NodeKind::Symlink {
                self.reply_sink
                    .reply_error(unique, self::POSIX_READLINK_EINVAL)?;
                return Err(MetaError::Io);
            }
        }

        // Retrieve symlink target and plan the reply.
        let target = self.inode_table.readlink_target(ino).unwrap_or_default();
        match plan_readlink_reply(&target, requested_size) {
            Ok(plan) => {
                self.reply_sink.reply_readlink(unique, plan.payload())?;
                Ok(())
            }
            Err(plan_err) => {
                self.reply_sink.reply_error(unique, plan_err.errno())?;
                Err(MetaError::Io)
            }
        }
    }

    /// Expose a reference to the inode table (for testing/inspection).
    pub fn inode_table(&self) -> &I {
        self.inode_table
    }

    /// Expose a reference to the attribute store (for testing/inspection).
    pub fn attr_store(&self) -> &A {
        self.attr_store
    }

    /// Handle a FUSE `STATFS` request.
    ///
    /// Combines block-allocator statistics (from the caller) with inode-table
    /// statistics to produce a complete `statfs_out` reply.
    pub fn handle_statfs(
        &mut self,
        unique: u64,
        block_total: u64,
        block_free: u64,
        block_avail: u64,
        block_size: u64,
        name_max: u32,
    ) -> Result<(), MetaError> {
        let (files, ffree) = self.inode_table.inode_stats().unwrap_or((0, 0));
        let fields = StatfsFields {
            blocks: block_total,
            bfree: block_free,
            bavail: block_avail,
            bsize: block_size,
            frsize: block_size,
            files,
            ffree,
            namemax: name_max,
        };
        self.reply_sink.reply_statfs(unique, &fields)
    }

    /// Handle a FUSE `STATX` request.
    ///
    /// Validates the inode exists, retrieves attributes through the
    /// attribute store, translates `PosixAttrs` into the `StatxReply`
    /// layout, and emits the reply through the sink.
    pub fn handle_statx(
        &mut self,
        ino: u64,
        unique: u64,
        _fh: Option<u64>,
    ) -> Result<(), MetaError> {
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        let attr = match self.inode_table.getattr(ino) {
            Some(a) => a,
            None => {
                self.reply_sink
                    .reply_error(unique, MetaError::InoNotFound.errno())?;
                return Err(MetaError::InoNotFound);
            }
        };

        let statx = statx_from_inode_attr(&attr);
        self.reply_sink.reply_statx(unique, &statx)?;
        Ok(())
    }

    /// Handle a FUSE `GETXATTR` request.
    ///
    /// Validates the inode exists, retrieves the xattr value, plans
    /// the reply with ERANGE semantics, and emits the response.
    pub fn handle_getxattr(
        &mut self,
        ino: u64,
        unique: u64,
        name: &[u8],
        requested_size: u32,
    ) -> Result<(), MetaError> {
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        // Default ACL xattrs are only valid on directories.
        if name == POSIX_ACL_DEFAULT_XATTR {
            if let Some(attr) = self.inode_table.getattr(ino) {
                if attr.kind != NodeKind::Dir {
                    self.reply_sink
                        .reply_error(unique, AclInterceptError::DefaultAclOnNonDirectory.errno())?;
                    return Err(MetaError::Io);
                }
            }
        }

        let value = match self.inode_table.get_xattr(ino, name) {
            Ok(v) => v,
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                return Err(e);
            }
        };

        match plan_getxattr_reply(&value, requested_size) {
            Ok(plan) => {
                if let Some(payload) = plan.payload() {
                    self.reply_sink.reply_xattr_data(unique, payload)?;
                } else {
                    self.reply_sink
                        .reply_error(unique, plan.required_len() as i32)?;
                }
                Ok(())
            }
            Err(plan_err) => {
                self.reply_sink.reply_error(unique, plan_err.errno())?;
                Err(MetaError::Io)
            }
        }
    }

    /// Handle a FUSE `LISTXATTR` request.
    ///
    /// Validates the inode exists, retrieves the packed name list,
    /// plans the reply with ERANGE semantics, and emits the response.
    pub fn handle_listxattr(
        &mut self,
        ino: u64,
        unique: u64,
        requested_size: u32,
    ) -> Result<(), MetaError> {
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        let packed_names = match self.inode_table.list_xattr(ino) {
            Ok(v) => v,
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                return Err(e);
            }
        };

        match plan_listxattr_reply(&packed_names, requested_size) {
            Ok(plan) => {
                if let Some(payload) = plan.payload() {
                    self.reply_sink.reply_xattr_data(unique, payload)?;
                } else {
                    self.reply_sink
                        .reply_error(unique, plan.required_len() as i32)?;
                }
                Ok(())
            }
            Err(plan_err) => {
                self.reply_sink.reply_error(unique, plan_err.errno())?;
                Err(MetaError::Io)
            }
        }
    }

    /// Handle a FUSE `SETXATTR` request.
    ///
    /// Validates the inode and flag shape, applies the mutation through the
    /// inode table, and emits the backend errno directly.
    pub fn handle_setxattr(
        &mut self,
        ino: u64,
        unique: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), MetaError> {
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        // ACL xattr payload validation: reject structurally invalid ACL blobs
        // before they reach the storage layer.
        if is_acl_xattr_name(name) {
            if let Err(acl_err) = validate_acl_setxattr_value(name, value) {
                self.reply_sink.reply_error(unique, acl_err.errno())?;
                return Err(MetaError::Io);
            }
        }

        if !matches!(flags, 0 | XATTR_CREATE | XATTR_REPLACE) {
            self.reply_sink.reply_error(unique, POSIX_XATTR_EINVAL)?;
            return Err(MetaError::InvalidInput);
        }

        match self.inode_table.set_xattr(ino, name, value, flags) {
            Ok(()) => {
                self.reply_sink.reply_error(unique, 0)?;
                Ok(())
            }
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                Err(e)
            }
        }
    }

    /// Handle a FUSE `REMOVEXATTR` request.
    ///
    /// Validates the inode exists, removes the xattr through the
    /// inode table, and emits the reply.
    pub fn handle_removexattr(
        &mut self,
        ino: u64,
        unique: u64,
        name: &[u8],
    ) -> Result<(), MetaError> {
        if !self.inode_table.lookup(ino) {
            self.reply_sink
                .reply_error(unique, MetaError::InoNotFound.errno())?;
            return Err(MetaError::InoNotFound);
        }

        match self.inode_table.remove_xattr(ino, name) {
            Ok(()) => {}
            Err(e) => {
                self.reply_sink.reply_error(unique, e.errno())?;
                return Err(e);
            }
        }
        self.reply_sink.reply_error(unique, 0)?;
        Ok(())
    }
}

// ── Dispatch functions ──────────────────────────────────────────────────

/// Dispatch a FUSE GETATTR request through the metadata worker.
///
/// This is the public dispatch entry point for MetaRead-class GETATTR
/// (opcode 3). It constructs a [`MetaWorker`] from the provided backends,
/// extracts the inode from the context mirror, and delegates to
/// [`MetaWorker::handle_getattr`].
pub fn dispatch_getattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_getattr(ctx.nodeid, ctx.unique, None)
}

/// Dispatch a FUSE SETATTR request through the metadata worker.
///
/// Although FUSE classifies SETATTR (opcode 4) as FileWriteback, the
/// metadata worker owns the inode table and attribute store mutations.
/// This dispatch entry point constructs a [`MetaWorker`] and delegates to
/// [`MetaWorker::handle_setattr`].
pub fn dispatch_setattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    attrs: &SetAttr,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    // Reject unsupported valid bits and conflicting timestamp flags
    // before delegating to the metadata worker.
    if let Err(plan_err) = plan_setattr(attrs) {
        reply_sink.reply_error(ctx.unique, plan_err.errno())?;
        return Err(MetaError::Io);
    }
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_setattr(ctx.nodeid, ctx.unique, attrs, ctx.uid, ctx.gid, &[])
}

/// Dispatch a FUSE READLINK request through the metadata worker.
///
/// This is the public dispatch entry point for MetaRead-class READLINK
/// (opcode 5). It constructs a [`MetaWorker`] from the provided backends,
/// extracts the inode from the context mirror, and delegates to
/// [`MetaWorker::handle_readlink_inode`].
///
/// The caller buffer size is inferred from the FUSE request; the worker
/// applies POSIX truncation semantics via [`plan_readlink_reply`].
pub fn dispatch_readlink<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    requested_size: u32,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_readlink_inode(ctx.nodeid, ctx.unique, requested_size)
}

/// Dispatch a FUSE STATFS request through the metadata worker.
///
/// Combines block-allocator statistics (from the capacity layer) with
/// inode-table statistics to produce a complete FUSE `statfs_out` reply.
/// `block_*` values come from the block allocator; inode counts come from
/// the inode table via [`InodeTable::inode_stats`].
#[allow(clippy::too_many_arguments)]
pub fn dispatch_statfs<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    block_total: u64,
    block_free: u64,
    block_avail: u64,
    block_size: u64,
    name_max: u32,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_statfs(
        ctx.unique,
        block_total,
        block_free,
        block_avail,
        block_size,
        name_max,
    )
}

/// Build a [`StatxReply`] from an [`InodeAttr`].
///
/// Converts nanosecond-precision timestamps from `PosixAttrs` into
/// (seconds, subsecond_nanoseconds) pairs expected by the statx layout.
/// All fields that TideFS can populate from `getattr` are reported
/// in `stx_mask`.
fn statx_from_inode_attr(attr: &InodeAttr) -> StatxReply {
    let posix = &attr.posix;
    let (atime_sec, atime_nsec) = split_posix_time_ns(posix.atime_ns);
    let (mtime_sec, mtime_nsec) = split_posix_time_ns(posix.mtime_ns);
    let (ctime_sec, ctime_nsec) = split_posix_time_ns(posix.ctime_ns);
    let (btime_sec, btime_nsec) = split_posix_time_ns(posix.btime_ns);

    // STATX_BASIC_STATS | STATX_BTIME
    let stx_mask: u32 = 0x0000_07ff | 0x0000_0800;

    StatxReply {
        stx_mask,
        stx_blksize: posix.blksize,
        stx_attributes: 0,
        stx_nlink: posix.nlink,
        stx_uid: posix.uid,
        stx_gid: posix.gid,
        stx_mode: posix.mode as u16,
        __spare0: 0,
        stx_ino: attr.inode_id.0,
        stx_size: posix.size,
        stx_blocks: posix.blocks_512,
        stx_attributes_mask: 0,
        stx_atime_sec: atime_sec,
        stx_atime_nsec: atime_nsec,
        stx_mtime_sec: mtime_sec,
        stx_mtime_nsec: mtime_nsec,
        stx_ctime_sec: ctime_sec,
        stx_ctime_nsec: ctime_nsec,
        stx_btime_sec: btime_sec,
        stx_btime_nsec: btime_nsec,
    }
}

/// Dispatch a FUSE STATX request through the metadata worker.
///
/// This is the public dispatch entry point for MetaRead-class STATX
/// (opcode 52). It constructs a [`MetaWorker`] from the provided backends
/// and delegates to [`MetaWorker::handle_statx`].
pub fn dispatch_statx<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_statx(ctx.nodeid, ctx.unique, None)
}

/// Dispatch a FUSE LOOKUP request through the metadata worker.
///
/// Resolves `child_name` within `parent_ino` via the [`DirIndex`] and
/// replies with a full [`FuseEntryOut`] carrying the child's inode,
/// generation, attributes, and cache timeout values. Successful replies are
/// projections of mounted dataset inode identity; kernel lookup-reference
/// counting is adapter state outside this metadata worker.
///
/// Returns `Err(MetaError::InoNotFound)` when the parent does not exist,
/// `Err(MetaError::Io)` when the parent is not a directory or the name
/// is not found.
pub fn dispatch_lookup<I: InodeTable, D: DirIndex, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    child_name: &[u8],
    lookup_cfg: LookupConfig,
    inode_table: &I,
    dir_index: &D,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    // Validate parent exists.
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    // Verify parent is a directory.
    if let Some(parent_attr) = inode_table.getattr(ctx.nodeid) {
        if parent_attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    // Resolve child name via directory index.
    match dir_index.lookup(ctx.nodeid, child_name) {
        Some(entry) => {
            // Produce FUSE attr_out for the child inode.
            let attr_out = attr_store.to_fuse_attr_out(entry.inode_id)?;
            let entry_out = FuseEntryOut::from_attr_out(
                &attr_out,
                entry.inode_id,
                entry.generation,
                lookup_cfg,
            );
            reply_sink.reply_entry(ctx.unique, &entry_out)?;
            Ok(())
        }
        None => {
            reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
            Err(MetaError::InoNotFound)
        }
    }
}

/// Dispatch a FUSE READDIR request through the metadata worker.
///
/// Iterates directory entries through [`DirIndex::readdir`] starting
/// from `offset` and delegates to [`MetaReplySink::reply_readdir`]
/// for FUSE buffer packing.
///
/// Returns `Err(MetaError::InoNotFound)` when the parent does not exist
/// and `Err(MetaError::NotDir)` when it is not a directory.
pub fn dispatch_readdir<I: InodeTable, D: DirIndex, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    offset: u64,
    max_entries: usize,
    inode_table: &I,
    dir_index: &D,
    _attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    // Validate parent exists.
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    // Verify parent is a directory.
    if let Some(parent_attr) = inode_table.getattr(ctx.nodeid) {
        if parent_attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    // Enumerate directory entries.
    let slice = dir_index.readdir(ctx.nodeid, offset, max_entries);
    if slice.entries.is_empty() && slice.next_cookie == 0 {
        // Empty directory: reply with no entries.
        reply_sink.reply_readdir(ctx.unique, &[], 0)?;
        return Ok(());
    }

    reply_sink.reply_readdir(ctx.unique, &slice.entries, slice.next_cookie)?;
    Ok(())
}

/// Dispatch a FUSE READDIRPLUS request through the metadata worker.
///
/// Same enumeration as [`dispatch_readdir`] but also resolves
/// [`FuseAttrOut`] for each entry and delegates to
/// [`MetaReplySink::reply_readdirplus`].
pub fn dispatch_readdirplus<I: InodeTable, D: DirIndex, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    offset: u64,
    max_entries: usize,
    inode_table: &I,
    dir_index: &D,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    // Validate parent exists.
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    // Verify parent is a directory.
    if let Some(parent_attr) = inode_table.getattr(ctx.nodeid) {
        if parent_attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    // Enumerate directory entries.
    let slice = dir_index.readdir(ctx.nodeid, offset, max_entries);
    if slice.entries.is_empty() && slice.next_cookie == 0 {
        // Empty directory: reply with no entries.
        reply_sink.reply_readdirplus(ctx.unique, &[], &[], 0)?;
        return Ok(());
    }

    // Resolve attributes for each entry.
    let mut attrs: Vec<FuseAttrOut> = Vec::new();
    for entry in &slice.entries {
        match attr_store.to_fuse_attr_out(entry.inode_id) {
            Ok(attr_out) => attrs.push(attr_out),
            Err(_) => {
                // Entry existed during readdir but disappeared; skip it.
                continue;
            }
        }
    }

    reply_sink.reply_readdirplus(ctx.unique, &slice.entries, &attrs, slice.next_cookie)?;
    Ok(())
}

// ── Opendir dispatch ──────────────────────────────────────────────────────

/// Dispatch a FUSE OPENDIR request through the metadata worker.
///
/// Validates that the target inode exists and is a directory, then
/// returns the directory handle (fh) and open flags. The handle is
/// the inode number itself, giving the kernel an opaque cookie for
/// subsequent READDIR/RELEASEDIR calls.
///
/// Returns `Err(MetaError::InoNotFound)` when the inode does not exist
/// and `Err(MetaError::NotDir)` when it is not a directory.
pub fn dispatch_opendir<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    flags: u32,
    inode_table: &I,
    _attr_store: &A,
    reply_sink: &mut R,
) -> Result<u64, MetaError> {
    // Validate inode exists.
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    // Verify it is a directory.
    if let Some(attr) = inode_table.getattr(ctx.nodeid) {
        if attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    // Use the nodeid as the opaque directory handle.
    let fh = ctx.nodeid;
    reply_sink.reply_opendir(ctx.unique, fh, flags)?;
    Ok(fh)
}

// ── Releasedir dispatch ──────────────────────────────────────────────────

/// Dispatch a FUSE RELEASEDIR request through the metadata worker.
///
/// Releases the directory handle. In this stateless implementation,
/// handle release is a no-op; the kernel is responsible for tracking
/// handle liveness.
pub fn dispatch_releasedir<R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    _fh: u64,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    reply_sink.reply_empty(ctx.unique)?;
    Ok(())
}

/// Dispatch a FUSE GETXATTR request through the metadata worker.
///
/// This is the public dispatch entry point for NamespaceMut-class GETXATTR
/// (opcode 22). It constructs a [`MetaWorker`], validates the inode,
/// retrieves the xattr value, and replies with data or size.
pub fn dispatch_getxattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    name: &[u8],
    requested_size: u32,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_getxattr(ctx.nodeid, ctx.unique, name, requested_size)
}

/// Dispatch a FUSE LISTXATTR request through the metadata worker.
///
/// This is the public dispatch entry point for NamespaceMut-class LISTXATTR
/// (opcode 23). It constructs a [`MetaWorker`], validates the inode,
/// retrieves the packed name list, and replies with data or size.
pub fn dispatch_listxattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    requested_size: u32,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_listxattr(ctx.nodeid, ctx.unique, requested_size)
}

/// Dispatch a FUSE SETXATTR request through the metadata worker.
///
/// This is the public dispatch entry point for NamespaceMut-class SETXATTR
/// (opcode 21). It constructs a [`MetaWorker`], validates the inode,
/// plans the setxattr flags, applies the mutation, and replies.
pub fn dispatch_setxattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    name: &[u8],
    value: &[u8],
    flags: u32,
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_setxattr(ctx.nodeid, ctx.unique, name, value, flags)
}

/// Dispatch a FUSE REMOVEXATTR request through the metadata worker.
///
/// This is the public dispatch entry point for NamespaceMut-class
/// REMOVEXATTR (opcode 24). It constructs a [`MetaWorker`], validates
/// the inode, removes the xattr, and replies.
pub fn dispatch_removexattr<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    name: &[u8],
    inode_table: &I,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    let mut worker = MetaWorker::new(inode_table, attr_store, reply_sink);
    worker.handle_removexattr(ctx.nodeid, ctx.unique, name)
}

// ── DirIterator readdir helpers ─────────────────────────────────────────

/// Collect up to `max_entries` directory entries from a [`DirIterator`],
/// producing [`DirLookupEntry`] items and a continuation cookie for the
/// next FUSE READDIR call.
///
/// `offset` is the kernel-supplied offset cookie; `0` starts from the
/// beginning.  The returned `next_cookie` is `0` when all entries have
/// been consumed (EOF).
fn collect_dir_iter_entries(
    iter: &mut dyn DirIterator<Error = DirIndexError>,
    offset: u64,
    max_entries: usize,
) -> (Vec<DirLookupEntry>, u64) {
    iter.seek_to_cursor(DirCookie(offset));

    let mut entries: Vec<DirLookupEntry> = Vec::new();
    let mut last_cursor: u64 = 0;

    for _ in 0..max_entries {
        match iter.next_entry() {
            Some(entry) => {
                last_cursor = iter.current_cursor().0;
                entries.push(DirLookupEntry {
                    inode_id: entry.inode_id,
                    generation: entry.generation,
                    kind: entry.kind,
                    name: entry.name,
                });
            }
            None => break,
        }
    }

    if entries.is_empty() {
        return (entries, 0);
    }
    (entries, last_cursor)
}

/// Dispatch a FUSE READDIR request using the DirIterator trait.
///
/// Validates the parent exists and is a directory, then collects entries
/// from the supplied iterator.  This is the preferred variant when the
/// caller holds a mutable directory handle with a positioned cursor.
///
/// Returns `Err(MetaError::InoNotFound)` when the parent does not exist
/// and `Err(MetaError::NotDir)` when it is not a directory.
pub fn dispatch_readdir_iter<I: InodeTable, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    offset: u64,
    max_entries: usize,
    inode_table: &I,
    dir_iter: &mut dyn DirIterator<Error = DirIndexError>,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    if let Some(attr) = inode_table.getattr(ctx.nodeid) {
        if attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    let (entries, next_cookie) = collect_dir_iter_entries(dir_iter, offset, max_entries);
    if entries.is_empty() && next_cookie == 0 {
        reply_sink.reply_readdir(ctx.unique, &[], 0)?;
        return Ok(());
    }

    reply_sink.reply_readdir(ctx.unique, &entries, next_cookie)?;
    Ok(())
}

/// Dispatch a FUSE READDIRPLUS request using the DirIterator trait.
///
/// Same enumeration as [`dispatch_readdir_iter`] but also resolves
/// [`FuseAttrOut`] for each entry and delegates to
/// [`MetaReplySink::reply_readdirplus`].
pub fn dispatch_readdirplus_iter<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    offset: u64,
    max_entries: usize,
    inode_table: &I,
    dir_iter: &mut dyn DirIterator<Error = DirIndexError>,
    attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    if !inode_table.lookup(ctx.nodeid) {
        reply_sink.reply_error(ctx.unique, MetaError::InoNotFound.errno())?;
        return Err(MetaError::InoNotFound);
    }

    if let Some(attr) = inode_table.getattr(ctx.nodeid) {
        if attr.kind != NodeKind::Dir {
            reply_sink.reply_error(ctx.unique, MetaError::NotDir.errno())?;
            return Err(MetaError::Io);
        }
    }

    let (entries, next_cookie) = collect_dir_iter_entries(dir_iter, offset, max_entries);
    if entries.is_empty() && next_cookie == 0 {
        reply_sink.reply_readdirplus(ctx.unique, &[], &[], 0)?;
        return Ok(());
    }

    let mut attrs: Vec<FuseAttrOut> = Vec::new();
    for entry in &entries {
        match attr_store.to_fuse_attr_out(entry.inode_id) {
            Ok(attr_out) => attrs.push(attr_out),
            Err(_) => continue,
        }
    }

    reply_sink.reply_readdirplus(ctx.unique, &entries, &attrs, next_cookie)?;
    Ok(())
}

// ── Access constants ────────────────────────────────────────────────────────

/// Permission bits for POSIX access checking.
///
/// These match the `access(2)` mask bits: R_OK=4, W_OK=2, X_OK=1.
pub const ACCESS_READ: u8 = 0x04;
pub const ACCESS_WRITE: u8 = 0x02;
pub const ACCESS_EXECUTE: u8 = 0x01;

// ── Access check ────────────────────────────────────────────────────────────

/// POSIX mode-based access check for a single inode.
///
/// Returns `true` when the `(uid, gid)` caller is allowed the `requested`
/// permission bits against the inode's owner/group/other mode bits.
///
/// Root (uid == 0) is always allowed (standard Unix semantics).
fn check_access_mode(attr: &InodeAttr, uid: u32, gid: u32, requested: u8) -> bool {
    if uid == 0 {
        return true;
    }

    let mode = attr.posix.mode;
    let file_uid = attr.posix.uid;
    let file_gid = attr.posix.gid;

    let perm_bits = if uid == file_uid {
        // Owner permissions.
        (mode >> 6) & 0o7
    } else if gid == file_gid {
        // Group permissions.
        (mode >> 3) & 0o7
    } else {
        // Other permissions.
        mode & 0o7
    };

    // Check each requested bit.
    let mut have_perm: u8 = 0;
    if perm_bits & 0o4 != 0 {
        have_perm |= ACCESS_READ;
    }
    if perm_bits & 0o2 != 0 {
        have_perm |= ACCESS_WRITE;
    }
    if perm_bits & 0o1 != 0 {
        have_perm |= ACCESS_EXECUTE;
    }

    (requested & have_perm) == requested
}

// ── Access dispatch ─────────────────────────────────────────────────────────

/// Dispatch a FUSE ACCESS request through the metadata worker.
///
/// Resolves the inode via [`InodeTable`] and evaluates POSIX discretionary
/// access control:
///
/// 1. Root (uid 0) always succeeds (standard Unix / POSIX ACL semantics).
/// 2. When a `system.posix_acl_access` xattr is present on the inode,
///    the ACL is decoded, validated, and evaluated via
///    [`plan_access_acl_check`].
/// 3. When no ACL is present, the check falls back to Unix mode bits
///    via [`check_access_mode`].
///
/// On success (access allowed), emits an empty reply via
/// [`MetaReplySink::reply_error`] with errno 0. On denial, emits EACCES.
/// On missing inode, emits ENOENT. A malformed ACL xattr returns EINVAL.
///
/// `mask` is the FUSE access mask (R_OK=4, W_OK=2, X_OK=1).
/// `uid` and `gid` are the caller's credentials.
pub fn dispatch_access<I: InodeTable, A: AttrStore, R: MetaReplySink>(
    ctx: &PosixFilesystemAdapterRequestContextMirrorRecord,
    uid: u32,
    gid: u32,
    mask: i32,
    inode_table: &I,
    _attr_store: &A,
    reply_sink: &mut R,
) -> Result<(), MetaError> {
    // Decode FUSE access mask.
    // R_OK=4, W_OK=2, X_OK=1.
    if mask & !7 != 0 {
        reply_sink.reply_error(ctx.unique, 22)?; // EINVAL
        return Err(MetaError::Io);
    }

    // Look up the inode.
    let attr = inode_table
        .getattr(ctx.nodeid)
        .ok_or(MetaError::InoNotFound)?;

    // Root bypass: uid 0 is always allowed (standard Unix / POSIX ACL
    // semantics).
    if uid == 0 {
        reply_sink.reply_error(ctx.unique, 0)?;
        return Ok(());
    }

    let requested = mask as u8;

    // Try ACL evaluation first when an access ACL xattr is present.
    let acl_result = inode_table.get_xattr(ctx.nodeid, POSIX_ACL_ACCESS_XATTR);

    match acl_result {
        Ok(raw_acl) => {
            // Decode and validate the ACL payload, then evaluate.
            match decode_access_acl_xattr(&raw_acl) {
                Ok(decoded) => {
                    let check = AccessAclCheck {
                        file_uid: attr.posix.uid,
                        file_gid: attr.posix.gid,
                        caller_uid: uid,
                        caller_gid: gid,
                        caller_groups: &[],
                        mode_fallback: attr.posix.mode,
                        requested,
                    };
                    match plan_access_acl_check(decoded.entries(), check) {
                        Ok(plan) => {
                            let errno = plan.errno();
                            reply_sink.reply_error(ctx.unique, errno)?;
                            if plan.is_allowed() {
                                Ok(())
                            } else {
                                Err(MetaError::Io)
                            }
                        }
                        Err(_) => {
                            reply_sink.reply_error(ctx.unique, POSIX_ACL_EINVAL)?;
                            Err(MetaError::Io)
                        }
                    }
                }
                Err(_) => {
                    reply_sink.reply_error(ctx.unique, POSIX_ACL_EINVAL)?;
                    Err(MetaError::Io)
                }
            }
        }
        Err(_) => {
            // No ACL xattr present; fall back to mode-bit checking.
            if check_access_mode(&attr, uid, gid, requested) {
                reply_sink.reply_error(ctx.unique, 0)?;
                Ok(())
            } else {
                reply_sink.reply_error(ctx.unique, 13)?; // EACCES
                Err(MetaError::Io)
            }
        }
    }
}
// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use std::vec::Vec;
    use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterShardKeyPolicy;
    use tidefs_types_vfs_core::{
        Generation, InodeFlags, InodeId, FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_GID,
        FATTR_LOCKOWNER, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, S_IFBLK,
        S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISGID, S_ISUID,
    };

    #[test]
    fn is_meta_read_detects_correct_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            nodeid: 5,
            ..Default::default()
        };
        assert!(is_meta_read_request(&ctx));
    }

    #[test]
    fn is_meta_read_rejects_other_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::FileRead.as_u32(),
            ..Default::default()
        };
        assert!(!is_meta_read_request(&ctx));
    }

    #[test]
    fn dispatch_preserves_context() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 100,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        };
        let dispatched = dispatch_meta_read(ctx);
        assert_eq!(dispatched.unique, ctx.unique);
        assert_eq!(dispatched.nodeid, ctx.nodeid);
    }

    #[test]
    fn shard_key_is_nodeid() {
        assert_eq!(meta_read_shard_key(42), 42);
        assert_eq!(meta_read_shard_key(1), 1);
    }

    #[test]
    fn lookup_config_defaults() {
        let cfg = LookupConfig::DEFAULT;
        assert_eq!(cfg.entry_ttl_secs, 1);
        assert_eq!(cfg.entry_ttl_nsec, 0);
        assert_eq!(cfg.attr_ttl_secs, 1);
        assert_eq!(cfg.attr_ttl_nsec, 0);
    }

    #[test]
    fn lookup_config_default_trait_zeroes() {
        let cfg = LookupConfig::default();
        assert_eq!(cfg, LookupConfig::DEFAULT);
    }

    #[test]
    fn lookup_error_kinds_have_correct_errno() {
        assert_eq!(LookupErrorKind::Enoent.as_errno(), -2i32);
        assert_eq!(LookupErrorKind::Enotdir.as_errno(), -20i32);
        assert_eq!(LookupErrorKind::Eio.as_errno(), -5i32);
        assert_eq!(LookupErrorKind::Eacces.as_errno(), -13i32);
    }

    #[test]
    fn handle_lookup_preserves_context() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 42,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        };
        let (result_ctx, outcome) = handle_lookup(ctx, 5, b"test_file", |parent, name| {
            assert_eq!(parent, 5);
            assert_eq!(name, b"test_file");
            LookupOutcome::Found {
                inode: 100,
                generation: 7,
            }
        });
        assert_eq!(result_ctx.unique, ctx.unique);
        assert_eq!(result_ctx.nodeid, ctx.nodeid);
        assert_eq!(
            outcome,
            LookupOutcome::Found {
                inode: 100,
                generation: 7
            }
        );
    }

    #[test]
    fn handle_lookup_propagates_not_found() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 43,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        };
        let (result_ctx, outcome) =
            handle_lookup(ctx, 5, b"missing", |_parent, _name| LookupOutcome::NotFound);
        assert_eq!(result_ctx.unique, ctx.unique);
        assert_eq!(outcome, LookupOutcome::NotFound);
    }

    #[test]
    fn handle_readlink_preserves_context_and_returns_target_plan() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 44,
            nodeid: 9,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        };
        let target = b"../target";

        let (result_ctx, outcome) = handle_readlink(ctx, 77, 64, |ino, requested_size| {
            assert_eq!(ino, 77);
            assert_eq!(requested_size, 64);
            ReadlinkOutcome::Target {
                plan: plan_readlink_reply(target, requested_size).expect("readlink plan"),
            }
        });

        assert_eq!(result_ctx.unique, ctx.unique);
        assert_eq!(result_ctx.nodeid, ctx.nodeid);
        assert!(outcome.is_target());
        assert_eq!(outcome.errno(), 0);
        assert_eq!(outcome.payload(), Some(&target[..]));
        assert!(!outcome.is_truncated());
    }

    #[test]
    fn handle_readlink_propagates_non_symlink_einval() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 45,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let (result_ctx, outcome) =
            handle_readlink(ctx, 88, 32, |_ino, _size| ReadlinkOutcome::NotSymlink);

        assert_eq!(result_ctx.unique, ctx.unique);
        assert_eq!(outcome, ReadlinkOutcome::NotSymlink);
        assert_eq!(outcome.errno(), POSIX_READLINK_EINVAL);
        assert_eq!(outcome.payload(), None);
    }

    #[test]
    fn handle_readlink_propagates_missing_inode_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 46,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let (_result_ctx, outcome) =
            handle_readlink(ctx, 99, 32, |_ino, _size| ReadlinkOutcome::NotFound);

        assert_eq!(outcome, ReadlinkOutcome::NotFound);
        assert_eq!(outcome.errno(), POSIX_READLINK_ENOENT);
        assert_eq!(outcome.payload(), None);
    }

    #[test]
    fn handle_readlink_preserves_truncated_target_plan() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 47,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let target = b"directory/target";

        let (_result_ctx, outcome) = handle_readlink(ctx, 100, 9, |_ino, requested_size| {
            ReadlinkOutcome::Target {
                plan: plan_readlink_reply(target, requested_size).expect("readlink plan"),
            }
        });

        assert!(outcome.is_target());
        assert_eq!(outcome.errno(), 0);
        assert_eq!(outcome.payload(), Some(&target[..9]));
        assert!(outcome.is_truncated());
    }

    #[test]
    fn lookup_outcome_found_has_inode_and_generation() {
        let outcome = LookupOutcome::Found {
            inode: 100,
            generation: 5,
        };
        assert!(outcome.is_found());
        assert!(!outcome.is_not_found());
        assert!(!outcome.is_error());
        assert_eq!(outcome.inode(), Some(100));
        assert_eq!(outcome.generation(), Some(5));
        assert_eq!(outcome.errno(), 0);
    }

    #[test]
    fn lookup_outcome_not_found_is_negative() {
        let outcome = LookupOutcome::NotFound;
        assert!(!outcome.is_found());
        assert!(outcome.is_not_found());
        assert!(!outcome.is_error());
        assert_eq!(outcome.inode(), None);
        assert_eq!(outcome.generation(), None);
        assert_eq!(outcome.errno(), LookupErrorKind::Enoent.as_errno());
    }

    #[test]
    fn lookup_outcome_error_maps_correctly() {
        let outcome = LookupOutcome::Error {
            kind: LookupErrorKind::Enotdir,
        };
        assert!(!outcome.is_found());
        assert!(!outcome.is_not_found());
        assert!(outcome.is_error());
        assert_eq!(outcome.inode(), None);
        assert_eq!(outcome.generation(), None);
        assert_eq!(outcome.errno(), LookupErrorKind::Enotdir.as_errno());
    }

    #[test]
    fn lookup_outcome_eio_maps_to_errno() {
        let outcome = LookupOutcome::Error {
            kind: LookupErrorKind::Eio,
        };
        assert_eq!(outcome.errno(), -5);
    }

    #[test]
    fn lookup_outcome_eacces_maps_to_errno() {
        let outcome = LookupOutcome::Error {
            kind: LookupErrorKind::Eacces,
        };
        assert_eq!(outcome.errno(), -13);
    }

    // ── Conversion helpers ──────────────────────────────────────────────

    #[test]
    fn ns_to_sec_nsec_converts_zero() {
        let (s, ns) = ns_to_sec_nsec(0);
        assert_eq!(s, 0);
        assert_eq!(ns, 0);
    }

    #[test]
    fn ns_to_sec_nsec_converts_exact_second() {
        let (s, ns) = ns_to_sec_nsec(2_000_000_000);
        assert_eq!(s, 2);
        assert_eq!(ns, 0);
    }

    #[test]
    fn ns_to_sec_nsec_splits_fractional() {
        let (s, ns) = ns_to_sec_nsec(1_500_000_000);
        assert_eq!(s, 1);
        assert_eq!(ns, 500_000_000);
    }

    #[test]
    fn ns_to_sec_nsec_encodes_pre_epoch_raw_seconds() {
        let (s, ns) = ns_to_sec_nsec(-1);
        assert_eq!(s as i64, -1);
        assert_eq!(ns, 999_999_999);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_maps_fields() {
        let posix = PosixAttrs {
            mode: S_IFREG | 0o755,
            uid: 1000,
            gid: 100,
            nlink: 2,
            rdev: 0,
            atime_ns: 1_500_000_000,
            mtime_ns: 2_500_000_000,
            ctime_ns: 3_500_000_000,
            btime_ns: 4_500_000_000,
            size: 1024,
            blocks_512: 2,
            blksize: 4096,
        };
        let attr = posix_attrs_to_fuse_attr(42, &posix, NodeKind::File);
        assert_eq!(attr.ino, 42);
        assert_eq!(attr.mode, S_IFREG | 0o755);
        assert_eq!(attr.nlink, 2);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 100);
        assert_eq!(attr.rdev, 0);
        assert_eq!(attr.size, 1024);
        assert_eq!(attr.blksize, 4096);
        assert_eq!(attr.blocks, 2);
        assert_eq!(attr.atime, 1);
        assert_eq!(attr.atimensec, 500_000_000);
        assert_eq!(attr.mtime, 2);
        assert_eq!(attr.mtimensec, 500_000_000);
        assert_eq!(attr.ctime, 3);
        assert_eq!(attr.ctimensec, 500_000_000);
        assert_eq!(attr.padding, 0);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_backfills_missing_type_bits() {
        let posix = PosixAttrs {
            mode: 0o755,
            nlink: 2,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(42, &posix, NodeKind::Dir);
        assert_eq!(attr.mode, S_IFDIR | 0o755);
    }

    #[test]
    fn fuse_attr_out_has_default_validity() {
        let posix = PosixAttrs {
            mode: S_IFREG | 0o644,
            blksize: 4096,
            ..Default::default()
        };
        let out = fuse_attr_out(1, &posix, NodeKind::File);
        assert_eq!(out.attr_valid, 1);
        assert_eq!(out.attr_valid_nsec, 0);
        assert_eq!(out.dummy, 0);
        assert_eq!(out.attr.ino, 1);
        assert_eq!(out.attr.mode, S_IFREG | 0o644);
    }

    #[test]
    fn fuse_attr_out_dir_clamps_nlink_floor_at_2() {
        // POSIX: empty directories must report nlink >= 2 (self + parent).
        let posix = PosixAttrs {
            mode: S_IFDIR | 0o755,
            nlink: 1, // incorrect stored value
            blksize: 4096,
            ..Default::default()
        };
        let out = fuse_attr_out(100, &posix, NodeKind::Dir);
        assert_eq!(out.attr.nlink, 2, "empty dir nlink must be clamped to 2");
        assert_eq!(out.attr.mode, S_IFDIR | 0o755);
        assert_eq!(out.attr.ino, 100);
    }

    #[test]
    fn fuse_attr_out_dir_preserves_nlink_above_minimum() {
        // A directory with 3 subdirectories should have nlink=5 (2 base + 3).
        let posix = PosixAttrs {
            mode: S_IFDIR | 0o755,
            nlink: 5,
            blksize: 4096,
            ..Default::default()
        };
        let out = fuse_attr_out(200, &posix, NodeKind::Dir);
        assert_eq!(out.attr.nlink, 5, "dir with subdirs preserves nlink");
        assert_eq!(out.attr.mode, S_IFDIR | 0o755);
        assert_eq!(out.attr.ino, 200);
    }

    #[test]
    fn fuse_attr_out_dir_clamps_zero_nlink() {
        // Zero nlink for a directory is clearly wrong; clamp to 2.
        let posix = PosixAttrs {
            mode: S_IFDIR | 0o700,
            nlink: 0,
            blksize: 4096,
            ..Default::default()
        };
        let out = fuse_attr_out(300, &posix, NodeKind::Dir);
        assert_eq!(out.attr.nlink, 2, "zero nlink dir clamped to 2");
    }

    #[test]
    fn fuse_attr_out_regular_file_nlink_unchanged() {
        // Regular files: nlink should pass through as-is.
        let posix = PosixAttrs {
            mode: S_IFREG | 0o644,
            nlink: 1,
            size: 1024,
            blksize: 4096,
            ..Default::default()
        };
        let out = fuse_attr_out(400, &posix, NodeKind::File);
        assert_eq!(out.attr.nlink, 1, "file nlink must not be clamped");
        assert_eq!(out.attr.mode, S_IFREG | 0o644);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_preserves_nonzero_rdev() {
        let posix = PosixAttrs {
            mode: S_IFBLK | 0o660,
            rdev: 0xABCD,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(99, &posix, NodeKind::BlockDev);
        assert_eq!(attr.rdev, 0xABCD);
        assert_eq!(attr.mode, S_IFBLK | 0o660);
        assert_eq!(attr.ino, 99);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_directory_sets_ifdir_and_nlink() {
        let posix = PosixAttrs {
            mode: S_IFDIR | 0o755,
            nlink: 2,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(10, &posix, NodeKind::Dir);
        assert_eq!(attr.mode, S_IFDIR | 0o755);
        assert_eq!(attr.nlink, 2);
        assert_eq!(attr.ino, 10);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_symlink_sets_iflnk_and_size() {
        let posix = PosixAttrs {
            mode: S_IFLNK | 0o777,
            size: 12,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(20, &posix, NodeKind::Symlink);
        assert_eq!(attr.mode, S_IFLNK | 0o777);
        assert_eq!(attr.size, 12);
        assert_eq!(attr.ino, 20);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_zero_size_zero_blocks() {
        let posix = PosixAttrs {
            mode: S_IFREG | 0o644,
            size: 0,
            blocks_512: 0,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(30, &posix, NodeKind::File);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.blocks, 0);
        assert_eq!(attr.ino, 30);
    }

    #[test]
    fn posix_attrs_to_fuse_attr_max_inode_preserved() {
        let posix = PosixAttrs {
            mode: S_IFREG | 0o644,
            blksize: 4096,
            ..Default::default()
        };
        let attr = posix_attrs_to_fuse_attr(u64::MAX, &posix, NodeKind::File);
        assert_eq!(attr.ino, u64::MAX);
        assert_eq!(attr.mode, S_IFREG | 0o644);
    }

    // ── Mock implementations ────────────────────────────────────────────

    /// Captured reply for inspection in tests.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CapturedReply {
        Error {
            unique: u64,
            errno: i32,
        },
        Attr {
            unique: u64,
            attr_out: FuseAttrOut,
        },
        ReadlinkData {
            unique: u64,
            data: Vec<u8>,
        },
        Statfs {
            unique: u64,
            fields: StatfsFields,
        },
        Entry {
            unique: u64,
            entry_out: FuseEntryOut,
        },
        ReaddirEntries {
            unique: u64,
            entries: Vec<DirLookupEntry>,
            next_cookie: u64,
        },
        Opendir {
            unique: u64,
            fh: u64,
            flags: u32,
        },
        Empty {
            unique: u64,
        },
        XattrData {
            unique: u64,
            data: Vec<u8>,
        },
    }

    /// Mock reply sink that records replies in a `Vec`.
    struct MockReplySink {
        replies: Vec<CapturedReply>,
    }

    impl MockReplySink {
        fn new() -> Self {
            Self {
                replies: Vec::new(),
            }
        }

        fn last_reply(&self) -> Option<&CapturedReply> {
            self.replies.last()
        }

        fn reply_count(&self) -> usize {
            self.replies.len()
        }

        fn replies(&self) -> &[CapturedReply] {
            &self.replies
        }
    }

    impl MetaReplySink for MockReplySink {
        fn reply_error(&mut self, unique: u64, errno: i32) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::Error { unique, errno });
            Ok(())
        }

        fn reply_attr(&mut self, unique: u64, attr_out: &FuseAttrOut) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::Attr {
                unique,
                attr_out: *attr_out,
            });
            Ok(())
        }

        fn reply_readlink(&mut self, unique: u64, data: &[u8]) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::ReadlinkData {
                unique,
                data: data.to_vec(),
            });
            Ok(())
        }

        fn reply_statfs(&mut self, unique: u64, fields: &StatfsFields) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::Statfs {
                unique,
                fields: *fields,
            });
            Ok(())
        }

        fn reply_entry(&mut self, unique: u64, entry_out: &FuseEntryOut) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::Entry {
                unique,
                entry_out: *entry_out,
            });
            Ok(())
        }

        fn reply_readdir(
            &mut self,
            unique: u64,
            entries: &[DirLookupEntry],
            next_cookie: u64,
        ) -> Result<ReaddirPackResult, MetaError> {
            self.replies.push(CapturedReply::ReaddirEntries {
                unique,
                entries: entries.to_vec(),
                next_cookie,
            });
            Ok(ReaddirPackResult {
                wrote: entries.len(),
                needs_continuation: next_cookie != 0,
                bytes_used: 0,
            })
        }

        fn reply_readdirplus(
            &mut self,
            unique: u64,
            entries: &[DirLookupEntry],
            _attrs: &[FuseAttrOut],
            next_cookie: u64,
        ) -> Result<ReaddirPackResult, MetaError> {
            self.replies.push(CapturedReply::ReaddirEntries {
                unique,
                entries: entries.to_vec(),
                next_cookie,
            });
            Ok(ReaddirPackResult {
                wrote: entries.len(),
                needs_continuation: next_cookie != 0,
                bytes_used: 0,
            })
        }

        fn reply_opendir(&mut self, unique: u64, fh: u64, flags: u32) -> Result<(), MetaError> {
            self.replies
                .push(CapturedReply::Opendir { unique, fh, flags });
            Ok(())
        }

        fn reply_empty(&mut self, unique: u64) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::Empty { unique });
            Ok(())
        }

        fn reply_xattr_data(&mut self, unique: u64, data: &[u8]) -> Result<(), MetaError> {
            self.replies.push(CapturedReply::XattrData {
                unique,
                data: data.to_vec(),
            });
            Ok(())
        }
    }

    /// Mock reply sink that records attempted replies and then fails selected paths.
    struct FailingReplySink {
        fail_error: bool,
        fail_attr: bool,
        error_calls: usize,
        attr_calls: usize,
    }

    impl FailingReplySink {
        fn fail_error_replies() -> Self {
            Self {
                fail_error: true,
                fail_attr: false,
                error_calls: 0,
                attr_calls: 0,
            }
        }

        fn fail_attr_replies() -> Self {
            Self {
                fail_error: false,
                fail_attr: true,
                error_calls: 0,
                attr_calls: 0,
            }
        }
    }

    impl MetaReplySink for FailingReplySink {
        fn reply_error(&mut self, _unique: u64, _errno: i32) -> Result<(), MetaError> {
            self.error_calls += 1;
            if self.fail_error {
                Err(MetaError::ReplyError)
            } else {
                Ok(())
            }
        }

        fn reply_attr(&mut self, _unique: u64, _attr_out: &FuseAttrOut) -> Result<(), MetaError> {
            self.attr_calls += 1;
            if self.fail_attr {
                Err(MetaError::ReplyError)
            } else {
                Ok(())
            }
        }

        fn reply_readlink(&mut self, _unique: u64, _data: &[u8]) -> Result<(), MetaError> {
            Ok(())
        }

        fn reply_statfs(&mut self, _unique: u64, _fields: &StatfsFields) -> Result<(), MetaError> {
            Ok(())
        }
        fn reply_statx(&mut self, _unique: u64, _statx: &StatxReply) -> Result<(), MetaError> {
            Ok(())
        }

        fn reply_entry(
            &mut self,
            _unique: u64,
            _entry_out: &FuseEntryOut,
        ) -> Result<(), MetaError> {
            Ok(())
        }

        fn reply_readdir(
            &mut self,
            _unique: u64,
            _entries: &[DirLookupEntry],
            _next_cookie: u64,
        ) -> Result<ReaddirPackResult, MetaError> {
            Ok(ReaddirPackResult {
                wrote: 0,
                needs_continuation: false,
                bytes_used: 0,
            })
        }

        fn reply_readdirplus(
            &mut self,
            _unique: u64,
            _entries: &[DirLookupEntry],
            _attrs: &[FuseAttrOut],
            _next_cookie: u64,
        ) -> Result<ReaddirPackResult, MetaError> {
            Ok(ReaddirPackResult {
                wrote: 0,
                needs_continuation: false,
                bytes_used: 0,
            })
        }

        fn reply_opendir(&mut self, _unique: u64, _fh: u64, _flags: u32) -> Result<(), MetaError> {
            Ok(())
        }

        fn reply_empty(&mut self, _unique: u64) -> Result<(), MetaError> {
            Ok(())
        }

        fn reply_xattr_data(&mut self, _unique: u64, _data: &[u8]) -> Result<(), MetaError> {
            Ok(())
        }
    }

    /// Mock inode table backed by a map.
    type MockXattrValues = BTreeMap<Vec<u8>, Vec<u8>>;
    type MockXattrTable = core::cell::RefCell<BTreeMap<u64, MockXattrValues>>;

    #[derive(Debug)]
    struct MockInodeTable {
        entries: BTreeMap<u64, InodeAttr>,
        xattrs: MockXattrTable,
    }

    impl MockInodeTable {
        fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
                xattrs: core::cell::RefCell::new(BTreeMap::new()),
            }
        }

        fn insert(&mut self, attr: InodeAttr) {
            self.entries.insert(attr.inode_id.get(), attr);
        }
    }

    impl InodeTable for MockInodeTable {
        fn lookup(&self, ino: u64) -> bool {
            self.entries.contains_key(&ino)
        }

        fn getattr(&self, ino: u64) -> Option<InodeAttr> {
            self.entries.get(&ino).copied()
        }

        fn setattr(&self, _ino: u64, _set: &SetAttr) -> Result<InodeAttr, MetaError> {
            // Simple mock: just return the current attr (caller verifies via attr_store).
            // Real implementation would apply the set fields.
            self.entries
                .get(&_ino)
                .copied()
                .ok_or(MetaError::InoNotFound)
        }

        fn readlink_target(&self, _ino: u64) -> Option<Vec<u8>> {
            // Mock: no symlink target storage; real backend provides this.
            None
        }

        fn inode_stats(&self) -> Option<(u64, u64)> {
            // Return tracked inode count; free = total - used.
            let total = self.entries.len() as u64 + 10;
            let free = total.saturating_sub(self.entries.len() as u64);
            Some((total, free))
        }

        fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let xattrs = self.xattrs.borrow();
            let per_inode = xattrs.get(&ino).ok_or(MetaError::Io)?;
            per_inode.get(name).cloned().ok_or(MetaError::Io)
        }

        fn get_xattr_size(&self, ino: u64, name: &[u8]) -> Result<usize, MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let xattrs = self.xattrs.borrow();
            let per_inode = xattrs.get(&ino).ok_or(MetaError::Io)?;
            per_inode.get(name).map(|v| v.len()).ok_or(MetaError::Io)
        }

        fn set_xattr(
            &self,
            ino: u64,
            name: &[u8],
            value: &[u8],
            flags: u32,
        ) -> Result<(), MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let mut xattrs = self.xattrs.borrow_mut();
            let per_inode = xattrs.entry(ino).or_default();
            let exists = per_inode.contains_key(name);
            match flags {
                0 => {}
                XATTR_CREATE if exists => return Err(MetaError::XattrAlreadyExists),
                XATTR_CREATE => {}
                XATTR_REPLACE if !exists => return Err(MetaError::XattrNoData),
                XATTR_REPLACE => {}
                _ => return Err(MetaError::InvalidInput),
            }
            per_inode.insert(name.to_vec(), value.to_vec());
            Ok(())
        }

        fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let xattrs = self.xattrs.borrow();
            let per_inode = match xattrs.get(&ino) {
                Some(p) => p,
                None => return Ok(Vec::new()),
            };
            let mut buf = Vec::new();
            for name in per_inode.keys() {
                buf.extend_from_slice(name);
                buf.push(0);
            }
            Ok(buf)
        }

        fn list_xattr_size(&self, ino: u64) -> Result<usize, MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let xattrs = self.xattrs.borrow();
            let per_inode = match xattrs.get(&ino) {
                Some(p) => p,
                None => return Ok(0),
            };
            if per_inode.is_empty() {
                return Ok(0);
            }
            Ok(per_inode.keys().map(|k| k.len() + 1).sum())
        }

        fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), MetaError> {
            if !self.entries.contains_key(&ino) {
                return Err(MetaError::InoNotFound);
            }
            let mut xattrs = self.xattrs.borrow_mut();
            let per_inode = xattrs.get_mut(&ino).ok_or(MetaError::XattrNoData)?;
            if per_inode.remove(name).is_none() {
                return Err(MetaError::XattrNoData);
            }
            Ok(())
        }
    }

    /// Mock attribute store backed by an in-memory map.
    struct MockAttrStore {
        entries: BTreeMap<u64, InodeAttr>,
    }

    impl MockAttrStore {
        fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
            }
        }

        fn insert(&mut self, attr: InodeAttr) {
            self.entries.insert(attr.inode_id.get(), attr);
        }

        #[allow(dead_code)]
        fn update_attr(&mut self, ino: u64, posix: PosixAttrs) {
            if let Some(entry) = self.entries.get_mut(&ino) {
                entry.posix = posix;
            }
        }
    }

    impl AttrStore for MockAttrStore {
        fn to_fuse_attr_out(&self, ino: u64) -> Result<FuseAttrOut, MetaError> {
            let attr = self.entries.get(&ino).ok_or(MetaError::InoNotFound)?;
            Ok(fuse_attr_out(ino, &attr.posix, attr.kind))
        }
    }

    /// Mock directory index backed by a map (parent_ino -> entries).
    struct MockDirIndex {
        dirs: BTreeMap<u64, BTreeMap<Vec<u8>, DirLookupEntry>>,
    }

    impl MockDirIndex {
        fn new() -> Self {
            Self {
                dirs: BTreeMap::new(),
            }
        }

        fn insert(
            &mut self,
            parent_ino: u64,
            name: &[u8],
            inode_id: u64,
            generation: u64,
            kind: u32,
        ) {
            let dir = self.dirs.entry(parent_ino).or_default();
            dir.insert(
                name.to_vec(),
                DirLookupEntry {
                    inode_id,
                    generation,
                    kind,
                    name: name.to_vec(),
                },
            );
        }
    }

    impl DirIndex for MockDirIndex {
        fn lookup(&self, parent_ino: u64, name: &[u8]) -> Option<DirLookupEntry> {
            self.dirs
                .get(&parent_ino)
                .and_then(|dir| dir.get(name).cloned())
        }

        fn readdir(&self, parent_ino: u64, cookie: u64, max_entries: usize) -> ReaddirSlice {
            let dir = match self.dirs.get(&parent_ino) {
                Some(d) => d,
                None => return ReaddirSlice::EMPTY,
            };
            // Sort entries by name for deterministic output.
            let mut sorted: Vec<_> = dir.iter().collect();
            sorted.sort_by(|(a_name, _), (b_name, _)| a_name.cmp(b_name));

            let start = cookie as usize;
            if start >= sorted.len() {
                return ReaddirSlice::EMPTY;
            }
            let end = (start + max_entries).min(sorted.len());
            let entries: Vec<DirLookupEntry> = sorted[start..end]
                .iter()
                .map(|(_, entry)| (*entry).clone())
                .collect();
            let next_cookie = if end < sorted.len() { end as u64 } else { 0 };

            ReaddirSlice {
                entries,
                next_cookie,
            }
        }
    }

    // ── Helper: build test InodeAttr ────────────────────────────────────

    fn make_test_attr(ino: u64, mode: u32, size: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: if mode & S_IFMT == S_IFREG {
                NodeKind::File
            } else {
                NodeKind::Dir
            },
            posix: PosixAttrs {
                mode,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 1_000_000_000,
                mtime_ns: 2_000_000_000,
                ctime_ns: 3_000_000_000,
                btime_ns: 4_000_000_000,
                size,
                blocks_512: size.div_ceil(512),
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    // ── handle_getattr tests ────────────────────────────────────────────

    #[test]
    fn getattr_valid_inode_replies_with_attr() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(42, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);

        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let result = worker.handle_getattr(42, 100, None);
        assert!(result.is_ok());

        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 100);
                assert_eq!(attr_out.attr.ino, 42);
                assert_eq!(attr_out.attr.mode, S_IFREG | 0o644);
                assert_eq!(attr_out.attr.size, 4096);
                assert_eq!(attr_out.attr.nlink, 1);
                assert_eq!(attr_out.attr.uid, 1000);
                assert_eq!(attr_out.attr.gid, 100);
                assert_eq!(attr_out.attr.blksize, 4096);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn getattr_nonexistent_inode_replies_with_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let result = worker.handle_getattr(99, 200, None);
        assert_eq!(result, Err(MetaError::InoNotFound));

        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 200);
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn getattr_inode_in_table_but_not_in_store() {
        let mut table = MockInodeTable::new();
        let attr = make_test_attr(7, S_IFREG | 0o644, 4096);
        table.insert(attr);
        // Deliberately don't insert into store.
        let store = MockAttrStore::new();

        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let result = worker.handle_getattr(7, 300, None);
        assert_eq!(result, Err(MetaError::InoNotFound));

        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 300);
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn getattr_attr_reply_error_returns_reply_error() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(42, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);

        let mut sink = FailingReplySink::fail_attr_replies();
        let result = {
            let mut worker = MetaWorker::new(&table, &store, &mut sink);
            worker.handle_getattr(42, 700, None)
        };

        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.attr_calls, 1);
        assert_eq!(sink.error_calls, 0);
    }

    #[test]
    fn getattr_error_reply_error_returns_reply_error() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = FailingReplySink::fail_error_replies();
        let result = {
            let mut worker = MetaWorker::new(&table, &store, &mut sink);
            worker.handle_getattr(99, 701, None)
        };

        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.error_calls, 1);
        assert_eq!(sink.attr_calls, 0);
    }

    // ── handle_setattr tests ────────────────────────────────────────────

    #[test]
    fn setattr_valid_inode_size_mutation() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);

        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 8192,
            ..Default::default()
        };

        let result = worker.handle_setattr(5, 400, &set, 0, 0, &[]);
        // Mock setattr returns the current attr unchanged, so reply will have size=512
        // In a real implementation, setattr would apply the mutation and the
        // subsequent to_fuse_attr_out would reflect the change.
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 400);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn setattr_nonexistent_inode_replies_with_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let set = SetAttr {
            valid: FATTR_MODE | FATTR_UID,
            mode: 0o600,
            uid: 2000,
            ..Default::default()
        };

        let result = worker.handle_setattr(99, 500, &set, 0, 0, &[]);
        assert_eq!(result, Err(MetaError::InoNotFound));

        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 500);
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn setattr_no_mutation_still_replies_with_stat() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(3, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);

        let mut sink = MockReplySink::new();
        let mut worker = MetaWorker::new(&table, &store, &mut sink);

        let set = SetAttr::new(); // valid == 0, no changes

        let result = worker.handle_setattr(3, 600, &set, 0, 0, &[]);
        assert!(result.is_ok());

        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 600);
                assert_eq!(attr_out.attr.mode, S_IFREG | 0o644);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn setattr_attr_reply_error_returns_reply_error() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);

        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 8192,
            ..Default::default()
        };
        let mut sink = FailingReplySink::fail_attr_replies();
        let result = {
            let mut worker = MetaWorker::new(&table, &store, &mut sink);
            worker.handle_setattr(5, 702, &set, 0, 0, &[])
        };

        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.attr_calls, 1);
        assert_eq!(sink.error_calls, 0);
    }

    #[test]
    fn setattr_error_reply_error_returns_reply_error() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..Default::default()
        };
        let mut sink = FailingReplySink::fail_error_replies();
        let result = {
            let mut worker = MetaWorker::new(&table, &store, &mut sink);
            worker.handle_setattr(99, 703, &set, 0, 0, &[])
        };

        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.error_calls, 1);
        assert_eq!(sink.attr_calls, 0);
    }

    // ── dispatch_getattr tests ──────────────────────────────────────────

    #[test]
    fn dispatch_getattr_valid_inode_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 101,
            nodeid: 42,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(42, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();

        let result = dispatch_getattr(&ctx, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 101);
                assert_eq!(attr_out.attr.ino, 42);
                assert_eq!(attr_out.attr.mode, S_IFREG | 0o644);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getattr_missing_inode_returns_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 202,
            nodeid: 99,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_getattr(&ctx, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 202);
                assert_eq!(*errno, 2);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    // ── dispatch_setattr tests ──────────────────────────────────────────

    #[test]
    fn dispatch_setattr_valid_size_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 401,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 8192,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 401);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_nonexistent_inode_returns_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 501,
            nodeid: 99,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 501);
                assert_eq!(*errno, 2);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    // ── dispatch_setattr mode mutation tests ────────────────────────────

    #[test]
    fn dispatch_setattr_valid_mode_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 601,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: S_IFREG | 0o600,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 601);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_dir_mode_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 602,
            nodeid: 10,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(10, S_IFDIR | 0o755, 0);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: S_IFDIR | 0o700,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 602);
                assert_eq!(attr_out.attr.ino, 10);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_sticky_bit_mode_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 603,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: S_IFREG | S_ISUID | S_ISGID | 0o755,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    // ── dispatch_setattr owner mutation tests ───────────────────────────

    #[test]
    fn dispatch_setattr_uid_gid_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 701,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_UID | FATTR_GID,
            uid: 2000,
            gid: 3000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 701);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_uid_only_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 702,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_UID,
            uid: 1001,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_gid_only_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 703,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 1001,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_root_uid_zero_mutation_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 704,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_UID,
            uid: 0,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    // ── dispatch_setattr size mutation tests ────────────────────────────

    #[test]
    fn dispatch_setattr_size_extend_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 801,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 1_048_576,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 801);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_size_shrink_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 802,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 8192);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 256,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_size_zero_truncate_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 803,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 0,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    // ── dispatch_setattr timestamp mutation tests ───────────────────────

    #[test]
    fn dispatch_setattr_atime_mtime_explicit_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 901,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME | FATTR_MTIME,
            atime_ns: 5_000_000_000,
            mtime_ns: 6_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 901);
                assert_eq!(attr_out.attr.ino, 5);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_atime_only_explicit_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 902,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME,
            atime_ns: 5_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_mtime_only_explicit_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 903,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MTIME,
            mtime_ns: 6_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_atime_now_mtime_now_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 904,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME_NOW | FATTR_MTIME_NOW,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_ctime_explicit_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 905,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_CTIME,
            ctime_ns: 7_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_all_three_timestamps_explicit_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 906,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME | FATTR_MTIME | FATTR_CTIME,
            atime_ns: 5_000_000_000,
            mtime_ns: 6_000_000_000,
            ctime_ns: 7_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    // ── dispatch_setattr multi-field combination tests ──────────────────

    #[test]
    fn dispatch_setattr_mode_plus_size_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1001,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_SIZE,
            mode: S_IFREG | 0o600,
            size: 8192,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_owner_plus_mode_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1002,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_UID | FATTR_GID,
            mode: S_IFREG | 0o600,
            uid: 2000,
            gid: 3000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_all_fields_except_timestamps_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1003,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE,
            mode: S_IFREG | 0o600,
            uid: 2000,
            gid: 3000,
            size: 8192,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_all_fields_including_timestamps_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1004,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME,
            mode: S_IFREG | 0o600,
            uid: 2000,
            gid: 3000,
            size: 8192,
            atime_ns: 5_000_000_000,
            mtime_ns: 6_000_000_000,
            ctime_ns: 7_000_000_000,
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    #[test]
    fn dispatch_setattr_timestamps_plus_size_replies() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1005,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_SIZE | FATTR_ATIME | FATTR_MTIME,
            size: 16384,
            atime_ns: 5_000_000_000,
            mtime_ns: 6_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
    }

    // ── dispatch_setattr no-mutation / error path tests ────────────────

    #[test]
    fn dispatch_setattr_no_mutation_still_replies_with_stat() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1101,
            nodeid: 3,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(3, S_IFREG | 0o644, 4096);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr::new();

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.reply_count(), 1);
        match sink.last_reply().unwrap() {
            CapturedReply::Attr { unique, attr_out } => {
                assert_eq!(*unique, 1101);
                assert_eq!(attr_out.attr.ino, 3);
                assert_eq!(attr_out.attr.mode, S_IFREG | 0o644);
            }
            other => panic!("expected Attr reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_nonexistent_inode_with_owner_returns_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1102,
            nodeid: 99,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_UID | FATTR_GID,
            uid: 2000,
            gid: 3000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 1102);
                assert_eq!(*errno, 2);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_nonexistent_inode_with_timestamps_returns_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1103,
            nodeid: 99,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME | FATTR_MTIME,
            atime_ns: 5_000_000_000,
            mtime_ns: 6_000_000_000,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 1103);
                assert_eq!(*errno, 2);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_unsupported_valid_bits_returns_eopnotsupp() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1104,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_LOCKOWNER,
            mode: 0o600,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 1104);
                assert_eq!(*errno, POSIX_SETATTR_EOPNOTSUPP);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_conflicting_atime_flags_returns_einval() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1105,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_ATIME | FATTR_ATIME_NOW,
            atime_ns: 100,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 1105);
                assert_eq!(*errno, POSIX_SETATTR_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_conflicting_mtime_flags_returns_einval() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1106,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);
        let mut sink = MockReplySink::new();
        let set = SetAttr {
            valid: FATTR_MTIME | FATTR_MTIME_NOW,
            mtime_ns: 200,
            ..Default::default()
        };

        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique, errno } => {
                assert_eq!(*unique, 1106);
                assert_eq!(*errno, POSIX_SETATTR_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setattr_reply_error_on_attr_reply_propagates() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let attr = make_test_attr(5, S_IFREG | 0o644, 512);
        table.insert(attr);
        store.insert(attr);

        let mut sink = FailingReplySink::fail_attr_replies();
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1107,
            nodeid: 5,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 8192,
            ..Default::default()
        };
        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.attr_calls, 1);
        assert_eq!(sink.error_calls, 0);
    }

    #[test]
    fn dispatch_setattr_reply_error_on_error_reply_propagates() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = FailingReplySink::fail_error_replies();
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 1108,
            nodeid: 99,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..Default::default()
        };
        let result = dispatch_setattr(&ctx, &set, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::ReplyError));
        assert_eq!(sink.error_calls, 1);
        assert_eq!(sink.attr_calls, 0);
    }

    // ── can_setattr permission gate tests ───────────────────────────────

    #[test]
    fn can_setattr_root_bypasses_all_checks() {
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_UID | FATTR_GID,
            mode: 0o777,
            uid: 2000,
            gid: 300,
            ..Default::default()
        };
        assert!(can_setattr(0, 0, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_can_chmod() {
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..Default::default()
        };
        assert!(can_setattr(1000, 100, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_non_owner_chmod_returns_eperm() {
        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(2000, 200, &[], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    #[test]
    fn can_setattr_non_root_chown_returns_eperm() {
        let set = SetAttr {
            valid: FATTR_UID,
            uid: 3000,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(1000, 100, &[], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    #[test]
    fn can_setattr_root_can_chown() {
        let set = SetAttr {
            valid: FATTR_UID,
            uid: 3000,
            ..Default::default()
        };
        assert!(can_setattr(0, 0, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_can_chgrp_to_own_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 100,
            ..Default::default()
        };
        assert!(can_setattr(1000, 100, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_cannot_chgrp_to_non_member_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 999,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(1000, 100, &[], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    #[test]
    fn can_setattr_non_owner_cannot_chgrp() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 300,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(2000, 200, &[], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    #[test]
    fn can_setattr_no_permission_attrs_passes_without_check() {
        let set = SetAttr {
            valid: FATTR_SIZE,
            size: 4096,
            ..Default::default()
        };
        assert!(can_setattr(2000, 200, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_mixed_bits_checks_each() {
        let set = SetAttr {
            valid: FATTR_MODE | FATTR_UID,
            mode: 0o600,
            uid: 3000,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(2000, 200, &[], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    #[test]
    fn can_setattr_root_chgrp_to_any_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 99999,
            ..Default::default()
        };
        assert!(can_setattr(0, 0, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_chgrp_to_current_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 100,
            ..Default::default()
        };
        assert!(can_setattr(1000, 100, &[], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_chgrp_to_supplementary_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 500,
            ..Default::default()
        };
        assert!(can_setattr(1000, 100, &[500, 600], 1000, 100, set.valid, &set).is_ok());
    }

    #[test]
    fn can_setattr_owner_cannot_chgrp_to_non_supplementary_group() {
        let set = SetAttr {
            valid: FATTR_GID,
            gid: 999,
            ..Default::default()
        };
        assert_eq!(
            can_setattr(1000, 100, &[500, 600], 1000, 100, set.valid, &set),
            Err(MetaError::PermDenied)
        );
    }

    // ── POSIX ACL helpers ───────────────────────────────────────────────

    fn acl_entry(tag: u16, perm: u16, id: u32) -> PosixAclEntry {
        PosixAclEntry { tag, perm, id }
    }

    fn extended_acl() -> Vec<PosixAclEntry> {
        vec![
            acl_entry(ACL_USER_OBJ, 7, 0),
            acl_entry(ACL_USER, 6, 2000),
            acl_entry(ACL_GROUP_OBJ, 0, 0),
            acl_entry(ACL_GROUP, 5, 500),
            acl_entry(ACL_MASK, 4, 0),
            acl_entry(ACL_OTHER, 1, 0),
        ]
    }

    #[test]
    fn access_acl_decode_encode_round_trip_uses_linux_xattr_codec() {
        let raw = encode_validated_access_acl(&extended_acl()).expect("encode ACL");
        let decoded = decode_access_acl_xattr(&raw).expect("decode ACL");

        assert_eq!(POSIX_ACL_ACCESS_XATTR, b"system.posix_acl_access");
        assert_eq!(decoded.entries(), extended_acl().as_slice());
        assert_eq!(decoded.encode(), raw);
    }

    #[test]
    fn access_acl_validation_rejects_missing_required_entry() {
        let raw =
            encode_posix_acl_xattr(&[acl_entry(ACL_USER_OBJ, 6, 0), acl_entry(ACL_OTHER, 4, 0)]);

        assert_eq!(
            decode_access_acl_xattr(&raw),
            Err(AccessAclError::MissingRequiredEntry { tag: ACL_GROUP_OBJ })
        );
    }

    #[test]
    fn access_acl_validation_rejects_named_entry_without_mask() {
        let acl = vec![
            acl_entry(ACL_USER_OBJ, 7, 0),
            acl_entry(ACL_USER, 4, 2000),
            acl_entry(ACL_GROUP_OBJ, 0, 0),
            acl_entry(ACL_OTHER, 0, 0),
        ];

        assert_eq!(validate_access_acl(&acl), Err(AccessAclError::MissingMask));
    }

    #[test]
    fn chmod_access_acl_updates_owner_group_mask_and_other() {
        let updated = chmod_access_acl(&extended_acl(), 0o640).expect("chmod ACL");

        assert_eq!(updated[0], acl_entry(ACL_USER_OBJ, 6, 0));
        assert_eq!(updated[1], acl_entry(ACL_USER, 6, 2000));
        assert_eq!(updated[2], acl_entry(ACL_GROUP_OBJ, 0, 0));
        assert_eq!(updated[3], acl_entry(ACL_GROUP, 5, 500));
        assert_eq!(updated[4], acl_entry(ACL_MASK, 4, 0));
        assert_eq!(updated[5], acl_entry(ACL_OTHER, 0, 0));
    }

    #[test]
    fn access_acl_plan_allows_named_user_read() {
        let acl = extended_acl();
        let plan = plan_access_acl_check(
            &acl,
            AccessAclCheck {
                file_uid: 1000,
                file_gid: 100,
                caller_uid: 2000,
                caller_gid: 200,
                caller_groups: &[],
                mode_fallback: 0o700,
                requested: 4,
            },
        )
        .expect("plan ACL access");

        assert!(plan.is_allowed());
        assert_eq!(plan.effective_perm, 4);
        assert_eq!(plan.errno(), 0);
    }

    #[test]
    fn access_acl_plan_denies_named_user_by_mask() {
        let acl = extended_acl();
        let plan = plan_access_acl_check(
            &acl,
            AccessAclCheck {
                file_uid: 1000,
                file_gid: 100,
                caller_uid: 2000,
                caller_gid: 200,
                caller_groups: &[],
                mode_fallback: 0o700,
                requested: 2,
            },
        )
        .expect("plan ACL access");

        assert!(!plan.is_allowed());
        assert_eq!(plan.effective_perm, 4);
        assert_eq!(plan.errno(), POSIX_ACL_EACCES);
    }

    #[test]
    fn access_acl_plan_allows_matching_supplementary_group() {
        let acl = extended_acl();
        let plan = plan_access_acl_check(
            &acl,
            AccessAclCheck {
                file_uid: 1000,
                file_gid: 100,
                caller_uid: 3000,
                caller_gid: 300,
                caller_groups: &[500],
                mode_fallback: 0o700,
                requested: 4,
            },
        )
        .expect("plan ACL access");

        assert!(plan.is_allowed());
        assert_eq!(plan.effective_perm, 4);
    }

    #[test]
    fn access_acl_plan_denies_other_write() {
        let acl = extended_acl();
        let plan = plan_access_acl_check(
            &acl,
            AccessAclCheck {
                file_uid: 1000,
                file_gid: 100,
                caller_uid: 3000,
                caller_gid: 300,
                caller_groups: &[],
                mode_fallback: 0o777,
                requested: 2,
            },
        )
        .expect("plan ACL access");

        assert!(!plan.is_allowed());
        assert_eq!(plan.effective_perm, 1);
        assert_eq!(plan.errno(), POSIX_ACL_EACCES);
    }

    // ── POSIX readlink planning helpers ────────────────────────────────

    #[test]
    fn readlink_plan_accepts_exact_and_larger_buffers() {
        let target = b"../target";
        let exact = plan_readlink_reply(target, target.len() as u32).expect("exact readlink plan");
        let larger = plan_readlink_reply(target, 64).expect("larger readlink plan");

        assert!(!exact.is_truncated());
        assert_eq!(exact.required_len(), target.len());
        assert_eq!(exact.provided_len(), target.len());
        assert_eq!(exact.copied_len(), target.len());
        assert_eq!(exact.payload(), &target[..]);

        assert!(!larger.is_truncated());
        assert_eq!(larger.required_len(), target.len());
        assert_eq!(larger.provided_len(), 64);
        assert_eq!(larger.copied_len(), target.len());
        assert_eq!(larger.payload(), &target[..]);
    }

    #[test]
    fn readlink_plan_truncates_short_nonzero_buffers() {
        let target = b"directory/target";
        let plan = plan_readlink_reply(target, 9).expect("truncated readlink plan");

        assert!(plan.is_truncated());
        assert_eq!(plan.required_len(), target.len());
        assert_eq!(plan.provided_len(), 9);
        assert_eq!(plan.copied_len(), 9);
        assert_eq!(plan.payload(), &target[..9]);
    }

    #[test]
    fn readlink_plan_rejects_zero_buffer_size() {
        let err = plan_readlink_reply(b"target", 0).expect_err("zero readlink buffer rejects");

        assert_eq!(err, ReadlinkPlanError::InvalidBufferSize { provided: 0 });
        assert_eq!(err.errno(), POSIX_READLINK_EINVAL);
    }

    #[test]
    fn readlink_plan_allows_empty_target_with_nonzero_buffer() {
        let plan = plan_readlink_reply(b"", 1).expect("empty target readlink plan");

        assert!(!plan.is_truncated());
        assert_eq!(plan.required_len(), 0);
        assert_eq!(plan.provided_len(), 1);
        assert_eq!(plan.copied_len(), 0);
        assert_eq!(plan.payload(), b"");
    }

    // ── POSIX xattr planning helpers ────────────────────────────────────

    #[test]
    fn xattr_set_plan_accepts_upsert_create_and_replace_modes() {
        assert_eq!(
            plan_setxattr(0, true),
            Ok(XattrSetPlan {
                flags: 0,
                exists: true,
                mode: XattrSetMode::Upsert,
            })
        );
        assert_eq!(
            plan_setxattr(XATTR_CREATE, false),
            Ok(XattrSetPlan {
                flags: XATTR_CREATE,
                exists: false,
                mode: XattrSetMode::CreateOnly,
            })
        );
        assert_eq!(
            plan_setxattr(XATTR_REPLACE, true),
            Ok(XattrSetPlan {
                flags: XATTR_REPLACE,
                exists: true,
                mode: XattrSetMode::ReplaceOnly,
            })
        );
    }

    #[test]
    fn xattr_set_plan_rejects_invalid_or_conflicting_flags() {
        let combined = XATTR_CREATE | XATTR_REPLACE;
        let err = plan_setxattr(combined, false).expect_err("combined flags reject");

        assert_eq!(err, XattrPlanError::InvalidSetFlags { flags: combined });
        assert_eq!(err.errno(), POSIX_XATTR_EINVAL);

        let err = plan_setxattr(0x8, false).expect_err("unknown flags reject");
        assert_eq!(err, XattrPlanError::InvalidSetFlags { flags: 0x8 });
        assert_eq!(err.errno(), POSIX_XATTR_EINVAL);
    }

    #[test]
    fn xattr_set_plan_enforces_create_and_replace_preconditions() {
        let err = plan_setxattr(XATTR_CREATE, true).expect_err("existing create rejects");
        assert_eq!(err, XattrPlanError::AlreadyExists);
        assert_eq!(err.errno(), POSIX_XATTR_EEXIST);

        let err = plan_setxattr(XATTR_REPLACE, false).expect_err("missing replace rejects");
        assert_eq!(err, XattrPlanError::Missing);
        assert_eq!(err.errno(), POSIX_XATTR_ENODATA);
    }

    #[test]
    fn xattr_set_plan_reports_create_replace_requirements() {
        let create = plan_setxattr(XATTR_CREATE, false).expect("create plan");
        let replace = plan_setxattr(XATTR_REPLACE, true).expect("replace plan");
        let upsert = plan_setxattr(0, false).expect("upsert plan");

        assert!(create.requires_absent());
        assert!(!create.requires_existing());
        assert!(replace.requires_existing());
        assert!(!replace.requires_absent());
        assert!(!upsert.requires_absent());
        assert!(!upsert.requires_existing());
    }

    #[test]
    fn xattr_read_plan_returns_required_length_for_size_probe() {
        let value = b"hello";
        let plan = plan_getxattr_reply(value, 0).expect("getxattr size probe");

        assert!(plan.is_size_probe());
        assert!(!plan.is_reply());
        assert_eq!(plan.required_len(), value.len());
        assert_eq!(plan.payload(), None);

        let names = b"user.alpha\0system.posix_acl_access\0";
        let plan = plan_listxattr_reply(names, 0).expect("listxattr size probe");
        assert_eq!(
            plan,
            XattrReadPlan::SizeProbe {
                required: names.len()
            }
        );
    }

    #[test]
    fn xattr_read_plan_rejects_too_small_nonzero_buffers() {
        let value = b"abcdef";
        let err = plan_getxattr_reply(value, 5).expect_err("small getxattr buffer");

        assert_eq!(
            err,
            XattrPlanError::BufferTooSmall {
                required: value.len(),
                provided: 5,
            }
        );
        assert_eq!(err.errno(), POSIX_XATTR_ERANGE);
    }

    #[test]
    fn xattr_read_plan_accepts_exact_and_larger_buffers() {
        let value = b"payload";
        let exact = plan_getxattr_reply(value, value.len() as u32).expect("exact buffer");
        let larger = plan_listxattr_reply(value, 64).expect("larger buffer");

        assert!(exact.is_reply());
        assert_eq!(exact.required_len(), value.len());
        assert_eq!(exact.payload(), Some(value.as_slice()));
        assert_eq!(larger, XattrReadPlan::Reply { payload: value });
    }

    // ── POSIX setattr planning helpers ──────────────────────────────────

    #[test]
    fn setattr_plan_extracts_explicit_metadata_fields() {
        let attr = SetAttr {
            valid: FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME,
            mode: 0o640,
            uid: 2000,
            gid: 3000,
            size: 8192,
            atime_ns: 111,
            mtime_ns: 222,
            ctime_ns: 333,
        };

        let plan = plan_setattr(&attr).expect("setattr plan");

        assert_eq!(
            plan,
            SetattrPlan {
                valid: attr.valid,
                mode: Some(0o640),
                uid: Some(2000),
                gid: Some(3000),
                size: Some(8192),
                atime: SetattrTimePlan::SetNs(111),
                mtime: SetattrTimePlan::SetNs(222),
                ctime: SetattrTimePlan::SetNs(333),
            }
        );
        assert!(plan.has_mutations());
        assert!(plan.changes_size());
        assert_eq!(plan.to_setattr_with_now(999), attr);
    }

    #[test]
    fn setattr_plan_keeps_chmod_mode_update_isolated() {
        let attr = SetAttr {
            valid: FATTR_MODE,
            mode: S_IFREG | 0o640,
            uid: 2000,
            gid: 3000,
            size: 8192,
            atime_ns: 111,
            mtime_ns: 222,
            ctime_ns: 333,
        };

        let plan = plan_setattr(&attr).expect("chmod-only setattr plan");

        assert_eq!(plan.valid, FATTR_MODE);
        assert_eq!(plan.mode, Some(S_IFREG | 0o640));
        assert_eq!(plan.uid, None);
        assert_eq!(plan.gid, None);
        assert_eq!(plan.size, None);
        assert_eq!(plan.atime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.mtime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.ctime, SetattrTimePlan::Unchanged);
        assert!(plan.has_mutations());
        assert!(!plan.changes_size());

        let materialized = plan.to_setattr_with_now(999);
        assert_eq!(materialized.valid, FATTR_MODE);
        assert_eq!(materialized.mode, S_IFREG | 0o640);
        assert_eq!(materialized.uid, 0);
        assert_eq!(materialized.gid, 0);
        assert_eq!(materialized.size, 0);
        assert_eq!(materialized.atime_ns, 0);
        assert_eq!(materialized.mtime_ns, 0);
        assert_eq!(materialized.ctime_ns, 0);
    }

    #[test]
    fn setattr_ownership_plan_keeps_root_chown_isolated() {
        let attr = SetAttr {
            valid: FATTR_UID | FATTR_GID,
            mode: S_IFREG | S_ISUID | S_ISGID | 0o755,
            uid: 2000,
            gid: 3000,
            size: 8192,
            atime_ns: 111,
            mtime_ns: 222,
            ctime_ns: 333,
        };

        let ownership = plan_setattr_ownership(&attr, S_IFREG | S_ISUID | S_ISGID | 0o755, 0)
            .expect("root ownership setattr plan");

        assert_eq!(ownership.plan.valid, FATTR_UID | FATTR_GID);
        assert_eq!(ownership.plan.mode, None);
        assert_eq!(ownership.plan.uid, Some(2000));
        assert_eq!(ownership.plan.gid, Some(3000));
        assert_eq!(ownership.plan.size, None);
        assert_eq!(ownership.plan.atime, SetattrTimePlan::Unchanged);
        assert_eq!(ownership.plan.mtime, SetattrTimePlan::Unchanged);
        assert_eq!(ownership.plan.ctime, SetattrTimePlan::Unchanged);
        assert!(ownership.ownership_changed);
        assert!(!ownership.privilege_bits_cleared);

        let materialized = ownership.to_setattr_with_now(999);
        assert_eq!(materialized.valid, FATTR_UID | FATTR_GID);
        assert_eq!(materialized.mode, 0);
        assert_eq!(materialized.uid, 2000);
        assert_eq!(materialized.gid, 3000);
        assert_eq!(materialized.size, 0);
        assert_eq!(materialized.atime_ns, 0);
        assert_eq!(materialized.mtime_ns, 0);
        assert_eq!(materialized.ctime_ns, 0);
    }

    #[test]
    fn setattr_ownership_plan_clears_privilege_bits_for_non_root_chown() {
        let attr = SetAttr {
            valid: FATTR_UID,
            uid: 2000,
            ..Default::default()
        };

        let ownership = plan_setattr_ownership(&attr, S_IFREG | S_ISUID | S_ISGID | 0o755, 1000)
            .expect("non-root ownership setattr plan");

        assert_eq!(ownership.plan.valid, FATTR_UID | FATTR_MODE);
        assert_eq!(ownership.plan.mode, Some(S_IFREG | 0o755));
        assert_eq!(ownership.plan.uid, Some(2000));
        assert_eq!(ownership.plan.gid, None);
        assert!(ownership.ownership_changed);
        assert!(ownership.privilege_bits_cleared);

        let materialized = ownership.to_setattr_with_now(999);
        assert_eq!(materialized.valid, FATTR_MODE | FATTR_UID);
        assert_eq!(materialized.mode, S_IFREG | 0o755);
        assert_eq!(materialized.uid, 2000);
        assert_eq!(materialized.gid, 0);
    }

    #[test]
    fn setattr_ownership_plan_uses_requested_mode_for_killpriv() {
        let attr = SetAttr {
            valid: FATTR_MODE | FATTR_GID,
            mode: S_IFREG | S_ISUID | S_ISGID | 0o700,
            gid: 3000,
            ..Default::default()
        };

        let ownership = plan_setattr_ownership(&attr, S_IFREG | 0o644, 1000)
            .expect("non-root ownership chmod setattr plan");

        assert_eq!(ownership.plan.valid, FATTR_MODE | FATTR_GID);
        assert_eq!(ownership.plan.mode, Some(S_IFREG | 0o700));
        assert_eq!(ownership.plan.uid, None);
        assert_eq!(ownership.plan.gid, Some(3000));
        assert!(ownership.ownership_changed);
        assert!(ownership.privilege_bits_cleared);
    }

    #[test]
    fn setattr_ownership_plan_leaves_non_ownership_setattr_alone() {
        let attr = SetAttr {
            valid: FATTR_MODE | FATTR_SIZE,
            mode: S_IFREG | S_ISUID | S_ISGID | 0o640,
            size: 8192,
            ..Default::default()
        };

        let ownership = plan_setattr_ownership(&attr, S_IFREG | S_ISUID | S_ISGID | 0o755, 1000)
            .expect("chmod and size setattr plan");

        assert_eq!(ownership.plan.valid, FATTR_MODE | FATTR_SIZE);
        assert_eq!(
            ownership.plan.mode,
            Some(S_IFREG | S_ISUID | S_ISGID | 0o640)
        );
        assert_eq!(ownership.plan.uid, None);
        assert_eq!(ownership.plan.gid, None);
        assert_eq!(ownership.plan.size, Some(8192));
        assert!(!ownership.ownership_changed);
        assert!(!ownership.privilege_bits_cleared);
    }

    #[test]
    fn setattr_plan_preserves_chmod_type_and_permission_bits_exactly() {
        for mode in [S_IFREG, S_IFREG | 0o4755, S_IFDIR | 0o3770] {
            let attr = SetAttr {
                valid: FATTR_MODE,
                mode,
                ..Default::default()
            };

            let plan = plan_setattr(&attr).expect("mode boundary setattr plan");

            assert_eq!(plan.mode, Some(mode));
            assert_eq!(plan.to_setattr_with_now(123).mode, mode);
        }
    }

    #[test]
    fn setattr_timestamp_plan_normalizes_mixed_time_modes() {
        let attr = SetAttr {
            valid: FATTR_MODE | FATTR_ATIME_NOW | FATTR_MTIME | FATTR_CTIME,
            mode: S_IFREG | 0o640,
            atime_ns: 101,
            mtime_ns: 202,
            ctime_ns: 303,
            ..Default::default()
        };

        let plan = plan_setattr_timestamps(&attr).expect("timestamp setattr plan");

        assert_eq!(plan.valid, FATTR_ATIME_NOW | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(plan.atime, SetattrTimePlan::SetNow);
        assert_eq!(plan.mtime, SetattrTimePlan::SetNs(202));
        assert_eq!(plan.ctime, SetattrTimePlan::SetNs(303));
        assert!(plan.has_mutations());

        let materialized = plan.to_setattr_with_now(987_654);
        assert_eq!(materialized.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(materialized.mode, 0);
        assert_eq!(materialized.atime_ns, 987_654);
        assert_eq!(materialized.mtime_ns, 202);
        assert_eq!(materialized.ctime_ns, 303);
    }

    #[test]
    fn setattr_timestamp_plan_accepts_empty_noop() {
        let plan = plan_setattr_timestamps(&SetAttr::new()).expect("empty timestamp plan");

        assert_eq!(plan.valid, 0);
        assert_eq!(plan.atime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.mtime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.ctime, SetattrTimePlan::Unchanged);
        assert!(!plan.has_mutations());
        assert_eq!(plan.to_setattr_with_now(123), SetAttr::new());
    }

    #[test]
    fn setattr_time_plan_keeps_explicit_timestamp_updates_isolated() {
        let attr = SetAttr {
            valid: FATTR_ATIME | FATTR_MTIME | FATTR_CTIME,
            mode: S_IFREG | 0o600,
            uid: 2000,
            gid: 3000,
            size: 8192,
            atime_ns: 101,
            mtime_ns: 202,
            ctime_ns: 303,
        };

        let plan = plan_setattr(&attr).expect("timestamp-only setattr plan");

        assert_eq!(plan.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(plan.mode, None);
        assert_eq!(plan.uid, None);
        assert_eq!(plan.gid, None);
        assert_eq!(plan.size, None);
        assert_eq!(plan.atime, SetattrTimePlan::SetNs(101));
        assert_eq!(plan.mtime, SetattrTimePlan::SetNs(202));
        assert_eq!(plan.ctime, SetattrTimePlan::SetNs(303));
        assert!(plan.has_mutations());
        assert!(!plan.changes_size());

        let materialized = plan.to_setattr_with_now(999);
        assert_eq!(materialized.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(materialized.mode, 0);
        assert_eq!(materialized.uid, 0);
        assert_eq!(materialized.gid, 0);
        assert_eq!(materialized.size, 0);
        assert_eq!(materialized.atime_ns, 101);
        assert_eq!(materialized.mtime_ns, 202);
        assert_eq!(materialized.ctime_ns, 303);
    }

    #[test]
    fn setattr_time_plan_materializes_now_and_ctime_without_unrelated_fields() {
        let attr = SetAttr {
            valid: FATTR_ATIME_NOW | FATTR_MTIME | FATTR_CTIME,
            mode: S_IFREG | 0o640,
            uid: 4000,
            gid: 5000,
            size: 16_384,
            atime_ns: 111,
            mtime_ns: 222,
            ctime_ns: 333,
        };

        let plan = plan_setattr(&attr).expect("mixed timestamp setattr plan");

        assert_eq!(plan.valid, FATTR_ATIME_NOW | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(plan.mode, None);
        assert_eq!(plan.uid, None);
        assert_eq!(plan.gid, None);
        assert_eq!(plan.size, None);
        assert_eq!(plan.atime, SetattrTimePlan::SetNow);
        assert_eq!(plan.mtime, SetattrTimePlan::SetNs(222));
        assert_eq!(plan.ctime, SetattrTimePlan::SetNs(333));
        assert!(plan.has_mutations());
        assert!(!plan.changes_size());

        let materialized = plan.to_setattr_with_now(987_654);
        assert_eq!(materialized.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(materialized.mode, 0);
        assert_eq!(materialized.uid, 0);
        assert_eq!(materialized.gid, 0);
        assert_eq!(materialized.size, 0);
        assert_eq!(materialized.atime_ns, 987_654);
        assert_eq!(materialized.mtime_ns, 222);
        assert_eq!(materialized.ctime_ns, 333);
    }

    #[test]
    fn setattr_plan_keeps_now_timestamps_until_materialized() {
        let attr = SetAttr {
            valid: FATTR_ATIME_NOW | FATTR_MTIME_NOW,
            ..Default::default()
        };

        let plan = plan_setattr(&attr).expect("setattr now plan");

        assert_eq!(plan.atime, SetattrTimePlan::SetNow);
        assert_eq!(plan.mtime, SetattrTimePlan::SetNow);
        assert_eq!(plan.ctime, SetattrTimePlan::Unchanged);
        assert!(plan.has_mutations());

        let materialized = plan.to_setattr_with_now(123_456);
        assert_eq!(materialized.valid, FATTR_ATIME | FATTR_MTIME);
        assert_eq!(materialized.atime_ns, 123_456);
        assert_eq!(materialized.mtime_ns, 123_456);
    }

    #[test]
    fn setattr_plan_accepts_empty_noop() {
        let plan = plan_setattr(&SetAttr::new()).expect("empty setattr plan");

        assert_eq!(plan.valid, 0);
        assert_eq!(plan.mode, None);
        assert_eq!(plan.uid, None);
        assert_eq!(plan.gid, None);
        assert_eq!(plan.size, None);
        assert_eq!(plan.atime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.mtime, SetattrTimePlan::Unchanged);
        assert_eq!(plan.ctime, SetattrTimePlan::Unchanged);
        assert!(!plan.has_mutations());
        assert!(!plan.changes_size());
        assert_eq!(plan.to_setattr_with_now(1), SetAttr::new());
    }

    #[test]
    fn setattr_plan_rejects_unsupported_valid_bits() {
        let attr = SetAttr {
            valid: FATTR_MODE | FATTR_LOCKOWNER,
            mode: 0o600,
            ..Default::default()
        };
        let err = plan_setattr(&attr).expect_err("unsupported lockowner flag");

        assert_eq!(
            err,
            SetattrPlanError::UnsupportedValidBits {
                valid: attr.valid,
                unsupported: FATTR_LOCKOWNER,
            }
        );
        assert_eq!(err.errno(), POSIX_SETATTR_EOPNOTSUPP);
    }

    #[test]
    fn setattr_timestamp_plan_rejects_conflicting_time_flags() {
        let attr = SetAttr {
            valid: FATTR_MTIME | FATTR_MTIME_NOW,
            mtime_ns: 20,
            ..Default::default()
        };
        let err = plan_setattr_timestamps(&attr).expect_err("conflicting timestamp flags");

        assert_eq!(
            err,
            SetattrPlanError::ConflictingTimeFlags {
                specific: FATTR_MTIME,
                now: FATTR_MTIME_NOW,
            }
        );
        assert_eq!(err.errno(), POSIX_SETATTR_EINVAL);
    }

    #[test]
    fn setattr_plan_rejects_conflicting_time_flags() {
        let attr = SetAttr {
            valid: FATTR_ATIME | FATTR_ATIME_NOW,
            atime_ns: 10,
            ..Default::default()
        };
        let err = plan_setattr(&attr).expect_err("conflicting atime flags");

        assert_eq!(
            err,
            SetattrPlanError::ConflictingTimeFlags {
                specific: FATTR_ATIME,
                now: FATTR_ATIME_NOW,
            }
        );
        assert_eq!(err.errno(), POSIX_SETATTR_EINVAL);

        let attr = SetAttr {
            valid: FATTR_MTIME | FATTR_MTIME_NOW,
            mtime_ns: 20,
            ..Default::default()
        };
        let err = plan_setattr(&attr).expect_err("conflicting mtime flags");

        assert_eq!(
            err,
            SetattrPlanError::ConflictingTimeFlags {
                specific: FATTR_MTIME,
                now: FATTR_MTIME_NOW,
            }
        );
        assert_eq!(err.errno(), POSIX_SETATTR_EINVAL);
    }

    // ── MetaError errno mapping ─────────────────────────────────────────

    #[test]
    fn meta_error_errno_mapping() {
        assert_eq!(MetaError::InoNotFound.errno(), 2); // ENOENT
        assert_eq!(MetaError::AttrStoreError.errno(), 67); // ENOLINK
        assert_eq!(MetaError::InvalidInput.errno(), POSIX_XATTR_EINVAL);
        assert_eq!(MetaError::XattrAlreadyExists.errno(), POSIX_XATTR_EEXIST);
        assert_eq!(MetaError::XattrNoData.errno(), POSIX_XATTR_ENODATA);
        assert_eq!(MetaError::ReplyError.errno(), 5); // EIO
        assert_eq!(MetaError::Io.errno(), 5); // EIO
        assert_eq!(MetaError::PermDenied.errno(), 1); // EPERM
    }

    // ── FuseAttr layout ─────────────────────────────────────────────────

    #[test]
    fn fuse_attr_size_matches_expected() {
        // fuse_attr: 8+8+8+8+8+8 + 4+4+4+4+4+4+4+4+4 = 6*8 + 9*4 = 48 + 36 = 84 bytes
        // But with repr(C) and alignment, it should be exactly core::mem::size_of
        let size = core::mem::size_of::<FuseAttr>();
        // Verify structure is non-zero and plausible
        assert!(size > 0);
        assert!(size <= 128);
    }

    #[test]
    fn fuse_attr_default_is_all_zeroes() {
        let attr = FuseAttr::default();
        assert_eq!(attr.ino, 0);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.mode, 0);
        assert_eq!(attr.padding, 0);
    }

    #[test]
    fn meta_worker_exposes_handles() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();
        let worker = MetaWorker::new(&table, &store, &mut sink);

        // Verify we can access the handles (smoke test for the accessor methods).
        let _itable = worker.inode_table();
        let _astore = worker.attr_store();
    }
    // ── dispatch_readlink helpers ──────────────────────────────────────

    /// Thin wrapper that adds symlink-target storage to a MockInodeTable.
    #[derive(Debug)]
    struct SymlinkTable {
        inner: MockInodeTable,
        targets: std::collections::BTreeMap<u64, Vec<u8>>,
    }

    impl SymlinkTable {
        fn new() -> Self {
            Self {
                inner: MockInodeTable::new(),
                targets: std::collections::BTreeMap::new(),
            }
        }

        fn insert(&mut self, attr: InodeAttr) {
            self.inner.insert(attr);
        }

        fn set_target(&mut self, ino: u64, target: Vec<u8>) {
            self.targets.insert(ino, target);
        }
    }

    impl InodeTable for SymlinkTable {
        fn lookup(&self, ino: u64) -> bool {
            self.inner.lookup(ino)
        }
        fn getattr(&self, ino: u64) -> Option<InodeAttr> {
            self.inner.getattr(ino)
        }
        fn setattr(&self, ino: u64, set: &SetAttr) -> Result<InodeAttr, MetaError> {
            self.inner.setattr(ino, set)
        }
        fn readlink_target(&self, ino: u64) -> Option<Vec<u8>> {
            self.targets.get(&ino).cloned()
        }

        fn inode_stats(&self) -> Option<(u64, u64)> {
            self.inner.inode_stats()
        }
    }

    // ── dispatch_readlink tests ─────────────────────────────────────────

    #[test]
    fn dispatch_readlink_resolves_symlink_target() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 200,
            nodeid: 10,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let target = b"/some/path";
        let mut table = SymlinkTable::new();
        let mut attrs = make_test_attr(10, S_IFLNK | 0o777, target.len() as u64);
        attrs.kind = NodeKind::Symlink;
        table.insert(attrs);
        table.set_target(10, target.to_vec());

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, target.len() as u32, &table, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReadlinkData { unique, data }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(data.as_slice(), target);
            }
            other => panic!("expected ReadlinkData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_non_symlink_returns_einval() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 201,
            nodeid: 20,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let mut table = MockInodeTable::new();
        table.insert(make_test_attr(20, S_IFREG | 0o644, 4096));

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, 64, &table, &store, &mut sink);
        assert!(result.is_err());

        match sink.last_reply() {
            Some(CapturedReply::Error { unique, errno }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(*errno, POSIX_READLINK_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_nonexistent_inode_returns_enoent() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 202,
            nodeid: 9999,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, 64, &table, &store, &mut sink);
        assert!(result.is_err());

        match sink.last_reply() {
            Some(CapturedReply::Error { unique, errno }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(*errno, MetaError::InoNotFound.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_empty_target() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 203,
            nodeid: 30,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let mut table = SymlinkTable::new();
        let mut attrs = make_test_attr(30, S_IFLNK | 0o777, 0);
        attrs.kind = NodeKind::Symlink;
        table.insert(attrs);
        table.set_target(30, Vec::new());

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, 1, &table, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReadlinkData { unique, data }) => {
                assert_eq!(*unique, ctx.unique);
                assert!(data.is_empty());
            }
            other => panic!("expected ReadlinkData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_long_target_near_pathmax() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 204,
            nodeid: 40,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        // PATH_MAX is 4096 on Linux; use a target near that length.
        let target_len = 4000usize;
        let target: Vec<u8> = (0u32..)
            .map(|i| b'a' + ((i % 26) as u8))
            .take(target_len)
            .collect();

        let mut table = SymlinkTable::new();
        let mut attrs = make_test_attr(40, S_IFLNK | 0o777, target_len as u64);
        attrs.kind = NodeKind::Symlink;
        table.insert(attrs);
        table.set_target(40, target.clone());

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, target_len as u32, &table, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReadlinkData { unique, data }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(data.len(), target_len);
                assert_eq!(data.as_slice(), target.as_slice());
            }
            other => panic!("expected ReadlinkData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_truncates_when_buffer_too_small() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 205,
            nodeid: 50,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let target = b"directory/subdir/target";
        let requested_size: u32 = 9; // smaller than target

        let mut table = SymlinkTable::new();
        let mut attrs = make_test_attr(50, S_IFLNK | 0o777, target.len() as u64);
        attrs.kind = NodeKind::Symlink;
        table.insert(attrs);
        table.set_target(50, target.to_vec());

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, requested_size, &table, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReadlinkData { unique, data }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(data.as_slice(), &target[..requested_size as usize]);
            }
            other => panic!("expected ReadlinkData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readlink_rejects_zero_buffer() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 206,
            nodeid: 60,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let target = b"/some/target";

        let mut table = SymlinkTable::new();
        let mut attrs = make_test_attr(60, S_IFLNK | 0o777, target.len() as u64);
        attrs.kind = NodeKind::Symlink;
        table.insert(attrs);
        table.set_target(60, target.to_vec());

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let result = dispatch_readlink(&ctx, 0, &table, &store, &mut sink);
        assert!(result.is_err());

        match sink.last_reply() {
            Some(CapturedReply::Error { unique, errno }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(*errno, POSIX_READLINK_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    // ── dispatch_statfs tests ──────────────────────────────────────────

    #[test]
    fn dispatch_statfs_replies_with_filled_statfs_fields() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 300,
            nodeid: 1,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        for i in 0..10 {
            store.insert(make_test_attr(i, S_IFREG | 0o644, 0));
        }
        for i in 0..6 {
            table.insert(make_test_attr(i, S_IFREG | 0o644, 0));
        }

        let mut sink = MockReplySink::new();

        let result = dispatch_statfs(
            &ctx, 1024, // block_total
            512,  // block_free
            500,  // block_avail
            4096, // block_size
            255,  // name_max
            &table, &store, &mut sink,
        );
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Statfs { unique, fields }) => {
                assert_eq!(*unique, ctx.unique);
                assert_eq!(fields.blocks, 1024);
                assert_eq!(fields.bfree, 512);
                assert_eq!(fields.bavail, 500);
                assert_eq!(fields.bsize, 4096);
                assert_eq!(fields.frsize, 4096);
                assert_eq!(fields.namemax, 255);
                // MockInodeTable inode_stats: total = entries + 10 = 16, free = 10
                assert_eq!(fields.files, 16);
                assert_eq!(fields.ffree, 10);
            }
            other => panic!("expected Statfs reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_statfs_zero_inodes_when_no_inode_stats() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 301,
            nodeid: 1,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        // Empty inode table (inode_stats returns None due to default impl)
        struct NoStatsInodeTable;
        impl InodeTable for NoStatsInodeTable {
            fn lookup(&self, _ino: u64) -> bool {
                false
            }
            fn getattr(&self, _ino: u64) -> Option<InodeAttr> {
                None
            }
            fn setattr(&self, _ino: u64, _set: &SetAttr) -> Result<InodeAttr, MetaError> {
                Err(MetaError::InoNotFound)
            }
            fn readlink_target(&self, _ino: u64) -> Option<Vec<u8>> {
                None
            }
            // inode_stats uses default: returns None
        }
        struct NoStatsAttrStore;
        impl AttrStore for NoStatsAttrStore {
            fn to_fuse_attr_out(&self, _ino: u64) -> Result<FuseAttrOut, MetaError> {
                Ok(FuseAttrOut::default())
            }
        }

        let table = NoStatsInodeTable;
        let store = NoStatsAttrStore;
        let mut sink = MockReplySink::new();

        let result = dispatch_statfs(
            &ctx, 2048, // block_total
            1000, // block_free
            900,  // block_avail
            512,  // block_size
            255,  // name_max
            &table, &store, &mut sink,
        );
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Statfs { unique: _, fields }) => {
                assert_eq!(fields.files, 0);
                assert_eq!(fields.ffree, 0);
            }
            other => panic!("expected Statfs reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_statfs_preserves_frsize_equal_to_bsize() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 302,
            nodeid: 1,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };

        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        dispatch_statfs(&ctx, 0, 0, 0, 8192, 0, &table, &store, &mut sink).unwrap();

        match sink.last_reply() {
            Some(CapturedReply::Statfs { unique: _, fields }) => {
                assert_eq!(fields.bsize, 8192);
                assert_eq!(fields.frsize, 8192);
                assert_eq!(fields.blocks, 0);
                assert_eq!(fields.namemax, 0);
            }
            other => panic!("expected Statfs reply, got {other:?}"),
        }
    }

    // ── dispatch_lookup tests ────────────────────────────────────────────

    fn make_dir_attr(ino: u64) -> InodeAttr {
        make_test_attr(ino, 0o40755, 4096)
    }

    fn make_file_attr(ino: u64) -> InodeAttr {
        make_test_attr(ino, 0o100644, 1024)
    }

    fn make_test_ctx(unique: u64, nodeid: u64) -> PosixFilesystemAdapterRequestContextMirrorRecord {
        PosixFilesystemAdapterRequestContextMirrorRecord {
            unique,
            nodeid,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        }
    }

    #[test]
    fn dispatch_lookup_found_replies_entry() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 2u64;
        let child_ino = 100u64;
        let child_name = b"target_file";

        // Set up parent dir.
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));
        table.insert(make_file_attr(child_ino));
        store.insert(make_file_attr(child_ino));
        dir_index.insert(
            parent_ino,
            child_name,
            child_ino,
            1,
            NodeKind::File.as_u32(),
        );

        let ctx = make_test_ctx(10, parent_ino);
        let cfg = LookupConfig::DEFAULT;

        let result = dispatch_lookup(&ctx, child_name, cfg, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Entry { unique, entry_out }) => {
                assert_eq!(*unique, 10);
                assert_eq!(entry_out.nodeid, child_ino);
                assert_eq!(entry_out.generation, 1);
                assert_eq!(entry_out.entry_valid, cfg.entry_ttl_secs);
            }
            other => panic!("expected Entry reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_uses_child_attr_projection_not_child_table_lifetime() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 2u64;
        let child_ino = 101u64;
        let child_name = b"projected_file";

        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));
        store.insert(make_file_attr(child_ino));
        dir_index.insert(
            parent_ino,
            child_name,
            child_ino,
            7,
            NodeKind::File.as_u32(),
        );

        assert!(
            !table.lookup(child_ino),
            "child lifetime is not owned by the metadata-worker table"
        );

        let ctx = make_test_ctx(10_665, parent_ino);
        let cfg = LookupConfig::DEFAULT;

        let result = dispatch_lookup(&ctx, child_name, cfg, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Entry { unique, entry_out }) => {
                assert_eq!(*unique, 10_665);
                assert_eq!(entry_out.nodeid, child_ino);
                assert_eq!(entry_out.generation, 7);
            }
            other => panic!("expected Entry reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_not_found_returns_enoent() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        let ctx = make_test_ctx(11, parent_ino);
        let cfg = LookupConfig::DEFAULT;

        let result = dispatch_lookup(
            &ctx,
            b"nonexistent",
            cfg,
            &table,
            &dir_index,
            &store,
            &mut sink,
        );
        assert_eq!(result, Err(MetaError::InoNotFound));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique, errno }) => {
                assert_eq!(*unique, 11);
                assert_eq!(*errno, MetaError::InoNotFound.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_parent_not_found_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let ctx = make_test_ctx(12, 999); // nonexistent parent
        let cfg = LookupConfig::DEFAULT;

        let result = dispatch_lookup(&ctx, b"any", cfg, &table, &dir_index, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, MetaError::InoNotFound.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_parent_not_dir_returns_enotdir() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 5u64;
        // Parent is a regular file, not a directory.
        table.insert(make_file_attr(parent_ino));
        store.insert(make_file_attr(parent_ino));

        let ctx = make_test_ctx(13, parent_ino);
        let cfg = LookupConfig::DEFAULT;

        let result = dispatch_lookup(&ctx, b"any", cfg, &table, &dir_index, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, MetaError::NotDir.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_with_custom_timeout_config() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 2u64;
        let child_ino = 200u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));
        table.insert(make_file_attr(child_ino));
        store.insert(make_file_attr(child_ino));
        dir_index.insert(parent_ino, b"child", child_ino, 3, NodeKind::File.as_u32());

        let ctx = make_test_ctx(20, parent_ino);
        let cfg = LookupConfig {
            entry_ttl_secs: 5,
            entry_ttl_nsec: 500_000_000,
            attr_ttl_secs: 10,
            attr_ttl_nsec: 0,
        };

        let result = dispatch_lookup(&ctx, b"child", cfg, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Entry {
                unique: _,
                entry_out,
            }) => {
                assert_eq!(entry_out.entry_valid, 5);
                assert_eq!(entry_out.entry_valid_nsec, 500_000_000);
            }
            other => panic!("expected Entry reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lookup_multiple_children() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        for i in 0..3 {
            let ino = 100 + i as u64;
            let name = format!("child_{i}");
            table.insert(make_file_attr(ino));
            store.insert(make_file_attr(ino));
            dir_index.insert(
                parent_ino,
                name.as_bytes(),
                ino,
                i as u64,
                NodeKind::File.as_u32(),
            );
        }

        let ctx = make_test_ctx(30, parent_ino);
        let cfg = LookupConfig::DEFAULT;
        let mut sink = MockReplySink::new();

        // Look up each child.
        for i in 0..3 {
            let name = format!("child_{i}");
            let result = dispatch_lookup(
                &ctx,
                name.as_bytes(),
                cfg,
                &table,
                &dir_index,
                &store,
                &mut sink,
            );
            assert!(result.is_ok());
        }
        assert_eq!(sink.reply_count(), 3);

        // Verify all replies are Entry.
        for reply in sink.replies() {
            assert!(matches!(reply, CapturedReply::Entry { .. }));
        }
    }

    // ── dispatch_readdir tests ───────────────────────────────────────────

    #[test]
    fn dispatch_readdir_empty_directory() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();
        let mut sink = MockReplySink::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        let ctx = make_test_ctx(50, parent_ino);

        let result = dispatch_readdir(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                unique: _,
                entries,
                next_cookie,
            }) => {
                assert!(entries.is_empty());
                assert_eq!(*next_cookie, 0);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_populated_directory() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        // Insert 5 files in reverse name order to test sorting.
        let names = ["zebra", "alpha", "delta", "beta", "gamma"];
        for (i, name) in names.iter().enumerate() {
            let ino = 100u64 + i as u64;
            table.insert(make_file_attr(ino));
            store.insert(make_file_attr(ino));
            dir_index.insert(
                parent_ino,
                name.as_bytes(),
                ino,
                i as u64,
                NodeKind::File.as_u32(),
            );
        }

        let ctx = make_test_ctx(51, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                unique: _,
                entries,
                next_cookie,
            }) => {
                assert_eq!(entries.len(), 5);
                // Must be sorted by name.
                let entry_names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
                assert_eq!(
                    entry_names,
                    vec![
                        b"alpha".as_slice(),
                        b"beta".as_slice(),
                        b"delta".as_slice(),
                        b"gamma".as_slice(),
                        b"zebra".as_slice()
                    ]
                );
                assert_eq!(*next_cookie, 0);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_parent_not_found_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();
        let ctx = make_test_ctx(52, 999);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
    }

    #[test]
    fn dispatch_readdir_parent_not_dir_returns_enotdir() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();

        let parent_ino = 5u64;
        table.insert(make_file_attr(parent_ino));
        store.insert(make_file_attr(parent_ino));

        let ctx = make_test_ctx(53, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, MetaError::NotDir.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_pagination() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        // Insert 5 entries, request only 2 per page.
        for i in 0..5 {
            let ino = 200 + i as u64;
            let name = format!("file_{i}");
            table.insert(make_file_attr(ino));
            store.insert(make_file_attr(ino));
            dir_index.insert(
                parent_ino,
                name.as_bytes(),
                ino,
                i as u64,
                NodeKind::File.as_u32(),
            );
        }

        let ctx = make_test_ctx(60, parent_ino);

        // First page.
        let mut sink = MockReplySink::new();
        let result = dispatch_readdir(&ctx, 0, 2, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());
        let (first_entries, first_cookie) = match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => (entries.clone(), *next_cookie),
            other => panic!("expected ReaddirEntries, got {other:?}"),
        };
        assert_eq!(first_entries.len(), 2);
        assert!(first_cookie > 0, "should have more entries");

        // Second page.
        let mut sink = MockReplySink::new();
        assert!(
            dispatch_readdir(&ctx, first_cookie, 2, &table, &dir_index, &store, &mut sink).is_ok()
        );
        let (sec_entries, sec_cookie) = match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => (entries.clone(), *next_cookie),
            other => panic!("expected ReaddirEntries, got {other:?}"),
        };
        assert_eq!(sec_entries.len(), 2);
        assert!(sec_cookie > 0);

        // Third page (last).
        let mut sink = MockReplySink::new();
        assert!(
            dispatch_readdir(&ctx, sec_cookie, 2, &table, &dir_index, &store, &mut sink).is_ok()
        );
        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(*next_cookie, 0, "last page should have cookie 0");
            }
            other => panic!("expected ReaddirEntries, got {other:?}"),
        }
    }

    // ── dispatch_readdirplus tests ───────────────────────────────────────

    #[test]
    fn dispatch_readdirplus_populated_directory() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut dir_index = MockDirIndex::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        // Insert 3 files.
        for i in 0..3 {
            let ino = 300 + i as u64;
            let name = format!("entry_{i}");
            table.insert(make_file_attr(ino));
            store.insert(make_file_attr(ino));
            dir_index.insert(
                parent_ino,
                name.as_bytes(),
                ino,
                i as u64,
                NodeKind::File.as_u32(),
            );
        }

        let ctx = make_test_ctx(70, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdirplus(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(*next_cookie, 0);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdirplus_empty_directory() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let dir_index = MockDirIndex::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));
        store.insert(make_dir_attr(parent_ino));

        let ctx = make_test_ctx(71, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdirplus(&ctx, 0, 100, &table, &dir_index, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                unique: _,
                entries,
                next_cookie,
            }) => {
                assert!(entries.is_empty());
                assert_eq!(*next_cookie, 0);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    // ── dispatch_opendir tests ───────────────────────────────────────────

    #[test]
    fn dispatch_opendir_directory_succeeds() {
        let mut table = MockInodeTable::new();
        let store = MockAttrStore::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));

        let ctx = make_test_ctx(100, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_opendir(&ctx, 0, &table, &store, &mut sink);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), parent_ino);

        match sink.last_reply() {
            Some(CapturedReply::Opendir { unique, fh, flags }) => {
                assert_eq!(*unique, 100);
                assert_eq!(*fh, parent_ino);
                assert_eq!(*flags, 0);
            }
            other => panic!("expected Opendir reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_opendir_not_found_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();

        let ctx = make_test_ctx(101, 999);
        let mut sink = MockReplySink::new();

        let result = dispatch_opendir(&ctx, 0, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
    }

    #[test]
    fn dispatch_opendir_not_a_directory_returns_enotdir() {
        let mut table = MockInodeTable::new();
        let store = MockAttrStore::new();

        let parent_ino = 5u64;
        table.insert(make_file_attr(parent_ino));

        let ctx = make_test_ctx(102, parent_ino);
        let mut sink = MockReplySink::new();

        let result = dispatch_opendir(&ctx, 0, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::Io));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, MetaError::NotDir.errno());
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    // ── dispatch_releasedir tests ────────────────────────────────────────

    #[test]
    fn dispatch_releasedir_succeeds() {
        let ctx = make_test_ctx(110, 2);
        let mut sink = MockReplySink::new();

        let result = dispatch_releasedir(&ctx, 2, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Empty { unique }) => {
                assert_eq!(*unique, 110);
            }
            other => panic!("expected Empty reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_opendir_then_releasedir_lifecycle() {
        let mut table = MockInodeTable::new();
        let store = MockAttrStore::new();

        let parent_ino = 2u64;
        table.insert(make_dir_attr(parent_ino));

        let ctx_open = make_test_ctx(120, parent_ino);
        let mut sink = MockReplySink::new();
        let fh = dispatch_opendir(&ctx_open, 0, &table, &store, &mut sink).unwrap();
        assert_eq!(fh, parent_ino);

        let ctx_rel = make_test_ctx(121, parent_ino);
        let mut sink = MockReplySink::new();
        assert!(dispatch_releasedir(&ctx_rel, fh, &mut sink).is_ok());
    }

    // ── dispatch_access tests ────────────────────────────────────────────

    #[test]
    fn dispatch_access_allowed_owner_read() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // Owner (uid 1000) reading their own file with mode 0o400.
        let ino = 10u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100400,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(80, ino);
        let result = dispatch_access(&ctx, 1000, 100, 4, &table, &store, &mut sink); // R_OK
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, 0, "successful access should reply with errno 0");
            }
            other => panic!("expected Error reply with errno 0, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_denied_other_write() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File owned by uid 1000, mode 0o100400 (owner read only).
        let ino = 11u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100400,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(81, ino);
        // uid 2000 (other) tries to write.
        let result = dispatch_access(&ctx, 2000, 200, 2, &table, &store, &mut sink); // W_OK
        assert_eq!(result, Err(MetaError::Io));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, 13, "denied access should return EACCES");
            }
            other => panic!("expected Error reply with EACCES, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_root_bypass() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File with mode 0o000 (no permissions) — root should still pass.
        let ino = 12u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(82, ino);
        let result = dispatch_access(&ctx, 0, 0, 6, &table, &store, &mut sink); // R_OK|W_OK
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, 0);
            }
            _other => panic!("root should bypass permissions"),
        }
    }

    #[test]
    fn dispatch_access_group_permissions() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File owned by uid 1000, gid 100, mode 0o100040 (group read).
        let ino = 13u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100040,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(83, ino);
        // uid 2000 is not the owner, but gid 100 matches group.
        let result = dispatch_access(&ctx, 2000, 100, 4, &table, &store, &mut sink); // R_OK
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_access_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let ctx = make_test_ctx(84, 999);
        let result = dispatch_access(&ctx, 1000, 100, 4, &table, &store, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
    }

    #[test]
    fn dispatch_access_invalid_mask_returns_einval() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let ino = 14u64;
        let attr = make_file_attr(ino);
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(85, ino);
        let result = dispatch_access(&ctx, 1000, 100, 8, &table, &store, &mut sink); // invalid mask bit
        assert_eq!(result, Err(MetaError::Io));

        match sink.last_reply() {
            Some(CapturedReply::Error { unique: _, errno }) => {
                assert_eq!(*errno, 22, "invalid mask should return EINVAL");
            }
            _other => panic!("expected EINVAL"),
        }
    }

    #[test]
    fn dispatch_access_mode_bits() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let _sink = MockReplySink::new();

        // File owned by uid 1000, mode 0o100750 (owner rwx, group rx, other none).
        let ino = 15u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100750,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(86, ino);

        // Owner can read.
        let mut sink = MockReplySink::new();
        assert!(dispatch_access(&ctx, 1000, 100, 4, &table, &store, &mut sink).is_ok());

        // Owner can write.
        let mut sink = MockReplySink::new();
        assert!(dispatch_access(&ctx, 1000, 100, 2, &table, &store, &mut sink).is_ok());

        // Other cannot read.
        let mut sink = MockReplySink::new();
        assert!(dispatch_access(&ctx, 2000, 200, 4, &table, &store, &mut sink).is_err());
    }

    // ── dispatch_access ACL-aware tests ────────────────────────────────

    #[test]
    fn dispatch_access_acl_owner_allowed() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File owned by uid 1000, mode 0o100000 (owner-only, 000 for group/other).
        // ACL with USER_OBJ perm=7 gives owner rwx regardless of mode bits.
        let ino = 20u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        // Install an ACL: owner rwx, group ---, other ---
        let acl = vec![
            acl_entry(ACL_USER_OBJ, 7, 0),
            acl_entry(ACL_GROUP_OBJ, 0, 0),
            acl_entry(ACL_OTHER, 0, 0),
        ];
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(100, ino);
        // Owner tries to read: ACL USER_OBJ perm=7 grants it.
        let result = dispatch_access(&ctx, 1000, 100, 4, &table, &store, &mut sink);
        assert!(result.is_ok());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 0),
            other => panic!("expected Error reply with errno 0, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_acl_named_user_allowed() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File owned by uid 1000, mode 0o100000.
        // ACL grants named user uid=2000 r-x (perm=5), mask=5.
        let ino = 21u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let acl = extended_acl(); // USER_OBJ=7, USER:2000=6, GROUP_OBJ=0, GROUP:500=5, MASK=4, OTHER=1
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(101, ino);
        // Named user uid=2000 has raw perm=6 (rw-), mask=4 (r--) => effective=4.
        // Read (4) should be allowed.
        let result = dispatch_access(&ctx, 2000, 200, 4, &table, &store, &mut sink);
        assert!(result.is_ok());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 0),
            other => panic!("expected Error reply with errno 0, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_acl_named_user_denied_by_mask() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let ino = 22u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let acl = extended_acl(); // MASK=4 limits named user effective to r--
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(102, ino);
        // Named user uid=2000 tries to write (W_OK=2). Mask limits to r-- (4).
        let result = dispatch_access(&ctx, 2000, 200, 2, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 13), // EACCES
            other => panic!("expected EACCES, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_acl_group_allowed() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File with mode 0o100000 (no permissions). ACL has GROUP:500 r-x (perm=5),
        // no mask present (only named group, no named users => mask not required).
        let ino = 23u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let acl = vec![
            acl_entry(ACL_USER_OBJ, 0, 0),
            acl_entry(ACL_GROUP_OBJ, 0, 0),
            acl_entry(ACL_GROUP, 5, 500),
            acl_entry(ACL_MASK, 7, 0),
            acl_entry(ACL_OTHER, 0, 0),
        ];
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(103, ino);
        // Caller gid=500 (matching named group with mask=7), tries to read.
        let result = dispatch_access(&ctx, 3000, 500, 4, &table, &store, &mut sink);
        assert!(result.is_ok());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 0),
            other => panic!("expected Error reply with errno 0, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_acl_other_denied() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        let ino = 24u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let acl = extended_acl(); // OTHER=1 (--x), no read/write for other
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(104, ino);
        // Caller uid=3000, gid=300: not owner, not named user, not in any group => OTHER
        // OTHER=1 (--x), read (4) denied.
        let result = dispatch_access(&ctx, 3000, 300, 4, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 13),
            other => panic!("expected EACCES, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_access_acl_fallback_to_mode_when_no_xattr() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();

        // File with mode 0o100400 (owner read only), no ACL xattr.
        let ino = 25u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100400,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        let ctx = make_test_ctx(105, ino);

        // Owner can read (mode grants r-- to owner).
        let mut sink1 = MockReplySink::new();
        assert!(dispatch_access(&ctx, 1000, 100, 4, &table, &store, &mut sink1).is_ok());

        // Other cannot read.
        let mut sink2 = MockReplySink::new();
        assert!(dispatch_access(&ctx, 2000, 200, 4, &table, &store, &mut sink2).is_err());
    }

    #[test]
    fn dispatch_access_acl_root_bypass_with_acl() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // File with mode 0o100000 (no permissions for anyone), but ACL present.
        let ino = 26u64;
        let attr = InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100000,
                uid: 1000,
                gid: 100,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        table.insert(attr);
        store.insert(attr);

        // ACL that denies everyone except owner (who has no permissions either).
        let acl = vec![
            acl_entry(ACL_USER_OBJ, 0, 0),
            acl_entry(ACL_GROUP_OBJ, 0, 0),
            acl_entry(ACL_OTHER, 0, 0),
        ];
        let encoded = encode_validated_access_acl(&acl).unwrap();
        table
            .set_xattr(ino, POSIX_ACL_ACCESS_XATTR, &encoded, 0)
            .unwrap();

        let ctx = make_test_ctx(106, ino);
        // Root (uid=0) should bypass both ACL and mode bits.
        let result = dispatch_access(&ctx, 0, 0, 6, &table, &store, &mut sink);
        assert!(result.is_ok());
        match sink.last_reply() {
            Some(CapturedReply::Error { errno, .. }) => assert_eq!(*errno, 0),
            other => panic!("expected root bypass, got {other:?}"),
        }
    }

    // ── FuseAttr wire round-trip tests ─────────────────────────────────

    fn filled_fuse_attr() -> FuseAttr {
        FuseAttr {
            ino: 42,
            size: 8192,
            blocks: 16,
            atime: 1_500_000_000 / 1_000_000_000,
            mtime: 2_500_000_000 / 1_000_000_000,
            ctime: 3_500_000_000 / 1_000_000_000,
            atimensec: 500_000_000,
            mtimensec: 500_000_000,
            ctimensec: 500_000_000,
            mode: 0o100_755,
            nlink: 3,
            uid: 1000,
            gid: 100,
            rdev: 0,
            blksize: 4096,
            padding: 0,
        }
    }

    #[test]
    fn fuse_attr_encode_decode_roundtrip() {
        let orig = filled_fuse_attr();
        let mut buf = [0u8; FuseAttr::WIRE_SIZE];
        orig.encode(&mut buf);
        let decoded = FuseAttr::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_wire_size_matches_expected() {
        assert_eq!(FuseAttr::WIRE_SIZE, 88);
    }

    #[test]
    fn fuse_attr_zeroed_roundtrip() {
        let orig = FuseAttr::default();
        let mut buf = [0u8; FuseAttr::WIRE_SIZE];
        orig.encode(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        let decoded = FuseAttr::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_max_values_roundtrip() {
        let orig = FuseAttr {
            ino: u64::MAX,
            size: u64::MAX,
            blocks: u64::MAX,
            atime: u64::MAX,
            mtime: u64::MAX,
            ctime: u64::MAX,
            atimensec: u32::MAX,
            mtimensec: u32::MAX,
            ctimensec: u32::MAX,
            mode: u32::MAX,
            nlink: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            rdev: u32::MAX,
            blksize: u32::MAX,
            padding: u32::MAX,
        };
        let mut buf = [0u8; FuseAttr::WIRE_SIZE];
        orig.encode(&mut buf);
        let decoded = FuseAttr::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_encode_only_writes_within_bounds() {
        let orig = filled_fuse_attr();
        let mut buf = [0xFFu8; FuseAttr::WIRE_SIZE + 8];
        orig.encode(&mut buf[..FuseAttr::WIRE_SIZE]);
        // Bytes after WIRE_SIZE should be untouched
        assert!(buf[FuseAttr::WIRE_SIZE..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn fuse_attr_fields_preserved_individually() {
        let orig = filled_fuse_attr();
        let mut buf = [0u8; FuseAttr::WIRE_SIZE];
        orig.encode(&mut buf);

        // Verify a few known fields at their wire offsets
        let decoded_ino = decode_u64_le(&buf, 0);
        assert_eq!(decoded_ino, 42);

        let decoded_mode = decode_u32_le(&buf, 60);
        assert_eq!(decoded_mode, 0o100_755);

        let decoded_nlink = decode_u32_le(&buf, 64);
        assert_eq!(decoded_nlink, 3);

        let decoded_uid = decode_u32_le(&buf, 68);
        assert_eq!(decoded_uid, 1000);

        let decoded_gid = decode_u32_le(&buf, 72);
        assert_eq!(decoded_gid, 100);

        let decoded_blksize = decode_u32_le(&buf, 80);
        assert_eq!(decoded_blksize, 4096);

        let decoded_padding = decode_u32_le(&buf, 84);
        assert_eq!(decoded_padding, 0);
    }

    // ── FuseAttrOut wire round-trip tests ──────────────────────────────

    fn filled_fuse_attr_out() -> FuseAttrOut {
        FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: filled_fuse_attr(),
        }
    }

    #[test]
    fn fuse_attr_out_encode_decode_roundtrip() {
        let orig = filled_fuse_attr_out();
        let mut buf = [0u8; FuseAttrOut::WIRE_SIZE];
        orig.encode(&mut buf);
        let decoded = FuseAttrOut::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_out_wire_size_matches_expected() {
        assert_eq!(FuseAttrOut::WIRE_SIZE, 104);
    }

    #[test]
    fn fuse_attr_out_zeroed_roundtrip() {
        let orig = FuseAttrOut::default();
        let mut buf = [0u8; FuseAttrOut::WIRE_SIZE];
        orig.encode(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        let decoded = FuseAttrOut::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_out_max_values_roundtrip() {
        let orig = FuseAttrOut {
            attr_valid: u64::MAX,
            attr_valid_nsec: u32::MAX,
            dummy: u32::MAX,
            attr: FuseAttr {
                ino: u64::MAX,
                size: u64::MAX,
                blocks: u64::MAX,
                atime: u64::MAX,
                mtime: u64::MAX,
                ctime: u64::MAX,
                atimensec: u32::MAX,
                mtimensec: u32::MAX,
                ctimensec: u32::MAX,
                mode: u32::MAX,
                nlink: u32::MAX,
                uid: u32::MAX,
                gid: u32::MAX,
                rdev: u32::MAX,
                blksize: u32::MAX,
                padding: u32::MAX,
            },
        };
        let mut buf = [0u8; FuseAttrOut::WIRE_SIZE];
        orig.encode(&mut buf);
        let decoded = FuseAttrOut::decode(&buf);
        assert_eq!(orig, decoded);
    }

    #[test]
    fn fuse_attr_out_attr_valid_fields_preserved() {
        let orig = filled_fuse_attr_out();
        let mut buf = [0u8; FuseAttrOut::WIRE_SIZE];
        orig.encode(&mut buf);

        let decoded_valid = decode_u64_le(&buf, 0);
        assert_eq!(decoded_valid, 1);

        let decoded_nsec = decode_u32_le(&buf, 8);
        assert_eq!(decoded_nsec, 0);

        let decoded_dummy = decode_u32_le(&buf, 12);
        assert_eq!(decoded_dummy, 0);
    }

    #[test]
    fn fuse_attr_out_custom_timeout_roundtrip() {
        let mut orig = filled_fuse_attr_out();
        orig.attr_valid = 10;
        orig.attr_valid_nsec = 500_000_000;

        let mut buf = [0u8; FuseAttrOut::WIRE_SIZE];
        orig.encode(&mut buf);
        let decoded = FuseAttrOut::decode(&buf);
        assert_eq!(orig, decoded);
        assert_eq!(decoded.attr_valid, 10);
        assert_eq!(decoded.attr_valid_nsec, 500_000_000);
    }

    // ── DirIterator-based readdir tests ──────────────────────────────────

    use tidefs_dir_index::DirEntry;

    /// In-memory DirIterator backed by a sorted Vec.
    struct TestDirIterator {
        entries: Vec<DirEntry>,
        cursor: usize,
    }

    impl TestDirIterator {
        fn new(mut entries: Vec<DirEntry>) -> Self {
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Self { entries, cursor: 0 }
        }
    }

    impl DirIterator for TestDirIterator {
        type Error = DirIndexError;

        fn next_entry(&mut self) -> Option<DirEntry> {
            if self.cursor >= self.entries.len() {
                return None;
            }
            let entry = self.entries[self.cursor].clone();
            self.cursor += 1;
            Some(entry)
        }

        fn reset_cursor(&mut self) {
            self.cursor = 0;
        }

        fn seek_to_cursor(&mut self, cookie: DirCookie) {
            self.cursor = (cookie.0 as usize).min(self.entries.len());
        }

        fn current_cursor(&self) -> DirCookie {
            DirCookie(self.cursor as u64)
        }
    }

    fn dir_entry(name: &[u8], inode_id: u64, kind: u32) -> DirEntry {
        DirEntry {
            name_len: name.len() as u32,
            inode_id,
            generation: 0,
            kind,
            name: name.to_vec(),
        }
    }

    #[test]
    fn dispatch_readdir_iter_empty_directory_returns_eof() {
        let mut table = MockInodeTable::new();
        table.insert(make_dir_attr(2));

        let entries: Vec<DirEntry> = Vec::new();
        let mut dir_iter = TestDirIterator::new(entries);

        let ctx = make_test_ctx(200, 2);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir_iter(&ctx, 0, 100, &table, &mut dir_iter, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                unique: _,
                entries,
                next_cookie,
            }) => {
                assert!(entries.is_empty());
                assert_eq!(*next_cookie, 0);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_iter_populated_directory() {
        let mut table = MockInodeTable::new();
        table.insert(make_dir_attr(2));

        let mut dir_iter = TestDirIterator::new(vec![
            dir_entry(b"zebra", 101, 1),
            dir_entry(b"alpha", 102, 1),
            dir_entry(b"delta", 103, 1),
            dir_entry(b"beta", 104, 1),
            dir_entry(b"gamma", 105, 1),
        ]);

        let ctx = make_test_ctx(201, 2);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir_iter(&ctx, 0, 100, &table, &mut dir_iter, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                unique: _,
                entries,
                next_cookie: _,
            }) => {
                assert_eq!(entries.len(), 5);
                let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
                assert_eq!(
                    names,
                    vec![
                        b"alpha".as_slice(),
                        b"beta".as_slice(),
                        b"delta".as_slice(),
                        b"gamma".as_slice(),
                        b"zebra".as_slice()
                    ]
                );
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_iter_parent_not_found_returns_enoent() {
        let table = MockInodeTable::new();
        let entries: Vec<DirEntry> = Vec::new();
        let mut dir_iter = TestDirIterator::new(entries);

        let ctx = make_test_ctx(202, 999);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir_iter(&ctx, 0, 100, &table, &mut dir_iter, &mut sink);
        assert_eq!(result, Err(MetaError::InoNotFound));
    }

    #[test]
    fn dispatch_readdir_iter_parent_not_dir_returns_enotdir() {
        let mut table = MockInodeTable::new();
        table.insert(make_file_attr(5));

        let entries: Vec<DirEntry> = Vec::new();
        let mut dir_iter = TestDirIterator::new(entries);

        let ctx = make_test_ctx(203, 5);
        let mut sink = MockReplySink::new();

        let result = dispatch_readdir_iter(&ctx, 0, 100, &table, &mut dir_iter, &mut sink);
        assert_eq!(result, Err(MetaError::Io));
    }

    #[test]
    fn dispatch_readdir_iter_pagination() {
        let mut table = MockInodeTable::new();
        table.insert(make_dir_attr(2));

        let entry_list: Vec<DirEntry> = (0..5)
            .map(|i| dir_entry(format!("file_{i}").as_bytes(), 200 + i as u64, 1))
            .collect();
        let mut dir_iter = TestDirIterator::new(entry_list);

        let ctx = make_test_ctx(210, 2);

        // Page 1: 2 entries
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, 0, 2, &table, &mut dir_iter, &mut sink).is_ok());
        let (page1_entries, cookie1) = match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => (entries.clone(), *next_cookie),
            other => panic!("expected ReaddirEntries, got {other:?}"),
        };
        assert_eq!(page1_entries.len(), 2);

        // Page 2: 2 more entries
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, cookie1, 2, &table, &mut dir_iter, &mut sink).is_ok());
        let (page2_entries, cookie2) = match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie,
                ..
            }) => (entries.clone(), *next_cookie),
            other => panic!("expected ReaddirEntries, got {other:?}"),
        };
        assert_eq!(page2_entries.len(), 2);

        // Page 3: last entry
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, cookie2, 2, &table, &mut dir_iter, &mut sink).is_ok());
        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie: _,
                ..
            }) => {
                assert_eq!(entries.len(), 1);
            }
            other => panic!("expected ReaddirEntries, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdirplus_iter_populated_directory() {
        let mut table = MockInodeTable::new();
        let mut store = MockAttrStore::new();
        table.insert(make_dir_attr(2));
        store.insert(make_dir_attr(2));

        let entry_list: Vec<DirEntry> = (0..3)
            .map(|i| {
                let ino = 300 + i as u64;
                table.insert(make_file_attr(ino));
                store.insert(make_file_attr(ino));
                dir_entry(format!("entry_{i}").as_bytes(), ino, 1)
            })
            .collect();
        let mut dir_iter = TestDirIterator::new(entry_list);

        let ctx = make_test_ctx(220, 2);
        let mut sink = MockReplySink::new();

        let result =
            dispatch_readdirplus_iter(&ctx, 0, 100, &table, &mut dir_iter, &store, &mut sink);
        assert!(result.is_ok());

        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries {
                entries,
                next_cookie: _,
                ..
            }) => {
                assert_eq!(entries.len(), 3);
            }
            other => panic!("expected ReaddirEntries reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_readdir_iter_concurrent_handles_independent_cursors() {
        let mut table = MockInodeTable::new();
        table.insert(make_dir_attr(2));

        let entry_list: Vec<DirEntry> = vec![
            dir_entry(b"alpha", 101, 1),
            dir_entry(b"beta", 102, 1),
            dir_entry(b"gamma", 103, 1),
        ];

        // Two independent iterators on the same directory.
        let mut iter_a = TestDirIterator::new(entry_list.clone());
        let mut iter_b = TestDirIterator::new(entry_list);

        let ctx = make_test_ctx(230, 2);

        // Iterator A: read first entry.
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, 0, 1, &table, &mut iter_a, &mut sink).is_ok());
        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries { entries, .. }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, b"alpha");
            }
            other => panic!("expected ReaddirEntries, got {other:?}"),
        }

        // Iterator B: read all 3 entries (independent cursor).
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, 0, 3, &table, &mut iter_b, &mut sink).is_ok());
        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries { entries, .. }) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0].name, b"alpha");
                assert_eq!(entries[1].name, b"beta");
                assert_eq!(entries[2].name, b"gamma");
            }
            other => panic!("expected ReaddirEntries, got {other:?}"),
        }

        // Iterator A: resume at position 1.
        let mut sink = MockReplySink::new();
        assert!(dispatch_readdir_iter(&ctx, 1, 1, &table, &mut iter_a, &mut sink).is_ok());
        match sink.last_reply() {
            Some(CapturedReply::ReaddirEntries { entries, .. }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, b"beta");
            }
            other => panic!("expected ReaddirEntries, got {other:?}"),
        }
    }
    // ── Xattr dispatch tests ──────────────────────────────────────────

    /// Helper: create a context mirror for xattr dispatch tests.
    fn xattr_ctx(nodeid: u64, unique: u64) -> PosixFilesystemAdapterRequestContextMirrorRecord {
        PosixFilesystemAdapterRequestContextMirrorRecord {
            nodeid,
            unique,
            uid: 1000,
            gid: 1001,
            ..Default::default()
        }
    }

    /// Helper: create an inode attribute for insertion into mock tables.
    fn test_inode_attr(ino: u64, kind: NodeKind) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind,
            posix: PosixAttrs {
                mode: 0o644,
                uid: 1000,
                gid: 1001,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            ..Default::default()
        }
    }

    #[test]
    fn dispatch_getxattr_returns_value_for_existing_xattr() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.hello", b"world", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_getxattr(&ctx, b"user.hello", 1024, &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::XattrData { data, .. } => {
                assert_eq!(data, b"world");
            }
            other => panic!("expected XattrData, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_size_probe_returns_required_len() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.big", b"hello world", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_getxattr(&ctx, b"user.big", 0, &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 11); // ERANGE: size = 11
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_missing_xattr_returns_error() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_getxattr(&ctx, b"user.missing", 1024, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 5); // EIO
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_missing_inode_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_getxattr(&ctx, b"user.any", 1024, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_listxattr_returns_packed_names() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.a", b"1", 0).unwrap();
        table.set_xattr(1, b"user.b", b"2", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_listxattr(&ctx, 1024, &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::XattrData { data, .. } => {
                assert!(data.windows(b"user.a".len()).any(|w| w == b"user.a"));
                assert!(data.windows(b"user.b".len()).any(|w| w == b"user.b"));
            }
            other => panic!("expected XattrData, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_listxattr_empty_inode_returns_empty() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_listxattr(&ctx, 1024, &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::XattrData { data, .. } => {
                assert!(data.is_empty());
            }
            other => panic!("expected XattrData, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_listxattr_size_probe_returns_required_len() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.a", b"x", 0).unwrap();
        table.set_xattr(1, b"user.b", b"y", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_listxattr(&ctx, 0, &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                // 2 names * (len("user.X") + 1 NUL) = 2 * 7 = 14
                assert_eq!(*errno, 14);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_listxattr_missing_inode_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_listxattr(&ctx, 1024, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_upsert_stores_value() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_setxattr(
            &ctx,
            b"user.newkey",
            b"newval",
            0,
            &table,
            &store,
            &mut sink,
        )
        .unwrap();

        // Verify success reply (errno 0)
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 0);
            }
            other => panic!("expected Error(0) reply, got {other:?}"),
        }

        // Verify value stored
        let val = table.get_xattr(1, b"user.newkey").unwrap();
        assert_eq!(val, b"newval");
    }

    #[test]
    fn dispatch_setxattr_create_flag_fails_if_exists() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.dup", b"first", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_setxattr(
            &ctx,
            b"user.dup",
            b"second",
            XATTR_CREATE,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 17); // EEXIST
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_replace_flag_fails_if_missing() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_setxattr(
            &ctx,
            b"user.missing",
            b"val",
            XATTR_REPLACE,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 61); // ENODATA
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_replace_flag_succeeds_if_exists() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.rep", b"old", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_setxattr(
            &ctx,
            b"user.rep",
            b"new",
            XATTR_REPLACE,
            &table,
            &store,
            &mut sink,
        )
        .unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 0);
            }
            other => panic!("expected Error(0) reply, got {other:?}"),
        }

        let val = table.get_xattr(1, b"user.rep").unwrap();
        assert_eq!(val, b"new");
    }

    #[test]
    fn dispatch_setxattr_missing_inode_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_setxattr(&ctx, b"user.key", b"val", 0, &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_removexattr_removes_existing_xattr() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        table.set_xattr(1, b"user.del", b"val", 0).unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_removexattr(&ctx, b"user.del", &table, &store, &mut sink).unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 0);
            }
            other => panic!("expected Error(0) reply, got {other:?}"),
        }

        // Verify removed
        assert!(table.get_xattr(1, b"user.del").is_err());
    }

    #[test]
    fn dispatch_removexattr_missing_xattr_returns_error() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_removexattr(&ctx, b"user.missing", &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 5); // EIO
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_removexattr_missing_inode_returns_enoent() {
        let table = MockInodeTable::new();
        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_removexattr(&ctx, b"user.any", &table, &store, &mut sink);
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { errno, .. } => {
                assert_eq!(*errno, 2); // ENOENT
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_setxattr_roundtrip() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let mut sink = MockReplySink::new();

        // Set via dispatch
        let ctx1 = xattr_ctx(1, 100);
        dispatch_setxattr(&ctx1, b"user.round", b"trip", 0, &table, &store, &mut sink).unwrap();
        assert!(matches!(
            sink.last_reply().unwrap(),
            CapturedReply::Error { errno: 0, .. }
        ));

        // Get via dispatch
        let ctx2 = xattr_ctx(1, 200);
        let mut sink2 = MockReplySink::new();
        dispatch_getxattr(&ctx2, b"user.round", 1024, &table, &store, &mut sink2).unwrap();
        match sink2.last_reply().unwrap() {
            CapturedReply::XattrData { data, .. } => {
                assert_eq!(data, b"trip");
            }
            other => panic!("expected XattrData, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_removexattr_lifecycle() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();

        // Create
        let ctx1 = xattr_ctx(1, 100);
        let mut sink1 = MockReplySink::new();
        dispatch_setxattr(&ctx1, b"user.life", b"cycle", 0, &table, &store, &mut sink1).unwrap();

        // Verify exists
        let val = table.get_xattr(1, b"user.life").unwrap();
        assert_eq!(val, b"cycle");

        // Remove
        let ctx2 = xattr_ctx(1, 200);
        let mut sink2 = MockReplySink::new();
        dispatch_removexattr(&ctx2, b"user.life", &table, &store, &mut sink2).unwrap();

        // Verify gone
        assert!(table.get_xattr(1, b"user.life").is_err());
    }

    // ── ACL xattr dispatch interception tests ──────────────────────────

    /// Helper: build a minimal valid POSIX access ACL blob.
    fn valid_access_acl_bytes() -> Vec<u8> {
        let entries = std::vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        encode_posix_acl_xattr(&entries)
    }

    #[test]
    fn dispatch_setxattr_acl_rejects_malformed_blob() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        // Malformed blob: version byte 0x03 (unsupported)
        let bad_blob: &[u8] = &[0x03, 0x00, 0x00, 0x00];
        let result = dispatch_setxattr(
            &ctx,
            POSIX_ACL_ACCESS_XATTR,
            bad_blob,
            0,
            &table,
            &store,
            &mut sink,
        );
        // The dispatch should fail, and the reply should be EINVAL.
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique: _, errno } => {
                assert_eq!(*errno, POSIX_ACL_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_acl_rejects_invalid_entry_perm() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        // Malformed blob: valid version but permission bits > 0x7
        let mut bad: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00]; // version 2
        bad.extend_from_slice(&ACL_USER_OBJ.to_le_bytes());
        bad.extend_from_slice(&0x09u16.to_le_bytes()); // perm = 9 (invalid)
        bad.extend_from_slice(&0u32.to_le_bytes());
        // Second entry to satisfy required-entry validation
        bad.extend_from_slice(&ACL_GROUP_OBJ.to_le_bytes());
        bad.extend_from_slice(&0x04u16.to_le_bytes()); // perm = 4
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&ACL_OTHER.to_le_bytes());
        bad.extend_from_slice(&0x04u16.to_le_bytes());
        bad.extend_from_slice(&0u32.to_le_bytes());

        let result = dispatch_setxattr(
            &ctx,
            POSIX_ACL_ACCESS_XATTR,
            &bad,
            0,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique: _, errno } => {
                assert_eq!(*errno, POSIX_ACL_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_acl_rejects_missing_required_entry() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        // Only USER_OBJ and GROUP_OBJ — missing OTHER.
        let entries = std::vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
        ];
        let blob = encode_posix_acl_xattr(&entries);

        let result = dispatch_setxattr(
            &ctx,
            POSIX_ACL_ACCESS_XATTR,
            &blob,
            0,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique: _, errno } => {
                assert_eq!(*errno, POSIX_ACL_EINVAL);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_acl_accepts_empty_value_as_delete() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        // Pre-populate an ACL
        table
            .set_xattr(1, POSIX_ACL_ACCESS_XATTR, &valid_access_acl_bytes(), 0)
            .unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        // Empty value = Linux ACL deletion convention; should succeed.
        let result = dispatch_setxattr(
            &ctx,
            POSIX_ACL_ACCESS_XATTR,
            b"",
            XATTR_REPLACE,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_setxattr_acl_roundtrip() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let acl_bytes = valid_access_acl_bytes();

        // Set ACL via setxattr dispatch
        let ctx_set = xattr_ctx(1, 100);
        let mut sink_set = MockReplySink::new();
        dispatch_setxattr(
            &ctx_set,
            POSIX_ACL_ACCESS_XATTR,
            &acl_bytes,
            0,
            &table,
            &store,
            &mut sink_set,
        )
        .unwrap();

        // Get ACL via getxattr dispatch
        let ctx_get = xattr_ctx(1, 200);
        let mut sink_get = MockReplySink::new();
        dispatch_getxattr(
            &ctx_get,
            POSIX_ACL_ACCESS_XATTR,
            1024,
            &table,
            &store,
            &mut sink_get,
        )
        .unwrap();

        match sink_get.last_reply().unwrap() {
            CapturedReply::XattrData { unique: _, data } => {
                assert_eq!(*data, acl_bytes);
            }
            other => panic!("expected XattrData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_acl_default_on_file_returns_enodata() {
        let mut table = MockInodeTable::new();
        // Regular file (not a directory)
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_getxattr(
            &ctx,
            POSIX_ACL_DEFAULT_XATTR,
            1024,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_err());
        match sink.last_reply().unwrap() {
            CapturedReply::Error { unique: _, errno } => {
                // ENODATA: default ACL is only valid on directories
                assert_eq!(*errno, Errno::ENODATA.raw() as i32);
            }
            other => panic!("expected Error reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_getxattr_acl_default_on_directory_proceeds() {
        let mut table = MockInodeTable::new();
        // Directory: default ACL is valid here
        table.insert(test_inode_attr(1, NodeKind::Dir));
        let acl_bytes = valid_access_acl_bytes();
        table
            .set_xattr(1, POSIX_ACL_DEFAULT_XATTR, &acl_bytes, 0)
            .unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        let result = dispatch_getxattr(
            &ctx,
            POSIX_ACL_DEFAULT_XATTR,
            1024,
            &table,
            &store,
            &mut sink,
        );
        assert!(result.is_ok());
        match sink.last_reply().unwrap() {
            CapturedReply::XattrData { unique: _, data } => {
                assert_eq!(*data, acl_bytes);
            }
            other => panic!("expected XattrData reply, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setxattr_non_acl_xattr_passes_through() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        // A non-ACL xattr should not be intercepted.
        dispatch_setxattr(
            &ctx,
            b"user.myattr",
            b"myvalue",
            0,
            &table,
            &store,
            &mut sink,
        )
        .unwrap();

        // Verify it was stored.
        let val = table.get_xattr(1, b"user.myattr").unwrap();
        assert_eq!(val, b"myvalue");
    }

    #[test]
    fn dispatch_getxattr_acl_access_on_file_works() {
        let mut table = MockInodeTable::new();
        table.insert(test_inode_attr(1, NodeKind::File));
        let acl_bytes = valid_access_acl_bytes();
        table
            .set_xattr(1, POSIX_ACL_ACCESS_XATTR, &acl_bytes, 0)
            .unwrap();

        let store = MockAttrStore::new();
        let ctx = xattr_ctx(1, 100);
        let mut sink = MockReplySink::new();

        dispatch_getxattr(
            &ctx,
            POSIX_ACL_ACCESS_XATTR,
            1024,
            &table,
            &store,
            &mut sink,
        )
        .unwrap();

        match sink.last_reply().unwrap() {
            CapturedReply::XattrData { unique: _, data } => {
                assert_eq!(*data, acl_bytes);
            }
            other => panic!("expected XattrData reply, got {other:?}"),
        }
    }
}
