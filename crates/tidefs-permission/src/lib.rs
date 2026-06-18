// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_imports)]
#![deny(dead_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_debug_implementations)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unused_must_use)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Unix discretionary-access-control engine: mode-bit permission checking,
//! POSIX ACL evaluation, unified access-decision API, and xattr namespace
//! validation.
//!
//! Re-exports canonical ACL types and codec from [`tidefs_posix_acl`] so
//! callers only need a single permission dependency.
//!
//! # Access checking quick-start
//!
//! ```ignore
//! use tidefs_permission::{InodeAttr, MountIdentity, check_access, ACCESS_READ};
//!
//! struct MyInode { uid: u32, gid: u32, mode: u32 }
//! impl InodeAttr for MyInode {
//!     fn uid(&self) -> u32 { self.uid }
//!     fn gid(&self) -> u32 { self.gid }
//!     fn mode(&self) -> u32 { self.mode }
//! }
//!
//! let ino = MyInode { uid: 1000, gid: 100, mode: 0o644 };
//! let mount_id = MountIdentity::new([1u8; 16], 1);
//! if check_access(&ino, None, 1000, 100, &[], ACCESS_READ, &mount_id) {
//!     // access granted
//! }
//! ```

extern crate alloc;

pub use tidefs_posix_acl::*;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// InodeId
// ---------------------------------------------------------------------------

/// Inode identifier used to key xattr storage.
pub type InodeId = u64;

// ---------------------------------------------------------------------------
// MountIdentity — committed dataset mount identity token
// ---------------------------------------------------------------------------

/// Committed dataset mount identity token.
///
/// Binds every permission evaluation to the specific dataset mount. A zero
/// or default [`MountIdentity`] is invalid and causes permission checks to
/// fail closed. The mount epoch increments on each dataset mount, ensuring
/// that stale mounts cannot reuse privileges from a prior mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MountIdentity {
    /// Dataset UUID (16 bytes).
    pub dataset_id: [u8; 16],
    /// Mount epoch — incremented on each dataset mount.
    pub mount_epoch: u64,
}

impl MountIdentity {
    /// Create a new mount identity.
    #[must_use]
    pub const fn new(dataset_id: [u8; 16], mount_epoch: u64) -> Self {
        Self {
            dataset_id,
            mount_epoch,
        }
    }

    /// Returns `true` when this mount identity has a non-zero epoch.
    ///
    /// The all-zero dataset id is reserved by current TideFS storage as the
    /// root dataset, so the epoch is the invalid/default discriminator.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.mount_epoch > 0
    }
}

impl Default for MountIdentity {
    fn default() -> Self {
        Self {
            dataset_id: [0u8; 16],
            mount_epoch: 0,
        }
    }
}

/// Error returned when a mount identity validation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MountIdentityError {
    /// The mount identity is invalid (zero epoch).
    InvalidMountIdentity,
}

impl core::fmt::Display for MountIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMountIdentity => write!(f, "invalid mount identity"),
        }
    }
}

/// Validate that `mount_identity` is valid (non-zero epoch).
/// Returns `Ok(())` when valid, or
/// `Err(MountIdentityError::InvalidMountIdentity)` when invalid.
#[inline]
#[allow(dead_code)]
pub fn validate_mount_identity(mount_identity: &MountIdentity) -> Result<(), MountIdentityError> {
    if mount_identity.is_valid() {
        Ok(())
    } else {
        Err(MountIdentityError::InvalidMountIdentity)
    }
}

// ---------------------------------------------------------------------------
// Permission bit constants (classic Unix rwx)
// ---------------------------------------------------------------------------

/// Read permission for owner.
pub const S_IRUSR: u32 = 0o400;
/// Write permission for owner.
pub const S_IWUSR: u32 = 0o200;
/// Execute permission for owner.
pub const S_IXUSR: u32 = 0o100;
/// Read permission for group.
pub const S_IRGRP: u32 = 0o040;
/// Write permission for group.
pub const S_IWGRP: u32 = 0o020;
/// Execute permission for group.
pub const S_IXGRP: u32 = 0o010;
/// Read permission for other.
pub const S_IROTH: u32 = 0o004;
/// Write permission for other.
pub const S_IWOTH: u32 = 0o002;
/// Execute permission for other.
pub const S_IXOTH: u32 = 0o001;

/// Set-user-ID.
pub const S_ISUID: u32 = 0o4000;
/// Set-group-ID.
pub const S_ISGID: u32 = 0o2000;
/// Sticky bit.
pub const S_ISVTX: u32 = 0o1000;

// ---------------------------------------------------------------------------
// File type constants (classic Unix S_IFMT bits)
// ---------------------------------------------------------------------------

/// File type mask (S_IFMT).
pub const S_IFMT: u32 = 0o170000;
/// Regular file (S_IFREG).
pub const S_IFREG: u32 = 0o100000;
/// Directory (S_IFDIR).
pub const S_IFDIR: u32 = 0o040000;
/// Character device (S_IFCHR).
pub const S_IFCHR: u32 = 0o020000;
/// Block device (S_IFBLK).
pub const S_IFBLK: u32 = 0o060000;
/// FIFO / named pipe (S_IFIFO).
pub const S_IFIFO: u32 = 0o010000;
/// Symbolic link (S_IFLNK).
pub const S_IFLNK: u32 = 0o120000;

// ---------------------------------------------------------------------------
// Access check flags
// ---------------------------------------------------------------------------

/// Request read access.
pub const ACCESS_READ: u8 = 0x04;
/// Request write access.
pub const ACCESS_WRITE: u8 = 0x02;
/// Request execute / lookup access.
pub const ACCESS_EXECUTE: u8 = 0x01;
/// Request read + write (for convenience).
pub const ACCESS_RDWR: u8 = ACCESS_READ | ACCESS_WRITE;
/// Request read + write + execute.
pub const ACCESS_RWX: u8 = ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE;
/// No permission bits requested; callers use this after proving existence.
pub const ACCESS_NONE: u8 = 0;
/// Valid permission request bits.
pub const ACCESS_VALID_MASK: u8 = ACCESS_RWX;

// ---------------------------------------------------------------------------
// Access request validation
// ---------------------------------------------------------------------------

/// Error returned when an access request contains unsupported bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRequestError {
    /// Requested access contains bits outside
    /// [`ACCESS_READ`] | [`ACCESS_WRITE`] | [`ACCESS_EXECUTE`].
    InvalidMask {
        /// Original requested access mask.
        requested: u8,
        /// Unsupported bits present in `requested`.
        invalid_bits: u8,
    },
}

/// Validate that `requested` contains only supported permission bits.
pub fn validate_access_request(requested: u8) -> Result<(), AccessRequestError> {
    let invalid_bits = requested & !ACCESS_VALID_MASK;
    if invalid_bits == 0 {
        Ok(())
    } else {
        Err(AccessRequestError::InvalidMask {
            requested,
            invalid_bits,
        })
    }
}

// ---------------------------------------------------------------------------
// PermissionError — denial result with errno mapping
// ---------------------------------------------------------------------------

/// Error returned when discretionary access control denies an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionError {
    /// Permission denied (EACCES): the caller lacks the required access
    /// bits on the target inode.
    AccessDenied,
}

impl PermissionError {
    /// Map this permission error to the closest POSIX errno.
    #[must_use]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::AccessDenied => 13, // EACCES
        }
    }
}

impl core::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AccessDenied => write!(f, "permission denied"),
        }
    }
}

// ---------------------------------------------------------------------------
// AccessMode — discrete access request
// ---------------------------------------------------------------------------

/// Discrete access mode requested by a caller.
///
/// Unlike the bitmask constants ([], [], etc.),
/// this enum expresses the single action being attempted (read, write,
/// execute, or read+write for O_RDWR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read access (O_RDONLY equivalent).
    Read,
    /// Write access (O_WRONLY equivalent).
    Write,
    /// Execute / search access (X_OK equivalent).
    Execute,
    /// Read + write access (O_RDWR equivalent).
    ReadWrite,
}

impl AccessMode {
    /// Convert this [] to a bitmask suitable for
    /// [] or [].
    #[must_use]
    pub const fn to_mask(self) -> u8 {
        match self {
            Self::Read => ACCESS_READ,
            Self::Write => ACCESS_WRITE,
            Self::Execute => ACCESS_EXECUTE,
            Self::ReadWrite => ACCESS_RDWR,
        }
    }
}

// ---------------------------------------------------------------------------
// Result-returning access check (wired into FUSE handlers)
// ---------------------------------------------------------------------------

/// Check whether `(uid, gid)` is allowed the `requested` access against
/// the classic Unix permission bits in `inode.mode()`.
///
/// # Root override
///
/// `uid == 0` (root) bypasses all discretionary access checks except
/// execute on a non-executable regular file (POSIX rule: root may not
/// execute a regular file that has no execute bits set for anyone).
/// Root always retains directory search permission.
///
/// # Algorithm
///
/// 1. If the caller is the file owner, use the owner bits.
/// 2. Else if the caller's gid matches the file's gid, use the group bits.
/// 3. Otherwise, use the other bits.
///
/// Returns `Ok(())` when the requested access is granted, or
/// `Err(PermissionError::AccessDenied)` when denied.
pub fn check_access_result(
    inode: &dyn InodeAttr,
    uid: u32,
    gid: u32,
    requested: AccessMode,
    mount_identity: &MountIdentity,
) -> Result<(), PermissionError> {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return Err(PermissionError::AccessDenied);
    }

    let mask = requested.to_mask();

    // Root override with execute-on-regular-file restriction
    if uid == 0 {
        let mode = inode.mode();
        if requested == AccessMode::Execute
            && (mode & S_IFMT) == S_IFREG
            && (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0
        {
            return Err(PermissionError::AccessDenied);
        }
        return Ok(());
    }

    let mode = inode.mode();
    let perm_bits = mode_permission_bits_result(mode, inode, uid, gid);
    if (perm_bits & mask) == mask {
        Ok(())
    } else {
        Err(PermissionError::AccessDenied)
    }
}

/// Return the effective 3-bit permission set (`0..7`) from mode bits
/// for the given caller, *without* root override.
fn mode_permission_bits_result(mode: u32, inode: &dyn InodeAttr, uid: u32, gid: u32) -> u8 {
    if uid == inode.uid() {
        ((mode >> 6) & 0x7) as u8
    } else if gid == inode.gid() {
        ((mode >> 3) & 0x7) as u8
    } else {
        (mode & 0x7) as u8
    }
}

/// Check directory search (execute) permission for path traversal.
///
/// This is the POSIX directory execute-bit check: a caller must have
/// execute permission on a directory to traverse it, regardless of
/// read permission on the directory contents.
///
/// Root (uid 0) always retains directory search permission, matching
/// standard Unix semantics (root may always traverse directories).
///
/// Returns `Ok(())` when traversal is allowed, or
/// `Err(PermissionError::AccessDenied)` when denied.
pub fn check_search(
    inode: &dyn InodeAttr,
    uid: u32,
    gid: u32,
    mount_identity: &MountIdentity,
) -> Result<(), PermissionError> {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return Err(PermissionError::AccessDenied);
    }

    if uid == 0 {
        return Ok(());
    }

    let mode = inode.mode();
    let perm_bits = mode_permission_bits_result(mode, inode, uid, gid);
    if (perm_bits & ACCESS_EXECUTE) != 0 {
        Ok(())
    } else {
        Err(PermissionError::AccessDenied)
    }
}

// ---------------------------------------------------------------------------
// InodeAttr trait
// ---------------------------------------------------------------------------

/// Trait for types that expose the POSIX ownership and mode metadata
/// needed for discretionary access control.
///
/// Implementations are expected in crates such as `tidefs-inode-table`
/// (`IN-001`) that hold per-inode `uid`, `gid`, and `mode`.
pub trait InodeAttr {
    /// Owner user id.
    fn uid(&self) -> u32;
    /// Owning group id.
    fn gid(&self) -> u32;
    /// File mode (type + permission bits).
    fn mode(&self) -> u32;
}

// ---------------------------------------------------------------------------
// Mode permission checker – classic owner / group / other logic
// ---------------------------------------------------------------------------

/// Check whether `(uid, gid, groups)` is allowed `requested` access against
/// the classic Unix permission bits in `attrs.mode()`.
///
/// # Root override
///
/// `uid == 0` (root) is always granted access regardless of permission bits,
/// matching standard Unix semantics.
///
/// # Algorithm
///
/// 1. If the caller is the file owner, use the owner (high) bits.
/// 2. Else if the caller's gid matches the file's gid, or any supplementary
///    group matches the file's gid, use the group (middle) bits.
/// 3. Otherwise, use the other (low) bits.
///
/// Returns `true` when all bits in `requested` are present in the applicable
/// permission set.
pub fn check_mode_access(
    attrs: &dyn InodeAttr,
    uid: u32,
    gid: u32,
    groups: &[u32],
    requested: u8,
    mount_identity: &MountIdentity,
) -> bool {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return false;
    }

    // Root bypasses most DAC checks, but may not execute a regular file
    // that has no execute bits set for anyone (POSIX rule).
    if uid == 0 {
        if (requested & ACCESS_EXECUTE) != 0
            && (attrs.mode() & S_IFMT) == S_IFREG
            && (attrs.mode() & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0
        {
            return false;
        }
        return true;
    }

    let mode = attrs.mode();
    let perm_bits = mode_permission_bits(mode, attrs, uid, gid, groups);
    (perm_bits & requested) == requested
}

/// Return the effective 3-bit permission set (`0..7`) from mode bits
/// for the given caller, *without* root override.
fn mode_permission_bits(
    mode: u32,
    attrs: &dyn InodeAttr,
    uid: u32,
    gid: u32,
    groups: &[u32],
) -> u8 {
    if uid == attrs.uid() {
        ((mode >> 6) & 0x7) as u8
    } else if gid == attrs.gid() || groups.contains(&attrs.gid()) {
        ((mode >> 3) & 0x7) as u8
    } else {
        (mode & 0x7) as u8
    }
}

// ---------------------------------------------------------------------------
// Unified access check – ACL-first, mode-fallback
// ---------------------------------------------------------------------------

/// Unified discretionary access check.
///
/// When `acl` is `Some` and non-empty, delegates to
/// [`posix_acl_perm_bits_for_caller`] from `tidefs-posix-acl` and then
/// checks the resulting bits against `requested`.  When `acl` is `None`
/// or empty, falls back to [`check_mode_access`].
///
/// # Parameters
///
/// - `attrs` — inode attributes providing uid, gid, and mode.
/// - `acl` — optional access ACL. `None` or an empty slice means
///   "no ACL present; use mode bits".
/// - `uid`, `gid`, `groups` — caller credentials.
/// - `requested` — bitmask of `ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE`.
///
/// Returns `true` when all requested bits are granted.
pub fn check_access(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    requested: u8,
    mount_identity: &MountIdentity,
) -> bool {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return false;
    }

    // Root (uid 0) bypasses most DAC checks, but may not execute a regular
    // file that has no execute bits set for anyone (POSIX rule).  This
    // applies regardless of whether an ACL is present.
    if uid == 0 {
        if (requested & ACCESS_EXECUTE) != 0
            && (attrs.mode() & S_IFMT) == S_IFREG
            && (attrs.mode() & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0
        {
            return false;
        }
        return true;
    }

    match acl {
        Some(entries) if !entries.is_empty() => {
            let perm = posix_acl_perm_bits_for_caller(
                entries,
                attrs.uid(),
                attrs.gid(),
                uid,
                gid,
                groups,
                attrs.mode(),
            );
            (perm & requested) == requested
        }
        _ => check_mode_access(attrs, uid, gid, groups, requested, mount_identity),
    }
}

/// Validated discretionary access check.
///
/// This is the same permission decision as [`check_access`], with an explicit
/// validation boundary for syscall-style masks. [`ACCESS_NONE`] succeeds after
/// the caller has resolved the inode metadata, matching `F_OK`-style existence
/// probes.
pub fn check_validated_access(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    requested: u8,
    mount_identity: &MountIdentity,
) -> Result<bool, AccessRequestError> {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return Ok(false);
    }

    validate_access_request(requested)?;
    if requested == ACCESS_NONE {
        return Ok(true);
    }

    Ok(check_access(
        attrs,
        acl,
        uid,
        gid,
        groups,
        requested,
        mount_identity,
    ))
}

/// Structured report for a validated permission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionCheckReport {
    /// Mount identity used for the permission evaluation.
    pub mount_identity: MountIdentity,
    /// Original requested access mask.
    pub requested: u8,
    /// Final allow/deny result after mount validation and DAC evaluation.
    pub allowed: bool,
}

/// Run a validated permission check and return the mount-bound report.
pub fn check_access_report(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    requested: u8,
    mount_identity: &MountIdentity,
) -> Result<PermissionCheckReport, AccessRequestError> {
    let allowed = check_validated_access(attrs, acl, uid, gid, groups, requested, mount_identity)?;
    Ok(PermissionCheckReport {
        mount_identity: *mount_identity,
        requested,
        allowed,
    })
}

// ---------------------------------------------------------------------------
// Convenience access functions
// ---------------------------------------------------------------------------

/// Short-hand: does the caller have read permission?
pub fn can_read(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &MountIdentity,
) -> bool {
    check_access(attrs, acl, uid, gid, groups, ACCESS_READ, mount_identity)
}

/// Short-hand: does the caller have write permission?
pub fn can_write(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &MountIdentity,
) -> bool {
    check_access(attrs, acl, uid, gid, groups, ACCESS_WRITE, mount_identity)
}

/// Short-hand: does the caller have execute permission?
pub fn can_execute(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &MountIdentity,
) -> bool {
    check_access(attrs, acl, uid, gid, groups, ACCESS_EXECUTE, mount_identity)
}

/// Short-hand: can the caller traverse (lookup) a directory?
///
/// Directory traversal requires execute permission on the directory.
pub fn can_lookup(
    attrs: &dyn InodeAttr,
    acl: Option<&[PosixAclEntry]>,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &MountIdentity,
) -> bool {
    check_access(attrs, acl, uid, gid, groups, ACCESS_EXECUTE, mount_identity)
}

/// One directory component whose execute/search permission must be granted
/// before path traversal may continue.
#[derive(Clone, Copy)]
pub struct PathTraversalComponent<'a> {
    attrs: &'a dyn InodeAttr,
    acl: Option<&'a [PosixAclEntry]>,
}

impl<'a> PathTraversalComponent<'a> {
    /// Create a traversal component from directory attributes and an optional
    /// POSIX access ACL.
    #[must_use]
    pub fn new(attrs: &'a dyn InodeAttr, acl: Option<&'a [PosixAclEntry]>) -> Self {
        PathTraversalComponent { attrs, acl }
    }

    /// Directory attributes used for the search permission check.
    #[must_use]
    pub fn attrs(&self) -> &'a dyn InodeAttr {
        self.attrs
    }

    /// Optional POSIX access ACL used for the search permission check.
    #[must_use]
    pub fn acl(&self) -> Option<&'a [PosixAclEntry]> {
        self.acl
    }
}

impl<'a> core::fmt::Debug for PathTraversalComponent<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PathTraversalComponent")
            .field("uid", &self.attrs.uid())
            .field("gid", &self.attrs.gid())
            .field("mode", &self.attrs.mode())
            .field("acl_len", &self.acl.map(|a| a.len()))
            .finish()
    }
}

/// First directory component that denied path traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTraversalDenied {
    /// Zero-based index into the checked component slice.
    pub component_index: usize,
}

/// Check execute/search permission over each directory component in a path.
///
/// The leaf operation is intentionally out of scope; callers should pass only
/// directories that must be searched before reaching the leaf and then perform
/// the leaf-specific access check separately.
pub fn check_path_traversal(
    components: &[PathTraversalComponent<'_>],
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &MountIdentity,
) -> Result<(), PathTraversalDenied> {
    // Fail closed on invalid mount identity
    if !mount_identity.is_valid() {
        return Err(PathTraversalDenied { component_index: 0 });
    }

    for (component_index, component) in components.iter().enumerate() {
        if !can_lookup(
            component.attrs,
            component.acl,
            uid,
            gid,
            groups,
            mount_identity,
        ) {
            return Err(PathTraversalDenied { component_index });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sticky-directory delete permission planning
// ---------------------------------------------------------------------------

/// Reason a sticky-directory delete or rename-over-target operation is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyDirectoryDeleteAllow {
    /// Parent directory does not have [`S_ISVTX`] set.
    DirectoryNotSticky,
    /// Caller is root.
    Root,
    /// Caller owns the parent directory.
    DirectoryOwner,
    /// Caller owns the victim entry.
    VictimOwner,
}

/// Planned result for POSIX sticky-directory delete authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyDirectoryDeletePlan {
    /// Operation is allowed for the included reason.
    Allow(StickyDirectoryDeleteAllow),
    /// Sticky bit denies the operation after ordinary directory permissions.
    Deny,
}

impl StickyDirectoryDeletePlan {
    /// Returns true when the planned sticky-directory check permits the
    /// operation.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, StickyDirectoryDeletePlan::Allow(_))
    }
}

/// Plan POSIX sticky-directory delete authorization for an already-resolved
/// parent directory and victim entry.
///
/// This helper only models the sticky-bit rule. Callers should perform ordinary
/// parent directory write/search checks, lookup checks, and operation-specific
/// type checks separately.
#[must_use]
pub fn plan_sticky_directory_delete(
    directory_attrs: &dyn InodeAttr,
    victim_attrs: &dyn InodeAttr,
    caller_uid: u32,
) -> StickyDirectoryDeletePlan {
    if directory_attrs.mode() & S_ISVTX == 0 {
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryNotSticky)
    } else if caller_uid == 0 {
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::Root)
    } else if caller_uid == directory_attrs.uid() {
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryOwner)
    } else if caller_uid == victim_attrs.uid() {
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner)
    } else {
        StickyDirectoryDeletePlan::Deny
    }
}

/// Existing target entry for a POSIX rename operation.
#[derive(Clone, Copy)]
pub struct StickyDirectoryRenameTarget<'a> {
    directory_attrs: &'a dyn InodeAttr,
    victim_attrs: &'a dyn InodeAttr,
}

impl<'a> StickyDirectoryRenameTarget<'a> {
    /// Create a rename target from the target parent directory and the existing
    /// target entry that would be replaced.
    #[must_use]
    pub const fn new(directory_attrs: &'a dyn InodeAttr, victim_attrs: &'a dyn InodeAttr) -> Self {
        StickyDirectoryRenameTarget {
            directory_attrs,
            victim_attrs,
        }
    }

    /// Target parent directory attributes.
    #[must_use]
    pub fn directory_attrs(&self) -> &'a dyn InodeAttr {
        self.directory_attrs
    }

    /// Existing target entry attributes.
    #[must_use]
    pub fn victim_attrs(&self) -> &'a dyn InodeAttr {
        self.victim_attrs
    }
}
impl<'a> core::fmt::Debug for StickyDirectoryRenameTarget<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StickyDirectoryRenameTarget")
            .field("dir_uid", &self.directory_attrs.uid())
            .field("dir_gid", &self.directory_attrs.gid())
            .field("dir_mode", &self.directory_attrs.mode())
            .field("victim_uid", &self.victim_attrs.uid())
            .field("victim_gid", &self.victim_attrs.gid())
            .field("victim_mode", &self.victim_attrs.mode())
            .finish()
    }
}

/// Side of a rename blocked by sticky-directory authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyDirectoryRenameDeny {
    /// Source directory and source entry failed the sticky rule.
    Source,
    /// Existing target directory entry failed the sticky rule.
    Target,
}

/// Planned POSIX sticky-directory authorization for rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StickyDirectoryRenamePlan {
    /// Sticky-directory decision for removing the source entry.
    pub source: StickyDirectoryDeletePlan,
    /// Sticky-directory decision for replacing an existing target entry, if any.
    pub target: Option<StickyDirectoryDeletePlan>,
}

impl StickyDirectoryRenamePlan {
    /// Returns true when both source removal and target replacement, when
    /// present, satisfy POSIX sticky-directory authorization.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        if !self.source.is_allowed() {
            return false;
        }

        match self.target {
            Some(target) => target.is_allowed(),
            None => true,
        }
    }

    /// Returns the first rename side denied by the sticky-directory rule.
    #[must_use]
    pub const fn denied_by(self) -> Option<StickyDirectoryRenameDeny> {
        if !self.source.is_allowed() {
            return Some(StickyDirectoryRenameDeny::Source);
        }

        match self.target {
            Some(target) if !target.is_allowed() => Some(StickyDirectoryRenameDeny::Target),
            _ => None,
        }
    }
}

/// Plan POSIX sticky-directory authorization for rename.
///
/// The source side uses the same rule as unlink because rename removes the
/// source directory entry. When `target` is `Some`, replacing that existing
/// target entry must also satisfy the target parent directory's sticky rule.
#[must_use]
pub fn plan_sticky_directory_rename(
    source_directory_attrs: &dyn InodeAttr,
    source_victim_attrs: &dyn InodeAttr,
    target: Option<StickyDirectoryRenameTarget<'_>>,
    caller_uid: u32,
) -> StickyDirectoryRenamePlan {
    let source =
        plan_sticky_directory_delete(source_directory_attrs, source_victim_attrs, caller_uid);
    let target = target.map(|target| {
        plan_sticky_directory_delete(target.directory_attrs(), target.victim_attrs(), caller_uid)
    });

    StickyDirectoryRenamePlan { source, target }
}

// ---------------------------------------------------------------------------
// can_unlink – simplified sticky-bit gate for unlink / rename-over-target
// ---------------------------------------------------------------------------

/// Error returned when the POSIX sticky bit blocks an unlink or rename-over-target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StickyBitDenied;

/// Check POSIX sticky-directory authorization for unlink or rename-over-target.
///
/// When `dir_mode` has [`S_ISVTX`] set, the caller must be root (uid 0), own
/// the parent directory, or own the victim entry. Returns `Ok(())` when the
/// sticky-bit rule permits the operation, or `Err(`[`StickyBitDenied`]`)` when
/// the sticky bit blocks the caller.
///
/// This is a thin convenience wrapper over [`plan_sticky_directory_delete`]
/// that takes raw integer values so callers do not need to implement the
/// [`InodeAttr`] trait for simple permission gating.
pub fn can_unlink(
    dir_mode: u32,
    dir_uid: u32,
    victim_uid: u32,
    caller_uid: u32,
) -> Result<(), StickyBitDenied> {
    if dir_mode & S_ISVTX == 0 {
        return Ok(());
    }
    if caller_uid == 0 || caller_uid == dir_uid || caller_uid == victim_uid {
        return Ok(());
    }
    Err(StickyBitDenied)
}

// ---------------------------------------------------------------------------
// Setgid-directory create inheritance planning
// ---------------------------------------------------------------------------

/// Kind of child entry being created under a parent directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatedEntryKind {
    /// Child entry is a directory.
    Directory,
    /// Child entry is not a directory.
    NonDirectory,
}

/// Source selected for the newly created entry's group id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetgidCreateGidSource {
    /// Use the caller's effective group id.
    Caller,
    /// Inherit the parent directory's group id because it has [`S_ISGID`] set.
    ParentDirectory,
}

/// Planned POSIX group and mode result for creating a child entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetgidCreatePlan {
    /// Group id to assign to the created entry.
    pub gid: u32,
    /// Mode to assign after setgid-directory inheritance rules.
    pub mode: u32,
    /// Why `gid` was selected.
    pub gid_source: SetgidCreateGidSource,
}

impl SetgidCreatePlan {
    /// Returns true when the created entry inherits the parent directory group.
    #[must_use]
    pub const fn inherits_parent_group(self) -> bool {
        matches!(self.gid_source, SetgidCreateGidSource::ParentDirectory)
    }
}

/// Plan POSIX setgid-directory inheritance for a child create operation.
///
/// When the parent directory has [`S_ISGID`] set, children inherit the parent
/// group id. Directories also inherit the setgid bit so descendants continue to
/// use the same group. Non-directories keep the requested mode unchanged; they
/// inherit only the group id from the parent directory.
#[must_use]
pub fn plan_setgid_create_inheritance(
    parent_directory_attrs: &dyn InodeAttr,
    caller_gid: u32,
    requested_mode: u32,
    child_kind: CreatedEntryKind,
) -> SetgidCreatePlan {
    if parent_directory_attrs.mode() & S_ISGID == 0 {
        return SetgidCreatePlan {
            gid: caller_gid,
            mode: requested_mode,
            gid_source: SetgidCreateGidSource::Caller,
        };
    }

    let mode = match child_kind {
        CreatedEntryKind::Directory => requested_mode | S_ISGID,
        CreatedEntryKind::NonDirectory => requested_mode,
    };

    SetgidCreatePlan {
        gid: parent_directory_attrs.gid(),
        mode,
        gid_source: SetgidCreateGidSource::ParentDirectory,
    }
}

/// Xattr name for the POSIX access ACL (`system.posix_acl_access`).
pub const POSIX_ACL_ACCESS_XATTR: &[u8] = b"system.posix_acl_access";

/// Xattr name for the POSIX default ACL (`system.posix_acl_default`).
pub const POSIX_ACL_DEFAULT_XATTR: &[u8] = b"system.posix_acl_default";
// ---------------------------------------------------------------------------
// POSIX ACL xattr and mode synchronisation helpers
// ---------------------------------------------------------------------------

/// Serialize ACL entries into the Linux POSIX ACL xattr wire format.
#[must_use]
pub fn serialize_acl(entries: &[PosixAclEntry]) -> Vec<u8> {
    encode_posix_acl_xattr(entries)
}

/// Deserialize ACL entries from the Linux POSIX ACL xattr wire format.
pub fn deserialize_acl(data: &[u8]) -> Result<PosixAcl, AclError> {
    decode_posix_acl_xattr(data)
}

/// Update an existing `ACL_MASK` entry to match the group class bits in
/// `new_mode`.
pub fn recalc_acl_mask(new_mode: u16, acl: &mut [PosixAclEntry]) {
    let group_perm = (new_mode >> 3) & 0x7;
    for entry in acl {
        if entry.tag == ACL_MASK {
            entry.perm = group_perm;
        }
    }
}

/// Derive visible permission bits from an ACL, using zero for missing classes.
#[must_use]
pub fn recalc_mode_from_acl(acl: &[PosixAclEntry]) -> u16 {
    (posix_mode_from_access_acl(acl, 0) & 0o777) as u16
}

// ---------------------------------------------------------------------------
// Xattr namespace validation
// ---------------------------------------------------------------------------

/// Recognised xattr namespace prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// `security.*` – SELinux / capability attributes.
    Security,
    /// `system.*` – POSIX ACLs and other system attributes.
    System,
    /// `trusted.*` – attributes only settable by CAP_SYS_ADMIN.
    Trusted,
    /// `user.*` – arbitrary user attributes.
    User,
}

/// Error returned when an xattr name fails namespace validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespaceError {
    /// Name is empty or only contains the prefix separator.
    EmptyName,
    /// Name exceeds the maximum allowed length (255 bytes on Linux).
    NameTooLong,
    /// Name does not contain a recognised namespace prefix (`user.`,
    /// `system.`, `security.`, `trusted.`).
    UnknownNamespace,
}

/// Maximum length of an xattr name (including namespace prefix), as
/// enforced by Linux.
pub const XATTR_NAME_MAX: usize = 255;

/// Validate an xattr name against the set of recognised namespace
/// prefixes.
///
/// Returns the recognised [`XattrNamespace`] on success.
pub fn validate_xattr_namespace(name: &[u8]) -> Result<XattrNamespace, XattrNamespaceError> {
    if name.is_empty() {
        return Err(XattrNamespaceError::EmptyName);
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(XattrNamespaceError::NameTooLong);
    }

    if name.starts_with(b"user.") && name.len() > 5 {
        Ok(XattrNamespace::User)
    } else if name.starts_with(b"system.") && name.len() > 7 {
        Ok(XattrNamespace::System)
    } else if name.starts_with(b"security.") && name.len() > 9 {
        Ok(XattrNamespace::Security)
    } else if name.starts_with(b"trusted.") && name.len() > 8 {
        Ok(XattrNamespace::Trusted)
    } else {
        Err(XattrNamespaceError::UnknownNamespace)
    }
}

// ---------------------------------------------------------------------------
// In-memory xattr store
// ---------------------------------------------------------------------------

/// Error returned by in-memory xattr store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrMapError {
    /// Namespace validation failed.
    InvalidNamespace(XattrNamespaceError),
    /// The requested xattr does not exist.
    NotFound,
}

impl From<XattrNamespaceError> for XattrMapError {
    fn from(e: XattrNamespaceError) -> Self {
        XattrMapError::InvalidNamespace(e)
    }
}

/// A simple in-memory extended-attribute store keyed by `(InodeId, xattr name)`.
///
/// All mutation operations validate the xattr name against the recognised
/// namespace prefixes (`user.`, `system.`, `security.`, `trusted.`).
///
/// This is a straightforward correctness-oriented store.  For polymorphic
/// storage with B+tree / inline representation switching see
/// `tidefs_xattr_storage::XattrStore`.
#[derive(Clone, Debug, Default)]
pub struct XattrMap {
    entries: BTreeMap<(InodeId, Vec<u8>), Vec<u8>>,
}

impl XattrMap {
    /// Create an empty xattr map.
    #[must_use]
    pub fn new() -> Self {
        XattrMap {
            entries: BTreeMap::new(),
        }
    }

    /// Number of xattr entries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the store has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ------------------------------------------------------------------
    // Set / Get / Remove / List
    // ------------------------------------------------------------------

    /// Set or replace the value of an extended attribute.
    ///
    /// The name is validated against recognised namespace prefixes before
    /// the write proceeds.
    pub fn setxattr(
        &mut self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), XattrMapError> {
        validate_xattr_namespace(name)?;
        self.entries.insert((inode, name.to_vec()), value.to_vec());
        Ok(())
    }

    /// Retrieve the value of an extended attribute.
    ///
    /// Returns `None` when the attribute does not exist.  Does *not*
    /// validate the name – callers that want namespace filtering should
    /// call [`validate_xattr_namespace`] separately.
    #[must_use]
    pub fn getxattr(&self, inode: InodeId, name: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(&(inode, name.to_vec())).cloned()
    }

    /// List all xattr names attached to `inode`.
    ///
    /// The returned names include the namespace prefix (e.g. `user.myattr`).
    #[must_use]
    pub fn listxattr(&self, inode: InodeId) -> Vec<Vec<u8>> {
        self.entries
            .range((inode, Vec::new())..)
            .take_while(|((ino, _), _)| *ino == inode)
            .map(|((_, name), _)| name.clone())
            .collect()
    }

    /// Remove an extended attribute.
    ///
    /// Returns `Err(XattrMapError::NotFound)` when the attribute does not
    /// exist for the given inode.
    pub fn removexattr(&mut self, inode: InodeId, name: &[u8]) -> Result<(), XattrMapError> {
        validate_xattr_namespace(name)?;
        let key = (inode, name.to_vec());
        if self.entries.remove(&key).is_some() {
            Ok(())
        } else {
            Err(XattrMapError::NotFound)
        }
    }

    /// Remove all xattrs associated with `inode` (bulk cleanup on unlink).
    ///
    /// Returns the number of entries removed.
    pub fn remove_all(&mut self, inode: InodeId) -> usize {
        let before = self.entries.len();

        // Collect keys for the given inode, then remove them.
        let keys: Vec<(InodeId, Vec<u8>)> = self
            .entries
            .range((inode, Vec::new())..)
            .take_while(|((ino, _), _)| *ino == inode)
            .map(|(k, _)| k.clone())
            .collect();

        for k in &keys {
            self.entries.remove(k);
        }

        before - self.entries.len()
    }

    /// Bulk-load xattrs from an iterator of `(name, value)` pairs.
    ///
    /// Each name is validated; the entire operation fails on the first
    /// invalid name without making partial changes.
    pub fn bulk_set(
        &mut self,
        inode: InodeId,
        iter: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<(), XattrMapError> {
        // Validate all names first.
        let pairs: Vec<_> = iter.into_iter().collect();
        for (name, _) in &pairs {
            validate_xattr_namespace(name)?;
        }
        for (name, value) in pairs {
            self.entries.insert((inode, name), value);
        }
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    // Mount identity constants shared by all permission binding tests.
    const VALID_MOUNT: MountIdentity = MountIdentity::new(
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
        1,
    );

    #[allow(dead_code)]
    const OTHER_MOUNT: MountIdentity = MountIdentity::new(
        [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ],
        2,
    );

    #[allow(dead_code)]
    const ROOT_MOUNT: MountIdentity = MountIdentity::new([0u8; 16], 1);
    #[allow(dead_code)]
    const INVALID_MOUNT_ZERO_EPOCH: MountIdentity = MountIdentity::new([0x01u8; 16], 0);

    use super::*;
    use alloc::vec;

    // -- Test helper -------------------------------------------------------

    /// A minimal inode implementation for tests.
    struct TestInode {
        uid: u32,
        gid: u32,
        mode: u32,
    }

    impl InodeAttr for TestInode {
        fn uid(&self) -> u32 {
            self.uid
        }
        fn gid(&self) -> u32 {
            self.gid
        }
        fn mode(&self) -> u32 {
            self.mode
        }
    }

    impl TestInode {
        const fn new(uid: u32, gid: u32, mode: u32) -> Self {
            TestInode { uid, gid, mode }
        }
    }

    fn assert_mode_access_matrix(
        inode: &TestInode,
        uid: u32,
        gid: u32,
        groups: &[u32],
        expected_bits: u8,
    ) {
        let cases = [
            (ACCESS_NONE, true),
            (ACCESS_READ, expected_bits & ACCESS_READ != 0),
            (ACCESS_WRITE, expected_bits & ACCESS_WRITE != 0),
            (ACCESS_EXECUTE, expected_bits & ACCESS_EXECUTE != 0),
            (
                ACCESS_READ | ACCESS_WRITE,
                expected_bits & ACCESS_RDWR == ACCESS_RDWR,
            ),
            (
                ACCESS_READ | ACCESS_EXECUTE,
                expected_bits & (ACCESS_READ | ACCESS_EXECUTE) == ACCESS_READ | ACCESS_EXECUTE,
            ),
            (
                ACCESS_WRITE | ACCESS_EXECUTE,
                expected_bits & (ACCESS_WRITE | ACCESS_EXECUTE) == ACCESS_WRITE | ACCESS_EXECUTE,
            ),
            (ACCESS_RWX, expected_bits & ACCESS_RWX == ACCESS_RWX),
        ];

        for (requested, expected) in cases {
            assert_eq!(
                check_mode_access(inode, uid, gid, groups, requested, &VALID_MOUNT),
                expected,
                "mode={:#05o} uid={} gid={} groups={:?} requested={:#04x}",
                inode.mode(),
                uid,
                gid,
                groups,
                requested
            );
        }
    }

    // =====================================================================
    // Mode permission matrix tests
    // =====================================================================

    #[test]
    fn mode_owner_read_granted() {
        let ino = TestInode::new(1000, 100, 0o400);
        assert!(check_mode_access(
            &ino,
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_owner_read_denied() {
        let ino = TestInode::new(1000, 100, 0o200); // write-only
        assert!(!check_mode_access(
            &ino,
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_owner_write_granted() {
        let ino = TestInode::new(1000, 100, 0o200);
        assert!(check_mode_access(
            &ino,
            1000,
            200,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_owner_execute_granted() {
        let ino = TestInode::new(1000, 100, 0o100);
        assert!(check_mode_access(
            &ino,
            1000,
            100,
            &[],
            ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_owner_all_granted() {
        let ino = TestInode::new(1000, 100, 0o700);
        assert!(check_mode_access(
            &ino,
            1000,
            100,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_group_read_granted_by_gid() {
        let ino = TestInode::new(1000, 100, 0o040);
        assert!(check_mode_access(
            &ino,
            2000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_group_read_granted_by_supplementary() {
        let ino = TestInode::new(1000, 100, 0o040);
        assert!(check_mode_access(
            &ino,
            2000,
            200,
            &[100],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_group_read_denied() {
        let ino = TestInode::new(1000, 100, 0o004); // only other-read
        assert!(!check_mode_access(
            &ino,
            2000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_group_write_denied() {
        let ino = TestInode::new(1000, 100, 0o040); // group read-only
        assert!(!check_mode_access(
            &ino,
            2000,
            100,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_other_read_granted() {
        let ino = TestInode::new(1000, 100, 0o004);
        assert!(check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_other_read_denied() {
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(!check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_other_all_granted() {
        let ino = TestInode::new(1000, 100, 0o007);
        assert!(check_mode_access(
            &ino,
            2000,
            300,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_root_always_granted() {
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(check_mode_access(
            &ino,
            0,
            200,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_root_read_on_write_only() {
        let ino = TestInode::new(1000, 100, 0o222);
        assert!(check_mode_access(
            &ino,
            0,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_owner_overrides_group() {
        // Owner bits are rwx, group bits are ---, uid matches owner
        let ino = TestInode::new(1000, 100, 0o700);
        assert!(check_mode_access(
            &ino,
            1000,
            100,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_group_member_not_owner() {
        // uid 2000 (not owner), gid 100 (matches file group), group bits r-x
        let ino = TestInode::new(1000, 100, 0o750);
        assert!(check_mode_access(
            &ino,
            2000,
            100,
            &[],
            ACCESS_READ | ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
        assert!(!check_mode_access(
            &ino,
            2000,
            100,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_supplementary_group_takes_group_bits() {
        let ino = TestInode::new(1000, 100, 0o070);
        assert!(check_mode_access(
            &ino,
            2000,
            200,
            &[100],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_other_when_neither_owner_nor_group() {
        let ino = TestInode::new(1000, 100, 0o701);
        // uid 2000 != owner 1000, gid 200 != 100, no supp groups -> other bits
        assert!(check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
        assert!(!check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mode_exhaustive_owner_matrix() {
        // For each possible mode combination, verify owner gets owner bits.
        for mode in 0u32..512 {
            let ino = TestInode::new(1000, 100, mode);
            let expected_r = ((mode >> 6) & 4) != 0;
            let expected_w = ((mode >> 6) & 2) != 0;
            let expected_x = ((mode >> 6) & 1) != 0;
            assert_eq!(
                check_mode_access(&ino, 1000, 100, &[], ACCESS_READ, &VALID_MOUNT),
                expected_r,
                "mode={mode:#05o} owner read"
            );
            assert_eq!(
                check_mode_access(&ino, 1000, 100, &[], ACCESS_WRITE, &VALID_MOUNT),
                expected_w,
                "mode={mode:#05o} owner write"
            );
            assert_eq!(
                check_mode_access(&ino, 1000, 100, &[], ACCESS_EXECUTE, &VALID_MOUNT),
                expected_x,
                "mode={mode:#05o} owner exec"
            );
        }
    }

    #[test]
    fn mode_exhaustive_primary_group_matrix() {
        for mode in 0u32..512 {
            let ino = TestInode::new(1000, 100, mode);
            assert_mode_access_matrix(&ino, 2000, 100, &[], ((mode >> 3) & 0x7) as u8);
        }
    }

    #[test]
    fn mode_exhaustive_supplementary_group_matrix() {
        for mode in 0u32..512 {
            let ino = TestInode::new(1000, 100, mode);
            assert_mode_access_matrix(&ino, 2000, 200, &[10, 100, 300], ((mode >> 3) & 0x7) as u8);
        }
    }

    #[test]
    fn mode_exhaustive_other_matrix() {
        for mode in 0u32..512 {
            let ino = TestInode::new(1000, 100, mode);
            assert_mode_access_matrix(&ino, 2000, 200, &[10, 300], (mode & 0x7) as u8);
        }
    }

    #[test]
    fn mode_owner_class_takes_precedence_over_group_membership() {
        let ino = TestInode::new(1000, 100, 0o070);

        assert_mode_access_matrix(&ino, 1000, 100, &[100], 0);
    }

    #[test]
    fn mode_root_override_matrix_allows_all_permission_requests() {
        let ino = TestInode::new(1000, 100, 0o000);

        assert_mode_access_matrix(&ino, 0, 200, &[], ACCESS_RWX);
    }

    // =====================================================================
    // Unified access check (ACL) tests
    // =====================================================================

    #[test]
    fn unified_no_acl_falls_back_to_mode() {
        let ino = TestInode::new(1000, 100, 0o400);
        assert!(check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn unified_empty_acl_falls_back_to_mode() {
        let ino = TestInode::new(1000, 100, 0o200);
        assert!(check_access(
            &ino,
            Some(&[]),
            1000,
            100,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn validated_access_allows_f_ok_style_empty_request() {
        let ino = TestInode::new(1000, 100, 0o000);

        assert_eq!(
            check_validated_access(&ino, None, 2000, 200, &[], ACCESS_NONE, &VALID_MOUNT),
            Ok(true)
        );
    }

    #[test]
    fn validated_access_rejects_invalid_permission_bits() {
        let ino = TestInode::new(1000, 100, 0o777);
        let invalid = ACCESS_VALID_MASK | 0x08;

        assert_eq!(
            check_validated_access(&ino, None, 1000, 100, &[], invalid, &VALID_MOUNT),
            Err(AccessRequestError::InvalidMask {
                requested: invalid,
                invalid_bits: 0x08,
            })
        );
    }

    #[test]
    fn validated_access_rejects_invalid_bits_before_root_override() {
        let ino = TestInode::new(1000, 100, 0o000);

        assert_eq!(
            check_validated_access(&ino, None, 0, 0, &[], 0x80, &VALID_MOUNT),
            Err(AccessRequestError::InvalidMask {
                requested: 0x80,
                invalid_bits: 0x80,
            })
        );
    }

    #[test]
    fn validated_access_checks_owner_group_and_other_mode_bits() {
        let ino = TestInode::new(1000, 100, 0o754);

        assert_eq!(
            check_validated_access(&ino, None, 1000, 200, &[], ACCESS_RWX, &VALID_MOUNT),
            Ok(true)
        );
        assert_eq!(
            check_validated_access(
                &ino,
                None,
                2000,
                100,
                &[],
                ACCESS_READ | ACCESS_EXECUTE,
                &VALID_MOUNT
            ),
            Ok(true)
        );
        assert_eq!(
            check_validated_access(&ino, None, 2000, 200, &[100], ACCESS_WRITE, &VALID_MOUNT),
            Ok(false)
        );
        assert_eq!(
            check_validated_access(&ino, None, 3000, 300, &[], ACCESS_READ, &VALID_MOUNT),
            Ok(true)
        );
        assert_eq!(
            check_validated_access(&ino, None, 3000, 300, &[], ACCESS_EXECUTE, &VALID_MOUNT),
            Ok(false)
        );
    }

    #[test]
    fn validated_access_preserves_root_read_write_and_execute_override() {
        let ino = TestInode::new(1000, 100, 0o000);

        assert_eq!(
            check_validated_access(
                &ino,
                None,
                0,
                0,
                &[],
                ACCESS_READ | ACCESS_WRITE,
                &VALID_MOUNT
            ),
            Ok(true)
        );
        assert_eq!(
            check_validated_access(&ino, None, 0, 0, &[], ACCESS_EXECUTE, &VALID_MOUNT),
            Ok(true)
        );
    }

    #[test]
    fn unified_acl_minimal_owner() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(check_access(
            &ino,
            Some(&acl),
            1000,
            100,
            &[],
            ACCESS_READ | ACCESS_WRITE,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            1000,
            100,
            &[],
            ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn unified_acl_with_mask_restricts_named_user() {
        // Named user 2000 gets rwx, but mask is r-- (4)
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        // Caller 2000 gets mask-clamped r--
        assert!(check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[],
            ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn unified_acl_named_group_with_mask() {
        // Named group 500 gets rwx, mask is r-x (5), caller in group 500
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 7,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[500],
            ACCESS_READ | ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[500],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn unified_acl_deny_then_grant_via_order() {
        // OWNER entry denies all, but caller 2000 matches named USER entry
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        // caller 2000 != owner 1000 -> falls through to named user check
        assert!(check_access(
            &ino,
            Some(&acl),
            2000,
            200,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn unified_acl_other_fallback() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            }, // r--
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        // Caller 3000, gid 300 – not owner, not in group 100 -> other
        assert!(check_access(
            &ino,
            Some(&acl),
            3000,
            300,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            3000,
            300,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn acl_serialize_deserialize_helpers_round_trip() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let encoded = serialize_acl(&acl);
        let decoded = deserialize_acl(&encoded).expect("decode serialized ACL");
        assert_eq!(decoded, acl);
    }

    #[test]
    fn acl_recalc_mask_updates_existing_mask_only() {
        let mut acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 7,
                id: 0,
            },
        ];

        recalc_acl_mask(0o640, &mut acl);

        assert_eq!(acl[1].perm, 7);
        assert_eq!(acl[2].perm, 7);
        assert_eq!(acl[3].perm, 4);
        assert_eq!(acl[4].perm, 7);
    }

    #[test]
    fn acl_recalc_mode_from_acl_uses_mask_for_group_class() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];

        assert_eq!(recalc_mode_from_acl(&acl), 0o641);
    }

    // =====================================================================
    // Convenience function tests
    // =====================================================================

    #[test]
    fn can_read_wrapper() {
        let ino = TestInode::new(1000, 100, 0o400);
        assert!(can_read(&ino, None, 1000, 100, &[], &VALID_MOUNT));
        assert!(!can_read(&ino, None, 2000, 200, &[], &VALID_MOUNT));
    }

    #[test]
    fn can_write_wrapper() {
        let ino = TestInode::new(1000, 100, 0o020);
        assert!(can_write(&ino, None, 2000, 100, &[], &VALID_MOUNT));
        assert!(!can_write(&ino, None, 2000, 200, &[], &VALID_MOUNT));
    }

    #[test]
    fn can_execute_wrapper() {
        let ino = TestInode::new(1000, 100, 0o001);
        assert!(can_execute(&ino, None, 2000, 200, &[], &VALID_MOUNT));
        assert!(!can_execute(&ino, None, 1000, 100, &[], &VALID_MOUNT));
    }

    #[test]
    fn can_lookup_same_as_execute() {
        let ino = TestInode::new(1000, 100, 0o001);
        assert!(can_lookup(&ino, None, 2000, 200, &[], &VALID_MOUNT));
        let ino2 = TestInode::new(1000, 100, 0o000);
        assert!(!can_lookup(&ino2, None, 2000, 200, &[], &VALID_MOUNT));
    }

    #[test]
    fn path_traversal_empty_path_is_allowed() {
        assert_eq!(
            check_path_traversal(&[], 1000, 100, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn path_traversal_all_components_searchable() {
        let root = TestInode::new(0, 0, 0o755);
        let home = TestInode::new(1000, 100, 0o710);
        let project = TestInode::new(2000, 200, 0o100);
        let components = [
            PathTraversalComponent::new(&root, None),
            PathTraversalComponent::new(&home, None),
            PathTraversalComponent::new(&project, None),
        ];

        assert_eq!(
            check_path_traversal(&components, 2000, 100, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn path_traversal_reports_first_denied_component() {
        let root = TestInode::new(0, 0, 0o755);
        let private = TestInode::new(1000, 100, 0o700);
        let leaf_parent = TestInode::new(1000, 100, 0o777);
        let components = [
            PathTraversalComponent::new(&root, None),
            PathTraversalComponent::new(&private, None),
            PathTraversalComponent::new(&leaf_parent, None),
        ];

        assert_eq!(
            check_path_traversal(&components, 2000, 200, &[], &VALID_MOUNT),
            Err(PathTraversalDenied { component_index: 1 })
        );
    }

    #[test]
    fn path_traversal_uses_supplementary_groups() {
        let shared = TestInode::new(1000, 500, 0o010);
        let components = [PathTraversalComponent::new(&shared, None)];

        assert_eq!(
            check_path_traversal(&components, 2000, 200, &[500], &VALID_MOUNT),
            Ok(())
        );
        assert_eq!(
            check_path_traversal(&components, 2000, 200, &[], &VALID_MOUNT),
            Err(PathTraversalDenied { component_index: 0 })
        );
    }

    #[test]
    fn path_traversal_honors_acl_search_bits() {
        let dir = TestInode::new(1000, 100, 0o000);
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 1,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let components = [PathTraversalComponent::new(&dir, Some(&acl))];

        assert_eq!(
            check_path_traversal(&components, 2000, 200, &[], &VALID_MOUNT),
            Ok(())
        );
        assert_eq!(
            check_path_traversal(&components, 3000, 300, &[], &VALID_MOUNT),
            Err(PathTraversalDenied { component_index: 0 })
        );
    }

    #[test]
    fn path_traversal_preserves_root_mode_override() {
        let private = TestInode::new(1000, 100, 0o000);
        let components = [PathTraversalComponent::new(&private, None)];

        assert_eq!(
            check_path_traversal(&components, 0, 0, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    // =====================================================================
    // Sticky-directory delete planning tests
    // =====================================================================

    #[test]
    fn sticky_delete_allows_non_sticky_directory() {
        let directory = TestInode::new(1000, 100, 0o777);
        let victim = TestInode::new(2000, 200, 0o600);

        let plan = plan_sticky_directory_delete(&directory, &victim, 3000);

        assert_eq!(
            plan,
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryNotSticky)
        );
        assert!(plan.is_allowed());
    }

    #[test]
    fn sticky_delete_allows_root() {
        let directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let victim = TestInode::new(2000, 200, 0o600);

        assert_eq!(
            plan_sticky_directory_delete(&directory, &victim, 0),
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::Root)
        );
    }

    #[test]
    fn sticky_delete_allows_directory_owner() {
        let directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let victim = TestInode::new(2000, 200, 0o600);

        assert_eq!(
            plan_sticky_directory_delete(&directory, &victim, 1000),
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryOwner)
        );
    }

    #[test]
    fn sticky_delete_allows_victim_owner() {
        let directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let victim = TestInode::new(2000, 200, 0o600);

        assert_eq!(
            plan_sticky_directory_delete(&directory, &victim, 2000),
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner)
        );
    }

    #[test]
    fn sticky_delete_denies_unrelated_caller() {
        let directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let victim = TestInode::new(2000, 200, 0o600);

        let plan = plan_sticky_directory_delete(&directory, &victim, 3000);

        assert_eq!(plan, StickyDirectoryDeletePlan::Deny);
        assert!(!plan.is_allowed());
    }

    // =====================================================================
    // can_unlink behavioral tests
    // =====================================================================

    #[test]
    fn can_unlink_non_sticky_directory_always_ok() {
        // Non-sticky directory: any caller can unlink regardless of ownership.
        let result = can_unlink(0o777, 100, 200, 9999);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_unlink_sticky_root_caller_ok() {
        // Sticky directory + root (uid 0): always permitted.
        let result = can_unlink(S_ISVTX | 0o777, 100, 200, 0);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_unlink_sticky_directory_owner_ok() {
        // Sticky directory + caller owns the directory.
        let result = can_unlink(S_ISVTX | 0o777, 100, 200, 100);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_unlink_sticky_victim_owner_ok() {
        // Sticky directory + caller owns the victim entry.
        let result = can_unlink(S_ISVTX | 0o777, 100, 200, 200);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_unlink_sticky_unrelated_caller_denied() {
        // Sticky directory + caller is neither root, dir owner, nor victim owner.
        let result = can_unlink(S_ISVTX | 0o777, 100, 200, 9999);
        assert_eq!(result, Err(StickyBitDenied));
    }

    #[test]
    fn can_unlink_zero_mode_non_sticky_ok() {
        // Zero mode (no sticky bit): behaves as non-sticky directory.
        let result = can_unlink(0o000, 100, 200, 9999);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_unlink_sticky_set_only_bit_in_mode() {
        // Only S_ISVTX is set in the mode field; no permission bits set.
        // The sticky check only inspects the S_ISVTX bit, so this is denied
        // for an unrelated caller.
        assert_eq!(can_unlink(S_ISVTX, 100, 200, 9999), Err(StickyBitDenied));
        // But root still bypasses.
        assert_eq!(can_unlink(S_ISVTX, 100, 200, 0), Ok(()));
    }

    #[test]
    fn can_unlink_sticky_with_high_bits_present() {
        // S_IFDIR (0o40000) plus other high bits set alongside S_ISVTX.
        // The mask only checks S_ISVTX, so unrelated caller is still denied.
        let mode_with_dir = S_ISVTX | 0o40777; // S_IFDIR | 0777 | S_ISVTX
        assert_eq!(
            can_unlink(mode_with_dir, 100, 200, 9999),
            Err(StickyBitDenied)
        );
        // Victim owner is still permitted.
        assert_eq!(can_unlink(mode_with_dir, 100, 200, 200), Ok(()));
    }

    // =====================================================================
    // StickyBitDenied error type tests
    // =====================================================================

    #[test]
    fn sticky_bit_denied_is_copy_and_eq() {
        let a = StickyBitDenied;
        let b = a;
        assert_eq!(a, b);
        // StickyBitDenied is a unit struct — all values are equal.
        let c = StickyBitDenied;
        assert_eq!(a, c);
    }

    #[test]
    fn sticky_bit_denied_propagates_from_can_unlink() {
        // Confirm that can_unlink returns the exact StickyBitDenied variant
        // and not just a generic error.
        let result = can_unlink(S_ISVTX | 0o777, 100, 200, 9999);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StickyBitDenied);
    }

    #[test]
    fn sticky_rename_without_target_uses_source_rule() {
        let source_directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let source_victim = TestInode::new(2000, 200, 0o600);

        let plan = plan_sticky_directory_rename(&source_directory, &source_victim, None, 2000);

        assert_eq!(
            plan.source,
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner)
        );
        assert_eq!(plan.target, None);
        assert!(plan.is_allowed());
        assert_eq!(plan.denied_by(), None);
    }

    #[test]
    fn sticky_rename_reports_source_denial_before_target() {
        let source_directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let source_victim = TestInode::new(2000, 200, 0o600);
        let target_directory = TestInode::new(1000, 100, 0o777);
        let target_victim = TestInode::new(3000, 300, 0o600);

        let plan = plan_sticky_directory_rename(
            &source_directory,
            &source_victim,
            Some(StickyDirectoryRenameTarget::new(
                &target_directory,
                &target_victim,
            )),
            4000,
        );

        assert_eq!(plan.source, StickyDirectoryDeletePlan::Deny);
        assert_eq!(
            plan.target,
            Some(StickyDirectoryDeletePlan::Allow(
                StickyDirectoryDeleteAllow::DirectoryNotSticky
            ))
        );
        assert!(!plan.is_allowed());
        assert_eq!(plan.denied_by(), Some(StickyDirectoryRenameDeny::Source));
    }

    #[test]
    fn sticky_rename_denies_existing_target_replacement() {
        let source_directory = TestInode::new(1000, 100, 0o777);
        let source_victim = TestInode::new(2000, 200, 0o600);
        let target_directory = TestInode::new(3000, 300, S_ISVTX | 0o777);
        let target_victim = TestInode::new(4000, 400, 0o600);

        let plan = plan_sticky_directory_rename(
            &source_directory,
            &source_victim,
            Some(StickyDirectoryRenameTarget::new(
                &target_directory,
                &target_victim,
            )),
            2000,
        );

        assert_eq!(
            plan.source,
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryNotSticky)
        );
        assert_eq!(plan.target, Some(StickyDirectoryDeletePlan::Deny));
        assert!(!plan.is_allowed());
        assert_eq!(plan.denied_by(), Some(StickyDirectoryRenameDeny::Target));
    }

    #[test]
    fn sticky_rename_allows_existing_target_owner() {
        let source_directory = TestInode::new(1000, 100, S_ISVTX | 0o777);
        let source_victim = TestInode::new(2000, 200, 0o600);
        let target_directory = TestInode::new(3000, 300, S_ISVTX | 0o777);
        let target_victim = TestInode::new(2000, 200, 0o600);

        let plan = plan_sticky_directory_rename(
            &source_directory,
            &source_victim,
            Some(StickyDirectoryRenameTarget::new(
                &target_directory,
                &target_victim,
            )),
            2000,
        );

        assert_eq!(
            plan.source,
            StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner)
        );
        assert_eq!(
            plan.target,
            Some(StickyDirectoryDeletePlan::Allow(
                StickyDirectoryDeleteAllow::VictimOwner
            ))
        );
        assert!(plan.is_allowed());
        assert_eq!(plan.denied_by(), None);
    }

    // =====================================================================
    // Setgid-directory create inheritance planning tests
    // =====================================================================

    #[test]
    fn setgid_create_uses_caller_group_when_parent_is_not_setgid() {
        let parent = TestInode::new(1000, 100, 0o775);

        let plan = plan_setgid_create_inheritance(
            &parent,
            200,
            S_ISGID | 0o640,
            CreatedEntryKind::NonDirectory,
        );

        assert_eq!(
            plan,
            SetgidCreatePlan {
                gid: 200,
                mode: S_ISGID | 0o640,
                gid_source: SetgidCreateGidSource::Caller,
            }
        );
        assert!(!plan.inherits_parent_group());
    }

    #[test]
    fn setgid_create_inherits_parent_group_for_non_directory() {
        let parent = TestInode::new(1000, 300, S_ISGID | 0o775);

        let plan =
            plan_setgid_create_inheritance(&parent, 200, 0o640, CreatedEntryKind::NonDirectory);

        assert_eq!(
            plan,
            SetgidCreatePlan {
                gid: 300,
                mode: 0o640,
                gid_source: SetgidCreateGidSource::ParentDirectory,
            }
        );
        assert!(plan.inherits_parent_group());
    }

    #[test]
    fn setgid_create_sets_directory_setgid_when_parent_is_setgid() {
        let parent = TestInode::new(1000, 300, S_ISGID | 0o775);

        let plan = plan_setgid_create_inheritance(&parent, 200, 0o750, CreatedEntryKind::Directory);

        assert_eq!(
            plan,
            SetgidCreatePlan {
                gid: 300,
                mode: S_ISGID | 0o750,
                gid_source: SetgidCreateGidSource::ParentDirectory,
            }
        );
    }

    #[test]
    fn setgid_create_preserves_non_directory_mode_when_parent_is_setgid() {
        let parent = TestInode::new(1000, 300, S_ISGID | 0o775);

        let plan = plan_setgid_create_inheritance(
            &parent,
            200,
            S_ISGID | 0o660,
            CreatedEntryKind::NonDirectory,
        );

        assert_eq!(
            plan,
            SetgidCreatePlan {
                gid: 300,
                mode: S_ISGID | 0o660,
                gid_source: SetgidCreateGidSource::ParentDirectory,
            }
        );
    }

    // =====================================================================
    // Xattr namespace validation tests
    // =====================================================================

    #[test]
    fn namespace_user_ok() {
        assert_eq!(
            validate_xattr_namespace(b"user.myattr"),
            Ok(XattrNamespace::User)
        );
    }

    #[test]
    fn namespace_system_ok() {
        assert_eq!(
            validate_xattr_namespace(b"system.posix_acl_access"),
            Ok(XattrNamespace::System)
        );
    }

    #[test]
    fn namespace_security_ok() {
        assert_eq!(
            validate_xattr_namespace(b"security.selinux"),
            Ok(XattrNamespace::Security)
        );
    }

    #[test]
    fn namespace_trusted_ok() {
        assert_eq!(
            validate_xattr_namespace(b"trusted.overlay"),
            Ok(XattrNamespace::Trusted)
        );
    }

    #[test]
    fn namespace_user_just_dot_rejected() {
        assert_eq!(
            validate_xattr_namespace(b"user."),
            Err(XattrNamespaceError::UnknownNamespace)
        );
    }

    #[test]
    fn namespace_empty_rejected() {
        assert_eq!(
            validate_xattr_namespace(b""),
            Err(XattrNamespaceError::EmptyName)
        );
    }

    #[test]
    fn namespace_no_prefix_rejected() {
        assert_eq!(
            validate_xattr_namespace(b"myattr"),
            Err(XattrNamespaceError::UnknownNamespace)
        );
    }

    #[test]
    fn namespace_unknown_prefix_rejected() {
        assert_eq!(
            validate_xattr_namespace(b"custom.myattr"),
            Err(XattrNamespaceError::UnknownNamespace)
        );
    }

    #[test]
    fn namespace_length_overflow_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(
            validate_xattr_namespace(&long),
            Err(XattrNamespaceError::NameTooLong)
        );
    }

    #[test]
    fn namespace_max_length_accepted() {
        // "user." (5) + 250 'a' = 255
        let mut name = b"user.".to_vec();
        name.extend(vec![b'a'; 250]);
        assert_eq!(validate_xattr_namespace(&name), Ok(XattrNamespace::User));
    }

    // =====================================================================
    // Xattr store CRUD tests
    // =====================================================================

    #[test]
    fn xattr_insert_and_get() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.foo", b"bar").unwrap();
        assert_eq!(store.getxattr(1, b"user.foo"), Some(b"bar".to_vec()));
    }

    #[test]
    fn xattr_overwrite() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.foo", b"v1").unwrap();
        store.setxattr(1, b"user.foo", b"v2").unwrap();
        assert_eq!(store.getxattr(1, b"user.foo"), Some(b"v2".to_vec()));
    }

    #[test]
    fn xattr_list_keys() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.a", b"1").unwrap();
        store.setxattr(1, b"user.b", b"2").unwrap();
        store.setxattr(1, b"system.c", b"3").unwrap();
        let mut names = store.listxattr(1);
        names.sort();
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], b"system.c");
        assert_eq!(names[1], b"user.a");
        assert_eq!(names[2], b"user.b");
    }

    #[test]
    fn xattr_list_only_requested_inode() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.a", b"1").unwrap();
        store.setxattr(2, b"user.b", b"2").unwrap();
        assert_eq!(store.listxattr(1).len(), 1);
        assert_eq!(store.listxattr(2).len(), 1);
        assert!(store.listxattr(3).is_empty());
    }

    #[test]
    fn xattr_remove_existing() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.foo", b"bar").unwrap();
        assert!(store.removexattr(1, b"user.foo").is_ok());
        assert!(store.getxattr(1, b"user.foo").is_none());
    }

    #[test]
    fn xattr_remove_nonexistent() {
        let mut store = XattrMap::new();
        assert_eq!(
            store.removexattr(1, b"user.nope"),
            Err(XattrMapError::NotFound)
        );
    }

    #[test]
    fn xattr_list_after_remove() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.a", b"1").unwrap();
        store.setxattr(1, b"user.b", b"2").unwrap();
        store.removexattr(1, b"user.a").unwrap();
        let names = store.listxattr(1);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], b"user.b");
    }

    #[test]
    fn xattr_get_nonexistent() {
        let store = XattrMap::new();
        assert!(store.getxattr(1, b"user.nope").is_none());
    }

    #[test]
    fn xattr_get_nonexistent_inode() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.foo", b"bar").unwrap();
        assert!(store.getxattr(2, b"user.foo").is_none());
    }

    #[test]
    fn xattr_set_rejects_bad_namespace() {
        let mut store = XattrMap::new();
        assert!(store.setxattr(1, b"bad.attr", b"v").is_err());
        assert!(store.setxattr(1, b"", b"v").is_err());
        assert!(store.setxattr(1, b"user.", b"v").is_err());
    }

    #[test]
    fn xattr_remove_rejects_bad_namespace() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.foo", b"bar").unwrap();
        assert!(store.removexattr(1, b"bad.attr").is_err());
        // Existing entry still present
        assert!(store.getxattr(1, b"user.foo").is_some());
    }

    #[test]
    fn xattr_remove_all_clears_inode() {
        let mut store = XattrMap::new();
        store.setxattr(1, b"user.a", b"1").unwrap();
        store.setxattr(1, b"user.b", b"2").unwrap();
        store.setxattr(2, b"user.c", b"3").unwrap();
        let removed = store.remove_all(1);
        assert_eq!(removed, 2);
        assert!(store.listxattr(1).is_empty());
        assert_eq!(store.listxattr(2).len(), 1);
    }

    #[test]
    fn xattr_remove_all_empty_inode() {
        let mut store = XattrMap::new();
        store.setxattr(2, b"user.a", b"1").unwrap();
        let removed = store.remove_all(1);
        assert_eq!(removed, 0);
        assert_eq!(store.listxattr(2).len(), 1);
    }

    #[test]
    fn xattr_bulk_set() {
        let mut store = XattrMap::new();
        store
            .bulk_set(
                1,
                vec![
                    (b"user.a".to_vec(), b"1".to_vec()),
                    (b"user.b".to_vec(), b"2".to_vec()),
                    (b"system.c".to_vec(), b"3".to_vec()),
                ],
            )
            .unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.getxattr(1, b"user.b"), Some(b"2".to_vec()));
    }

    #[test]
    fn xattr_bulk_set_rejects_bad_namespace() {
        let mut store = XattrMap::new();
        let result = store.bulk_set(
            1,
            vec![
                (b"user.a".to_vec(), b"1".to_vec()),
                (b"bad.attr".to_vec(), b"2".to_vec()),
            ],
        );
        assert!(result.is_err());
        // No partial writes
        assert!(store.is_empty());
    }

    #[test]
    fn xattr_len_and_is_empty() {
        let mut store = XattrMap::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.setxattr(1, b"user.a", b"v").unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    // =====================================================================
    // Default ACL roundtrip through xattr serialization
    // =====================================================================

    #[test]
    fn default_acl_roundtrip_via_xattr_store() {
        let default_acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];
        let encoded = encode_posix_acl_xattr(&default_acl);

        let mut store = XattrMap::new();
        store
            .setxattr(1, b"system.posix_acl_default", &encoded)
            .unwrap();

        let retrieved = store.getxattr(1, b"system.posix_acl_default").unwrap();
        let decoded = decode_posix_acl_xattr(&retrieved).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].perm, 7);
        assert_eq!(decoded[1].perm, 5);
        assert_eq!(decoded[2].perm, 5);
    }

    #[test]
    fn access_acl_roundtrip_via_xattr_store() {
        let access_acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 4,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let encoded = encode_posix_acl_xattr(&access_acl);

        let mut store = XattrMap::new();
        store
            .setxattr(1, b"system.posix_acl_access", &encoded)
            .unwrap();

        let retrieved = store.getxattr(1, b"system.posix_acl_access").unwrap();
        let decoded = decode_posix_acl_xattr(&retrieved).unwrap();
        assert_eq!(decoded, access_acl);
    }

    // =====================================================================
    // Constant validation tests
    // =====================================================================

    #[test]
    fn permission_constants_match_posix_octal_values() {
        assert_eq!(S_IRUSR, 0o400, "S_IRUSR should be 0o400");
        assert_eq!(S_IWUSR, 0o200, "S_IWUSR should be 0o200");
        assert_eq!(S_IXUSR, 0o100, "S_IXUSR should be 0o100");
        assert_eq!(S_IRGRP, 0o040, "S_IRGRP should be 0o040");
        assert_eq!(S_IWGRP, 0o020, "S_IWGRP should be 0o020");
        assert_eq!(S_IXGRP, 0o010, "S_IXGRP should be 0o010");
        assert_eq!(S_IROTH, 0o004, "S_IROTH should be 0o004");
        assert_eq!(S_IWOTH, 0o002, "S_IWOTH should be 0o002");
        assert_eq!(S_IXOTH, 0o001, "S_IXOTH should be 0o001");
        assert_eq!(S_ISUID, 0o4000, "S_ISUID should be 0o4000");
        assert_eq!(S_ISGID, 0o2000, "S_ISGID should be 0o2000");
        assert_eq!(S_ISVTX, 0o1000, "S_ISVTX should be 0o1000");
    }

    #[test]
    fn access_constants_cover_all_combinations() {
        assert_eq!(ACCESS_READ, 0x04);
        assert_eq!(ACCESS_WRITE, 0x02);
        assert_eq!(ACCESS_EXECUTE, 0x01);
        assert_eq!(ACCESS_NONE, 0x00);
        assert_eq!(ACCESS_RDWR, 0x06, "ACCESS_RDWR = READ | WRITE");
        assert_eq!(ACCESS_RWX, 0x07, "ACCESS_RWX = READ | WRITE | EXECUTE");
        assert_eq!(ACCESS_VALID_MASK, 0x07, "ACCESS_VALID_MASK = ACCESS_RWX");
    }

    #[test]
    fn access_constants_are_bitwise_disjoint() {
        // READ, WRITE, EXECUTE each occupy a single distinct bit
        assert_eq!(ACCESS_READ & ACCESS_WRITE, 0);
        assert_eq!(ACCESS_READ & ACCESS_EXECUTE, 0);
        assert_eq!(ACCESS_WRITE & ACCESS_EXECUTE, 0);
    }

    // =====================================================================
    // Access request validation direct tests
    // =====================================================================

    #[test]
    fn validate_access_request_accepts_valid_single_bits() {
        assert_eq!(validate_access_request(ACCESS_READ), Ok(()));
        assert_eq!(validate_access_request(ACCESS_WRITE), Ok(()));
        assert_eq!(validate_access_request(ACCESS_EXECUTE), Ok(()));
        assert_eq!(validate_access_request(ACCESS_NONE), Ok(()));
    }

    #[test]
    fn validate_access_request_accepts_valid_combinations() {
        assert_eq!(validate_access_request(ACCESS_READ | ACCESS_WRITE), Ok(()));
        assert_eq!(validate_access_request(ACCESS_RDWR), Ok(()));
        assert_eq!(validate_access_request(ACCESS_RWX), Ok(()));
    }

    #[test]
    fn validate_access_request_rejects_high_bits() {
        assert_eq!(
            validate_access_request(0x08),
            Err(AccessRequestError::InvalidMask {
                requested: 0x08,
                invalid_bits: 0x08,
            })
        );
        assert_eq!(
            validate_access_request(0x10),
            Err(AccessRequestError::InvalidMask {
                requested: 0x10,
                invalid_bits: 0x10,
            })
        );
        assert_eq!(
            validate_access_request(0x80),
            Err(AccessRequestError::InvalidMask {
                requested: 0x80,
                invalid_bits: 0x80,
            })
        );
    }

    #[test]
    fn validate_access_request_reports_all_invalid_bits() {
        // Requesting bits 0x08 and 0x10 together
        assert_eq!(
            validate_access_request(0x18),
            Err(AccessRequestError::InvalidMask {
                requested: 0x18,
                invalid_bits: 0x18,
            })
        );
    }

    #[test]
    fn validate_access_request_accepts_valid_bits_with_low_bits() {
        // Bits 0-2 are valid, bit 0x08 invalid
        assert_eq!(
            validate_access_request(ACCESS_RWX | 0x08),
            Err(AccessRequestError::InvalidMask {
                requested: ACCESS_RWX | 0x08,
                invalid_bits: 0x08,
            })
        );
    }

    // =====================================================================
    // check_access root bypass with ACL
    // =====================================================================

    #[test]
    fn check_access_root_bypasses_acl_deny_all() {
        // ACL denies everyone, but root should still get through
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(check_access(
            &ino,
            Some(&acl),
            0,
            0,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(check_access(
            &ino,
            Some(&acl),
            0,
            0,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT
        ));
        assert!(check_access(
            &ino,
            Some(&acl),
            0,
            0,
            &[],
            ACCESS_EXECUTE,
            &VALID_MOUNT
        ));
        assert!(check_access(
            &ino,
            Some(&acl),
            0,
            0,
            &[],
            ACCESS_RWX,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn check_access_non_root_denied_by_deny_all_acl() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let ino = TestInode::new(1000, 100, 0o777); // mode is permissive, ACL overrides
        assert!(!check_access(
            &ino,
            Some(&acl),
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            2000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        assert!(!check_access(
            &ino,
            Some(&acl),
            3000,
            300,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn check_access_non_root_falls_back_to_mode_when_acl_none() {
        let ino = TestInode::new(1000, 100, 0o400);
        assert!(check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
        // Non-owner, non-group -> other bits (0)
        assert!(!check_access(
            &ino,
            None,
            2000,
            200,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    // =====================================================================
    // Xattr namespace enum and error tests
    // =====================================================================

    #[test]
    fn xattr_namespace_variants_are_distinct() {
        // Each variant represents a different namespace
        assert_ne!(XattrNamespace::Security, XattrNamespace::System);
        assert_ne!(XattrNamespace::Security, XattrNamespace::Trusted);
        assert_ne!(XattrNamespace::Security, XattrNamespace::User);
        assert_ne!(XattrNamespace::System, XattrNamespace::Trusted);
        assert_ne!(XattrNamespace::System, XattrNamespace::User);
        assert_ne!(XattrNamespace::Trusted, XattrNamespace::User);
    }

    #[test]
    fn xattr_namespace_error_empty_name() {
        assert_eq!(
            validate_xattr_namespace(b""),
            Err(XattrNamespaceError::EmptyName)
        );
    }

    #[test]
    fn xattr_namespace_error_name_too_long_at_boundary() {
        let name_256 = vec![b'a'; 256];
        assert_eq!(
            validate_xattr_namespace(&name_256),
            Err(XattrNamespaceError::NameTooLong)
        );
        // 255 is OK
        let mut name_255 = b"user.".to_vec();
        name_255.extend(vec![b'a'; 250]);
        assert!(validate_xattr_namespace(&name_255).is_ok());
    }

    #[test]
    fn xattr_map_error_from_namespace_error() {
        let ns_err = XattrNamespaceError::EmptyName;
        let map_err: XattrMapError = ns_err.into();
        assert_eq!(map_err, XattrMapError::InvalidNamespace(ns_err));
    }

    #[test]
    fn xattr_map_error_not_found_is_distinct() {
        assert_ne!(
            XattrMapError::NotFound,
            XattrMapError::InvalidNamespace(XattrNamespaceError::EmptyName)
        );
    }

    // =====================================================================
    // check_pass_validated_access edge cases
    // =====================================================================

    #[test]
    fn validated_access_accepts_none_with_root() {
        let ino = TestInode::new(1000, 100, 0o000);
        assert_eq!(
            check_validated_access(&ino, None, 0, 0, &[], ACCESS_NONE, &VALID_MOUNT),
            Ok(true)
        );
    }

    #[test]
    fn validated_access_rejects_none_with_invalid_bits() {
        let ino = TestInode::new(1000, 100, 0o777);
        assert_eq!(
            check_validated_access(&ino, None, 1000, 100, &[], ACCESS_NONE | 0x08, &VALID_MOUNT),
            Err(AccessRequestError::InvalidMask {
                requested: ACCESS_NONE | 0x08,
                invalid_bits: 0x08,
            })
        );
    }

    #[test]
    fn mode_owner_check_preserves_access_none_always_true() {
        // ACCESS_NONE after validation always returns true (F_OK semantics)
        let ino = TestInode::new(1000, 100, 0o000);
        assert!(check_mode_access(
            &ino,
            2000,
            200,
            &[],
            ACCESS_NONE,
            &VALID_MOUNT
        ));
        assert!(check_mode_access(
            &ino,
            0,
            0,
            &[],
            ACCESS_NONE,
            &VALID_MOUNT
        ));
    }

    // =====================================================================
    // StickyDirectoryDeleteAllow enum tests
    // =====================================================================

    #[test]
    fn sticky_allow_variants_are_distinct() {
        assert_ne!(
            StickyDirectoryDeleteAllow::DirectoryNotSticky,
            StickyDirectoryDeleteAllow::Root
        );
        assert_ne!(
            StickyDirectoryDeleteAllow::Root,
            StickyDirectoryDeleteAllow::DirectoryOwner
        );
        assert_ne!(
            StickyDirectoryDeleteAllow::DirectoryOwner,
            StickyDirectoryDeleteAllow::VictimOwner
        );
    }

    // =====================================================================
    // StickyDirectoryRenameDeny + CreatedEntryKind + SetgidCreateGidSource
    // =====================================================================

    #[test]
    fn sticky_rename_deny_variants_are_distinct() {
        assert_ne!(
            StickyDirectoryRenameDeny::Source,
            StickyDirectoryRenameDeny::Target
        );
    }

    #[test]
    fn created_entry_kind_variants_are_distinct() {
        assert_ne!(CreatedEntryKind::Directory, CreatedEntryKind::NonDirectory);
    }

    #[test]
    fn setgid_create_gid_source_variants_are_distinct() {
        assert_ne!(
            SetgidCreateGidSource::Caller,
            SetgidCreateGidSource::ParentDirectory
        );
    }

    // =====================================================================
    // XATTR_NAME_MAX constant
    // =====================================================================

    #[test]
    fn xattr_name_max_matches_posix_value() {
        assert_eq!(XATTR_NAME_MAX, 255);
    }

    // =====================================================================
    // Mount identity binding tests
    // =====================================================================

    #[test]
    fn mount_identity_valid_allows_access() {
        let ino = TestInode::new(1000, 100, 0o644);
        assert!(check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mount_identity_zero_epoch_denies_access() {
        let ino = TestInode::new(1000, 100, 0o644);
        // Zero epoch — invalid mount
        assert!(!check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &INVALID_MOUNT_ZERO_EPOCH
        ));
    }

    #[test]
    fn mount_identity_invalid_denies_root() {
        let ino = TestInode::new(1000, 100, 0o644);
        // Even root (uid 0) is denied when mount identity is invalid
        assert!(!check_access(
            &ino,
            None,
            0,
            0,
            &[],
            ACCESS_READ,
            &INVALID_MOUNT_ZERO_EPOCH
        ));
    }

    #[test]
    fn mount_identity_valid_allows_root() {
        let ino = TestInode::new(1000, 100, 0o000); // no permissions
        assert!(check_access(
            &ino,
            None,
            0,
            0,
            &[],
            ACCESS_READ,
            &VALID_MOUNT
        ));
    }

    #[test]
    fn mount_identity_root_dataset_with_epoch_is_valid() {
        let ino = TestInode::new(1000, 100, 0o644);
        assert!(check_access(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &ROOT_MOUNT
        ));
        assert_eq!(validate_mount_identity(&ROOT_MOUNT), Ok(()));
    }

    #[test]
    fn mount_identity_different_id_same_epoch_are_distinct() {
        let m1 = MountIdentity::new([0x01u8; 16], 1);
        let m2 = MountIdentity::new([0x02u8; 16], 1);
        assert_ne!(m1, m2);
    }

    #[test]
    fn mount_identity_same_id_different_epoch_are_distinct() {
        let m1 = MountIdentity::new([0x01u8; 16], 1);
        let m2 = MountIdentity::new([0x01u8; 16], 2);
        assert_ne!(m1, m2);
    }

    #[test]
    fn validate_mount_identity_accepts_valid() {
        assert_eq!(validate_mount_identity(&VALID_MOUNT), Ok(()));
    }

    #[test]
    fn validate_mount_identity_rejects_invalid() {
        assert_eq!(
            validate_mount_identity(&INVALID_MOUNT_ZERO_EPOCH),
            Err(MountIdentityError::InvalidMountIdentity)
        );
    }

    #[test]
    fn check_access_result_fails_on_invalid_mount() {
        let ino = TestInode::new(1000, 100, 0o644);
        assert_eq!(
            check_access_result(&ino, 1000, 100, AccessMode::Read, &INVALID_MOUNT_ZERO_EPOCH),
            Err(PermissionError::AccessDenied)
        );
    }

    #[test]
    fn check_search_fails_on_invalid_mount() {
        let dir = TestInode::new(1000, 100, S_IFDIR | 0o755);
        assert_eq!(
            check_search(&dir, 1000, 100, &INVALID_MOUNT_ZERO_EPOCH),
            Err(PermissionError::AccessDenied)
        );
    }

    #[test]
    fn check_validated_access_fails_on_invalid_mount() {
        let ino = TestInode::new(1000, 100, 0o644);
        assert_eq!(
            check_validated_access(
                &ino,
                None,
                1000,
                100,
                &[],
                ACCESS_READ,
                &INVALID_MOUNT_ZERO_EPOCH
            ),
            Ok(false)
        );
    }

    #[test]
    fn check_access_report_records_mount_identity() {
        let ino = TestInode::new(1000, 100, 0o644);
        let report = check_access_report(&ino, None, 1000, 100, &[], ACCESS_READ, &VALID_MOUNT)
            .expect("valid access report");

        assert_eq!(report.mount_identity, VALID_MOUNT);
        assert_eq!(report.requested, ACCESS_READ);
        assert!(report.allowed);
    }

    #[test]
    fn check_access_report_records_invalid_mount_fail_closed() {
        let ino = TestInode::new(1000, 100, 0o644);
        let report = check_access_report(
            &ino,
            None,
            1000,
            100,
            &[],
            ACCESS_READ,
            &INVALID_MOUNT_ZERO_EPOCH,
        )
        .expect("invalid mount returns a fail-closed report");

        assert_eq!(report.mount_identity, INVALID_MOUNT_ZERO_EPOCH);
        assert_eq!(report.requested, ACCESS_READ);
        assert!(!report.allowed);
    }

    #[test]
    fn can_read_fails_on_invalid_mount() {
        let ino = TestInode::new(1000, 100, 0o644);
        assert!(!can_read(
            &ino,
            None,
            1000,
            100,
            &[],
            &INVALID_MOUNT_ZERO_EPOCH
        ));
    }

    #[test]
    fn can_lookup_fails_on_invalid_mount() {
        let ino = TestInode::new(1000, 100, S_IFDIR | 0o755);
        assert!(!can_lookup(
            &ino,
            None,
            1000,
            100,
            &[],
            &INVALID_MOUNT_ZERO_EPOCH
        ));
    }
}
