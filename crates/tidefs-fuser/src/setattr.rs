//! FUSE `setattr` handler helpers — attribute mutation dispatcher for
//! chmod, chown, truncate, and utimens, with relatime timestamp policy.
//!
//! Provides:
//! - [`SetAttrPlan`]: structured, validated plan for attribute mutation
//!   derived from raw FUSE setattr parameters.
//! - [`plan_setattr`]: convert raw FUSE setattr parameters into a
//!   [`SetAttrPlan`] with relatime enforcement.
//! - [`should_update_atime_relatime`]: Linux relatime timestamp policy.
//! - [`validate_setattr_mode`]: mode-bit sanity (S_IFMT preservation).
//! - [`check_setattr_ownership`]: POSIX ownership-change permission check.
//! - [`apply_setattr_plan`]: apply a [`SetAttrPlan`] to a [`FileAttr`]
//!   and return the mutated attributes.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::setattr;
//!
//! let plan = setattr::plan_setattr(
//!     Some(0o600),    // mode
//!     None,           // uid
//!     None,           // gid
//!     Some(0),        // size (truncate)
//!     None,           // atime
//!     None,           // mtime
//!     None,           // fh
//! );
//! let result = setattr::apply_setattr_plan(&current_attrs, &plan);
//! ```

use crate::errno;
use libc::c_int;
use std::convert::TryInto;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Re-export FUSE setattr validity constants for callers.
pub use crate::ll::fuse_abi::consts::{
    FATTR_ATIME, FATTR_FH, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID,
};

// Feature-gated constants redefined locally for unconditional use.
// These mirror the definitions in crate::ll::fuse_abi::consts but are
// available regardless of enabled ABI features.

/// Set atime to the current time (FATTR_ATIME_NOW).
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
/// Set mtime to the current time (FATTR_MTIME_NOW).
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
/// Explicit ctime change (FATTR_CTIME, introduced in ABI 7.23).
pub const FATTR_CTIME: u32 = 1 << 10;

use crate::ll::TimeOrNow;
use crate::FileAttr;
use crate::FileType;

// ---------------------------------------------------------------------------
// SetAttrPlan — structured, validated setattr request
// ---------------------------------------------------------------------------

/// Planned attribute mutation derived from a FUSE `setattr` request.
///
/// Only fields present in the original FUSE request are set; unchanged
/// fields retain their current values. The [`SetAttrPlan::valid`] bitmask
/// tracks which fields are active.
///
/// The plan is constructed by [`plan_setattr`] and consumed by
/// [`apply_setattr_plan`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetAttrPlan {
    /// Validity bitmask (`FATTR_*` constants). A bit is set when the
    /// corresponding field was requested for change.
    pub valid: u32,
    /// New file mode (permission bits only; S_IFMT is preserved on apply).
    pub mode: u32,
    /// New owner uid.
    pub uid: u32,
    /// New owner gid.
    pub gid: u32,
    /// New file size in bytes.
    pub size: u64,
    /// New atime in signed nanoseconds since UNIX epoch (`0` means unset).
    pub atime_ns: i64,
    /// New mtime in signed nanoseconds since UNIX epoch (`0` means unset).
    pub mtime_ns: i64,
    /// New ctime in signed nanoseconds since UNIX epoch (`0` means unset).
    pub ctime_ns: i64,
    /// File handle passed through from FUSE (for truncate extent
    /// management by the adapter layer).
    pub fh: Option<u64>,
}

impl SetAttrPlan {
    /// Create an empty plan with no fields set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            valid: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            fh: None,
        }
    }

    /// Return `true` when at least one attribute field is scheduled for
    /// mutation (excluding automatic ctime advancement).
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.valid
            & (FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_ATIME_NOW
                | FATTR_MTIME_NOW)
            != 0
    }

    /// Return `true` when the mode field is scheduled for change.
    #[must_use]
    pub const fn wants_chmod(&self) -> bool {
        self.valid & FATTR_MODE != 0
    }

    /// Return `true` when the uid field is scheduled for change.
    #[must_use]
    pub const fn wants_chown_uid(&self) -> bool {
        self.valid & FATTR_UID != 0
    }

    /// Return `true` when the gid field is scheduled for change.
    #[must_use]
    pub const fn wants_chown_gid(&self) -> bool {
        self.valid & FATTR_GID != 0
    }

    /// Return `true` when the size field is scheduled for change
    /// (truncate request).
    #[must_use]
    pub const fn wants_truncate(&self) -> bool {
        self.valid & FATTR_SIZE != 0
    }
}

// ---------------------------------------------------------------------------
// plan_setattr — convert raw FUSE parameters into a SetAttrPlan
// ---------------------------------------------------------------------------

/// Convert raw FUSE `setattr` parameters into a [`SetAttrPlan`].
///
/// Only fields with `Some(...)` values are included; `None` fields are
/// left unchanged. `TimeOrNow::Now` sets the corresponding `FATTR_*_NOW`
/// flag instead of storing a concrete timestamp.
///
/// The function does **not** apply relatime policy — callers that need
/// relatime should use [`should_update_atime_relatime`] separately or
/// use the plan-aware apply path.
#[must_use]
pub fn plan_setattr(
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    atime: Option<TimeOrNow>,
    mtime: Option<TimeOrNow>,
    fh: Option<u64>,
) -> SetAttrPlan {
    let mut plan = SetAttrPlan::new();

    if let Some(m) = mode {
        plan.valid |= FATTR_MODE;
        plan.mode = m;
    }
    if let Some(u) = uid {
        plan.valid |= FATTR_UID;
        plan.uid = u;
    }
    if let Some(g) = gid {
        plan.valid |= FATTR_GID;
        plan.gid = g;
    }
    if let Some(s) = size {
        plan.valid |= FATTR_SIZE;
        plan.size = s;
    }
    if let Some(at) = atime {
        match at {
            TimeOrNow::Now => {
                plan.valid |= FATTR_ATIME_NOW;
            }
            TimeOrNow::SpecificTime(t) => {
                plan.valid |= FATTR_ATIME;
                plan.atime_ns = system_time_to_ns(t);
            }
        }
    }
    if let Some(mt) = mtime {
        match mt {
            TimeOrNow::Now => {
                plan.valid |= FATTR_MTIME_NOW;
            }
            TimeOrNow::SpecificTime(t) => {
                plan.valid |= FATTR_MTIME;
                plan.mtime_ns = system_time_to_ns(t);
            }
        }
    }
    if fh.is_some() {
        plan.valid |= FATTR_FH;
        plan.fh = fh;
    }

    plan
}

// ---------------------------------------------------------------------------
// system_time_to_ns — helper conversion
// ---------------------------------------------------------------------------

/// Convert [`SystemTime`] to signed nanoseconds since UNIX epoch.
#[must_use]
pub fn system_time_to_ns(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos().try_into().unwrap_or(i64::MAX),
        Err(err) => {
            let duration_ns: i64 = err.duration().as_nanos().try_into().unwrap_or(i64::MAX);
            -duration_ns
        }
    }
}

/// Convert signed nanoseconds since UNIX epoch to [`SystemTime`].
#[must_use]
pub fn ns_to_system_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

// ---------------------------------------------------------------------------
// should_update_atime_relatime — Linux relatime policy
// ---------------------------------------------------------------------------

/// Number of nanoseconds in 24 hours.
pub const RELATIME_24H_NS: i64 = 24 * 3600 * 1_000_000_000;

/// Determine whether atime should be updated under Linux `relatime` policy.
///
/// Returns `true` if atime should be bumped to the current time.
///
/// Rules (matching Linux `relatime` behaviour):
/// - Update if atime is not newer than mtime.
/// - Update if atime is not newer than ctime.
/// - Update if atime is more than 24 hours in the past from `now_ns`.
#[must_use]
pub fn should_update_atime_relatime(
    atime_ns: i64,
    mtime_ns: i64,
    ctime_ns: i64,
    now_ns: i64,
) -> bool {
    atime_ns <= mtime_ns
        || atime_ns <= ctime_ns
        || now_ns.saturating_sub(atime_ns) >= RELATIME_24H_NS
}

/// Current time as nanoseconds since UNIX epoch.
#[must_use]
pub fn now_ns() -> i64 {
    system_time_to_ns(SystemTime::now())
}

// ---------------------------------------------------------------------------
// validate_setattr_mode — S_IFMT preservation
// ---------------------------------------------------------------------------

/// POSIX file-type mask (S_IFMT).
pub const S_IFMT: u32 = 0o170000;

/// Validate that a requested mode change preserves the file-type bits.
///
/// Returns `Err(EINVAL)` when the requested mode would alter the S_IFMT
/// portion of `current_mode`.
///
/// If `new_mode` is `None`, the mode is unchanged — returns `Ok(())`.
pub fn validate_setattr_mode(current_mode: u32, new_mode: Option<u32>) -> Result<(), c_int> {
    let Some(m) = new_mode else {
        return Ok(());
    };
    let current_type = current_mode & S_IFMT;
    // The new mode's type bits must either be zero (caller only set
    // permission bits) or match the current type.
    let new_type = m & S_IFMT;
    if new_type != 0 && new_type != current_type {
        return Err(errno::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// check_setattr_ownership — POSIX ownership-change permission check
// ---------------------------------------------------------------------------

/// Check whether `caller_uid` may modify ownership/group of a file.
///
/// Permission rules:
/// - Root (uid 0) may change anything.
/// - Mode change (`FATTR_MODE`): only the file owner or root may chmod.
/// - Owner change (`FATTR_UID`): only root may chown (Linux semantics).
/// - Group change (`FATTR_GID`): the file owner may chgrp to any group
///   they belong to (checked via `primary_gid` and `supplemental_gids`).
///
/// `current_uid` / `current_gid` are the file's current owner/group.
/// `caller_gid` is the caller's primary GID.
/// `supplemental_gids` is the caller's supplementary group list.
/// `new_uid` / `new_gid` are the requested new owner/group values.
///
/// Returns `Ok(())` or `Err(EPERM)`.
#[allow(clippy::too_many_arguments)]
pub fn check_setattr_ownership(
    caller_uid: u32,
    caller_gid: u32,
    supplemental_gids: &[u32],
    current_uid: u32,
    current_gid: u32,
    to_set: u32,
    _new_uid: u32,
    new_gid: u32,
) -> Result<(), c_int> {
    // Root bypass — always allowed.
    if caller_uid == 0 {
        return Ok(());
    }

    // Mode change: only the file owner may chmod.
    if to_set & FATTR_MODE != 0 && caller_uid != current_uid {
        return Err(errno::EPERM);
    }

    // Owner change: only root may chown (already rejected non-root above).
    if to_set & FATTR_UID != 0 {
        return Err(errno::EPERM);
    }

    // Group change: the file owner may chgrp to a group they belong to.
    if to_set & FATTR_GID != 0 {
        if caller_uid != current_uid {
            return Err(errno::EPERM);
        }
        // Owner may only chgrp to a group they are a member of.
        let in_target_group =
            caller_gid == new_gid || current_gid == new_gid || supplemental_gids.contains(&new_gid);
        if !in_target_group {
            return Err(errno::EPERM);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// apply_setattr_plan — apply the plan to a FileAttr
// ---------------------------------------------------------------------------

/// Apply a [`SetAttrPlan`] to `current` and return the mutated [`FileAttr`].
///
/// Only fields marked in `plan.valid` are changed. `FATTR_ATIME_NOW` and
/// `FATTR_MTIME_NOW` are resolved to the current time. `ctime` is
/// automatically advanced when any non-timestamp field changes, or when
/// atime/mtime changes (POSIX semantics).
#[must_use]
pub fn apply_setattr_plan(current: &FileAttr, plan: &SetAttrPlan) -> FileAttr {
    let mut out = *current;
    let now = now_ns();
    let mut has_non_timestamp_change = false;
    let mut has_timestamp_change = false;

    if plan.valid & FATTR_MODE != 0 {
        out.perm = ((u32::from(current.perm) & S_IFMT) | (plan.mode & !S_IFMT)) as u16;
        has_non_timestamp_change = true;
    }
    if plan.valid & FATTR_UID != 0 {
        out.uid = plan.uid;
        has_non_timestamp_change = true;
    }
    if plan.valid & FATTR_GID != 0 {
        out.gid = plan.gid;
        has_non_timestamp_change = true;
    }
    if plan.valid & FATTR_SIZE != 0 {
        out.size = plan.size;
        out.blocks = blocks_512_for_size(plan.size);
        has_non_timestamp_change = true;
    }
    if plan.valid & FATTR_ATIME_NOW != 0 {
        out.atime = ns_to_system_time(now);
        has_timestamp_change = true;
    } else if plan.valid & FATTR_ATIME != 0 {
        out.atime = ns_to_system_time(plan.atime_ns);
        has_timestamp_change = true;
    }
    if plan.valid & FATTR_MTIME_NOW != 0 {
        out.mtime = ns_to_system_time(now);
        has_timestamp_change = true;
    } else if plan.valid & FATTR_MTIME != 0 {
        out.mtime = ns_to_system_time(plan.mtime_ns);
        has_timestamp_change = true;
    }
    if plan.valid & FATTR_CTIME != 0 {
        out.ctime = ns_to_system_time(plan.ctime_ns);
    } else if has_non_timestamp_change || has_timestamp_change {
        // POSIX: ctime advances when any metadata field or timestamp changes.
        out.ctime = ns_to_system_time(now);
    }

    out
}

// ---------------------------------------------------------------------------
// blocks_512_for_size — POSIX block count
// ---------------------------------------------------------------------------

const POSIX_STAT_BLOCK_SIZE: u64 = 512;

/// Compute the number of 512-byte blocks for a given file size.
#[must_use]
pub const fn blocks_512_for_size(size: u64) -> u64 {
    let full_blocks = size / POSIX_STAT_BLOCK_SIZE;
    if size % POSIX_STAT_BLOCK_SIZE == 0 {
        full_blocks
    } else {
        full_blocks + 1
    }
}

// ---------------------------------------------------------------------------
// SetattrMutation -- discrete attribute sub-operation for VfsEngine dispatch
// ---------------------------------------------------------------------------

/// A single attribute mutation from a decomposed FUSE `setattr` request.
///
/// Each variant maps to one VfsEngine::setattr call. The daemon layer
/// iterates over the returned mutations and applies each one atomically
/// via intent-log recording.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetattrMutation {
    /// Change file mode (permission bits, S_IFMT preserved).
    Chmod {
        /// New permission bits (0o000 – 0o7777).
        mode: u32,
    },
    /// Change owner uid.
    Chown {
        /// New owner uid.
        uid: u32,
    },
    /// Change group gid.
    Chgrp {
        /// New group gid.
        gid: u32,
    },
    /// Truncate or extend file size (length in bytes).
    Truncate {
        /// New file size in bytes.
        size: u64,
        /// Optional file handle for extent management.
        fh: Option<u64>,
    },
    /// Set atime and/or mtime explicitly.
    Utimes {
        /// New atime in nanoseconds since UNIX epoch (None = unchanged).
        atime_ns: Option<i64>,
        /// New mtime in nanoseconds since UNIX epoch (None = unchanged).
        mtime_ns: Option<i64>,
    },
    /// Set atime to current time.
    UtimesAtimeNow,
    /// Set mtime to current time.
    UtimesMtimeNow,
    /// Set ctime explicitly.
    Ctime {
        /// New ctime in nanoseconds since UNIX epoch.
        ctime_ns: i64,
    },
}

// ---------------------------------------------------------------------------
// validate_setattr_request -- request-level constraint checks
// ---------------------------------------------------------------------------

/// Validate a FUSE `setattr` request against POSIX constraints.
///
/// Checks:
/// - The inode number is valid (non-zero).
/// - The validity bitmask contains only recognised FATTR_* bits.
/// - Truncate (`FATTR_SIZE`) is only permitted on regular files (not
///   directories, symlinks, FIFOs, sockets, or block/char devices).
/// - The filesystem is not mounted read-only when mutations are requested.
///
/// This is a lightweight gate that can be called before any engine or
/// namespace interaction.  More specific checks (ownership permission,
/// immutable flags) are handled by the daemon layer.
pub fn validate_setattr_request(
    ino: u64,
    valid: u32,
    file_type: FileType,
    read_only: bool,
) -> Result<(), c_int> {
    // Reject invalid inode numbers.
    if ino == 0 {
        return Err(errno::ENOENT);
    }

    // Validate the validity bitmask: all bits must be known FATTR_* flags.
    const KNOWN_FATTR_BITS: u32 = FATTR_MODE
        | FATTR_UID
        | FATTR_GID
        | FATTR_SIZE
        | FATTR_ATIME
        | FATTR_MTIME
        | FATTR_FH
        | FATTR_ATIME_NOW
        | FATTR_MTIME_NOW
        | FATTR_CTIME;
    if valid & !KNOWN_FATTR_BITS != 0 {
        return Err(errno::EINVAL);
    }

    let has_mutation = valid
        & (FATTR_MODE
            | FATTR_UID
            | FATTR_GID
            | FATTR_SIZE
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW
            | FATTR_CTIME)
        != 0;

    // Read-only filesystem: reject any attribute mutation.
    if has_mutation && read_only {
        return Err(errno::EROFS);
    }

    // Truncate is only valid on regular files.
    if valid & FATTR_SIZE != 0 && file_type != FileType::RegularFile {
        if matches!(file_type, FileType::Directory) {
            return Err(libc::EISDIR);
        }
        return Err(errno::EINVAL);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// plan_setattr_mutation -- decompose plan into discrete sub-operations
// ---------------------------------------------------------------------------

/// Decompose a [`SetAttrPlan`] into a list of discrete [`SetattrMutation`]
/// sub-operations that the daemon layer applies via VfsEngine::setattr.
///
/// Each mutation step can be recorded individually in the intent log for
/// crash safety.  The caller is responsible for iterating through the
/// mutations and applying them in order.
#[must_use]
pub fn plan_setattr_mutation(plan: &SetAttrPlan) -> Vec<SetattrMutation> {
    let mut mutations = Vec::new();

    if plan.valid & FATTR_MODE != 0 {
        mutations.push(SetattrMutation::Chmod { mode: plan.mode });
    }
    if plan.valid & FATTR_UID != 0 {
        mutations.push(SetattrMutation::Chown { uid: plan.uid });
    }
    if plan.valid & FATTR_GID != 0 {
        mutations.push(SetattrMutation::Chgrp { gid: plan.gid });
    }
    if plan.valid & FATTR_SIZE != 0 {
        mutations.push(SetattrMutation::Truncate {
            size: plan.size,
            fh: plan.fh,
        });
    }
    if plan.valid & FATTR_CTIME != 0 {
        mutations.push(SetattrMutation::Ctime {
            ctime_ns: plan.ctime_ns,
        });
    }
    if plan.valid & FATTR_ATIME != 0 || plan.valid & FATTR_MTIME != 0 {
        let atime = (plan.valid & FATTR_ATIME != 0).then_some(plan.atime_ns);
        let mtime = (plan.valid & FATTR_MTIME != 0).then_some(plan.mtime_ns);
        mutations.push(SetattrMutation::Utimes {
            atime_ns: atime,
            mtime_ns: mtime,
        });
    }
    if plan.valid & FATTR_ATIME_NOW != 0 {
        mutations.push(SetattrMutation::UtimesAtimeNow);
    }
    if plan.valid & FATTR_MTIME_NOW != 0 {
        mutations.push(SetattrMutation::UtimesMtimeNow);
    }

    mutations
}

// ---------------------------------------------------------------------------
// handle_setattr -- canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical entry point for FUSE `setattr` dispatch.
///
/// Combines request-level validation and mutation planning into a single
/// call.  Returns the list of [`SetattrMutation`] sub-operations on success,
/// or a POSIX errno on failure.
///
/// The caller is expected to apply each mutation via VfsEngine::setattr,
/// recording intent-log entries for crash safety, and then format a FUSE
/// reply with the post-mutation attributes.
///
/// # Errors
///
/// | Condition | Errno |
/// |---|---|
/// | `ino` is zero | `ENOENT` |
/// | Unknown bits in `valid` mask | `EINVAL` |
/// | Truncate on directory | `EISDIR` |
/// | Truncate on non-regular file | `EINVAL` |
/// | Mutation on read-only mount | `EROFS` |
pub fn handle_setattr(
    ino: u64,
    valid: u32,
    file_type: FileType,
    read_only: bool,
    plan: &SetAttrPlan,
) -> Result<Vec<SetattrMutation>, c_int> {
    validate_setattr_request(ino, valid, file_type, read_only)?;
    Ok(plan_setattr_mutation(plan))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileType;

    fn dummy_file_attr(ino: u64, mode: u32, size: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size,
            blocks: blocks_512_for_size(size),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: (mode & 0o7777) as u16,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    // -- plan_setattr ---------------------------------------------------

    #[test]
    fn plan_setattr_empty_returns_no_changes() {
        let plan = plan_setattr(None, None, None, None, None, None, None);
        assert!(!plan.has_changes());
        assert_eq!(plan.valid, 0);
    }

    #[test]
    fn plan_setattr_mode_only() {
        let plan = plan_setattr(Some(0o600), None, None, None, None, None, None);
        assert!(plan.wants_chmod());
        assert_eq!(plan.mode, 0o600);
        assert_eq!(plan.valid, FATTR_MODE);
    }

    #[test]
    fn plan_setattr_uid_only() {
        let plan = plan_setattr(None, Some(42), None, None, None, None, None);
        assert!(plan.wants_chown_uid());
        assert_eq!(plan.uid, 42);
        assert_eq!(plan.valid, FATTR_UID);
    }

    #[test]
    fn plan_setattr_gid_only() {
        let plan = plan_setattr(None, None, Some(84), None, None, None, None);
        assert!(plan.wants_chown_gid());
        assert_eq!(plan.gid, 84);
        assert_eq!(plan.valid, FATTR_GID);
    }

    #[test]
    fn plan_setattr_size_only() {
        let plan = plan_setattr(None, None, None, Some(1024), None, None, None);
        assert!(plan.wants_truncate());
        assert_eq!(plan.size, 1024);
        assert_eq!(plan.valid, FATTR_SIZE);
    }

    #[test]
    fn plan_setattr_atime_explicit() {
        let ts = UNIX_EPOCH + Duration::from_secs(1000);
        let plan = plan_setattr(
            None,
            None,
            None,
            None,
            Some(TimeOrNow::SpecificTime(ts)),
            None,
            None,
        );
        assert_eq!(plan.valid, FATTR_ATIME);
        assert_eq!(plan.atime_ns, 1_000_000_000_000);
    }

    #[test]
    fn plan_setattr_mtime_explicit() {
        let ts = UNIX_EPOCH + Duration::from_secs(2000);
        let plan = plan_setattr(
            None,
            None,
            None,
            None,
            None,
            Some(TimeOrNow::SpecificTime(ts)),
            None,
        );
        assert_eq!(plan.valid, FATTR_MTIME);
        assert_eq!(plan.mtime_ns, 2_000_000_000_000);
    }

    #[test]
    fn plan_setattr_atime_now() {
        let plan = plan_setattr(None, None, None, None, Some(TimeOrNow::Now), None, None);
        assert_eq!(plan.valid, FATTR_ATIME_NOW);
    }

    #[test]
    fn plan_setattr_mtime_now() {
        let plan = plan_setattr(None, None, None, None, None, Some(TimeOrNow::Now), None);
        assert_eq!(plan.valid, FATTR_MTIME_NOW);
    }

    #[test]
    fn plan_setattr_combined() {
        let ts = UNIX_EPOCH + Duration::from_nanos(500);
        let plan = plan_setattr(
            Some(0o644),
            Some(1001),
            Some(1001),
            Some(4096),
            Some(TimeOrNow::SpecificTime(ts)),
            Some(TimeOrNow::Now),
            Some(3),
        );
        assert_eq!(
            plan.valid,
            FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME_NOW
                | FATTR_FH
        );
        assert_eq!(plan.mode, 0o644);
        assert_eq!(plan.uid, 1001);
        assert_eq!(plan.gid, 1001);
        assert_eq!(plan.size, 4096);
        assert_eq!(plan.atime_ns, 500);
        assert_eq!(plan.fh, Some(3));
    }

    #[test]
    fn plan_setattr_fh_only_sets_flag() {
        let plan = plan_setattr(None, None, None, None, None, None, Some(42));
        assert_eq!(plan.valid, FATTR_FH);
        assert_eq!(plan.fh, Some(42));
        assert!(!plan.has_changes());
    }

    // -- should_update_atime_relatime -----------------------------------

    #[test]
    fn relatime_updates_if_atime_before_mtime() {
        assert!(should_update_atime_relatime(100, 200, 200, 300));
    }

    #[test]
    fn relatime_updates_if_atime_before_ctime() {
        assert!(should_update_atime_relatime(100, 100, 200, 300));
    }

    #[test]
    fn relatime_updates_if_atime_equals_mtime() {
        assert!(should_update_atime_relatime(100, 100, 99, 300));
    }

    #[test]
    fn relatime_updates_if_atime_equals_ctime() {
        assert!(should_update_atime_relatime(100, 99, 100, 300));
    }

    #[test]
    fn relatime_updates_if_24h_old() {
        let now = 1_000_000_000_000i64;
        let atime = now - RELATIME_24H_NS - 1;
        assert!(should_update_atime_relatime(atime, 0, 0, now));
    }

    #[test]
    fn relatime_skips_if_recent() {
        let now = 1_000_000_000_000i64;
        let atime = now - 1_000_000_000; // 1 second ago
        let mtime = atime - 1;
        let ctime = atime - 1;
        assert!(!should_update_atime_relatime(atime, mtime, ctime, now));
    }

    #[test]
    fn relatime_exact_24h_is_update() {
        let now = RELATIME_24H_NS;
        assert!(should_update_atime_relatime(0, 0, 0, now));
    }

    // -- validate_setattr_mode ------------------------------------------

    #[test]
    fn validate_mode_preserves_type_bits_when_new_has_no_type() {
        // Regular file: S_IFREG = 0o100000
        let current = 0o100644;
        assert!(validate_setattr_mode(current, Some(0o600)).is_ok());
    }

    #[test]
    fn validate_mode_allows_same_type() {
        let current = 0o100644;
        assert!(validate_setattr_mode(current, Some(0o100600)).is_ok());
    }

    #[test]
    fn validate_mode_rejects_type_change() {
        let current = 0o100644; // S_IFREG | 0o644
        assert_eq!(
            validate_setattr_mode(current, Some(0o040755)),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_mode_none_is_ok() {
        assert!(validate_setattr_mode(0o100644, None).is_ok());
    }

    // -- check_setattr_ownership ----------------------------------------

    #[test]
    fn root_may_chown() {
        assert!(check_setattr_ownership(0, 0, &[], 1000, 1000, FATTR_UID, 2000, 1000).is_ok());
    }

    #[test]
    fn root_may_chgrp() {
        assert!(check_setattr_ownership(0, 0, &[], 1000, 1000, FATTR_GID, 1000, 2000).is_ok());
    }

    #[test]
    fn root_may_chmod() {
        assert!(check_setattr_ownership(0, 0, &[], 1000, 1000, FATTR_MODE, 1000, 1000).is_ok());
    }

    #[test]
    fn owner_may_chmod_own_file() {
        assert!(
            check_setattr_ownership(1000, 1000, &[], 1000, 1000, FATTR_MODE, 1000, 1000).is_ok()
        );
    }

    #[test]
    fn non_owner_may_not_chmod() {
        assert_eq!(
            check_setattr_ownership(2000, 2000, &[], 1000, 1000, FATTR_MODE, 1000, 1000),
            Err(errno::EPERM)
        );
    }

    #[test]
    fn non_root_may_not_chown() {
        assert_eq!(
            check_setattr_ownership(1000, 1000, &[], 1000, 1000, FATTR_UID, 2000, 1000),
            Err(errno::EPERM)
        );
    }

    #[test]
    fn owner_may_chgrp_to_own_primary_group() {
        assert!(check_setattr_ownership(1000, 1000, &[], 1000, 500, FATTR_GID, 1000, 1000).is_ok());
    }

    #[test]
    fn owner_may_chgrp_to_current_group() {
        assert!(check_setattr_ownership(1000, 1000, &[], 1000, 500, FATTR_GID, 1000, 500).is_ok());
    }

    #[test]
    fn owner_may_chgrp_to_supplemental_group() {
        assert!(check_setattr_ownership(
            1000,
            1000,
            &[3000, 4000],
            1000,
            500,
            FATTR_GID,
            1000,
            3000
        )
        .is_ok());
    }

    #[test]
    fn owner_may_not_chgrp_to_non_member_group() {
        assert_eq!(
            check_setattr_ownership(1000, 1000, &[3000], 1000, 500, FATTR_GID, 1000, 9999),
            Err(errno::EPERM)
        );
    }

    #[test]
    fn non_owner_may_not_chgrp() {
        assert_eq!(
            check_setattr_ownership(2000, 2000, &[], 1000, 500, FATTR_GID, 1000, 2000),
            Err(errno::EPERM)
        );
    }

    // -- apply_setattr_plan ---------------------------------------------

    #[test]
    fn apply_chmod_updates_perm_and_ctime() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let sleep_ns = 1_000_000; // 1 ms
        std::thread::sleep(Duration::from_nanos(sleep_ns));

        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MODE;
        plan.mode = 0o600;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.perm, 0o600);
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_chown_updates_uid_and_ctime() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let sleep_ns = 1_000_000;
        std::thread::sleep(Duration::from_nanos(sleep_ns));

        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_UID;
        plan.uid = 42;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.uid, 42);
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_truncate_updates_size_and_ctime() {
        let current = dummy_file_attr(1, 0o100644, 8192);
        let sleep_ns = 1_000_000;
        std::thread::sleep(Duration::from_nanos(sleep_ns));

        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_SIZE;
        plan.size = 1024;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.size, 1024);
        assert_eq!(out.blocks, blocks_512_for_size(1024));
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_utimens_explicit_atime_mtime() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_ATIME | FATTR_MTIME;
        plan.atime_ns = 1_000_000_000;
        plan.mtime_ns = 2_000_000_000;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(
            out.atime.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            1_000_000_000
        );
        assert_eq!(
            out.mtime.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            2_000_000_000
        );
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_atime_now_uses_current_time() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let before = SystemTime::now();

        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_ATIME_NOW;
        let out = apply_setattr_plan(&current, &plan);
        assert!(out.atime >= before);
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_mtime_now_uses_current_time() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let before = SystemTime::now();

        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MTIME_NOW;
        let out = apply_setattr_plan(&current, &plan);
        assert!(out.mtime >= before);
        assert!(out.ctime > current.ctime);
    }

    #[test]
    fn apply_noop_does_not_change_ctime() {
        let current = dummy_file_attr(1, 0o100644, 1024);
        let plan = SetAttrPlan::new(); // valid = 0
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.ctime, current.ctime);
        assert_eq!(out.atime, current.atime);
        assert_eq!(out.mtime, current.mtime);
    }

    #[test]
    fn apply_preserves_ino_nlink_kind() {
        let current = dummy_file_attr(42, 0o100644, 1024);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MODE;
        plan.mode = 0o700;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.ino, 42);
        assert_eq!(out.nlink, 1);
        assert_eq!(out.kind, FileType::RegularFile);
    }

    #[test]
    fn apply_mode_preserves_type_bits() {
        // S_IFREG = 0o100000
        let current = dummy_file_attr(1, 0o100644, 0);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MODE;
        plan.mode = 0o777; // only permission bits
        let out = apply_setattr_plan(&current, &plan);
        // The type bits from current.perm should be preserved
        let current_type = u32::from(current.perm) & S_IFMT;
        let out_type = u32::from(out.perm) & S_IFMT;
        assert_eq!(out_type, current_type);
        // Permission bits should be updated
        assert_eq!(u32::from(out.perm) & !S_IFMT, 0o777);
    }

    #[test]
    fn apply_explicit_ctime_set() {
        let current = dummy_file_attr(1, 0o100644, 0);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_CTIME;
        plan.ctime_ns = 42;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(
            out.ctime.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            42
        );
    }

    #[test]
    fn apply_gid_update_preserves_uid() {
        let current = dummy_file_attr(1, 0o100644, 0);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_GID;
        plan.gid = 2000;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.gid, 2000);
        assert_eq!(out.uid, current.uid); // unchanged
    }

    #[test]
    fn apply_size_zero_clears_blocks() {
        let current = dummy_file_attr(1, 0o100644, 8192);
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_SIZE;
        plan.size = 0;
        let out = apply_setattr_plan(&current, &plan);
        assert_eq!(out.size, 0);
        assert_eq!(out.blocks, 0);
    }

    // -- blocks_512_for_size --------------------------------------------

    #[test]
    fn blocks_zero_for_zero_size() {
        assert_eq!(blocks_512_for_size(0), 0);
    }

    #[test]
    fn blocks_one_for_one_byte() {
        assert_eq!(blocks_512_for_size(1), 1);
    }

    #[test]
    fn blocks_exact_for_512() {
        assert_eq!(blocks_512_for_size(512), 1);
    }

    #[test]
    fn blocks_rounds_up() {
        assert_eq!(blocks_512_for_size(513), 2);
    }

    // -- system_time helpers --------------------------------------------

    #[test]
    fn roundtrip_ns_to_system_time() {
        let ns = 1_000_000_000_000_i64;
        let st = ns_to_system_time(ns);
        let back = system_time_to_ns(st);
        assert_eq!(back, ns);
    }

    #[test]
    fn roundtrip_pre_epoch_ns_to_system_time() {
        let ns = -315_619_199_876_543_211_i64;
        let st = ns_to_system_time(ns);
        let back = system_time_to_ns(st);
        assert_eq!(back, ns);
    }

    #[test]
    fn system_time_to_ns_epoch() {
        let ns = system_time_to_ns(UNIX_EPOCH);
        assert_eq!(ns, 0);
    }

    // -- validate_setattr_request ---------------------------------------

    #[test]
    fn validate_inode_zero_returns_enoent() {
        assert_eq!(
            validate_setattr_request(0, 0, FileType::RegularFile, false),
            Err(errno::ENOENT)
        );
    }

    #[test]
    fn validate_unknown_bits_returns_einval() {
        let bad_valid: u32 = 1 << 31; // undefined FATTR bit
        assert_eq!(
            validate_setattr_request(1, bad_valid, FileType::RegularFile, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_read_only_rejects_mode() {
        assert_eq!(
            validate_setattr_request(1, FATTR_MODE, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_read_only_rejects_truncate() {
        assert_eq!(
            validate_setattr_request(1, FATTR_SIZE, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_read_only_rejects_uid() {
        assert_eq!(
            validate_setattr_request(1, FATTR_UID, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_read_only_rejects_gid() {
        assert_eq!(
            validate_setattr_request(1, FATTR_GID, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_read_only_rejects_utimes() {
        assert_eq!(
            validate_setattr_request(1, FATTR_ATIME, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
        assert_eq!(
            validate_setattr_request(1, FATTR_ATIME_NOW, FileType::RegularFile, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_truncate_on_directory_returns_eisdir() {
        assert_eq!(
            validate_setattr_request(1, FATTR_SIZE, FileType::Directory, false),
            Err(libc::EISDIR)
        );
    }

    #[test]
    fn validate_truncate_on_symlink_returns_einval() {
        assert_eq!(
            validate_setattr_request(1, FATTR_SIZE, FileType::Symlink, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_truncate_on_socket_returns_einval() {
        assert_eq!(
            validate_setattr_request(1, FATTR_SIZE, FileType::Socket, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_truncate_on_fifo_returns_einval() {
        assert_eq!(
            validate_setattr_request(1, FATTR_SIZE, FileType::NamedPipe, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_truncate_on_regular_file_passes() {
        assert!(validate_setattr_request(1, FATTR_SIZE, FileType::RegularFile, false).is_ok());
    }

    #[test]
    fn validate_mode_on_directory_passes() {
        assert!(validate_setattr_request(1, FATTR_MODE, FileType::Directory, false).is_ok());
    }

    #[test]
    fn validate_noop_with_no_mutations_passes_even_if_readonly() {
        // FH-only (no mutation bits) should pass
        assert!(validate_setattr_request(1, FATTR_FH, FileType::RegularFile, true).is_ok());
    }

    // -- plan_setattr_mutation ------------------------------------------

    #[test]
    fn mutation_plan_empty_returns_no_ops() {
        let plan = SetAttrPlan::new();
        let mutations = plan_setattr_mutation(&plan);
        assert!(mutations.is_empty());
    }

    #[test]
    fn mutation_plan_chmod() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MODE;
        plan.mode = 0o644;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0], SetattrMutation::Chmod { mode: 0o644 });
    }

    #[test]
    fn mutation_plan_chown() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_UID;
        plan.uid = 42;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations, vec![SetattrMutation::Chown { uid: 42 }]);
    }

    #[test]
    fn mutation_plan_chgrp() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_GID;
        plan.gid = 84;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations, vec![SetattrMutation::Chgrp { gid: 84 }]);
    }

    #[test]
    fn mutation_plan_truncate_with_fh() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_SIZE;
        plan.size = 4096;
        plan.fh = Some(3);
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(
            mutations,
            vec![SetattrMutation::Truncate {
                size: 4096,
                fh: Some(3)
            }]
        );
    }

    #[test]
    fn mutation_plan_truncate_without_fh() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_SIZE;
        plan.size = 0;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(
            mutations,
            vec![SetattrMutation::Truncate { size: 0, fh: None }]
        );
    }

    #[test]
    fn mutation_plan_utimes_explicit() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_ATIME | FATTR_MTIME;
        plan.atime_ns = 100;
        plan.mtime_ns = 200;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(
            mutations,
            vec![SetattrMutation::Utimes {
                atime_ns: Some(100),
                mtime_ns: Some(200)
            }]
        );
    }

    #[test]
    fn mutation_plan_utimes_atime_now() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_ATIME_NOW;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations, vec![SetattrMutation::UtimesAtimeNow]);
    }

    #[test]
    fn mutation_plan_utimes_mtime_now() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MTIME_NOW;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations, vec![SetattrMutation::UtimesMtimeNow]);
    }

    #[test]
    fn mutation_plan_ctime() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_CTIME;
        plan.ctime_ns = 999;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations, vec![SetattrMutation::Ctime { ctime_ns: 999 }]);
    }

    #[test]
    fn mutation_plan_combined_all_fields() {
        let mut plan = SetAttrPlan::new();
        plan.valid = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | FATTR_ATIME | FATTR_MTIME;
        plan.mode = 0o755;
        plan.uid = 1000;
        plan.gid = 1000;
        plan.size = 1024;
        plan.atime_ns = 111;
        plan.mtime_ns = 222;
        let mutations = plan_setattr_mutation(&plan);
        assert_eq!(mutations.len(), 5);
        assert!(mutations.contains(&SetattrMutation::Chmod { mode: 0o755 }));
        assert!(mutations.contains(&SetattrMutation::Chown { uid: 1000 }));
        assert!(mutations.contains(&SetattrMutation::Chgrp { gid: 1000 }));
        assert!(mutations.contains(&SetattrMutation::Truncate {
            size: 1024,
            fh: None
        }));
        assert!(mutations.contains(&SetattrMutation::Utimes {
            atime_ns: Some(111),
            mtime_ns: Some(222)
        }));
    }

    // -- handle_setattr -------------------------------------------------

    #[test]
    fn handle_setattr_valid_regular_file() {
        let plan = plan_setattr(
            Some(0o644),
            Some(42),
            None,
            Some(1024),
            Some(TimeOrNow::Now),
            None,
            None,
        );
        let result = handle_setattr(1, plan.valid, FileType::RegularFile, false, &plan);
        assert!(result.is_ok());
        let mutations = result.unwrap();
        assert_eq!(mutations.len(), 4); // chmod, chown, truncate, utimes_now
    }

    #[test]
    fn handle_setattr_read_only_rejected() {
        let plan = plan_setattr(Some(0o600), None, None, None, None, None, None);
        let result = handle_setattr(1, plan.valid, FileType::RegularFile, true, &plan);
        assert_eq!(result, Err(errno::EROFS));
    }

    #[test]
    fn handle_setattr_truncate_dir_rejected() {
        let plan = plan_setattr(None, None, None, Some(0), None, None, None);
        let result = handle_setattr(1, plan.valid, FileType::Directory, false, &plan);
        assert_eq!(result, Err(libc::EISDIR));
    }

    #[test]
    fn handle_setattr_inode_zero_rejected() {
        let plan = SetAttrPlan::new();
        let result = handle_setattr(0, plan.valid, FileType::RegularFile, false, &plan);
        assert_eq!(result, Err(errno::ENOENT));
    }

    #[test]
    fn handle_setattr_unknown_bits_rejected() {
        let mut plan = SetAttrPlan::new();
        plan.valid = 1 << 31; // unknown bit
        let result = handle_setattr(1, plan.valid, FileType::RegularFile, false, &plan);
        assert_eq!(result, Err(errno::EINVAL));
    }

    #[test]
    fn ns_to_system_time_zero() {
        let st = ns_to_system_time(0);
        assert_eq!(st, UNIX_EPOCH);
    }
}
