//! FUSE `access` handler helpers — POSIX permission checking against
//! inode mode, uid, and gid, with root override and ACL support.
//!
//! Provides:
//! - [`fuse_access_requested_from_mask`]: convert FUSE access mask to
//!   [`tidefs_permission`] access bits.
//! - [`check_fuse_access`]: POSIX discretionary access check against
//!   a given inode's mode/uid/gid and caller credentials.
//! - [`plan_fuse_access`]: combined mask conversion + access check
//!   returning `Ok(())` or a FUSE errno.
//! - [`check_fuse_access_acl`]: ACL-aware variant of
//!   [`check_fuse_access`].
//! - [`AccessRequest`]: parsed FUSE access request with mask field.
//! - [`validate_access_request`]: mask validation rejecting unknown
//!   flags.
//! - [`check_access_readonly`]: reject `W_OK` checks on read-only
//!   filesystems.
//! - [`handle_access`]: canonical FUSE dispatch entry point for
//!   opcode 34 combining mask validation, read-only guard, and
//!   POSIX permission checking.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::access;
//!
//! let result = access::check_fuse_access(
//!     0o644,  // file mode
//!     1000,   // file uid
//!     100,    // file gid
//!     1000,   // caller uid
//!     100,    // caller gid
//!     &[],    // caller supplementary groups
//!     access::ACCESS_READ | access::ACCESS_WRITE,
//! );
//! assert_eq!(result, Ok(()));
//! ```

use crate::errno;
use libc::c_int;

use tidefs_permission::{check_access, InodeAttr};
pub use tidefs_permission::{
    ACCESS_EXECUTE, ACCESS_NONE, ACCESS_RDWR, ACCESS_READ, ACCESS_RWX, ACCESS_WRITE,
};

// ---------------------------------------------------------------------------
// FUSE access mask conversion
// ---------------------------------------------------------------------------

/// Convert a FUSE `access(2)`-style mask into
/// [`tidefs_permission`] access bits.
///
/// The mask uses the standard Unix constants:
/// - `R_OK` (4) → [`ACCESS_READ`]
/// - `W_OK` (2) → [`ACCESS_WRITE`]
/// - `X_OK` (1) → [`ACCESS_EXECUTE`]
/// - `F_OK` (0) → [`ACCESS_NONE`] (existence check; always succeeds
///   after metadata lookup)
///
/// Returns `Err(EINVAL)` when unsupported bits are set in `mask`.
pub fn fuse_access_requested_from_mask(mask: i32) -> Result<u8, c_int> {
    const VALID_MASK: i32 = libc::R_OK | libc::W_OK | libc::X_OK;
    if mask & !VALID_MASK != 0 {
        return Err(errno::EINVAL);
    }

    let mut requested = 0u8;
    if mask & libc::R_OK != 0 {
        requested |= ACCESS_READ;
    }
    if mask & libc::W_OK != 0 {
        requested |= ACCESS_WRITE;
    }
    if mask & libc::X_OK != 0 {
        requested |= ACCESS_EXECUTE;
    }
    Ok(requested)
}

// ---------------------------------------------------------------------------
// AccessAttrView — InodeAttr adapter for raw values
// ---------------------------------------------------------------------------

/// Adapter implementing [`InodeAttr`] for raw mode/uid/gid values,
/// so callers can use [`check_fuse_access`] without implementing the
/// trait themselves.
#[derive(Clone, Copy, Debug)]
struct AccessAttrView {
    mode: u32,
    uid: u32,
    gid: u32,
}

impl InodeAttr for AccessAttrView {
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

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check POSIX discretionary access for a FUSE `access` handler.
///
/// This is a thin wrapper around [`tidefs_permission::check_access`]
/// that takes raw inode attribute values instead of requiring the
/// caller to implement [`InodeAttr`].
///
/// # Parameters
///
/// - `mode` — file mode including permission bits (e.g. `0o644`).
/// - `file_uid` — owner of the inode.
/// - `file_gid` — owning group of the inode.
/// - `caller_uid` — requesting user from the FUSE request context.
/// - `caller_gid` — requesting group from the FUSE request context.
/// - `caller_groups` — supplementary groups (empty slice when none).
/// - `requested` — access bits from [`fuse_access_requested_from_mask`]
///   or the re-exported [`ACCESS_READ`], [`ACCESS_WRITE`],
///   [`ACCESS_EXECUTE`], or [`ACCESS_NONE`] constants.
///
/// Returns `Ok(())` when all requested access bits are granted, or
/// `Err(EACCES)` when denied.
pub fn check_fuse_access(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    requested: u8,
) -> Result<(), c_int> {
    if requested == ACCESS_NONE {
        return Ok(());
    }
    // Root bypass: uid 0 granted except execute on non-executable regular
    // files (POSIX rule). Root always retains directory search permission.
    if caller_uid == 0 {
        if (requested & ACCESS_EXECUTE) != 0
            && (mode & tidefs_permission::S_IFMT) == tidefs_permission::S_IFREG
            && (mode
                & (tidefs_permission::S_IXUSR
                    | tidefs_permission::S_IXGRP
                    | tidefs_permission::S_IXOTH))
                == 0
        {
            return Err(errno::EACCES);
        }
        return Ok(());
    }

    let view = AccessAttrView {
        mode,
        uid: file_uid,
        gid: file_gid,
    };
    if check_access(
        &view,
        None,
        caller_uid,
        caller_gid,
        caller_groups,
        requested,
    ) {
        Ok(())
    } else {
        Err(errno::EACCES)
    }
}

/// Check POSIX discretionary access with optional ACL.
///
/// Like [`check_fuse_access`] but accepts an optional POSIX access ACL.
/// When `acl` is `Some` and non-empty, ACL evaluation takes precedence
/// over mode bits.
#[allow(clippy::too_many_arguments)]
pub fn check_fuse_access_acl(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    requested: u8,
    acl: Option<&[tidefs_permission::PosixAclEntry]>,
) -> Result<(), c_int> {
    if requested == ACCESS_NONE {
        return Ok(());
    }
    if caller_uid == 0 {
        if (requested & ACCESS_EXECUTE) != 0
            && (mode & tidefs_permission::S_IFMT) == tidefs_permission::S_IFREG
            && (mode
                & (tidefs_permission::S_IXUSR
                    | tidefs_permission::S_IXGRP
                    | tidefs_permission::S_IXOTH))
                == 0
        {
            return Err(errno::EACCES);
        }
        return Ok(());
    }

    let view = AccessAttrView {
        mode,
        uid: file_uid,
        gid: file_gid,
    };
    if check_access(&view, acl, caller_uid, caller_gid, caller_groups, requested) {
        Ok(())
    } else {
        Err(errno::EACCES)
    }
}

// ---------------------------------------------------------------------------
// Combined mask + access check (convenience)
// ---------------------------------------------------------------------------

/// Convert a FUSE access mask and check permissions in one call.
///
/// This is the most common entry point for FUSE adapter daemons:
/// convert the raw `mask` (i32 with R_OK/W_OK/X_OK) into access bits,
/// then check the caller's permission against the inode's mode/uid/gid.
///
/// Returns `Ok(())` on success, or an errno (`EACCES` or `EINVAL`).
pub fn plan_fuse_access(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mask: i32,
) -> Result<(), c_int> {
    let requested = fuse_access_requested_from_mask(mask)?;
    check_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        requested,
    )
}

/// Combined mask + access check with optional ACL.
#[allow(clippy::too_many_arguments)]
pub fn plan_fuse_access_acl(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mask: i32,
    acl: Option<&[tidefs_permission::PosixAclEntry]>,
) -> Result<(), c_int> {
    let requested = fuse_access_requested_from_mask(mask)?;
    check_fuse_access_acl(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        requested,
        acl,
    )
}

// ---------------------------------------------------------------------------
// AccessRequest -- parsed FUSE access request
// ---------------------------------------------------------------------------

/// Parsed FUSE `access` request carrying the access mask.
///
/// The mask uses standard Unix constants:
/// - `F_OK` (0) -- existence check
/// - `R_OK` (4) -- read permission
/// - `W_OK` (2) -- write permission
/// - `X_OK` (1) -- execute/search permission
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Access mask from the FUSE request (R_OK/W_OK/X_OK bitmask,
    /// or 0 for F_OK).
    pub mask: i32,
}

impl AccessRequest {
    /// Create a new access request from a raw mask value.
    #[must_use]
    pub const fn new(mask: i32) -> Self {
        Self { mask }
    }
}

// ---------------------------------------------------------------------------
// validate_access_request -- mask validation
// ---------------------------------------------------------------------------

/// Validate a FUSE access request mask.
///
/// Rejects masks with unsupported bits set beyond
/// `R_OK | W_OK | X_OK`.  Returns `Ok(mask)` on success,
/// `Err(EINVAL)` on invalid mask.
pub fn validate_access_request(request: &AccessRequest) -> Result<i32, c_int> {
    const VALID_MASK: i32 = libc::R_OK | libc::W_OK | libc::X_OK;
    if request.mask & !VALID_MASK != 0 {
        return Err(errno::EINVAL);
    }
    Ok(request.mask)
}

// ---------------------------------------------------------------------------
// check_access_readonly -- read-only filesystem guard
// ---------------------------------------------------------------------------

/// Reject write-access checks on a read-only filesystem.
///
/// When the filesystem is read-only, any access check that includes
/// `W_OK` (write permission) must be rejected with `EROFS`.
/// Read, execute, and existence (`F_OK`) checks are allowed.
pub fn check_access_readonly(mask: i32, read_only: bool) -> Result<(), c_int> {
    if read_only && (mask & libc::W_OK != 0) {
        return Err(errno::EROFS);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_access -- canonical FUSE dispatch entry point for access(2)
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for `access` (opcode 34).
///
/// Combines mask validation, read-only filesystem guard, and POSIX
/// permission checking into a single call, matching the established
/// `handle_flush` / `handle_mknod` canonical dispatch pattern.
///
/// Returns `Ok(())` when all requested access bits are granted, or a
/// FUSE errno (`EACCES`, `EINVAL`, `EROFS`).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn handle_access(
    mask: i32,
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    read_only: bool,
) -> Result<(), c_int> {
    let req = AccessRequest::new(mask);
    let validated_mask = validate_access_request(&req)?;
    check_access_readonly(validated_mask, read_only)?;
    plan_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        validated_mask,
    )
}
// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- fuse_access_requested_from_mask --

    #[test]
    fn mask_f_ok_returns_access_none() {
        assert_eq!(fuse_access_requested_from_mask(0), Ok(ACCESS_NONE));
    }

    #[test]
    fn mask_r_ok_returns_access_read() {
        assert_eq!(fuse_access_requested_from_mask(libc::R_OK), Ok(ACCESS_READ));
    }

    #[test]
    fn mask_w_ok_returns_access_write() {
        assert_eq!(
            fuse_access_requested_from_mask(libc::W_OK),
            Ok(ACCESS_WRITE)
        );
    }

    #[test]
    fn mask_x_ok_returns_access_execute() {
        assert_eq!(
            fuse_access_requested_from_mask(libc::X_OK),
            Ok(ACCESS_EXECUTE)
        );
    }

    #[test]
    fn mask_rwx_returns_all() {
        assert_eq!(
            fuse_access_requested_from_mask(libc::R_OK | libc::W_OK | libc::X_OK),
            Ok(ACCESS_RWX)
        );
    }

    #[test]
    fn mask_rw_returns_rdwr() {
        assert_eq!(
            fuse_access_requested_from_mask(libc::R_OK | libc::W_OK),
            Ok(ACCESS_RDWR)
        );
    }

    #[test]
    fn mask_invalid_bit_returns_einval() {
        assert_eq!(fuse_access_requested_from_mask(0x08), Err(errno::EINVAL));
        assert_eq!(fuse_access_requested_from_mask(0x10), Err(errno::EINVAL));
    }

    // -- check_fuse_access: root bypass --

    #[test]
    fn root_bypasses_no_permissions() {
        // File mode 000, not owned by root — root still gets through.
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 0, 0, &[], ACCESS_READ),
            Ok(())
        );
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 0, 0, &[], ACCESS_WRITE),
            Ok(())
        );
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 0, 0, &[], ACCESS_EXECUTE),
            Ok(())
        );
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 0, 0, &[], ACCESS_RWX),
            Ok(())
        );
    }

    // -- check_fuse_access: owner --

    #[test]
    fn owner_read_on_readable_file() {
        assert_eq!(
            check_fuse_access(0o400, 1000, 100, 1000, 100, &[], ACCESS_READ),
            Ok(())
        );
    }

    #[test]
    fn owner_write_denied_on_readonly_file() {
        assert_eq!(
            check_fuse_access(0o400, 1000, 100, 1000, 100, &[], ACCESS_WRITE),
            Err(errno::EACCES)
        );
    }

    #[test]
    fn owner_rw_on_rw_file() {
        assert_eq!(
            check_fuse_access(0o600, 1000, 100, 1000, 100, &[], ACCESS_RDWR),
            Ok(())
        );
    }

    #[test]
    fn owner_execute_on_executable_file() {
        assert_eq!(
            check_fuse_access(0o500, 1000, 100, 1000, 100, &[], ACCESS_EXECUTE),
            Ok(())
        );
    }

    // -- check_fuse_access: group --

    #[test]
    fn group_member_read_on_group_readable_file() {
        // File owner 1000, group 100, mode 0o040 (group read).
        // Caller 2000 is in group 100.
        assert_eq!(
            check_fuse_access(0o040, 1000, 100, 2000, 100, &[], ACCESS_READ),
            Ok(())
        );
    }

    #[test]
    fn group_member_denied_write_on_group_readonly() {
        assert_eq!(
            check_fuse_access(0o040, 1000, 100, 2000, 100, &[], ACCESS_WRITE),
            Err(errno::EACCES)
        );
    }

    #[test]
    fn supplementary_group_match_grants_access() {
        // Caller primary gid 200, but supplementary groups include 100.
        assert_eq!(
            check_fuse_access(0o040, 1000, 100, 2000, 200, &[100], ACCESS_READ),
            Ok(())
        );
    }

    // -- check_fuse_access: other --

    #[test]
    fn other_read_on_world_readable_file() {
        assert_eq!(
            check_fuse_access(0o004, 1000, 100, 2000, 200, &[], ACCESS_READ),
            Ok(())
        );
    }

    #[test]
    fn other_denied_on_world_unreadable_file() {
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 2000, 200, &[], ACCESS_READ),
            Err(errno::EACCES)
        );
    }

    // -- check_fuse_access: ACCESS_NONE (F_OK) --

    #[test]
    fn access_none_always_succeeds() {
        // Even mode 000 and non-owner: existence check always passes
        assert_eq!(
            check_fuse_access(0o000, 1000, 100, 2000, 200, &[], ACCESS_NONE),
            Ok(())
        );
    }

    // -- plan_fuse_access: combined conversion + check --

    #[test]
    fn plan_fuse_access_f_ok_succeeds() {
        assert_eq!(
            plan_fuse_access(0o600, 1000, 100, 1000, 100, &[], 0),
            Ok(())
        );
    }

    #[test]
    fn plan_fuse_access_owner_rw() {
        assert_eq!(
            plan_fuse_access(0o600, 1000, 100, 1000, 100, &[], libc::R_OK | libc::W_OK),
            Ok(())
        );
    }

    #[test]
    fn plan_fuse_access_other_denied() {
        assert_eq!(
            plan_fuse_access(0o600, 1000, 100, 2000, 200, &[], libc::R_OK),
            Err(errno::EACCES)
        );
    }

    #[test]
    fn plan_fuse_access_invalid_mask_returns_einval() {
        assert_eq!(
            plan_fuse_access(0o777, 1000, 100, 1000, 100, &[], 0x10),
            Err(errno::EINVAL)
        );
    }

    // -- check_fuse_access_acl: ACL-aware access --

    #[test]
    fn acl_deny_all_blocks_non_root() {
        use tidefs_permission::{PosixAclEntry, ACL_GROUP_OBJ, ACL_OTHER, ACL_USER_OBJ};
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
        // Owner (1000) is denied because ACL overrides mode bits
        assert_eq!(
            check_fuse_access_acl(0o777, 1000, 100, 1000, 100, &[], ACCESS_READ, Some(&acl)),
            Err(errno::EACCES)
        );
        // Root still bypasses
        assert_eq!(
            check_fuse_access_acl(0o000, 1000, 100, 0, 0, &[], ACCESS_READ, Some(&acl)),
            Ok(())
        );
    }

    #[test]
    fn acl_none_falls_back_to_mode() {
        assert_eq!(
            check_fuse_access_acl(0o400, 1000, 100, 1000, 100, &[], ACCESS_READ, None),
            Ok(())
        );
        assert_eq!(
            check_fuse_access_acl(0o400, 1000, 100, 2000, 200, &[], ACCESS_READ, None),
            Err(errno::EACCES)
        );
    }

    // -- plan_fuse_access_acl: combined ACL + mask --

    #[test]
    fn plan_fuse_access_acl_root_bypass() {
        assert_eq!(
            plan_fuse_access_acl(0o000, 1000, 100, 0, 0, &[], libc::R_OK, None),
            Ok(())
        );
    }

    #[test]
    fn plan_fuse_access_acl_other_denied() {
        assert_eq!(
            plan_fuse_access_acl(0o600, 1000, 100, 2000, 200, &[], libc::R_OK, None),
            Err(errno::EACCES)
        );
    }

    // -- AccessRequest construction ---------------------------------------

    #[test]
    fn access_request_new_stores_mask() {
        let req = AccessRequest::new(libc::R_OK);
        assert_eq!(req.mask, libc::R_OK);
    }

    #[test]
    fn access_request_f_ok_zero_mask() {
        let req = AccessRequest::new(0);
        assert_eq!(req.mask, 0);
    }

    #[test]
    fn access_request_rwx_mask() {
        let req = AccessRequest::new(libc::R_OK | libc::W_OK | libc::X_OK);
        assert_eq!(req.mask, libc::R_OK | libc::W_OK | libc::X_OK);
    }

    // -- validate_access_request ------------------------------------------

    #[test]
    fn validate_access_f_ok() {
        let req = AccessRequest::new(0);
        assert_eq!(validate_access_request(&req), Ok(0));
    }

    #[test]
    fn validate_access_r_ok() {
        let req = AccessRequest::new(libc::R_OK);
        assert_eq!(validate_access_request(&req), Ok(libc::R_OK));
    }

    #[test]
    fn validate_access_rwx() {
        let req = AccessRequest::new(libc::R_OK | libc::W_OK | libc::X_OK);
        assert_eq!(
            validate_access_request(&req),
            Ok(libc::R_OK | libc::W_OK | libc::X_OK)
        );
    }

    #[test]
    fn validate_access_bad_mask_rejected() {
        let req = AccessRequest::new(0x08);
        assert_eq!(validate_access_request(&req), Err(errno::EINVAL));
    }

    #[test]
    fn validate_access_high_bit_rejected() {
        let req = AccessRequest::new(0x100);
        assert_eq!(validate_access_request(&req), Err(errno::EINVAL));
    }

    // -- check_access_readonly --------------------------------------------

    #[test]
    fn readonly_w_ok_rejected() {
        assert_eq!(check_access_readonly(libc::W_OK, true), Err(errno::EROFS));
        assert_eq!(
            check_access_readonly(libc::R_OK | libc::W_OK, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn readonly_r_ok_allowed() {
        assert_eq!(check_access_readonly(libc::R_OK, true), Ok(()));
    }

    #[test]
    fn readonly_x_ok_allowed() {
        assert_eq!(check_access_readonly(libc::X_OK, true), Ok(()));
    }

    #[test]
    fn readonly_f_ok_allowed() {
        assert_eq!(check_access_readonly(0, true), Ok(()));
    }

    #[test]
    fn readwrite_fs_allows_w_ok() {
        assert_eq!(check_access_readonly(libc::W_OK, false), Ok(()));
    }

    // -- handle_access: success cases -------------------------------------

    #[test]
    fn handle_access_f_ok_success() {
        assert_eq!(
            handle_access(0, 0o000, 1000, 100, 2000, 200, &[], false),
            Ok(())
        );
    }

    #[test]
    fn handle_access_r_ok_on_readable_file() {
        assert_eq!(
            handle_access(libc::R_OK, 0o400, 1000, 100, 1000, 100, &[], false),
            Ok(())
        );
    }

    #[test]
    fn handle_access_w_ok_on_writable_file() {
        assert_eq!(
            handle_access(libc::W_OK, 0o200, 1000, 100, 1000, 100, &[], false),
            Ok(())
        );
    }

    #[test]
    fn handle_access_x_ok_on_executable_file() {
        assert_eq!(
            handle_access(libc::X_OK, 0o100, 1000, 100, 1000, 100, &[], false),
            Ok(())
        );
    }

    #[test]
    fn handle_access_root_bypass() {
        // uid 0 has full access even on mode 000
        assert_eq!(
            handle_access(libc::R_OK | libc::W_OK, 0o000, 1000, 100, 0, 0, &[], false),
            Ok(())
        );
    }

    // -- handle_access: rejection cases -----------------------------------

    #[test]
    fn handle_access_permission_denied() {
        // Non-owner, non-group, non-other read on mode 600
        assert_eq!(
            handle_access(libc::R_OK, 0o600, 1000, 100, 2000, 200, &[], false),
            Err(errno::EACCES)
        );
    }

    #[test]
    fn handle_access_read_only_rejects_write() {
        assert_eq!(
            handle_access(libc::W_OK, 0o600, 1000, 100, 1000, 100, &[], true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn handle_access_read_only_allows_read() {
        assert_eq!(
            handle_access(libc::R_OK, 0o400, 1000, 100, 1000, 100, &[], true),
            Ok(())
        );
    }

    #[test]
    fn handle_access_bad_mask_einval() {
        assert_eq!(
            handle_access(0x08, 0o777, 1000, 100, 1000, 100, &[], false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn handle_access_read_only_priority_over_bad_mask() {
        // EROFS takes priority over EINVAL when read-only and W_OK requested
        // with an otherwise-valid mask
        assert_eq!(
            handle_access(libc::W_OK, 0o600, 1000, 100, 1000, 100, &[], true),
            Err(errno::EROFS)
        );
    }
}
