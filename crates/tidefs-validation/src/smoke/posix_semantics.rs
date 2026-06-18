// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! POSIX-semantics smoke: deterministic checks for pure permission,
//! metadata, and name-validation helpers.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_posix_semantics::{
    apply_setgid_inheritance_for_create, chmod_sanitize_mode_unprivileged, inode_is_append_only,
    inode_is_immutable, inode_is_noatime, killpriv_mode_on_chown,
    killpriv_mode_on_write_or_truncate, posix_has_perm, posix_perm_bits_for_caller,
    should_update_atime_relatime, sticky_dir_allows_unlink_or_rename, validate_dir_entry_name,
    DirEntryNameError, FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, F_OK, POSIX_NAME_MAX,
    RELATIME_24H_NS, R_OK, S_IFDIR, S_IFREG, S_IRGRP, S_IROTH, S_IRUSR, S_ISGID, S_ISUID, S_ISVTX,
    S_IWUSR, S_IXGRP, S_IXUSR, W_OK, X_OK,
};

/// Run the POSIX-semantics smoke sequence and return the harness.
#[must_use]
pub fn run_posix_semantics_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("posix-semantics/smoke");

    record_posix_semantics_op(&mut h, "perm.bits");
    let mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH;
    h.assert_eq_ev(
        "owner gets owner rwx bits",
        posix_perm_bits_for_caller(mode, 1000, 100, 1000, 200, &[]),
        R_OK | W_OK | X_OK,
    );
    h.assert_eq_ev(
        "primary group gets group bits",
        posix_perm_bits_for_caller(mode, 1000, 100, 2000, 100, &[]),
        R_OK | X_OK,
    );
    h.assert_eq_ev(
        "supplementary group gets group bits",
        posix_perm_bits_for_caller(mode, 1000, 100, 2000, 300, &[400, 100]),
        R_OK | X_OK,
    );
    h.assert_eq_ev(
        "unmatched caller gets other bits",
        posix_perm_bits_for_caller(mode, 1000, 100, 2000, 300, &[400]),
        R_OK,
    );
    h.assert_eq_ev(
        "root can read and write non-executable regular file",
        posix_perm_bits_for_caller(S_IFREG | S_IRUSR, 1000, 100, 0, 0, &[]),
        R_OK | W_OK,
    );
    h.assert_eq_ev(
        "root can execute directories",
        posix_perm_bits_for_caller(S_IFDIR | S_IRUSR, 1000, 100, 0, 0, &[]),
        R_OK | W_OK | X_OK,
    );

    record_posix_semantics_op(&mut h, "perm.has");
    h.assert_ev(
        "owner has read-write",
        posix_has_perm(mode, 1000, 100, 1000, 200, &[], R_OK | W_OK),
    );
    h.assert_ev(
        "group lacks write",
        !posix_has_perm(mode, 1000, 100, 2000, 100, &[], W_OK),
    );
    h.assert_ev(
        "other lacks execute",
        !posix_has_perm(mode, 1000, 100, 2000, 300, &[], X_OK),
    );
    h.assert_ev(
        "F_OK is existence-only",
        posix_has_perm(0, 1000, 100, 2000, 300, &[], F_OK),
    );

    record_posix_semantics_op(&mut h, "chmod.sanitize");
    let old_regular = S_IFREG | 0o664;
    h.assert_eq_ev(
        "owner chmod clears non-executable regular-file setgid",
        chmod_sanitize_mode_unprivileged(old_regular, S_ISGID | 0o660, 1000, 1000),
        (S_IFREG | 0o660, true),
    );
    h.assert_eq_ev(
        "owner chmod keeps executable regular-file setgid",
        chmod_sanitize_mode_unprivileged(old_regular, S_ISGID | 0o670, 1000, 1000),
        (S_IFREG | S_ISGID | 0o670, true),
    );
    h.assert_eq_ev(
        "root chmod can keep non-executable regular-file setgid",
        chmod_sanitize_mode_unprivileged(old_regular, S_ISGID | 0o660, 1000, 0),
        (S_IFREG | S_ISGID | 0o660, true),
    );
    h.assert_eq_ev(
        "non-owner chmod is denied without mutation",
        chmod_sanitize_mode_unprivileged(old_regular, 0o777, 1000, 2000),
        (old_regular, false),
    );

    record_posix_semantics_op(&mut h, "setgid.inherit");
    h.assert_eq_ev(
        "setgid parent propagates directory gid and setgid bit",
        apply_setgid_inheritance_for_create(S_IFDIR | S_ISGID | 0o775, 42, S_IFDIR | 0o755, 7),
        (S_IFDIR | S_ISGID | 0o755, 42),
    );
    h.assert_eq_ev(
        "setgid parent propagates file gid only",
        apply_setgid_inheritance_for_create(S_IFDIR | S_ISGID | 0o775, 42, S_IFREG | 0o644, 7),
        (S_IFREG | 0o644, 42),
    );
    h.assert_eq_ev(
        "non-setgid parent leaves child mode and gid unchanged",
        apply_setgid_inheritance_for_create(S_IFDIR | 0o775, 42, S_IFREG | 0o644, 7),
        (S_IFREG | 0o644, 7),
    );

    record_posix_semantics_op(&mut h, "sticky.gate");
    let sticky_parent = S_IFDIR | S_ISVTX | 0o777;
    h.assert_ev(
        "sticky directory allows parent owner",
        sticky_dir_allows_unlink_or_rename(sticky_parent, 1000, 2000, 1000),
    );
    h.assert_ev(
        "sticky directory allows entry owner",
        sticky_dir_allows_unlink_or_rename(sticky_parent, 1000, 2000, 2000),
    );
    h.assert_ev(
        "sticky directory allows root",
        sticky_dir_allows_unlink_or_rename(sticky_parent, 1000, 2000, 0),
    );
    h.assert_ev(
        "sticky directory denies unrelated caller",
        !sticky_dir_allows_unlink_or_rename(sticky_parent, 1000, 2000, 3000),
    );
    h.assert_ev(
        "non-sticky directory leaves sticky gate open",
        sticky_dir_allows_unlink_or_rename(S_IFDIR | 0o777, 1000, 2000, 3000),
    );

    record_posix_semantics_op(&mut h, "killpriv");
    let privileged_exec = S_IFREG | S_ISUID | S_ISGID | S_IXGRP | 0o775;
    h.assert_eq_ev(
        "non-root write clears suid and executable sgid",
        killpriv_mode_on_write_or_truncate(privileged_exec, 1000),
        S_IFREG | S_IXGRP | 0o775,
    );
    h.assert_eq_ev(
        "root write preserves privilege bits",
        killpriv_mode_on_write_or_truncate(privileged_exec, 0),
        privileged_exec,
    );
    h.assert_eq_ev(
        "non-root chown clears suid and sgid",
        killpriv_mode_on_chown(privileged_exec, 1000),
        S_IFREG | S_IXGRP | 0o775,
    );
    h.assert_eq_ev(
        "root chown preserves privilege bits",
        killpriv_mode_on_chown(privileged_exec, 0),
        privileged_exec,
    );

    record_posix_semantics_op(&mut h, "relatime");
    h.assert_ev(
        "relatime updates when atime predates mtime",
        should_update_atime_relatime(10, 20, 10, 30),
    );
    h.assert_ev(
        "relatime updates when atime predates ctime",
        should_update_atime_relatime(10, 10, 20, 30),
    );
    h.assert_ev(
        "relatime updates after twenty-four hours",
        should_update_atime_relatime(10, 10, 10, 10 + RELATIME_24H_NS),
    );
    h.assert_ev(
        "relatime skips fresh atime",
        !should_update_atime_relatime(100, 90, 90, 100 + RELATIME_24H_NS - 1),
    );

    record_posix_semantics_op(&mut h, "inode.flags");
    let flags = FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NOATIME_FL;
    h.assert_ev("immutable flag detected", inode_is_immutable(flags));
    h.assert_ev("append-only flag detected", inode_is_append_only(flags));
    h.assert_ev("noatime flag detected", inode_is_noatime(flags));
    h.assert_ev("unset immutable flag is false", !inode_is_immutable(0));
    h.assert_ev("unset append-only flag is false", !inode_is_append_only(0));
    h.assert_ev("unset noatime flag is false", !inode_is_noatime(0));

    record_posix_semantics_op(&mut h, "name.validate");
    h.assert_eq_ev(
        "plain directory entry name validates",
        validate_dir_entry_name(b"readme.txt"),
        Ok(()),
    );
    h.assert_eq_ev(
        "empty directory entry name is rejected",
        validate_dir_entry_name(b""),
        Err(DirEntryNameError::Empty),
    );
    h.assert_eq_ev(
        "slash in directory entry name is rejected",
        validate_dir_entry_name(b"nested/name"),
        Err(DirEntryNameError::ContainsSlash),
    );
    h.assert_eq_ev(
        "nul in directory entry name is rejected",
        validate_dir_entry_name(b"name\0suffix"),
        Err(DirEntryNameError::ContainsNul),
    );
    let too_long_name = vec![b'a'; POSIX_NAME_MAX + 1];
    h.assert_eq_ev(
        "too-long directory entry name is rejected",
        validate_dir_entry_name(&too_long_name),
        Err(DirEntryNameError::TooLong {
            len: POSIX_NAME_MAX + 1,
        }),
    );

    h.scenario_end("posix-semantics/smoke");
    h
}

fn record_posix_semantics_op(h: &mut SmokeHarness, op_name: &str) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 0,
        op_name: op_name.to_string(),
        payload: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_semantics_smoke_passes() {
        let h = run_posix_semantics_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
