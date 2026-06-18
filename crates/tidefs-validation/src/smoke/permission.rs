// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Permission smoke: deterministic DAC, ACL, traversal, sticky-directory,
//! setgid-inheritance, and xattr namespace checks over `tidefs-permission`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_permission::{
    can_execute, can_lookup, can_read, can_write, check_access, check_path_traversal,
    check_validated_access, deserialize_acl, plan_setgid_create_inheritance,
    plan_sticky_directory_delete, plan_sticky_directory_rename, recalc_acl_mask,
    recalc_mode_from_acl, serialize_acl, validate_access_request, validate_xattr_namespace,
    AccessRequestError, CreatedEntryKind, InodeAttr, MountIdentity, PathTraversalComponent,
    PosixAcl, PosixAclEntry, SetgidCreateGidSource, StickyDirectoryDeleteAllow,
    StickyDirectoryDeletePlan, StickyDirectoryRenameDeny, StickyDirectoryRenameTarget,
    XattrNamespace, XattrNamespaceError, ACCESS_NONE, ACCESS_READ, ACCESS_RWX, ACCESS_WRITE,
    ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER_OBJ, S_IRGRP, S_IROTH, S_IRUSR, S_ISGID, S_ISVTX,
    S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR, XATTR_NAME_MAX,
};

const VALID_MOUNT: MountIdentity = MountIdentity::new([0x41; 16], 1);

#[derive(Clone, Copy)]
struct SmokeInode {
    uid: u32,
    gid: u32,
    mode: u32,
}

impl InodeAttr for SmokeInode {
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

/// Run the full permission smoke sequence and return the harness.
#[must_use]
pub fn run_permission_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("permission/smoke");
    smoke_access_checks(&mut h);
    smoke_path_traversal(&mut h);
    smoke_sticky_directory_plans(&mut h);
    smoke_setgid_inheritance(&mut h);
    smoke_acl_codec_and_mode_sync(&mut h);
    smoke_xattr_namespace_validation(&mut h);
    h.scenario_end("permission/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("permission smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("permission smoke trace should deserialize");
    h.assert_eq_ev(
        "permission smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_access_checks(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.access.mode", b"mode-bits");
    let inode = SmokeInode {
        uid: 1000,
        gid: 100,
        mode: S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | S_IXOTH,
    };

    h.assert_ev(
        "owner read is allowed by owner bits",
        can_read(&inode, None, 1000, 100, &[], &VALID_MOUNT),
    );
    h.assert_ev(
        "owner write is allowed by owner bits",
        can_write(&inode, None, 1000, 100, &[], &VALID_MOUNT),
    );
    h.assert_ev(
        "owner execute is denied without owner execute bit",
        !can_execute(&inode, None, 1000, 100, &[], &VALID_MOUNT),
    );
    h.assert_ev(
        "supplementary group read is allowed by group bits",
        can_read(&inode, None, 2000, 200, &[100], &VALID_MOUNT),
    );
    h.assert_ev(
        "other execute is allowed by other bits",
        can_execute(&inode, None, 2000, 200, &[], &VALID_MOUNT),
    );
    h.assert_ev(
        "other write is denied without other write bit",
        !can_write(&inode, None, 2000, 200, &[], &VALID_MOUNT),
    );
    h.assert_ev(
        "root override grants rwx",
        check_access(&inode, None, 0, 0, &[], ACCESS_RWX, &VALID_MOUNT),
    );
    h.assert_eq_ev(
        "validated ACCESS_NONE succeeds",
        check_validated_access(&inode, None, 2000, 200, &[], ACCESS_NONE, &VALID_MOUNT),
        Ok(true),
    );
    h.assert_ev(
        "invalid access mask is rejected",
        matches!(
            validate_access_request(0x80),
            Err(AccessRequestError::InvalidMask {
                requested: 0x80,
                invalid_bits: 0x80,
            })
        ),
    );
}

fn smoke_path_traversal(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.path_traversal", b"execute-components");
    let searchable_root = SmokeInode {
        uid: 1000,
        gid: 100,
        mode: S_IXUSR | S_IXGRP | S_IXOTH,
    };
    let searchable_child = SmokeInode {
        uid: 2000,
        gid: 200,
        mode: S_IXUSR | S_IXGRP | S_IXOTH,
    };
    let blocked_child = SmokeInode {
        uid: 2000,
        gid: 200,
        mode: 0,
    };

    let accessible = [
        PathTraversalComponent::new(&searchable_root, None),
        PathTraversalComponent::new(&searchable_child, None),
    ];
    h.assert_eq_ev(
        "all searchable path components traverse",
        check_path_traversal(&accessible, 3000, 300, &[], &VALID_MOUNT),
        Ok(()),
    );
    h.assert_ev(
        "can_lookup mirrors execute permission",
        can_lookup(&searchable_root, None, 3000, 300, &[], &VALID_MOUNT),
    );

    let denied = [
        PathTraversalComponent::new(&searchable_root, None),
        PathTraversalComponent::new(&blocked_child, None),
    ];
    h.assert_eq_ev(
        "first denied path component is reported",
        check_path_traversal(&denied, 3000, 300, &[], &VALID_MOUNT).map_err(|e| e.component_index),
        Err(1),
    );
}

fn smoke_sticky_directory_plans(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.sticky_directory", b"unlink-rename");
    let sticky_dir = SmokeInode {
        uid: 1000,
        gid: 100,
        mode: S_ISVTX | S_IWUSR | S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH,
    };
    let non_sticky_dir = SmokeInode {
        uid: 1000,
        gid: 100,
        mode: S_IWUSR | S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH,
    };
    let victim = SmokeInode {
        uid: 2000,
        gid: 100,
        mode: S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
    };

    h.assert_eq_ev(
        "non-sticky directory allows delete",
        plan_sticky_directory_delete(&non_sticky_dir, &victim, 3000),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryNotSticky),
    );
    h.assert_eq_ev(
        "sticky directory owner may delete",
        plan_sticky_directory_delete(&sticky_dir, &victim, 1000),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryOwner),
    );
    h.assert_eq_ev(
        "sticky victim owner may delete",
        plan_sticky_directory_delete(&sticky_dir, &victim, 2000),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner),
    );
    h.assert_eq_ev(
        "root may delete in sticky directory",
        plan_sticky_directory_delete(&sticky_dir, &victim, 0),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::Root),
    );
    h.assert_eq_ev(
        "unrelated caller is denied by sticky directory",
        plan_sticky_directory_delete(&sticky_dir, &victim, 3000),
        StickyDirectoryDeletePlan::Deny,
    );

    let source_denied = plan_sticky_directory_rename(&sticky_dir, &victim, None, 3000);
    h.assert_ev(
        "sticky rename reports denied source",
        !source_denied.is_allowed()
            && source_denied.denied_by() == Some(StickyDirectoryRenameDeny::Source),
    );

    let target_dir = SmokeInode {
        uid: 4000,
        gid: 400,
        mode: sticky_dir.mode,
    };
    let target_victim = SmokeInode {
        uid: 5000,
        gid: 400,
        mode: S_IRUSR | S_IROTH,
    };
    let target_denied = plan_sticky_directory_rename(
        &sticky_dir,
        &victim,
        Some(StickyDirectoryRenameTarget::new(
            &target_dir,
            &target_victim,
        )),
        2000,
    );
    h.assert_ev(
        "sticky rename reports denied target",
        !target_denied.is_allowed()
            && target_denied.denied_by() == Some(StickyDirectoryRenameDeny::Target),
    );
}

fn smoke_setgid_inheritance(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.setgid_create", b"group-inheritance");
    let setgid_parent = SmokeInode {
        uid: 1000,
        gid: 220,
        mode: S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP,
    };
    let plain_parent = SmokeInode {
        uid: 1000,
        gid: 220,
        mode: S_IRUSR | S_IWUSR | S_IXUSR,
    };

    let dir_plan =
        plan_setgid_create_inheritance(&setgid_parent, 110, 0o755, CreatedEntryKind::Directory);
    h.assert_ev(
        "setgid directory create inherits parent group",
        dir_plan.inherits_parent_group(),
    );
    h.assert_eq_ev(
        "setgid directory create chooses parent gid",
        dir_plan.gid,
        220,
    );
    h.assert_eq_ev(
        "setgid directory create preserves setgid bit",
        dir_plan.mode & S_ISGID,
        S_ISGID,
    );
    h.assert_eq_ev(
        "setgid directory create source is parent",
        dir_plan.gid_source,
        SetgidCreateGidSource::ParentDirectory,
    );

    let file_plan =
        plan_setgid_create_inheritance(&setgid_parent, 110, 0o644, CreatedEntryKind::NonDirectory);
    h.assert_eq_ev("setgid file create chooses parent gid", file_plan.gid, 220);
    h.assert_eq_ev(
        "setgid file create keeps requested mode",
        file_plan.mode,
        0o644,
    );

    let plain_plan =
        plan_setgid_create_inheritance(&plain_parent, 110, 0o755, CreatedEntryKind::Directory);
    h.assert_eq_ev("plain parent uses caller gid", plain_plan.gid, 110);
    h.assert_eq_ev(
        "plain parent gid source is caller",
        plain_plan.gid_source,
        SetgidCreateGidSource::Caller,
    );
}

fn smoke_acl_codec_and_mode_sync(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.acl", b"codec-mode-sync");
    let mut acl: PosixAcl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 0o7,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 0o5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 0o5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0o4,
            id: 0,
        },
    ];

    let serialized = serialize_acl(&acl);
    h.assert_ev("serialized ACL xattr is non-empty", !serialized.is_empty());
    h.assert_eq_ev(
        "ACL xattr decode round-trips entries",
        deserialize_acl(&serialized),
        Ok(acl.clone()),
    );

    recalc_acl_mask(0o740, &mut acl);
    h.assert_eq_ev(
        "ACL mask follows group-class mode bits",
        acl.iter()
            .find(|entry| entry.tag == ACL_MASK)
            .map(|entry| entry.perm),
        Some(0o4),
    );
    h.assert_eq_ev(
        "mode sync derives visible mode from ACL",
        recalc_mode_from_acl(&acl),
        0o744,
    );

    let attrs = SmokeInode {
        uid: 1000,
        gid: 100,
        mode: 0,
    };
    h.assert_ev(
        "ACL owner entry grants read",
        check_access(
            &attrs,
            Some(&acl),
            1000,
            100,
            &[],
            ACCESS_READ,
            &VALID_MOUNT,
        ),
    );
    h.assert_ev(
        "ACL other entry does not grant write",
        !check_access(
            &attrs,
            Some(&acl),
            3000,
            300,
            &[],
            ACCESS_WRITE,
            &VALID_MOUNT,
        ),
    );
}

fn smoke_xattr_namespace_validation(h: &mut SmokeHarness) {
    record_permission_op(h, "permission.xattr_namespace", b"namespace-prefixes");
    h.assert_eq_ev(
        "user xattr namespace validates",
        validate_xattr_namespace(b"user.comment"),
        Ok(XattrNamespace::User),
    );
    h.assert_eq_ev(
        "system xattr namespace validates",
        validate_xattr_namespace(b"system.posix_acl_access"),
        Ok(XattrNamespace::System),
    );
    h.assert_eq_ev(
        "security xattr namespace validates",
        validate_xattr_namespace(b"security.selinux"),
        Ok(XattrNamespace::Security),
    );
    h.assert_eq_ev(
        "trusted xattr namespace validates",
        validate_xattr_namespace(b"trusted.overlay"),
        Ok(XattrNamespace::Trusted),
    );
    h.assert_eq_ev(
        "empty xattr name is rejected",
        validate_xattr_namespace(b""),
        Err(XattrNamespaceError::EmptyName),
    );
    h.assert_eq_ev(
        "prefix-only xattr name is rejected",
        validate_xattr_namespace(b"user."),
        Err(XattrNamespaceError::UnknownNamespace),
    );

    let oversized = vec![b'a'; XATTR_NAME_MAX + 1];
    h.assert_eq_ev(
        "oversized xattr name is rejected",
        validate_xattr_namespace(&oversized),
        Err(XattrNamespaceError::NameTooLong),
    );
}

fn record_permission_op(h: &mut SmokeHarness, op_name: &str, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_permission_passes() {
        let h = run_permission_smoke();
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
