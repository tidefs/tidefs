// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! POSIX DAC (Discretionary Access Control) permission evaluation tests.
//!
//! These tests exercise [`tidefs_permission`] through the `tidefs-auth`
//! crate boundary, validating owner/group/other mode-bit logic, root
//! override, ACL-first access decisions, and xattr namespace isolation
//! against the `fuse-xattr-acl-locks` milestone requirements of the
//! userspace-filesystem phase.

use tidefs_permission::{
    can_execute, can_lookup, can_read, can_write, check_access, check_mode_access,
    check_path_traversal, check_validated_access, plan_setgid_create_inheritance,
    plan_sticky_directory_delete, plan_sticky_directory_rename, validate_access_request,
    validate_xattr_namespace, AccessRequestError, CreatedEntryKind, InodeAttr, MountIdentity,
    PathTraversalComponent, PathTraversalDenied, PosixAclEntry, SetgidCreateGidSource,
    StickyDirectoryDeleteAllow, StickyDirectoryDeletePlan, StickyDirectoryRenameDeny,
    StickyDirectoryRenameTarget, XattrMap, XattrMapError, XattrNamespace, XattrNamespaceError,
    ACCESS_EXECUTE, ACCESS_NONE, ACCESS_RDWR, ACCESS_READ, ACCESS_RWX, ACCESS_WRITE, ACL_GROUP,
    ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ, S_IRGRP, S_IROTH, S_IRUSR, S_ISGID,
    S_ISUID, S_ISVTX, S_IWUSR, S_IXUSR,
};

/// Valid mount identity used across all permission DAC tests.
const VALID_MOUNT: MountIdentity = MountIdentity::new(
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ],
    1,
);

// =========================================================================
// Test helper: InodeAttr implementor
// =========================================================================

struct TestInode {
    uid: u32,
    gid: u32,
    mode: u32,
}

impl TestInode {
    fn new(uid: u32, gid: u32, mode: u32) -> Self {
        Self { uid, gid, mode }
    }
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

// =========================================================================
// 1. DAC mode-bit evaluation — owner / group / other rwx + root override
// =========================================================================

#[test]
fn dac_owner_read_on_readable_file() {
    let ino = TestInode::new(1000, 100, S_IRUSR);
    assert!(check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_owner_read_denied_on_write_only_file() {
    let ino = TestInode::new(1000, 100, S_IWUSR);
    assert!(!check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_owner_write_granted() {
    let ino = TestInode::new(1000, 100, S_IWUSR);
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
fn dac_owner_execute_granted() {
    let ino = TestInode::new(1000, 100, S_IXUSR);
    assert!(check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_EXECUTE,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_owner_all_perms() {
    let ino = TestInode::new(1000, 100, 0o700);
    assert!(check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_RWX,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_group_read_by_gid() {
    let ino = TestInode::new(1000, 100, S_IRGRP);
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
fn dac_group_read_by_supplementary_group() {
    let ino = TestInode::new(1000, 100, S_IRGRP);
    assert!(check_mode_access(
        &ino,
        2000,
        300,
        &[400, 100],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_group_read_denied_for_non_member() {
    let ino = TestInode::new(1000, 500, S_IRGRP);
    assert!(!check_mode_access(
        &ino,
        2000,
        300,
        &[400],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_other_read_granted() {
    let ino = TestInode::new(1000, 100, S_IROTH);
    assert!(check_mode_access(
        &ino,
        2000,
        300,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_other_read_denied() {
    let ino = TestInode::new(1000, 100, 0);
    assert!(!check_mode_access(
        &ino,
        2000,
        300,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_root_always_granted() {
    let ino = TestInode::new(1000, 100, 0);
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
fn dac_root_bypass_on_no_exec_file() {
    let ino = TestInode::new(1000, 100, 0o600);
    assert!(check_mode_access(
        &ino,
        0,
        200,
        &[],
        ACCESS_READ | ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_owner_precedence_over_group() {
    let ino = TestInode::new(1000, 200, 0o700);
    assert!(check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_RWX,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_group_member_when_not_owner() {
    let ino = TestInode::new(1000, 200, 0o070);
    assert!(check_mode_access(
        &ino,
        2000,
        200,
        &[],
        ACCESS_RWX,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_other_when_neither_owner_nor_group() {
    let ino = TestInode::new(1000, 200, 0o007);
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
fn dac_supplementary_group_takes_group_bits() {
    let ino = TestInode::new(1000, 500, 0o050);
    assert!(check_mode_access(
        &ino,
        2000,
        300,
        &[700, 500],
        ACCESS_READ | ACCESS_EXECUTE,
        &VALID_MOUNT
    ));
    assert!(!check_mode_access(
        &ino,
        2000,
        300,
        &[700, 500],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

// =========================================================================
// 2. Unified access check — ACL-first, mode-fallback
// =========================================================================

#[test]
fn unified_no_acl_falls_back_to_mode_bits() {
    let ino = TestInode::new(1000, 100, 0o644);
    assert!(check_access(
        &ino,
        None,
        1000,
        200,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(check_access(
        &ino,
        None,
        1000,
        200,
        &[],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_empty_acl_falls_back_to_mode_bits() {
    let ino = TestInode::new(1000, 100, 0o600);
    assert!(check_access(
        &ino,
        Some(&[]),
        1000,
        200,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_root_bypasses_acl() {
    let ino = TestInode::new(1000, 100, 0o000);
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
    assert!(check_access(
        &ino,
        Some(&acl),
        0,
        200,
        &[],
        ACCESS_RWX,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_acl_minimal_owner_access() {
    let ino = TestInode::new(1000, 100, 0o000);
    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
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
    assert!(check_access(
        &ino,
        Some(&acl),
        1000,
        200,
        &[],
        ACCESS_RWX,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_acl_named_user_with_mask_restriction() {
    let ino = TestInode::new(1000, 100, 0o000);
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
    assert!(check_access(
        &ino,
        Some(&acl),
        2000,
        300,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(!check_access(
        &ino,
        Some(&acl),
        2000,
        300,
        &[],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_acl_named_group_with_mask() {
    let ino = TestInode::new(1000, 100, 0o000);
    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 0,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP,
            perm: 6,
            id: 500,
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
    assert!(check_access(
        &ino,
        Some(&acl),
        2000,
        300,
        &[500],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(!check_access(
        &ino,
        Some(&acl),
        2000,
        300,
        &[500],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

#[test]
fn unified_acl_other_fallback() {
    let ino = TestInode::new(1000, 100, 0o000);
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
            tag: ACL_OTHER,
            perm: 4,
            id: 0,
        },
    ];
    assert!(check_access(
        &ino,
        Some(&acl),
        3000,
        400,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(!check_access(
        &ino,
        Some(&acl),
        3000,
        400,
        &[],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

// =========================================================================
// 3. Validated access boundary — mask validation
// =========================================================================

#[test]
fn validated_access_rejects_invalid_mask() {
    let ino = TestInode::new(1000, 100, 0o644);
    assert!(matches!(
        check_validated_access(&ino, None, 1000, 200, &[], 0x08, &VALID_MOUNT),
        Err(AccessRequestError::InvalidMask { .. })
    ));
}

#[test]
fn validated_access_allows_f_ok() {
    let ino = TestInode::new(1000, 100, 0o000);
    assert_eq!(
        check_validated_access(&ino, None, 2000, 300, &[], ACCESS_NONE, &VALID_MOUNT),
        Ok(true)
    );
}

#[test]
fn validated_access_non_owner_denied_by_mode() {
    let ino = TestInode::new(1000, 100, 0o700);
    assert_eq!(
        check_validated_access(&ino, None, 2000, 300, &[], ACCESS_READ, &VALID_MOUNT),
        Ok(false)
    );
}

// =========================================================================
// 4. Convenience access wrappers
// =========================================================================

#[test]
fn can_read_on_readable_file() {
    let ino = TestInode::new(1000, 100, 0o400);
    assert!(can_read(&ino, None, 1000, 200, &[], &VALID_MOUNT));
}

#[test]
fn can_write_on_writable_file() {
    let ino = TestInode::new(1000, 100, 0o200);
    assert!(can_write(&ino, None, 1000, 200, &[], &VALID_MOUNT));
}

#[test]
fn can_execute_on_executable_file() {
    let ino = TestInode::new(1000, 100, 0o100);
    assert!(can_execute(&ino, None, 1000, 200, &[], &VALID_MOUNT));
}

#[test]
fn can_lookup_same_as_execute() {
    let ino = TestInode::new(1000, 100, 0o100);
    assert_eq!(
        can_lookup(&ino, None, 1000, 200, &[], &VALID_MOUNT),
        can_execute(&ino, None, 1000, 200, &[], &VALID_MOUNT)
    );
}

// =========================================================================
// 5. Path traversal
// =========================================================================

#[test]
fn path_traversal_empty_components_is_ok() {
    assert_eq!(
        check_path_traversal(&[], 1000, 200, &[], &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn path_traversal_all_searchable() {
    let dir1 = TestInode::new(1000, 100, 0o001);
    let dir2 = TestInode::new(1000, 100, 0o001);
    let components = [
        PathTraversalComponent::new(&dir1, None),
        PathTraversalComponent::new(&dir2, None),
    ];
    assert_eq!(
        check_path_traversal(&components, 2000, 300, &[], &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn path_traversal_denied_at_first_blocked() {
    let dir1 = TestInode::new(1000, 100, 0o000);
    let dir2 = TestInode::new(1000, 100, 0o001);
    let components = [
        PathTraversalComponent::new(&dir1, None),
        PathTraversalComponent::new(&dir2, None),
    ];
    assert_eq!(
        check_path_traversal(&components, 2000, 300, &[], &VALID_MOUNT),
        Err(PathTraversalDenied { component_index: 0 })
    );
}

#[test]
fn path_traversal_root_bypass() {
    let dir = TestInode::new(1000, 100, 0o000);
    let components = [PathTraversalComponent::new(&dir, None)];
    assert_eq!(
        check_path_traversal(&components, 0, 0, &[], &VALID_MOUNT),
        Ok(())
    );
}

// =========================================================================
// 6. Sticky-directory delete planning
// =========================================================================

#[test]
fn sticky_delete_non_sticky_dir_allows_anyone_with_write_perm() {
    let dir = TestInode::new(1000, 100, 0o777);
    let victim = TestInode::new(2000, 200, 0o600);
    let plan = plan_sticky_directory_delete(&dir, &victim, 3000);
    assert_eq!(
        plan,
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryNotSticky)
    );
    assert!(plan.is_allowed());
}

#[test]
fn sticky_delete_root_allowed() {
    let dir = TestInode::new(1000, 100, S_ISVTX | 0o777);
    let victim = TestInode::new(2000, 200, 0o600);
    assert_eq!(
        plan_sticky_directory_delete(&dir, &victim, 0),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::Root)
    );
}

#[test]
fn sticky_delete_dir_owner_allowed() {
    let dir = TestInode::new(1000, 100, S_ISVTX | 0o777);
    let victim = TestInode::new(2000, 200, 0o600);
    assert_eq!(
        plan_sticky_directory_delete(&dir, &victim, 1000),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::DirectoryOwner)
    );
}

#[test]
fn sticky_delete_victim_owner_allowed() {
    let dir = TestInode::new(1000, 100, S_ISVTX | 0o777);
    let victim = TestInode::new(2000, 200, 0o600);
    assert_eq!(
        plan_sticky_directory_delete(&dir, &victim, 2000),
        StickyDirectoryDeletePlan::Allow(StickyDirectoryDeleteAllow::VictimOwner)
    );
}

#[test]
fn sticky_delete_denies_unrelated_caller() {
    let dir = TestInode::new(1000, 100, S_ISVTX | 0o777);
    let victim = TestInode::new(2000, 200, 0o600);
    let plan = plan_sticky_directory_delete(&dir, &victim, 3000);
    assert_eq!(plan, StickyDirectoryDeletePlan::Deny);
    assert!(!plan.is_allowed());
}

// =========================================================================
// 7. Sticky-directory rename planning
// =========================================================================

#[test]
fn sticky_rename_without_target_uses_source_rule() {
    let src_dir = TestInode::new(1000, 100, S_ISVTX | 0o777);
    let src_entry = TestInode::new(2000, 200, 0o600);
    let plan = plan_sticky_directory_rename(&src_dir, &src_entry, None, 2000);
    assert!(plan.is_allowed());
    assert_eq!(plan.denied_by(), None);
}

#[test]
fn sticky_rename_denies_target_replacement() {
    let src_dir = TestInode::new(1000, 100, 0o777);
    let src_entry = TestInode::new(2000, 200, 0o600);
    let tgt_dir = TestInode::new(3000, 300, S_ISVTX | 0o777);
    let tgt_entry = TestInode::new(4000, 400, 0o600);
    let plan = plan_sticky_directory_rename(
        &src_dir,
        &src_entry,
        Some(StickyDirectoryRenameTarget::new(&tgt_dir, &tgt_entry)),
        2000,
    );
    assert!(!plan.is_allowed());
    assert_eq!(plan.denied_by(), Some(StickyDirectoryRenameDeny::Target));
}

// =========================================================================
// 8. Setgid-directory create inheritance planning
// =========================================================================

#[test]
fn setgid_create_no_setgid_parent_uses_caller_gid() {
    let parent = TestInode::new(1000, 100, 0o755);
    let plan = plan_setgid_create_inheritance(&parent, 200, 0o640, CreatedEntryKind::NonDirectory);
    assert_eq!(plan.gid, 200);
    assert_eq!(plan.mode, 0o640);
    assert!(!plan.inherits_parent_group());
}

#[test]
fn setgid_create_non_dir_inherits_parent_gid() {
    let parent = TestInode::new(1000, 300, S_ISGID | 0o775);
    let plan = plan_setgid_create_inheritance(&parent, 200, 0o640, CreatedEntryKind::NonDirectory);
    assert_eq!(plan.gid, 300);
    assert_eq!(plan.gid_source, SetgidCreateGidSource::ParentDirectory);
    assert_eq!(plan.mode, 0o640);
}

#[test]
fn setgid_create_dir_inherits_parent_gid_and_setgid_bit() {
    let parent = TestInode::new(1000, 300, S_ISGID | 0o775);
    let plan = plan_setgid_create_inheritance(&parent, 200, 0o750, CreatedEntryKind::Directory);
    assert_eq!(plan.gid, 300);
    assert_eq!(plan.mode, S_ISGID | 0o750);
    assert!(plan.inherits_parent_group());
}

// =========================================================================
// 9. Xattr namespace validation
// =========================================================================

#[test]
fn xattr_namespace_user_accepted() {
    assert_eq!(
        validate_xattr_namespace(b"user.myattr"),
        Ok(XattrNamespace::User)
    );
}

#[test]
fn xattr_namespace_system_accepted() {
    assert_eq!(
        validate_xattr_namespace(b"system.posix_acl_access"),
        Ok(XattrNamespace::System)
    );
}

#[test]
fn xattr_namespace_security_accepted() {
    assert_eq!(
        validate_xattr_namespace(b"security.selinux"),
        Ok(XattrNamespace::Security)
    );
}

#[test]
fn xattr_namespace_trusted_accepted() {
    assert_eq!(
        validate_xattr_namespace(b"trusted.overlay.upper"),
        Ok(XattrNamespace::Trusted)
    );
}

#[test]
fn xattr_namespace_empty_rejected() {
    assert_eq!(
        validate_xattr_namespace(b""),
        Err(XattrNamespaceError::EmptyName)
    );
}

#[test]
fn xattr_namespace_no_prefix_rejected() {
    assert_eq!(
        validate_xattr_namespace(b"myattr"),
        Err(XattrNamespaceError::UnknownNamespace)
    );
}

#[test]
fn xattr_namespace_unknown_prefix_rejected() {
    assert_eq!(
        validate_xattr_namespace(b"custom.myattr"),
        Err(XattrNamespaceError::UnknownNamespace)
    );
}

#[test]
fn xattr_namespace_user_just_dot_rejected() {
    assert_eq!(
        validate_xattr_namespace(b"user."),
        Err(XattrNamespaceError::UnknownNamespace)
    );
}

#[test]
fn xattr_namespace_too_long_rejected() {
    let long = vec![b'a'; 256];
    assert_eq!(
        validate_xattr_namespace(&long),
        Err(XattrNamespaceError::NameTooLong)
    );
}

// =========================================================================
// 10. Xattr store CRUD
// =========================================================================

#[test]
fn xattr_store_insert_and_get() {
    let mut store = XattrMap::new();
    store.setxattr(1, b"user.foo", b"bar").unwrap();
    assert_eq!(store.getxattr(1, b"user.foo"), Some(b"bar".to_vec()));
}

#[test]
fn xattr_store_overwrite() {
    let mut store = XattrMap::new();
    store.setxattr(1, b"user.key", b"v1").unwrap();
    store.setxattr(1, b"user.key", b"v2").unwrap();
    assert_eq!(store.getxattr(1, b"user.key"), Some(b"v2".to_vec()));
}

#[test]
fn xattr_store_remove() {
    let mut store = XattrMap::new();
    store.setxattr(1, b"user.foo", b"bar").unwrap();
    assert!(store.removexattr(1, b"user.foo").is_ok());
    assert!(store.getxattr(1, b"user.foo").is_none());
}

#[test]
fn xattr_store_remove_nonexistent() {
    let mut store = XattrMap::new();
    assert_eq!(
        store.removexattr(1, b"user.nope"),
        Err(XattrMapError::NotFound)
    );
}

#[test]
fn xattr_store_list_keys() {
    let mut store = XattrMap::new();
    store.setxattr(1, b"user.a", b"1").unwrap();
    store.setxattr(1, b"user.b", b"2").unwrap();
    let mut names = store.listxattr(1);
    names.sort();
    assert_eq!(names.len(), 2);
}

#[test]
fn xattr_store_rejects_bad_namespace() {
    let mut store = XattrMap::new();
    assert!(store.setxattr(1, b"bad.attr", b"v").is_err());
}

#[test]
fn xattr_store_remove_all_clears_inode() {
    let mut store = XattrMap::new();
    store.setxattr(1, b"user.a", b"1").unwrap();
    store.setxattr(1, b"user.b", b"2").unwrap();
    store.setxattr(2, b"user.c", b"3").unwrap();
    let removed = store.remove_all(1);
    assert_eq!(removed, 2);
    assert!(store.listxattr(1).is_empty());
    assert_eq!(store.listxattr(2).len(), 1);
}

// =========================================================================
// 11. Validate access request boundary
// =========================================================================

#[test]
fn validate_access_request_accepts_valid_masks() {
    assert!(validate_access_request(ACCESS_READ).is_ok());
    assert!(validate_access_request(ACCESS_WRITE).is_ok());
    assert!(validate_access_request(ACCESS_EXECUTE).is_ok());
    assert!(validate_access_request(ACCESS_RDWR).is_ok());
    assert!(validate_access_request(ACCESS_RWX).is_ok());
    assert!(validate_access_request(ACCESS_NONE).is_ok());
}

#[test]
fn validate_access_request_rejects_bits_outside_valid_mask() {
    assert!(validate_access_request(0x08).is_err());
    assert!(validate_access_request(ACCESS_RWX | 0x10).is_err());
}

#[test]
fn validate_access_request_reports_invalid_bits() {
    let err = validate_access_request(0x0F).unwrap_err();
    assert_eq!(
        err,
        AccessRequestError::InvalidMask {
            requested: 0x0F,
            invalid_bits: 0x08,
        }
    );
}

// =========================================================================
// 12. Boundary and edge cases
// =========================================================================

#[test]
fn dac_mode_zero_file_owner_cannot_access() {
    let ino = TestInode::new(1000, 100, 0o000);
    assert!(!check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(!check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_mode_zero_file_root_can_access() {
    let ino = TestInode::new(1000, 100, 0o000);
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
fn dac_file_with_suid_sgid_sticky_does_not_affect_permission_eval() {
    let ino = TestInode::new(1000, 100, S_ISUID | S_ISGID | S_ISVTX | 0o644);
    assert!(check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_READ | ACCESS_WRITE,
        &VALID_MOUNT
    ));
    assert!(!check_mode_access(
        &ino,
        1000,
        200,
        &[],
        ACCESS_EXECUTE,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_group_member_reads_file_with_owner_uid_zero() {
    let ino = TestInode::new(0, 500, 0o040);
    assert!(check_mode_access(
        &ino,
        2000,
        500,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn dac_large_supplementary_group_list() {
    let ino = TestInode::new(1000, 500, 0o070);
    let mut groups: Vec<u32> = (0..50).map(|i| 1000 + i).collect();
    groups.push(500);
    assert!(check_mode_access(
        &ino,
        2000,
        300,
        &groups,
        ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE,
        &VALID_MOUNT
    ));
}

#[test]
fn validated_access_rejects_invalid_bits_even_for_root() {
    let ino = TestInode::new(1000, 100, 0o644);
    assert!(check_validated_access(&ino, None, 0, 0, &[], 0x10, &VALID_MOUNT).is_err());
}

#[test]
fn validated_access_with_acl_uses_acl_for_permission() {
    let ino = TestInode::new(1000, 100, 0o000);
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
    assert_eq!(
        check_validated_access(
            &ino,
            Some(&acl),
            1000,
            200,
            &[],
            ACCESS_READ | ACCESS_WRITE,
            &VALID_MOUNT
        ),
        Ok(true)
    );
}
