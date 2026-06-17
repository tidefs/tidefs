// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for POSIX mode-bit permission checking.
//!
//! Validates [`check_access_result`], [`check_search`], [`check_mode_access`],
//! and [`check_access`] across owner/group/other, root override, execute
//! restriction, supplementary groups, and denial paths.

use tidefs_permission::{
    check_access, check_access_result, check_mode_access, check_search, AccessMode, InodeAttr,
    MountIdentity, PermissionError, ACCESS_EXECUTE, ACCESS_RDWR, ACCESS_READ, ACCESS_WRITE,
    S_IFDIR, S_IFREG,
};

// Mount identity used across all permission binding tests.
const VALID_MOUNT: MountIdentity = MountIdentity::new(
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ],
    1,
);

// ---------------------------------------------------------------------------
// Test helper — a simple inode
// ---------------------------------------------------------------------------

struct TestInode {
    uid: u32,
    gid: u32,
    mode: u32,
}

impl TestInode {
    const fn new(uid: u32, gid: u32, mode: u32) -> Self {
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

// ---------------------------------------------------------------------------
// check_access_result — owner tests
// ---------------------------------------------------------------------------

#[test]
fn owner_read_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o400);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn owner_read_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o200); // write-only
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Read, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn owner_write_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o200);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Write, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn owner_write_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o400); // read-only
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Write, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn owner_execute_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o100);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn owner_execute_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o600); // rw-, no x
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Execute, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn owner_readwrite_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o600);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::ReadWrite, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn owner_readwrite_denied_read_missing() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o200); // -w-
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::ReadWrite, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn owner_readwrite_denied_write_missing() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o400); // r--
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::ReadWrite, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

// ---------------------------------------------------------------------------
// check_access_result — group tests
// ---------------------------------------------------------------------------

#[test]
fn group_read_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o040);
    assert_eq!(
        check_access_result(&ino, 2000, 100, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn group_read_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o020); // group write-only
    assert_eq!(
        check_access_result(&ino, 2000, 100, AccessMode::Read, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn group_write_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o020);
    assert_eq!(
        check_access_result(&ino, 2000, 100, AccessMode::Write, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn group_execute_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o010);
    assert_eq!(
        check_access_result(&ino, 2000, 100, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn group_execute_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o060); // rw-, group
    assert_eq!(
        check_access_result(&ino, 2000, 100, AccessMode::Execute, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

// ---------------------------------------------------------------------------
// check_access_result — other tests
// ---------------------------------------------------------------------------

#[test]
fn other_read_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o004);
    assert_eq!(
        check_access_result(&ino, 2000, 200, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn other_read_denied() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 2000, 200, AccessMode::Read, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn other_write_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o002);
    assert_eq!(
        check_access_result(&ino, 2000, 200, AccessMode::Write, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn other_execute_granted() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o001);
    assert_eq!(
        check_access_result(&ino, 2000, 200, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Root (uid 0) bypass with execute restriction
// ---------------------------------------------------------------------------

#[test]
fn root_read_bypasses_no_permissions() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_write_bypasses_no_permissions() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Write, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_readwrite_bypasses_no_permissions() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::ReadWrite, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_execute_denied_on_non_executable_regular_file_644() {
    // POSIX rule: root may not execute a regular file with no execute bits
    let ino = TestInode::new(1000, 100, S_IFREG | 0o644);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Execute, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn root_execute_allowed_when_any_execute_bit_set() {
    // Owner execute bit set
    let ino = TestInode::new(1000, 100, S_IFREG | 0o744); // owner has x
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_execute_allowed_when_group_execute_set() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o474); // group has x
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_execute_allowed_when_other_execute_set() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o445); // other has x
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn root_execute_denied_on_mode_644_file_check_mode_access() {
    // Same rule via check_mode_access (the bool-returning API)
    let ino = TestInode::new(1000, 100, S_IFREG | 0o644);
    assert!(!check_mode_access(
        &ino,
        0,
        0,
        &[],
        ACCESS_EXECUTE,
        &VALID_MOUNT
    ));
    // But read and write are still allowed
    assert!(check_mode_access(
        &ino,
        0,
        0,
        &[],
        ACCESS_READ,
        &VALID_MOUNT
    ));
    assert!(check_mode_access(
        &ino,
        0,
        0,
        &[],
        ACCESS_WRITE,
        &VALID_MOUNT
    ));
}

// ---------------------------------------------------------------------------
// Directory search (check_search)
// ---------------------------------------------------------------------------

#[test]
fn directory_search_granted_to_owner_with_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o700);
    assert_eq!(check_search(&dir, 1000, 100, &VALID_MOUNT), Ok(()));
}

#[test]
fn directory_search_denied_to_owner_without_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o600); // rw- only
    assert_eq!(
        check_search(&dir, 1000, 100, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn directory_search_granted_to_group_with_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o070);
    assert_eq!(check_search(&dir, 2000, 100, &VALID_MOUNT), Ok(()));
}

#[test]
fn directory_search_denied_to_group_without_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o060); // rw- group
    assert_eq!(
        check_search(&dir, 2000, 100, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn directory_search_granted_to_other_with_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o007);
    assert_eq!(check_search(&dir, 2000, 200, &VALID_MOUNT), Ok(()));
}

#[test]
fn directory_search_denied_to_other_without_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o006); // rw- other
    assert_eq!(
        check_search(&dir, 2000, 200, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn root_always_searches_directories() {
    // Root can search directories even with mode 000
    let dir = TestInode::new(1000, 100, S_IFDIR);
    assert_eq!(check_search(&dir, 0, 0, &VALID_MOUNT), Ok(()));
}

// ---------------------------------------------------------------------------
// Mode 000 — denial for all non-root users
// ---------------------------------------------------------------------------

#[test]
fn mode_000_denies_owner_read() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Read, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn mode_000_denies_owner_write() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Write, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn mode_000_denies_owner_execute() {
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 1000, 100, AccessMode::Execute, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

#[test]
fn mode_000_root_read_write_bypasses() {
    // Root bypasses mode 000 for read/write
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Write, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn mode_000_root_execute_denied() {
    // Root denied execute on mode 000 regular file (no execute bits)
    let ino = TestInode::new(1000, 100, S_IFREG);
    assert_eq!(
        check_access_result(&ino, 0, 0, AccessMode::Execute, &VALID_MOUNT),
        Err(PermissionError::AccessDenied)
    );
}

// ---------------------------------------------------------------------------
// Supplementary group membership (via check_access / check_mode_access)
// ---------------------------------------------------------------------------

#[test]
fn supplementary_group_grants_group_access() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o040); // group read
                                                          // Caller's primary gid is 200, but supplementary groups include 100
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
fn supplementary_group_denied_when_not_matching() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o070); // group rwx
                                                          // Caller has gid 200, supplementary groups [300, 400] — none match file gid 100
    assert!(!check_mode_access(
        &ino,
        2000,
        200,
        &[300, 400],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

#[test]
fn supplementary_group_via_check_access() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o040);
    assert!(check_access(
        &ino,
        None,
        2000,
        200,
        &[100],
        ACCESS_READ,
        &VALID_MOUNT
    ));
}

// ---------------------------------------------------------------------------
// setuid/setgid ignored for access check
// ---------------------------------------------------------------------------

#[test]
fn setuid_bit_does_not_grant_extra_access() {
    // Mode 0o4644: owner rw-, others r--, but setuid bit set
    let ino = TestInode::new(1000, 100, S_IFREG | 0o4644);
    // Non-owner, non-group member: should get 'other' bits (r--) regardless of setuid
    assert!(check_mode_access(
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
fn setgid_bit_does_not_grant_extra_access() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o2644);
    // Non-owner, non-group member: 'other' bits, setgid doesn't change that
    assert!(check_mode_access(
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
fn sticky_bit_does_not_affect_access_check() {
    let ino = TestInode::new(1000, 100, S_IFREG | 0o1644);
    assert!(check_mode_access(
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

// ---------------------------------------------------------------------------
// PermissionError Display and errno mapping
// ---------------------------------------------------------------------------

#[test]
fn permission_error_displays_as_permission_denied() {
    let err = PermissionError::AccessDenied;
    assert_eq!(format!("{err}"), "permission denied");
}

#[test]
fn permission_error_to_errno_is_eacces() {
    assert_eq!(PermissionError::AccessDenied.to_errno(), 13); // EACCES
}

// ---------------------------------------------------------------------------
// AccessMode to_mask
// ---------------------------------------------------------------------------

#[test]
fn access_mode_read_to_mask() {
    assert_eq!(AccessMode::Read.to_mask(), ACCESS_READ);
}

#[test]
fn access_mode_write_to_mask() {
    assert_eq!(AccessMode::Write.to_mask(), ACCESS_WRITE);
}

#[test]
fn access_mode_execute_to_mask() {
    assert_eq!(AccessMode::Execute.to_mask(), ACCESS_EXECUTE);
}

#[test]
fn access_mode_readwrite_to_mask() {
    assert_eq!(AccessMode::ReadWrite.to_mask(), ACCESS_RDWR);
}

// ---------------------------------------------------------------------------
// check_access_result on directory (should use mode bits same as files)
// ---------------------------------------------------------------------------

#[test]
fn directory_search_via_check_access_result_execute() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o700);
    assert_eq!(
        check_access_result(&dir, 1000, 100, AccessMode::Execute, &VALID_MOUNT),
        Ok(())
    );
}

#[test]
fn directory_owner_read_on_readable_dir() {
    let dir = TestInode::new(1000, 100, S_IFDIR | 0o500); // r-x
    assert_eq!(
        check_access_result(&dir, 1000, 100, AccessMode::Read, &VALID_MOUNT),
        Ok(())
    );
}
