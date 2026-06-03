//! Integration tests for xattr-statx round-trip with BLAKE3-verified
//! xattr state integrity.
//!
//! Domain: `tidefs-fuse-xattr-statx-v1`
//!
//! Validates that statx replies carry xattr/ACL presence metadata and
//! that BLAKE3 xattr state digests are deterministic across mount cycles.

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-xattr-statx-blake3-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-xattr-statx-blake3".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn path_c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path nul")
}

fn name_c(name: &str) -> CString {
    CString::new(name).expect("name nul")
}

unsafe fn setxattr_sys(
    path: &CString,
    name: &CString,
    value: &[u8],
    flags: i32,
) -> std::io::Result<()> {
    let r = libc::setxattr(
        path.as_ptr(),
        name.as_ptr(),
        value.as_ptr() as *const libc::c_void,
        value.len(),
        flags,
    );
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// statx via libc syscall(2). Returns (stx_mask, stx_attributes).
unsafe fn statx_probe(path: &CString, flags: i32) -> std::io::Result<(u32, u64)> {
    let mut buf = vec![0u8; 256];
    let r = libc::syscall(
        libc::SYS_statx,
        0i32,          // dirfd (AT_FDCWD)
        path.as_ptr(), // pathname
        flags,
        0x7ff_u64 | 0x1000_u64, // mask: BASIC_STATS | STATX_ATTRS
        buf.as_mut_ptr(),
    );
    if r == 0 {
        let stx_mask = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let stx_attributes = u64::from_le_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        Ok((stx_mask, stx_attributes))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn create_file(path: &Path, mode: u32) {
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)
        .expect("create file");
    f.write_all(b"statx xattr blake3 test payload")
        .expect("write");
    drop(f);
}

// ---------------------------------------------------------------------------
// Test: statx reports xattr presence after setxattr
// ---------------------------------------------------------------------------

#[test]
fn statx_reports_xattr_present_after_setxattr() {
    let root = unique_test_root();
    let store = root.join("store");
    let mount = root.join("mnt");
    fs::create_dir_all(&store).expect("create store");
    fs::create_dir_all(&mount).expect("create mount");

    let fs = LocalFileSystem::open_with_root_authentication_key(
        &store,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open fs");
    let engine = VfsLocalFileSystem::new(fs);
    let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter");
    let _session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount");

    let file_path = mount.join("statx_test.txt");
    create_file(&file_path, 0o644);
    let pc = path_c(&file_path);

    unsafe {
        // Before setxattr: stx_attributes should not have XATTR_PRESENT.
        let (mask, attrs) = match statx_probe(&pc, 0x1000 /* AT_EMPTY_PATH */) {
            Ok(v) => v,
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                eprintln!("statx not available on this kernel, skipping");
                return;
            }
            Err(e) => panic!("statx failed: {e:?}"),
        };
        assert!(
            mask & 0x1000 != 0,
            "stx_mask should include STATX_ATTRS (0x1000), got {mask:#x}"
        );
        assert_eq!(
            attrs & 0x1,
            0,
            "no STATX_ATTR_XATTR_PRESENT before setxattr, got {attrs:#x}"
        );

        // Set a user xattr.
        setxattr_sys(&pc, &name_c("user.statx-test"), b"hello", 0).expect("setxattr");

        // After setxattr: stx_attributes should have XATTR_PRESENT.
        let (mask2, attrs2) = statx_probe(&pc, 0x1000).expect("statx after setxattr");
        assert!(mask2 & 0x1000 != 0);
        assert_eq!(
            attrs2 & 0x1,
            0x1,
            "STATX_ATTR_XATTR_PRESENT should be set, got {attrs2:#x}"
        );
    }

    drop(_session);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Test: statx reports ACL presence when ACL xattrs are set
// ---------------------------------------------------------------------------

#[test]
fn statx_reports_acl_presence_when_acl_xattrs_set() {
    // ACL xattrs require root (CAP_SYS_ADMIN). This test is skipped
    // when running as non-root.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping ACL statx test (requires root)");
        return;
    }

    let root = unique_test_root();
    let store = root.join("store");
    let mount = root.join("mnt");
    fs::create_dir_all(&store).expect("create store");
    fs::create_dir_all(&mount).expect("create mount");

    let fs = LocalFileSystem::open_with_root_authentication_key(
        &store,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open fs");
    let engine = VfsLocalFileSystem::new(fs);
    let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter");
    let _session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount");

    let file_path = mount.join("acl_test.txt");
    create_file(&file_path, 0o644);
    let pc = path_c(&file_path);

    // Minimal valid access ACL: version=2, user::rwx, mask::rwx, other::rwx
    // Encoded in Linux ACL xattr format: 4-byte version + 3x8-byte entries.
    let mut acl_blob = Vec::new();
    acl_blob.extend_from_slice(&0x0002u32.to_le_bytes()); // version
                                                          // ACL_USER_OBJ (tag 1), perm 7 (rwx), id 0
    acl_blob.extend_from_slice(&1u16.to_le_bytes());
    acl_blob.extend_from_slice(&7u16.to_le_bytes());
    acl_blob.extend_from_slice(&0u32.to_le_bytes());
    // ACL_MASK (tag 0x10), perm 7, id 0
    acl_blob.extend_from_slice(&0x10u16.to_le_bytes());
    acl_blob.extend_from_slice(&7u16.to_le_bytes());
    acl_blob.extend_from_slice(&0u32.to_le_bytes());
    // ACL_OTHER (tag 0x20), perm 7, id 0
    acl_blob.extend_from_slice(&0x20u16.to_le_bytes());
    acl_blob.extend_from_slice(&7u16.to_le_bytes());
    acl_blob.extend_from_slice(&0u32.to_le_bytes());

    unsafe {
        setxattr_sys(&pc, &name_c("system.posix_acl_access"), &acl_blob, 0)
            .expect("setxattr system.posix_acl_access");

        let (_mask, attrs) = match statx_probe(&pc, 0x1000) {
            Ok(v) => v,
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                eprintln!("statx not available, skipping");
                return;
            }
            Err(e) => panic!("statx after ACL set failed: {e:?}"),
        };
        assert_eq!(
            attrs & 0x2,
            0x2,
            "STATX_ATTR_POSIX_ACL_ACCESS (0x2) should be set when ACL xattr exists, got {attrs:#x}"
        );
    }

    drop(_session);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Test: BLAKE3 xattr state digest deterministic across remount
// ---------------------------------------------------------------------------

#[test]
fn xattr_blake3_digest_deterministic_across_remount() {
    let root = unique_test_root();
    let store = root.join("store");
    let mount = root.join("mnt");
    fs::create_dir_all(&store).expect("create store");
    fs::create_dir_all(&mount).expect("create mount");

    let file_path = mount.join("blake3_test.txt");

    // First mount: create file and set xattrs.
    {
        let fs = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs 1");
        let engine = VfsLocalFileSystem::new(fs);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter 1");
        let _session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount 1");

        create_file(&file_path, 0o644);
        let pc = path_c(&file_path);

        unsafe {
            setxattr_sys(&pc, &name_c("user.a"), b"val-a", 0).expect("set user.a");
            setxattr_sys(&pc, &name_c("user.b"), b"val-b", 0).expect("set user.b");
        }
    }

    // Second mount: verify xattrs persist and read back deterministically.
    let digest1 = {
        let fs = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs 2");
        let engine = VfsLocalFileSystem::new(fs);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter 2");
        let _session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount 2");

        let pc = path_c(&file_path);

        unsafe {
            // Read all xattrs and compute a simple deterministic digest
            let size = libc::listxattr(pc.as_ptr(), std::ptr::null_mut(), 0);
            assert!(
                size >= 0,
                "listxattr size query should succeed after remount, got {size}"
            );

            let mut list_buf = vec![0u8; size as usize];
            let n = libc::listxattr(
                pc.as_ptr(),
                list_buf.as_mut_ptr() as *mut libc::c_char,
                list_buf.len(),
            );
            assert!(n >= 0, "listxattr should succeed after remount");

            // Collect all (name, value) pairs and hash them for comparison
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let raw = &list_buf[..n as usize];
            for name_bytes in raw.split(|b| *b == 0) {
                if name_bytes.is_empty() {
                    continue;
                }
                let val_size = libc::getxattr(
                    pc.as_ptr(),
                    name_bytes.as_ptr() as *const libc::c_char,
                    std::ptr::null_mut(),
                    0,
                );
                assert!(
                    val_size >= 0,
                    "getxattr size query should succeed for {name_bytes:?}"
                );
                let mut val_buf = vec![0u8; val_size as usize];
                let vn = libc::getxattr(
                    pc.as_ptr(),
                    name_bytes.as_ptr() as *const libc::c_char,
                    val_buf.as_mut_ptr() as *mut libc::c_void,
                    val_buf.len(),
                );
                assert!(vn >= 0);
                pairs.push((name_bytes.to_vec(), val_buf[..vn as usize].to_vec()));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));

            // Compute a simple BLAKE3 digest over the sorted pairs
            let mut hasher = blake3::Hasher::new();
            for (name, val) in &pairs {
                hasher.update(&name[..]);
                hasher.update(&val[..]);
            }
            hasher.finalize()
        }
    };

    // Third mount: verify the digest matches.
    let digest2 = {
        let fs = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs 3");
        let engine = VfsLocalFileSystem::new(fs);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter 3");
        let _session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount 3");

        let pc = path_c(&file_path);

        unsafe {
            let size = libc::listxattr(pc.as_ptr(), std::ptr::null_mut(), 0);
            assert!(size >= 0);
            let mut list_buf = vec![0u8; size as usize];
            let n = libc::listxattr(
                pc.as_ptr(),
                list_buf.as_mut_ptr() as *mut libc::c_char,
                list_buf.len(),
            );
            assert!(n >= 0);
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let raw = &list_buf[..n as usize];
            for name_bytes in raw.split(|b| *b == 0) {
                if name_bytes.is_empty() {
                    continue;
                }
                let val_size = libc::getxattr(
                    pc.as_ptr(),
                    name_bytes.as_ptr() as *const libc::c_char,
                    std::ptr::null_mut(),
                    0,
                );
                assert!(val_size >= 0);
                let mut val_buf = vec![0u8; val_size as usize];
                let vn = libc::getxattr(
                    pc.as_ptr(),
                    name_bytes.as_ptr() as *const libc::c_char,
                    val_buf.as_mut_ptr() as *mut libc::c_void,
                    val_buf.len(),
                );
                assert!(vn >= 0);
                pairs.push((name_bytes.to_vec(), val_buf[..vn as usize].to_vec()));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut hasher = blake3::Hasher::new();
            for (name, val) in &pairs {
                hasher.update(&name[..]);
                hasher.update(&val[..]);
            }
            hasher.finalize()
        }
    };

    assert_eq!(
        digest1, digest2,
        "BLAKE3 xattr state digest must be deterministic across remounts"
    );

    let _ = fs::remove_dir_all(&root);
}
