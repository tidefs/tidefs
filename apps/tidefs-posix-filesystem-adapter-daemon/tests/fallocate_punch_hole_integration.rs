// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE fallocate PUNCH_HOLE integration tests.
//!
//! Tests the FUSE fallocate handler's FALLOC_FL_PUNCH_HOLE mode through a
//! mounted TideFS filesystem.  Covers:
//!   - Basic punch-hole creates sparse gaps (data before and after hole intact).
//!   - Concurrent write interleaving: punch while another fd writes to the
//!     punched range.
//!   - Fsync durability ordering: punch, fsync, remount, verify persistence.
//!   - ENOSPC edge case: punch hole near capacity must succeed (it frees space).
//!
//! Tests skip gracefully when /dev/fuse is unavailable.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::{RequestCtx, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE};
use tidefs_vfs_engine::VfsEngine;

// ---------------------------------------------------------------------------
// Mount harness
// ---------------------------------------------------------------------------

fn unique_test_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-fallocate-{prefix}-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-fallocate-punch".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn request_ctx() -> RequestCtx {
    // SAFETY: `geteuid`/`getegid` read the current process credentials and do
    // not require pointer, fd, or buffer invariants.
    let gid = unsafe { libc::getegid() } as u32;
    RequestCtx {
        uid: unsafe { libc::geteuid() } as u32,
        gid,
        pid: std::process::id(),
        umask: 0o022,
        groups: vec![gid],
    }
}

struct MountedVfs {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new_with_seed(prefix: &str, seed: impl FnOnce(&VfsLocalFileSystem)) -> Self {
        let root = unique_test_root(prefix);
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        seed(&engine);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE");

        Self {
            root,
            mount,
            session: Some(session),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }

    fn remount(&mut self) {
        self.session.take();
        thread::sleep(std::time::Duration::from_millis(100));

        let store = self.root.join("store");
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("re-open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session =
            fuser::spawn_mount2(adapter, &self.mount, &mount_options()).expect("remount FUSE");
        self.session = Some(session);
    }
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Raw-fd helpers
// ---------------------------------------------------------------------------

fn do_fallocate(fd: RawFd, mode: i32, offset: i64, len: i64) -> io::Result<()> {
    // SAFETY: `fd` is supplied by the caller as an open file descriptor; the
    // mode and byte range are copied scalar syscall arguments.
    let rc = unsafe { libc::fallocate(fd, mode, offset, len) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn pread_exact(fd: RawFd, buf: &mut [u8], offset: i64) -> io::Result<usize> {
    // SAFETY: `fd` is caller-owned and open, and `buf` is a valid writable
    // slice for `buf.len()` bytes at the requested offset.
    let n = unsafe { libc::pread64(fd, buf.as_mut_ptr().cast(), buf.len(), offset) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

macro_rules! require_fuse {
    () => {
        if !std::path::Path::new("/dev/fuse").exists() {
            eprintln!(
                "SKIP: /dev/fuse not available — integration test requires FUSE kernel module"
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn seed_punched_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create punched fixture");
    let chunk = tidefs_local_filesystem::content_chunk_size() as usize;
    let payload: Vec<u8> = (0..(chunk * 3))
        .map(|i| ((i as i32).wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect();
    engine
        .write(&fh, 0, &payload, &ctx)
        .expect("write punched fixture");
    engine
        .fallocate(
            &fh,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            chunk as u64,
            chunk as u64,
            &ctx,
        )
        .expect("punch hole in fixture");
}

// ===========================================================================
// Test: basic PUNCH_HOLE with KEEP_SIZE creates sparse gap
// ===========================================================================

#[test]
fn fallocate_punch_hole_keep_size_creates_sparse_gap() {
    require_fuse!();

    let chunk = tidefs_local_filesystem::content_chunk_size() as usize;
    let mount = MountedVfs::new_with_seed("punch-basic", |engine| {
        seed_punched_file(engine, b"hole.bin");
    });

    let path = mount.path("/hole.bin");
    let file = File::open(&path).expect("open mounted hole.bin");
    let fd = file.as_raw_fd();

    // Hole range (chunk..2*chunk) should read as zeroes.
    let mut hole_buf = vec![0xFFu8; 512];
    let n = pread_exact(fd, &mut hole_buf, chunk as i64).expect("pread hole range");
    assert_eq!(n, 512, "should have read 512 bytes from hole range");
    assert_eq!(
        &hole_buf[..n],
        vec![0u8; 512],
        "hole range must read as zeroes"
    );

    // Data before hole should be intact (first 64 bytes of chunk 0).
    let mut pre_buf = vec![0u8; 64];
    pread_exact(fd, &mut pre_buf, 0).expect("pread pre-hole data");
    let expected_pre: Vec<u8> = (0..64)
        .map(|i: i32| (i.wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect();
    assert_eq!(pre_buf, expected_pre, "data before hole must be intact");

    // Data after hole should be intact (first 64 bytes of chunk 2).
    let mut post_buf = vec![0u8; 64];
    pread_exact(fd, &mut post_buf, (chunk * 2) as i64).expect("pread post-hole data");
    let expected_post: Vec<u8> = ((chunk * 2)..(chunk * 2 + 64))
        .map(|i| ((i as i32).wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect();
    assert_eq!(post_buf, expected_post, "data after hole must be intact");
}

// ===========================================================================
// Test: concurrent write interleaving
// ===========================================================================

#[test]
fn fallocate_punch_hole_concurrent_write_interleaving() {
    require_fuse!();

    let chunk = tidefs_local_filesystem::content_chunk_size() as u64;
    let mount = MountedVfs::new_with_seed("punch-concur", |engine| {
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");
        let (_attr, fh) = engine
            .create(root, b"concur.bin", 0o644, 0, &ctx)
            .expect("create concur fixture");
        let payload = vec![0xABu8; chunk as usize * 3];
        engine
            .write(&fh, 0, &payload, &ctx)
            .expect("write concur fixture");
    });

    let path = mount.path("/concur.bin");

    let fd1 = {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("open fd1");
        f.into_raw_fd()
    };
    let fd2 = {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("open fd2");
        f.into_raw_fd()
    };

    let (punched_tx, punched_rx) = mpsc::channel();

    let t1 = {
        thread::spawn(move || {
            do_fallocate(
                fd1,
                (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) as i32,
                chunk as i64,
                chunk as i64,
            )
            .expect("punch hole in concur.bin");
            punched_tx.send(()).expect("signal punch completion");
        })
    };

    let write_data: Vec<u8> = vec![0x42u8; 512];
    let t2 = {
        let w = write_data.clone();
        thread::spawn(move || {
            punched_rx.recv().expect("wait for punch completion");
            // SAFETY: `fd2` is a raw duplicate kept open until both threads
            // join, and `w` is an immutable byte buffer alive for the write.
            let n = unsafe { libc::pwrite(fd2, w.as_ptr().cast(), w.len(), (chunk + 128) as i64) };
            assert!(n > 0, "concurrent write should write some bytes");
            // SAFETY: `fd2` remains open and owned by the harness until the
            // final close after both worker threads have joined.
            unsafe {
                libc::fsync(fd2);
            }
        })
    };

    t1.join().expect("punch thread");
    t2.join().expect("write thread");

    // After both operations complete, verify data visibility.
    let mut buf = vec![0u8; 1024];
    let n = pread_exact(fd2, &mut buf, chunk as i64).expect("pread after concurrent ops");
    // First 128 bytes within punched range should be zeroes.
    assert_eq!(
        &buf[..128],
        vec![0u8; 128],
        "first 128 bytes of hole should read as zeroes"
    );
    // The concurrent write at chunk+128 should be visible.
    let visible_len = (n as usize).saturating_sub(128).min(write_data.len());
    assert_eq!(
        &buf[128..128 + visible_len],
        &write_data[..visible_len],
        "concurrent write data should be visible at offset chunk+128"
    );

    // SAFETY: both duplicated descriptors are owned by this harness and are not
    // used after this final close.
    unsafe {
        libc::close(fd1);
        libc::close(fd2);
    }
}

// ===========================================================================
// Test: fsync durability ordering
// ===========================================================================

#[test]
fn fallocate_punch_hole_survives_fsync_remount() {
    require_fuse!();

    let chunk = tidefs_local_filesystem::content_chunk_size() as usize;
    let mut mount = MountedVfs::new_with_seed("punch-fsync", |engine| {
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");
        let (_attr, fh) = engine
            .create(root, b"durable.bin", 0o644, 0, &ctx)
            .expect("create durable fixture");
        let payload: Vec<u8> = (0..(chunk * 3)).map(|i| (i as i32 % 256) as u8).collect();
        engine
            .write(&fh, 0, &payload, &ctx)
            .expect("write durable fixture");
    });

    let path = mount.path("/durable.bin");

    // Punch a hole, then fsync.
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("open durable.bin for punch");
        let fd = file.as_raw_fd();
        do_fallocate(
            fd,
            (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) as i32,
            chunk as i64,
            chunk as i64,
        )
        .expect("punch hole");
        // SAFETY: `fd` is borrowed from a live `File` and remains open for the
        // duration of the fsync call.
        unsafe {
            libc::fsync(fd);
        }
    }

    // Remount to re-read backing store.
    mount.remount();

    {
        let file = File::open(&path).expect("open durable.bin after remount");
        let fd = file.as_raw_fd();

        // Pre-hole data intact.
        let mut pre_buf = vec![0u8; 64];
        pread_exact(fd, &mut pre_buf, 0).expect("pread pre-hole after remount");
        let expected_pre: Vec<u8> = (0..64).map(|i| (i % 256) as u8).collect();
        assert_eq!(pre_buf, expected_pre, "pre-hole data must survive remount");

        // Hole reads as zeroes.
        let mut hole_buf = vec![0xFFu8; 512];
        let n = pread_exact(fd, &mut hole_buf, chunk as i64).expect("pread hole after remount");
        assert_eq!(
            &hole_buf[..n],
            vec![0u8; 512],
            "hole must persist after remount"
        );

        // Post-hole data intact.
        let mut post_buf = vec![0u8; 64];
        pread_exact(fd, &mut post_buf, (chunk * 2) as i64).expect("pread post-hole after remount");
        let expected_post: Vec<u8> = ((chunk * 2)..(chunk * 2 + 64))
            .map(|i| (i as i32 % 256) as u8)
            .collect();
        assert_eq!(
            post_buf, expected_post,
            "post-hole data must survive remount"
        );
    }
}

// ===========================================================================
// Test: ENOSPC behavior — punch hole near capacity must succeed
// ===========================================================================

#[test]
fn fallocate_punch_hole_near_enospc_succeeds() {
    require_fuse!();

    let chunk = tidefs_local_filesystem::content_chunk_size() as usize;
    let mount = MountedVfs::new_with_seed("punch-enospc", |engine| {
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");
        let (_attr, fh) = engine
            .create(root, b"sparse.bin", 0o644, 0, &ctx)
            .expect("create enospc fixture");
        let payload = vec![0x7Fu8; chunk * 3];
        engine
            .write(&fh, 0, &payload, &ctx)
            .expect("write enospc fixture");
    });

    let path = mount.path("/sparse.bin");

    // Punch a hole — this deallocates space, so it must never return ENOSPC.
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("open sparse.bin for punch");
        let fd = file.as_raw_fd();

        let result = do_fallocate(
            fd,
            (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) as i32,
            chunk as i64,
            chunk as i64,
        );

        assert!(
            result.is_ok(),
            "PUNCH_HOLE must succeed near capacity (frees space, never ENOSPC): got {:?}",
            result.err()
        );

        // Verify hole was created.
        let mut hole_buf = vec![0xFFu8; 512];
        let n = pread_exact(fd, &mut hole_buf, chunk as i64).expect("pread hole");
        assert_eq!(
            &hole_buf[..n],
            vec![0u8; 512],
            "hole range must read as zeroes"
        );
    }
}

// ===========================================================================
// Test: PUNCH_HOLE on a file opened read-only returns EBADF
// ===========================================================================

#[test]
fn fallocate_punch_hole_read_only_fd_returns_ebadf() {
    require_fuse!();

    let chunk = tidefs_local_filesystem::content_chunk_size();
    let mount = MountedVfs::new_with_seed("punch-ebadf", |engine| {
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");
        let (_attr, fh) = engine
            .create(root, b"ro.bin", 0o644, 0, &ctx)
            .expect("create ro fixture");
        let payload = vec![0xAAu8; chunk as usize];
        engine
            .write(&fh, 0, &payload, &ctx)
            .expect("write ro fixture");
    });

    let path = mount.path("/ro.bin");
    let file = File::open(&path).expect("open ro.bin read-only");
    let fd = file.as_raw_fd();

    let result = do_fallocate(
        fd,
        (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) as i32,
        0,
        4096,
    );
    assert_eq!(
        result.unwrap_err().raw_os_error(),
        Some(libc::EBADF),
        "PUNCH_HOLE on read-only fd must return EBADF"
    );
}
