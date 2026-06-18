// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration smoke for lseek (SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE) through the VFS adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::{RequestCtx, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE};
use tidefs_vfs_engine::VfsEngine;

const CHUNK: u64 = 64 * 1024;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-vfs-lseek-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-vfs-lseek-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn request_ctx() -> RequestCtx {
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
    fn new_with_seed(seed: impl FnOnce(&VfsLocalFileSystem)) -> Self {
        let root = unique_test_root();
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
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn seed_empty_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create empty lseek fixture");
}

fn seed_dense_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create dense lseek fixture");
    engine
        .write(&fh, 0, b"dense file data", &ctx)
        .expect("write dense lseek fixture");
}

fn seed_sparse_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create sparse lseek fixture");
    let payload = vec![0xAB; (CHUNK * 3) as usize];
    engine
        .write(&fh, 0, &payload, &ctx)
        .expect("write sparse lseek fixture");
    engine
        .fallocate(
            &fh,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            CHUNK,
            CHUNK,
            &ctx,
        )
        .expect("punch sparse lseek fixture hole");
}

fn seed_leading_hole_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create leading-hole lseek fixture");
    let payload = vec![0xCD; (CHUNK + b"tail data".len() as u64) as usize];
    engine
        .write(&fh, 0, &payload, &ctx)
        .expect("write leading-hole lseek fixture");
    engine
        .fallocate(
            &fh,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            0,
            CHUNK,
            &ctx,
        )
        .expect("punch leading-hole lseek fixture");
}

fn open_readonly(path: &PathBuf) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .expect("open mounted lseek fixture")
}

fn lseek_fd_raw(file: &File, offset: libc::off_t, whence: i32) -> std::io::Result<u64> {
    let result = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as u64)
    }
}

fn lseek_fd(file: &File, offset: u64, whence: i32) -> std::io::Result<u64> {
    lseek_fd_raw(file, offset as libc::off_t, whence)
}

fn assert_lseek(file: &File, offset: u64, whence: i32, expected: u64) {
    let actual = lseek_fd(file, offset, whence).expect("mounted lseek should succeed");
    assert_eq!(actual, expected);
}

fn assert_lseek_errno(file: &File, offset: u64, whence: i32, expected_errno: i32) {
    let err = lseek_fd(file, offset, whence).expect_err("mounted lseek should fail");
    assert_eq!(err.raw_os_error(), Some(expected_errno));
}

fn assert_lseek_raw_errno(file: &File, offset: libc::off_t, whence: i32, expected_errno: i32) {
    let err = lseek_fd_raw(file, offset, whence).expect_err("mounted lseek should fail");
    assert_eq!(err.raw_os_error(), Some(expected_errno));
}

#[test]
fn lseek_sparse_file_reports_initial_data_first_hole_and_second_data() {
    let mount = MountedVfs::new_with_seed(|engine| seed_sparse_file(engine, b"sparse.bin"));
    let file = open_readonly(&mount.path("/sparse.bin"));

    assert_lseek(&file, 0, libc::SEEK_DATA, 0);
    assert_lseek(&file, 0, libc::SEEK_HOLE, CHUNK);
    assert_lseek(&file, CHUNK, libc::SEEK_DATA, CHUNK * 2);
    assert_lseek(&file, CHUNK * 2, libc::SEEK_HOLE, CHUNK * 3);
}

#[test]
fn lseek_leading_hole_reports_hole_at_zero_and_next_data() {
    let mount = MountedVfs::new_with_seed(|engine| seed_leading_hole_file(engine, b"leading.bin"));
    let file = open_readonly(&mount.path("/leading.bin"));

    assert_lseek(&file, 0, libc::SEEK_HOLE, 0);
    assert_lseek(&file, 0, libc::SEEK_DATA, CHUNK);
    assert_lseek(&file, CHUNK, libc::SEEK_DATA, CHUNK);
    assert_lseek(
        &file,
        CHUNK,
        libc::SEEK_HOLE,
        CHUNK + b"tail data".len() as u64,
    );
}

#[test]
fn lseek_inside_sparse_hole_reports_current_hole_and_next_data() {
    let mount = MountedVfs::new_with_seed(|engine| seed_sparse_file(engine, b"sparse.bin"));
    let file = open_readonly(&mount.path("/sparse.bin"));
    let inside_hole = CHUNK + 512;

    assert_lseek(&file, inside_hole, libc::SEEK_HOLE, inside_hole);
    assert_lseek(&file, inside_hole, libc::SEEK_DATA, CHUNK * 2);
}

#[test]
fn lseek_dense_file_reports_data_and_eof_hole() {
    let mount = MountedVfs::new_with_seed(|engine| seed_dense_file(engine, b"dense.bin"));
    let file = open_readonly(&mount.path("/dense.bin"));
    let file_size = file.metadata().expect("dense metadata").len();

    assert_lseek(&file, 0, libc::SEEK_DATA, 0);
    assert_lseek(&file, 4, libc::SEEK_DATA, 4);
    assert_lseek(&file, 0, libc::SEEK_HOLE, file_size);
    assert_lseek(&file, 4, libc::SEEK_HOLE, file_size);
}

#[test]
fn lseek_at_or_past_eof_returns_enxio() {
    let mount = MountedVfs::new_with_seed(|engine| seed_dense_file(engine, b"dense.bin"));
    let file = open_readonly(&mount.path("/dense.bin"));
    let file_size = file.metadata().expect("dense metadata").len();

    assert_lseek_errno(&file, file_size, libc::SEEK_DATA, libc::ENXIO);
    assert_lseek_errno(&file, file_size, libc::SEEK_HOLE, libc::ENXIO);
    assert_lseek_errno(&file, file_size + 1, libc::SEEK_DATA, libc::ENXIO);
    assert_lseek_errno(&file, file_size + 1, libc::SEEK_HOLE, libc::ENXIO);
}

#[test]
fn lseek_empty_file_returns_enxio() {
    let mount = MountedVfs::new_with_seed(|engine| seed_empty_file(engine, b"empty.bin"));
    let file = open_readonly(&mount.path("/empty.bin"));

    assert_lseek_errno(&file, 0, libc::SEEK_DATA, libc::ENXIO);
    assert_lseek_errno(&file, 0, libc::SEEK_HOLE, libc::ENXIO);
}

#[test]
fn lseek_negative_offset_returns_einval() {
    let mount = MountedVfs::new_with_seed(|engine| seed_dense_file(engine, b"dense.bin"));
    let file = open_readonly(&mount.path("/dense.bin"));

    assert_lseek_raw_errno(&file, -1, libc::SEEK_DATA, libc::EINVAL);
    assert_lseek_raw_errno(&file, -1, libc::SEEK_HOLE, libc::EINVAL);
}

#[test]
fn lseek_after_write_close_reopen_reports_written_data() {
    let mount = MountedVfs::new_with_seed(|engine| seed_empty_file(engine, b"reopen.bin"));
    let path = mount.path("/reopen.bin");
    let payload = b"mounted lseek reopen data";

    {
        let mut writer = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("open mounted lseek writer");
        writer.write_all(payload).expect("write mounted lseek data");
        writer.flush().expect("flush mounted lseek data");
    }

    let file = open_readonly(&path);
    assert_lseek(&file, 0, libc::SEEK_DATA, 0);
    assert_lseek(&file, 0, libc::SEEK_HOLE, payload.len() as u64);
}

// Helper: read from a raw file descriptor.
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let result = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

// Seed a file with a known repeating 0x00..0xFF byte pattern for round-trip verification.
fn seed_seek_roundtrip_file(engine: &VfsLocalFileSystem, name: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create seek roundtrip fixture");
    let payload: Vec<u8> = (0..4096u64).map(|i| (i % 256) as u8).collect();
    engine
        .write(&fh, 0, &payload, &ctx)
        .expect("write seek roundtrip fixture");
}

#[test]
fn lseek_set_read_roundtrip_verifies_data_at_offset() {
    let mount =
        MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"roundtrip.bin"));
    let file = open_readonly(&mount.path("/roundtrip.bin"));

    // Seek to offset 100 with SEEK_SET
    let pos = lseek_fd(&file, 100, libc::SEEK_SET).expect("SEEK_SET should succeed");
    assert_eq!(pos, 100);

    // Read 16 bytes and verify they match the byte pattern (100..116 % 256)
    let mut buf = [0u8; 16];
    let n = read_fd(file.as_raw_fd(), &mut buf).expect("read after SEEK_SET");
    assert_eq!(n, 16);
    for (i, &byte) in buf.iter().enumerate() {
        assert_eq!(
            byte,
            ((100 + i as u64) % 256) as u8,
            "byte at offset {}",
            100 + i
        );
    }
}

#[test]
fn lseek_cur_advances_position_after_set() {
    let mount = MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"cur.bin"));
    let file = open_readonly(&mount.path("/cur.bin"));

    // SEEK_SET to offset 50
    let pos = lseek_fd(&file, 50, libc::SEEK_SET).expect("SEEK_SET");
    assert_eq!(pos, 50);

    // SEEK_CUR +20 should advance to 70
    let pos = lseek_fd(&file, 20, libc::SEEK_CUR).expect("SEEK_CUR +20");
    assert_eq!(pos, 70);

    // Verify the data at position 70 matches the pattern
    let mut buf = [0u8; 8];
    let n = read_fd(file.as_raw_fd(), &mut buf).expect("read after SEEK_CUR");
    assert_eq!(n, 8);
    for (i, &byte) in buf.iter().enumerate() {
        assert_eq!(byte, ((70 + i as u64) % 256) as u8);
    }
}

#[test]
fn lseek_end_zero_offset_returns_file_size() {
    let mount = MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"end.bin"));
    let file = open_readonly(&mount.path("/end.bin"));
    let file_size = file.metadata().expect("metadata").len();

    let pos = lseek_fd(&file, 0, libc::SEEK_END).expect("SEEK_END 0");
    assert_eq!(pos, file_size);
}

#[test]
fn lseek_end_positive_offset_extends_beyond_file_size() {
    let mount =
        MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"end-pos.bin"));
    let file = open_readonly(&mount.path("/end-pos.bin"));
    let file_size = file.metadata().expect("metadata").len();

    let pos = lseek_fd(&file, 100, libc::SEEK_END).expect("SEEK_END +100");
    assert_eq!(pos, file_size + 100);
}

#[test]
fn lseek_end_negative_offset_within_file() {
    let mount =
        MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"end-neg.bin"));
    let file = open_readonly(&mount.path("/end-neg.bin"));

    // SEEK_END -10: should point to file_size - 10
    let pos = lseek_fd_raw(&file, -10, libc::SEEK_END).expect("SEEK_END -10");
    let file_size = file.metadata().expect("metadata").len();
    assert_eq!(pos, file_size - 10);

    // Verify data at that position
    let mut buf = [0u8; 8];
    let n = read_fd(file.as_raw_fd(), &mut buf).expect("read after SEEK_END -10");
    assert_eq!(n, 8);
    let expected_offset = file_size - 10;
    for (i, &byte) in buf.iter().enumerate() {
        assert_eq!(byte, ((expected_offset + i as u64) % 256) as u8);
    }
}

#[test]
fn lseek_set_negative_offset_returns_einval() {
    let mount =
        MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"set-neg.bin"));
    let file = open_readonly(&mount.path("/set-neg.bin"));

    assert_lseek_raw_errno(&file, -1, libc::SEEK_SET, libc::EINVAL);
}

#[test]
fn lseek_end_negative_offset_past_start_returns_einval() {
    let mount =
        MountedVfs::new_with_seed(|engine| seed_seek_roundtrip_file(engine, b"end-past.bin"));
    let file = open_readonly(&mount.path("/end-past.bin"));
    let file_size = file.metadata().expect("metadata").len() as libc::off_t;

    // Negative offset that goes before the start of the file
    assert_lseek_raw_errno(&file, -(file_size + 1), libc::SEEK_END, libc::EINVAL);
}
