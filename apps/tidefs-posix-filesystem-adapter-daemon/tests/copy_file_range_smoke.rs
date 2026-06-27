// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration smoke for copy_file_range through the VFS adapter.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-copy-file-range-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-copy-file-range-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

struct MountedVfs {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new(filenames: &[&str]) -> Self {
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
        seed_empty_files(&engine, filenames);
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

fn seed_empty_files(engine: &VfsLocalFileSystem, filenames: &[&str]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    for filename in filenames {
        engine
            .create(root, filename.as_bytes(), 0o644, 0, &ctx)
            .unwrap_or_else(|err| panic!("seed mounted VFS file {filename}: {err:?}"));
    }
}

fn open_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open mounted VFS file read/write")
}

fn open_write_only(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open mounted VFS file write-only")
}

fn write_payload(path: &Path, payload: &[u8]) {
    let mut file = open_read_write(path);
    file.write_all(payload)
        .expect("write mounted copy_file_range fixture");
    file.flush().expect("flush mounted copy_file_range fixture");
}

fn read_all(path: &Path) -> Vec<u8> {
    fs::read(path).expect("read mounted copy_file_range fixture")
}

fn copy_file_range_fd(
    src: &File,
    src_offset: Option<u64>,
    dst: &File,
    dst_offset: Option<u64>,
    len: usize,
) -> std::io::Result<usize> {
    let mut src_offset = src_offset.map(|offset| offset as libc::loff_t);
    let mut dst_offset = dst_offset.map(|offset| offset as libc::loff_t);
    let src_offset_ptr = src_offset
        .as_mut()
        .map_or(std::ptr::null_mut(), |offset| offset as *mut libc::loff_t);
    let dst_offset_ptr = dst_offset
        .as_mut()
        .map_or(std::ptr::null_mut(), |offset| offset as *mut libc::loff_t);

    // SAFETY: The file descriptors come from live `File` handles. Optional
    // offsets point to stack locals alive for the call, or are null as allowed
    // by copy_file_range.
    let result = unsafe {
        libc::copy_file_range(
            src.as_raw_fd(),
            src_offset_ptr,
            dst.as_raw_fd(),
            dst_offset_ptr,
            len,
            0,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn assert_copy_errno(
    src: &File,
    src_offset: Option<u64>,
    dst: &File,
    dst_offset: Option<u64>,
    len: usize,
    expected_errno: i32,
) {
    let err = copy_file_range_fd(src, src_offset, dst, dst_offset, len)
        .expect_err("mounted copy_file_range should fail");
    assert_eq!(err.raw_os_error(), Some(expected_errno));
}

#[test]
fn copy_file_range_between_files_copies_requested_bytes() {
    let mount = MountedVfs::new(&["source.bin", "dest.bin"]);
    let source_path = mount.path("/source.bin");
    let dest_path = mount.path("/dest.bin");
    write_payload(&source_path, b"0123456789abcdef");
    write_payload(&dest_path, b"AAAAAAAABBBBBBBB");
    let source = open_read_write(&source_path);
    let dest = open_read_write(&dest_path);

    let copied = copy_file_range_fd(&source, Some(4), &dest, Some(6), 5)
        .expect("copy range between mounted files");

    assert_eq!(copied, 5);
    assert_eq!(read_all(&source_path), b"0123456789abcdef");
    assert_eq!(read_all(&dest_path), b"AAAAAA45678BBBBB");
}

#[test]
fn copy_file_range_same_file_non_overlapping_range_succeeds() {
    let mount = MountedVfs::new(&["self.bin"]);
    let path = mount.path("/self.bin");
    write_payload(&path, b"abcdefghijklmnop");
    let file = open_read_write(&path);

    let copied = copy_file_range_fd(&file, Some(0), &file, Some(8), 4)
        .expect("copy non-overlapping range within one mounted file");

    assert_eq!(copied, 4);
    assert_eq!(read_all(&path), b"abcdefghabcdmnop");
}

#[test]
fn copy_file_range_zero_length_returns_zero_and_preserves_destination() {
    let mount = MountedVfs::new(&["source.bin", "dest.bin"]);
    let source_path = mount.path("/source.bin");
    let dest_path = mount.path("/dest.bin");
    write_payload(&source_path, b"copy nothing from here");
    write_payload(&dest_path, b"destination unchanged");
    let source = open_read_write(&source_path);
    let dest = open_read_write(&dest_path);

    let copied = copy_file_range_fd(&source, Some(0), &dest, Some(5), 0)
        .expect("zero-length mounted copy_file_range");

    assert_eq!(copied, 0);
    assert_eq!(read_all(&dest_path), b"destination unchanged");
}

#[test]
fn copy_file_range_source_offset_beyond_eof_returns_zero() {
    let mount = MountedVfs::new(&["source.bin", "dest.bin"]);
    let source_path = mount.path("/source.bin");
    let dest_path = mount.path("/dest.bin");
    write_payload(&source_path, b"short source");
    write_payload(&dest_path, b"unchanged destination");
    let source = open_read_write(&source_path);
    let dest = open_read_write(&dest_path);

    let copied = copy_file_range_fd(&source, Some(4096), &dest, Some(0), 32)
        .expect("copy range starting beyond mounted source EOF");

    assert_eq!(copied, 0);
    assert_eq!(read_all(&dest_path), b"unchanged destination");
}

#[test]
fn copy_file_range_same_file_overlapping_range_returns_einval() {
    let mount = MountedVfs::new(&["overlap.bin"]);
    let path = mount.path("/overlap.bin");
    write_payload(&path, b"abcdefghijklmnop");
    let file = open_read_write(&path);

    assert_copy_errno(&file, Some(0), &file, Some(3), 8, libc::EINVAL);
    assert_eq!(read_all(&path), b"abcdefghijklmnop");
}

#[test]
fn copy_file_range_rejects_write_only_source_fd() {
    let mount = MountedVfs::new(&["source.bin", "dest.bin"]);
    let source_path = mount.path("/source.bin");
    let dest_path = mount.path("/dest.bin");
    write_payload(&source_path, b"source requires a readable fd");
    write_payload(&dest_path, b"dest");
    let source = open_write_only(&source_path);
    let dest = open_read_write(&dest_path);

    assert_copy_errno(&source, Some(0), &dest, Some(0), 4, libc::EBADF);
    assert_eq!(read_all(&dest_path), b"dest");
}
