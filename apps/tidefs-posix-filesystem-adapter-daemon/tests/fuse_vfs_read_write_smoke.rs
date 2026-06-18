// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted read/write smoke tests for the VFS-backed FUSE adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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
        "tidefs-vfs-read-write-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-vfs-read-write-smoke".to_string()),
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

fn seed_empty_files(engine: &VfsLocalFileSystem, filenames: &[&str]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    for filename in filenames {
        engine
            .create(root, filename.as_bytes(), 0o644, 0, &ctx)
            .unwrap_or_else(|err| panic!("seed mounted VFS file {filename}: {err:?}"));
    }
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open mounted VFS file")
}

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx.wrapping_mul(31).wrapping_add(7)) % 251) as u8)
        .collect()
}

fn assert_all_zero(bytes: &[u8]) {
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "sparse hole should read back as zero-filled bytes"
    );
}

#[test]
fn write_then_read_round_trip_through_vfs_mount() {
    let mnt = MountedVfs::new(&["roundtrip.bin"]);
    let path = mnt.path("/roundtrip.bin");
    let payload = b"vfs mounted read/write round trip";
    let mut file = create_read_write(&path);

    file.write_all(payload)
        .expect("write payload through mount");
    file.flush().expect("flush payload to mounted file");
    file.seek(SeekFrom::Start(0)).expect("seek to start");

    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read payload through mount");
    assert_eq!(readback, payload);
    assert_eq!(fs::read(&path).expect("path readback"), payload);
}

#[test]
fn multi_block_read_crosses_written_block_boundaries() {
    let mnt = MountedVfs::new(&["multi-block.bin"]);
    let path = mnt.path("/multi-block.bin");
    let content = patterned_bytes(12 * 1024);
    let mut file = create_read_write(&path);

    file.write_all(&content)
        .expect("write multi-block payload through mount");
    file.flush().expect("flush multi-block payload");
    assert_eq!(
        file.metadata()
            .expect("metadata after multi-block write")
            .len(),
        content.len() as u64
    );

    let offset = 3_500_u64;
    let len = 5_000_usize;
    file.seek(SeekFrom::Start(offset))
        .expect("seek across block boundary");
    let mut readback = vec![0_u8; len];
    file.read_exact(&mut readback)
        .expect("read range crossing block boundaries");
    assert_eq!(readback, content[offset as usize..offset as usize + len]);
}

#[test]
fn partial_read_and_eof_read_match_posix_behavior() {
    let mnt = MountedVfs::new(&["partial-eof.bin"]);
    let path = mnt.path("/partial-eof.bin");
    let content = patterned_bytes(8 * 1024);
    let mut file = create_read_write(&path);

    file.write_all(&content)
        .expect("write partial-read payload through mount");
    file.seek(SeekFrom::Start(2 * 1024))
        .expect("seek to partial read offset");

    let mut partial = vec![0_u8; 3 * 1024];
    file.read_exact(&mut partial)
        .expect("read partial slice through mount");
    assert_eq!(partial, content[2 * 1024..5 * 1024]);

    file.seek(SeekFrom::Start(content.len() as u64))
        .expect("seek to EOF");
    let mut eof = Vec::new();
    file.read_to_end(&mut eof).expect("read at EOF");
    assert!(eof.is_empty());
}

#[test]
fn overwrite_updates_only_the_target_range() {
    let mnt = MountedVfs::new(&["overwrite.bin"]);
    let path = mnt.path("/overwrite.bin");
    let mut file = create_read_write(&path);

    file.write_all(b"AAAAA").expect("write original bytes");
    file.seek(SeekFrom::Start(1))
        .expect("seek to overwrite offset");
    file.write_all(b"BBB").expect("overwrite byte range");
    file.flush().expect("flush overwrite");
    file.seek(SeekFrom::Start(0)).expect("seek to start");

    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read overwritten payload");
    assert_eq!(readback, b"ABBBA");
}

#[test]
fn sparse_write_reads_hole_as_zeroes() {
    let mnt = MountedVfs::new(&["sparse.bin"]);
    let path = mnt.path("/sparse.bin");
    let tail = b"tail after sparse hole";
    let mut file = create_read_write(&path);

    file.seek(SeekFrom::Start(8 * 1024))
        .expect("seek to sparse offset");
    file.write_all(tail).expect("write sparse tail");
    file.flush().expect("flush sparse write");
    assert_eq!(
        file.metadata().expect("metadata after sparse write").len(),
        (8 * 1024 + tail.len()) as u64
    );

    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read sparse payload");
    assert_eq!(readback.len(), 8 * 1024 + tail.len());
    assert_all_zero(&readback[..8 * 1024]);
    assert_eq!(&readback[8 * 1024..], tail);
}

#[test]
fn write_close_reopen_read_preserves_bytes() {
    let mnt = MountedVfs::new(&["reopen.bin"]);
    let path = mnt.path("/reopen.bin");
    let payload = patterned_bytes(4097);

    {
        let mut file = create_read_write(&path);
        file.write_all(&payload)
            .expect("write payload before close");
        file.flush().expect("flush payload before close");
    }

    let mut reopened = File::open(&path).expect("reopen mounted VFS file");
    let mut readback = Vec::new();
    reopened
        .read_to_end(&mut readback)
        .expect("read payload after reopen");
    assert_eq!(readback, payload);
}
