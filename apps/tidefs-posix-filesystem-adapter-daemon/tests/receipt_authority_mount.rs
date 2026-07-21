// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Same-open-file-descriptor mounted receipt-authority regression.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

const PAYLOAD_BYTES: usize = 1024 * 1024 + 4096;

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-receipt-authority".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

struct MountedReceiptAuthority {
    root: Option<tempfile::TempDir>,
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    raw_replacement_trigger: Arc<AtomicBool>,
}

impl MountedReceiptAuthority {
    fn new() -> Self {
        let fuse = fs::metadata("/dev/fuse")
            .expect("/dev/fuse is mandatory evidence for this integration test");
        assert!(
            fuse.file_type().is_char_device(),
            "/dev/fuse must be a character device"
        );

        let root = tempfile::Builder::new()
            .prefix("tidefs-receipt-authority-mount-")
            .tempdir()
            .expect("create receipt-authority test root");
        let store = root.path().join("store");
        let mountpoint = root.path().join("mnt");
        fs::create_dir_all(&store).expect("create receipt-authority store");
        fs::create_dir_all(&mountpoint).expect("create receipt-authority mountpoint");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open receipt-authority filesystem");
        let raw_replacement_trigger = Arc::new(AtomicBool::new(false));
        let engine = VfsLocalFileSystem::new(filesystem)
            .with_receipt_authority_raw_replacement_before_next_read_for_test(Arc::clone(
                &raw_replacement_trigger,
            ));
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mountpoint, &mount_options())
            .expect("mount receipt-authority FUSE filesystem");

        Self {
            root: Some(root),
            mountpoint,
            session: Some(session),
            raw_replacement_trigger,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mountpoint.join(relative.trim_start_matches('/'))
    }

    fn arm_raw_replacement_before_next_read(&self) {
        self.raw_replacement_trigger
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .expect("raw-replacement trigger must be idle before arming");
    }

    fn raw_replacement_was_consumed(&self) -> bool {
        !self.raw_replacement_trigger.load(Ordering::Acquire)
    }

    fn join_session(&mut self) {
        if let Some(session) = self.session.take() {
            session.join();
        }
    }

    fn is_mounted(&self) -> bool {
        let mountpoint = self.mountpoint.to_string_lossy();
        fs::read_to_string("/proc/self/mountinfo")
            .expect("read mountinfo")
            .lines()
            .any(|line| line.split_whitespace().nth(4) == Some(mountpoint.as_ref()))
    }

    fn finish(mut self) {
        self.join_session();
        assert!(
            !self.is_mounted(),
            "receipt-authority FUSE mount must disappear after joining the session"
        );
        self.root
            .take()
            .expect("receipt-authority test root must exist")
            .close()
            .expect("remove receipt-authority test root");
    }
}

impl Drop for MountedReceiptAuthority {
    fn drop(&mut self) {
        self.join_session();
        if let Some(root) = self.root.take() {
            if let Err(error) = root.close() {
                eprintln!("failed to remove receipt-authority test root: {error}");
            }
        }
    }
}

fn create_writer(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create mounted receipt-authority file")
}

#[test]
fn same_open_fd_rejects_unauthorized_raw_chunk_replacement() {
    let mounted = MountedReceiptAuthority::new();
    let path = mounted.path("receipt-bound.bin");
    let payload = vec![0x5a; PAYLOAD_BYTES];
    let mut writer = create_writer(&path);

    writer
        .write_all(&payload)
        .expect("write chunked file through mounted FUSE");
    writer.sync_all().expect("fsync mounted chunked file");
    drop(writer);

    let mut reader = File::open(&path).expect("open mounted receipt-authority file for reading");
    let mut first = vec![0; payload.len()];
    reader
        .read_exact(&mut first)
        .expect("first mounted read through receipt authority");
    assert_eq!(first, payload);

    mounted.arm_raw_replacement_before_next_read();
    reader
        .seek(SeekFrom::Start(0))
        .expect("seek same descriptor before corrupt read");
    let mut second = vec![0; payload.len()];
    let error = reader
        .read_exact(&mut second)
        .expect_err("unauthorized raw replacement must fail the same open descriptor");

    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert!(
        mounted.raw_replacement_was_consumed(),
        "the second read must reach the live VFS engine instead of kernel-cached bytes"
    );
    drop(reader);
    mounted.finish();
}
