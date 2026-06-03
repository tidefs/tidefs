//! Mounted FUSE integration tests for release-side file and directory handle lifecycle.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_test_guard() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-flush-release-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-flush-release-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

struct MountedVfs {
    root: PathBuf,
    store: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new() -> Self {
        let root = unique_test_root();
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let mut mounted = Self {
            root,
            store,
            mount,
            session: None,
        };
        mounted.mount();
        mounted
    }

    fn mount(&mut self) {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &self.store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session =
            fuser::spawn_mount2(adapter, &self.mount, &mount_options()).expect("mount FUSE");
        self.session = Some(session);
    }

    fn unmount(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
            // Give FUSE a moment to tear down
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn remount(&mut self) {
        self.unmount();
        self.mount();
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

fn close_fd(fd: RawFd) -> io::Result<()> {
    let result = unsafe { libc::close(fd) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn duplicate_fd(fd: RawFd) -> io::Result<File> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(duplicate) })
    }
}

fn read_file(path: &std::path::Path) -> Vec<u8> {
    fs::read(path).expect("read mounted VFS file")
}

#[test]
fn flush_release_close_reopen_preserves_written_bytes() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/close-reopen.txt");
    let payload = b"bytes written before release";

    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create mounted VFS file");
        file.write_all(payload)
            .expect("write mounted VFS payload before close");
    }

    assert_eq!(read_file(&path), payload);
}

#[test]
fn flush_release_duplicate_fd_stays_live_until_last_close() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/duplicated-fd.txt");
    let payload = b"duplicate descriptor keeps the open file live";

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create mounted VFS file");
    file.write_all(payload).expect("write mounted VFS payload");
    file.seek(SeekFrom::Start(0)).expect("seek original handle");

    let mut duplicate = duplicate_fd(file.as_raw_fd()).expect("duplicate mounted VFS fd");
    drop(file);

    let mut readback = Vec::new();
    duplicate
        .read_to_end(&mut readback)
        .expect("read through duplicated fd after original close");
    assert_eq!(readback, payload);
    drop(duplicate);

    assert_eq!(read_file(&path), payload);
}

#[test]
fn flush_release_unlinked_open_file_survives_until_close() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/unlink-open.txt");
    let payload = b"open file remains readable after unlink";

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create mounted VFS file");
    file.write_all(payload)
        .expect("write mounted VFS payload before unlink");
    file.seek(SeekFrom::Start(0))
        .expect("seek before unlink read");

    fs::remove_file(&path).expect("unlink open mounted VFS file");
    assert!(
        !path.exists(),
        "path should disappear immediately after unlink"
    );

    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read unlinked file through still-open handle");
    assert_eq!(readback, payload);

    let fd = file.into_raw_fd();
    close_fd(fd).expect("close unlinked mounted VFS file");
    assert!(
        !path.exists(),
        "path should stay absent after final release"
    );
}

#[test]
fn flush_release_closedir_after_empty_iteration_allows_rmdir() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let dir = mnt.path("/iterated-dir");

    fs::create_dir(&dir).expect("create mounted VFS directory");
    let mut entries = fs::read_dir(&dir).expect("open and read mounted VFS directory");
    assert!(
        entries.next().is_none(),
        "newly-created directory should have no visible children"
    );
    drop(entries);

    fs::remove_dir(&dir).expect("rmdir after releasedir");
    assert!(
        !dir.exists(),
        "directory should be removed after releasedir"
    );
}

#[test]
fn flush_release_remount_persistence_write_close_reopen_preserves_data() {
    let _guard = serial_test_guard();
    let mut mnt = MountedVfs::new();
    let path = mnt.path("/remount-persist.txt");
    let payload = b"write close unmount remount read";

    // Write payload and close the file. close() triggers flush+release
    // through the FUSE adapter, which must persist dirty data to the
    // underlying block-volume store.
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create mounted VFS file");
        file.write_all(payload).expect("write mounted VFS payload");
        // file drops here → close() → FUSE flush → FUSE release
    }

    // Unmount and remount the same store. If flush+release correctly
    // persisted dirty data, the payload must survive the remount cycle.
    mnt.remount();

    let readback = fs::read(&path).expect("read mounted VFS file after remount");
    assert_eq!(readback, payload);
}

#[test]
fn flush_release_open_close_clean_file_returns_no_error() {
    // Open and immediately close a never-written file.  The close()
    // triggers FUSE flush + release on a clean inode; the dirty-state
    // short-circuit in dispatch_flush must return success without
    // initiating engine writeback.
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/clean-open-close.txt");

    {
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create mounted VFS file");
        // file drops here -> close() -> FUSE flush (clean short-circuit)
        //                     -> FUSE release
    }

    // Reopen and verify the file is empty (no spurious data from flush).
    let readback = fs::read(&path).expect("read clean file after close");
    assert!(readback.is_empty(), "clean file must be empty after close");
}
