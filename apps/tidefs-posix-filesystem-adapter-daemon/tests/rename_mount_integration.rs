#![cfg(target_os = "linux")]

//! Mounted FUSE integration tests for FUSE rename dispatch covering plain
//! rename, RENAME_NOREPLACE, RENAME_EXCHANGE, persistence round-trips,
//! link-count correctness, and open-file-handle survival through the VFS
//! adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> MutexGuard<'static, ()> {
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
        "tidefs-rename-mount-integration-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-rename-mount-int".to_string()),
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
    fn new() -> Self {
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

fn renameat2(old_path: &Path, new_path: &Path, flags: u32) -> io::Result<()> {
    let old_c = CString::new(old_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "old path contains nul byte"))?;
    let new_c = CString::new(new_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "new path contains nul byte"))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            old_c.as_ptr(),
            libc::AT_FDCWD,
            new_c.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn rename(old_path: &Path, new_path: &Path) -> io::Result<()> {
    renameat2(old_path, new_path, 0)
}

fn rename_noreplace(old_path: &Path, new_path: &Path) -> io::Result<()> {
    renameat2(old_path, new_path, RENAME_NOREPLACE)
}

fn rename_exchange(old_path: &Path, new_path: &Path) -> io::Result<()> {
    renameat2(old_path, new_path, RENAME_EXCHANGE)
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

// ── plain rename ───────────────────────────────────────────────────

#[test]
fn rename_plain_same_directory_moves_file() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let old = mnt.path("/source.txt");
    let new = mnt.path("/renamed.txt");
    fs::write(&old, b"source contents").expect("write source file");
    let before = fs::metadata(&old).expect("source metadata");

    rename(&old, &new).expect("plain rename same-directory through FUSE mount");

    let after = fs::metadata(&new).expect("dest metadata after rename");
    assert_eq!(after.ino(), before.ino(), "inode preserved after rename");
    assert_eq!(
        fs::read(&new).expect("read renamed file"),
        b"source contents"
    );
    assert!(fs::metadata(&old).is_err(), "old path must be gone");
}

#[test]
fn rename_plain_cross_directory_moves_file() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/src")).expect("create src dir");
    fs::create_dir(mnt.path("/dst")).expect("create dst dir");
    fs::write(mnt.path("/src/file.txt"), b"cross-dir data").expect("write file");
    let before = fs::metadata(mnt.path("/src/file.txt")).expect("source metadata");

    rename(&mnt.path("/src/file.txt"), &mnt.path("/dst/moved.txt"))
        .expect("cross-directory rename");

    let after = fs::metadata(mnt.path("/dst/moved.txt")).expect("dest metadata");
    assert_eq!(
        after.ino(),
        before.ino(),
        "inode preserved after cross-dir rename"
    );
    assert_eq!(
        fs::read(mnt.path("/dst/moved.txt")).expect("read moved file"),
        b"cross-dir data"
    );
    assert!(
        fs::metadata(mnt.path("/src/file.txt")).is_err(),
        "old path must be gone"
    );
}

#[test]
fn rename_plain_overwrites_existing_file() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/alpha.txt"), b"alpha").expect("write alpha");
    fs::write(mnt.path("/beta.txt"), b"beta").expect("write beta");
    let alpha_before = fs::metadata(mnt.path("/alpha.txt")).expect("alpha metadata");

    rename(&mnt.path("/alpha.txt"), &mnt.path("/beta.txt")).expect("rename overwrite");

    assert!(
        fs::metadata(mnt.path("/alpha.txt")).is_err(),
        "alpha must be gone"
    );
    let beta = fs::metadata(mnt.path("/beta.txt")).expect("beta metadata after overwrite");
    assert_eq!(beta.ino(), alpha_before.ino(), "inode swapped on overwrite");
    assert_eq!(
        fs::read(mnt.path("/beta.txt")).expect("read overwritten"),
        b"alpha"
    );
}

#[test]
fn rename_plain_nonexistent_source_returns_enoent() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let err = rename(&mnt.path("/missing"), &mnt.path("/dest"))
        .expect_err("non-existent source should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_plain_into_nonexistent_parent_returns_enoent() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/exists.txt"), b"data").expect("write file");
    let err = rename(&mnt.path("/exists.txt"), &mnt.path("/no-dir/target"))
        .expect_err("missing destination parent should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

// ── RENAME_NOREPLACE ───────────────────────────────────────────────

#[test]
fn rename_noreplace_moves_when_target_absent() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/src.txt"), b"source").expect("write source");
    let before = fs::metadata(mnt.path("/src.txt")).expect("source metadata");

    rename_noreplace(&mnt.path("/src.txt"), &mnt.path("/dst.txt"))
        .expect("noreplace rename to absent target");

    assert!(fs::metadata(mnt.path("/src.txt")).is_err());
    let after = fs::metadata(mnt.path("/dst.txt")).expect("dst metadata");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::read(mnt.path("/dst.txt")).expect("read dst"), b"source");
}

#[test]
fn rename_noreplace_rejects_existing_target() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/src.txt"), b"source").expect("write source");
    fs::write(mnt.path("/dst.txt"), b"target").expect("write target");

    let err = rename_noreplace(&mnt.path("/src.txt"), &mnt.path("/dst.txt"))
        .expect_err("noreplace must reject existing target");
    assert_raw_errno(&err, libc::EEXIST);

    // Both files preserved.
    assert!(fs::metadata(mnt.path("/src.txt")).is_ok());
    assert!(fs::metadata(mnt.path("/dst.txt")).is_ok());
    assert_eq!(fs::read(mnt.path("/src.txt")).unwrap(), b"source");
    assert_eq!(fs::read(mnt.path("/dst.txt")).unwrap(), b"target");
}

// ── RENAME_EXCHANGE ────────────────────────────────────────────────

#[test]
fn rename_exchange_swaps_file_entries() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/left.txt"), b"left contents").expect("write left");
    fs::write(mnt.path("/right.txt"), b"right contents").expect("write right");
    let left_before = fs::metadata(mnt.path("/left.txt")).expect("left metadata");
    let right_before = fs::metadata(mnt.path("/right.txt")).expect("right metadata");

    rename_exchange(&mnt.path("/left.txt"), &mnt.path("/right.txt"))
        .expect("rename exchange files");

    let left_after = fs::metadata(mnt.path("/left.txt")).expect("left after exchange");
    let right_after = fs::metadata(mnt.path("/right.txt")).expect("right after exchange");
    assert_eq!(left_after.ino(), right_before.ino());
    assert_eq!(right_after.ino(), left_before.ino());
    assert_eq!(fs::read(mnt.path("/left.txt")).unwrap(), b"right contents");
    assert_eq!(fs::read(mnt.path("/right.txt")).unwrap(), b"left contents");
}

#[test]
fn rename_exchange_missing_target_returns_enoent() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/present.txt"), b"data").expect("write file");

    let err = rename_exchange(&mnt.path("/present.txt"), &mnt.path("/missing.txt"))
        .expect_err("exchange with missing target should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_exchange_same_name_is_noop() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let same = mnt.path("/same.txt");
    fs::write(&same, b"same contents").expect("write file");
    let before = fs::metadata(&same).expect("metadata");

    rename_exchange(&same, &same).expect("same-name exchange should be no-op");

    let after = fs::metadata(&same).expect("metadata after no-op exchange");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::read(&same).unwrap(), b"same contents");
}

#[test]
fn rename_exchange_combined_with_noreplace_returns_einval() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/left.txt"), b"left").expect("write left");
    fs::write(mnt.path("/right.txt"), b"right").expect("write right");

    let err = renameat2(
        &mnt.path("/left.txt"),
        &mnt.path("/right.txt"),
        RENAME_EXCHANGE | RENAME_NOREPLACE,
    )
    .expect_err("combined flags should fail");
    assert_raw_errno(&err, libc::EINVAL);
}

// ── directory rename ───────────────────────────────────────────────

#[test]
fn rename_empty_dir_over_empty_dir_replaces_target() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/src")).expect("create src dir");
    fs::create_dir(mnt.path("/dst")).expect("create dst dir");
    let src_before = fs::metadata(mnt.path("/src")).expect("src metadata");

    rename(&mnt.path("/src"), &mnt.path("/dst")).expect("rename empty dir over empty dir");

    assert!(
        fs::metadata(mnt.path("/src")).is_err(),
        "src dir must be gone"
    );
    let dst_after = fs::metadata(mnt.path("/dst")).expect("dst metadata after rename");
    assert_eq!(dst_after.ino(), src_before.ino());
}

#[test]
fn rename_dir_over_nonempty_dir_returns_enotempty() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/src")).expect("create src dir");
    fs::create_dir(mnt.path("/dst")).expect("create dst dir");
    fs::write(mnt.path("/dst/child.txt"), b"child").expect("create child in dst");

    let err = rename(&mnt.path("/src"), &mnt.path("/dst"))
        .expect_err("rename over non-empty dir should fail");
    assert_raw_errno(&err, libc::ENOTEMPTY);

    // Both directories preserved.
    assert!(fs::metadata(mnt.path("/src")).is_ok());
    assert!(fs::metadata(mnt.path("/dst")).is_ok());
    assert!(fs::metadata(mnt.path("/dst/child.txt")).is_ok());
}

#[test]
fn rename_dir_into_descendant_is_rejected() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/parent")).expect("create parent");
    fs::create_dir(mnt.path("/parent/child")).expect("create child");

    let err = rename(&mnt.path("/parent"), &mnt.path("/parent/child/moved"))
        .expect_err("rename into descendant should fail");
    assert_raw_errno(&err, libc::EINVAL);
}

#[test]
fn rename_file_over_dir_returns_eisdir() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/file.txt"), b"file").expect("write file");
    fs::create_dir(mnt.path("/dir")).expect("create dir");

    let err = rename(&mnt.path("/file.txt"), &mnt.path("/dir"))
        .expect_err("rename file over dir should fail");
    assert_raw_errno(&err, libc::EISDIR);
}

#[test]
fn rename_dir_over_file_returns_enotdir() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/dir")).expect("create dir");
    fs::write(mnt.path("/file.txt"), b"file").expect("write file");

    let err = rename(&mnt.path("/dir"), &mnt.path("/file.txt"))
        .expect_err("rename dir over file should fail");
    assert_raw_errno(&err, libc::ENOTDIR);
}

// ── link count ─────────────────────────────────────────────────────

#[test]
fn rename_preserves_link_count_after_plain_rename() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/src.txt"), b"data").expect("write file");
    let before = fs::metadata(mnt.path("/src.txt")).expect("src metadata");
    let nlink_before = before.nlink();

    rename(&mnt.path("/src.txt"), &mnt.path("/dst.txt")).expect("plain rename");

    let after = fs::metadata(mnt.path("/dst.txt")).expect("dst metadata");
    assert_eq!(
        after.nlink(),
        nlink_before,
        "link count preserved after rename"
    );
}

#[test]
fn rename_preserves_link_count_after_exchange() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::write(mnt.path("/left.txt"), b"left").expect("write left");
    fs::write(mnt.path("/right.txt"), b"right").expect("write right");
    let left_nlink = fs::metadata(mnt.path("/left.txt")).unwrap().nlink();
    let right_nlink = fs::metadata(mnt.path("/right.txt")).unwrap().nlink();

    rename_exchange(&mnt.path("/left.txt"), &mnt.path("/right.txt")).expect("rename exchange");

    let left_after = fs::metadata(mnt.path("/left.txt")).unwrap();
    let right_after = fs::metadata(mnt.path("/right.txt")).unwrap();
    assert_eq!(left_after.nlink(), right_nlink, "left gets right's nlink");
    assert_eq!(right_after.nlink(), left_nlink, "right gets left's nlink");
}

// ── persistence round-trip ─────────────────────────────────────────

#[test]
fn rename_persistence_round_trip_survives_remount() {
    let _guard = test_lock();

    // Phase 1: mount, create entries, rename, unmount.
    let (store_path, mount_path, entries) = {
        let mut mnt = MountedVfs::new();
        fs::write(mnt.path("/a.txt"), b"content a").expect("write a");
        fs::write(mnt.path("/b.txt"), b"content b").expect("write b");

        rename(&mnt.path("/a.txt"), &mnt.path("/c.txt")).expect("rename a -> c through mount");

        let c_ino = fs::metadata(mnt.path("/c.txt")).unwrap().ino();
        let b_ino = fs::metadata(mnt.path("/b.txt")).unwrap().ino();
        let entries = vec![
            ("/b.txt".to_string(), b"content b".to_vec(), b_ino),
            ("/c.txt".to_string(), b"content a".to_vec(), c_ino),
        ];
        // Copy the store to a persistent temp location before cleanup.
        let saved_store = unique_test_root().join("saved-store");
        fs::create_dir_all(&saved_store).expect("create saved store dir");
        copy_dir_all(mnt.root.join("store"), &saved_store)
            .expect("copy store for persistence test");
        let mp = mnt.mount.clone();
        // Drop MountedVfs (cleans up original root).
        drop(mnt.session.take());
        (saved_store, mp, entries)
    };

    // Phase 2: reopen saved store, verify entries survived.
    {
        fs::create_dir_all(&mount_path).expect("recreate mount dir");
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store_path,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter");
        let _session =
            fuser::spawn_mount2(adapter, &mount_path, &mount_options()).expect("remount FUSE");

        for (rel_path, expected_data, expected_ino) in &entries {
            let full = mount_path.join(rel_path.trim_start_matches('/'));
            let meta = fs::metadata(&full)
                .unwrap_or_else(|e| panic!("{rel_path} must survive remount: {e}"));
            assert_eq!(
                meta.ino(),
                *expected_ino,
                "inode preserved for {rel_path} after remount"
            );
            let data =
                fs::read(&full).unwrap_or_else(|e| panic!("read {rel_path} after remount: {e}"));
            assert_eq!(&data, expected_data, "content preserved for {rel_path}");
        }

        // Cleanup.
        let _ = fs::remove_dir_all(store_path.parent().unwrap());
    }
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

// ── open file handle survives rename ───────────────────────────────

#[test]
fn rename_open_file_handle_survives_rename() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let old_path = mnt.path("/before_rename.txt");
    let new_path = mnt.path("/after_rename.txt");

    fs::write(&old_path, b"initial content").expect("write file");

    // Open the file before renaming.
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_RDWR)
        .open(&old_path)
        .expect("open file before rename");

    // Rename while the handle is open.
    rename(&old_path, &new_path).expect("rename with open handle");

    // Verify old path is gone, new path exists.
    assert!(fs::metadata(&old_path).is_err());
    assert!(fs::metadata(&new_path).is_ok());

    // Write through the open handle — seek to end first.
    use std::io::{Read, Seek, SeekFrom, Write};
    file.seek(SeekFrom::End(0)).expect("seek to end");
    file.write_all(b" appended after rename")
        .expect("write after rename");

    // Read back entire content through the handle.
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("read through open handle");
    assert_eq!(
        String::from_utf8_lossy(&buf),
        "initial content appended after rename"
    );
}

#[test]
fn rename_open_file_handle_reads_correctly_after_rename() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let old_path = mnt.path("/before.txt");
    let new_path = mnt.path("/after.txt");

    fs::write(&old_path, b"persistent data").expect("write file");

    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_RDWR)
        .open(&old_path)
        .expect("open file");

    rename(&old_path, &new_path).expect("rename");

    // Seek to start and read.
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read after rename");
    assert_eq!(buf, b"persistent data");
}
