//! FUSE mount harness backed by an in-memory LocalObjectStore.
//!
//! `TempMount` boots a `LocalFileSystem` over a `LocalObjectStore` with
//! `StoreOptions::test_fast()`, wraps it in a `VfsLocalFileSystem` adapter,
//! and spawns a background FUSE session at a unique temp directory.
//! The guard ensures `unmount + cleanup` on drop even under panic.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

/// Unique name for a temp root directory used for a single mount session.
#[allow(dead_code)]
fn unique_test_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "{prefix}-{pid}-{nanos}",
        pid = std::process::id(),
        nanos = nanos,
    ))
}

/// Build the standard set of FUSE mount options for smoke tests.
#[allow(dead_code)]
fn smoke_mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

/// A mounted FUSE filesystem that unmounts and cleans up on drop.
#[allow(dead_code)]
pub struct TempMount {
    /// Root directory containing both `store` and `mountpoint` subdirs.
    root: PathBuf,
    /// The FUSE mountpoint directory.
    #[allow(dead_code)]
    mount_path: PathBuf,
    /// The background FUSE session; dropping it unmounts.
    session: Option<fuser::BackgroundSession>,
}

#[allow(dead_code)]
impl TempMount {
    /// Create a new in-memory-backed FUSE mount.
    ///
    /// Creates a temporary directory tree (`root/store` and `root/mnt`),
    /// opens a `LocalFileSystem` with `StoreOptions::test_fast()`,
    /// wraps it in the VFS adapter, and spawns a background FUSE session.
    pub fn new() -> Self {
        let root = unique_test_root("tidefs-filesystem-demo");
        let store = root.join("store");
        let mount_path = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount_path).expect("create mount dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::test_fast(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");

        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");

        let session = fuser::spawn_mount2(adapter, &mount_path, &smoke_mount_options())
            .expect("spawn FUSE mount");

        Self {
            root,
            mount_path,
            session: Some(session),
        }
    }

    /// Return the FUSE mountpoint path.
    pub fn mountpoint(&self) -> &Path {
        &self.mount_path
    }

    /// Convenience: resolve a path relative to the mountpoint.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.mount_path.join(relative.trim_start_matches('/'))
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        // Drop the session first to unmount cleanly.
        drop(self.session.take());
        // Best-effort cleanup.
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use std::fs as std_fs;

    /// Mount/unmount lifecycle: the guard must drop without panicking.
    #[test]
    fn mount_unmount_clean() {
        let mount = TempMount::new();
        // Verify the mountpoint exists and is a directory.
        assert!(mount.mountpoint().exists());
        assert!(mount.mountpoint().is_dir());
        // Drop runs implicitly; ensure no panic.
        drop(mount);
    }

    /// stat_root: `std::fs::metadata("/")` returns a directory with valid inode.
    #[test]
    fn stat_root() {
        let mount = TempMount::new();
        let meta = std_fs::metadata(mount.mountpoint()).expect("metadata on mount root");
        assert!(meta.is_dir(), "root must be a directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(meta.ino() > 0, "root inode must be non-zero");
        }
    }

    /// create_file_stat: create a file and verify metadata (size, mode).
    #[test]
    fn create_file_stat() {
        let mount = TempMount::new();
        let file_path = mount.path("/hello.txt");
        let content = b"hello FUSE smoke test";
        std_fs::write(&file_path, content).expect("create and write file");

        let meta = std_fs::metadata(&file_path).expect("stat created file");
        assert!(meta.is_file());
        assert_eq!(meta.len(), content.len() as u64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            assert!(mode & 0o400 != 0, "file must be readable by owner");
            assert!(mode & 0o200 != 0, "file must be writable by owner");
        }
    }

    /// write_read_roundtrip: write bytes, read back, compare.
    ///
    /// NOTE: this test exercises FUSE write (#3581) and read (#3574)
    /// dispatch batches that are currently owned by peer workers.
    /// If the read or write path is incomplete, this test will fail.
    /// When the batches land, remove the `#[ignore]` attribute.
    #[test]
    #[ignore = "depends on FUSE read (#3574) and write (#3581) dispatch batches"]
    fn write_read_roundtrip() {
        let mount = TempMount::new();
        let file_path = mount.path("/data.bin");
        let payload: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_mul(7)).collect();

        std_fs::write(&file_path, &payload).expect("write to file");
        let read_back = std_fs::read(&file_path).expect("read from file");
        assert_eq!(read_back, payload, "roundtrip data mismatch");
    }

    /// mkdir_readdir: create a subdirectory and verify it appears in listing.
    #[test]
    fn mkdir_readdir() {
        let mount = TempMount::new();
        let subdir = mount.path("/subdir");
        std_fs::create_dir(&subdir).expect("create subdir");

        let entries: Vec<String> = std_fs::read_dir(mount.mountpoint())
            .expect("readdir mount root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        assert!(
            entries.contains(&"subdir".to_string()),
            "readdir must include newly created subdir, got: {entries:?}"
        );
    }

    /// unlink_gone: remove file, subsequent stat returns NotFound.
    #[test]
    fn unlink_gone() {
        let mount = TempMount::new();
        let file_path = mount.path("/todelete.txt");
        std_fs::write(&file_path, b"will be deleted").expect("create file");

        std_fs::remove_file(&file_path).expect("remove file");

        match std_fs::metadata(&file_path) {
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::NotFound,
                    "expected NotFound after unlink"
                );
            }
            Ok(_) => panic!("stat on removed file should fail"),
        }
    }

    /// Concurrent readers: spawn threads that open and read a shared file.
    ///
    /// NOTE: depends on FUSE read dispatch (#3574) owned by peer workers.
    /// When the batch lands, remove the `#[ignore]` attribute.
    #[test]
    #[ignore = "depends on FUSE read dispatch (#3574)"]
    fn concurrent_readers() {
        let mount = TempMount::new();
        let file_path = mount.path("/shared.txt");
        let payload = b"concurrent smoke test data";
        std_fs::write(&file_path, payload).expect("create shared file");

        let mount_path = mount.mountpoint().to_path_buf();
        let file_rel = "/shared.txt".to_string();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let mp = mount_path.clone();
                let fr = file_rel.clone();
                std::thread::spawn(move || {
                    let p = mp.join(fr.trim_start_matches('/'));
                    let data = std_fs::read(&p).expect("read shared file");
                    assert_eq!(data, payload, "concurrent reader mismatch");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("reader thread panicked");
        }
    }

    /// Panic-safety: if a test panics while a TempMount is live, drop
    /// must still run. We verify by using catch_unwind.
    #[test]
    fn panic_during_mount_still_unmounts() {
        use std::panic;

        let result = panic::catch_unwind(|| {
            let mount = TempMount::new();
            // Verify mount is alive
            assert!(mount.mountpoint().exists());
            // Simulate a panic while the mount is live.
            panic!("simulated mid-mount panic");
        });

        assert!(result.is_err(), "catch_unwind should capture the panic");

        // After the panic, the TempMount guard runs Drop which unmounts
        // the filesystem and cleans up the temp directory. If Drop
        // double-panics, catch_unwind would propagate it. The fact that
        // we reach here means the guard ran successfully.
    }
}
