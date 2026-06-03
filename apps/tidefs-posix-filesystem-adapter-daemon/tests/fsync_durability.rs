//! Clean-unmount fsync/fdatasync durability integration tests.
//!
//! Each test follows: mount FUSE → write → fsync/fdatasync → clean unmount →
//! remount → verify byte-for-byte persistence.
//!
//! Coverage gaps filled here (the remaining fsync-durability scenarios
//! already live in fuse_sync_smoke.rs):
//!   - Multi-file fsync isolation
//!   - Append-and-fsync across remount
//!   - Large-write fsync (1 MiB)
//!   - Concurrent fsync stress (4 threads)
//!   - fsync after rename
//!
//! Tests skip gracefully when /dev/fuse is unavailable.

mod fuse_mount_harness;

use fuse_mount_harness::{create_read_write, patterned_bytes, read_all, MountedVfs};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

macro_rules! require_fuse {
    () => {
        if !fuse_mount_harness::fuse_available() {
            eprintln!(
                "SKIP: /dev/fuse not available — integration test requires FUSE kernel module"
            );
            return;
        }
    };
}

/// Write payload, close handle, then fsync on a separate read-only handle.
fn write_close_fsync(path: &Path, payload: &[u8]) {
    {
        let mut file = create_read_write(path);
        file.write_all(payload).expect("write payload");
    }
    File::open(path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync on separate handle");
}

/// Write payload, close handle, then fdatasync on a separate read-only handle.
fn write_close_fdatasync(path: &Path, payload: &[u8]) {
    {
        let mut file = create_read_write(path);
        file.write_all(payload).expect("write payload");
    }
    File::open(path)
        .expect("reopen for fdatasync")
        .sync_data()
        .expect("fdatasync on separate handle");
}

/// Generate a distinct deterministic payload for a given file index.
fn distinct_payload(file_index: usize, len: usize) -> Vec<u8> {
    let base = (file_index as u8).wrapping_mul(37).wrapping_add(13);
    (0..len).map(|i| base.wrapping_add(i as u8)).collect()
}

// ===========================================================================
// Multi-file fsync isolation
// ===========================================================================

/// Write distinct data to 8 files, fsync each individually, remount, and
/// verify all 8 files retain their correct payloads byte-for-byte.
#[test]
fn multi_file_fsync_isolation_eight_files_survive_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("multi-fsync", &[], &[]);
    let filenames: Vec<String> = (1..=8).map(|i| format!("file_{i}.bin")).collect();
    let payloads: Vec<Vec<u8>> = (0..8).map(|idx| distinct_payload(idx, 4096)).collect();

    // Write and fsync each file individually (creates files on first write).
    for (idx, fname) in filenames.iter().enumerate() {
        let path = mnt.path(&format!("/{fname}"));
        write_close_fsync(&path, &payloads[idx]);
    }

    mnt.remount();

    // Verify every file survived remount byte-for-byte.
    for (idx, fname) in filenames.iter().enumerate() {
        let path = mnt.path(&format!("/{fname}"));
        let readback = read_all(&path);
        assert_eq!(
            readback, payloads[idx],
            "file {fname} must survive remount byte-for-byte"
        );
        let meta = fs::metadata(&path).expect("stat");
        assert_eq!(
            meta.len(),
            4096,
            "file {fname} must have correct size after remount"
        );
    }
}

/// fsync only one of multiple dirty files; remount and verify the
/// fsync'd file survived. Non-fsyncd file behavior is documented but
/// not strictly asserted (it may or may not persist depending on
/// writeback implementation during clean unmount).
#[test]
fn selective_multi_file_only_fsyncd_file_persists() {
    require_fuse!();

    let mut mnt = MountedVfs::new("select-fsync", &[], &[]);
    let keep_path = mnt.path("/keep.bin");
    let lose_path = mnt.path("/lose.bin");
    let keep_payload = &distinct_payload(0, 2048);
    let _lose_payload = &distinct_payload(1, 2048);

    // Write both files, but only fsync one.
    write_close_fsync(&keep_path, keep_payload);
    {
        let mut file = create_read_write(&lose_path);
        file.write_all(_lose_payload).expect("write lose.bin");
        // Intentional: no fsync for lose.bin — it may or may not persist
        // after clean unmount depending on writeback implementation.
    }

    mnt.remount();

    // The fsync'd file must be intact.
    assert_eq!(
        read_all(&keep_path),
        keep_payload.as_slice(),
        "fsync'd file must survive clean remount"
    );

    // The non-fsync'd file behavior is documented but not strictly asserted.
    let _ = File::open(&lose_path);
}

// ===========================================================================
// Append-and-fsync across remount
// ===========================================================================

/// Write base content, fsync, append more data, fsync again, remount, and
/// verify the concatenated content survives byte-for-byte.
#[test]
fn append_and_fsync_survives_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("append-fsync", &[], &[]);
    let path = mnt.path("/append.bin");
    let base = b"FIRST BLOCK: 512 bytes of initial data that was written and then fsync'd before append.\n";
    let append = b"SECOND BLOCK: 512 bytes appended after re-opening and seeking to end and then fsync'd again.\n";

    // Phase 1: write base, fsync.
    write_close_fsync(&path, base);

    // Phase 2: reopen, seek to end, append, fsync.
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("reopen for append");
        file.seek(SeekFrom::End(0)).expect("seek to end");
        file.write_all(append).expect("append payload");
        file.sync_all().expect("fsync after append");
    }

    mnt.remount();

    let expected: Vec<u8> = base.iter().chain(append.iter()).copied().collect();
    let readback = read_all(&mnt.path("/append.bin"));
    assert_eq!(readback, expected, "appended content must survive remount");

    let meta = fs::metadata(mnt.path("/append.bin")).expect("stat");
    assert_eq!(
        meta.len(),
        expected.len() as u64,
        "size must reflect base + append"
    );
}

// ===========================================================================
// Large-write fsync (1 MiB)
// ===========================================================================

/// Write 1 MiB of deterministic patterned data through FUSE, fsync, remount,
/// and verify full content byte-for-byte.  Exercises the multi-block flush
/// path.
#[test]
fn large_write_1mib_fsync_survives_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("large-fsync", &[], &[]);
    let path = mnt.path("/large.bin");
    let payload = patterned_bytes(1024 * 1024); // 1 MiB

    // Write and fsync.
    {
        let mut file = create_read_write(&path);
        file.write_all(&payload).expect("write 1 MiB");
        file.flush().expect("flush");
    }
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync 1 MiB file");

    mnt.remount();

    let remounted_path = mnt.path("/large.bin");
    let meta = fs::metadata(&remounted_path).expect("stat after remount");
    assert_eq!(meta.len(), 1024 * 1024, "1 MiB size must survive remount");

    let readback = read_all(&remounted_path);
    assert_eq!(
        readback, payload,
        "1 MiB data must survive remount byte-for-byte"
    );
}

/// Write 1 MiB through FUSE, fdatasync, remount, and verify content.
#[test]
fn large_write_1mib_fdatasync_survives_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("large-fdatasync", &[], &[]);
    let path = mnt.path("/large2.bin");
    let payload = patterned_bytes(1024 * 1024);

    write_close_fdatasync(&path, &payload);

    mnt.remount();

    let remounted_path = mnt.path("/large2.bin");
    let meta = fs::metadata(&remounted_path).expect("stat after remount");
    assert_eq!(
        meta.len(),
        1024 * 1024,
        "1 MiB size must survive fdatasync remount"
    );

    let readback = read_all(&remounted_path);
    assert_eq!(
        readback, payload,
        "1 MiB data must survive fdatasync remount byte-for-byte"
    );
}

// ===========================================================================
// Concurrent fsync stress
// ===========================================================================

/// Spawn 4 threads, each creating its own file, writing distinct data,
/// fsyncing, and reporting success.  Remount and verify all 4 files.
#[test]
fn concurrent_fsync_four_threads_survive_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("concur-fsync", &[], &[]);
    let mount_dir = mnt.mount.clone();
    let num_threads = 4;

    let handles: Vec<thread::JoinHandle<io::Result<()>>> = (0..num_threads)
        .map(|tidx| {
            let mnt_dir = mount_dir.clone();
            thread::spawn(move || {
                let fname = format!("concur_{tidx}.bin");
                let path = mnt_dir.join(&fname);
                let payload = distinct_payload(tidx, 8192);

                {
                    let mut file = File::create(&path).expect("create concurrent file");
                    file.write_all(&payload).expect("write concurrent payload");
                }
                File::open(&path)
                    .expect("reopen concurrent file for fsync")
                    .sync_all()
                    .expect("fsync concurrent file");
                Ok(())
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .expect("thread panicked")
            .expect("thread I/O error");
    }

    mnt.remount();

    for tidx in 0..num_threads {
        let path = mnt.path(&format!("/concur_{tidx}.bin"));
        let expected = distinct_payload(tidx, 8192);
        let readback = read_all(&path);
        assert_eq!(
            readback, expected,
            "concurrent file {tidx} must survive remount byte-for-byte"
        );
        let meta = fs::metadata(&path).expect("stat concurrent file");
        assert_eq!(meta.len(), 8192, "concurrent file {tidx} size must match");
    }
}

// ===========================================================================
// fsync after rename
// ===========================================================================

/// Create a file, write data, rename it, fsync the renamed path, remount,
/// and verify the data is present under the new name and the old name is
/// absent.
#[test]
fn fsync_after_rename_survives_remount() {
    require_fuse!();

    let mut mnt = MountedVfs::new("rename-fsync", &[], &[]);
    let old_path = mnt.path("/before_rename.bin");
    let new_path = mnt.path("/after_rename.bin");
    let payload = b"data written before rename, fsync'd after rename\n";

    // Write to old path and close.
    {
        let mut file = create_read_write(&old_path);
        file.write_all(payload).expect("write before rename");
    }

    // Rename, then fsync on the new path.
    fs::rename(&old_path, &new_path).expect("rename mounted file");
    File::open(&new_path)
        .expect("open renamed file")
        .sync_all()
        .expect("fsync renamed file");

    mnt.remount();

    // Data must exist under new name.
    assert_eq!(
        read_all(&mnt.path("/after_rename.bin")),
        payload,
        "data must survive rename+fsync+remount under new name"
    );

    // Old name must not exist.
    assert!(
        mnt.path("/before_rename.bin")
            .try_exists()
            .is_ok_and(|ex| !ex),
        "old path must not exist after rename+remount"
    );
}
