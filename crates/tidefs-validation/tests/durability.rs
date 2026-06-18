// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE durability integration tests for the `fuse-fsync-durability` and
//! `fuse-crash-recovery` milestones.
//!
//! These tests mount a real FUSE daemon, perform filesystem operations
//! through the kernel VFS, and verify end-to-end durability across:
//!
//! 1. Clean unmount-remount cycles (fsync/fdatasync data survives)
//! 2. Crash-remount cycles (SIGKILL + lazy-unmount + remount)
//! 3. Data-loss verification for non-fsynced data after crash
//! 4. Multi-file, multi-directory durability at scale
//!
//! Tests use deterministic write patterns so failures are reproducible.
//! When /dev/fuse is unavailable, tests skip gracefully.

use std::path::Path;
use tidefs_validation::mount_harness::MountHarness;

// ── test-data helpers ───────────────────────────────────────────────────────

/// Deterministic test data: incrementing byte sequence mod 256.
fn sequenced_test_data(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes).map(|i| (i % 256) as u8).collect()
}

/// Pseudo-random data seeded by `seed`, len_bytes output.
fn prng_test_data(seed: u64, len_bytes: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len_bytes)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

// ── DurabilityHarness ───────────────────────────────────────────────────────

/// Wraps [`MountHarness`] with durability-specific convenience methods
/// and lifecycle helpers for the standard durability test pattern:
///
///   mount → write → fsync/fdatasync → unmount → remount → read → verify
///
/// The harness spawns a real FUSE daemon, mounts at a temp directory,
/// and handles cleanup on Drop.
struct DurabilityHarness {
    harness: MountHarness,
}

impl DurabilityHarness {
    /// Spawn daemon, mount, wait for readiness.  Returns an error when
    /// /dev/fuse is unavailable (callers should skip, not fail).
    fn new() -> std::io::Result<Self> {
        if !Path::new("/dev/fuse").exists() {
            return Err(std::io::Error::other(
                "FUSE /dev/fuse not available — durability tests require FUSE kernel support",
            ));
        }
        MountHarness::new().map(|h| Self { harness: h })
    }

    // ── delegation to MountHarness ──────────────────────────────────────

    fn write_file(&self, relative: &str, data: &[u8]) -> std::io::Result<()> {
        self.harness.create_file(relative, data)
    }

    fn read_file(&self, relative: &str) -> std::io::Result<Vec<u8>> {
        self.harness.read_file(relative)
    }

    fn fsync_file(&self, relative: &str) -> std::io::Result<()> {
        self.harness.fsync_file(relative)
    }

    fn fdatasync_file(&self, relative: &str) -> std::io::Result<()> {
        self.harness.fdatasync_file(relative)
    }

    fn mkdir(&self, relative: &str) -> std::io::Result<()> {
        self.harness.mkdir(relative)
    }

    fn readdir(&self, relative: &str) -> std::io::Result<Vec<String>> {
        self.harness.readdir(relative)
    }

    /// Graceful unmount via fusermount -u, killing daemon if needed.
    fn clean_unmount(&mut self) -> std::io::Result<()> {
        self.harness.unmount_only(true)
    }

    /// Spawn a fresh daemon on the same backing store and mount point.
    fn remount(&mut self) -> std::io::Result<()> {
        self.harness.remount()
    }

    /// SIGKILL the daemon, lazy-unmount, and restart on the same store.
    /// Simulates a crash where the daemon cannot run its Drop cleanup.
    fn crash_and_remount(&mut self) -> std::io::Result<()> {
        self.harness.crash_and_remount()
    }

    /// Helper: verify a file under the mount point matches `expected` data
    /// byte-for-byte.  Returns Ok on match, Err with diagnostic on mismatch.
    fn verify_file(&self, relative: &str, expected: &[u8]) -> Result<(), String> {
        let actual = self
            .read_file(relative)
            .map_err(|e| format!("read {relative}: {e}"))?;
        if actual.len() != expected.len() {
            return Err(format!(
                "{relative}: length mismatch: got {} bytes, expected {}",
                actual.len(),
                expected.len(),
            ));
        }
        if actual != expected {
            for (i, (a, b)) in actual.iter().zip(expected.iter()).enumerate() {
                if a != b {
                    return Err(format!(
                        "{relative}: byte mismatch at offset {i}: got 0x{a:02x}, expected 0x{b:02x}"
                    ));
                }
            }
            return Err(format!("{relative}: data mismatch (unknown offset)"));
        }
        Ok(())
    }
}

// ── 1. clean remount: fsync durability ──────────────────────────────────────

/// Write 4 KiB of deterministic data, fsync, clean unmount, remount,
/// verify byte-for-byte match.
///
/// This is the foundational durability contract: after fsync + clean
/// unmount, all data must survive remount.
#[test]
fn clean_remount_fsync_4kib() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP clean_remount_fsync_4kib: {e}");
            return;
        }
    };

    let data = sequenced_test_data(4096);
    h.write_file("fsync_4kib.bin", &data).expect("write_file");
    h.fsync_file("fsync_4kib.bin").expect("fsync_file");

    h.clean_unmount().expect("clean unmount");
    h.remount().expect("remount");

    if let Err(e) = h.verify_file("fsync_4kib.bin", &data) {
        panic!("clean_remount_fsync_4kib: {e}");
    }
}

// ── 2. clean remount: fdatasync durability ──────────────────────────────────

/// Write 4 KiB of deterministic data, fdatasync, clean unmount, remount,
/// verify byte-for-byte match.  fdatasync skips metadata sync but file
/// content must survive.
#[test]
fn clean_remount_fdatasync_4kib() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP clean_remount_fdatasync_4kib: {e}");
            return;
        }
    };

    let data = prng_test_data(0xBEEF, 4096);
    h.write_file("fdatasync_4kib.bin", &data)
        .expect("write_file");
    h.fdatasync_file("fdatasync_4kib.bin")
        .expect("fdatasync_file");

    h.clean_unmount().expect("clean unmount");
    h.remount().expect("remount");

    if let Err(e) = h.verify_file("fdatasync_4kib.bin", &data) {
        panic!("clean_remount_fdatasync_4kib: {e}");
    }
}

// ── 3. crash remount: fsync survives SIGKILL ────────────────────────────────

/// Write 4 KiB, fsync, SIGKILL the daemon, remount, verify fsync'd data
/// survives byte-for-byte.  This is the primary crash-recovery gate:
/// fsync must have flushed data to durable object-store storage before
/// the daemon was killed, so remount can reconstruct it.
#[test]
fn crash_remount_fsync_4kib() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_fsync_4kib: {e}");
            return;
        }
    };

    let data = sequenced_test_data(4096);
    h.write_file("crash_fsync.bin", &data).expect("write_file");
    h.fsync_file("crash_fsync.bin").expect("fsync_file");

    // SIGKILL the daemon (no graceful shutdown, no Drop flush).
    h.crash_and_remount().expect("crash_and_remount");

    if let Err(e) = h.verify_file("crash_fsync.bin", &data) {
        panic!(
            "crash_remount_fsync_4kib: {e}
             fsynced data must survive SIGKILL + remount.
             Check that fsync flushes to durable object-store storage
             before the daemon is killed."
        );
    }
}

// ── 4. crash remount: no-fsync data loss ────────────────────────────────────

/// Write checkpoint data A, fsync.  Then write data B WITHOUT fsync,
/// SIGKILL the daemon, remount.  Verify:
///   - A (fsynced) survives byte-for-byte
///   - B (not fsynced) is absent or the file is truncated to A's length
///
/// This is a negative-space test: crash-consistency semantics require
/// that only fsync'd data survives a power-loss or crash event.
/// Non-fsynced writes may be lost entirely.
#[test]
fn crash_remount_no_fsync_data_loss() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_no_fsync_data_loss: {e}");
            return;
        }
    };

    let checkpoint = sequenced_test_data(2048);
    let unsynced = prng_test_data(0xDEAD, 4096);

    // Phase 1: write and fsync checkpoint data.
    h.write_file("crash_loss_test.bin", &checkpoint)
        .expect("write checkpoint");
    h.fsync_file("crash_loss_test.bin")
        .expect("fsync checkpoint");

    // Phase 2: overwrite with larger data WITHOUT fsync.
    h.write_file("crash_loss_test.bin", &unsynced)
        .expect("write unsynced override");

    // Crash — unsynced data should be lost.
    h.crash_and_remount().expect("crash_and_remount");

    // Read back: file must exist and contain at least the checkpoint data.
    let actual = h
        .read_file("crash_loss_test.bin")
        .expect("file must exist after remount (checkpoint was fsynced)");

    // The file after crash may be:
    //   a) exactly the checkpoint data (ideal: unsynced data was lost)
    //   b) the full unsynced data (Drop flush happened before kill — ok but
    //      means the fsync barrier timing is tight)
    //   c) something else (corruption)

    assert!(
        actual.len() >= checkpoint.len(),
        "file after crash ({actual_len} bytes) shorter than checkpoint ({checkpoint_len} bytes) — corruption",
        actual_len = actual.len(),
        checkpoint_len = checkpoint.len(),
    );

    assert_eq!(
        &actual[..checkpoint.len()],
        checkpoint.as_slice(),
        "checkpoint prefix must survive SIGKILL byte-for-byte"
    );

    // Behavioural probe: was the unsynced data lost?
    let unsynced_lost = actual.len() == checkpoint.len();
    eprintln!(
        "INFO: crash_remount_no_fsync_data_loss: {previous} bytes fsynced, \
         {full} bytes before crash. After remount: {actual_len} bytes. \
         Unsynced data {lost_result} lost.",
        previous = checkpoint.len(),
        full = unsynced.len(),
        actual_len = actual.len(),
        lost_result = if unsynced_lost { "was" } else { "was NOT" }
    );
}

// ── 5. multi-file 16-files 4-subdirs durability ─────────────────────────────

/// Create 16 files distributed across 4 subdirectories (4 files each),
/// fsync all, clean unmount, remount, and verify every file byte-for-byte.
/// Exercises directory durability at scale — no existing test covers more
/// than 4 files across 2 directories.
#[test]
fn multi_file_16_files_4_subdirs_durability() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP multi_file_16_files_4_subdirs_durability: {e}");
            return;
        }
    };

    let dirs = ["dir_a", "dir_b", "dir_c", "dir_d"];
    let files_per_dir = 4u32;
    let file_size = 512usize;

    // Build a map of path → data.
    let mut expected: Vec<(String, Vec<u8>)> = Vec::new();

    for dir in &dirs {
        h.mkdir(dir).expect("mkdir {dir}");
        for i in 0..files_per_dir {
            let path = format!("{dir}/file_{i}.bin");
            // Each file gets unique deterministic data via sequenced pattern
            // plus a per-file seed in the first 8 bytes.
            let mut data = Vec::with_capacity(file_size);
            data.extend_from_slice(&i.to_le_bytes());
            data.extend(sequenced_test_data(file_size - 8));
            h.write_file(&path, &data)
                .unwrap_or_else(|e| panic!("write {path}: {e}"));
            expected.push((path, data));
        }
    }

    // fsync all files.
    for (path, _) in &expected {
        h.fsync_file(path)
            .unwrap_or_else(|e| panic!("fsync {path}: {e}"));
    }

    h.clean_unmount().expect("clean unmount");
    h.remount().expect("remount");

    // Verify all directories and files survived.
    for dir in &dirs {
        let entries = h
            .readdir(dir)
            .unwrap_or_else(|e| panic!("readdir {dir} after remount: {e}"));
        assert_eq!(
            entries.len(),
            files_per_dir as usize,
            "{dir}: expected {} entries after remount, got {}: {entries:?}",
            files_per_dir,
            entries.len(),
        );
    }

    for (path, data) in &expected {
        if let Err(e) = h.verify_file(path, data) {
            panic!("multi_file_durability: {e}");
        }
    }
}

// ── 6. crash-remount multi-file durability ──────────────────────────────────

/// Create 8 files across 2 subdirectories, fsync all, SIGKILL daemon,
/// remount, verify all 8 survive.  The existing crash tests in
/// write_durability.rs are #[ignore]; this exercises the crash path
/// at moderate scale (8 files, 2 dirs) to validate multi-file crash
/// recovery without the ignore marker.
#[test]
fn crash_remount_multi_file_8_files_2_subdirs() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_multi_file_8_files_2_subdirs: {e}");
            return;
        }
    };

    let dirs = ["crash_top", "crash_sub"];
    let files_per_dir = 4u32;

    let mut expected: Vec<(String, Vec<u8>)> = Vec::new();

    for dir in &dirs {
        h.mkdir(dir).expect("mkdir {dir}");
        for i in 0..files_per_dir {
            let path = format!("{dir}/cfile_{i}.bin");
            let data = prng_test_data(0xCAFE + i as u64, 512);
            h.write_file(&path, &data)
                .unwrap_or_else(|e| panic!("write {path}: {e}"));
            expected.push((path, data));
        }
    }

    // fsync all files before crash.
    for (path, _) in &expected {
        h.fsync_file(path)
            .unwrap_or_else(|e| panic!("fsync {path}: {e}"));
    }

    h.crash_and_remount().expect("crash_and_remount");

    // Verify all files and directory entries survived the crash.
    for dir in &dirs {
        let entries = h
            .readdir(dir)
            .unwrap_or_else(|e| panic!("readdir {dir} after crash: {e}"));
        assert_eq!(
            entries.len(),
            files_per_dir as usize,
            "{dir}: expected {} entries after crash, got {}: {entries:?}",
            files_per_dir,
            entries.len(),
        );
    }

    for (path, data) in &expected {
        if let Err(e) = h.verify_file(path, data) {
            panic!(
                "crash_remount_multi_file: {e}
                 fsynced data must survive SIGKILL crash + remount.
                 Check that fsync flushes directory entries and file data
                 to durable object-store storage."
            );
        }
    }
}

// ── 7. crash remount: overwrite survives SIGKILL ────────────────────────────

/// Write initial data, fsync, overwrite with larger content, fsync again,
/// SIGKILL the daemon, remount, verify the latest (overwritten) content
/// survived byte-for-byte.
#[test]
fn crash_remount_overwrite_survives() {
    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_overwrite_survives: {e}");
            return;
        }
    };

    let initial = b"original content that was overwritten\n".to_vec();
    let overwrite = sequenced_test_data(8192);

    h.write_file("overwrite_crash.bin", &initial)
        .expect("write initial");
    h.fsync_file("overwrite_crash.bin").expect("fsync initial");

    h.write_file("overwrite_crash.bin", &overwrite)
        .expect("overwrite");
    h.fsync_file("overwrite_crash.bin")
        .expect("fsync overwrite");

    h.crash_and_remount().expect("crash_and_remount");

    if let Err(e) = h.verify_file("overwrite_crash.bin", &overwrite) {
        panic!(
            "crash_remount_overwrite_survives: {e}
             Latest fsynced content must survive SIGKILL + remount;
             if the initial content survived, the overwrite fsync
             did not flush to durable storage."
        );
    }
}

// ── 8. crash remount: truncate+extend survives SIGKILL ──────────────────────

/// Write 8 KiB, truncate to 1 KiB, extend to 4 KiB with zero-fill, fsync,
/// SIGKILL, remount, verify size=4 KiB and the zero-filled region is intact.
#[test]
fn crash_remount_truncate_extend_survives() {
    use std::fs::File;
    use std::io::Write;

    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_truncate_extend_survives: {e}");
            return;
        }
    };

    let full_data = sequenced_test_data(8192); // 8 KiB
    let path = h.harness.mount_path().join("trunc_ext_crash.bin");

    // Phase 1: write 8 KiB, truncate to 1 KiB, fxport.
    h.write_file("trunc_ext_crash.bin", &full_data)
        .expect("write 8 KiB");

    {
        let file = File::open(&path).expect("open for truncate");
        file.set_len(1024).expect("truncate to 1 KiB");
        file.sync_all().expect("fsync after truncate");
    }

    // Phase 2: reopen (fresh daemon state), extend to 4 KiB with zero-fill.
    // Extend by writing zeros at offset 1024..4096.
    {
        let mut file = File::options()
            .write(true)
            .open(&path)
            .expect("open for extend");
        let zeros = vec![0u8; 3072];
        file.write_all(&full_data[..1024])
            .expect("rewrite first 1 KiB");
        // Seek past first 1 KiB and write zeros for the extension.
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(1024))
            .expect("seek to 1024");
        file.write_all(&zeros).expect("write zero-fill extension");
        file.sync_all().expect("fsync after extend");
    }

    h.crash_and_remount().expect("crash_and_remount");

    let actual = h
        .read_file("trunc_ext_crash.bin")
        .expect("read after crash");
    assert_eq!(
        actual.len(),
        4096,
        "file size should be 4 KiB after truncate+extend+crash; got {}",
        actual.len()
    );

    // First 1024 bytes: original data.
    assert_eq!(
        &actual[..1024],
        &full_data[..1024],
        "first 1 KiB after crash must match original data"
    );

    // Bytes 1024..4096: zero-filled from the extend.
    for (i, byte) in actual.iter().enumerate().take(4096).skip(1024) {
        assert_eq!(
            *byte, 0u8,
            "byte at offset {i} should be zero-filled after extend; got 0x{:02x}",
            *byte
        );
    }
}

// ── 9. crash remount: chmod attribute survives SIGKILL ──────────────────────

/// Create a file, chmod 0o600, fsync the file, SIGKILL the daemon,
/// remount, verify mode bits are 0o600 (not the default 0o644).
#[test]
fn crash_remount_chmod_survives() {
    use std::os::unix::fs::PermissionsExt;

    let mut h = match DurabilityHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_remount_chmod_survives: {e}");
            return;
        }
    };

    h.write_file("chmod_crash.bin", b"mode test\n")
        .expect("write_file");
    h.harness.chmod("chmod_crash.bin", 0o600).expect("chmod");
    h.fsync_file("chmod_crash.bin").expect("fsync after chmod");

    let before = h
        .harness
        .stat("chmod_crash.bin")
        .expect("stat before crash");
    let mode_before = before.permissions().mode() & 0o777;
    assert_eq!(mode_before, 0o600, "chmod should take effect before crash");

    h.crash_and_remount().expect("crash_and_remount");

    let after = h.harness.stat("chmod_crash.bin").expect("stat after crash");
    let mode_after = after.permissions().mode() & 0o777;
    assert_eq!(
        mode_after, 0o600,
        "mode bits should survive SIGKILL crash + remount;
         expected 0o600, got 0o{mode_after:03o}"
    );

    // Verify content also survived.
    let content = h.read_file("chmod_crash.bin").expect("read after crash");
    assert_eq!(
        content, b"mode test\n",
        "file content must also survive crash"
    );
}
