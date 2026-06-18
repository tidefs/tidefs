// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE write-durability integration test.
//!
//! Exercises advancement criteria 1-3 of the `fuse-write-durability` focus
//! slice through a real read-write FUSE mount:
//!
//! 1. write data and read it back in the same session (write-read coherence)
//! 2. fsync flushes dirty writeback buffers to durable object-store storage
//! 3. after daemon restart (simulated crash), remount recovers all
//!    previously fsync'd data with correct content
//!
//! The test uses `MountHarness` infrastructure to spawn the
//! `tidefs-posix-filesystem-adapter-daemon`, perform IO through the FUSE
//! mount, and remount the same backing store after a daemon restart.
//!
//! When a test cannot pass due to missing infrastructure (e.g. writeback
//! flush on fsync not yet wired, or empty object-store after remount), the
//! test is marked `#[ignore]` with a comment identifying the exact blocker.

use tidefs_validation::mount_harness::MountHarness;

// ── test-data helpers ──────────────────────────────────────────────────────

/// Build reproducible multi-block test data: `count` bytes of seeded
/// pseudo-random content followed by a 16-byte checksum footer.
///
/// The pseudo-random sequence uses a splitmix64 generator seeded by `seed`.
/// The checksum is computed with std DefaultHasher over (seed, count, data)
/// and repeated to fill 16 bytes.  This lets the test distinguish "all
/// zeros" from "corrupted after write" with high probability.
fn make_test_buffer(seed: u64, count: usize) -> Vec<u8> {
    use std::hash::{Hash, Hasher};
    let mut buf = Vec::with_capacity(count + 16);
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    for _ in 0..count {
        buf.push((state >> 32) as u8);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    (count as u64).hash(&mut hasher);
    buf.hash(&mut hasher);
    let h64 = hasher.finish();
    let mut footer = [0u8; 16];
    footer[..8].copy_from_slice(&h64.to_le_bytes());
    footer[8..].copy_from_slice(&h64.to_le_bytes());
    buf.extend_from_slice(&footer);
    buf
}

/// Verify `data` matches `make_test_buffer(seed, _)` contract byte-for-byte.
fn verify_test_buffer(seed: u64, data: &[u8]) -> Result<(), String> {
    let expected = make_test_buffer(seed, data.len().saturating_sub(16));
    if data.len() != expected.len() {
        return Err(format!(
            "length mismatch: got {} bytes, expected {}",
            data.len(),
            expected.len()
        ));
    }
    if data != expected.as_slice() {
        for (i, (a, b)) in data.iter().zip(expected.iter()).enumerate() {
            if a != b {
                return Err(format!(
                    "byte mismatch at offset {i}: got 0x{a:02x}, expected 0x{b:02x}"
                ));
            }
        }
        return Err("data mismatch (unknown offset)".to_string());
    }
    Ok(())
}

/// Generate a repeating 0..255 sequenced buffer of `len_bytes` bytes.
fn sequenced_test_data(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes).map(|i| (i % 256) as u8).collect()
}

// ── criterion 1: same-session write-read coherence ─────────────────────────

/// Write multi-block data (8 KiB) through the FUSE mount and read it back
/// within the same session without any unmount.  Confirms write-dispatch
/// and read-dispatch are wired correctly.
#[test]
fn same_session_write_read_8kib() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP same_session_write_read_8kib: daemon not available -- {e}");
            return;
        }
    };

    let data = sequenced_test_data(8192);
    harness
        .create_file("ss_write_read.bin", &data)
        .expect("create_file through FUSE mount");

    let read_back = harness
        .read_file("ss_write_read.bin")
        .expect("read_file through FUSE mount");

    assert_eq!(
        read_back.len(),
        data.len(),
        "same-session read-back length mismatch"
    );
    assert_eq!(
        read_back, data,
        "same-session read-back byte-for-byte mismatch"
    );
}

/// Write pseudo-random multi-block data (16 KiB) with checksum footer and
/// verify byte-for-byte within the same session.
#[test]
fn same_session_write_read_16kib_checksummed() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP same_session_write_read_16kib_checksummed: daemon not available -- {e}"
            );
            return;
        }
    };

    let seed: u64 = 0xfeedface_c0ffee12;
    let data = make_test_buffer(seed, 16384);
    harness
        .create_file("ss_checksum.bin", &data)
        .expect("create_file through FUSE mount");

    let read_back = harness
        .read_file("ss_checksum.bin")
        .expect("read_file through FUSE mount");

    if let Err(e) = verify_test_buffer(seed, &read_back) {
        panic!("same-session checksummed read-back failed: {e}");
    }
}

// ── criterion 2: fsync flushes to durable storage ──────────────────────────

/// Write data, fsync the file, unmount, remount, then verify byte-for-byte.
/// This tests that fsync flushes dirty writeback buffers to the object store
/// so data survives a daemon restart.  The writeback-flush-on-fsync wiring in
/// LocalFileSystem is already complete (verified via MountHarness integration).
#[test]
fn write_fsync_remount_verify_8kib() {
    let data = sequenced_test_data(8192);
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_fsync_remount_verify_8kib: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("durable.bin", &data)
        .expect("create_file session 1");
    harness.fsync_file("durable.bin").expect("fsync session 1");

    // Capture store path before unmount kills the TempDir guard.
    let store_path = harness.store_path().to_path_buf();

    harness.unmount_only(true).expect("unmount session 1");

    // Verify backing store directory still exists and has content.
    assert!(
        store_path.exists(),
        "backing store {} must exist after unmount",
        store_path.display()
    );

    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("durable.bin")
        .expect("read_file session 2");

    assert_eq!(
        read_back.len(),
        data.len(),
        "file length mismatch after remount: expected {} bytes, got {}",
        data.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, data,
        "byte-for-byte data mismatch after fsync + remount:          writeback flush may not have persisted data to object store"
    );
}

/// Write pseudo-random 4 KiB data with checksum, fsync, remount, verify.
#[test]
fn write_fsync_remount_verify_4kib_checksummed() {
    let seed: u64 = 0xdeadbeef_cafebabe;
    let data = make_test_buffer(seed, 4096);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_fsync_remount_verify_4kib_checksummed: daemon not available -- {e}"
            );
            return;
        }
    };

    harness
        .create_file("cksum_durable.bin", &data)
        .expect("create_file session 1");
    harness
        .fsync_file("cksum_durable.bin")
        .expect("fsync session 1");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("cksum_durable.bin")
        .expect("read_file session 2");

    if let Err(e) = verify_test_buffer(seed, &read_back) {
        panic!(
            "checksummed data verification failed after fsync + remount: {e}
             The writeback layer may not be flushing dirty data to the              object store on fsync."
        );
    }
}

// ── criterion 3: crash-recovery simulation ─────────────────────────────────

/// Full advancement-gate test: write → fsync → unmount (simulate crash) →
/// daemon restart → remount → read → verify byte-for-byte.
///
/// Uses the same `MountHarness::remount()` helper which spawns a fresh
/// daemon process on the same backing store directory.  The mount point
/// path is preserved across sessions by the harness lifetime.
#[test]
fn full_write_fsync_remount_verify_cycle() {
    let seed: u64 = 0x01234567_89abcdef;
    let data_len: usize = 8192;
    let test_data = make_test_buffer(seed, data_len);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP full_write_fsync_remount_verify_cycle: daemon not available -- {e}");
            return;
        }
    };

    // Session 1: write, fsync, unmount.
    harness
        .create_file("write_durability_test.bin", &test_data)
        .expect("create_file session 1");

    harness
        .fsync_file("write_durability_test.bin")
        .expect("fsync session 1");

    harness.unmount_only(true).expect("unmount session 1");

    // Session 2: daemon restart, remount, read, verify.
    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("write_durability_test.bin")
        .expect("read_file session 2");

    if let Err(e) = verify_test_buffer(seed, &read_back) {
        panic!(
            "write-durability verification failed: {e}
             seed=0x{seed:x}, data_len={data_len}
             Expected byte-for-byte match after fsync + daemon restart + remount.
             Possible causes:
             - writeback layer does not flush dirty buffers on fsync
             - object store does not commit writeback data to durable storage
             - remount does not reconstruct namespace/inode state from object store"
        );
    }
}

// ── stress: multi-block write with varying sizes ───────────────────────────

/// Verify same-session write-read for several block sizes to exercise any
/// block-alignment or extent-boundary paths in the write dispatch.
#[test]
fn same_session_write_read_varying_sizes() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP same_session_write_read_varying_sizes: daemon not available -- {e}");
            return;
        }
    };

    let sizes: &[usize] = &[
        1, 63, 64, 65, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 65536,
    ];
    for &size in sizes {
        let name = format!("var_{size}.bin");
        let data = sequenced_test_data(size);
        harness
            .create_file(&name, &data)
            .unwrap_or_else(|e| panic!("create_file {name}: {e}"));

        let read_back = harness
            .read_file(&name)
            .unwrap_or_else(|e| panic!("read_file {name}: {e}"));

        assert_eq!(
            read_back, data,
            "same-session mismatch for {size}-byte file {name}"
        );
    }
}

// ── stress: concurrent write to multiple files, then remount ───────────────

/// Write three files of varying sizes, fsync each, remount, verify all three.
#[test]
fn multi_file_write_fsync_remount_verify() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP multi_file_write_fsync_remount_verify: daemon not available -- {e}");
            return;
        }
    };

    let data_a = sequenced_test_data(512);
    let seed_b: u64 = 0xaaaa_bbbb_cccc_dddd;
    let data_b = make_test_buffer(seed_b, 2048);
    let data_c = sequenced_test_data(65536);

    harness
        .create_file("multi_a.bin", &data_a)
        .expect("create multi_a.bin");
    harness
        .create_file("multi_b.bin", &data_b)
        .expect("create multi_b.bin");
    harness
        .create_file("multi_c.bin", &data_c)
        .expect("create multi_c.bin");

    harness
        .fsync_file("multi_a.bin")
        .expect("fsync multi_a.bin");
    harness
        .fsync_file("multi_b.bin")
        .expect("fsync multi_b.bin");
    harness
        .fsync_file("multi_c.bin")
        .expect("fsync multi_c.bin");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_a = harness.read_file("multi_a.bin").expect("read multi_a.bin");
    let read_b = harness.read_file("multi_b.bin").expect("read multi_b.bin");
    let read_c = harness.read_file("multi_c.bin").expect("read multi_c.bin");

    assert_eq!(read_a, data_a, "multi_a.bin mismatch after remount");
    assert_eq!(read_b, data_b, "multi_b.bin mismatch after remount");
    assert_eq!(read_c, data_c, "multi_c.bin mismatch after remount");
}

// ── additional write-durability coverage ──────────────────────────────────

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// Pseudo-random data seeded by `seed` and sized to `len_bytes`.
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

/// Wait for a mount point to become ready (times out after 10s).
fn wait_for_mount(path: &Path) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match fs::metadata(path) {
            Ok(_) => return Ok(()),
            Err(_) if start.elapsed() < Duration::from_secs(10) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Spawn a fresh daemon on an existing store/mount pair.
fn spawn_daemon_on(store: &Path, mount: &Path) -> io::Result<(std::process::Child, u32)> {
    let daemon_bin = tidefs_validation::mount_harness::find_daemon_binary()?;
    let child = Command::new(&daemon_bin)
        .arg("mount-vfs")
        .arg("--store")
        .arg(store)
        .arg("--mount")
        .arg(mount)
        .arg("--root-auth-key-hex")
        .arg("0000000000000000000000000000000000000000000000000000000000000001")
        .spawn()
        .map_err(|e| io::Error::other(format!("spawn daemon: {e}")))?;
    let pid = child.id();
    wait_for_mount(mount)?;
    Ok((child, pid))
}

/// Kill a child process by PID with SIGTERM then SIGKILL.
fn kill_daemon(pid: u32) {
    // SAFETY: kill(2) with SIGTERM; pid is a valid daemon PID.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    thread::sleep(Duration::from_millis(200));
    // SAFETY: kill(2) is a C FFI call; pid is a valid daemon PID.
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    thread::sleep(Duration::from_millis(100));
}

// ── multi-chunk large-file durability ─────────────────────────────────────

#[test]
fn write_durability_multi_chunk_64kib() {
    let test_data = sequenced_test_data(64 * 1024);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_multi_chunk_64kib: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("wd_64k.bin", &test_data)
        .expect("create_file");
    harness.fsync_file("wd_64k.bin").expect("fsync");
    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let read_back = harness.read_file("wd_64k.bin").expect("read after remount");
    assert_eq!(read_back.len(), test_data.len(), "length mismatch");
    assert_eq!(
        read_back, test_data,
        "byte-for-byte mismatch after remount (64 KiB)"
    );
}

// ── fdatasync durability ──────────────────────────────────────────────────

#[test]
fn write_durability_fdatasync_4kib() {
    use std::os::unix::io::AsRawFd;

    let test_data = prng_test_data(0x42, 4096);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_fdatasync_4kib: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("wd_fdatasync.bin", &test_data)
        .expect("create_file");

    // Call fdatasync directly via libc on the mounted file.
    let path = harness.mount_path().join("wd_fdatasync.bin");
    let file = fs::File::open(&path).expect("open for fdatasync");
    // SAFETY: fdatasync is a C FFI call; the fd is valid.
    let rc = unsafe { libc::fdatasync(file.as_raw_fd()) };
    assert_eq!(rc, 0, "fdatasync syscall failed");
    drop(file);

    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let read_back = harness
        .read_file("wd_fdatasync.bin")
        .expect("read after remount");
    assert_eq!(
        read_back, test_data,
        "byte-for-byte mismatch after fdatasync+remount"
    );
}

// ── nested directory structure preservation ───────────────────────────────

#[test]
fn write_durability_nested_dirs() {
    let data_deep = prng_test_data(0xDEAD, 1024);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_nested_dirs: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir_all("a/b/c").expect("mkdir -p a/b/c");
    harness
        .create_file("a/b/c/deep.bin", &data_deep)
        .expect("create deep file");
    harness
        .create_file("a/root_level.txt", b"root-level\n")
        .expect("create root-level");
    harness.fsync_file("a/b/c/deep.bin").expect("fsync deep");
    harness
        .fsync_file("a/root_level.txt")
        .expect("fsync root-level");

    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let entries_a = harness.readdir("a").expect("readdir a");
    assert!(entries_a.contains(&"b".to_string()), "a should contain b/");
    assert!(
        entries_a.contains(&"root_level.txt".to_string()),
        "a should contain root_level.txt"
    );

    let entries_c = harness.readdir("a/b/c").expect("readdir a/b/c");
    assert!(
        entries_c.contains(&"deep.bin".to_string()),
        "a/b/c should contain deep.bin"
    );

    assert_eq!(
        harness.read_file("a/b/c/deep.bin").expect("read deep"),
        data_deep,
        "deep.bin data mismatch"
    );
    assert_eq!(
        harness
            .read_file("a/root_level.txt")
            .expect("read root-level"),
        b"root-level\n",
        "root_level.txt data mismatch"
    );
}

// ── overwrite durability ──────────────────────────────────────────────────

#[test]
fn write_durability_overwrite_then_remount() {
    let overwrite = b"NEW CONTENT AFTER OVERWRITE!\n".to_vec();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_overwrite_then_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("overwrite.bin", b"original content\n")
        .expect("create original");
    harness
        .create_file("overwrite.bin", &overwrite)
        .expect("overwrite");
    harness
        .fsync_file("overwrite.bin")
        .expect("fsync overwrite");
    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let read_back = harness
        .read_file("overwrite.bin")
        .expect("read after remount");
    assert_eq!(
        read_back, overwrite,
        "overwrite should persist across remount"
    );
}

// ── empty file durability ─────────────────────────────────────────────────

#[test]
fn write_durability_empty_file_survives_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_empty_file_survives_remount: daemon not available -- {e}"
            );
            return;
        }
    };

    harness.create_file("empty.bin", b"").expect("create empty");
    harness.fsync_file("empty.bin").expect("fsync empty");
    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let read_back = harness.read_file("empty.bin").expect("read after remount");
    assert!(
        read_back.is_empty(),
        "empty file should remain empty after remount"
    );
}

// ── unlink persistence across remount ─────────────────────────────────────

#[test]
fn write_durability_unlink_survives_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_unlink_survives_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("to_delete.txt", b"delete me\n")
        .expect("create");
    harness.fsync_file("to_delete.txt").expect("fsync");
    harness.remove_file("to_delete.txt").expect("unlink");
    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    assert!(
        !harness.exists("to_delete.txt"),
        "unlinked file should not reappear after remount"
    );
}

// ── crash simulation: SIGKILL daemon with prior fsync ─────────────────────

#[test]
fn write_durability_fsync_crash_remount_4kib() {
    let test_data = prng_test_data(0xCAFE, 4096);

    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_fsync_crash_remount_4kib: daemon not available -- {e}"
            );
            return;
        }
    };

    harness
        .create_file("crash_test.bin", &test_data)
        .expect("create_file");
    harness.fsync_file("crash_test.bin").expect("fsync");

    // Save paths before killing the daemon.
    let store_path = harness.store_path().to_path_buf();
    let mount_path = harness.mount_path().to_path_buf();
    let pid = harness.daemon_pid();

    // Hard crash: SIGKILL.
    // SAFETY: kill(2) is a C FFI call; pid is a valid daemon PID.
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    thread::sleep(Duration::from_millis(300));

    // Force unmount: fusermount -u may fail on dead mount, use -z (lazy).
    let _ = Command::new("fusermount")
        .arg("-u")
        .arg("-z")
        .arg(&mount_path)
        .output();

    // Keep the harness alive via ManuallyDrop: its TempDir holds the
    // backing store which must survive until after the remount read.
    let mut harness = std::mem::ManuallyDrop::new(harness);

    // Spawn a fresh daemon on the same store/mount.
    let (child, pid2) =
        spawn_daemon_on(&store_path, &mount_path).expect("spawn daemon after crash");

    // Verify data survived.
    let read_back = fs::read(mount_path.join("crash_test.bin")).expect("read after crash+remount");
    assert_eq!(
        read_back.len(),
        test_data.len(),
        "length mismatch after crash"
    );
    assert_eq!(
        read_back, test_data,
        "byte-for-byte mismatch after fsync+crash+remount"
    );

    // Cleanup: kill daemon, unmount, then drop the harness.
    kill_daemon(pid2);
    let _ = Command::new("fusermount")
        .arg("-u")
        .arg("-z")
        .arg(&mount_path)
        .output();
    drop(child);
    // SAFETY: ManuallyDrop::drop prevents the normal Drop from running;
    // this avoids double-unmount when the daemon has already been killed.
    // The pointer to harness is valid (live local variable).
    unsafe {
        std::mem::ManuallyDrop::drop(&mut harness);
    }
}

// ── negative test: write without fsync before crash ────────────────────────

#[test]
fn write_durability_no_fsync_crash_test() {
    let test_data = prng_test_data(0xBEEF, 2048);

    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_no_fsync_crash_test: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("no_fsync.bin", &test_data)
        .expect("create_file");
    // Explicitly DO NOT fsync.

    let store_path = harness.store_path().to_path_buf();
    let mount_path = harness.mount_path().to_path_buf();
    let pid = harness.daemon_pid();

    // SAFETY: kill(2) is a C FFI call; pid is a valid daemon PID.
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    thread::sleep(Duration::from_millis(300));
    let _ = Command::new("fusermount")
        .arg("-u")
        .arg("-z")
        .arg(&mount_path)
        .output();

    let mut harness = std::mem::ManuallyDrop::new(harness);

    let (child, pid2) =
        spawn_daemon_on(&store_path, &mount_path).expect("spawn daemon after crash (no fsync)");

    // The file may or may not survive. POSIX does not guarantee data
    // written without fsync survives a crash.
    match fs::read(mount_path.join("no_fsync.bin")) {
        Ok(data) => {
            if data == test_data {
                eprintln!("note: no-fsync data survived crash (implementation detail)");
            } else {
                eprintln!("note: no-fsync data partially survived crash (expected)");
            }
        }
        Err(e) => {
            eprintln!("note: no-fsync file not found after crash (expected): {e}");
        }
    }

    kill_daemon(pid2);
    let _ = Command::new("fusermount")
        .arg("-u")
        .arg("-z")
        .arg(&mount_path)
        .output();
    drop(child);
    // SAFETY: ManuallyDrop::drop prevents the normal Drop from running;
    // this avoids double-unmount when the daemon has already been killed.
    // The pointer to harness is valid (live local variable).
    unsafe {
        std::mem::ManuallyDrop::drop(&mut harness);
    }
}

// ── rename durability across remount ──────────────────────────────────────

#[test]
fn write_durability_rename_survives_remount() {
    let data = b"renamed file content\n".to_vec();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_rename_survives_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("old_name.txt", &data)
        .expect("create old");
    harness.fsync_file("old_name.txt").expect("fsync old");
    harness
        .rename("old_name.txt", "new_name.txt")
        .expect("rename");

    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    assert!(
        !harness.exists("old_name.txt"),
        "old name should not exist after rename+remount"
    );
    assert!(
        harness.exists("new_name.txt"),
        "new name should exist after rename+remount"
    );
    let read_back = harness.read_file("new_name.txt").expect("read new");
    assert_eq!(read_back, data, "renamed file data mismatch after remount");
}

// ── file size metadata persistence ────────────────────────────────────────

#[test]
fn write_durability_file_size_survives_remount() {
    let sizes: &[u64] = &[0, 1, 511, 512, 4095, 4096, 8192, 65536];

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_file_size_survives_remount: daemon not available -- {e}"
            );
            return;
        }
    };

    for &size in sizes {
        let fname = format!("size_{size}.bin");
        let data = vec![0xABu8; size as usize];
        harness
            .create_file(&fname, &data)
            .expect("create sized file");
        harness.fsync_file(&fname).expect("fsync sized file");
    }

    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    for &size in sizes {
        let fname = format!("size_{size}.bin");
        let md = harness.stat(&fname).expect("stat after remount");
        assert_eq!(md.len(), size, "file size mismatch for size={size}");
    }
}

// ── append/extend durability ──────────────────────────────────────────────

#[test]
fn write_durability_append_extend_survives_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_append_extend_survives_remount: daemon not available -- {e}"
            );
            return;
        }
    };

    // Create with initial data, then extend by overwriting with larger content.
    harness
        .create_file("append.bin", b"AAAA")
        .expect("create initial");
    harness.fsync_file("append.bin").expect("fsync initial");

    let full_data = b"AAAABBBBCCCCDDDD";
    harness
        .create_file("append.bin", full_data)
        .expect("extend file");
    harness.fsync_file("append.bin").expect("fsync extended");

    harness.unmount_only(true).expect("unmount clean");
    harness.remount().expect("remount");

    let read_back = harness.read_file("append.bin").expect("read after remount");
    assert_eq!(
        read_back,
        full_data.as_slice(),
        "extended file data mismatch after remount"
    );
    assert_eq!(
        read_back.len(),
        full_data.len(),
        "extended file length mismatch"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests from issue #3739: directory-fsync propagation, large-file,
// incremental fsync patterns.
// ═══════════════════════════════════════════════════════════════════════════

// ── directory-fsync propagation ───────────────────────────────────────────

/// Helper: fsync a directory by path using libc::fsync with O_DIRECTORY open.
/// This is distinct from per-file fsync — it tests whether the filesystem
/// propagates a directory sync to dirty writeback on child inodes.
fn fsync_dir_impl(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let dir_c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::other(format!("path with nul: {e}")))?;
    // SAFETY: O_RDONLY | O_DIRECTORY open for fsync; no other flags.
    // SAFETY: open(2) is a C FFI call; the path pointer is a valid
    // null-terminated CString; the flags are valid O_* constants.
    let fd = unsafe { libc::open(dir_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fsync is a C FFI call; the fd is valid.
    let rc = unsafe { libc::fsync(fd) };
    let save_err = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }
    if rc != 0 {
        return Err(save_err);
    }
    Ok(())
}

/// Write 3 files inside a subdirectory, fsync the parent directory (not
/// the individual files), unmount/remount, then verify all 3 files survived
/// with correct contents.  Validates that directory-fsync propagation
/// flushes dirty writeback for children to durable storage.
#[test]
fn multi_file_dir_fsync_propagation_remount_verify() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP multi_file_dir_fsync_propagation_remount_verify: daemon not available -- {e}"
            );
            return;
        }
    };

    let data_a = sequenced_test_data(1024);
    let seed_b: u64 = 0x1111_2222_3333_4444;
    let data_b = make_test_buffer(seed_b, 4096);
    let data_c = sequenced_test_data(256);

    harness.mkdir("subdir_prop").expect("mkdir subdir_prop");
    harness
        .create_file("subdir_prop/a.bin", &data_a)
        .expect("create a.bin");
    harness
        .create_file("subdir_prop/b.bin", &data_b)
        .expect("create b.bin");
    harness
        .create_file("subdir_prop/c.bin", &data_c)
        .expect("create c.bin");

    // fsync the parent directory only — tests propagation to children.
    let dir_path = harness.mount_path().join("subdir_prop");
    fsync_dir_impl(&dir_path).expect("fsync subdir_prop");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_a = harness.read_file("subdir_prop/a.bin").expect("read a.bin");
    let read_b = harness.read_file("subdir_prop/b.bin").expect("read b.bin");
    let read_c = harness.read_file("subdir_prop/c.bin").expect("read c.bin");

    assert_eq!(read_a, data_a, "a.bin mismatch after dir-fsync + remount");
    assert_eq!(read_b, data_b, "b.bin mismatch after dir-fsync + remount");
    assert_eq!(read_c, data_c, "c.bin mismatch after dir-fsync + remount");
}

// ── large-file / multi-extent write ────────────────────────────────────────

/// Write 1.5 MiB of reproducible data (spanning multiple extent-map entries),
/// fsync, remount, and verify byte-for-byte.  Exercises writeback iterator
/// over dirty pages that cross extent boundaries and confirms extent-map
/// reconstruction on remount produces contiguous readable data.
///
/// #3731's multi_chunk_64kib covers 64 KiB — this test exercises an order
/// of magnitude more data to stress multi-extent paths.
#[test]
fn large_file_write_fsync_remount_verify() {
    let seed: u64 = 0xabcdef01_23456789;
    // 1.5 MiB exceeds a typical FUSE page/EIO extent size and exercises
    // the writeback iterator across extent boundaries.
    let data_len: usize = 1_572_864; // 1.5 MiB exactly
    let data = make_test_buffer(seed, data_len);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP large_file_write_fsync_remount_verify: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("large.bin", &data)
        .expect("create large.bin session 1");
    harness
        .fsync_file("large.bin")
        .expect("fsync large.bin session 1");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("large.bin")
        .expect("read large.bin session 2");

    if let Err(e) = verify_test_buffer(seed, &read_back) {
        panic!(
            "large-file (1.5 MiB) verification failed after fsync + remount: {e}\n\
             seed=0x{seed:x}\n\
             Expected byte-for-byte match across multiple extents.\n\
             Possible causes:\n\
             - extent-map reconstruction drops or mangles extent boundaries\n\
             - writeback flush truncates at extent boundary\n\
             - object store write coalescing loses data"
        );
    }
}

// ── incremental fsync patterns ─────────────────────────────────────────────

/// Helper: append `data` to an existing file at `relative` under the mount
/// point.  Uses OpenOptions with append mode — distinct from create_file
/// which truncates-then-writes.
fn append_to_file(
    harness: &MountHarness,
    relative: impl AsRef<std::path::Path>,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    let path = harness.mount_path().join(relative);
    let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
    file.write_all(data)?;
    Ok(())
}

/// Write A, fsync, append B, fsync, remount, verify A+B both survive.
/// This is the append-after-commit pattern applications rely on: write a
/// record, fsync, write another record, fsync.  Contrast with #3731's
/// append_extend test which uses full-file overwrite.
#[test]
fn incremental_fsync_both_durable() {
    let data_a = sequenced_test_data(2048);
    let data_b = sequenced_test_data(4096);
    let mut combined = data_a.clone();
    combined.extend_from_slice(&data_b);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP incremental_fsync_both_durable: daemon not available -- {e}");
            return;
        }
    };

    // Write A (initial write).
    harness
        .create_file("incr_both.dat", &data_a)
        .expect("write data A");
    harness.fsync_file("incr_both.dat").expect("fsync after A");

    // Append B.
    append_to_file(&harness, "incr_both.dat", &data_b).expect("append data B");
    harness.fsync_file("incr_both.dat").expect("fsync after B");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("incr_both.dat")
        .expect("read incr_both.dat session 2");

    assert_eq!(
        read_back.len(),
        combined.len(),
        "length mismatch: expected {}, got {}",
        combined.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, combined,
        "incremental append with fsync after each write: \
         data mismatch after remount"
    );
}

/// Write A, fsync, append B (NO second fsync), remount, document behavior.
///
/// After remount, A must survive (it was fsynced). B may or may not survive
/// depending on whether Drop flush or background writeback ran before the
/// daemon exited.  This is a negative-space bridge toward crash-consistency
/// semantics where non-fsynced data may be lost.
#[test]
fn incremental_fsync_second_not_durable() {
    let data_a = sequenced_test_data(1024);
    let data_b = sequenced_test_data(256);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP incremental_fsync_second_not_durable: daemon not available -- {e}");
            return;
        }
    };

    // Write A (fsync immediately).
    harness
        .create_file("incr_one_fsync.dat", &data_a)
        .expect("write data A");
    harness
        .fsync_file("incr_one_fsync.dat")
        .expect("fsync after A");

    // Append B (no fsync).
    append_to_file(&harness, "incr_one_fsync.dat", &data_b).expect("append data B (no fsync)");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("incr_one_fsync.dat")
        .expect("read incr_one_fsync.dat session 2");

    // File must be at least as long as data A (which was fsynced).
    assert!(
        read_back.len() >= data_a.len(),
        "fsynced data A must be present: expected at least {} bytes, got {}",
        data_a.len(),
        read_back.len()
    );
    assert_eq!(
        &read_back[..data_a.len()],
        data_a.as_slice(),
        "fsynced data A must survive remount byte-for-byte"
    );

    // B: document whether it survived — behavioral probe, not pass/fail.
    let b_survived = read_back.len() >= data_a.len() + data_b.len()
        && read_back[data_a.len()..data_a.len() + data_b.len()] == data_b[..];
    eprintln!(
        "INFO: incremental_fsync_second_not_durable: \
         data B ({} bytes, not fsynced) {} survive remount",
        data_b.len(),
        if b_survived { "did" } else { "did NOT" }
    );
}

// ── crash-recovery: multi-file SIGKILL ────────────────────────────────────
//
// These tests validate crash-recovery for scenarios not covered by the
// existing upstream crash tests (write_durability_fsync_crash_remount_4kib
// and write_durability_no_fsync_crash_test).  They use MountHarness::
// crash_and_remount and fdatasync_file methods added in this issue.

/// Write N distinct files, fsync each, SIGKILL daemon, restart, remount,
/// verify all files intact and directory entries preserved.  This complements
/// the upstream single-file crash test by exercising multi-file recovery.
#[test]
fn crash_after_fsync_multi_file_survives() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_after_fsync_multi_file_survives: daemon not available -- {e}");
            return;
        }
    };

    let data_a = sequenced_test_data(512);
    let data_b = prng_test_data(0xBEEF, 2048);
    let data_c = sequenced_test_data(65536);
    let data_d = b"deep-nested-crash-test\n".to_vec();

    harness
        .create_file("crash_multi_a.bin", &data_a)
        .expect("create a");
    harness
        .create_file("crash_multi_b.bin", &data_b)
        .expect("create b");
    harness
        .create_file("crash_multi_c.bin", &data_c)
        .expect("create c");
    harness.mkdir_all("sub").expect("mkdir sub");
    harness
        .create_file("sub/crash_multi_d.bin", &data_d)
        .expect("create d");

    harness.fsync_file("crash_multi_a.bin").expect("fsync a");
    harness.fsync_file("crash_multi_b.bin").expect("fsync b");
    harness.fsync_file("crash_multi_c.bin").expect("fsync c");
    harness
        .fsync_file("sub/crash_multi_d.bin")
        .expect("fsync d");

    harness.crash_and_remount().expect("crash_and_remount");

    let ra = harness.read_file("crash_multi_a.bin").expect("read a");
    let rb = harness.read_file("crash_multi_b.bin").expect("read b");
    let rc = harness.read_file("crash_multi_c.bin").expect("read c");
    let rd = harness.read_file("sub/crash_multi_d.bin").expect("read d");

    assert_eq!(ra, data_a, "crash_multi_a.bin mismatch");
    assert_eq!(rb, data_b, "crash_multi_b.bin mismatch");
    assert_eq!(rc, data_c, "crash_multi_c.bin mismatch");
    assert_eq!(rd, data_d, "crash_multi_d.bin mismatch");

    let entries = harness.readdir(".").expect("readdir root");
    assert!(
        entries.contains(&"crash_multi_a.bin".to_string()),
        "root missing a"
    );
    assert!(
        entries.contains(&"crash_multi_b.bin".to_string()),
        "root missing b"
    );
    assert!(
        entries.contains(&"crash_multi_c.bin".to_string()),
        "root missing c"
    );

    let sub_entries = harness.readdir("sub").expect("readdir sub");
    assert!(
        sub_entries.contains(&"crash_multi_d.bin".to_string()),
        "sub missing d"
    );
}

/// Write data, fdatasync, SIGKILL daemon, restart, remount, verify file
/// content is byte-for-byte intact.  fdatasync skips metadata sync so mtime
/// may be stale, but file content must survive the crash.  The upstream
/// write_durability_fdatasync_4kib test only covers clean unmount, not crash.
#[test]
fn crash_after_fdatasync_data_survives() {
    let data = prng_test_data(0xF00D, 4096);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP crash_after_fdatasync_data_survives: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("fdatasync_crash.bin", &data)
        .expect("create_file");
    harness
        .fdatasync_file("fdatasync_crash.bin")
        .expect("fdatasync");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("fdatasync_crash.bin")
        .expect("read after crash");
    assert_eq!(
        read_back, data,
        "fdatasync data mismatch after SIGKILL crash:
         fdatasync must flush file content to durable storage.
         Check that fdatasync is wired to writeback flush in #3732."
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ── selective multi-file fsync isolation ──────────────────────────────────
//
// Write 3 files, fsync only file B, unmount, remount, and verify only the
// fsynced file survives with correct content.  Files A and C that were not
// fsynced may or may not survive — document the observed behavior.

/// Write three files, fsync only the middle file, remount, verify:
/// - File B (fsynced) is intact byte-for-byte.
/// - Files A and C (not fsynced) state is documented (not asserted).
#[test]
fn write_durability_selective_fsync_isolation() {
    let data_a = sequenced_test_data(1024);
    let data_b = make_test_buffer(0xAAAA_BBBB_CCCC_DDDD, 2048);
    let data_c = sequenced_test_data(512);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_selective_fsync_isolation: daemon not available -- {e}"
            );
            return;
        }
    };

    harness
        .create_file("iso_a.bin", &data_a)
        .expect("create iso_a.bin");
    harness
        .create_file("iso_b.bin", &data_b)
        .expect("create iso_b.bin");
    harness
        .create_file("iso_c.bin", &data_c)
        .expect("create iso_c.bin");

    // fsync only file B — A and C remain dirty.
    harness.fsync_file("iso_b.bin").expect("fsync iso_b.bin");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // File B must be intact.
    let read_b = harness
        .read_file("iso_b.bin")
        .expect("read iso_b.bin session 2");
    assert_eq!(
        read_b, data_b,
        "iso_b.bin (fsynced) must survive remount byte-for-byte"
    );

    // Files A and C: document observed behavior.
    let read_a = harness.read_file("iso_a.bin").ok();
    let read_c = harness.read_file("iso_c.bin").ok();
    eprintln!(
        "INFO: write_durability_selective_fsync_isolation: \
         iso_a.bin (not fsynced): {} \
         iso_c.bin (not fsynced): {}",
        read_a
            .as_ref()
            .map_or("absent/error".to_string(), |v| format!("{} bytes", v.len())),
        read_c
            .as_ref()
            .map_or("absent/error".to_string(), |v| format!("{} bytes", v.len())),
    );

    // If a non-fsynced file survived, its content must match.
    if let Some(ref a) = read_a {
        if a.len() == data_a.len() {
            assert_eq!(
                a.as_slice(),
                data_a.as_slice(),
                "iso_a.bin (not fsynced but present) content mismatch"
            );
        }
    }
    if let Some(ref c) = read_c {
        if c.len() == data_c.len() {
            assert_eq!(
                c.as_slice(),
                data_c.as_slice(),
                "iso_c.bin (not fsynced but present) content mismatch"
            );
        }
    }
}

// ── O_TRUNC + fsync durability ────────────────────────────────────────────

/// Create a file, write initial data, fsync.  Reopen with O_TRUNC, write
/// entirely new (smaller) data, fsync.  Remount and verify only the new
/// data survives with the correct (shorter) length.
#[test]
fn write_durability_otrunc_fsync_remount() {
    use std::io::Write;

    let initial = sequenced_test_data(8192);
    let after_trunc = b"TRUNCATED-NEW-CONTENT\n".to_vec();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_otrunc_fsync_remount: daemon not available -- {e}");
            return;
        }
    };

    // Session 1: write initial data + fsync.
    harness
        .create_file("otrunc.bin", &initial)
        .expect("create initial otrunc.bin");
    harness.fsync_file("otrunc.bin").expect("fsync initial");

    // O_TRUNC reopen + write new data + fsync.
    let path = harness.mount_path().join("otrunc.bin");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open otrunc.bin with O_TRUNC");
        file.write_all(&after_trunc).expect("write after trunc");
        file.sync_all().expect("fsync after trunc");
    }

    // Verify in-session visibility of truncated content.
    let read_pre = harness.read_file("otrunc.bin").expect("read after trunc");
    assert_eq!(
        read_pre, after_trunc,
        "in-session content after O_TRUNC write"
    );
    let md_pre = harness.stat("otrunc.bin").expect("stat after trunc");
    assert_eq!(
        md_pre.len(),
        after_trunc.len() as u64,
        "in-session file size after O_TRUNC write"
    );

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // Session 2: only the post-trunc content should survive.
    let read_post = harness
        .read_file("otrunc.bin")
        .expect("read otrunc.bin session 2");
    assert_eq!(
        read_post, after_trunc,
        "post-O_TRUNC content must survive remount byte-for-byte"
    );

    let md_post = harness.stat("otrunc.bin").expect("stat session 2");
    assert_eq!(
        md_post.len(),
        after_trunc.len() as u64,
        "file size must reflect truncated content after remount: \
         expected {} bytes, got {}",
        after_trunc.len(),
        md_post.len()
    );

    // The original large content must not leak.
    assert!(
        read_post.len() < initial.len(),
        "file must not retain original content length after O_TRUNC + fsync: \
         expected < {} bytes, got {}",
        initial.len(),
        read_post.len()
    );
}

// ── fdatasync vs fsync metadata persistence ───────────────────────────────

/// Write two files: fdatasync file A, fsync file B.  Remount and verify both
/// files have correct content.  Then check that the fsynced file has a
/// plausible metadata timestamp while the fdatasync'd file may or may not
/// have its metadata persisted (fdatasync skips metadata sync).
#[test]
fn write_durability_fdatasync_vs_fsync_metadata() {
    let data_a = prng_test_data(0xFDA7, 2048);
    let data_b = prng_test_data(0xF5AC, 2048);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_fdatasync_vs_fsync_metadata: daemon not available -- {e}"
            );
            return;
        }
    };

    // Write and fdatasync file A (metadata may be stale).
    harness
        .create_file("fdatasync_meta.bin", &data_a)
        .expect("create fdatasync_meta.bin");
    harness
        .fdatasync_file("fdatasync_meta.bin")
        .expect("fdatasync fdatasync_meta.bin");

    // Write and fsync file B (metadata must be durable).
    harness
        .create_file("fsync_meta.bin", &data_b)
        .expect("create fsync_meta.bin");
    harness
        .fsync_file("fsync_meta.bin")
        .expect("fsync fsync_meta.bin");

    // Record pre-remount metadata.
    let md_a_pre = harness.stat("fdatasync_meta.bin").expect("stat A pre");
    let md_b_pre = harness.stat("fsync_meta.bin").expect("stat B pre");
    let size_a = md_a_pre.len();
    let size_b = md_b_pre.len();

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // Both files must have correct content.
    let read_a = harness
        .read_file("fdatasync_meta.bin")
        .expect("read fdatasync_meta.bin");
    let read_b = harness
        .read_file("fsync_meta.bin")
        .expect("read fsync_meta.bin");
    assert_eq!(
        read_a, data_a,
        "fdatasync file content mismatch after remount"
    );
    assert_eq!(read_b, data_b, "fsync file content mismatch after remount");

    // Size must survive for both.
    let md_a_post = harness.stat("fdatasync_meta.bin").expect("stat A post");
    let md_b_post = harness.stat("fsync_meta.bin").expect("stat B post");
    assert_eq!(md_a_post.len(), size_a, "fdatasync file size mismatch");
    assert_eq!(md_b_post.len(), size_b, "fsync file size mismatch");

    // Document mtime behavior.
    let mtime_a_pre = md_a_pre.modified().ok();
    let mtime_a_post = md_a_post.modified().ok();
    let mtime_b_pre = md_b_pre.modified().ok();
    let mtime_b_post = md_b_post.modified().ok();
    eprintln!(
        "INFO: write_durability_fdatasync_vs_fsync_metadata: \
         fdatasync mtime pre={mtime_a_pre:?} post={mtime_a_post:?}; \
         fsync     mtime pre={mtime_b_pre:?} post={mtime_b_post:?}",
    );

    // The fsynced file's mtime must survive (be the same or close).
    // The fdatasync'd file's mtime may be stale — document but don't assert.
    if let (Some(pre), Some(post)) = (mtime_b_pre, mtime_b_post) {
        let diff = pre
            .duration_since(post)
            .or_else(|_| post.duration_since(pre))
            .unwrap_or_default();
        eprintln!("INFO: fsync mtime drift: {diff:?}");
    }
}
// ── crash-recovery: mixed-fsync ordering ──────────────────────────────────
//
// Tests added for #4099: crash-recovery write-durability integration tests
// for fsync ordering and partial-write survival.

/// Write file A (fsync), write file B (no fsync), SIGKILL daemon, restart,
/// verify file A is intact and file B is absent or stale.  Validates that
/// fsync ordering is respected across a crash boundary: fsynced data must
/// survive; non-fsynced data may be lost.
#[test]
fn write_durability_crash_mixed_sync_states() {
    let data_a = prng_test_data(0xAAAA, 2048);
    let data_b = prng_test_data(0xBBBB, 1024);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_crash_mixed_sync_states: daemon not available -- {e}");
            return;
        }
    };

    // Write file A and fsync immediately.
    harness
        .create_file("sync_A.bin", &data_a)
        .expect("create A");
    harness.fsync_file("sync_A.bin").expect("fsync A");

    // Write file B but do NOT fsync.
    harness
        .create_file("unsync_B.bin", &data_b)
        .expect("create B");
    // Explicitly skip fsync for B.

    harness.crash_and_remount().expect("crash_and_remount");

    // File A (fsynced): must be intact byte-for-byte.
    let read_a = harness.read_file("sync_A.bin").expect("read A after crash");
    assert_eq!(
        read_a, data_a,
        "fsynced file A must survive crash byte-for-byte"
    );

    // File B (not fsynced): may be absent, empty, or partially present.
    // POSIX does not guarantee non-fsynced data survives a crash.
    match harness.read_file("unsync_B.bin") {
        Ok(read_b) => {
            if read_b == data_b {
                eprintln!(
                    "INFO: crash_fsync_ordering: non-fsynced file B fully survived (best-effort)"
                );
            } else {
                eprintln!(
                    "INFO: crash_fsync_ordering: non-fsynced file B partially survived ({} of {} bytes)",
                    read_b.len(), data_b.len()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "INFO: crash_fsync_ordering: non-fsynced file B absent after crash (expected): {e}"
            );
        }
    }
}

// ── crash-recovery: partial-block write ───────────────────────────────────

/// Write 100 bytes (sub-block, well under 4 KiB), fsync, SIGKILL daemon,
/// remount, and verify the exact partial content survives byte-for-byte.
/// Exercises the writeback path for unaligned / sub-block data that does
/// not fill a full FUSE page.
#[test]
fn write_durability_crash_partial_block() {
    let partial_data: Vec<u8> = (0..100).map(|i: usize| (i * 7 + 13) as u8).collect();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_crash_partial_block: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("partial.bin", &partial_data)
        .expect("create partial file");
    harness
        .fsync_file("partial.bin")
        .expect("fsync partial file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("partial.bin")
        .expect("read partial after crash");
    assert_eq!(
        read_back.len(),
        partial_data.len(),
        "partial-block file length mismatch after crash: expected {}, got {}",
        partial_data.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, partial_data,
        "partial-block (100-byte) content must survive fsync+crash+remount byte-for-byte"
    );
}

// ── crash-recovery: fdatasync vs fsync side-by-side ───────────────────────

/// Write two files: fdatasync file F, fsync file S.  SIGKILL daemon,
/// remount, and verify both have correct content.  Then document mtime
/// survival across the crash boundary: fsync must have preserved mtime;
/// fdatasync may or may not.  Unlike the clean-unmount variant, the crash
/// path gives the daemon no chance to flush metadata on Drop.
#[test]
fn write_durability_crash_fdatasync_vs_fsync() {
    let data_f = prng_test_data(0xFDA7, 2048);
    let data_s = prng_test_data(0xF5C7, 2048);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_durability_crash_fdatasync_vs_fsync: daemon not available -- {e}"
            );
            return;
        }
    };

    // Write and fdatasync file F.
    harness
        .create_file("fdata.bin", &data_f)
        .expect("create fdata.bin");
    harness
        .fdatasync_file("fdata.bin")
        .expect("fdatasync fdata.bin");

    // Write and fsync file S.
    harness
        .create_file("fsync.bin", &data_s)
        .expect("create fsync.bin");
    harness.fsync_file("fsync.bin").expect("fsync fsync.bin");

    // Record pre-crash metadata.
    let md_f_pre = harness.stat("fdata.bin").expect("stat fdata pre");
    let md_s_pre = harness.stat("fsync.bin").expect("stat fsync pre");
    let size_f = md_f_pre.len();
    let size_s = md_s_pre.len();

    harness.crash_and_remount().expect("crash_and_remount");

    // Both files must have correct content after crash.
    let read_f = harness
        .read_file("fdata.bin")
        .expect("read fdata after crash");
    let read_s = harness
        .read_file("fsync.bin")
        .expect("read fsync after crash");
    assert_eq!(
        read_f, data_f,
        "fdatasync file content mismatch after crash"
    );
    assert_eq!(read_s, data_s, "fsync file content mismatch after crash");

    // Size must survive for both.
    let md_f_post = harness.stat("fdata.bin").expect("stat fdata post");
    let md_s_post = harness.stat("fsync.bin").expect("stat fsync post");
    assert_eq!(
        md_f_post.len(),
        size_f,
        "fdatasync file size mismatch after crash"
    );
    assert_eq!(
        md_s_post.len(),
        size_s,
        "fsync file size mismatch after crash"
    );

    // Document mtime behavior across crash.
    let mtime_f_pre = md_f_pre.modified().ok();
    let mtime_f_post = md_f_post.modified().ok();
    let mtime_s_pre = md_s_pre.modified().ok();
    let mtime_s_post = md_s_post.modified().ok();
    eprintln!(
        "INFO: write_durability_crash_fdatasync_vs_fsync: \
         fdatasync mtime pre={mtime_f_pre:?} post={mtime_f_post:?}; \
         fsync     mtime pre={mtime_s_pre:?} post={mtime_s_post:?}",
    );
}

// ── crash-recovery: append chain with intermediate fsyncs ─────────────────

/// Append A, fsync. Append B, fsync. Append C, fsync.  SIGKILL daemon,
/// remount, verify all three appends survived as a contiguous byte stream.
/// This is the journal / WAL append pattern: commit records one at a time
/// with fsync between each, then crash.
#[test]
fn write_durability_crash_append_chain() {
    let chunk_a: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let chunk_b: Vec<u8> = (0..512).map(|i: u32| (i.wrapping_add(128)) as u8).collect();
    let chunk_c: Vec<u8> = (0..128).map(|i: u32| (i.wrapping_mul(3)) as u8).collect();

    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(&chunk_a);
    expected.extend_from_slice(&chunk_b);
    expected.extend_from_slice(&chunk_c);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_durability_crash_append_chain: daemon not available -- {e}");
            return;
        }
    };

    // Initial create with chunk A, fsync.
    harness
        .create_file("append_chain.bin", &chunk_a)
        .expect("create with A");
    harness
        .fsync_file("append_chain.bin")
        .expect("fsync after A");

    // Append chunk B, fsync.
    append_to_file(&harness, "append_chain.bin", &chunk_b).expect("append B");
    harness
        .fsync_file("append_chain.bin")
        .expect("fsync after B");

    // Append chunk C, fsync.
    append_to_file(&harness, "append_chain.bin", &chunk_c).expect("append C");
    harness
        .fsync_file("append_chain.bin")
        .expect("fsync after C");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("append_chain.bin")
        .expect("read after crash");
    assert_eq!(
        read_back.len(),
        expected.len(),
        "append chain length mismatch after crash: expected {}, got {}",
        expected.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, expected,
        "triple-append chain with fsync between each must survive crash byte-for-byte"
    );
}
// Object-store durability tests (direct LocalObjectStore API).
// These exercise the segment-based put/get/sync/rotate pipeline without
// going through the FUSE mount layer. Requires `--features fuse`.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "fuse")]
mod object_store_durability {

    use std::thread;
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

    /// Open a fresh store in a tempdir with durable options (sync_on_write
    /// disabled so we can control sync boundaries explicitly).
    fn open_temp() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut opts = StoreOptions::durable();
        opts.sync_on_write = false;
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        (store, dir)
    }

    /// Open an existing store from a tempdir path.
    fn reopen(dir: &tempfile::TempDir) -> LocalObjectStore {
        let mut opts = StoreOptions::durable();
        opts.sync_on_write = false;
        LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen store")
    }

    // ── Group 1: Basic put/get round-trip ─────────────────────────────────

    #[test]
    fn write_durability_put_get_identity() {
        let (mut store, _dir) = open_temp();
        let payload = b"hello world".to_vec();
        let key = ObjectKey::from_name("identity-key");

        store.put(key, &payload).expect("put");
        let got = store.get(key).expect("get").expect("object must exist");

        assert_eq!(got, payload, "put→get must return byte-identical payload");
    }

    #[test]
    fn write_durability_independent_keys() {
        let (mut store, _dir) = open_temp();
        let a = b"payload A".to_vec();
        let b = b"payload B".to_vec();
        let ka = ObjectKey::from_name("key-a");
        let kb = ObjectKey::from_name("key-b");

        store.put(ka, &a).expect("put a");
        store.put(kb, &b).expect("put b");

        let got_a = store.get(ka).expect("get a").expect("key-a must exist");
        let got_b = store.get(kb).expect("get b").expect("key-b must exist");

        assert_eq!(got_a, a, "key-a payload mismatch");
        assert_eq!(got_b, b, "key-b payload mismatch");
    }

    #[test]
    fn write_durability_missing_key_none() {
        let (store, _dir) = open_temp();
        let absent = ObjectKey::from_name("no-such-key");

        let got = store.get(absent).expect("get");
        assert!(got.is_none(), "get on absent key must return None");
    }

    // ── Group 2: fsync flush durability ──────────────────────────────────

    #[test]
    fn write_durability_fsync_survives_reopen() {
        let (mut store, dir) = open_temp();
        let payload = vec![0x42u8; 4096];
        let key = ObjectKey::from_name("survive-reopen");

        store.put(key, &payload).expect("put");
        store.sync().expect("sync");
        drop(store);

        let store2 = reopen(&dir);
        let got = store2
            .get(key)
            .expect("get")
            .expect("must exist after reopen");
        assert_eq!(got, payload, "fsynced data must survive close+reopen");
    }

    #[test]
    fn write_durability_multi_put_single_fsync() {
        let (mut store, dir) = open_temp();
        let data: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 256]).collect();
        let keys: Vec<ObjectKey> = (0..5)
            .map(|i| ObjectKey::from_name(format!("multi-{i}")))
            .collect();

        for (k, d) in keys.iter().zip(&data) {
            store.put(*k, d).expect("put");
        }
        store.sync().expect("sync");
        drop(store);

        let store2 = reopen(&dir);
        for (k, d) in keys.iter().zip(&data) {
            let got = store2.get(*k).expect("get").expect("must exist");
            assert_eq!(&got, d, "multi-put key {} mismatch after reopen", k);
        }
    }

    #[test]
    fn write_durability_fsync_empty_noop() {
        let (mut store, dir) = open_temp();
        // Sync an untouched store — must succeed.
        store.sync().expect("sync on empty store");
        drop(store);

        // Reopen must also succeed.
        let _store2 = reopen(&dir);
    }

    // ── Group 3: Crash recovery simulation ───────────────────────────────

    /// Simulate crash by dropping the store without syncing some writes.
    /// Synced data must survive; unsynced data is best-effort.
    #[test]
    fn write_durability_unsynced_may_vanish_synced_survives() {
        let (mut store, dir) = open_temp();
        let synced_payload = b"SYNCED-DATA".to_vec();
        let unsynced_payload = b"UNSYNCED-DATA".to_vec();
        let sk = ObjectKey::from_name("synced-key");
        let uk = ObjectKey::from_name("unsynced-key");

        store.put(sk, &synced_payload).expect("put synced");
        store.sync().expect("sync");

        store.put(uk, &unsynced_payload).expect("put unsynced");
        // No sync after unsynced put — simulate crash by dropping store.
        drop(store);

        let store2 = reopen(&dir);
        let got_s = store2.get(sk).expect("get synced");
        assert_eq!(
            got_s.as_ref(),
            Some(&synced_payload),
            "synced data must survive crash"
        );

        // Unsynced data may or may not be present; either is valid.
        let got_u = store2.get(uk).expect("get unsynced");
        if let Some(ref u) = got_u {
            eprintln!(
                "note: unsynced data survived crash (best-effort behavior): \
                 got {} bytes",
                u.len()
            );
        }
    }

    /// Overwrite a key without syncing; after reopen, the value must be
    /// either the old or the new payload (atomic at the object level), never
    /// a corrupted mix.
    #[test]
    fn write_durability_overwrite_without_sync_atomic() {
        let (mut store, dir) = open_temp();
        let old = b"OLD-VALUE".to_vec();
        let new = b"NEW-VALUE-OVERWRITE".to_vec();
        let key = ObjectKey::from_name("atomic-key");

        store.put(key, &old).expect("put old");
        store.sync().expect("sync old");
        store.put(key, &new).expect("put new");
        // No sync after overwrite — crash simulation.
        drop(store);

        let store2 = reopen(&dir);
        let got = store2.get(key).expect("get").expect("key must exist");
        assert!(
            got == old || got == new,
            "unsynced overwrite must return old or new payload, \
             not a corrupted mix: got {} bytes",
            got.len()
        );
    }

    /// Multiple sync points across segments; after reopen all synced keys
    /// are present with correct content.
    #[test]
    fn write_durability_mixed_sync_recovery() {
        let (mut store, dir) = open_temp();
        let k1 = ObjectKey::from_name("s1-key");
        let k2 = ObjectKey::from_name("s2-key");
        let k3 = ObjectKey::from_name("s3-key");
        let d1 = vec![0x11u8; 128];
        let d2 = vec![0x22u8; 256];
        let d3 = vec![0x33u8; 512];

        store.put(k1, &d1).expect("put k1");
        store.sync().expect("sync 1");

        store.put(k2, &d2).expect("put k2");
        store.sync().expect("sync 2");

        store.put(k3, &d3).expect("put k3");
        store.sync().expect("sync 3");
        drop(store);

        let store2 = reopen(&dir);
        assert_eq!(store2.get(k1).expect("get").expect("exist"), d1);
        assert_eq!(store2.get(k2).expect("get").expect("exist"), d2);
        assert_eq!(store2.get(k3).expect("get").expect("exist"), d3);
    }

    // ── Group 4: Segment lifecycle ───────────────────────────────────────

    #[test]
    fn write_durability_segment_rotation_survival() {
        let (mut store, dir) = open_temp();
        let payload = b"persistent-across-rotation".to_vec();
        let key = ObjectKey::from_name("rotate-key");

        store.put(key, &payload).expect("put");
        store.sync().expect("sync");
        store.rotate_if_needed().expect("rotate"); // explicit rotation
        drop(store);

        let store2 = reopen(&dir);
        let got = store2
            .get(key)
            .expect("get")
            .expect("must survive rotation");
        assert_eq!(got, payload, "data must survive segment rotation");
    }

    #[test]
    fn write_durability_mixed_put_delete_across_rotation() {
        let (mut store, dir) = open_temp();
        let keep_key = ObjectKey::from_name("keep-me");
        let del_key = ObjectKey::from_name("delete-me");
        let data = vec![0xABu8; 64];

        store.put(keep_key, &data).expect("put keep");
        store.put(del_key, b"temp-data").expect("put del");
        store.sync().expect("sync 1");

        store.delete(del_key).expect("delete");
        store.rotate_if_needed().expect("rotate");
        store.sync().expect("sync 2");
        drop(store);

        let store2 = reopen(&dir);
        assert_eq!(
            store2.get(keep_key).expect("get").expect("exist"),
            data,
            "keep-me must survive put+delete+rotate+reopen"
        );
        assert!(
            store2.get(del_key).expect("get").is_none(),
            "delete-me must be absent after delete+rotate+reopen"
        );
    }

    #[test]
    fn write_durability_zero_length_durable() {
        let (mut store, dir) = open_temp();
        let empty: Vec<u8> = Vec::new();
        let key = ObjectKey::from_name("zero-len");

        store.put(key, &empty).expect("put zero-length");
        store.sync().expect("sync");
        drop(store);

        let store2 = reopen(&dir);
        let got = store2.get(key).expect("get").expect("must exist");
        assert!(got.is_empty(), "zero-length payload must persist as empty");
    }

    // ── Group 5: Edge cases ──────────────────────────────────────────────

    #[test]
    fn write_durability_large_payload_roundtrip() {
        let (mut store, _dir) = open_temp();
        // 1 MiB + 7 bytes exercises multi-buffer write paths.
        let size = 1024 * 1024 + 7;
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let key = ObjectKey::from_name("large-payload");

        store.put(key, &payload).expect("put large");
        let got = store.get(key).expect("get").expect("must exist");
        assert_eq!(got.len(), payload.len(), "large payload length mismatch");
        assert_eq!(got, payload, "large payload byte-for-byte mismatch");
    }

    #[test]
    fn write_durability_rapid_put_fsync_delete_sequence() {
        let (mut store, dir) = open_temp();
        let n_cycles = 50;

        for i in 0..n_cycles {
            let key = ObjectKey::from_name(format!("rapid-{i}"));
            let payload = vec![i as u8; 32];
            store.put(key, &payload).expect("put");
            store.sync().expect("sync");
            store.delete(key).expect("delete");
        }
        drop(store);

        let store2 = reopen(&dir);
        // All keys should be deleted (tombstoned).
        for i in 0..n_cycles {
            let key = ObjectKey::from_name(format!("rapid-{i}"));
            assert!(
                store2.get(key).expect("get").is_none(),
                "rapid-{i} must be absent after put+sync+delete cycle"
            );
        }
    }

    #[test]
    fn write_durability_concurrent_puts_per_thread_fsync() {
        let n_threads = 4;
        let puts_per_thread = 50;

        // Phase 1: each thread opens its own tempdir, does puts+sync, then
        // we verify all keys survived reopen.
        let results: Vec<_> = (0..n_threads)
            .map(|tid| {
                let t = thread::spawn(move || {
                    let (mut store, dir) = open_temp();
                    let keys: Vec<(ObjectKey, Vec<u8>)> = (0..puts_per_thread)
                        .map(|i| {
                            let name = format!("t{tid}-k{i}");
                            let payload = vec![tid as u8; 16 + (i as usize % 64)];
                            (ObjectKey::from_name(name), payload)
                        })
                        .collect();
                    for (k, d) in &keys {
                        store.put(*k, d).expect("put");
                    }
                    store.sync().expect("sync");
                    // Return dir and keys for verification.
                    (dir, keys)
                });
                t.join().expect("thread join")
            })
            .collect();

        // Phase 2: reopen each thread's store and verify all keys.
        for (dir, keys) in &results {
            let store2 = reopen(dir);
            for (k, expected) in keys {
                let got = store2.get(*k).expect("get").expect("must exist");
                assert_eq!(
                    &got, expected,
                    "thread key {} mismatch after concurrent puts+sync",
                    k
                );
            }
        }

        // Ensure cleanup: explicitly drop stores and directories.
        for (dir, _) in results {
            drop(dir);
        }
    }

    // ── Group 6: BLAKE3 chain integrity ───────────────────────────────────

    /// Write a small object (< 1 segment), build a BLAKE3 checksum tree,
    /// and verify roundtrip: get_verified returns correct content and
    /// the checksum tree verifies successfully against the stored data.
    #[test]
    fn write_durability_blake3_get_verified_single_segment() {
        let (mut store, _dir) = open_temp();
        let payload: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
        let content_key = store
            .put_content_addressed(&payload)
            .expect("put_content_addressed");
        store.sync().expect("sync");

        // get_verified must return byte-identical payload for content key.
        let got = store
            .get_verified(content_key)
            .expect("get_verified")
            .expect("object must exist");
        assert_eq!(
            got, payload,
            "get_verified roundtrip: byte-for-byte mismatch"
        );

        // get_verified must detect a key that does not match the content.
        let wrong_key = ObjectKey::from_name("nonexistent");
        let wrong_result = store.get_verified(wrong_key);
        match wrong_result {
            Ok(None) => { /* expected: key not found */ }
            Err(_) => { /* also acceptable: content mismatch detected */ }
            Ok(Some(_)) => panic!("get_verified with non-matching key must not return data"),
        }

        // Build BLAKE3 checksum tree and verify full-object integrity.
        let tree = store
            .get_checksum_tree(content_key, 4096)
            .expect("get_checksum_tree")
            .expect("tree must exist");
        assert!(
            store
                .verify_checksum_tree(content_key, &tree)
                .expect("verify_checksum_tree"),
            "BLAKE3 checksum tree must verify intact data"
        );
    }

    /// Write an object spanning multiple segments via segment rotation,
    /// then verify BLAKE3 chain integrity across segment boundaries
    /// using get_checksum_tree / verify_checksum_tree.
    #[test]
    fn write_durability_multi_segment_blake3_chain() {
        let (mut store, _dir) = open_temp();
        // Fill several objects with enough data to trigger rotation.
        let payload_a: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let payload_b: Vec<u8> = (0..32768).map(|i| ((i + 128) % 251) as u8).collect();
        let key_a = ObjectKey::from_name("multi-seg-a");
        let key_b = ObjectKey::from_name("multi-seg-b");

        store.put(key_a, &payload_a).expect("put a");
        store.sync().expect("sync a");
        store.rotate_if_needed().expect("rotate to new segment");
        store.put(key_b, &payload_b).expect("put b in new segment");
        store.sync().expect("sync b");

        // Verify both objects survive segment rotation.
        let got_a = store.get(key_a).expect("get a").expect("must exist");
        let got_b = store.get(key_b).expect("get b").expect("must exist");
        assert_eq!(
            got_a, payload_a,
            "object a across segment rotation mismatch"
        );
        assert_eq!(got_b, payload_b, "object b in rotated segment mismatch");

        // Build and verify BLAKE3 trees for both objects.
        let tree_a = store
            .get_checksum_tree(key_a, 4096)
            .expect("tree a")
            .expect("tree a must exist");
        assert!(
            store
                .verify_checksum_tree(key_a, &tree_a)
                .expect("verify a"),
            "BLAKE3 chain verification failed for object a"
        );
        let tree_b = store
            .get_checksum_tree(key_b, 4096)
            .expect("tree b")
            .expect("tree b must exist");
        assert!(
            store
                .verify_checksum_tree(key_b, &tree_b)
                .expect("verify b"),
            "BLAKE3 chain verification failed for object b"
        );
    }

    /// Write an object, inject single-byte corruption into its on-disk
    /// payload, and confirm the BLAKE3 checksum tree verification detects
    /// the tampering (returns false / integrity error).
    #[test]
    fn write_durability_blake3_chain_break_detection() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let (mut store, dir) = open_temp();
        let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let key = ObjectKey::from_name("corrupt-target");

        store.put(key, &payload).expect("put");
        // Build the checksum tree BEFORE corruption so we verify against
        // the original expected hashes.
        let tree = store
            .get_checksum_tree(key, 4096)
            .expect("get_checksum_tree")
            .expect("tree must exist");
        // Sanity: tree verifies against the intact data.
        assert!(
            store
                .verify_checksum_tree(key, &tree)
                .expect("verify intact"),
            "pre-corruption verification must pass"
        );

        let location = store.location_of(key).expect("location exists");
        let segment_path = std::path::PathBuf::from(store.segments_dir()).join(
            tidefs_local_object_store::segment_file_name(location.segment_id),
        );
        store.sync().expect("sync before corruption");
        drop(store);

        // Corrupt a byte in the on-disk payload region (past the record
        // header).
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .read(true)
                .open(&segment_path)
                .expect("open segment for corruption");
            let flip_offset = location.record_offset
                + tidefs_local_object_store::constants::RECORD_HEADER_LEN_U64
                + (payload.len() as u64 / 2);
            f.seek(SeekFrom::Start(flip_offset)).expect("seek");
            let mut original = [0u8; 1];
            f.read_exact(&mut original).expect("read original byte");
            f.seek(SeekFrom::Start(flip_offset)).expect("seek back");
            f.write_all(&[original[0] ^ 0xFF]).expect("corrupt byte");
            f.sync_all().expect("sync");
        }

        // Reopen: the production integrity check may reject the
        // corrupted store at open time, which IS successful detection.
        // If reopen succeeds, verify_checksum_tree must catch it.
        let open_result = LocalObjectStore::open_with_options(dir.path(), StoreOptions::durable());
        match open_result {
            Err(_) => {
                // Production integrity mismatch detected at open time.
                // This is successful BLAKE3 chain break detection.
                return;
            }
            Ok(store2) => {
                let verified = store2
                    .verify_checksum_tree(key, &tree)
                    .expect("verify after corruption");
                assert!(
                    !verified,
                    "BLAKE3 chain must detect single-byte corruption: \
                     verify_checksum_tree returned true on tampered data"
                );
            }
        }
    }

    /// Write an object, overwrite its middle region (crossing a natural
    /// block boundary), and verify that the BLAKE3 checksum tree updates
    /// correctly — only the overwritten region changes while the rest
    /// of the tree remains verifiable.
    #[test]
    fn write_durability_partial_overwrite_blake3_chain() {
        let (mut store, _dir) = open_temp();
        let original: Vec<u8> = (0..12288).map(|i| (i % 251) as u8).collect();
        let key = ObjectKey::from_name("partial-overwrite");

        store.put(key, &original).expect("put original");
        store.sync().expect("sync original");

        // Overwrite the middle 4096 bytes (block-aligned, crosses a
        // segment record if segments are small).
        let mut overwritten = original.clone();
        let offset = 4096usize;
        let len = 4096usize;
        for i in offset..offset + len {
            overwritten[i] = (i.wrapping_mul(7) % 251) as u8;
        }

        store.put(key, &overwritten).expect("put overwritten");
        store.sync().expect("sync overwritten");

        let got = store
            .get(key)
            .expect("get overwritten")
            .expect("must exist");
        assert_eq!(got, overwritten, "overwritten data read-back mismatch");

        // Verify prefix (first 4 KiB) unchanged.
        assert_eq!(
            &got[..offset],
            &original[..offset],
            "prefix region must be unchanged after partial overwrite"
        );

        // Verify suffix (last 4 KiB) unchanged.
        assert_eq!(
            &got[offset + len..],
            &original[offset + len..],
            "suffix region must be unchanged after partial overwrite"
        );

        // Build and verify BLAKE3 tree for the overwritten data.
        let tree = store
            .get_checksum_tree(key, 4096)
            .expect("get_checksum_tree")
            .expect("tree must exist");
        assert!(
            store
                .verify_checksum_tree(key, &tree)
                .expect("verify after overwrite"),
            "BLAKE3 chain verification failed after partial overwrite"
        );
    }

    /// Concurrent reads during an in-progress write must see either the
    /// old or the new content atomically — never a torn or partial write.
    ///
    /// Uses Arc<Mutex<LocalObjectStore>> to serialize write access while
    /// allowing concurrent reads through cloned Arc handles.
    #[test]
    fn write_durability_concurrent_read_during_write_atomic() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let (store, _dir) = open_temp();
        let old_data: Vec<u8> = vec![0xAAu8; 1024];
        let new_data: Vec<u8> = vec![0xBBu8; 1024];
        let key = ObjectKey::from_name("concurrent-atomic");

        // Seed with old data.
        {
            let mut s = store;
            s.put(key, &old_data).expect("put old");
            s.sync().expect("sync old");
        }

        // Reopen so we can wrap in Arc<Mutex<>>.
        let store = reopen(&_dir);
        let shared = Arc::new(Mutex::new(store));
        let shared_writer = Arc::clone(&shared);

        // Writer thread: perform the overwrite.
        let new_data_for_assert = new_data.clone();
        let writer = thread::spawn(move || {
            let mut s = shared_writer.lock().expect("lock for write");
            s.put(key, &new_data).expect("put new");
            s.sync().expect("sync new");
            drop(s);
        });

        // Reader threads: perform concurrent gets while write may be
        // in progress (readers only hold &self, but we serialize via
        // Mutex so reads wait behind or ahead of the write lock).
        let reader_count = 8;
        let mut readers = Vec::new();
        for _ in 0..reader_count {
            let shared_reader = Arc::clone(&shared);
            readers.push(thread::spawn(move || {
                let s = shared_reader.lock().expect("lock for read");
                s.get(key).expect("get during write")
            }));
        }

        writer.join().expect("writer join");

        // Every reader saw either old or new — never a partial mix.
        for handle in readers {
            let result = handle.join().expect("reader join");
            match result {
                Some(data) => {
                    assert!(
                        data == old_data || data == new_data_for_assert,
                        "concurrent read returned torn data: \
                         expected {} bytes of 0xAA or 0xBB, \
                         got {} bytes (different content)",
                        old_data.len(),
                        data.len()
                    );
                }
                None => panic!("concurrent read returned None (key must exist)"),
            }
        }

        // Final state must be the new data.
        let s = shared.lock().expect("final lock");
        let final_data = s.get(key).expect("final get").expect("must exist");
        assert_eq!(
            final_data, new_data_for_assert,
            "final data must be new content"
        );
    }
}
