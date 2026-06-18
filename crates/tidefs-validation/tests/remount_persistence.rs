// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Remount-persistence integration test for the FUSE RW persistence slice.
//! Tests the advancement criterion: mount(RW) → write → sync → unmount →
//! remount → read → verify bytes match exactly.  Uses the `MountHarness`
//! infrastructure to spawn the posix-filesystem-adapter-daemon, perform IO
//! through the FUSE mount, and remount the same backing store.
//! This test proves that write data survives a clean unmount/remount cycle
//! and is the gate for the `fuse-mount-rw-persistence` slice advancement.

use tidefs_validation::mount_harness::MountHarness;

/// Sequenced byte pattern: 64 KiB of [0, 1, 2, ..., 255, 0, 1, ...].
fn sequenced_test_data(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes).map(|i| (i % 256) as u8).collect()
}

#[test]
fn remount_persistence_64kib_sequenced() {
    let test_data = sequenced_test_data(64 * 1024);

    // ── Session 1: mount, write, fsync, unmount ──────────────────────

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP remount_persistence_64kib_sequenced: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("remount_test.bin", &test_data)
        .expect("create_file session 1");
    harness
        .fsync_file("remount_test.bin")
        .expect("fsync session 1");

    harness.unmount_only(true).expect("unmount session 1");

    // ── Session 2: remount, read, verify ─────────────────────────────

    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("remount_test.bin")
        .expect("read_file session 2");

    assert_eq!(
        read_back.len(),
        test_data.len(),
        "file length mismatch after remount"
    );
    assert_eq!(
        read_back, test_data,
        "byte-for-byte data mismatch after remount: persistence test failed"
    );
}

#[test]
fn remount_persistence_multiple_files() {
    let data_a = b"file alpha content\n".to_vec();
    let data_b = b"file beta content\n".to_vec();
    let data_c = (0..4096).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP remount_persistence_multiple_files: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("alpha.txt", &data_a)
        .expect("create alpha");
    harness
        .create_file("beta.txt", &data_b)
        .expect("create beta");
    harness
        .create_file("gamma.bin", &data_c)
        .expect("create gamma");

    harness.fsync_file("alpha.txt").expect("fsync alpha");
    harness.fsync_file("beta.txt").expect("fsync beta");
    harness.fsync_file("gamma.bin").expect("fsync gamma");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    assert_eq!(
        harness.read_file("alpha.txt").expect("read alpha"),
        data_a,
        "alpha mismatch"
    );
    assert_eq!(
        harness.read_file("beta.txt").expect("read beta"),
        data_b,
        "beta mismatch"
    );
    assert_eq!(
        harness.read_file("gamma.bin").expect("read gamma"),
        data_c,
        "gamma mismatch"
    );
}

#[test]
fn remount_persistence_subdir_files() {
    let data_x = b"nested file x data\n".to_vec();
    let data_y = b"nested file y data\n".to_vec();

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP remount_persistence_subdir_files: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir_all("subdir/deep").expect("mkdir subdir/deep");
    harness
        .create_file("subdir/x.txt", &data_x)
        .expect("create subdir/x.txt");
    harness
        .create_file("subdir/deep/y.txt", &data_y)
        .expect("create subdir/deep/y.txt");

    harness.fsync_file("subdir/x.txt").expect("fsync x");
    harness.fsync_file("subdir/deep/y.txt").expect("fsync y");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // Verify directory structure survived.
    let entries_subdir = harness.readdir("subdir").expect("readdir subdir session 2");
    assert!(
        entries_subdir.contains(&"x.txt".to_string()),
        "subdir should contain x.txt"
    );
    assert!(
        entries_subdir.contains(&"deep".to_string()),
        "subdir should contain deep/"
    );

    let entries_deep = harness
        .readdir("subdir/deep")
        .expect("readdir subdir/deep session 2");
    assert!(
        entries_deep.contains(&"y.txt".to_string()),
        "subdir/deep should contain y.txt"
    );

    assert_eq!(
        harness
            .read_file("subdir/x.txt")
            .expect("read subdir/x.txt"),
        data_x,
        "subdir/x.txt mismatch"
    );
    assert_eq!(
        harness
            .read_file("subdir/deep/y.txt")
            .expect("read subdir/deep/y.txt"),
        data_y,
        "subdir/deep/y.txt mismatch"
    );
}

// ===========================================================================
// Same-session write-read smoke tests (issue #3732 advancement criterion 1)
// ===========================================================================

/// Write known data through a FUSE mount, then read it back within the same
/// mount session and verify byte-for-byte equality.  This proves that the
/// FUSE write dispatch path is functional end-to-end.
#[test]
fn same_session_write_read_roundtrip() {
    let test_data = b"same-session write-then-read roundtrip payload\n";

    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("ss_wr.bin", test_data)
        .expect("create_file same-session");

    let read_back = harness
        .read_file("ss_wr.bin")
        .expect("read_file same-session");

    assert_eq!(
        read_back, test_data,
        "same-session write-read must return written bytes exactly"
    );
}

/// Write a multi-block payload (32 KiB) and read back within the same
/// session to verify correctness across block boundaries.
#[test]
fn same_session_write_read_multiblock() {
    let test_data: Vec<u8> = (0..32768u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();

    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("ss_multiblock.bin", &test_data)
        .expect("create_file multiblock");

    let read_back = harness
        .read_file("ss_multiblock.bin")
        .expect("read_file multiblock");

    assert_eq!(
        read_back.len(),
        test_data.len(),
        "file length mismatch in same-session multiblock read"
    );
    assert_eq!(
        read_back, test_data,
        "same-session multiblock write-read must be byte-for-byte identical"
    );
}

/// Write data, fsync via FUSE (sync_all), then immediately read back within
/// the same session to confirm flush does not invalidate the read path.
#[test]
fn same_session_write_fsync_read() {
    let test_data = b"write, fsync, read in same session\n";

    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("ss_fsync.bin", test_data)
        .expect("create_file");
    harness
        .fsync_file("ss_fsync.bin")
        .expect("fsync_file same-session");

    let read_back = harness
        .read_file("ss_fsync.bin")
        .expect("read_file after fsync same-session");

    assert_eq!(
        read_back, test_data,
        "data must be readable after fsync within same session"
    );
}

/// Write data, fdatasync via FUSE (sync_data), then read back.
/// Fdatasync is a data-only sync; read-back must return the written bytes.
#[test]
fn same_session_write_fdatasync_read() {
    use std::os::unix::io::AsRawFd;
    let test_data = b"write, fdatasync, read in same session\n";

    let harness = MountHarness::new().expect("harness setup");
    let rel = "ss_fdatasync.bin";
    harness.create_file(rel, test_data).expect("create_file");

    // Open the file and issue fdatasync (sync_data) directly.
    let full = harness.mount_path().join(rel);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&full)
        .expect("open for fdatasync");
    // SAFETY: fdatasync is a C FFI call; fd is a valid open file descriptor.
    unsafe {
        libc::fdatasync(file.as_raw_fd());
    }

    let read_back = harness
        .read_file(rel)
        .expect("read_file after fdatasync same-session");

    assert_eq!(
        read_back, test_data,
        "data must be readable after fdatasync within same session"
    );
}
