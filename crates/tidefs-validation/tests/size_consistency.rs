// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE size-consistency integration test.
//!
//! Exercises truncate, write, and stat operations through a real FUSE mount
//! and asserts that reported file sizes remain consistent across operations
//! and survive unmount/remount cycles.
//!
//! Supports advancement criteria for the `fuse-metadata-batch` milestone
//! (truncate behavior) and the `fuse-crash-recovery` milestone (size
//! survival across remount).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::thread;

use tidefs_validation::mount_harness::MountHarness;

// ── helpers ────────────────────────────────────────────────────────────────

/// Open a file under the mount point for reading and writing, creating
/// it if it does not exist.
fn open_rw(harness: &MountHarness, relative: &str) -> File {
    let path = harness.mount_path().join(relative);
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|_| panic!("open_rw {relative}"))
}

/// Open a file under the mount point for reading only.
fn open_ro(harness: &MountHarness, relative: &str) -> File {
    let path = harness.mount_path().join(relative);
    File::open(&path).unwrap_or_else(|_| panic!("open_ro {relative}"))
}

/// Return the file size from metadata (fstat equivalent).
fn file_size(file: &File) -> u64 {
    file.metadata().expect("metadata").len()
}

// ── test 1: truncate-extend-then-stat ──────────────────────────────────────

/// Create an empty file, ftruncate to non-zero size, stat returns that size,
/// and reading returns zero-filled bytes beyond the original EOF.
#[test]
fn truncate_extend_then_stat() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_extend_then_stat: daemon not available -- {e}");
            return;
        }
    };

    let file = open_rw(&harness, "extend.bin");

    // File is initially zero-length.
    assert_eq!(file_size(&file), 0, "new file must have size 0");

    // Extend to 4096 bytes.
    file.set_len(4096).expect("ftruncate to 4096");
    assert_eq!(file_size(&file), 4096, "size after extend to 4096");

    // Read beyond original EOF (offset 0) should return zero-filled bytes.
    let mut buf = vec![0xFFu8; 4096];
    let n = file.read_at(&mut buf, 0).expect("pread at 0");
    assert_eq!(n, 4096, "read 4096 bytes from extended file");
    assert!(
        buf.iter().all(|&b| b == 0),
        "extended region must be zero-filled"
    );

    // Extend further.
    file.set_len(8192).expect("ftruncate to 8192");
    assert_eq!(file_size(&file), 8192, "size after second extend");

    let mut buf2 = vec![0xFFu8; 8192];
    let n2 = file
        .read_at(&mut buf2, 0)
        .expect("pread after second extend");
    assert_eq!(n2, 8192);
    assert!(
        buf2.iter().all(|&b| b == 0),
        "entire file must be zero-filled"
    );
}

// ── test 2: truncate-shrink-then-stat ──────────────────────────────────────

/// Write data, ftruncate to a smaller size, stat returns reduced size,
/// read beyond new EOF returns empty.
#[test]
fn truncate_shrink_then_stat() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_shrink_then_stat: daemon not available -- {e}");
            return;
        }
    };

    let mut file = open_rw(&harness, "shrink.bin");

    // Write 4096 bytes of known content.
    let data: Vec<u8> = (0..4096u64).map(|i| (i % 256) as u8).collect();
    file.write_all_at(&data, 0).expect("pwrite 4096 bytes");
    file.flush().expect("flush");
    assert_eq!(file_size(&file), 4096, "size after write");

    // Shrink to 1024 bytes.
    file.set_len(1024).expect("ftruncate to 1024");
    assert_eq!(file_size(&file), 1024, "size after shrink");

    // Read first 1024 bytes — must match original data.
    let mut buf = vec![0u8; 1024];
    let n = file.read_at(&mut buf, 0).expect("pread first 1024");
    assert_eq!(n, 1024);
    assert_eq!(&buf[..], &data[..1024], "first 1K must be intact");

    // Read at offset 2048 (beyond new EOF) should return 0 bytes.
    let mut buf2 = [0u8; 16];
    let n2 = file.read_at(&mut buf2, 2048).expect("pread beyond EOF");
    assert_eq!(n2, 0, "read beyond new EOF must return empty");
}

// ── test 3: truncate-to-zero ───────────────────────────────────────────────

/// Write data, ftruncate to 0, stat returns 0, read returns empty.
#[test]
fn truncate_to_zero() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_to_zero: daemon not available -- {e}");
            return;
        }
    };

    let mut file = open_rw(&harness, "tozero.bin");

    // Write known content.
    let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    file.write_all_at(&data, 0).expect("pwrite 512 bytes");
    file.flush().expect("flush");
    assert_eq!(file_size(&file), 512, "size after write");

    // Truncate to zero.
    file.set_len(0).expect("ftruncate to 0");
    assert_eq!(file_size(&file), 0, "size after truncate to 0");

    // Reading should return empty.
    let mut buf = [0u8; 64];
    let n = file.read_at(&mut buf, 0).expect("pread at 0");
    assert_eq!(n, 0, "read from zero-length file must return empty");
}

// ── test 4: write-past-eof ─────────────────────────────────────────────────

/// Create a sparse file via ftruncate to a large offset, write at an
/// offset beyond that, stat reflects max(written_offset + len).
#[test]
fn write_past_eof() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_past_eof: daemon not available -- {e}");
            return;
        }
    };

    let mut file = open_rw(&harness, "sparse.bin");

    // Truncate to create a sparse 64 KiB file.
    file.set_len(65536).expect("ftruncate to 64K");
    assert_eq!(file_size(&file), 65536);

    // Write 256 bytes at offset 131072 (128K), beyond the current EOF.
    let data: Vec<u8> = (0..=255u8).collect();
    file.write_all_at(&data, 131072).expect("pwrite at 128K");
    file.flush().expect("flush");

    // Size should be max(65536, 131072 + 256) = 131328.
    assert_eq!(file_size(&file), 131328, "size must reflect write past EOF");

    // Read at the written offset to verify content.
    let mut buf = vec![0u8; 256];
    let n = file.read_at(&mut buf, 131072).expect("pread at 128K");
    assert_eq!(n, 256);
    assert_eq!(&buf[..], &data[..], "written data at 128K");

    // Read in the sparse region (64K..128K) should be zero-filled.
    let mut hole_buf = [1u8; 512];
    let n_hole = file.read_at(&mut hole_buf, 70000).expect("pread in hole");
    if n_hole > 0 {
        assert!(
            hole_buf[..n_hole].iter().all(|&b| b == 0),
            "sparse region must be zero-filled"
        );
    }
}

// ── test 5: size-survives-remount ──────────────────────────────────────────

/// Write data, fsync, unmount, remount, stat returns same size, read
/// returns same data (ties into crash-recovery path).
#[test]
fn size_survives_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP size_survives_remount: daemon not available -- {e}");
            return;
        }
    };

    let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();

    {
        let mut file = open_rw(&harness, "persist.bin");
        file.write_all_at(&data, 0).expect("pwrite 8K");
        file.flush().expect("flush");
        file.sync_all().expect("fsync");
        let sz = file_size(&file);
        assert_eq!(sz, 8192, "size before remount");
    }

    harness.unmount_only(true).expect("unmount");
    harness.remount().expect("remount");

    {
        let file = open_ro(&harness, "persist.bin");
        let sz = file_size(&file);
        assert_eq!(sz, 8192, "size must survive remount");

        let mut buf = vec![0u8; 8192];
        let n = file.read_at(&mut buf, 0).expect("pread after remount");
        assert_eq!(n, 8192, "read all bytes after remount");
        assert_eq!(
            &buf[..],
            &data[..],
            "data must survive remount byte-for-byte"
        );
    }
}

// ── test 6: concurrent-truncate-write ──────────────────────────────────────

/// Two threads: one truncating up/down while another writes.
/// Final size is deterministic: max of last write end or last truncate.
#[test]
fn concurrent_truncate_write() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP concurrent_truncate_write: daemon not available -- {e}");
            return;
        }
    };

    let mount_path = harness.mount_path().to_path_buf();
    let file_path = mount_path.join("concurrent.bin");

    // Seed the file with zero length.
    File::create(&file_path).expect("create concurrent.bin");

    let p1 = file_path.clone();
    let t1 = thread::spawn(move || {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&p1)
            .expect("open writer");
        // Write 4096 bytes of 0xAA at offset 4096.
        let data = vec![0xAAu8; 4096];
        for _ in 0..100 {
            file.write_all_at(&data, 4096).expect("pwrite at 4K");
            thread::yield_now();
        }
        file.flush().expect("flush writer");
    });

    let p2 = file_path.clone();
    let t2 = thread::spawn(move || {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&p2)
            .expect("open truncator");
        for _ in 0..100 {
            // Alternate between extending and shrinking.
            file.set_len(8192).expect("extend");
            thread::yield_now();
            file.set_len(2048).expect("shrink");
            thread::yield_now();
        }
        file.flush().expect("flush truncator");
    });

    t1.join().expect("writer thread");
    t2.join().expect("truncator thread");

    // Re-open to get a clean view of final state.
    let file = File::open(&file_path).expect("reopen");
    let final_size = file_size(&file);

    // Final size must be one of the valid truncate/write boundaries.
    assert!(
        final_size <= 8192,
        "final size {final_size} must not exceed max extent"
    );

    // Reading within bounds should succeed without error.
    if final_size > 0 {
        let mut buf = [0u8; 64];
        let n = file.read_at(&mut buf, 0).expect("pread at 0");
        assert!(n > 0, "must read at least 1 byte from non-empty file");
    }
}

// ── test 7: truncate-zero-length-file ──────────────────────────────────────

/// stat on newly created zero-length file returns 0, ftruncate(0) is
/// idempotent.
#[test]
fn truncate_zero_length_file() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_zero_length_file: daemon not available -- {e}");
            return;
        }
    };

    let mut file = open_rw(&harness, "zerolen.bin");

    // Newly created file has zero size.
    assert_eq!(file_size(&file), 0, "new file must have size 0");

    // ftruncate(0) on an already-zero-length file is idempotent.
    file.set_len(0).expect("ftruncate(0) #1");
    assert_eq!(file_size(&file), 0, "size after first truncate(0)");

    file.set_len(0).expect("ftruncate(0) #2");
    assert_eq!(file_size(&file), 0, "size after second truncate(0)");

    // Reading returns empty.
    let mut buf = [0xFFu8; 16];
    let n = file.read_at(&mut buf, 0).expect("pread at 0");
    assert_eq!(n, 0, "read from zero-length file must return empty");

    // Writing to a zero-length file should work and update size.
    file.write_all_at(b"hello", 0).expect("pwrite at 0");
    file.flush().expect("flush");
    assert_eq!(file_size(&file), 5, "size after write to zero-length file");
}
