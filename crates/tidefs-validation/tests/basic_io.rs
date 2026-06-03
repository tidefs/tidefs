// Worker slot: s6
//! Basic I/O validation tests: create/stat/unlink lifecycle, small
//! write-read byte verification, sparse-hole zero-fill semantics,
//! and concurrent disjoint-region write integrity.
//!
//! These tests exercise the FUSE write dispatch path and byte-level
//! correctness within a single mount session (no remount).

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use tidefs_validation::mount_harness::MountHarness;

// ── create_stat_unlink ─────────────────────────────────────────────────

/// Create a file, stat it (size=0, mode correct), unlink it, then
/// verify stat fails with ENOENT.
#[cfg(target_os = "linux")]
#[test]
fn create_stat_unlink() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP create_stat_unlink: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("create_stat_unlink_test");

    // Create an empty file.
    {
        let _f = fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
    }

    assert!(path.exists(), "file must exist after create");

    // Stat: size must be 0, mode must be a regular file.
    let md = fs::metadata(&path).expect("stat after create");
    assert_eq!(md.len(), 0, "newly created file must have size 0");
    assert!(md.is_file(), "must be a regular file");

    // Mode check: the mode must have owner-readable bits at minimum.
    use std::os::unix::fs::PermissionsExt;
    let mode = md.permissions().mode();
    assert!(
        mode & 0o400 != 0,
        "file must be readable by owner, got mode 0o{mode:o}"
    );

    // Unlink.
    fs::remove_file(&path).expect("unlink file");

    // Stat must fail with NotFound.
    match fs::metadata(&path) {
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "stat after unlink must return NotFound (ENOENT), got {:?}",
            e.kind()
        ),
        Ok(_) => panic!("stat after unlink must fail with ENOENT"),
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn create_stat_unlink() {}

// ── write_read_verify_small ─────────────────────────────────────────────

/// Write 4 KiB of known pattern, read back byte-for-byte within a
/// single mount session; no remount.
#[cfg(target_os = "linux")]
#[test]
fn write_read_verify_small() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_read_verify_small: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("wr_verify.bin");
    let size: usize = 4096;
    let expected = patterned_data(0x42, size);

    // Write.
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open for write");
        f.write_all(&expected).expect("write 4 KiB");
        f.flush().expect("flush");
    }

    // Read back.
    let got = fs::read(&path).expect("read back");

    assert_eq!(
        got.len(),
        expected.len(),
        "length mismatch: expected {}, got {}",
        expected.len(),
        got.len()
    );
    assert_eq!(got, expected, "byte-for-byte readback mismatch");
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn write_read_verify_small() {}

// ── write_read_sparse_hole ──────────────────────────────────────────────

/// Write at offset 0 (4 KiB) and offset 1 MiB (4 KiB); read the entire
/// file and verify:
///  - Region [0..4KiB) matches the first write.
///  - Region [4KiB..1MiB) is all zeros (the hole).
///  - Region [1MiB..1MiB+4KiB) matches the second write.
///  - File total size is 1 MiB + 4 KiB.
#[cfg(target_os = "linux")]
#[test]
fn write_read_sparse_hole() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_read_sparse_hole: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("sparse_hole.bin");
    let block_size: usize = 4096;
    let _offset_first: u64 = 0;
    let offset_second: u64 = 1024 * 1024; // 1 MiB
    let expected_size: u64 = offset_second + block_size as u64;

    let first_data = patterned_data(0xA1, block_size);
    let second_data = patterned_data(0xB2, block_size);

    // Write at offset 0.
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open for first write");
        f.write_all(&first_data).expect("write at offset 0");
        f.flush().expect("flush first write");
    }

    // Write at offset 1 MiB.
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for second write");
        f.seek(SeekFrom::Start(offset_second))
            .expect("seek to 1 MiB");
        f.write_all(&second_data).expect("write at offset 1 MiB");
        f.flush().expect("flush second write");
    }

    // Stat: file size must be 1 MiB + 4 KiB.
    let md = fs::metadata(&path).expect("stat after writes");
    assert_eq!(
        md.len(),
        expected_size,
        "file size mismatch: expected {expected_size}, got {}",
        md.len()
    );

    // Read the entire file back.
    let got = fs::read(&path).expect("read entire file");
    assert_eq!(got.len() as u64, expected_size, "read length mismatch");

    // Verify first region.
    let first_region = &got[0..block_size];
    assert_eq!(
        first_region,
        &first_data[..],
        "first region [0..4KiB) byte mismatch"
    );

    // Verify hole region [4 KiB .. 1 MiB) is all zeros.
    let hole_start = block_size;
    let hole_end = offset_second as usize;
    let hole = &got[hole_start..hole_end];
    let hole_is_zero = hole.iter().all(|b| *b == 0);
    assert!(
        hole_is_zero,
        "hole region [{hole_start}..{hole_end}) must be all zeros; \
         found non-zero bytes"
    );

    // Verify second region.
    let second_start = offset_second as usize;
    let second_end = second_start + block_size;
    let second_region = &got[second_start..second_end];
    assert_eq!(
        second_region,
        &second_data[..],
        "second region [1MiB..1MiB+4KiB) byte mismatch"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn write_read_sparse_hole() {}

// ── concurrent_write_no_corruption ──────────────────────────────────────

/// Two threads write disjoint 4 KiB regions of the same file; after
/// both complete, read back and verify both regions are intact.
#[cfg(target_os = "linux")]
#[test]
fn concurrent_write_no_corruption() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP concurrent_write_no_corruption: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("concurrent.bin");
    let block_size: usize = 4096;
    let offset_a: u64 = 0;
    let offset_b: u64 = block_size as u64;
    let data_a = patterned_data(0xCA, block_size);
    let data_b = patterned_data(0xFE, block_size);

    // Seed the file with zeros up to the second region end.
    {
        let expected_size = (offset_b + block_size as u64) as usize;
        fs::write(&path, vec![0u8; expected_size]).expect("seed file with zeros");
    }

    let path_a = path.clone();
    let path_b = path.clone();
    let data_a_clone = data_a.clone();
    let data_b_clone = data_b.clone();

    let t1 = std::thread::spawn(move || {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path_a)
            .expect("thread A: open");
        f.seek(SeekFrom::Start(offset_a)).expect("thread A: seek");
        f.write_all(&data_a_clone).expect("thread A: write");
        f.flush().expect("thread A: flush");
    });

    let t2 = std::thread::spawn(move || {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path_b)
            .expect("thread B: open");
        f.seek(SeekFrom::Start(offset_b)).expect("thread B: seek");
        f.write_all(&data_b_clone).expect("thread B: write");
        f.flush().expect("thread B: flush");
    });

    t1.join().expect("thread A panic");
    t2.join().expect("thread B panic");

    // Read back and verify.
    let got = fs::read(&path).expect("read after concurrent writes");
    assert_eq!(got.len(), block_size * 2, "concurrent file length mismatch");

    let region_a = &got[0..block_size];
    let region_b = &got[block_size..block_size * 2];

    assert_eq!(
        region_a,
        &data_a[..],
        "region A (offset 0..4KiB) corrupted after concurrent write"
    );
    assert_eq!(
        region_b,
        &data_b[..],
        "region B (offset 4KiB..8KiB) corrupted after concurrent write"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn concurrent_write_no_corruption() {}

// ── helpers ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn patterned_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push((state >> 32) as u8);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    buf
}
