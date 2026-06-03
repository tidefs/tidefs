//! FUSE cache-coherency integration tests for tidefs-transport.
//!
//! Exercises the page cache through the FUSE read/write dispatch path
//! by mounting a real TideFS filesystem and driving IO through the
//! kernel VFS layer.  Every read, write, fsync, and remount exercises
//! the PageCache state machine (insert, lookup, mark_dirty, eviction,
//! writeback) integrated in the daemon's data path.
//!
//! # Test cases
//!
//! - **sequential_read_hit**: Write a multi-block file through FUSE,
//!   read it block-by-block, re-read, and verify content is identical
//!   on both reads.
//! - **write_invalidation**: Write a block, read it back, verify the
//!   read returns the newly written data (not a stale cached version).
//! - **random_read_eviction_coherency**: Create files totaling >4 MiB
//!   (exceeding typical page cache capacity), read them in random
//!   order, verify no stale data is served.
//! - **fsync_remount_cold_cache**: Write data, fsync, kill the daemon,
//!   remount, verify the cache is cold after remount and data matches.
//! - **concurrent_read_no_corruption**: Two reader threads hitting
//!   disjoint files concurrently, verifying no torn reads or panics.
//!
//! All tests are gated on the daemon binary being available and will
//! skip harmlessly when the binary is not found (CI environments
//! without FUSE kernel support).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::thread;

use tidefs_validation::mount_harness::MountHarness;

// ── helpers ────────────────────────────────────────────────────────────────

/// Page size used in TideFS page cache.  Must match the value in
/// `tidefs-transport/src/page_cache.rs` and
/// `tidefs-local-filesystem/src/page_cache/mod.rs`.
const PAGE_SIZE: usize = 4096;

/// Build reproducible pseudo-random data of `len` bytes seeded by `seed`.
fn patterned_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Deterministic incrementing byte sequence: `[0, 1, 2, ..., 255, 0, 1, ...]`.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Write `data` to `path` via normal filesystem IO (through the FUSE mount).
fn write_file(path: &std::path::Path, data: &[u8]) {
    let mut f = File::create(path).expect("create file for write");
    f.write_all(data).expect("write_all");
    f.flush().expect("flush");
}

/// Read entire file at `path` via normal filesystem IO (through the FUSE mount).
fn read_file(path: &std::path::Path) -> Vec<u8> {
    fs::read(path).expect("read file")
}

// ── sequential-read-hit ────────────────────────────────────────────────────

/// Write a multi-block file (16 KiB = 4 pages) through FUSE, read it back
/// block-by-block, then re-read the entire file.  Both reads must return
/// identical content byte-for-byte.
///
/// This exercises the PageCache hit path: the first read fills the cache,
/// and the second read should hit the cache for each page.
#[test]
fn cache_coherency_sequential_read_hit() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP cache_coherency_sequential_read_hit: daemon not available -- {e}");
            return;
        }
    };

    let file_path = harness.mount_path().join("seq_read_hit.bin");
    let data = seq_data(16 * 1024); // 16 KiB = 4 pages

    // Phase 1: Write the multi-block file.
    write_file(&file_path, &data);

    // Phase 2: Read it back block-by-block (4 pages).
    let mut read1 = Vec::with_capacity(data.len());
    {
        let mut f = File::open(&file_path).expect("open for read");
        let mut buf = [0u8; PAGE_SIZE];
        for i in 0..4 {
            f.seek(SeekFrom::Start((i * PAGE_SIZE) as u64))
                .expect("seek");
            let n = f.read(&mut buf).expect("read block");
            read1.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(read1, data, "first read must match written data");

    // Phase 3: Re-read the entire file in one operation.  By now the
    // daemon's page cache should hold all four pages — this exercises
    // the cache-hit path through the FUSE read dispatch.
    let read2 = read_file(&file_path);
    assert_eq!(
        read2, data,
        "second read (cache hit) must match written data"
    );
    assert_eq!(read2, read1, "both reads must return identical content");
}

// ── write-invalidation ─────────────────────────────────────────────────────

/// Write block N through FUSE, read block N, then overwrite it with new
/// data and re-read.  Each read must return the most recently written
/// data — the cache must not serve stale content after a write.
///
/// This validates the dirty-page upgrade path: after writing to a cached
/// page, subsequent reads must see the dirty (in-cache) content, not the
/// old on-disk data.
#[test]
fn cache_coherency_write_invalidation() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP cache_coherency_write_invalidation: daemon not available -- {e}");
            return;
        }
    };

    let file_path = harness.mount_path().join("write_inval.bin");

    // Phase 1: Write initial data and verify.
    let initial = patterned_data(0xDEAD, PAGE_SIZE);
    write_file(&file_path, &initial);
    let read1 = read_file(&file_path);
    assert_eq!(read1, initial, "initial write-read must match");

    // Phase 2: Overwrite with different data and verify the read returns
    // the new data, not the old cached content.
    let updated = patterned_data(0xBEEF, PAGE_SIZE);
    assert_ne!(updated, initial, "test data must differ");
    write_file(&file_path, &updated);
    let read2 = read_file(&file_path);
    assert_eq!(
        read2, updated,
        "overwrite must invalidate stale cache, got old data?"
    );
    assert_ne!(
        read2, initial,
        "second read must not return initial (stale) data"
    );
}

// ── random-read eviction coherency ──────────────────────────────────────────

/// Create N files totaling >4 MiB, then read them back in random order.
/// All reads must return byte-for-byte correct data — evicted pages
/// must be re-fetched from the object store correctly, and no stale or
/// zero-filled pages may be served.
///
/// File count and sizes are chosen to exceed typical default page-cache
/// capacity (which may vary, but 256 pages * 4 KiB = 1 MiB is a common
/// lower bound).  The total data size of ~5 MiB ensures cache pressure.
#[test]
fn cache_coherency_random_read_eviction() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP cache_coherency_random_read_eviction: daemon not available -- {e}");
            return;
        }
    };

    // Use a deterministic pseudo-random permutation for reproducibility.
    // We write 32 files of ~160 KiB each (~5 MiB total), then read them
    // back in a shuffled order to maximize eviction pressure.
    const FILE_COUNT: usize = 32;
    const FILE_SIZE: usize = 160 * 1024; // 160 KiB

    // Phase 1: Create all files.
    for i in 0..FILE_COUNT {
        let path = harness.mount_path().join(format!("evict_{i:04}.bin"));
        let data = patterned_data(i as u64, FILE_SIZE);
        write_file(&path, &data);
    }

    // Phase 2: Read all files in shuffled order.
    // Shuffle indices deterministically using a simple LCG.
    let mut indices: Vec<usize> = (0..FILE_COUNT).collect();
    let mut state: u64 = 0xCAFE_F00D;
    for i in (1..FILE_COUNT).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (state as usize) % (i + 1);
        indices.swap(i, j);
    }

    for &idx in &indices {
        let path = harness.mount_path().join(format!("evict_{idx:04}.bin"));
        let expected = patterned_data(idx as u64, FILE_SIZE);
        let actual = read_file(&path);
        assert_eq!(
            actual, expected,
            "evicted-and-re-fetched data mismatch for file {idx}"
        );
    }
}

// ── fsync-flush-and-reread ──────────────────────────────────────────────────

/// Write data, fsync, kill the daemon, remount the same backing store,
/// and read the file back.  The data must survive the daemon restart
/// byte-for-byte.
///
/// After remount, the page cache is cold — all reads go through the
/// object-store path.  This validates that fsync correctly flushes the
/// dirty page-cache pages to durable storage.
#[test]
fn cache_coherency_fsync_remount_cold_cache() {
    let data = patterned_data(0xCAFE_F00D_D00F, 8192);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP cache_coherency_fsync_remount_cold_cache: daemon not available -- {e}");
            return;
        }
    };

    // Phase 1: Write and fsync.
    let file_path = harness.mount_path().join("fsync_cold.bin");
    write_file(&file_path, &data);
    harness
        .fsync_file("fsync_cold.bin")
        .expect("fsync before remount");

    // Phase 2: Kill daemon and remount.
    harness
        .unmount_only(true)
        .expect("unmount for cold-cache test");
    harness.remount().expect("remount for cold-cache test");

    // Phase 3: Read on cold cache — all pages must be fetched from storage.
    let read_back = harness
        .read_file("fsync_cold.bin")
        .expect("read after remount");

    assert_eq!(
        read_back, data,
        "cold-cache read after remount must match originally written data"
    );
}

// ── concurrent read no corruption ───────────────────────────────────────────

/// Spawn two reader threads that repeatedly read disjoint files through
/// the FUSE mount.  Each thread verifies its own file's content is
/// byte-for-byte correct on every read, catching any torn reads or
/// cache-level data races.
#[test]
fn cache_coherency_concurrent_read_no_corruption() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP cache_coherency_concurrent_read_no_corruption: daemon not available -- {e}"
            );
            return;
        }
    };

    let mount = Arc::new(harness.mount_path().to_path_buf());
    let data_a = seq_data(4096);
    let data_b = patterned_data(0xABCD, 4096);

    // Create both files before spawning threads.
    write_file(&mount.join("concur_a.bin"), &data_a);
    write_file(&mount.join("concur_b.bin"), &data_b);

    let mount_a = Arc::clone(&mount);
    let mount_b = Arc::clone(&mount);

    let expected_a = data_a.clone();
    let expected_b = data_b.clone();

    let handle_a = thread::spawn(move || {
        for _ in 0..50 {
            let actual = read_file(&mount_a.join("concur_a.bin"));
            assert_eq!(actual, expected_a, "thread A: data corruption detected");
        }
    });

    let handle_b = thread::spawn(move || {
        for _ in 0..50 {
            let actual = read_file(&mount_b.join("concur_b.bin"));
            assert_eq!(actual, expected_b, "thread B: data corruption detected");
        }
    });

    handle_a.join().expect("thread A panicked");
    handle_b.join().expect("thread B panicked");
}

// ── cache pressure under mixed read/write ───────────────────────────────────

/// Create several files while interleaving reads of previously written
/// files.  This exercises cache eviction during active FUSE IO, ensuring
/// evicted pages are re-fetched correctly without data corruption.
#[test]
fn cache_coherency_mixed_read_write_pressure() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP cache_coherency_mixed_read_write_pressure: daemon not available -- {e}"
            );
            return;
        }
    };

    const ROUNDS: usize = 16;
    const CHUNK_SIZE: usize = 8192; // 2 pages per chunk

    // Write rounds: write a new file, then verify several earlier files still intact.
    for round in 0..ROUNDS {
        // Write new file.
        let path = harness.mount_path().join(format!("mix_{round:03}.bin"));
        let data = patterned_data(round as u64, CHUNK_SIZE);
        write_file(&path, &data);

        // Re-verify a subset of earlier files.
        for &prev in &[0usize, round / 2, round.saturating_sub(1)] {
            if prev < round {
                let prev_path = harness.mount_path().join(format!("mix_{prev:03}.bin"));
                let expected = patterned_data(prev as u64, CHUNK_SIZE);
                let actual = read_file(&prev_path);
                assert_eq!(
                    actual, expected,
                    "round {round}: previously written file {prev} corrupted"
                );
            }
        }
    }

    // Final sweep: verify all files are intact.
    for round in 0..ROUNDS {
        let path = harness.mount_path().join(format!("mix_{round:03}.bin"));
        let expected = patterned_data(round as u64, CHUNK_SIZE);
        let actual = read_file(&path);
        assert_eq!(
            actual, expected,
            "final sweep: file {round} corrupted after mixed workload"
        );
    }
}
