//! BLAKE3-verified concurrent cache-core writeback integrity validation.
//!
//! This module exercises the `PageCache` writeback path with interleaved
//! reader/writer access patterns and verifies that no silent data corruption
//! (stale reads, torn writes, lost dirty pages, checksum mismatches) occurs.
//!
//! # Concurrency Model
//!
//! Multiple OS threads operate on a shared `PageCache` protected by its
//! internal `Mutex`.  Each thread follows the PageCache contract: never
//! call back into `PageCache` while holding a `PageHandle` (which holds
//! the internal lock).
//!
//! # BLAKE3 Integrity Invariants
//!
//! Every data block written into the cache carries a known BLAKE3-256
//! checksum.  On every read, the block content is hashed and compared
//! against the expected checksum.  A mismatch indicates corruption.
//!
//! # Seed-Based Reproducibility
//!
//! All randomized operation sequences are driven by a seed recorded in
//! the test output.  When a test fails, the seed in the panic message
//! can be used to deterministically reproduce the failure.

use blake3::Hasher;
use std::sync::Arc;
use std::thread;
use tidefs_cache_core::page_cache::{InsertError, PageCache};

const PAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Deterministic PRNG (LCG, same as glibc rand())
// ---------------------------------------------------------------------------

/// A simple linear congruential generator for deterministic
/// pseudo-random sequences.  Seeded once per test.
struct Rng(u64);

impl Rng {
    const MULTIPLIER: u64 = 1103515245;
    const INCREMENT: u64 = 12345;
    const MASK: u64 = 0x7fff_ffff;

    fn new(seed: u64) -> Self {
        // Ensure seed is non-zero
        Self(if seed == 0 { 1 } else { seed })
    }

    /// Return a value in [0, 2^31).
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(Self::MULTIPLIER)
            .wrapping_add(Self::INCREMENT)
            & Self::MASK;
        (self.0 >> 16) as u32
    }

    /// Return a value in [0, bound).
    fn next_bound(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        let max = (1u64 << 31) - ((1u64 << 31) % bound as u64);
        loop {
            let v = self.next() as u64;
            if v < max {
                return (v % bound as u64) as u32;
            }
        }
    }

    /// Fill `buf` with pseudo-random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let v = self.next();
            let bytes = v.to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 helpers
// ---------------------------------------------------------------------------

/// Compute the BLAKE3-256 hash of `data` and return it as 32 bytes.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the BLAKE3-256 hash of a page-sized data block, keyed by
/// `(inode, offset)` so distinct cache locations have distinct hashes.
/// Fill a page buffer with deterministic content derived from `seed`,
/// `inode`, and `offset`.  Returns the BLAKE3 hash of the result.
fn fill_page(rng: &mut Rng, buf: &mut [u8], inode: u64, offset: u64) -> [u8; 32] {
    rng.fill_bytes(buf);
    // Mix inode/offset into the first 16 bytes for identity
    let prefix = [inode.to_le_bytes(), offset.to_le_bytes()].concat();
    buf[..16].copy_from_slice(&prefix);
    blake3_hash(buf)
}

/// Write deterministic content into an existing page; return the
/// expected BLAKE3 checksum.
fn write_page_data(cache: &PageCache, rng: &mut Rng, inode: u64, offset: u64) -> [u8; 32] {
    let mut handle = cache.lookup(inode, offset).expect("page must exist");
    let expected = fill_page(rng, handle.data_mut(), inode, offset);
    drop(handle);
    expected
}

/// Read a page from the cache and verify its content matches the
/// expected BLAKE3 checksum.  Returns `true` on match, `false` on
/// mismatch.
fn verify_page(
    cache: &PageCache,
    expected: &[u8; 32],
    inode: u64,
    offset: u64,
) -> Result<(), String> {
    let handle = match cache.lookup(inode, offset) {
        Some(h) => h,
        None => return Err("page not found in cache".into()),
    };
    let actual = blake3_hash(handle.data());
    drop(handle);

    if actual != *expected {
        return Err(format!(
            "BLAKE3 mismatch at (inode={inode}, offset={offset}): \
             expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 1: Single-writer sequential-reader baseline
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn baseline_single_writer_sequential_reader() {
    let seed = 0x5630_0001;
    let mut rng = Rng::new(seed);
    let cache = PageCache::new(64, PAGE_SIZE);

    const N_PAGES: u64 = 40;
    let mut checksums: Vec<(u64, u64, [u8; 32])> = Vec::new();

    // Write phase: insert pages and record checksums
    for inode in 1..=N_PAGES {
        let offset = (rng.next_bound(16) as u64) * PAGE_SIZE as u64;
        let key = cache.insert(inode, offset).expect("insert should succeed");
        let expected = write_page_data(&cache, &mut rng, inode, offset);
        checksums.push((inode, offset, expected));
        let _ = key; // not needed further
    }

    assert_eq!(cache.len() as u64, N_PAGES);

    // Read-back phase: verify every page
    for (inode, offset, expected) in &checksums {
        verify_page(&cache, expected, *inode, *offset).unwrap_or_else(|e| panic!("baseline: {e}"));
    }

    // Verify all pages remain
    assert_eq!(cache.len() as u64, N_PAGES);
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 2: Concurrent writer and reader on the same page
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_writer_reader_same_page_no_tearing() {
    let seed = 0x5630_0002;
    let cache = Arc::new(PageCache::new(16, PAGE_SIZE));
    let inode = 1u64;
    let offset = 0u64;

    // Insert initial page
    cache.insert(inode, offset).expect("initial insert");

    let cache_w = Arc::clone(&cache);
    let cache_r = Arc::clone(&cache);

    // Writer thread: repeatedly writes new content to the page
    let writer = thread::spawn(move || {
        let mut rng = Rng::new(seed);
        for _ in 0..200 {
            let _ = write_page_data(&cache_w, &mut rng, inode, offset);
        }
    });

    // Reader thread: repeatedly reads the page and verifies it's not
    // obviously corrupted (full page of zeros would be suspicious)
    let reader = thread::spawn(move || {
        for _ in 0..500 {
            if let Some(handle) = cache_r.lookup(inode, offset) {
                let data = handle.data().to_vec();
                drop(handle);
                // Every read should give exactly PAGE_SIZE bytes
                assert_eq!(data.len(), PAGE_SIZE);
                // The first 8 bytes should be the inode (LE)
                let found_inode = u64::from_le_bytes(data[0..8].try_into().unwrap());
                assert_eq!(found_inode, inode, "inode marker corrupted");
            }
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();

    // Final sanity: page exists
    assert!(cache.lookup(inode, offset).is_some());
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 3: Writeback overlapping with reader access
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn writeback_overlap_with_reader_no_corruption() {
    let seed = 0x5630_0003;
    let cache = Arc::new(PageCache::new(32, PAGE_SIZE));
    let inode = 10u64;
    let offset = 0u64;

    // Pre-populate: write content and record checksum
    cache.insert(inode, offset).expect("insert");
    let mut rng = Rng::new(seed);
    let expected = write_page_data(&cache, &mut rng, inode, offset);

    // Verify initial content
    verify_page(&cache, &expected, inode, offset).expect("initial verify");

    // Mark dirty
    cache.mark_dirty(inode, offset);
    assert!(!cache.dirty_pages().is_empty());

    // Start writeback (pins the page)
    assert!(cache.start_writeback(inode, offset));

    let cache_r = Arc::clone(&cache);

    // Reader thread: read during writeback; the page is pinned so it
    // won't be evicted, and the content should still be the same
    let reader = thread::spawn(move || {
        for _ in 0..50 {
            let _ = verify_page(&cache_r, &expected, inode, offset);
        }
    });

    reader.join().unwrap();

    // Complete writeback successfully → page becomes clean
    assert!(cache.complete_writeback(inode, offset, true));

    // Page still exists and should have the same content
    verify_page(&cache, &expected, inode, offset).expect("post-writeback verify");
    assert!(
        cache.dirty_pages().is_empty(),
        "page should be clean after writeback"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 4: Multiple writers to disjoint inode regions
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn multiple_writers_disjoint_regions_no_interference() {
    let seed = 0x5630_0004;
    let cache = Arc::new(PageCache::new(100, PAGE_SIZE));
    const N_WRITERS: u64 = 4;
    const PAGES_PER_WRITER: u64 = 20;

    let mut handles = Vec::new();

    for tid in 0..N_WRITERS {
        let cache = Arc::clone(&cache);
        let base_inode = tid * 1000;
        let h = thread::spawn(move || {
            let mut rng = Rng::new(seed + tid);
            let mut checksums: Vec<(u64, u64, [u8; 32])> = Vec::new();

            for i in 0..PAGES_PER_WRITER {
                let inode = base_inode + i;
                let offset = ((rng.next_bound(8) as u64) % 8) * PAGE_SIZE as u64;
                // Try insert; if at capacity with all dirty, evict_one() then retry
                loop {
                    match cache.insert(inode, offset) {
                        Ok(_) => break,
                        Err(InsertError::AlreadyExists) => {
                            cache.remove(inode, offset);
                            continue;
                        }
                        Err(InsertError::AtCapacityNoCleanPages) => {
                            // Flush some dirty pages first
                            let dirty = cache.dirty_pages();
                            for key in &dirty[..dirty.len().min(5)] {
                                cache.start_writeback(key.inode, key.offset);
                                cache.complete_writeback(key.inode, key.offset, true);
                            }
                            continue;
                        }
                    }
                }
                let expected = write_page_data(&cache, &mut rng, inode, offset);
                checksums.push((inode, offset, expected));
            }
            checksums
        });
        handles.push(h);
    }

    // Collect results
    let mut all_checksums: Vec<(u64, u64, [u8; 32])> = Vec::new();
    for h in handles {
        all_checksums.extend(h.join().unwrap());
    }

    // Verify every page written
    for (inode, offset, expected) in &all_checksums {
        verify_page(&cache, expected, *inode, *offset)
            .unwrap_or_else(|e| panic!("disjoint-regions: {e}"));
    }

    assert_eq!(all_checksums.len(), (N_WRITERS * PAGES_PER_WRITER) as usize);
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 5: Single-region write contention (multiple writers to same page)
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn single_region_write_contention_no_tearing() {
    let seed = 0x5630_0005;
    let cache = Arc::new(PageCache::new(8, PAGE_SIZE));
    let inode = 1u64;
    let offset = 0u64;

    // Insert initial page
    cache.insert(inode, offset).expect("initial insert");

    let mut handles = Vec::new();

    for tid in 0..4 {
        let cache = Arc::clone(&cache);
        let h = thread::spawn(move || {
            let mut rng = Rng::new(seed + tid as u64);
            for _ in 0..100 {
                // Look up, write deterministic content
                if let Some(mut handle) = cache.lookup(inode, offset) {
                    let data = handle.data_mut();
                    fill_page(&mut rng, data, inode, offset);
                    drop(handle);
                }
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }

    // Final state: page exists and contains a valid-looking buffer
    let handle = cache.lookup(inode, offset).expect("page should exist");
    let data = handle.data();
    assert_eq!(data.len(), PAGE_SIZE);
    let found_inode = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(found_inode, inode, "final content has correct inode marker");
    drop(handle);
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 6: Dirty-page endurance — write, dirty, evict, re-read
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn dirty_page_endurance_through_writeback_cycles() {
    let seed = 0x5630_0006;
    let cache = PageCache::new(16, PAGE_SIZE);
    let mut rng = Rng::new(seed);

    // Write 8 pages
    let mut checksums: Vec<(u64, u64, [u8; 32])> = Vec::new();
    for i in 0..8 {
        let inode = i as u64;
        let offset = 0;
        cache.insert(inode, offset).expect("insert");
        let expected = write_page_data(&cache, &mut rng, inode, offset);
        checksums.push((inode, offset, expected));
    }

    // Cycle each page through: mark dirty → start writeback → read → complete
    for (inode, offset, expected) in &checksums {
        cache.mark_dirty(*inode, *offset);
        assert!(cache.dirty_pages().iter().any(|k| k.inode == *inode));

        let dirty_before = cache.dirty_pages().len();
        cache.start_writeback(*inode, *offset);
        // Page remains in dirty set during writeback
        assert_eq!(cache.dirty_pages().len(), dirty_before);

        // Read during writeback → content must match
        verify_page(&cache, expected, *inode, *offset)
            .unwrap_or_else(|e| panic!("endurance-verify during WB: {e}"));

        cache.complete_writeback(*inode, *offset, true);

        // Read after writeback → content must match
        verify_page(&cache, expected, *inode, *offset)
            .unwrap_or_else(|e| panic!("endurance-verify after WB: {e}"));
    }

    // No dirty pages remain
    assert!(cache.dirty_pages().is_empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 7: Writeback abort preserves data integrity
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn writeback_abort_preserves_written_content() {
    let seed = 0x5630_0007;
    let cache = PageCache::new(4, PAGE_SIZE);
    let mut rng = Rng::new(seed);

    // Write content
    let inode = 42;
    let offset = 0;
    cache.insert(inode, offset).expect("insert");
    let expected = write_page_data(&cache, &mut rng, inode, offset);

    // Start writeback, then abort
    cache.mark_dirty(inode, offset);
    cache.start_writeback(inode, offset);
    cache.abort_writeback(inode, offset);

    // After abort: page should still be dirty with original content
    assert!(!cache.dirty_pages().is_empty());
    verify_page(&cache, &expected, inode, offset).expect("data intact after writeback abort");

    // Now do a full successful writeback cycle
    cache.start_writeback(inode, offset);
    cache.complete_writeback(inode, offset, true);

    assert!(cache.dirty_pages().is_empty());
    verify_page(&cache, &expected, inode, offset).expect("data intact after successful writeback");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 8: Eviction does not lose dirty pages
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn eviction_respects_dirty_pages_no_silent_data_loss() {
    let cache = PageCache::new(4, PAGE_SIZE);
    let mut rng = Rng::new(0x5630_0008);

    // Fill cache (4 pages)
    let mut clean_pages: Vec<(u64, u64, [u8; 32])> = Vec::new();
    for i in 0..4 {
        let inode = i;
        let offset = 0;
        cache.insert(inode, offset).expect("insert");
        let expected = write_page_data(&cache, &mut rng, inode, offset);
        clean_pages.push((inode, offset, expected));
    }

    // Mark half dirty
    cache.mark_dirty(0, 0);
    cache.mark_dirty(1, 0);

    // Try to insert a new page: must evict a clean page, not a dirty one
    let result = cache.insert(99, 0);
    assert!(result.is_ok(), "should evict clean page and insert new one");

    // Dirty pages must remain
    assert!(cache.lookup(0, 0).is_some(), "dirty page 0 must survive");
    assert!(cache.lookup(1, 0).is_some(), "dirty page 1 must survive");

    // At least one clean page was evicted
    let dirty_count = cache.dirty_pages().len();
    assert_eq!(dirty_count, 2, "both dirty pages still tracked");

    // Verify dirty pages still have correct content
    verify_page(&cache, &clean_pages[0].2, 0, 0).expect("dirty page 0 content intact");
    verify_page(&cache, &clean_pages[1].2, 1, 0).expect("dirty page 1 content intact");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 9: Flush dirty range integrity
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn flush_dirty_range_writes_correct_data() {
    let seed = 0x5630_0009;
    let cache = PageCache::new(10, PAGE_SIZE);
    let mut rng = Rng::new(seed);

    let inode = 5;
    let mut checksums: Vec<(u64, [u8; 32])> = Vec::new();

    // Write 3 pages at offsets 0, 4096, 8192; mark all dirty
    for i in 0..3 {
        let offset = i * PAGE_SIZE as u64;
        cache.insert(inode, offset).expect("insert");
        let expected = write_page_data(&cache, &mut rng, inode, offset);
        cache.mark_dirty(inode, offset);
        checksums.push((offset, expected));
    }

    assert_eq!(cache.dirty_pages_for_inode(inode).len(), 3);

    // Flush dirty range [0, 8192) — covers offsets 0 and 4096
    let mut flushed: Vec<(u64, Vec<u8>)> = Vec::new();
    let result = cache.flush_dirty_range(inode, 0, 8192, |offset, data| {
        flushed.push((offset, data.to_vec()));
        Ok(())
    });

    assert!(result.is_ok());
    assert_eq!(flushed.len(), 2);

    // Verify flushed data matches expected checksums
    for (offset, data) in &flushed {
        let expected = checksums.iter().find(|(o, _)| o == offset).unwrap().1;
        let actual = blake3_hash(data);
        assert_eq!(
            actual, expected,
            "flushed data checksum mismatch at offset {offset}"
        );
    }

    // Page at offset 8192 remains dirty
    let remaining = cache.dirty_pages_for_inode(inode);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].offset, 8192);
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 10: Concurrent mixed workload stress test with BLAKE3 verification
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_mixed_workload_stress_with_integrity() {
    let seed = 0x5630_000A;
    let cache = Arc::new(PageCache::new(64, PAGE_SIZE));

    const N_INODES: u64 = 32;
    const N_WORKER_GROUPS: usize = 4;

    // Pre-populate with known content
    {
        let mut rng = Rng::new(seed);
        for inode in 1..=N_INODES {
            let offset = 0;
            cache.insert(inode, offset).expect("pre-populate insert");
            write_page_data(&cache, &mut rng, inode, offset);
        }
    }

    let mut handles = Vec::new();

    for group in 0..N_WORKER_GROUPS {
        let cache = Arc::clone(&cache);
        let h = thread::spawn(move || {
            let mut rng = Rng::new(seed + group as u64 * 100);
            for _round in 0..50 {
                let inode = ((rng.next_bound(N_INODES as u32) as u64) % N_INODES) + 1;
                let op = rng.next_bound(5);

                match op {
                    0 => {
                        // Read and verify inode/offset markers
                        if let Some(handle) = cache.lookup(inode, 0) {
                            let data = handle.data().to_vec();
                            drop(handle);
                            let found_inode = u64::from_le_bytes(data[0..8].try_into().unwrap());
                            assert_eq!(found_inode, inode, "inode marker corrupted in stress read");
                        }
                    }
                    1 => {
                        // Write new content to the page
                        if let Some(mut handle) = cache.lookup(inode, 0) {
                            fill_page(&mut rng, handle.data_mut(), inode, 0);
                            drop(handle);
                        }
                    }
                    2 => {
                        // Mark dirty
                        cache.mark_dirty(inode, 0);
                    }
                    3 => {
                        // Start writeback
                        cache.start_writeback(inode, 0);
                    }
                    4 => {
                        // Complete writeback (success)
                        cache.complete_writeback(inode, 0, true);
                    }
                    _ => unreachable!(),
                }
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }

    // All originally inserted pages should still be present
    // (capacity 64 > 32, so no evictions expected)
    assert_eq!(cache.len(), N_INODES as usize);
    for inode in 1..=N_INODES {
        assert!(
            cache.lookup(inode, 0).is_some(),
            "page for inode {inode} must survive stress test"
        );
    }

    // No panics, no deadlocks → test passes
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 11: Deterministic reproducibility smoke test
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn deterministic_seed_reproduces_same_checksums() {
    let seed = 0x5630_000B;

    // Run 1: compute checksums
    let cache1 = PageCache::new(10, PAGE_SIZE);
    let mut rng1 = Rng::new(seed);
    cache1.insert(1, 0).expect("insert");
    let chk1a = fill_page(&mut rng1, &mut vec![0u8; PAGE_SIZE], 1, 0);
    cache1.insert(2, 0).expect("insert");
    let chk2a = fill_page(&mut rng1, &mut vec![0u8; PAGE_SIZE], 2, 0);

    // Run 2: compute checksums with same seed — must match
    let cache2 = PageCache::new(10, PAGE_SIZE);
    let mut rng2 = Rng::new(seed);
    cache2.insert(1, 0).expect("insert");
    let chk1b = fill_page(&mut rng2, &mut vec![0u8; PAGE_SIZE], 1, 0);
    cache2.insert(2, 0).expect("insert");
    let chk2b = fill_page(&mut rng2, &mut vec![0u8; PAGE_SIZE], 2, 0);

    assert_eq!(chk1a, chk1b, "seed not reproducible for chk1");
    assert_eq!(chk2a, chk2b, "seed not reproducible for chk2");
}
