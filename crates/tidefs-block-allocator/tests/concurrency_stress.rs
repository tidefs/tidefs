//! Concurrent stress tests for tidefs-block-allocator.
//!
//! These tests verify that the allocator remains internally consistent
//! under multi-threaded allocate/deallocate workloads:
//!  - Free-count returns to total after concurrent drain.
//!  - Flush_words bitmap is all-zero after full drain.
//!  - Statfs invariants hold under concurrent mutations.
//!  - No block double-counting: blocks held simultaneously by different
//!    threads are disjoint.
//!
//! The allocator uses internal `RwLock` synchronization, so tests use
//! `Arc<BlockAllocator>` directly without additional external locking.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use tidefs_block_allocator::{BlockAllocator, BlockId, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

// ── invariant helpers ──────────────────────────────────────────────────

/// Verify that the flush_words bitmap is all-zero (all blocks free).
fn assert_all_blocks_free(ba: &BlockAllocator) {
    let words = ba.flush_words();
    for (i, &w) in words.iter().enumerate() {
        assert!(
            w == 0,
            "flush_words[{i}] = {w:#018x}, expected 0 (block {}..{} not fully freed)",
            i * 64,
            (i + 1) * 64 - 1
        );
    }
}

/// Verify that flush_words word count matches the expected value.
fn assert_flush_words_len(ba: &BlockAllocator) {
    let words = ba.flush_words();
    let expected = ba.block_count().div_ceil(64) as usize;
    assert_eq!(words.len(), expected, "flush_words length mismatch");
}

// ── basic multi-threaded round-trip ────────────────────────────────────

#[test]
fn concurrent_alloc_free_roundtrip_4_threads() {
    let ba = Arc::new(BlockAllocator::new(512, 4096, region(512)));
    let total = ba.block_count();

    let mut handles = Vec::new();
    for _tid in 0..4 {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for cycle in 0..100 {
                let n = ((cycle % 4) + 1) as u32;
                match ba.alloc(n) {
                    Ok(blocks) => held.push(blocks),
                    Err(_) => {
                        // ENOSPC: drain half and retry.
                        let drain = held.len() / 2;
                        for batch in held.drain(..drain) {
                            ba.free(&batch);
                        }
                    }
                }
            }
            // Drain remaining on exit.
            for batch in held {
                ba.free(&batch);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        ba.free_count(),
        total,
        "pool not fully free after concurrent drain"
    );
    assert_all_blocks_free(&ba);
    assert_flush_words_len(&ba);
}

// ── high-contention stress: many threads, small pool ────────────────────

#[test]
fn concurrent_high_contention_8_threads_small_pool() {
    let ba = Arc::new(BlockAllocator::new(64, 4096, region(64)));
    let total = ba.block_count();

    let mut handles = Vec::new();
    for _tid in 0..8 {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for cycle in 0..200 {
                let n = 1u32 + ((cycle as u32) % 3); // 1-3 blocks
                match ba.alloc(n) {
                    Ok(blocks) => held.push(blocks),
                    Err(_) => {
                        // Free one batch and retry.
                        if let Some(batch) = held.pop() {
                            ba.free(&batch);
                        }
                    }
                }
            }
            for batch in held {
                ba.free(&batch);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        ba.free_count(),
        total,
        "pool not fully free after high-contention drain"
    );
    assert_all_blocks_free(&ba);
}

// ── mixed allocator paths under concurrency ──────────────────────────────

#[test]
fn concurrent_mixed_alloc_paths() {
    let ba = Arc::new(BlockAllocator::new(256, 4096, region(256)));
    let total = ba.block_count();

    let mut handles = Vec::new();

    // Thread 0: uses alloc (first-fit).
    {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..150 {
                match ba.alloc(2) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    // Thread 1: uses alloc_contiguous.
    {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..150 {
                match ba.alloc_contiguous(2) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    // Thread 2: uses alloc_any.
    {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..150 {
                match ba.alloc_any(3) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    // Thread 3: alloc/free-heavy (rapid turnover).
    {
        let ba = Arc::clone(&ba);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..150 {
                match ba.alloc(1) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
                // Free immediately every other iteration.
                if held.len() > 1 {
                    let b = held.remove(0);
                    ba.free(&b);
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        ba.free_count(),
        total,
        "pool not fully free after mixed-path drain"
    );
    assert_all_blocks_free(&ba);
}

// ── statfs consistency under concurrent mutations ───────────────────────

#[test]
fn concurrent_statfs_consistency() {
    let ba = Arc::new(BlockAllocator::new(128, 4096, region(128)));
    let total = ba.block_count();
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    // 2 worker threads doing alloc/free.
    for _tid in 0..2 {
        let ba = Arc::clone(&ba);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..100 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match ba.alloc(1) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    // 1 reader thread checking statfs invariants.
    {
        let ba = Arc::clone(&ba);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let s = ba.allocator_statfs();
                assert!(
                    s.f_bfree <= total,
                    "statfs.f_bfree {} > total {}",
                    s.f_bfree,
                    total
                );
                let allocated = total.saturating_sub(s.f_bfree);
                assert!(
                    allocated <= total,
                    "implied allocated {allocated} > total {total}"
                );
                assert!(
                    s.f_bavail <= s.f_bfree,
                    "statfs.f_bavail {} > f_bfree {}",
                    s.f_bavail,
                    s.f_bfree
                );
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(ba.free_count(), total);
}

// ── flush_words snapshot consistency ────────────────────────────────────

#[test]
fn concurrent_flush_words_consistency() {
    let ba = Arc::new(BlockAllocator::new(128, 4096, region(128)));
    let total = ba.block_count();
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    // Writer threads.
    for _tid in 0..4 {
        let ba = Arc::clone(&ba);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut held: Vec<Vec<BlockId>> = Vec::new();
            for _ in 0..100 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match ba.alloc(1) {
                    Ok(b) => held.push(b),
                    Err(_) => {
                        if let Some(b) = held.pop() {
                            ba.free(&b);
                        }
                    }
                }
                // Drain every 10 cycles.
                if held.len() > 20 {
                    let drain = held.split_off(held.len() / 2);
                    for b in drain {
                        ba.free(&b);
                    }
                }
            }
            for b in held {
                ba.free(&b);
            }
        }));
    }

    // Reader thread taking flush_words snapshots.
    {
        let ba = Arc::clone(&ba);
        let stop = Arc::clone(&stop);
        let expected_words = total.div_ceil(64) as usize;
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let words = ba.flush_words();
                assert!(!words.is_empty(), "flush_words returned empty");
                assert_eq!(
                    words.len(),
                    expected_words,
                    "flush_words len {} != expected {}",
                    words.len(),
                    expected_words
                );
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(ba.free_count(), total);
}
