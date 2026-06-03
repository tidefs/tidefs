//! Space accounting tests for tidefs-block-allocator.
//!
//! Verifies that free_count, block_count, statfs, and derived byte-level
//! counters stay consistent across single-block alloc, multi-block alloc,
//! aligned/unaligned byte allocations, near-full-pool edge cases, and
//! root-reserve withholding.

use tidefs_block_allocator::{AllocError, AllocatorTopology, BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

fn allocated(ba: &BlockAllocator) -> u64 {
    ba.block_count() - ba.free_count()
}

// ─── Single-block alloc / free accounting ─────────────────────────────

#[test]
fn single_block_alloc_decrements_free_count() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    assert_eq!(ba.free_count(), 128);
    let b = ba.alloc(1).unwrap();
    assert_eq!(ba.free_count(), 127);
    assert_eq!(allocated(&ba), 1);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
    assert_eq!(allocated(&ba), 0);
}

#[test]
fn multi_block_alloc_decrements_by_n() {
    let sizes = [1, 2, 3, 5, 8, 13, 21];
    for &n in &sizes {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let b = ba.alloc(n).unwrap();
        assert_eq!(b.len(), n as usize);
        assert_eq!(ba.free_count(), 128 - n as u64);
        assert_eq!(allocated(&ba), n as u64);
        ba.free(&b);
        assert_eq!(ba.free_count(), 128);
    }
}

#[test]
fn alloc_any_and_alloc_contiguous_accounting() {
    let ba = BlockAllocator::new(256, 4096, region(256));

    let c = ba.alloc_contiguous(10).unwrap();
    assert_eq!(ba.free_count(), 246);
    assert_eq!(allocated(&ba), 10);

    let a = ba.alloc_any(15).unwrap();
    assert_eq!(ba.free_count(), 231);
    assert_eq!(allocated(&ba), 25);

    ba.free(&c);
    assert_eq!(ba.free_count(), 241);
    assert_eq!(allocated(&ba), 15);

    ba.free(&a);
    assert_eq!(ba.free_count(), 256);
    assert_eq!(allocated(&ba), 0);
}

// ─── Accounting invariant: free + allocated == total ──────────────────

#[test]
fn invariant_free_plus_allocated_equals_total() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let total = ba.block_count();

    let a = ba.alloc(10).unwrap();
    assert_eq!(ba.free_count() + allocated(&ba), total);

    let b = ba.alloc_contiguous(5).unwrap();
    assert_eq!(ba.free_count() + allocated(&ba), total);

    let c = ba.alloc_any(7).unwrap();
    assert_eq!(ba.free_count() + allocated(&ba), total);

    ba.free(&a[..3]);
    assert_eq!(ba.free_count() + allocated(&ba), total);

    ba.free(&b);
    assert_eq!(ba.free_count() + allocated(&ba), total);

    ba.free(&a[3..]);
    ba.free(&c);
    assert_eq!(ba.free_count() + allocated(&ba), total);
}

// ─── Accounting never exceeds bounds ──────────────────────────────────

#[test]
fn accounting_never_exceeds_pool_size() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let total = ba.block_count();

    let mut held: Vec<Vec<u64>> = Vec::new();
    for i in 0..200 {
        let n = ((i % 5) + 1) as u32;
        match ba.alloc(n) {
            Ok(blocks) => {
                assert!(ba.free_count() <= total);
                assert!(allocated(&ba) <= total);
                held.push(blocks);
            }
            Err(AllocError::NoSpace) => {
                for batch in held.drain(..) {
                    ba.free(&batch);
                }
                assert!(ba.free_count() <= total);
            }
            Err(_) => panic!("unexpected error"),
        }
        if held.len() > 30 {
            let old = held.remove(0);
            ba.free(&old);
        }
    }
    for batch in held.drain(..) {
        ba.free(&batch);
    }
    assert_eq!(ba.free_count(), total);
}

#[test]
fn accounting_never_goes_negative() {
    let ba = BlockAllocator::new(128, 4096, region(128));

    // Free unallocated blocks (noop, must not corrupt).
    ba.free(&[100, 200, 300]);
    assert!(ba.free_count() <= ba.block_count());

    for _ in 0..50 {
        let b = ba.alloc(1).unwrap();
        ba.free(&b);
        assert!(ba.free_count() <= ba.block_count());
    }
}

// ─── Near-full-pool edge cases ────────────────────────────────────────

#[test]
fn near_full_pool_one_block_remaining() {
    let ba = BlockAllocator::new(64, 4096, region(64));

    let large = ba.alloc(63).unwrap();
    assert_eq!(ba.free_count(), 1);
    assert_eq!(allocated(&ba), 63);

    let last = ba.alloc(1).unwrap();
    assert_eq!(ba.free_count(), 0);
    assert_eq!(allocated(&ba), 64);

    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 0);
    assert_eq!(s.f_blocks, 64);

    ba.free(&large);
    ba.free(&last);
    assert_eq!(ba.free_count(), 64);
}

// ─── statfs consistency ───────────────────────────────────────────────

#[test]
fn statfs_reports_correct_block_counts() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let s = ba.allocator_statfs();
    assert_eq!(s.f_blocks, 256);
    assert_eq!(s.f_bfree, 256);
    assert_eq!(s.f_bavail, 256);
    assert_eq!(s.f_bsize, 4096);
    assert_eq!(s.f_frsize, 4096);

    let a = ba.alloc_any(50).unwrap();
    let s = ba.allocator_statfs();
    assert_eq!(s.f_blocks, 256);
    assert_eq!(s.f_bfree, 206);
    assert_eq!(s.f_bavail, 206);

    let b = ba.alloc_any(206).unwrap();
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 0);
    assert_eq!(s.f_bavail, 0);

    ba.free(&a);
    ba.free(&b);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 256);
}

#[test]
fn statfs_with_root_reserve() {
    let ba = BlockAllocator::with_root_reserve(100, 4096, region(100), 20);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_blocks, 100);
    assert_eq!(s.f_bfree, 100);
    assert_eq!(s.f_bavail, 80);

    let a = ba.alloc_any(80).unwrap();
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 20);
    assert_eq!(s.f_bavail, 0);

    assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));

    ba.free(&a);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 100);
    assert_eq!(s.f_bavail, 80);
}

#[test]
fn statfs_free_bytes_equals_free_count_times_block_size() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree * s.f_bsize, 128 * 4096);

    let a = ba.alloc(30).unwrap();
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree * s.f_bsize, 98 * 4096);

    ba.free(&a);
}

// ─── Byte-level allocation accounting ─────────────────────────────────

#[test]
fn alloc_bytes_accounting() {
    let ba = BlockAllocator::new(128, 4096, region(128));

    let b1 = ba.alloc_bytes(4096).unwrap();
    assert_eq!(b1.len(), 1);
    assert_eq!(ba.free_count(), 127);

    let b2 = ba.alloc_bytes(12288).unwrap();
    assert_eq!(b2.len(), 3);
    assert_eq!(ba.free_count(), 124);

    let b3 = ba.alloc_bytes(5000).unwrap();
    assert_eq!(b3.len(), 2);
    assert_eq!(ba.free_count(), 122);

    ba.free(&b1);
    ba.free(&b2);
    ba.free(&b3);
    assert_eq!(ba.free_count(), 128);
}

#[test]
fn alloc_bytes_at_accounting_with_different_sector_sizes() {
    // Default 512B logical: 513 bytes → rounds to 1024 → 1 block.
    let ba = BlockAllocator::new(128, 4096, region(128));
    let b = ba.alloc_bytes_at(0, 513).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(ba.free_count(), 127);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);

    // 4K logical device: 1 byte → rounds to 4096 → 1 block.
    let t = AllocatorTopology::new(4096, 0);
    let ba = BlockAllocator::with_topology(128, 4096, region(128), t, 0);
    let b = ba.alloc_bytes_at(0, 4096).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(ba.free_count(), 127);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
}

// ─── Accounting after persist / restore ───────────────────────────────

#[test]
fn accounting_survives_persist_restore_roundtrip() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_contiguous(10).unwrap();
    let b = ba.alloc_any(5).unwrap();

    let words = ba.flush_words();
    let free_before = ba.free_count();

    let ba2 = BlockAllocator::from_persisted(128, 4096, region(128), words);
    assert_eq!(ba2.free_count(), free_before);
    assert_eq!(ba2.block_count(), 128);

    let s1 = ba.allocator_statfs();
    let s2 = ba2.allocator_statfs();
    assert_eq!(s1.f_blocks, s2.f_blocks);
    assert_eq!(s1.f_bfree, s2.f_bfree);

    ba.free(&a);
    ba.free(&b);
}

// ─── Accounting across all three alloc paths ──────────────────────────

#[test]
fn all_three_alloc_paths_consistent_accounting() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let total = ba.block_count();

    let a1 = ba.alloc(5).unwrap();
    assert_eq!(ba.free_count(), total - 5);

    let a2 = ba.alloc_contiguous(3).unwrap();
    assert_eq!(ba.free_count(), total - 8);

    let a3 = ba.alloc_any(7).unwrap();
    assert_eq!(ba.free_count(), total - 15);

    ba.free(&a1);
    ba.free(&a2);
    ba.free(&a3);
    assert_eq!(ba.free_count(), total);
}

// ─── Root-reserve accounting edge ─────────────────────────────────────

#[test]
fn root_reserve_exceeds_pool_size() {
    let ba = BlockAllocator::with_root_reserve(16, 4096, region(16), 16);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 16);
    assert_eq!(s.f_bavail, 0);
    assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));
}

#[test]
fn root_reserve_zero_behaves_normally() {
    let ba = BlockAllocator::with_root_reserve(64, 4096, region(64), 0);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 64);
    assert_eq!(s.f_bavail, 64);
    ba.alloc_any(64).unwrap();
    assert_eq!(ba.free_count(), 0);
}

#[test]
fn total_committed_summary_in_statfs_context() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    // total_committed tracks committed quota blocks across inodes.
    // It starts at 0 with no inode activity.
    assert_eq!(ba.total_committed(), 0);

    // After reserve+commit, total_committed increases.
    let ino = tidefs_types_vfs_core::InodeId::new(1);
    ba.reserve(ino, 10).unwrap();
    ba.commit(ino, 10);
    assert_eq!(ba.total_committed(), 10);

    ba.uncommit(ino, 10);
    assert_eq!(ba.total_committed(), 0);
}
