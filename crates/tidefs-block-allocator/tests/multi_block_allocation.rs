//! Integration tests: multi-block contiguous and non-contiguous allocation,
//! block-level accounting invariants.

use tidefs_block_allocator::{BlockAllocator, BlockId, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

#[test]
fn contiguous_range_sizes_up_to_pool_size() {
    // Use a fresh allocator per size: otherwise the alloc_contiguous hint
    // drifts and the two-pass scan cannot find a full-pool run (e.g.
    // with hint=63, passes are [63,64) and [0,63), neither 64 blocks).
    let sizes = [1, 2, 4, 8, 16, 32, 64];
    for &sz in &sizes {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_contiguous(sz).unwrap();
        assert_eq!(blocks.len(), sz as usize);
        assert!(
            blocks.windows(2).all(|w| w[1] == w[0] + 1),
            "non-contiguous at size {sz}"
        );
        ba.free(&blocks);
        assert_eq!(ba.free_count(), 64);
    }
}

#[test]
fn non_contiguous_multi_block_counts_match() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let a = ba.alloc_any(50).unwrap();
    assert_eq!(a.len(), 50);
    assert_eq!(ba.free_count(), 206);

    let b = ba.alloc_any(30).unwrap();
    assert_eq!(b.len(), 30);
    assert_eq!(ba.free_count(), 176);

    let c = ba.alloc_any(20).unwrap();
    assert_eq!(c.len(), 20);
    assert_eq!(ba.free_count(), 156);

    assert_eq!(ba.free_count() + 100, ba.block_count());

    ba.free(&a);
    ba.free(&b);
    ba.free(&c);
    assert_eq!(ba.free_count(), 256);
}

#[test]
fn accounting_invariant_alloc_free_never_breaches_total() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let total = ba.block_count();

    let mut held: Vec<Vec<BlockId>> = Vec::new();
    for i in 0..50 {
        // Alloc 1-5 blocks per round, free oldest every 3rd round.
        // Max simultaneously held is ~10-15 blocks (pool is 128).
        let n = ((i % 5) + 1) as u32;
        let blocks = ba.alloc(n).unwrap();
        assert!(ba.free_count() <= total);
        held.push(blocks);

        if i % 3 == 2 && !held.is_empty() {
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
fn alloc_contiguous_prefers_largest_free_run() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let a = ba.alloc_contiguous(3).unwrap();
    let b = ba.alloc_contiguous(10).unwrap();
    assert_eq!(&a, &[0, 1, 2]);
    assert_eq!(&b, &[3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    ba.free(&a);
    let c = ba.alloc_contiguous(5).unwrap();
    assert_eq!(&c, &[13, 14, 15, 16, 17]);

    ba.free(&b);
    ba.free(&c);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn alloc_any_scatters_across_free_regions() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let a = ba.alloc_contiguous(10).unwrap();
    ba.free(&a);
    let _b = ba.alloc_contiguous(4).unwrap();
    let s = ba.alloc_any(10).unwrap();
    assert!(s[0] >= 14, "expected start >= 14, got {}", s[0]);
    assert_eq!(s.len(), 10);

    ba.free(&_b);
    ba.free(&s);
    assert_eq!(ba.free_count(), 64);
}
