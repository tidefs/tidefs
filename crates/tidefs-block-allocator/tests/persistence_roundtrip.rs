// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: persistence roundtrip.
//!
//! Serialize allocator state (flush_words), deserialize into a fresh
//! instance, verify identical free/allocated set, allocate after restart
//! and confirm no corruption.

use tidefs_block_allocator::{AllocError, BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

#[test]
fn flush_words_reconstruct_identical_state() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let a = ba.alloc_contiguous(10).unwrap();
    let b = ba.alloc_any(15).unwrap();
    let c = ba.alloc_contiguous(5).unwrap();

    let words = ba.flush_words();
    let free_before = ba.free_count();

    let ba2 = BlockAllocator::from_persisted(256, 4096, region(256), words);
    assert_eq!(ba2.free_count(), free_before);
    assert_eq!(ba2.block_count(), 256);
    assert_eq!(ba2.block_size(), 4096);

    ba.free(&a);
    ba.free(&b);
    ba.free(&c);
    assert_eq!(ba.free_count(), 256);

    assert_eq!(ba2.free_count(), free_before);
}

#[test]
fn allocate_after_restart_no_corruption() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let pre = ba.alloc_any(50).unwrap();
    assert_eq!(ba.free_count(), 206);

    let words = ba.flush_words();
    ba.mark_clean();

    let ba2 = BlockAllocator::from_persisted(256, 4096, region(256), words);
    assert_eq!(ba2.free_count(), 206);

    let post = ba2.alloc_contiguous(30).unwrap();
    assert_eq!(post.len(), 30);
    assert_eq!(ba2.free_count(), 176);

    ba2.free(&pre);
    ba2.free(&post);
    assert_eq!(ba2.free_count(), 256);
}

#[test]
fn multi_cycle_persistence() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    ba.alloc_contiguous(10).unwrap();
    let words1 = ba.flush_words();
    assert!(ba.is_dirty());
    ba.mark_clean();
    assert!(!ba.is_dirty());

    ba.alloc_any(20).unwrap();
    let words2 = ba.flush_words();
    ba.mark_clean();

    let ba2 = BlockAllocator::from_persisted(128, 4096, region(128), words2);
    assert_eq!(ba2.free_count(), 98);

    let ba1 = BlockAllocator::from_persisted(128, 4096, region(128), words1);
    assert_eq!(ba1.free_count(), 118);
}

#[test]
fn root_reserve_preserved_through_persistence() {
    let ba = BlockAllocator::with_root_reserve(128, 4096, region(128), 16);
    ba.alloc_any(20).unwrap();
    let words = ba.flush_words();

    let ba2 = BlockAllocator::from_persisted_with_root_reserve(128, 4096, region(128), words, 16);
    assert_eq!(ba2.free_count(), 108);

    let s = ba2.allocator_statfs();
    assert_eq!(s.f_bfree, 108);
    assert_eq!(s.f_bavail, 92);

    assert!(ba2.alloc_any(93).is_err());
    assert!(ba2.alloc_any(92).is_ok());
}

#[test]
fn flush_to_sink_then_reconstruct() {
    use tidefs_block_allocator::BitmapFlushSink;

    #[derive(Default)]
    struct Sink {
        region: Option<Region>,
        words: Vec<u64>,
    }

    impl BitmapFlushSink for Sink {
        fn write_bitmap(&mut self, region: Region, words: &[u64]) -> Result<(), AllocError> {
            self.region = Some(region);
            self.words = words.to_vec();
            Ok(())
        }
    }

    let ba = BlockAllocator::new(64, 4096, region(64));
    ba.alloc(5).unwrap();
    assert!(ba.is_dirty());

    let mut sink = Sink::default();
    ba.flush_to(&mut sink).unwrap();
    assert!(!ba.is_dirty());

    let ba2 = BlockAllocator::from_persisted(64, 4096, sink.region.unwrap(), sink.words);
    assert_eq!(ba2.free_count(), 59);
    assert!(!ba2.is_dirty());
}

#[test]
fn dirty_flag_clears_after_flush() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    assert!(ba.is_dirty());
    ba.alloc(3).unwrap();
    assert!(ba.is_dirty());

    let _words = ba.flush_words();
    ba.flush().unwrap();
    assert!(!ba.is_dirty());

    ba.alloc_any(2).unwrap();
    assert!(ba.is_dirty());
}
