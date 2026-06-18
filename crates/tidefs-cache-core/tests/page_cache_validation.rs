// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the page-cache surface in tidefs-cache-core.
//!
//! These tests exercise the public [`PageCache`] API as an external consumer
//! would. The in-module `#[cfg(test)]` tests in page_cache.rs cover basic
//! mechanics; these integration tests focus on edge cases and behavioral
//! invariants that are observable through the public API.
//!
//! All tests must respect the PageCache contract: never call PageCache
//! methods while holding a PageHandle, as that would deadlock on the
//! internal mutex.

use tidefs_cache_core::page_cache::{page_flags, InsertError, PageCache, PageKey};

const PAGE_SIZE: usize = 4096;

fn new_cache(cap: usize) -> PageCache {
    PageCache::new(cap, PAGE_SIZE)
}

// ── Group 1: insert / lookup / remove basics ───────────────────────

#[test]
fn insert_returns_page_key() {
    let cache = new_cache(10);
    let key = cache.insert(1, 0).expect("insert should succeed");
    assert_eq!(key.inode, 1);
    assert_eq!(key.offset, 0);
}

#[test]
fn insert_then_lookup_returns_handle() {
    let cache = new_cache(10);
    cache.insert(42, PAGE_SIZE as u64).unwrap();

    let handle = cache
        .lookup(42, PAGE_SIZE as u64)
        .expect("lookup should hit");
    assert_eq!(handle.key().inode, 42);
    assert_eq!(handle.key().offset, PAGE_SIZE as u64);
    assert_eq!(handle.data().len(), PAGE_SIZE);
    assert!(!handle.is_dirty());
    assert!(!handle.is_writeback());
    drop(handle);
}

#[test]
fn remove_evicts_page() {
    let cache = new_cache(10);
    cache.insert(7, 0).unwrap();
    assert_eq!(cache.len(), 1);

    let page = cache.remove(7, 0).expect("remove should return page");
    assert_eq!(page.key.inode, 7);
    assert_eq!(cache.len(), 0);
}

#[test]
fn lookup_after_remove_returns_none() {
    let cache = new_cache(10);
    cache.insert(9, 0).unwrap();
    cache.remove(9, 0).unwrap();
    assert!(cache.lookup(9, 0).is_none());
}

#[test]
fn remove_nonexistent_returns_none() {
    let cache = new_cache(10);
    assert!(cache.remove(999, 0).is_none());
}

#[test]
fn lookup_miss_on_empty_cache() {
    let cache = new_cache(10);
    assert!(cache.lookup(1, 0).is_none());
    assert!(cache.lookup(0, 0).is_none());
    assert_eq!(cache.miss_count(), 2);
    assert_eq!(cache.hit_count(), 0);
}

// ── Group 2: LRU eviction order & capacity invariants ─────────────

#[test]
fn capacity_invariant_after_eviction_pressure() {
    let cache = new_cache(4);

    for i in 0..4 {
        cache.insert(i, 0).unwrap();
    }
    assert!(cache.is_full());
    assert_eq!(cache.len(), 4);

    cache.insert(10, 0).unwrap();
    assert_eq!(cache.len(), 4);
    assert!(
        cache.lookup(0, 0).is_none(),
        "oldest page should be evicted"
    );

    cache.insert(11, 0).unwrap();
    assert_eq!(cache.len(), 4);
    assert!(cache.lookup(1, 0).is_none());

    assert_eq!(cache.eviction_count(), 2);
}

#[test]
fn touch_promotes_to_mru_and_avoids_eviction() {
    let cache = new_cache(3);

    cache.insert(10, 0).unwrap();
    cache.insert(20, 0).unwrap();
    cache.insert(30, 0).unwrap();

    // Touch oldest (10), moving it to MRU
    {
        let _h = cache.lookup(10, 0).expect("should find 10");
    }

    // Insert beyond capacity: 20 (now oldest) evicted
    cache.insert(40, 0).unwrap();
    assert!(
        cache.lookup(20, 0).is_none(),
        "20 should be oldest and evicted"
    );
    assert!(
        cache.lookup(10, 0).is_some(),
        "10 was touched, should remain"
    );
    assert!(cache.lookup(30, 0).is_some());
    assert!(cache.lookup(40, 0).is_some());
    assert_eq!(cache.len(), 3);
}

#[test]
fn eviction_skips_when_all_dirty_or_pinned() {
    let cache = new_cache(2);

    cache.insert(100, 0).unwrap();
    cache.insert(200, 0).unwrap();
    cache.mark_dirty(100, 0);
    cache.mark_dirty(200, 0);

    let err = cache.insert(300, 0).unwrap_err();
    assert_eq!(err, InsertError::AtCapacityNoCleanPages);
    assert_eq!(cache.len(), 2);
}

// ── Group 3: dirty / writeback / clean lifecycle ──────────────────

#[test]
fn mark_dirty_via_convenience() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();

    assert!(cache.mark_dirty(1, 0));
    {
        let h = cache.lookup(1, 0).unwrap();
        assert!(h.is_dirty());
    }
}

#[test]
fn mark_dirty_nonexistent_returns_false() {
    let cache = new_cache(10);
    assert!(!cache.mark_dirty(99, 0));
}

#[test]
fn dirty_page_appears_in_dirty_iterator() {
    let cache = new_cache(10);

    for i in 0..5 {
        cache.insert(i, 0).unwrap();
    }
    cache.mark_dirty(1, 0);
    cache.mark_dirty(3, 0);

    let dirty = cache.dirty_pages();
    assert_eq!(dirty.len(), 2);
    let inodes: Vec<u64> = dirty.iter().map(|k| k.inode).collect();
    assert!(inodes.contains(&1));
    assert!(inodes.contains(&3));
    assert!(!inodes.contains(&0));
}

#[test]
fn full_writeback_cycle_success() {
    let cache = new_cache(10);
    cache.insert(5, 0).unwrap();

    cache.mark_dirty(5, 0);
    assert!(cache.dirty_pages().iter().any(|k| k.inode == 5));

    assert!(cache.start_writeback(5, 0));
    {
        let h = cache.lookup(5, 0).unwrap();
        assert!(h.is_writeback());
        assert!(h.is_pinned());
        assert!(h.is_dirty());
    }

    assert!(cache.complete_writeback(5, 0, true));
    {
        let h = cache.lookup(5, 0).unwrap();
        assert!(!h.is_writeback());
        assert!(!h.is_pinned());
        assert!(!h.is_dirty());
    }
    assert!(cache.dirty_pages().iter().all(|k| k.inode != 5));
}

#[test]
fn writeback_failure_retains_dirty() {
    let cache = new_cache(10);
    cache.insert(6, 0).unwrap();
    cache.mark_dirty(6, 0);
    cache.start_writeback(6, 0);

    assert!(cache.complete_writeback(6, 0, false));
    {
        let h = cache.lookup(6, 0).unwrap();
        assert!(!h.is_writeback());
        assert!(!h.is_pinned());
        assert!(h.is_dirty());
    }
}

#[test]
fn abort_writeback_preserves_dirty() {
    let cache = new_cache(10);
    cache.insert(7, 0).unwrap();
    cache.mark_dirty(7, 0);
    cache.start_writeback(7, 0);

    assert!(cache.abort_writeback(7, 0));
    {
        let h = cache.lookup(7, 0).unwrap();
        assert!(!h.is_writeback());
        assert!(!h.is_pinned());
        assert!(h.is_dirty());
    }
}

#[test]
fn start_writeback_twice_fails() {
    let cache = new_cache(10);
    cache.insert(8, 0).unwrap();
    cache.mark_dirty(8, 0);

    assert!(cache.start_writeback(8, 0));
    assert!(!cache.start_writeback(8, 0));
}

// ── Group 4: concurrent access ────────────────────────────────────

#[test]
fn concurrent_distinct_inserts_no_cross_talk() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(new_cache(100));
    let mut threads = Vec::new();

    for tid in 0..4 {
        let c = Arc::clone(&cache);
        threads.push(thread::spawn(move || {
            let base = tid * 25;
            for i in 0..25 {
                let inode = base + i;
                c.insert(inode, 0).ok();
                let h = c.lookup(inode, 0);
                assert!(
                    h.is_some(),
                    "thread {tid}: insert+lookup for inode {inode} should succeed"
                );
                drop(h);
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    assert_eq!(cache.len(), 100);
    for i in 0..100 {
        let h = cache
            .lookup(i, 0)
            .expect("page should exist after concurrent insert");
        assert_eq!(h.key().inode, i);
        drop(h);
    }
}

#[test]
fn concurrent_writeback_on_distinct_pages() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(new_cache(50));

    for i in 0..40 {
        cache.insert(i, 0).unwrap();
        cache.mark_dirty(i, 0);
    }

    let mut threads = Vec::new();
    for tid in 0..4 {
        let c = Arc::clone(&cache);
        threads.push(thread::spawn(move || {
            let base = tid * 10;
            for i in base..(base + 10) {
                assert!(c.start_writeback(i, 0));
                assert!(c.complete_writeback(i, 0, true));
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    for i in 0..40 {
        let h = cache.lookup(i, 0).unwrap();
        assert!(!h.is_dirty(), "page {i} should be clean after writeback");
        assert!(!h.is_writeback());
        assert!(!h.is_pinned());
        drop(h);
    }
    assert!(cache.dirty_pages().is_empty());
}

// ── Group 5: PageHandle drop semantics ─────────────────────────────

#[test]
fn page_handle_drop_releases_lock() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();

    {
        let _h = cache.lookup(1, 0).unwrap();
        // _h holds the lock; dropping it should release.
    }

    // Must not deadlock
    let h2 = cache
        .lookup(1, 0)
        .expect("lookup after drop should succeed");
    assert!(!h2.is_dirty());
    drop(h2);
}

#[test]
fn page_handle_can_reacquire_after_insert() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();

    {
        let mut h = cache.lookup(1, 0).unwrap();
        h.mark_dirty();
    }

    // Re-acquire and verify dirty persisted
    let h2 = cache.lookup(1, 0).unwrap();
    assert!(h2.is_dirty());
    drop(h2);
}

#[test]
fn page_handle_guard_data_mutation_persists() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();

    {
        let mut h = cache.lookup(1, 0).unwrap();
        let buf = h.data_mut();
        buf[0] = 0xDE;
        buf[1] = 0xAD;
        buf[2] = 0xBE;
        buf[3] = 0xEF;
        buf[PAGE_SIZE - 1] = 0x42;
    }

    let h = cache.lookup(1, 0).unwrap();
    let buf = h.data();
    assert_eq!(buf[0], 0xDE);
    assert_eq!(buf[1], 0xAD);
    assert_eq!(buf[2], 0xBE);
    assert_eq!(buf[3], 0xEF);
    assert_eq!(buf[PAGE_SIZE - 1], 0x42);
    drop(h);
}

// ── Group 6: edge cases ───────────────────────────────────────────

#[test]
fn zero_capacity_cache_all_inserts_fail() {
    let cache = PageCache::new(0, PAGE_SIZE);

    let err = cache.insert(1, 0).unwrap_err();
    assert_eq!(err, InsertError::AtCapacityNoCleanPages);
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    assert_eq!(cache.capacity(), 0);
}

#[test]
fn zero_capacity_evict_one_returns_none() {
    let cache = PageCache::new(0, PAGE_SIZE);
    assert!(cache.evict_one().is_none());
}

#[test]
fn duplicate_insert_fails_with_already_exists() {
    let cache = new_cache(10);
    cache.insert(42, 4096).unwrap();

    let err = cache.insert(42, 4096).unwrap_err();
    assert_eq!(err, InsertError::AlreadyExists);

    assert!(cache.lookup(42, 4096).is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn remove_then_reinsert_same_key() {
    let cache = new_cache(10);
    cache.insert(99, 0).unwrap();
    cache.remove(99, 0).unwrap();
    assert!(cache.lookup(99, 0).is_none());

    cache.insert(99, 0).unwrap();
    // Drop handle before calling cache.len() to avoid deadlock
    {
        let h = cache.lookup(99, 0).unwrap();
        assert_eq!(h.key().inode, 99);
        assert!(!h.is_dirty());
    }
    assert_eq!(cache.len(), 1);
}

#[test]
fn evict_one_on_empty_cache_returns_none() {
    let cache = new_cache(10);
    assert!(cache.evict_one().is_none());
}

#[test]
fn stats_monotonic_with_operations() {
    let cache = new_cache(10);

    assert_eq!(cache.insert_count(), 0);
    assert_eq!(cache.hit_count(), 0);
    assert_eq!(cache.miss_count(), 0);
    assert_eq!(cache.eviction_count(), 0);

    cache.insert(1, 0).unwrap();
    assert_eq!(cache.insert_count(), 1);

    // Register a hit then drop handle before checking counter
    {
        let _h = cache.lookup(1, 0).unwrap();
    }
    assert_eq!(cache.hit_count(), 1);

    // Miss
    cache.lookup(99, 0);
    assert_eq!(cache.miss_count(), 1);

    // Fill to capacity then evict
    for i in 2..=11 {
        cache.insert(i, 0).unwrap();
    }
    assert_eq!(cache.insert_count(), 11);
    assert!(cache.eviction_count() >= 1);
}

#[test]
fn capacity_page_size_and_is_empty() {
    let cache = new_cache(8);
    assert_eq!(cache.capacity(), 8);
    assert_eq!(cache.page_size(), PAGE_SIZE);
    assert!(cache.is_empty());

    cache.insert(1, 0).unwrap();
    assert!(!cache.is_empty());
    assert!(!cache.is_full());
}

#[test]
fn is_full_accurate_at_capacity() {
    let cache = new_cache(3);

    assert!(!cache.is_full());
    cache.insert(1, 0).unwrap();
    cache.insert(2, 0).unwrap();
    assert!(!cache.is_full());
    cache.insert(3, 0).unwrap();
    assert!(cache.is_full());
}

#[test]
fn page_key_display_format() {
    let key = PageKey {
        inode: 42,
        offset: 8192,
    };
    let s = format!("{key}");
    assert_eq!(s, "ino:42@8192");
}

#[test]
fn page_is_clean_initially() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();
    let h = cache.lookup(1, 0).unwrap();
    assert!(!h.is_dirty());
    assert_eq!(h.flags(), page_flags::CLEAN);
    drop(h);
}

#[test]
fn clear_dirty_via_convenience() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();
    cache.mark_dirty(1, 0);
    assert!(cache.dirty_pages().iter().any(|k| k.inode == 1));

    assert!(cache.clear_dirty(1, 0));
    assert!(cache.dirty_pages().iter().all(|k| k.inode != 1));
    {
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_dirty());
    }
}

#[test]
fn clear_dirty_nonexistent_returns_false() {
    let cache = new_cache(10);
    assert!(!cache.clear_dirty(99, 0));
}

#[test]
fn complete_writeback_nonexistent_returns_false() {
    let cache = new_cache(10);
    assert!(!cache.complete_writeback(99, 0, true));
}

#[test]
fn start_writeback_nonexistent_returns_false() {
    let cache = new_cache(10);
    assert!(!cache.start_writeback(99, 0));
}

#[test]
fn abort_writeback_nonexistent_returns_false() {
    let cache = new_cache(10);
    assert!(!cache.abort_writeback(99, 0));
}

#[test]
fn eviction_increments_counter() {
    let cache = new_cache(2);
    assert_eq!(cache.eviction_count(), 0);

    cache.insert(1, 0).unwrap();
    cache.insert(2, 0).unwrap();
    cache.insert(3, 0).unwrap();
    assert_eq!(cache.eviction_count(), 1);

    cache.evict_one();
    assert_eq!(cache.eviction_count(), 2);
}

#[test]
fn insert_count_accurate_across_evictions() {
    let cache = new_cache(2);

    cache.insert(1, 0).unwrap();
    cache.insert(2, 0).unwrap();
    assert_eq!(cache.insert_count(), 2);

    cache.insert(3, 0).unwrap();
    assert_eq!(cache.insert_count(), 3);

    // AlreadyExists does not increment counter
    let _ = cache.insert(3, 0).unwrap_err();
    assert_eq!(cache.insert_count(), 3);
}

// ── Per-inode dirty page iteration ────────────────────────────────

#[test]
fn dirty_pages_for_inode_filters_by_inode() {
    let cache = new_cache(10);

    cache.insert(1, 0).unwrap();
    cache.insert(1, 4096).unwrap();
    cache.insert(2, 0).unwrap();
    cache.insert(3, 0).unwrap();

    cache.mark_dirty(1, 0);
    cache.mark_dirty(1, 4096);
    cache.mark_dirty(2, 0);

    let dirty_for_1 = cache.dirty_pages_for_inode(1);
    assert_eq!(dirty_for_1.len(), 2);
    for k in &dirty_for_1 {
        assert_eq!(k.inode, 1);
    }

    let dirty_for_2 = cache.dirty_pages_for_inode(2);
    assert_eq!(dirty_for_2.len(), 1);
    assert_eq!(
        dirty_for_2[0],
        PageKey {
            inode: 2,
            offset: 0
        }
    );

    assert!(cache.dirty_pages_for_inode(3).is_empty());
    assert!(cache.dirty_pages_for_inode(99).is_empty());
}

#[test]
fn clear_dirty_for_inode_clears_correct_inode_only() {
    let cache = new_cache(10);

    cache.insert(1, 0).unwrap();
    cache.insert(1, 4096).unwrap();
    cache.insert(2, 0).unwrap();

    cache.mark_dirty(1, 0);
    cache.mark_dirty(1, 4096);
    cache.mark_dirty(2, 0);

    let cleared = cache.clear_dirty_for_inode(1);
    assert_eq!(cleared, 2);
    assert!(cache.dirty_pages_for_inode(1).is_empty());

    // Inode 2 should still be dirty
    let dirty_for_2 = cache.dirty_pages_for_inode(2);
    assert_eq!(dirty_for_2.len(), 1);
}

#[test]
fn clear_dirty_for_inode_on_clean_inode_returns_zero() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();

    assert_eq!(cache.clear_dirty_for_inode(1), 0);
    assert_eq!(cache.clear_dirty_for_inode(99), 0);
}

#[test]
fn dirty_pages_for_inode_empty_when_none_dirty() {
    let cache = new_cache(10);
    cache.insert(1, 0).unwrap();
    cache.insert(1, 4096).unwrap();

    assert!(cache.dirty_pages_for_inode(1).is_empty());
}

#[test]
fn dirty_pages_for_inode_does_not_include_clean_pages() {
    let cache = new_cache(10);

    cache.insert(1, 0).unwrap();
    cache.insert(1, 4096).unwrap();

    cache.mark_dirty(1, 0);
    cache.clear_dirty(1, 0);
    assert!(cache.dirty_pages_for_inode(1).is_empty());

    cache.mark_dirty(1, 4096);
    let dirty = cache.dirty_pages_for_inode(1);
    assert_eq!(dirty.len(), 1);
    assert_eq!(
        dirty[0],
        PageKey {
            inode: 1,
            offset: 4096
        }
    );
}
