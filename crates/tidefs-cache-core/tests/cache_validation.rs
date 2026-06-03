//! Comprehensive cache-core validation covering page states, dirty tracking,
//! LRU ordering, eviction policy, pin lifecycle, and edge cases.
//!
//! These tests exercise the public [`PageCache`] API from `tidefs_cache_core`.
//! They complement the in-module tests in `page_cache.rs` and the integration
//! tests in `page_cache_validation.rs` by providing methodical state-machine
//! coverage, systematic LRU ordering verification, and pin-lifecycle
//! scenarios. Tests avoid duplicating coverage already present in the other
//! two test suites.

use tidefs_cache_core::page_cache::{page_flags, InsertError, PageCache};

const PAGE_SIZE: usize = 4096;

fn new_cache(cap: usize) -> PageCache {
    PageCache::new(cap, PAGE_SIZE)
}

fn insert_one(cache: &PageCache, inode: u64, offset: u64) {
    cache.insert(inode, offset).expect("insert should succeed");
}

// ====================================================================
// Group 1: Page state machine
// ====================================================================

mod page_state_machine {
    use super::*;

    // ── 1a. Initial state ────────────────────────────────────────────

    #[test]
    fn fresh_page_is_clean() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_dirty(), "fresh page must not be dirty");
        assert!(!h.is_writeback(), "fresh page must not be in writeback");
        assert!(!h.is_pinned(), "fresh page must not be pinned");
        assert_eq!(
            h.flags(),
            page_flags::CLEAN,
            "fresh page flags must be CLEAN (0)"
        );
        drop(h);
    }

    #[test]
    fn fresh_page_flags_are_zero() {
        let cache = new_cache(10);
        insert_one(&cache, 2, 0);
        let h = cache.lookup(2, 0).unwrap();
        assert_eq!(h.flags(), 0);
        drop(h);
    }

    // ── 1b. Clean → Dirty ────────────────────────────────────────────

    #[test]
    fn mark_dirty_transitions_from_clean() {
        let cache = new_cache(10);
        insert_one(&cache, 3, 0);
        {
            let mut h = cache.lookup(3, 0).unwrap();
            h.mark_dirty();
            assert!(h.is_dirty(), "page should be dirty after mark_dirty");
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert_eq!(h.flags(), page_flags::DIRTY);
        }
        let h = cache.lookup(3, 0).unwrap();
        assert!(h.is_dirty());
        drop(h);
    }

    #[test]
    fn mark_dirty_is_idempotent() {
        let cache = new_cache(10);
        insert_one(&cache, 33, 0);
        {
            let mut h = cache.lookup(33, 0).unwrap();
            h.mark_dirty();
            h.mark_dirty();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }
    }

    // ── 1c. Dirty → Clean (clear_dirty) ─────────────────────────────

    #[test]
    fn clear_dirty_transitions_to_clean() {
        let cache = new_cache(10);
        insert_one(&cache, 4, 0);
        cache.mark_dirty(4, 0);
        assert!(cache.clear_dirty(4, 0));
        let h = cache.lookup(4, 0).unwrap();
        assert!(!h.is_dirty());
        assert_eq!(h.flags(), page_flags::CLEAN);
        drop(h);
    }

    #[test]
    fn clear_dirty_via_handle() {
        let cache = new_cache(10);
        insert_one(&cache, 44, 0);
        {
            let mut h = cache.lookup(44, 0).unwrap();
            h.mark_dirty();
            assert!(h.is_dirty());
            h.clear_dirty();
            assert!(!h.is_dirty());
            assert_eq!(h.flags(), page_flags::CLEAN);
        }
    }

    // ── 1d. Dirty → Writeback ────────────────────────────────────────

    #[test]
    fn dirty_to_writeback_success() {
        let cache = new_cache(10);
        insert_one(&cache, 5, 0);
        cache.mark_dirty(5, 0);
        cache.start_writeback(5, 0);
        let h = cache.lookup(5, 0).unwrap();
        assert!(h.is_dirty(), "dirty persists during writeback");
        assert!(h.is_writeback(), "writeback flag set");
        assert!(h.is_pinned(), "page is pinned during writeback");
        assert_eq!(h.flags() & page_flags::DIRTY, page_flags::DIRTY);
        assert_eq!(h.flags() & page_flags::WRITEBACK, page_flags::WRITEBACK);
        assert_eq!(h.flags() & page_flags::PINNED, page_flags::PINNED);
        drop(h);
    }

    // ── 1e. Writeback → Clean (successful completion) ────────────────

    #[test]
    fn writeback_success_clears_all() {
        let cache = new_cache(10);
        insert_one(&cache, 6, 0);
        cache.mark_dirty(6, 0);
        cache.start_writeback(6, 0);
        assert!(cache.complete_writeback(6, 0, true));
        let h = cache.lookup(6, 0).unwrap();
        assert!(!h.is_dirty());
        assert!(!h.is_writeback());
        assert!(!h.is_pinned());
        assert_eq!(h.flags(), page_flags::CLEAN);
        drop(h);
    }

    // ── 1f. Writeback → Dirty (failed completion) ───────────────────

    #[test]
    fn writeback_failure_retains_dirty_clears_writeback() {
        let cache = new_cache(10);
        insert_one(&cache, 7, 0);
        cache.mark_dirty(7, 0);
        cache.start_writeback(7, 0);
        assert!(cache.complete_writeback(7, 0, false));
        let h = cache.lookup(7, 0).unwrap();
        assert!(h.is_dirty(), "dirty retained after failed writeback");
        assert!(!h.is_writeback(), "writeback cleared after failure");
        assert!(!h.is_pinned(), "pin cleared after failure");
        assert_eq!(h.flags(), page_flags::DIRTY);
        drop(h);
    }

    // ── 1g. Writeback → Dirty (abort) ───────────────────────────────

    #[test]
    fn writeback_abort_returns_to_dirty() {
        let cache = new_cache(10);
        insert_one(&cache, 8, 0);
        cache.mark_dirty(8, 0);
        cache.start_writeback(8, 0);
        assert!(cache.abort_writeback(8, 0));
        let h = cache.lookup(8, 0).unwrap();
        assert!(h.is_dirty(), "dirty preserved after abort");
        assert!(!h.is_writeback(), "writeback cleared after abort");
        assert!(!h.is_pinned(), "pin cleared after abort");
        assert_eq!(h.flags(), page_flags::DIRTY);
        drop(h);
    }

    // ── 1h. Illegal / rejected transitions ──────────────────────────

    #[test]
    fn start_writeback_on_clean_page_succeeds() {
        let cache = new_cache(10);
        insert_one(&cache, 9, 0);
        assert!(cache.start_writeback(9, 0));
        let h = cache.lookup(9, 0).unwrap();
        assert!(h.is_writeback());
        assert!(h.is_pinned());
        assert!(!h.is_dirty());
        drop(h);
    }

    #[test]
    fn double_start_writeback_rejected() {
        let cache = new_cache(10);
        insert_one(&cache, 10, 0);
        cache.mark_dirty(10, 0);
        assert!(cache.start_writeback(10, 0));
        assert!(
            !cache.start_writeback(10, 0),
            "second start_writeback must fail"
        );
    }

    #[test]
    fn start_writeback_nonexistent_fails() {
        let cache = new_cache(10);
        assert!(!cache.start_writeback(99, 0));
    }

    #[test]
    fn complete_writeback_nonexistent_fails() {
        let cache = new_cache(10);
        assert!(!cache.complete_writeback(99, 0, true));
        assert!(!cache.complete_writeback(99, 0, false));
    }

    #[test]
    fn abort_writeback_nonexistent_fails() {
        let cache = new_cache(10);
        assert!(!cache.abort_writeback(99, 0));
    }

    #[test]
    fn mark_dirty_nonexistent_fails() {
        let cache = new_cache(10);
        assert!(!cache.mark_dirty(99, 0));
    }

    #[test]
    fn clear_dirty_nonexistent_fails() {
        let cache = new_cache(10);
        assert!(!cache.clear_dirty(99, 0));
    }

    // ── 1i. State queries through all transitions ────────────────────

    #[test]
    fn state_queries_through_full_lifecycle() {
        let cache = new_cache(10);
        insert_one(&cache, 20, 0);

        // Fresh
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(!h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert_eq!(h.flags(), page_flags::CLEAN);
        }

        // Mark dirty
        cache.mark_dirty(20, 0);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }

        // Start writeback
        cache.start_writeback(20, 0);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(h.is_dirty());
            assert!(h.is_writeback());
            assert!(h.is_pinned());
        }

        // Complete writeback (success) → clean
        cache.complete_writeback(20, 0, true);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(!h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert_eq!(h.flags(), page_flags::CLEAN);
        }

        // Mark dirty again
        cache.mark_dirty(20, 0);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(h.is_dirty());
        }

        // Start writeback, then abort → dirty (not writeback, not pinned)
        cache.start_writeback(20, 0);
        cache.abort_writeback(20, 0);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }

        // Start writeback, complete with failure → dirty
        cache.start_writeback(20, 0);
        cache.complete_writeback(20, 0, false);
        {
            let h = cache.lookup(20, 0).unwrap();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }
    }

    // ── 1j. Flags consistency across repeated cycles ─────────────────

    #[test]
    fn dirty_flag_does_not_get_lost_on_repeated_cycles() {
        let cache = new_cache(10);

        for cycle in 0..5 {
            insert_one(&cache, 100 + cycle, 0);
            cache.mark_dirty(100 + cycle, 0);
            assert!(cache.dirty_pages().iter().any(|k| k.inode == 100 + cycle));

            cache.start_writeback(100 + cycle, 0);
            cache.complete_writeback(100 + cycle, 0, true);

            let h = cache.lookup(100 + cycle, 0).unwrap();
            assert!(!h.is_dirty(), "cycle {cycle}: page should be clean");
            drop(h);
        }
    }
}

// ====================================================================
// Group 2: Dirty tracking — membership, ordering, eviction rejection
// ====================================================================

mod dirty_tracking {
    use super::*;

    // ── 2a. Dirty set membership ─────────────────────────────────────

    #[test]
    fn dirty_pages_empty_on_clean_cache() {
        let cache = new_cache(10);
        for i in 0..5 {
            insert_one(&cache, i, 0);
        }
        assert!(cache.dirty_pages().is_empty());
    }

    #[test]
    fn dirty_pages_excludes_cleaned_pages() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);

        let dirty = cache.dirty_pages();
        assert_eq!(dirty.len(), 2);

        // Clean page 1, verify it drops from dirty set
        cache.clear_dirty(1, 0);
        let dirty_after = cache.dirty_pages();
        assert_eq!(dirty_after.len(), 1);
        assert_eq!(dirty_after[0].inode, 2);
    }

    #[test]
    fn dirty_pages_after_successful_writeback() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.mark_dirty(1, 0);
        assert_eq!(cache.dirty_pages().len(), 1);

        cache.start_writeback(1, 0);
        // Dirty page still in dirty set during writeback
        assert_eq!(cache.dirty_pages().len(), 1);

        cache.complete_writeback(1, 0, true);
        // Dirty page removed after successful writeback
        assert!(cache.dirty_pages().is_empty());
    }

    #[test]
    fn dirty_pages_after_failed_writeback() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.mark_dirty(1, 0);
        cache.start_writeback(1, 0);
        cache.complete_writeback(1, 0, false);
        // Failed writeback: dirty page stays in dirty set
        assert_eq!(cache.dirty_pages().len(), 1);
    }

    #[test]
    fn dirty_pages_after_writeback_abort() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.mark_dirty(1, 0);
        cache.start_writeback(1, 0);
        cache.abort_writeback(1, 0);
        // Abort: dirty page stays in dirty set
        assert_eq!(cache.dirty_pages().len(), 1);
    }

    // ── 2b. Eviction rejection for dirty pages ───────────────────────

    #[test]
    fn evict_one_rejects_all_dirty_cache() {
        let cache = new_cache(3);
        for i in 0..3 {
            insert_one(&cache, i, 0);
            cache.mark_dirty(i, 0);
        }
        assert!(cache.evict_one().is_none(), "no clean pages to evict");
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn evict_one_skips_dirty_evicts_clean() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);

        cache.mark_dirty(1, 0);
        // 1 is dirty; eviction must skip it and evict the oldest clean page
        let evicted = cache.evict_one().expect("should evict clean page");
        assert_ne!(evicted.key.inode, 1, "dirty page must not be evicted");
        drop(evicted);
        assert!(cache.lookup(1, 0).is_some(), "dirty page 1 should remain");
        assert_eq!(cache.len(), 2);
    }

    // ── 2c. Insert at capacity with dirty pages ──────────────────────

    #[test]
    fn insert_at_capacity_when_all_clean_evicts_one() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        cache.insert(3, 0).expect("should evict one clean");
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.eviction_count(), 1);
    }

    #[test]
    fn insert_at_capacity_when_all_dirty_fails() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);

        let err = cache.insert(3, 0).unwrap_err();
        assert_eq!(err, InsertError::AtCapacityNoCleanPages);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn insert_at_capacity_mixed_dirty_evicts_clean() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0); // will be dirtied
        insert_one(&cache, 2, 0); // clean

        cache.mark_dirty(1, 0);
        // 2 is the only clean page — it should be evicted
        cache.insert(3, 0).expect("should evict clean page 2");
        assert!(cache.lookup(1, 0).is_some(), "dirty page 1 remains");
        assert!(cache.lookup(2, 0).is_none(), "clean page 2 evicted");
        assert!(cache.lookup(3, 0).is_some(), "new page 3 inserted");
        assert_eq!(cache.len(), 2);
    }

    // ── 2d. Dirty tracking with multiple inodes ──────────────────────

    #[test]
    fn dirty_pages_for_inode_filters_correctly() {
        let cache = new_cache(20);

        // Inode 10: pages at offsets 0, 4096, 8192
        insert_one(&cache, 10, 0);
        insert_one(&cache, 10, 4096);
        insert_one(&cache, 10, 8192);
        // Inode 20: pages at offsets 0, 4096
        insert_one(&cache, 20, 0);
        insert_one(&cache, 20, 4096);
        // Inode 30: page at offset 0
        insert_one(&cache, 30, 0);

        // Dirty subset: inode 10 offset 0, inode 10 offset 8192, inode 20 offset 0
        cache.mark_dirty(10, 0);
        cache.mark_dirty(10, 8192);
        cache.mark_dirty(20, 0);

        let d10 = cache.dirty_pages_for_inode(10);
        assert_eq!(d10.len(), 2);
        let offsets: Vec<u64> = d10.iter().map(|k| k.offset).collect();
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&8192));
        assert!(!offsets.contains(&4096));

        let d20 = cache.dirty_pages_for_inode(20);
        assert_eq!(d20.len(), 1);
        assert_eq!(d20[0].offset, 0);

        let d30 = cache.dirty_pages_for_inode(30);
        assert!(d30.is_empty());
    }

    #[test]
    fn clear_dirty_for_inode_preserves_other_inodes() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);

        let cleared = cache.clear_dirty_for_inode(1);
        assert_eq!(cleared, 1);

        assert!(cache.dirty_pages_for_inode(1).is_empty());
        assert_eq!(cache.dirty_pages_for_inode(2).len(), 1);
    }

    #[test]
    fn clear_dirty_for_inode_multiple_pages() {
        let cache = new_cache(10);
        insert_one(&cache, 5, 0);
        insert_one(&cache, 5, 4096);
        insert_one(&cache, 5, 8192);
        insert_one(&cache, 5, 12288);
        cache.mark_dirty(5, 0);
        cache.mark_dirty(5, 4096);
        cache.mark_dirty(5, 8192);
        // 12288 stays clean

        let cleared = cache.clear_dirty_for_inode(5);
        assert_eq!(cleared, 3);
        assert!(cache.dirty_pages_for_inode(5).is_empty());
        assert!(cache.dirty_pages().is_empty());
    }
}

// ====================================================================
// Group 3: LRU ordering — strictness, promotion, pinned-pages
// ====================================================================

mod lru_ordering {
    use super::*;

    // ── 3a. Basic LRU invariant ──────────────────────────────────────

    #[test]
    fn oldest_page_evicted_first() {
        let cache = new_cache(4);
        for i in 1..=4 {
            insert_one(&cache, i, 0);
        }
        // LRU order: 1(oldest) → 2 → 3 → 4(MRU)
        cache.insert(5, 0).expect("should evict oldest");
        assert!(cache.lookup(1, 0).is_none(), "oldest (1) should be evicted");
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(4, 0).is_some());
        assert!(cache.lookup(5, 0).is_some());
    }

    #[test]
    fn multiple_evictions_follow_lru_order() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0); // oldest
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0); // MRU

        // Insert 4: evicts 1
        cache.insert(4, 0).unwrap();
        assert!(cache.lookup(1, 0).is_none());
        // LRU now: 2(oldest), 3, 4(MRU)

        // Insert 5: evicts 2
        cache.insert(5, 0).unwrap();
        assert!(cache.lookup(2, 0).is_none());
        // LRU now: 3(oldest), 4, 5(MRU)

        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(4, 0).is_some());
        assert!(cache.lookup(5, 0).is_some());
    }

    // ── 3b. Touch promotion ──────────────────────────────────────────

    #[test]
    fn lookup_promotes_to_mru() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0); // oldest
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0); // MRU

        // Touch 1 → moves to MRU: order becomes 2(oldest) → 3 → 1(MRU)
        {
            let _h = cache.lookup(1, 0).unwrap();
        }

        cache.insert(4, 0).unwrap();
        assert!(
            cache.lookup(2, 0).is_none(),
            "2 should be oldest and evicted"
        );
        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(1, 0).is_some(), "1 was promoted");
        assert!(cache.lookup(4, 0).is_some());
    }

    #[test]
    fn multiple_lookups_promote_correctly() {
        let cache = new_cache(4);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);
        insert_one(&cache, 4, 0);
        // Order: 1→2→3→4

        // Touch 1 (promote): 2→3→4→1
        {
            let _h = cache.lookup(1, 0).unwrap();
        }
        // Touch 2 (promote): 3→4→1→2
        {
            let _h = cache.lookup(2, 0).unwrap();
        }

        // Insert 5: evicts 3 (oldest)
        cache.insert(5, 0).unwrap();
        assert!(cache.lookup(3, 0).is_none());
        assert!(cache.lookup(4, 0).is_some());
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(5, 0).is_some());
    }

    // ── 3c. Pinned pages skip eviction scan ──────────────────────────

    #[test]
    fn pinned_page_skipped_during_eviction_scan() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);

        // Pin page 1 (oldest) via start_writeback
        cache.start_writeback(1, 0);

        // Insert 4: should skip pinned 1, evict 2 (oldest clean unpinned)
        cache.insert(4, 0).unwrap();
        assert!(cache.lookup(1, 0).is_some(), "pinned page 1 should remain");
        assert!(
            cache.lookup(2, 0).is_none(),
            "clean page 2 should be evicted"
        );
        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(4, 0).is_some());
    }

    #[test]
    fn all_pinned_no_eviction_possible() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);

        // Pin both
        cache.start_writeback(1, 0);
        cache.start_writeback(2, 0);

        // Both pages are pinned — insert should fail
        let err = cache.insert(3, 0).unwrap_err();
        assert_eq!(err, InsertError::AtCapacityNoCleanPages);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn unpin_after_writeback_makes_page_evictable() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);

        // Pin 1 via writeback, then complete it
        cache.start_writeback(1, 0);
        cache.complete_writeback(1, 0, true);

        // Now 1 is unpinned and clean. Insert 3 should evict the LRU.
        cache.insert(3, 0).unwrap();
        assert_eq!(cache.len(), 2);
    }

    // ── 3d. Interleaved insert / access / evict ──────────────────────

    #[test]
    fn interleaved_insert_access_evict_maintains_lru() {
        let cache = new_cache(3);

        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);

        // Access 1: promotes to MRU
        {
            let _h = cache.lookup(1, 0).unwrap();
        }

        // Evict one clean page
        let evicted = cache.evict_one().expect("should evict one");
        assert_ne!(
            evicted.key.inode, 1,
            "recently accessed page should not be evicted"
        );
        drop(evicted);
        assert_eq!(cache.len(), 2);

        // Fill back to capacity
        cache.insert(4, 0).unwrap();
        assert_eq!(cache.len(), 3);

        // Access 4, then insert 5 triggers eviction
        {
            let _h = cache.lookup(4, 0).unwrap();
        }
        cache.insert(5, 0).unwrap();
        // After eviction, exactly 3 pages remain
        assert_eq!(cache.len(), 3);
        // The recently accessed page (4) survives
        assert!(cache.lookup(4, 0).is_some());
        // The newly inserted page is present
        assert!(cache.lookup(5, 0).is_some());
    }

    // ── 3e. Remove restores LRU continuity ───────────────────────────

    #[test]
    fn remove_updates_lru_order() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);

        // Remove middle page (2)
        let removed = cache.remove(2, 0).unwrap();
        assert_eq!(removed.key.inode, 2);
        assert_eq!(cache.len(), 2);

        // Re-insert at same key
        insert_one(&cache, 2, 0);
        assert_eq!(cache.len(), 3);
        // Page 2 is back and accessible
        assert!(cache.lookup(2, 0).is_some());
    }
}

// ====================================================================
// Group 4: Pin lifecycle via writeback
// ====================================================================

mod pin_lifecycle {
    use super::*;

    // ── 4a. Pin on writeback start ───────────────────────────────────

    #[test]
    fn start_writeback_pins_page() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        assert!(cache.start_writeback(1, 0));
        let h = cache.lookup(1, 0).unwrap();
        assert!(h.is_pinned());
        drop(h);
    }

    #[test]
    fn start_writeback_on_nonexistent_returns_false() {
        let cache = new_cache(10);
        assert!(!cache.start_writeback(99, 0));
    }

    // ── 4b. Pinned pages resist eviction ─────────────────────────────

    #[test]
    fn pinned_page_not_evicted_by_insert() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);

        // Pin 1 via writeback
        cache.start_writeback(1, 0);

        // Insert 3: must evict 2 (clean, not pinned), not 1
        cache.insert(3, 0).unwrap();
        assert!(cache.lookup(1, 0).is_some(), "pinned 1 must remain");
        assert!(cache.lookup(2, 0).is_none());
        assert!(cache.lookup(3, 0).is_some());
    }

    #[test]
    fn pinned_page_not_evicted_by_evict_one() {
        let cache = new_cache(3);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);
        insert_one(&cache, 3, 0);

        // Pin 1 (oldest)
        cache.start_writeback(1, 0);

        // evict_one should skip 1 and evict 2
        let evicted = cache.evict_one().unwrap();
        assert_ne!(evicted.key.inode, 1, "pinned page must not be evicted");
        assert!(cache.lookup(1, 0).is_some());
    }

    // ── 4c. Unpin on writeback completion ────────────────────────────

    #[test]
    fn complete_writeback_unpins() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.start_writeback(1, 0);
        assert!(cache.complete_writeback(1, 0, true));
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_pinned(), "page unpinned after complete_writeback");
        drop(h);
    }

    #[test]
    fn abort_writeback_unpins() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.start_writeback(1, 0);
        assert!(cache.abort_writeback(1, 0));
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_pinned(), "page unpinned after abort_writeback");
        drop(h);
    }

    #[test]
    fn complete_writeback_unpins_even_on_failure() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.start_writeback(1, 0);
        cache.complete_writeback(1, 0, false);
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_pinned(), "page unpinned even on failed writeback");
        drop(h);
    }

    // ── 4d. Pinned + dirty page eviction behavior ────────────────────

    #[test]
    fn pinned_dirty_page_skipped_during_capacity_eviction() {
        let cache = new_cache(2);
        insert_one(&cache, 1, 0);
        insert_one(&cache, 2, 0);

        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);
        // Both dirty — no automatic eviction possible
        let err = cache.insert(3, 0).unwrap_err();
        assert_eq!(err, InsertError::AtCapacityNoCleanPages);

        // Now pin 1, complete writeback (making it clean)
        cache.start_writeback(1, 0);
        cache.complete_writeback(1, 0, true);

        // 1 is now clean, 2 is dirty. Insert 3 should evict 1.
        cache.insert(3, 0).unwrap();
        assert!(cache.lookup(1, 0).is_none(), "clean page 1 evicted");
        assert!(cache.lookup(2, 0).is_some(), "dirty page 2 retained");
    }

    // ── 4e. Writeback start on already-pinned page ───────────────────

    #[test]
    fn double_start_writeback_fails() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        assert!(cache.start_writeback(1, 0));
        assert!(!cache.start_writeback(1, 0));
    }

    #[test]
    fn complete_then_start_writeback_again() {
        let cache = new_cache(10);
        insert_one(&cache, 1, 0);
        cache.mark_dirty(1, 0);

        // First writeback cycle
        assert!(cache.start_writeback(1, 0));
        assert!(cache.complete_writeback(1, 0, true));

        // Second writeback cycle (after re-dirtying)
        cache.mark_dirty(1, 0);
        assert!(cache.start_writeback(1, 0));
        assert!(cache.complete_writeback(1, 0, true));
    }
}

// ====================================================================
// Group 5: Edge cases
// ====================================================================

mod edge_cases {
    use super::*;

    // ── 5a. Zero-capacity cache ──────────────────────────────────────

    #[test]
    fn zero_capacity_rejects_all_inserts() {
        let cache = PageCache::new(0, PAGE_SIZE);
        let err = cache.insert(1, 0).unwrap_err();
        assert_eq!(err, InsertError::AtCapacityNoCleanPages);
    }

    #[test]
    fn zero_capacity_has_correct_stats() {
        let cache = PageCache::new(0, PAGE_SIZE);
        assert_eq!(cache.capacity(), 0);
        assert_eq!(cache.page_size(), PAGE_SIZE);
        assert!(cache.is_empty());
        assert!(cache.is_full());
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.evict_one().is_none());
        assert!(cache.dirty_pages().is_empty());
        assert_eq!(cache.hit_count(), 0);
        assert_eq!(cache.miss_count(), 1);
    }

    // ── 5b. Single-page cache ────────────────────────────────────────

    #[test]
    fn single_page_cache_fill_and_evict() {
        let cache = new_cache(1);
        insert_one(&cache, 1, 0);
        assert!(cache.is_full());
        assert_eq!(cache.len(), 1);

        // This should evict the only page
        cache.insert(2, 0).unwrap();
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(2, 0).is_some());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.eviction_count(), 1);
    }

    #[test]
    fn single_page_dirty_blocks_insert() {
        let cache = new_cache(1);
        insert_one(&cache, 1, 0);
        cache.mark_dirty(1, 0);

        let err = cache.insert(2, 0).unwrap_err();
        assert_eq!(err, InsertError::AtCapacityNoCleanPages);
        assert_eq!(cache.len(), 1);
    }

    // ── 5c. Duplicate insert ─────────────────────────────────────────

    #[test]
    fn duplicate_insert_rejected() {
        let cache = new_cache(10);
        insert_one(&cache, 42, 4096);

        let err = cache.insert(42, 4096).unwrap_err();
        assert_eq!(err, InsertError::AlreadyExists);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn duplicate_insert_after_remove_succeeds() {
        let cache = new_cache(10);
        insert_one(&cache, 99, 0);
        cache.remove(99, 0).unwrap();
        // Re-insert at same key should succeed
        cache.insert(99, 0).unwrap();
        assert_eq!(cache.len(), 1);
    }

    // ── 5d. Boundary values ──────────────────────────────────────────

    #[test]
    fn inode_zero_is_valid() {
        let cache = new_cache(10);
        insert_one(&cache, 0, 0);
        let h = cache.lookup(0, 0).unwrap();
        assert_eq!(h.key().inode, 0);
        assert_eq!(h.key().offset, 0);
        drop(h);
    }

    #[test]
    fn maximum_u64_offset() {
        let cache = new_cache(10);
        let max_off = u64::MAX - (u64::MAX % PAGE_SIZE as u64); // page-aligned
        insert_one(&cache, 1, max_off);
        let h = cache.lookup(1, max_off).unwrap();
        assert_eq!(h.key().offset, max_off);
        drop(h);
    }

    #[test]
    fn large_inode_values() {
        let cache = new_cache(10);
        insert_one(&cache, u64::MAX, 0);
        insert_one(&cache, u64::MAX - 1, PAGE_SIZE as u64);
        let h = cache.lookup(u64::MAX, 0).unwrap();
        assert_eq!(h.key().inode, u64::MAX);
        drop(h);
    }

    // ── 5e. Non-page-aligned offsets ─────────────────────────────────

    #[test]
    fn non_page_aligned_offset_accepted_as_key() {
        // The PageCache does NOT enforce page alignment; the caller is
        // responsible.  Verify that unaligned offsets are stored as-is.
        let cache = new_cache(10);
        insert_one(&cache, 1, 512);
        let h = cache.lookup(1, 512).unwrap();
        assert_eq!(h.key().offset, 512);
        assert_eq!(h.data().len(), PAGE_SIZE);
        drop(h);
    }

    // ── 5f. Large capacity ───────────────────────────────────────────

    #[test]
    fn large_capacity_cache() {
        let cache = PageCache::new(10_000, PAGE_SIZE);
        assert_eq!(cache.capacity(), 10_000);
        assert!(cache.is_empty());

        // Insert a few and verify
        for i in 0..100 {
            insert_one(&cache, i, 0);
        }
        assert_eq!(cache.len(), 100);
        assert!(!cache.is_full());
        assert_eq!(cache.eviction_count(), 0);
    }

    // ── 5g. Repeated remove and reinsert ─────────────────────────────

    #[test]
    fn repeated_remove_and_reinsert_same_key() {
        let cache = new_cache(10);

        for cycle in 0..10 {
            cache.insert(cycle, 0).unwrap();
            {
                let mut h = cache.lookup(cycle, 0).unwrap();
                h.mark_dirty();
            }
            cache.remove(cycle, 0).unwrap();
        }
        assert!(cache.is_empty());
    }

    // ── 5h. Stats consistency ────────────────────────────────────────

    #[test]
    fn stats_consistent_after_mixed_operations() {
        let cache = new_cache(5);

        for i in 1..=5 {
            cache.insert(i, 0).unwrap();
        }
        // 5 inserts, 0 hits, 0 misses, 0 evictions
        assert_eq!(cache.insert_count(), 5);
        assert_eq!(cache.hit_count(), 0);
        assert_eq!(cache.miss_count(), 0);
        assert_eq!(cache.eviction_count(), 0);

        // Lookup hit
        {
            let _h = cache.lookup(3, 0).unwrap();
        }
        assert_eq!(cache.hit_count(), 1);

        // Lookup miss
        cache.lookup(99, 0);
        assert_eq!(cache.miss_count(), 1);

        // Evict via insert
        cache.insert(6, 0).unwrap();
        assert_eq!(cache.insert_count(), 6);
        assert_eq!(cache.eviction_count(), 1);
    }

    // ── 5i. Full cache lookup of all pages ───────────────────────────

    #[test]
    fn all_pages_lookupable_after_fill() {
        let cache = new_cache(50);
        for i in 1..=50 {
            insert_one(&cache, i, 0);
        }
        assert!(cache.is_full());

        for i in 1..=50 {
            let h = cache.lookup(i, 0).expect("page {i} should be present");
            assert_eq!(h.key().inode, i);
            drop(h);
        }
        assert_eq!(cache.hit_count(), 50);
    }
}
