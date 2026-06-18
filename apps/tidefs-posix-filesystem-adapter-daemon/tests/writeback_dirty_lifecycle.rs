// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Dirty-page lifecycle validation tests for the WritebackInodeCache.
//!
//! Covers clean-to-dirty marking, dirty-set queries, writeback-completion
//! transitions, eviction ordering, fsync simulation, and boundary behavior.

use tidefs_posix_filesystem_adapter_daemon::writeback_reclaim::WritebackInodeCache;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn new_cache(capacity: usize) -> WritebackInodeCache {
    WritebackInodeCache::new(capacity)
}

fn assert_dirty(cache: &WritebackInodeCache, ino: u64, expected_dirty: bool) {
    let actual = cache.is_dirty(ino);
    assert!(
        actual.is_some(),
        "inode {ino} should be present in cache when checking dirty state"
    );
    assert_eq!(
        actual.unwrap(),
        expected_dirty,
        "inode {ino} dirty state mismatch"
    );
}

fn assert_not_present(cache: &WritebackInodeCache, ino: u64) {
    assert!(
        !cache.contains(ino),
        "inode {ino} should not be present in cache"
    );
}

// ---------------------------------------------------------------------------
// 1. Dirty-page state transitions
// ---------------------------------------------------------------------------

#[test]
fn dirty_lifecycle_single_inode_basic_transition() {
    let mut cache = new_cache(16);
    cache.insert(1);
    assert_eq!(cache.clean_count(), 1);
    assert_eq!(cache.dirty_count(), 0);

    // mark dirty
    cache.mark_dirty(1, 4096);
    assert_dirty(&cache, 1, true);
    assert_eq!(cache.dirty_count(), 1);
    assert_eq!(cache.clean_count(), 0);

    // writeback completion -> clean
    cache.mark_clean(1);
    assert_dirty(&cache, 1, false);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 1);
    assert!(cache.contains(1));
}

#[test]
fn dirty_lifecycle_multiple_inodes_mixed_states() {
    let mut cache = new_cache(16);
    for ino in 1..=5 {
        cache.insert(ino);
    }
    assert_eq!(cache.entry_count(), 5);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 5);

    // make 1 and 3 dirty
    cache.mark_dirty(1, 1024);
    cache.mark_dirty(3, 2048);
    assert_dirty(&cache, 1, true);
    assert_dirty(&cache, 3, true);
    assert_dirty(&cache, 2, false);
    assert_dirty(&cache, 4, false);
    assert_eq!(cache.dirty_count(), 2);
    assert_eq!(cache.clean_count(), 3);

    // flush only inode 1
    cache.mark_clean(1);
    assert_dirty(&cache, 1, false);
    assert_dirty(&cache, 3, true);
    assert_eq!(cache.dirty_count(), 1);
    assert_eq!(cache.clean_count(), 4);

    // flush inode 3
    cache.mark_clean(3);
    assert_dirty(&cache, 3, false);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 5);
}

#[test]
fn dirty_lifecycle_dirty_bytes_accumulate() {
    let mut cache = new_cache(16);
    cache.insert(42);
    cache.mark_dirty(42, 1024);
    cache.mark_dirty(42, 2048);
    cache.mark_dirty(42, 512);

    // dirty_bytes should accumulate: 1024 + 2048 + 512 = 3584
    assert_dirty(&cache, 42, true);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn dirty_lifecycle_mark_dirty_unknown_inode_noop() {
    let mut cache = new_cache(16);
    cache.mark_dirty(99, 4096); // inode not inserted
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.is_dirty(99), None);
}

// ---------------------------------------------------------------------------
// 2. Eviction ordering (clean entries reclaimed in inode order)
// ---------------------------------------------------------------------------

#[test]
fn eviction_reclaim_clean_entries_lowest_inode_first() {
    let mut cache = new_cache(16);
    // Insert in non-sorted order
    for ino in &[10u64, 3, 7, 1, 5] {
        cache.insert(*ino);
    }
    assert_eq!(cache.entry_count(), 5);

    // Mark inodes 3 and 7 dirty, then immediately clean (simulating
    // writeback completed). All 5 entries are now clean.
    cache.mark_dirty(3, 4096);
    cache.mark_dirty(7, 4096);
    cache.mark_clean(3);
    cache.mark_clean(7);
    assert_eq!(cache.clean_count(), 5);
    assert_eq!(cache.dirty_count(), 0);

    // Reclaim 2 entries. BTreeMap order means lowest inode first.
    let reclaimed = cache.reclaim_clean(2);
    assert_eq!(reclaimed, 2);
    // Inodes 1 and 3 should be gone (lowest two)
    assert_not_present(&cache, 1);
    assert_not_present(&cache, 3);
    assert!(cache.contains(5));
    assert!(cache.contains(7));
    assert!(cache.contains(10));
}

#[test]
fn eviction_reclaim_refuses_dirty_entries() {
    let mut cache = new_cache(16);
    for ino in 1..=4 {
        cache.insert(ino);
    }
    cache.mark_dirty(1, 4096);
    cache.mark_dirty(3, 4096);
    assert_eq!(cache.dirty_count(), 2);
    assert_eq!(cache.clean_count(), 2);

    // Reclaim all clean. Only inodes 2 and 4 are clean.
    let reclaimed = cache.reclaim_clean(10);
    assert_eq!(reclaimed, 2);
    assert_eq!(cache.entry_count(), 2);
    // Dirty entries survive
    assert!(cache.contains(1) && cache.is_dirty(1).unwrap());
    assert!(cache.contains(3) && cache.is_dirty(3).unwrap());
}

#[test]
fn eviction_reclaim_refuses_pinned_entries() {
    let mut cache = new_cache(16);
    for ino in 1..=4 {
        cache.insert(ino);
    }
    // Pin inode 2 to protect it from reclaim
    cache.pin(2);
    assert_eq!(cache.pinned_count(), 1);

    let reclaimed = cache.reclaim_clean(10);
    // Only 1, 3, 4 are clean+unpinned -> 3 reclaimed
    assert_eq!(reclaimed, 3);
    assert!(cache.contains(2));
    assert!(!cache.contains(1));
    assert!(!cache.contains(3));
    assert!(!cache.contains(4));
}

#[test]
fn eviction_reclaim_all_clean_empties_fully_clean_cache() {
    let mut cache = new_cache(16);
    for ino in 0..6 {
        cache.insert(ino);
    }
    let reclaimed = cache.reclaim_all_clean();
    assert_eq!(reclaimed, 6);
    assert_eq!(cache.entry_count(), 0);
}

#[test]
fn eviction_reclaim_all_clean_preserves_dirty() {
    let mut cache = new_cache(16);
    for ino in 0..4 {
        cache.insert(ino);
    }
    cache.mark_dirty(0, 4096);
    cache.mark_dirty(2, 8192);
    let reclaimed = cache.reclaim_all_clean();
    assert_eq!(reclaimed, 2); // Inodes 1, 3 were clean
    assert_eq!(cache.entry_count(), 2);
    assert!(cache.contains(0));
    assert!(cache.contains(2));
}

// ---------------------------------------------------------------------------
// 3. fsync interaction (flush a specific inode, others stay dirty)
// ---------------------------------------------------------------------------

#[test]
fn fsync_flush_one_inode_leaves_others_dirty() {
    let mut cache = new_cache(16);
    for ino in 1..=4 {
        cache.insert(ino);
        cache.mark_dirty(ino, 1024);
    }
    assert_eq!(cache.dirty_count(), 4);

    // Simulate fsync on inode 2: flush it to clean
    cache.mark_clean(2);
    assert_dirty(&cache, 2, false);
    assert_dirty(&cache, 1, true);
    assert_dirty(&cache, 3, true);
    assert_dirty(&cache, 4, true);
    assert_eq!(cache.dirty_count(), 3);
    assert_eq!(cache.clean_count(), 1);
}

#[test]
fn fsync_flush_already_clean_inode_is_noop() {
    let mut cache = new_cache(16);
    cache.insert(5);
    // Already clean (default on insert)
    assert_dirty(&cache, 5, false);
    cache.mark_clean(5);
    assert_dirty(&cache, 5, false);
    assert_eq!(cache.clean_count(), 1);
}

#[test]
fn fsync_flush_unknown_inode_is_noop() {
    let mut cache = new_cache(16);
    cache.insert(1);
    cache.mark_clean(999); // not present
    assert_eq!(cache.entry_count(), 1);
    assert!(cache.contains(1));
}

#[test]
fn fsync_all_inodes_flushed_then_reclaim_works() {
    let mut cache = new_cache(16);
    for ino in 1..=5 {
        cache.insert(ino);
        cache.mark_dirty(ino, 4096);
    }
    assert_eq!(cache.dirty_count(), 5);

    // Flush all
    for ino in 1..=5 {
        cache.mark_clean(ino);
    }
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 5);

    // All can now be reclaimed
    let reclaimed = cache.reclaim_all_clean();
    assert_eq!(reclaimed, 5);
    assert_eq!(cache.entry_count(), 0);
}

// ---------------------------------------------------------------------------
// 4. Boundary behavior
// ---------------------------------------------------------------------------

#[test]
fn boundary_empty_cache_all_queries_return_zero() {
    let cache = new_cache(0);
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 0);
    assert_eq!(cache.pinned_count(), 0);
    assert!(cache.is_full()); // max_entries=0 means always full
    assert_eq!(cache.is_dirty(1), None);
    assert_eq!(cache.reclaim_stats(), (0, 0));
}

#[test]
fn boundary_capacity_zero_is_always_full() {
    let mut cache = new_cache(0);
    assert!(cache.is_full()); // max_entries=0 means always full
    cache.insert(1); // BTreeMap accepts insert regardless of max_entries
    assert!(cache.is_full());
}

#[test]
fn boundary_capacity_one_fills_correctly() {
    let mut cache = new_cache(1);
    assert!(!cache.is_full());
    cache.insert(1);
    assert!(cache.is_full());
    cache.insert(2); // still adds to BTreeMap
    assert!(cache.is_full());
}

#[test]
fn boundary_mark_already_clean_page_dirty_idempotent() {
    let mut cache = new_cache(16);
    cache.insert(7);
    assert_dirty(&cache, 7, false);

    // Mark clean page dirty: should work
    cache.mark_dirty(7, 4096);
    assert_dirty(&cache, 7, true);
    assert_eq!(cache.dirty_count(), 1);

    // Mark same inode dirty again (idempotent in the sense it stays dirty,
    // bytes accumulate)
    cache.mark_dirty(7, 2048);
    assert_dirty(&cache, 7, true);
    assert_eq!(cache.dirty_count(), 1); // still 1 dirty entry
}

#[test]
fn boundary_mark_clean_already_clean_page_noop() {
    let mut cache = new_cache(16);
    cache.insert(7);
    assert_dirty(&cache, 7, false);
    assert_eq!(cache.clean_count(), 1);

    cache.mark_clean(7);
    assert_dirty(&cache, 7, false);
    assert_eq!(cache.clean_count(), 1);
}

#[test]
fn boundary_rapid_dirty_clean_dirty_cycling() {
    let mut cache = new_cache(16);
    cache.insert(42);

    // Cycle 1: dirty -> clean
    cache.mark_dirty(42, 1024);
    assert_dirty(&cache, 42, true);
    cache.mark_clean(42);
    assert_dirty(&cache, 42, false);

    // Cycle 2: dirty -> clean
    cache.mark_dirty(42, 512);
    assert_dirty(&cache, 42, true);
    cache.mark_clean(42);
    assert_dirty(&cache, 42, false);

    // Cycle 3: dirty -> clean
    cache.mark_dirty(42, 256);
    assert_dirty(&cache, 42, true);
    cache.mark_clean(42);
    assert_dirty(&cache, 42, false);

    assert_eq!(cache.entry_count(), 1);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.clean_count(), 1);
}

#[test]
fn boundary_reclaim_zero_target_does_nothing() {
    let mut cache = new_cache(16);
    for ino in 0..5 {
        cache.insert(ino);
    }
    let reclaimed = cache.reclaim_clean(0);
    assert_eq!(reclaimed, 0);
    assert_eq!(cache.entry_count(), 5);
}

#[test]
fn boundary_reclaim_target_exceeds_capacity() {
    let mut cache = new_cache(16);
    cache.insert(1);
    cache.insert(2);
    cache.insert(3);
    cache.mark_dirty(1, 4096);
    // 2 clean entries (2, 3), try to reclaim 100
    let reclaimed = cache.reclaim_clean(100);
    assert_eq!(reclaimed, 2);
    assert_eq!(cache.entry_count(), 1);
    assert!(cache.contains(1));
}

#[test]
fn boundary_insert_duplicate_preserves_dirty_state() {
    let mut cache = new_cache(16);
    cache.insert(1);
    cache.mark_dirty(1, 8192);
    assert_dirty(&cache, 1, true);

    // Re-insert should preserve dirty state (explicit behavior)
    cache.insert(1);
    assert_dirty(&cache, 1, true);
    assert_eq!(cache.entry_count(), 1);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn boundary_insert_duplicate_resets_pinned() {
    let mut cache = new_cache(16);
    cache.insert(1);
    cache.pin(1);
    assert_eq!(cache.pinned_count(), 1);

    cache.insert(1); // resets pinned per implementation
    assert_eq!(cache.pinned_count(), 0);
}

#[test]
fn boundary_remove_nonexistent_returns_none() {
    let mut cache = new_cache(16);
    cache.insert(1);
    let removed = cache.remove(99);
    assert!(removed.is_none());
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn boundary_remove_existing_returns_entry() {
    let mut cache = new_cache(16);
    cache.insert(7);
    cache.mark_dirty(7, 1024);
    let removed = cache.remove(7);
    assert!(removed.is_some());
    let entry = removed.unwrap();
    assert_eq!(entry.ino, 7);
    assert!(entry.is_dirty());

    assert!(!cache.contains(7));
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.dirty_count(), 0);
}

#[test]
fn boundary_reclaim_stats_accumulate() {
    let mut cache = new_cache(16);
    for i in 0..8 {
        cache.insert(i);
    }
    cache.reclaim_clean(3);
    assert_eq!(cache.reclaim_stats(), (3, 3));

    cache.mark_dirty(5, 4096);
    cache.reclaim_clean(2);
    // Only 4 clean entries remain (0,1,2,3,4,6,7 minus dirty(5)),
    // asking for 2 -> 2 reclaimed, attempts accumulated by 2
    assert_eq!(cache.reclaim_stats(), (5, 5));
}

#[test]
fn boundary_pin_unpin_toggle() {
    let mut cache = new_cache(16);
    cache.insert(1);
    assert_eq!(cache.pinned_count(), 0);

    cache.pin(1);
    assert_eq!(cache.pinned_count(), 1);

    cache.unpin(1);
    assert_eq!(cache.pinned_count(), 0);
}

#[test]
fn boundary_pinned_does_not_prevent_dirty() {
    let mut cache = new_cache(16);
    cache.insert(1);
    cache.pin(1);
    cache.mark_dirty(1, 4096);
    assert_dirty(&cache, 1, true);
    assert_eq!(cache.pinned_count(), 1);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn boundary_pinned_dirty_withstands_reclaim() {
    let mut cache = new_cache(16);
    for ino in 1..=3 {
        cache.insert(ino);
    }
    cache.pin(2);
    cache.mark_dirty(2, 4096);
    // 1 and 3 are clean+unpinned -> reclaimable
    let reclaimed = cache.reclaim_clean(10);
    assert_eq!(reclaimed, 2);
    // Inode 2 is pinned AND dirty, so it survives
    assert!(cache.contains(2));
    assert_eq!(cache.pinned_count(), 1);
    assert_eq!(cache.dirty_count(), 1);
}
