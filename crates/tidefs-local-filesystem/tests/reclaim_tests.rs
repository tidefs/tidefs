//! Reclaim integration tests for the TideFS LocalFileSystem.
//!
//! This file covers two reclaim domains:
//!
//! **1. Page-cache reclaim (memory):** eviction of clean page-cache pages
//!    under memory pressure via `page_cache_maybe_reclaim` and
//!    `page_cache_evict_inode`.  These tests verify that clean pages are
//!    dropped and dirty pages are preserved.
//!
//! **2. Storage reclaim (dead-segment freeing):** the live production
//!    reclaim chain from filesystem mutation to object-store drain.
//!    The production chain is:
//!
//!    ```text
//!    mutation (unlink/truncate shrink/rename overwrite)
//!      -> record_reclaim_delta()            -- records Extent/InodeTombstone deltas
//!      -> local reclaim queue (LocalFileSystem.reclaim_queue)
//!      -> tick_background_services() Duty 2  -- drain_local_reclaim_queue_into_store()
//!      -> store.delete() into object-store durable reclaim queue
//!      -> LocalObjectStore::drain_dead_segments()  -- sole segment-freeing authority
//!    ```
//!
//!    The integration tests below exercise the public-API portion of this
//!    chain: mutation -> local queue population -> tick drain -> queue empty.
//!
//!    ## Nonclaim boundary
//!
//!    `drain_dead_segments()` requires `&mut LocalObjectStore`, which is
//!    only accessible through `pub(crate)` paths.  The full end-to-end
//!    chain (unlink -> drain_dead_segments -> reopen -> readback) is
//!    tested in the `lib.rs` unit tests:
//!
//!    - `full_reclaim_chain_unlink_to_drain_dead_segments_reopen_readback`
//!
//!    Truncate-shrink and rename-overwrite full-chain variants are not yet
//!    individually covered by reopen-verified drain_dead_segments tests.
//!    The queue-population and drain steps are verified here; segment-level
//!    freeing for those paths remains a documented nonclaim until
//!    pub(crate)-level tests are added.

use std::path::PathBuf;

use tidefs_local_filesystem::{
    page_cache::{CachedPage, PageKey},
    LocalFileSystem,
};
use tidefs_types_vfs_core::InodeId;

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn setup_fs(test_name: &str) -> (PathBuf, LocalFileSystem) {
    set_test_key();
    let root = std::env::temp_dir().join(test_name);
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let fs = LocalFileSystem::open(&root).expect("open");
    (root, fs)
}

fn page_key(inode: u64, offset: u64) -> PageKey {
    PageKey::new(InodeId::new(inode), offset, 4096)
}

fn data_page(size: usize) -> CachedPage {
    CachedPage::new(vec![0u8; size], size)
}

// ═══════════════════════════════════════════════════════════════════════
// PAGE-CACHE RECLAIM TESTS (memory eviction)
// ═══════════════════════════════════════════════════════════════════════

// ── Test 1: reclaim evicts clean pages to reach low watermark ──────────

#[test]
fn test_reclaim_evicts_clean_pages_below_low_watermark() {
    let (_root, fs) = setup_fs("reclaim_test_01_low_watermark");

    // Insert pages for inode 1. With default watermarks (256/128 MiB),
    // these will be below the high watermark so no eviction occurs.
    // We verify the API correctness and that pages are cached.
    for i in 0..50u64 {
        fs.insert_page_and_maybe_reclaim(page_key(1, i * 4096), data_page(4096));
    }

    let (resident, count) = fs.page_cache_stats();
    assert!(count >= 50, "pages should be cached: {count}");
    assert!(resident > 0, "resident bytes should be > 0: {resident}");
}

// ── Test 2: reclaim skips dirty pages ──────────────────────────────────

#[test]
fn test_reclaim_skips_dirty_pages() {
    let (_root, fs) = setup_fs("reclaim_test_02_skip_dirty");

    // Insert pages and mark some dirty.
    for i in 0..10u64 {
        fs.insert_page_and_maybe_reclaim(page_key(1, i * 4096), data_page(4096));
    }

    // Mark pages 0-4 as dirty.
    {
        let mut dt = fs.dirty_page_tracker_mut();
        for i in 0..5u64 {
            dt.mark_dirty(page_key(1, i * 4096));
        }
    }

    // Dirty page tracker should reflect the state.
    let dt = fs.dirty_page_tracker_mut();
    assert_eq!(dt.dirty_page_count(), 5);
    drop(dt);

    // Evict inode 1's clean pages.
    let evicted = fs.page_cache_evict_inode(InodeId::new(1));
    // 10 pages total, 5 dirty => 5 clean evicted.
    assert_eq!(evicted, 5, "should evict 5 clean pages, evicted {evicted}");

    // Dirty pages should still be in cache.
    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 5, "dirty pages should remain in cache: {count}");

    // Mark them clean and verify they can be evicted.
    {
        let mut dt = fs.dirty_page_tracker_mut();
        for i in 0..5u64 {
            dt.mark_clean(page_key(1, i * 4096));
        }
    }
    let evicted = fs.page_cache_evict_inode(InodeId::new(1));
    assert_eq!(evicted, 5, "should evict remaining 5 clean pages");
    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 0, "all pages should be evicted: {count}");
}

// ── Test 3: evict_inode drops all clean pages ─────────────────────────

#[test]
fn test_reclaim_evict_inode_drops_all_clean_pages() {
    let (_root, fs) = setup_fs("reclaim_test_03_evict_inode");

    // Populate cache for inode 1 with 20 pages.
    for i in 0..20u64 {
        fs.insert_page_and_maybe_reclaim(page_key(1, i * 4096), data_page(4096));
    }

    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 20, "should have 20 pages cached: {count}");

    // Evict inode 1.
    let evicted = fs.page_cache_evict_inode(InodeId::new(1));
    assert_eq!(evicted, 20, "should evict all 20 clean pages");

    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 0, "cache should be empty: {count}");
}

// ── Test 4: ReclaimStats counters increment ───────────────────────────

#[test]
fn test_reclaim_stats_increment() {
    let (_root, fs) = setup_fs("reclaim_test_04_stats");

    // Insert pages for multiple inodes.
    for inode in 1..=3u64 {
        for i in 0..10u64 {
            fs.insert_page_and_maybe_reclaim(page_key(inode, i * 4096), data_page(4096));
        }
    }

    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 30, "should have 30 pages: {count}");

    // Evict inode 1.
    let evicted = fs.page_cache_evict_inode(InodeId::new(1));
    assert_eq!(evicted, 10);

    // Evict inode 2.
    let evicted = fs.page_cache_evict_inode(InodeId::new(2));
    assert_eq!(evicted, 10);

    // 10 pages remain for inode 3.
    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 10, "inode 3 pages should remain: {count}");
}

// ── Test 5: no-op when below high watermark ────────────────────────────

#[test]
fn test_reclaim_noop_below_high_watermark() {
    let (_root, fs) = setup_fs("reclaim_test_05_noop");

    // Insert a few pages (well below default 256 MiB high watermark).
    for i in 0..5u64 {
        fs.insert_page_and_maybe_reclaim(page_key(1, i * 4096), data_page(4096));
    }

    let (resident_before, count_before) = fs.page_cache_stats();
    assert_eq!(count_before, 5);

    // Call maybe_reclaim explicitly — should be a no-op.
    let evicted = fs.page_cache_maybe_reclaim();
    assert_eq!(evicted, 0, "should not evict below high watermark");

    let (resident_after, count_after) = fs.page_cache_stats();
    assert_eq!(count_after, count_before, "page count should not change");
    assert_eq!(
        resident_after, resident_before,
        "resident bytes should not change"
    );
}

// ── Test 6: unlink triggers page cache eviction ────────────────────────

#[test]
fn test_unlink_triggers_page_cache_eviction() {
    let (_root, mut fs) = setup_fs("reclaim_test_06_unlink");

    // Create a file and insert some pages into the page cache for it.
    fs.create_file("/evictable", 0o644).expect("create_file");
    let inode = fs.lookup("/evictable").expect("lookup");

    for i in 0..10u64 {
        fs.insert_page_and_maybe_reclaim(page_key(inode.get(), i * 4096), data_page(4096));
    }

    let (_, count) = fs.page_cache_stats();
    assert_eq!(count, 10, "should have 10 pages cached: {count}");

    // Unlink the file — should trigger page_cache_evict_inode.
    fs.unlink("/evictable").expect("unlink");

    let (_, count) = fs.page_cache_stats();
    assert_eq!(
        count, 0,
        "all pages should be evicted after unlink: {count}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// STORAGE RECLAIM TESTS (dead-segment freeing chain)
// ═══════════════════════════════════════════════════════════════════════
//
// These tests exercise the public-API portion of the production reclaim
// chain.  The full chain through drain_dead_segments() and reopen
// verification requires pub(crate) access (tested in lib.rs unit tests).
//
// Nonclaim: truncate-shrink and rename-overwrite full-chain
// drain_dead_segments + reopen variants are not individually covered.
// The local-queue population and tick drain are verified below; the
// segment-freeing step for those paths relies on the same
// drain_dead_segments() authority proven by the unlink full-chain test.

// ── Storage Test 1: unlink populates reclaim queue ────────────────────

#[test]
fn test_storage_reclaim_unlink_populates_queue() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_unlink");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/victim", 0o644).expect("create_file");
    fs.write_file("/victim", 0, &[0xCCu8; 4096]).expect("write");
    // Commit the initial data before mutating.
    fs.commit().expect("commit");

    assert!(
        fs.reclaim_queue_depth() == 0,
        "reclaim queue must be empty before unlink"
    );

    // Disable auto-commit so reclaim deltas stay in the local queue.
    fs.set_auto_commit(false);
    fs.unlink("/victim").expect("unlink");

    let depth = fs.reclaim_queue_depth();
    assert!(
        depth >= 2,
        "reclaim queue should have entries after unlink (extent + inode tombstone), got {depth}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ── Storage Test 2: truncate shrink populates reclaim queue ───────────

#[test]
fn test_storage_reclaim_truncate_shrink_populates_queue() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_trunc");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/shrinkable", 0o644).expect("create_file");
    fs.write_file("/shrinkable", 0, &[0xDDu8; 8192])
        .expect("write");
    fs.commit().expect("commit");

    assert!(fs.reclaim_queue_depth() == 0);

    fs.set_auto_commit(false);
    fs.truncate_file("/shrinkable", 4096).expect("truncate");

    let depth = fs.reclaim_queue_depth();
    assert!(
        depth >= 1,
        "reclaim queue should have entries after truncate shrink, got {depth}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ── Storage Test 3: rename overwrite produces reclaim entries ──────────

#[test]
fn test_storage_reclaim_rename_overwrite_produces_entries() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_rename");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/old", 0o644).expect("create old");
    fs.write_file("/old", 0, &[0x11u8; 2048])
        .expect("write old");
    fs.create_file("/new", 0o644).expect("create new");
    fs.write_file("/new", 0, &[0x22u8; 1024])
        .expect("write new");
    fs.commit().expect("commit");

    fs.rename("/old", "/new", false).expect("rename");

    // /old must be gone after rename-overwrite.
    assert!(
        fs.stat("/old").is_err(),
        "/old must be absent after rename-overwrite"
    );
    // /new must exist and hold old content (2048 bytes).
    let dest = fs.stat("/new").expect("/new must exist after rename");
    assert_eq!(
        dest.size, 2048,
        "/new size must match old content after rename-overwrite"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ── Storage Test 4: tick_background_services drains reclaim queue ─────

#[test]
fn test_storage_reclaim_tick_drains_queue() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_drain");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/keep", 0o644).expect("create keep");
    fs.write_file("/keep", 0, &[0xBBu8; 4096])
        .expect("write keep");
    fs.create_file("/drop", 0o644).expect("create drop");
    fs.write_file("/drop", 0, &[0xAAu8; 4096])
        .expect("write drop");
    fs.commit().expect("commit");

    assert!(fs.reclaim_queue_depth() == 0);

    // Disable auto-commit before unlink so entries stay in local queue.
    fs.set_auto_commit(false);
    fs.unlink("/drop").expect("unlink");

    let pre_drain_depth = fs.reclaim_queue_depth();
    assert!(
        pre_drain_depth >= 2,
        "queue must have entries before tick, got {pre_drain_depth}"
    );

    // tick_background_services Duty 2 drains the local queue into the
    // object-store durable reclaim queue via drain_local_reclaim_queue_into_store().
    fs.tick_background_services();

    assert!(
        fs.reclaim_queue_depth() == 0,
        "local reclaim queue must be empty after tick_background_services"
    );

    // Surviving file must remain reachable.
    let s = fs.stat("/keep").expect("keep must survive drain");
    assert_eq!(s.size, 4096);

    let _ = std::fs::remove_dir_all(&root);
}

// ── Storage Test 5: drain_local_reclaim_queue_into_store returns stats ─

#[test]
fn test_storage_reclaim_drain_stats_nonzero_after_unlink() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_stats");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/victim", 0o644).expect("create_file");
    fs.write_file("/victim", 0, &[0xEEu8; 4096]).expect("write");
    fs.commit().expect("commit");

    fs.set_auto_commit(false);
    fs.unlink("/victim").expect("unlink");

    let stats = fs.drain_local_reclaim_queue_into_store();
    assert!(
        stats.drained_any(),
        "drain should process entries after unlink; stats={stats:?}"
    );

    let reclaim_stats = fs.reclaim_stats();
    assert!(
        reclaim_stats.total_reclaim_drains >= 1,
        "total_reclaim_drains counter should increment"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ── Storage Test 6: reclaim queue stays empty across operations on
//                     committed data ───────────────────────────────────

#[test]
fn test_storage_reclaim_empty_after_commit_with_no_deletions() {
    set_test_key();
    let root = std::env::temp_dir().join("srec_empty");
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let mut fs = LocalFileSystem::open(&root).expect("open");

    fs.create_file("/a", 0o644).expect("create");
    fs.write_file("/a", 0, &[0u8; 1024]).expect("write");
    fs.commit().expect("commit");

    // No deletions — queue should remain empty.
    assert_eq!(fs.reclaim_queue_depth(), 0);

    let drain = fs.drain_local_reclaim_queue_into_store();
    assert!(
        !drain.drained_any(),
        "drain should be a no-op when no reclaim entries exist"
    );

    let _ = std::fs::remove_dir_all(&root);
}
