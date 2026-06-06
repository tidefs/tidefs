//! Page-cache reclaim and eviction validation suite.
//!
//! Exercises the reclaim path: clean-page eviction under memory
//! pressure, dirty-page protection, and LRU insertion-order eviction.
//! Complements the writeback validation suite (#3519) by covering the
//! other half of the page-cache lifecycle.
//!
//! Tests operate through public [`tidefs_local_filesystem::LocalFileSystem`]
//! APIs and internal page-cache reclaim interfaces, with no dependency
//! on any FUSE dispatch surface.
//!
//! # Tests
//!
//! - `evict_single_clean_page` — populate one clean page, trigger
//!   reclaim, assert eviction and footprint drop.
//! - `dirty_page_not_evicted` — dirty a page, trigger reclaim without
//!   writeback, assert the page stays.
//! - `evict_lru_clean_pages` — populate N clean pages, trigger reclaim,
//!   assert oldest (first-inserted) evicted first.

use std::env;
use std::fs;

use tidefs_local_filesystem::page_cache::reclaim::{PageCacheReclaimer, ReclaimWatermarks};
use tidefs_local_filesystem::page_cache::{CachedPage, DirtyPageTracker, PageCache, PageKey};
use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

// ── helpers ───────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "tidefs-reclaim-val-{label}-{ts}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

/// Build a PageCacheReclaimer with tight watermarks so any eviction
/// request actually evicts.
fn testing_reclaimer<'a>(
    cache: &'a mut PageCache,
    dt: &'a DirtyPageTracker,
) -> PageCacheReclaimer<'a> {
    // 512-byte high, 256-byte low — one page triggers eviction.
    let wm = ReclaimWatermarks::new(512, 256);
    PageCacheReclaimer::new(cache, dt, wm)
}

/// Fill a 4 KiB buffer with a repeating byte pattern.
fn fill_page(pattern_byte: u8) -> Vec<u8> {
    vec![pattern_byte; 4096]
}

// ── test 1: clean-page eviction ───────────────────────────────────

/// Populate one clean page, trigger reclaim, and assert the page is
/// evicted and the cache footprint drops to zero.
#[test]
fn evict_single_clean_page() {
    set_test_key();
    let dir = temp_dir("evict_one");
    let mut fs = open_fs(&dir);

    // Create an inode to anchor the page key.
    let inode = fs
        .create_file("/page", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let key = PageKey::new(inode.inode_id, 0, 4096);
    let data = fill_page(0xAB);

    // Insert via the page-cache directly, skipping reclaim trigger.
    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key, CachedPage::new(data.clone(), data.len()));
    }
    assert_eq!(fs.page_cache_stats().1, 1, "one page should be resident");

    // Trigger reclaim with tiny watermarks — the single clean page
    // should be evicted.
    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        reclaimer.evict_lru(1)
    };
    assert_eq!(evicted, 1, "single clean page should be evicted");
    assert_eq!(
        fs.page_cache_stats().1,
        0,
        "cache should be empty after eviction"
    );
}

// ── test 2: dirty-page protection ─────────────────────────────────

/// Dirty a page without writeback, then trigger reclaim. The dirty
/// page must remain in the cache — reclaim must skip dirty pages.
#[test]
fn dirty_page_not_evicted() {
    set_test_key();
    let dir = temp_dir("dirty_protect");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/dirty", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let key = PageKey::new(inode.inode_id, 0, 4096);
    let data = fill_page(0xCC);

    // Insert the page and mark it dirty.
    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key, CachedPage::new(data.clone(), data.len()));
    }
    fs.dirty_page_tracker_mut().mark_dirty(key);

    assert_eq!(fs.page_cache_stats().1, 1, "one page resident");
    assert!(
        fs.dirty_page_tracker_mut().is_dirty(&key),
        "page should be tracked as dirty"
    );

    // Trigger reclaim — dirty page must be skipped.
    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        reclaimer.evict_lru(1)
    };
    assert_eq!(evicted, 0, "dirty page must not be evicted");
    assert_eq!(
        fs.page_cache_stats().1,
        1,
        "dirty page should still be resident"
    );

    // Verify the page is still in cache.
    let still_there = fs.page_cache_mut().get(&key).is_some();
    assert!(still_there, "dirty page should still be in cache");
}

// ── test 3: LRU insertion-order eviction ──────────────────────────

/// Insert three clean pages in a known order and trigger eviction one
/// page at a time. The oldest (first-inserted) page must be evicted
/// first because the current reclaim implementation uses insertion-order
/// LRU (front = oldest).
#[test]
fn evict_lru_clean_pages() {
    set_test_key();
    let dir = temp_dir("lru_order");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/lru", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert three pages in sequence: offset 0, 4096, 8192.
    let key0 = PageKey::new(inode_id, 0, 4096);
    let key1 = PageKey::new(inode_id, 4096, 4096);
    let key2 = PageKey::new(inode_id, 8192, 4096);

    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key0, CachedPage::new(fill_page(0x00), 4096));
        cache.insert(key1, CachedPage::new(fill_page(0x11), 4096));
        cache.insert(key2, CachedPage::new(fill_page(0x22), 4096));
    }
    assert_eq!(fs.page_cache_stats().1, 3, "three pages resident");

    // Evict one page — should be key0 (oldest/first-inserted).
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1, "one page should be evicted");
    }
    assert_eq!(fs.page_cache_stats().1, 2, "two pages remaining");

    // key0 must be gone; key1 and key2 remain.
    assert!(
        fs.page_cache_mut().get(&key0).is_none(),
        "oldest page (offset 0) should be evicted first"
    );
    assert!(
        fs.page_cache_mut().get(&key1).is_some(),
        "middle page (offset 4096) should remain"
    );
    assert!(
        fs.page_cache_mut().get(&key2).is_some(),
        "newest page (offset 8192) should remain"
    );

    // Evict a second page — should be key1.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1);
    }
    assert_eq!(fs.page_cache_stats().1, 1);

    assert!(fs.page_cache_mut().get(&key1).is_none());
    assert!(fs.page_cache_mut().get(&key2).is_some());
}

// ── test 4: mixed dirty/clean LRU ─────────────────────────────────

/// Populate a mix of dirty and clean pages in insertion order. Trigger
/// reclaim and assert clean pages are evicted first even when dirty
/// pages are older in the LRU order.
#[test]
fn mixed_dirty_clean_lru() {
    set_test_key();
    let dir = temp_dir("mixed_lru");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/mixed", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 4 pages: A (offset 0), B (4096), C (8192), D (12288).
    let key_a = PageKey::new(inode_id, 0, 4096);
    let key_b = PageKey::new(inode_id, 4096, 4096);
    let key_c = PageKey::new(inode_id, 8192, 4096);
    let key_d = PageKey::new(inode_id, 12288, 4096);

    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key_a, CachedPage::new(fill_page(0xAA), 4096));
        cache.insert(key_b, CachedPage::new(fill_page(0xBB), 4096));
        cache.insert(key_c, CachedPage::new(fill_page(0xCC), 4096));
        cache.insert(key_d, CachedPage::new(fill_page(0xDD), 4096));
    }

    // Mark A (oldest) and C as dirty.
    fs.dirty_page_tracker_mut().mark_dirty(key_a);
    fs.dirty_page_tracker_mut().mark_dirty(key_c);

    assert_eq!(fs.page_cache_stats().1, 4, "four pages resident");

    // Evict 2 pages. Should skip A (dirty, oldest), evict B (oldest clean),
    // skip C (dirty), evict D (next clean). Total evicted: 2.
    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        reclaimer.evict_lru(2)
    };
    assert_eq!(evicted, 2, "should evict the two clean pages");

    // A (dirty) and C (dirty) must remain; B and D must be gone.
    assert!(
        fs.page_cache_mut().get(&key_a).is_some(),
        "dirty page A should remain despite being oldest"
    );
    assert!(
        fs.page_cache_mut().get(&key_b).is_none(),
        "clean page B should be evicted"
    );
    assert!(
        fs.page_cache_mut().get(&key_c).is_some(),
        "dirty page C should remain"
    );
    assert!(
        fs.page_cache_mut().get(&key_d).is_none(),
        "clean page D should be evicted"
    );
}

// ── test 5: multi-handle LRU merged ───────────────────────────────

/// Populate pages for the same file through two interleaved insertion
/// sessions (simulating two handles). Assert the LRU is unified across
/// both sessions: eviction order follows insertion order, not per-handle
/// grouping.
#[test]
fn two_handles_single_file_lru_merged() {
    set_test_key();
    let dir = temp_dir("two_handles");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/shared", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Simulate handle-1 inserting pages at offsets 0, 8192.
    let h1_key0 = PageKey::new(inode_id, 0, 4096);
    let h1_key2 = PageKey::new(inode_id, 8192, 4096);

    // Simulate handle-2 inserting pages at offsets 4096, 12288.
    let h2_key1 = PageKey::new(inode_id, 4096, 4096);
    let h2_key3 = PageKey::new(inode_id, 12288, 4096);

    {
        let mut cache = fs.page_cache_mut();
        cache.insert(h1_key0, CachedPage::new(fill_page(0x00), 4096));
        cache.insert(h2_key1, CachedPage::new(fill_page(0x11), 4096));
        cache.insert(h1_key2, CachedPage::new(fill_page(0x22), 4096));
        cache.insert(h2_key3, CachedPage::new(fill_page(0x33), 4096));
    }
    assert_eq!(fs.page_cache_stats().1, 4, "four pages resident");

    // Evict 1 page — should be h1_key0 (oldest overall, offset 0).
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1);
    }

    assert!(
        fs.page_cache_mut().get(&h1_key0).is_none(),
        "handle-1 first page (offset 0) should be evicted (oldest overall)"
    );
    assert!(
        fs.page_cache_mut().get(&h2_key1).is_some(),
        "handle-2 first page (offset 4096) should remain"
    );
    assert!(
        fs.page_cache_mut().get(&h1_key2).is_some(),
        "handle-1 second page (offset 8192) should remain"
    );
    assert!(
        fs.page_cache_mut().get(&h2_key3).is_some(),
        "handle-2 second page (offset 12288) should remain"
    );

    // Evict second page — should be h2_key1 (next oldest).
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1);
    }

    assert!(fs.page_cache_mut().get(&h2_key1).is_none());
    assert!(fs.page_cache_mut().get(&h1_key2).is_some());
    assert!(fs.page_cache_mut().get(&h2_key3).is_some());

    // Evict remaining two.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(2);
        assert_eq!(evicted, 2);
    }
    assert_eq!(fs.page_cache_stats().1, 0, "all pages should be evicted");
}

// ── test 6: exact-pressure eviction ───────────────────────────────

/// Trigger reclaim with an exact page-count target and assert that
/// exactly the requested number of clean pages are evicted — no more,
/// no less (when enough clean pages exist).
#[test]
fn evict_under_exact_pressure() {
    set_test_key();
    let dir = temp_dir("exact_pressure");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/exact", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 5 clean pages.
    let keys: Vec<PageKey> = (0..5)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for (i, &key) in keys.iter().enumerate() {
            cache.insert(key, CachedPage::new(fill_page(i as u8), 4096));
        }
    }
    assert_eq!(fs.page_cache_stats().1, 5, "five pages resident");

    // Request eviction of exactly 3 pages.
    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        reclaimer.evict_lru(3)
    };
    assert_eq!(evicted, 3, "exactly 3 pages should be evicted");
    assert_eq!(
        fs.page_cache_stats().1,
        2,
        "two pages should remain after evicting 3 of 5"
    );

    // The first 3 pages (offset 0, 4096, 8192) should be gone.
    assert!(fs.page_cache_mut().get(&keys[0]).is_none());
    assert!(fs.page_cache_mut().get(&keys[1]).is_none());
    assert!(fs.page_cache_mut().get(&keys[2]).is_none());

    // The last 2 pages (offset 12288, 16384) should remain.
    assert!(fs.page_cache_mut().get(&keys[3]).is_some());
    assert!(fs.page_cache_mut().get(&keys[4]).is_some());
}

// ── test 7: dirty page evicted after writeback ────────────────────

/// Mark a page dirty, verify reclaim skips it. Then mark it clean
/// (simulating writeback completion) and assert reclaim now evicts it.
#[test]
fn dirty_page_evicted_after_writeback() {
    set_test_key();
    let dir = temp_dir("dirty_then_clean");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/wb", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let key = PageKey::new(inode.inode_id, 0, 4096);

    // Insert page and mark dirty.
    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key, CachedPage::new(fill_page(0xEE), 4096));
    }
    fs.dirty_page_tracker_mut().mark_dirty(key);
    assert_eq!(fs.page_cache_stats().1, 1);

    // Reclaim while dirty — must skip.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(
            evicted, 0,
            "dirty page must not be evicted before writeback"
        );
    }
    assert_eq!(fs.page_cache_stats().1, 1, "dirty page still resident");

    // Simulate writeback completion: mark clean.
    fs.dirty_page_tracker_mut().mark_clean(key);
    assert!(!fs.dirty_page_tracker_mut().is_dirty(&key));

    // Reclaim after writeback — page is now clean and evictable.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1, "clean page should be evicted after writeback");
    }
    assert_eq!(
        fs.page_cache_stats().1,
        0,
        "page should be gone after writeback+evict"
    );
}

// ── test 8: two-file independent LRU ──────────────────────────────

/// Populate pages for two different inodes, then trigger reclaim
/// targeting only one inode via [`LocalFileSystem::page_cache_evict_inode`].
/// Assert only the target inode's pages are evicted; the other inode's
/// pages are unaffected.
#[test]
fn two_files_independent_lru() {
    set_test_key();
    let dir = temp_dir("two_files");
    let mut fs = open_fs(&dir);

    let inode_a = fs
        .create_file("/file_a", DEFAULT_FILE_PERMISSIONS)
        .expect("create file a");
    let inode_b = fs
        .create_file("/file_b", DEFAULT_FILE_PERMISSIONS)
        .expect("create file b");

    // Insert 3 pages for inode A.
    let keys_a: Vec<PageKey> = (0..3)
        .map(|i| PageKey::new(inode_a.inode_id, i * 4096, 4096))
        .collect();
    // Insert 3 pages for inode B.
    let keys_b: Vec<PageKey> = (0..3)
        .map(|i| PageKey::new(inode_b.inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for key in keys_a.iter().chain(keys_b.iter()) {
            cache.insert(*key, CachedPage::new(fill_page(0x77), 4096));
        }
    }
    assert_eq!(fs.page_cache_stats().1, 6, "six pages total");

    // Evict all clean pages for inode A only.
    let evicted = fs.page_cache_evict_inode(inode_a.inode_id);
    assert_eq!(
        evicted, 3,
        "all 3 clean pages for inode A should be evicted"
    );

    // Inode A pages must be gone.
    for key in &keys_a {
        assert!(
            fs.page_cache_mut().get(key).is_none(),
            "inode A page should be evicted"
        );
    }

    // Inode B pages must remain untouched.
    for key in &keys_b {
        assert!(
            fs.page_cache_mut().get(key).is_some(),
            "inode B page should be unaffected"
        );
    }
    assert_eq!(
        fs.page_cache_stats().1,
        3,
        "three pages (inode B) should remain"
    );
}

// ── test 9: writeback-before-evict ordering ───────────────────────

/// Dirty a page, run reclaim, and verify the reclaim path recognizes
/// the dirty state: zero pages evicted and the dirty-page-skip counter
/// incremented. Then mark clean and assert the page is evicted on the
/// next reclaim pass — confirming the ordering invariant.
#[test]
fn writeback_before_evict_ordering() {
    set_test_key();
    let dir = temp_dir("wb_before_evict");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/ordered", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let key = PageKey::new(inode.inode_id, 0, 4096);

    // Insert page and mark dirty.
    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key, CachedPage::new(fill_page(0xFF), 4096));
    }
    fs.dirty_page_tracker_mut().mark_dirty(key);

    // Reclaim must skip the dirty page and record the skip.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);

        assert_eq!(evicted, 0, "no pages evicted while dirty");
        assert!(
            reclaimer.stats.pages_skipped_dirty > 0,
            "reclaim must record dirty-page skips (writeback-before-evict check)"
        );
    }

    // Mark clean (writeback completed) — page becomes evictable.
    fs.dirty_page_tracker_mut().mark_clean(key);

    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1, "page evicted after writeback completion");
    }
    assert_eq!(fs.page_cache_stats().1, 0);
}

// ── test 10: writeback failure keeps page ─────────────────────────

/// Dirty a page among several clean pages. Reclaim must evict the
/// clean pages but leave the dirty page untouched — simulating a
/// writeback failure where the dirty flag was never cleared.
#[test]
fn writeback_failure_keeps_page() {
    set_test_key();
    let dir = temp_dir("wb_fail");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/fail", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 4 pages: the last one will be dirtied and "fail" writeback.
    let key0 = PageKey::new(inode_id, 0, 4096);
    let key1 = PageKey::new(inode_id, 4096, 4096);
    let key2 = PageKey::new(inode_id, 8192, 4096);
    let key_dirty = PageKey::new(inode_id, 12288, 4096);

    {
        let mut cache = fs.page_cache_mut();
        cache.insert(key0, CachedPage::new(fill_page(0x00), 4096));
        cache.insert(key1, CachedPage::new(fill_page(0x11), 4096));
        cache.insert(key2, CachedPage::new(fill_page(0x22), 4096));
        cache.insert(key_dirty, CachedPage::new(fill_page(0xFF), 4096));
    }
    // Mark one page dirty — writeback "failed", dirty flag remains.
    fs.dirty_page_tracker_mut().mark_dirty(key_dirty);

    assert_eq!(fs.page_cache_stats().1, 4);

    // Evict up to 4 pages — should evict the 3 clean ones and skip the dirty one.
    let (evicted, skipped_dirty) = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let n = reclaimer.evict_lru(4);
        (n, reclaimer.stats.pages_skipped_dirty)
    };
    assert_eq!(evicted, 3, "only 3 clean pages evicted");
    assert!(skipped_dirty > 0, "dirty page skipped during reclaim");

    // Clean pages gone, dirty page remains.
    assert!(fs.page_cache_mut().get(&key0).is_none());
    assert!(fs.page_cache_mut().get(&key1).is_none());
    assert!(fs.page_cache_mut().get(&key2).is_none());
    assert!(
        fs.page_cache_mut().get(&key_dirty).is_some(),
        "dirty page must remain after failed writeback"
    );
    assert_eq!(fs.page_cache_stats().1, 1);
}

// ── test 11: evict_to_low_watermark stops at target ───────────────

/// Populate enough pages to exceed a high watermark, then call
/// `evict_to_low_watermark` and assert eviction stops once resident
/// bytes fall to or below the configured low watermark.
#[test]
fn evict_to_low_watermark_stops() {
    set_test_key();
    let dir = temp_dir("low_wm");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/wm", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 20 pages of 4096 bytes each (~80 KiB of data, ~82 KiB with overhead).
    let keys: Vec<PageKey> = (0..20)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for &key in &keys {
            cache.insert(key, CachedPage::new(fill_page(0x77), 4096));
        }
    }
    // Mark the last 3 pages dirty so eviction cannot clear everything.
    fs.dirty_page_tracker_mut().mark_dirty(keys[17]);
    fs.dirty_page_tracker_mut().mark_dirty(keys[18]);
    fs.dirty_page_tracker_mut().mark_dirty(keys[19]);
    let resident_before = fs.page_cache_stats().0;
    assert_eq!(fs.page_cache_stats().1, 20);
    assert!(
        resident_before > 40_000,
        "should have substantial resident bytes"
    );

    // Set watermarks: high at ~10 pages worth, low at ~5 pages worth.
    // One page overhead is ~4160 bytes (4096 data + 64 overhead).
    // high = 10 * 4160 ≈ 41600, low = 5 * 4160 ≈ 20800.
    let high_bytes = 10 * (4096 + 64);
    let low_bytes = 5 * (4096 + 64);

    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let wm = ReclaimWatermarks::new(high_bytes, low_bytes);
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        assert!(
            reclaimer.above_high_watermark(),
            "should exceed high watermark"
        );
        reclaimer.evict_to_low_watermark()
    };

    assert!(
        evicted > 0,
        "pages should be evicted to reach low watermark"
    );
    assert!(
        fs.page_cache_stats().0 <= low_bytes,
        "resident bytes should be at or below low watermark after eviction"
    );
    assert!(
        fs.page_cache_stats().1 < 20,
        "fewer pages should remain after eviction"
    );
    // At least some pages still resident (not everything evicted).
    assert!(fs.page_cache_stats().1 > 0, "should not evict everything");
}

// ── test 12: reclaim does not deadlock with open handles ───────────

/// Hold a reference to the filesystem, trigger aggressive reclaim, and
/// verify the filesystem remains responsive for basic operations.
#[test]
fn reclaim_does_not_deadlock_with_open_handles() {
    set_test_key();
    let dir = temp_dir("no_deadlock");
    let mut fs = open_fs(&dir);

    // Create a file and populate the page cache.
    let inode = fs
        .create_file("/alive", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    let keys: Vec<PageKey> = (0..10)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for &key in &keys {
            cache.insert(key, CachedPage::new(fill_page(0x42), 4096));
        }
    }
    assert_eq!(fs.page_cache_stats().1, 10);

    // Aggressive reclaim — evict all 10 pages.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(10);
        assert_eq!(evicted, 10, "all clean pages should be evicted");
    }
    assert_eq!(fs.page_cache_stats().1, 0);

    // Filesystem must still be responsive: stat the file, create another.
    let stat_result = fs.stat("/alive");
    assert!(stat_result.is_ok(), "stat should succeed after reclaim");

    let new_file = fs.create_file("/after_reclaim", DEFAULT_FILE_PERMISSIONS);
    assert!(new_file.is_ok(), "create_file should succeed after reclaim");
}

// ── test 13: read survives eviction ───────────────────────────────

/// Write data through the filesystem API (object-store-backed), insert
/// matching pages into the page cache, then evict those pages. Reading
/// the file must still return correct data — the object store is the
/// authority, and cache eviction must not affect read correctness.
#[test]
fn read_during_eviction() {
    set_test_key();
    let dir = temp_dir("read_evict");
    let mut fs = open_fs(&dir);

    let payload: Vec<u8> = b"read-survives-cache-eviction-test".to_vec();

    // Write data to the object store via the filesystem.
    fs.create_file("/data", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.write_file("/data", 0, &payload).expect("write file");

    // Also insert matching pages into the page cache.
    let inode_id = fs.stat("/data").expect("stat").inode_id;
    let key = PageKey::new(inode_id, 0, 4096);
    {
        let mut cache = fs.page_cache_mut();
        let mut page_data = vec![0u8; 4096];
        let copy_len = payload.len().min(4096);
        page_data[..copy_len].copy_from_slice(&payload[..copy_len]);
        cache.insert(key, CachedPage::new(page_data, copy_len));
    }
    assert_eq!(fs.page_cache_stats().1, 1, "page should be in cache");

    // Evict the page from cache.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 1, "page should be evicted from cache");
    }
    assert_eq!(fs.page_cache_stats().1, 0, "cache should be empty");

    // Read must still return correct data from the object store.
    let data = fs.read_file("/data").expect("read after eviction");
    assert_eq!(data, payload, "data must survive cache eviction");
}

// ── test 14: write keeps page dirty during reclaim ────────────────

/// Insert a page into the cache, mark it dirty, then trigger reclaim.
/// The dirty page must not be evicted — reclaim must respect the
/// dirty flag set by the write path. Subsequent read_file from the
/// object store must also succeed.
#[test]
fn write_during_eviction() {
    set_test_key();
    let dir = temp_dir("write_evict");
    let mut fs = open_fs(&dir);

    let payload: Vec<u8> = b"dirty-page-survives-reclaim".to_vec();

    // Write data through the filesystem's compatibility object-store path.
    fs.create_file("/dirty_write", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.write_file("/dirty_write", 0, &payload)
        .expect("write file");

    // Insert the page into the cache and mark it dirty (simulating an
    // in-flight dirty page from the write path).
    let inode_id = fs.stat("/dirty_write").expect("stat").inode_id;
    let key = PageKey::new(inode_id, 0, 4096);
    {
        let mut cache = fs.page_cache_mut();
        let mut page_data = vec![0u8; 4096];
        let copy_len = payload.len().min(4096);
        page_data[..copy_len].copy_from_slice(&payload[..copy_len]);
        cache.insert(key, CachedPage::new(page_data, copy_len));
    }
    fs.dirty_page_tracker_mut().mark_dirty(key);
    assert_eq!(fs.page_cache_stats().1, 1);

    // Trigger reclaim — the dirty page must survive.
    {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let evicted = reclaimer.evict_lru(1);
        assert_eq!(evicted, 0, "dirty page must not be evicted during write");
    }
    assert_eq!(fs.page_cache_stats().1, 1, "dirty page still in cache");

    // Object-store read must still work.
    let data = fs
        .read_file("/dirty_write")
        .expect("read after reclaim attempt");
    assert_eq!(data, payload, "object-store data intact after reclaim");
}

// ── test 15: reclaim stats track dirty skips precisely ────────────

/// Dirty an exact number of pages among clean pages, trigger reclaim,
/// and assert the reclaim statistics report exactly the expected number
/// of dirty-page skips — confirming writeback-before-evict accounting.
#[test]
fn reclaim_stats_track_dirty_skips() {
    set_test_key();
    let dir = temp_dir("dirty_stats");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/stats", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 6 pages: offsets 0, 4096, 8192, 12288, 16384, 20480.
    let keys: Vec<PageKey> = (0..6)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for &key in &keys {
            cache.insert(key, CachedPage::new(fill_page(0x99), 4096));
        }
    }

    // Mark exactly 2 pages dirty: keys at indices 1 and 4.
    fs.dirty_page_tracker_mut().mark_dirty(keys[1]);
    fs.dirty_page_tracker_mut().mark_dirty(keys[4]);

    assert_eq!(fs.page_cache_stats().1, 6);

    // Evict up to 6 pages — should evict 4 clean, skip 2 dirty.
    let (evicted, skipped) = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let mut reclaimer = testing_reclaimer(&mut cache, &dt);
        let n = reclaimer.evict_lru(6);
        (n, reclaimer.stats.pages_skipped_dirty)
    };

    assert_eq!(evicted, 4, "four clean pages evicted");
    assert_eq!(skipped, 2, "exactly two dirty pages skipped");

    // Only the 2 dirty pages should remain.
    assert_eq!(fs.page_cache_stats().1, 2);
    assert!(fs.page_cache_mut().get(&keys[1]).is_some());
    assert!(fs.page_cache_mut().get(&keys[4]).is_some());

    // Clean pages gone.
    assert!(fs.page_cache_mut().get(&keys[0]).is_none());
    assert!(fs.page_cache_mut().get(&keys[2]).is_none());
    assert!(fs.page_cache_mut().get(&keys[3]).is_none());
    assert!(fs.page_cache_mut().get(&keys[5]).is_none());
}

// ── test 16: hard limit enforced ──────────────────────────────────

/// Insert pages past a tight high watermark, trigger reclaim, and
/// assert resident bytes drop to or below the low watermark. Also
/// verify the public `insert_page_and_maybe_reclaim` API path is
/// callable without panicking.
#[test]
fn hard_limit_enforced() {
    set_test_key();
    let dir = temp_dir("hard_limit");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/limit", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    // Insert 15 clean pages + 3 dirty pages (floor) via the public API.
    let keys: Vec<PageKey> = (0..18)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    for &key in &keys {
        let page = CachedPage::new(fill_page(0xBB), 4096);
        let _old = fs.insert_page_and_maybe_reclaim(key, page);
        // Default watermarks are 256 MiB — no reclaim triggered here.
    }
    assert_eq!(fs.page_cache_stats().1, 18, "18 pages resident");

    // Mark last 2 pages dirty to act as an eviction floor.
    for key in &keys[16..] {
        fs.dirty_page_tracker_mut().mark_dirty(*key);
    }

    let page_overhead: u64 = 4096 + 64; // data + struct overhead

    // Set tight watermarks: high at 8 pages, low at 3 pages.
    let high_bytes = 8 * page_overhead;
    let low_bytes = 4 * page_overhead;

    let evicted = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        let wm = ReclaimWatermarks::new(high_bytes, low_bytes);
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        assert!(
            reclaimer.above_high_watermark(),
            "18 pages exceed 8-page high watermark"
        );
        reclaimer.evict_to_low_watermark()
    };

    assert!(evicted > 0, "pages should be evicted");
    assert!(
        fs.page_cache_stats().0 <= low_bytes,
        "resident bytes must be at or below low watermark after reclaim"
    );

    // At least the 5 dirty pages must remain (eviction floor).
    assert!(
        fs.page_cache_stats().1 >= 2,
        "at least 5 dirty pages should remain as eviction floor"
    );
}

// ── test 17: per-inode dirty count ────────────────────────────────

/// Dirty pages across multiple inodes and verify
/// [`DirtyPageTracker::per_inode_dirty_count`] returns the correct
/// count for each.
#[test]
fn per_inode_dirty_count() {
    set_test_key();
    let dir = temp_dir("per_ino_dirty");
    let mut fs = open_fs(&dir);

    let ino1 = fs
        .create_file("/f1", DEFAULT_FILE_PERMISSIONS)
        .expect("create f1");
    let ino2 = fs
        .create_file("/f2", DEFAULT_FILE_PERMISSIONS)
        .expect("create f2");
    let ino3 = fs
        .create_file("/f3", DEFAULT_FILE_PERMISSIONS)
        .expect("create f3");

    // Inode 1: 2 dirty pages.
    let k1a = PageKey::new(ino1.inode_id, 0, 4096);
    let k1b = PageKey::new(ino1.inode_id, 4096, 4096);
    fs.dirty_page_tracker_mut().mark_dirty(k1a);
    fs.dirty_page_tracker_mut().mark_dirty(k1b);

    // Inode 2: 3 dirty pages.
    let k2a = PageKey::new(ino2.inode_id, 0, 4096);
    let k2b = PageKey::new(ino2.inode_id, 4096, 4096);
    let k2c = PageKey::new(ino2.inode_id, 8192, 4096);
    fs.dirty_page_tracker_mut().mark_dirty(k2a);
    fs.dirty_page_tracker_mut().mark_dirty(k2b);
    fs.dirty_page_tracker_mut().mark_dirty(k2c);

    // Inode 3: 0 dirty pages.

    let dt = fs.dirty_page_tracker_mut();
    assert_eq!(
        dt.per_inode_dirty_count(ino1.inode_id),
        2,
        "inode 1 should have 2 dirty pages"
    );
    assert_eq!(
        dt.per_inode_dirty_count(ino2.inode_id),
        3,
        "inode 2 should have 3 dirty pages"
    );
    assert_eq!(
        dt.per_inode_dirty_count(ino3.inode_id),
        0,
        "inode 3 should have 0 dirty pages"
    );
    assert_eq!(dt.dirty_page_count(), 5, "total 5 dirty pages");
}

// ── test 18: all-dirty pages block eviction ───────────────────────

/// Insert pages and mark every one dirty, then call
/// `evict_to_low_watermark`. Zero pages should be evicted, and the
/// reclaim stats must report that every page was skipped.
#[test]
fn full_lru_walk_stops_on_all_dirty() {
    set_test_key();
    let dir = temp_dir("all_dirty");
    let mut fs = open_fs(&dir);

    let inode = fs
        .create_file("/all_dirty", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    let inode_id = inode.inode_id;

    let keys: Vec<PageKey> = (0..8)
        .map(|i| PageKey::new(inode_id, i * 4096, 4096))
        .collect();

    {
        let mut cache = fs.page_cache_mut();
        for &key in &keys {
            cache.insert(key, CachedPage::new(fill_page(0xDD), 4096));
        }
    }

    // Mark every page dirty.
    for &key in &keys {
        fs.dirty_page_tracker_mut().mark_dirty(key);
    }
    assert_eq!(fs.page_cache_stats().1, 8);

    // Reclaim must evict nothing and skip all 8 pages.
    let (evicted, skipped) = {
        let mut cache = fs.page_cache_mut();
        let dt = fs.dirty_page_tracker_mut();
        // Tiny watermarks force eviction attempt.
        let wm = ReclaimWatermarks::new(512, 256);
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);
        let n = reclaimer.evict_to_low_watermark();
        (n, reclaimer.stats.pages_skipped_dirty)
    };

    assert_eq!(evicted, 0, "no pages evicted when all are dirty");
    assert_eq!(skipped, 8, "all 8 dirty pages should be skipped");

    // All pages still resident.
    assert_eq!(fs.page_cache_stats().1, 8);
    for key in &keys {
        assert!(
            fs.page_cache_mut().get(key).is_some(),
            "every dirty page must remain after reclaim attempt"
        );
    }
}
