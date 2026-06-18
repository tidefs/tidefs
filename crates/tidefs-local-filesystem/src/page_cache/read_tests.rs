// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page-cache read-path validation.
//!
//! Exercises the PageCache read surface through a simple read-through helper
//! that mirrors how the VFS engine will use the cache: hash lookup on
//! cache-hit, fetch-and-insert on cache-miss, byte-range slicing across
//! page boundaries for partial and multi-page reads.
//!
//! Coverage:
//! - Cache-hit: exact byte content returned, hit counter incremented
//! - Cache-miss: page fetched from mock store, inserted into cache
//! - Read-around: partial pages at arbitrary offsets/lengths
//! - Multi-page reads: spanning page boundaries with mixed cache state
//! - Concurrent reads: overlapping and non-overlapping ranges
//! - Read-after-write: dirty-page read correctness
//! - Error injection: fetch failure propagation

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};

type MockObjectStore = HashMap<PageKey, Vec<u8>>;

/// Stats collected by read-through helper, since PageCache does not
/// auto-increment misses.
#[derive(Debug, Default)]
struct ReadStats {
    misses: u64,
}

/// Read `length` bytes starting at `offset` for `inode_id` through
/// the page cache.  On cache-miss fetches from `mock_store`.
///
/// Returns `None` when any required page is absent from the store
/// (simulating an object-store read failure).
fn read_through_page_cache(
    cache: &mut PageCache,
    mock_store: &MockObjectStore,
    inode_id: InodeId,
    offset: u64,
    length: usize,
    stats: &mut ReadStats,
) -> Option<Vec<u8>> {
    if length == 0 {
        return Some(Vec::new());
    }

    let page_size = cache.page_size();
    let end_offset = offset.saturating_add(length as u64);
    let mut page_keys: Vec<PageKey> = Vec::new();
    let mut pos = (offset / page_size) * page_size;
    while pos < end_offset {
        page_keys.push(PageKey::new(inode_id, pos, page_size));
        pos = pos.saturating_add(page_size);
    }

    let mut result = Vec::with_capacity(length);

    for key in &page_keys {
        let chunk: Vec<u8> = match cache.get(key) {
            Some(page) => slice_page(page, *key, offset, end_offset, page_size),
            None => {
                stats.misses += 1;
                let data = mock_store.get(key)?.clone();
                cache.insert(*key, CachedPage::new(data.clone(), data.len()));
                let page = cache.get(key).expect("page must be cached after insert");
                slice_page(page, *key, offset, end_offset, page_size)
            }
        };
        result.extend_from_slice(&chunk);
    }

    Some(result)
}

/// Extract the bytes overlapping [offset, end_offset) from a cached page.
fn slice_page(
    page: &CachedPage,
    key: PageKey,
    offset: u64,
    end_offset: u64,
    page_size: u64,
) -> Vec<u8> {
    let page_start = key.page_offset;
    let page_end = page_start.saturating_add(page_size);

    let slice_start = if offset > page_start {
        (offset - page_start) as usize
    } else {
        0
    };
    let slice_end = if end_offset < page_end {
        (end_offset - page_start) as usize
    } else {
        page.data.len()
    };

    page.data[slice_start..slice_end].to_vec()
}

fn key(inode: u64, offset: u64) -> PageKey {
    PageKey::new(InodeId::new(inode), offset, 4096)
}

fn patterned_page(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn mock_insert(store: &mut MockObjectStore, inode: u64, offset: u64, page: Vec<u8>) -> PageKey {
    let k = key(inode, offset);
    store.insert(k, page);
    k
}

// ── Cache-hit tests ────────────────────────────────────────────────────

#[test]
fn cache_hit_returns_exact_bytes() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    let inode = InodeId::new(1);
    mock_insert(&mut store, 1, 0, patterned_page(b'A', 4096));

    let r1 = read_through_page_cache(&mut cache, &store, inode, 0, 10, &mut stats).unwrap();
    assert_eq!(r1, &b"AAAAAAAAAA"[..]);
    assert_eq!(stats.misses, 1);

    let inserts_before = cache.inserts;
    let r2 = read_through_page_cache(&mut cache, &store, inode, 5, 8, &mut stats).unwrap();
    assert_eq!(r2, &b"AAAAAAAA"[..]);
    assert_eq!(stats.misses, 1, "no additional miss");
    assert_eq!(cache.inserts, inserts_before, "no additional insert");
}

#[test]
fn cache_hit_increments_counter_once_per_page() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 2, 0, patterned_page(b'X', 4096));
    mock_insert(&mut store, 2, 4096, patterned_page(b'Y', 4096));

    read_through_page_cache(&mut cache, &store, InodeId::new(2), 0, 5000, &mut stats).unwrap();
    assert_eq!(stats.misses, 2);
    assert_eq!(cache.inserts, 2);

    let hits_before = cache.hits;
    read_through_page_cache(&mut cache, &store, InodeId::new(2), 0, 5000, &mut stats).unwrap();
    assert_eq!(cache.hits - hits_before, 2, "two pages, one hit each");
    assert_eq!(stats.misses, 2, "misses unchanged");
    assert_eq!(cache.inserts, 2, "inserts unchanged");
}

#[test]
fn cache_hit_consistent_after_many_reads() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 3, 0, patterned_page(b'Z', 4096));

    read_through_page_cache(&mut cache, &store, InodeId::new(3), 0, 1, &mut stats).unwrap();
    let hits_before = cache.hits;

    for _ in 0..100 {
        let r = read_through_page_cache(&mut cache, &store, InodeId::new(3), 100, 50, &mut stats)
            .unwrap();
        assert_eq!(r, patterned_page(b'Z', 50));
    }
    assert_eq!(cache.hits - hits_before, 100, "one hit per read");
    assert_eq!(stats.misses, 1, "only the initial populate was a miss");
}

// ── Cache-miss tests ────────────────────────────────────────────────────

#[test]
fn cache_miss_populates_and_returns_data() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 4, 0, patterned_page(b'B', 4096));

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(4), 100, 20, &mut stats).unwrap();
    assert_eq!(r, &b"BBBBBBBBBBBBBBBBBBBB"[..]);
    assert_eq!(stats.misses, 1);
    assert_eq!(cache.inserts, 1);
}

#[test]
fn cache_miss_populates_multiple_pages() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    for i in 0..5u64 {
        mock_insert(
            &mut store,
            5,
            i * 4096,
            patterned_page(b'0' + i as u8, 4096),
        );
    }

    let r = read_through_page_cache(&mut cache, &store, InodeId::new(5), 0, 5 * 4096, &mut stats)
        .unwrap();
    assert_eq!(r.len(), 5 * 4096);
    for i in 0..5 {
        let chunk = &r[(i * 4096) as usize..((i + 1) * 4096) as usize];
        assert!(
            chunk.iter().all(|b| *b == b'0' + i as u8),
            "chunk {i} mismatch"
        );
    }
    assert_eq!(stats.misses, 5);
    assert_eq!(cache.inserts, 5);
}

// ── Read-around (partial page) tests ────────────────────────────────────

#[test]
fn read_around_page_beginning() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 6, 0, patterned_page(b'E', 4096));
    let mut stats = ReadStats::default();

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(6), 0, 256, &mut stats).unwrap();
    assert_eq!(r, patterned_page(b'E', 256));
}

#[test]
fn read_around_page_end() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 7, 0, patterned_page(b'F', 4096));
    let mut stats = ReadStats::default();

    let r = read_through_page_cache(
        &mut cache,
        &store,
        InodeId::new(7),
        4096 - 128,
        128,
        &mut stats,
    )
    .unwrap();
    assert_eq!(r, patterned_page(b'F', 128));
}

#[test]
fn read_around_page_middle() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 8, 0, patterned_page(b'G', 4096));
    let mut stats = ReadStats::default();

    let r = read_through_page_cache(&mut cache, &store, InodeId::new(8), 1024, 2048, &mut stats)
        .unwrap();
    assert_eq!(r, patterned_page(b'G', 2048));
}

#[test]
fn read_around_single_byte() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut page = vec![0u8; 4096];
    page[2048] = 0x42;
    mock_insert(&mut store, 9, 0, page);
    let mut stats = ReadStats::default();

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(9), 2048, 1, &mut stats).unwrap();
    assert_eq!(r, &[0x42]);
}

#[test]
fn read_around_zero_length() {
    let mut cache = PageCache::new(4096);
    let store = MockObjectStore::new();
    let mut stats = ReadStats::default();

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(10), 0, 0, &mut stats).unwrap();
    assert!(r.is_empty());
    assert_eq!(stats.misses, 0);
}

// ── Multi-page read tests ───────────────────────────────────────────────

#[test]
fn multi_page_read_spans_two_pages() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 11, 0, patterned_page(b'A', 4096));
    mock_insert(&mut store, 11, 4096, patterned_page(b'B', 4096));
    let mut stats = ReadStats::default();

    let r = read_through_page_cache(&mut cache, &store, InodeId::new(11), 3072, 2048, &mut stats)
        .unwrap();
    assert_eq!(r.len(), 2048);
    assert_eq!(&r[..1024], patterned_page(b'A', 1024).as_slice());
    assert_eq!(&r[1024..], patterned_page(b'B', 1024).as_slice());
}

#[test]
fn multi_page_read_three_pages_mixed_cache() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    let p1 = patterned_page(b'1', 4096);
    mock_insert(&mut store, 12, 0, patterned_page(b'0', 4096));
    mock_insert(&mut store, 12, 4096, p1.clone());
    mock_insert(&mut store, 12, 8192, patterned_page(b'2', 4096));

    // Pre-cache only the middle page (offset 4096).
    cache.insert(key(12, 4096), CachedPage::new(p1, 4096));

    // Read across three pages: offset 1024, length 9216.
    // Page 0 ([0, 4096)): bytes 1024..4096 = 3072 of '0'
    // Page 1 ([4096, 8192)): bytes 4096..8192 = 4096 of '1'
    // Page 2 ([8192, 12288)): bytes 8192..10240 = 2048 of '2'
    let r = read_through_page_cache(&mut cache, &store, InodeId::new(12), 1024, 9216, &mut stats)
        .unwrap();
    assert_eq!(r.len(), 9216);
    assert_eq!(&r[0..3072], patterned_page(b'0', 3072).as_slice());
    assert_eq!(&r[3072..7168], patterned_page(b'1', 4096).as_slice());
    assert_eq!(&r[7168..9216], patterned_page(b'2', 2048).as_slice());

    // Pages 0 and 2 were misses; page 1 was pre-cached (hit).
    assert_eq!(stats.misses, 2);
    assert_eq!(cache.page_count(), 3);
}

#[test]
fn multi_page_read_exact_boundary() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 13, 0, patterned_page(b'X', 4096));
    mock_insert(&mut store, 13, 4096, patterned_page(b'Y', 4096));
    mock_insert(&mut store, 13, 8192, patterned_page(b'Z', 4096));

    let r = read_through_page_cache(&mut cache, &store, InodeId::new(13), 4096, 4096, &mut stats)
        .unwrap();
    assert_eq!(r, patterned_page(b'Y', 4096));
    assert_eq!(stats.misses, 1);
}

#[test]
fn multi_page_read_many_pages() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    let n: u64 = 10;
    for i in 0..n {
        mock_insert(&mut store, 14, i * 4096, patterned_page(i as u8, 4096));
    }

    // Read from offset 512, length = 10 pages minus first and last partials.
    let r = read_through_page_cache(
        &mut cache,
        &store,
        InodeId::new(14),
        512,
        (n as usize) * 4096 - 1024,
        &mut stats,
    )
    .unwrap();

    // First page: bytes 512..4096 of pattern 0.
    assert!(r[0..(4096 - 512)].iter().all(|b| *b == 0));
    // Middle pages: each full page of pattern i.
    for i in 1..(n as usize - 1) {
        let off = (i - 1) * 4096 + (4096 - 512);
        assert!(
            r[off..off + 4096].iter().all(|b| *b == i as u8),
            "page {i} mismatch"
        );
    }
    // Last page: bytes 0..(4096-512) of pattern (n-1).
    let last_off = (n as usize - 2) * 4096 + (4096 - 512);
    assert!(
        r[last_off..].iter().all(|b| *b == (n - 1) as u8),
        "last page mismatch"
    );
}

// ── Read-after-write tests ──────────────────────────────────────────────

#[test]
fn read_after_write_sees_dirty_bytes() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 15, 0, patterned_page(b'O', 4096));

    read_through_page_cache(&mut cache, &store, InodeId::new(15), 0, 10, &mut stats).unwrap();

    // Modify cached page in-place (simulates a write dirtying the page).
    if let Some(page) = cache.get_mut(&key(15, 0)) {
        page.data[0..5].copy_from_slice(b"HELLO");
        page.dirty = true;
    }

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(15), 0, 10, &mut stats).unwrap();
    assert_eq!(&r[..5], b"HELLO");
    assert_eq!(&r[5..10], b"OOOOO");
}

#[test]
fn dirty_tracker_reflects_write_state() {
    let mut dt = DirtyPageTracker::new();
    let k1 = key(100, 0);
    let k2 = key(100, 4096);

    assert!(!dt.is_dirty(&k1));
    dt.mark_dirty(k1);
    assert!(dt.is_dirty(&k1));
    assert!(!dt.is_dirty(&k2));

    dt.mark_dirty(k2);
    assert_eq!(dt.dirty_page_count(), 2);
    assert_eq!(dt.per_inode_dirty_count(InodeId::new(100)), 2);

    dt.mark_clean(k1);
    assert!(!dt.is_dirty(&k1));
    assert!(dt.is_dirty(&k2));
    assert_eq!(dt.dirty_page_count(), 1);
}

// ── Concurrent read tests ───────────────────────────────────────────────

#[test]
fn concurrent_reads_non_overlapping() {
    let cache = Arc::new(Mutex::new(PageCache::new(4096)));
    let store = {
        let mut s = MockObjectStore::new();
        mock_insert(&mut s, 20, 0, patterned_page(b'A', 4096));
        mock_insert(&mut s, 20, 4096, patterned_page(b'B', 4096));
        mock_insert(&mut s, 20, 8192, patterned_page(b'C', 4096));
        Arc::new(s)
    };
    let bar = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();

    for (t, expected) in [(0u64, b'A'), (4096u64, b'B'), (8192u64, b'C')] {
        let c = Arc::clone(&cache);
        let s = Arc::clone(&store);
        let b = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            b.wait();
            let mut cache = c.lock().unwrap();
            let mut stats = ReadStats::default();
            let r = read_through_page_cache(&mut cache, &s, InodeId::new(20), t, 1000, &mut stats)
                .unwrap();
            assert_eq!(r, patterned_page(expected, 1000));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_reads_overlapping_no_corruption() {
    let cache = Arc::new(Mutex::new(PageCache::new(4096)));
    let store = {
        let mut s = MockObjectStore::new();
        mock_insert(&mut s, 21, 0, patterned_page(b'X', 4096));
        Arc::new(s)
    };
    let bar = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for t in 0..4 {
        let c = Arc::clone(&cache);
        let s = Arc::clone(&store);
        let b = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            b.wait();
            let mut stats = ReadStats::default();
            for _ in 0..50 {
                let mut cache = c.lock().unwrap();
                let off = ((t * 257) % 4000) as u64;
                let r =
                    read_through_page_cache(&mut cache, &s, InodeId::new(21), off, 96, &mut stats)
                        .unwrap();
                assert_eq!(r, patterned_page(b'X', 96));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_reads_mixed_cache_state() {
    let cache = Arc::new(Mutex::new(PageCache::new(4096)));
    let store = {
        let mut s = MockObjectStore::new();
        mock_insert(&mut s, 22, 0, patterned_page(b'P', 4096));
        mock_insert(&mut s, 22, 4096, patterned_page(b'Q', 4096));
        Arc::new(s)
    };

    {
        let mut c = cache.lock().unwrap();
        c.insert(
            key(22, 0),
            CachedPage::new(patterned_page(b'P', 4096), 4096),
        );
    }

    let bar = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();

    // Reader 1: page 0 only (always hit).
    {
        let c = Arc::clone(&cache);
        let s = Arc::clone(&store);
        let b = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            b.wait();
            let mut stats = ReadStats::default();
            for _ in 0..100 {
                let mut cache = c.lock().unwrap();
                let r =
                    read_through_page_cache(&mut cache, &s, InodeId::new(22), 0, 100, &mut stats)
                        .unwrap();
                assert_eq!(r, patterned_page(b'P', 100));
            }
        }));
    }

    // Reader 2: crosses boundary (page 0 hit, page 1 miss).
    {
        let c = Arc::clone(&cache);
        let s = Arc::clone(&store);
        let b = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            b.wait();
            let mut stats = ReadStats::default();
            for _ in 0..100 {
                let mut cache = c.lock().unwrap();
                let r = read_through_page_cache(
                    &mut cache,
                    &s,
                    InodeId::new(22),
                    2048,
                    3072,
                    &mut stats,
                )
                .unwrap();
                assert_eq!(r.len(), 3072);
                assert_eq!(&r[..2048], patterned_page(b'P', 2048).as_slice());
                assert_eq!(&r[2048..], patterned_page(b'Q', 1024).as_slice());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_reads_different_inodes() {
    let cache = Arc::new(Mutex::new(PageCache::new(4096)));
    let store = {
        let mut s = MockObjectStore::new();
        mock_insert(&mut s, 200, 0, patterned_page(b'J', 4096));
        mock_insert(&mut s, 201, 0, patterned_page(b'K', 4096));
        Arc::new(s)
    };
    let mut handles = Vec::new();

    for inode in [200u64, 201u64] {
        let c = Arc::clone(&cache);
        let s = Arc::clone(&store);
        let expected = if inode == 200 { b'J' } else { b'K' };
        handles.push(std::thread::spawn(move || {
            let mut stats = ReadStats::default();
            for _ in 0..200 {
                let mut cache = c.lock().unwrap();
                let r = read_through_page_cache(
                    &mut cache,
                    &s,
                    InodeId::new(inode),
                    0,
                    128,
                    &mut stats,
                )
                .unwrap();
                assert_eq!(r, patterned_page(expected, 128));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── Error injection tests ───────────────────────────────────────────────

#[test]
fn read_fails_when_store_has_no_page() {
    let mut cache = PageCache::new(4096);
    let store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    let r = read_through_page_cache(&mut cache, &store, InodeId::new(30), 0, 100, &mut stats);
    assert!(r.is_none());
}

#[test]
fn read_fails_when_one_page_of_many_missing() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 31, 0, patterned_page(b'A', 4096));
    // Intentionally omit page at offset 4096.
    mock_insert(&mut store, 31, 8192, patterned_page(b'C', 4096));
    let mut stats = ReadStats::default();

    let r = read_through_page_cache(
        &mut cache,
        &store,
        InodeId::new(31),
        0,
        3 * 4096,
        &mut stats,
    );
    assert!(r.is_none());
}

#[test]
fn read_succeeds_when_all_pages_present() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    mock_insert(&mut store, 32, 0, patterned_page(b'A', 4096));
    mock_insert(&mut store, 32, 4096, patterned_page(b'B', 4096));
    mock_insert(&mut store, 32, 8192, patterned_page(b'C', 4096));
    let mut stats = ReadStats::default();

    let r =
        read_through_page_cache(&mut cache, &store, InodeId::new(32), 0, 10, &mut stats).unwrap();
    assert_eq!(r, patterned_page(b'A', 10));
}

// ── Page-key boundary edge cases ───────────────────────────────────────

#[test]
fn page_key_rounds_down_to_page_size() {
    assert_eq!(PageKey::new(InodeId::new(99), 4096, 4096).page_offset, 4096);
    assert_eq!(PageKey::new(InodeId::new(99), 4095, 4096).page_offset, 0);
    assert_eq!(PageKey::new(InodeId::new(99), 8191, 4096).page_offset, 4096);
    assert_eq!(PageKey::new(InodeId::new(99), 8192, 4096).page_offset, 8192);
}

#[test]
fn read_large_offset_across_pages() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    for i in 0..10u64 {
        mock_insert(&mut store, 40, i * 4096, patterned_page(i as u8, 4096));
    }

    // offset = 5*4096 + 1024 = 21504, length = 2*4096 + 512 = 8704
    // Page 5 (20480-24575): bytes 21504..24576 = 3072 of 0x05
    // Page 6 (24576-28671): bytes 24576..28672 = 4096 of 0x06
    // Page 7 (28672-32767): bytes 28672..30208 = 1536 of 0x07
    let r = read_through_page_cache(
        &mut cache,
        &store,
        InodeId::new(40),
        5 * 4096 + 1024,
        2 * 4096 + 512,
        &mut stats,
    )
    .unwrap();

    assert_eq!(r.len(), 8704);
    assert_eq!(&r[0..3072], patterned_page(5, 3072).as_slice());
    assert_eq!(&r[3072..7168], patterned_page(6, 4096).as_slice());
    assert_eq!(&r[7168..8704], patterned_page(7, 1536).as_slice());
}

// ── Integration: byte-for-byte multi-page read ─────────────────────────

#[test]
fn integration_full_read_path_three_pages_mixed_cache() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();

    let inode = InodeId::new(99);
    mock_insert(&mut store, 99, 0, vec![0xAAu8; 4096]);
    mock_insert(&mut store, 99, 4096, vec![0xBBu8; 4096]);
    mock_insert(&mut store, 99, 8192, vec![0xCCu8; 4096]);

    // Pre-cache only page 1.
    cache.insert(key(99, 4096), CachedPage::new(vec![0xBBu8; 4096], 4096));

    // Read all three pages fully.
    let r = read_through_page_cache(&mut cache, &store, inode, 0, 3 * 4096, &mut stats).unwrap();
    assert_eq!(r.len(), 12288);

    assert!(r[0..4096].iter().all(|b| *b == 0xAA), "page 0 mismatch");
    assert!(r[4096..8192].iter().all(|b| *b == 0xBB), "page 1 mismatch");
    assert!(r[8192..12288].iter().all(|b| *b == 0xCC), "page 2 mismatch");

    // Page 1 was pre-cached (hit), pages 0 and 2 were misses.
    assert_eq!(stats.misses, 2);
    assert_eq!(cache.page_count(), 3);
}

// ── PageCache statistics integrity ─────────────────────────────────────

#[test]
fn statistics_accurate_after_mixed_workload() {
    let mut cache = PageCache::new(4096);
    let mut store = MockObjectStore::new();
    let mut stats = ReadStats::default();
    mock_insert(&mut store, 50, 0, patterned_page(b'M', 4096));
    mock_insert(&mut store, 50, 4096, patterned_page(b'N', 4096));

    read_through_page_cache(&mut cache, &store, InodeId::new(50), 0, 5000, &mut stats).unwrap();
    assert_eq!(stats.misses, 2);
    assert_eq!(cache.inserts, 2);

    let misses_before = stats.misses;
    let inserts_before = cache.inserts;
    read_through_page_cache(&mut cache, &store, InodeId::new(50), 0, 5000, &mut stats).unwrap();
    assert_eq!(stats.misses, misses_before);
    assert_eq!(cache.inserts, inserts_before);
}

#[test]
fn remove_page_adjusts_eviction_counter() {
    let mut cache = PageCache::new(4096);
    cache.insert(
        key(60, 0),
        CachedPage::new(patterned_page(b'R', 4096), 4096),
    );
    assert_eq!(cache.page_count(), 1);
    cache.remove(&key(60, 0));
    assert_eq!(cache.page_count(), 0);
    assert_eq!(cache.evictions, 1);
}

#[test]
fn remove_inode_clears_only_that_inode() {
    let mut cache = PageCache::new(4096);
    for i in 0..4u64 {
        cache.insert(
            key(70, i * 4096),
            CachedPage::new(patterned_page(b'S', 4096), 4096),
        );
    }
    cache.insert(
        key(71, 0),
        CachedPage::new(patterned_page(b'T', 4096), 4096),
    );
    assert_eq!(cache.page_count(), 5);

    let removed = cache.remove_inode(InodeId::new(70));
    assert_eq!(removed, 4);
    assert_eq!(cache.page_count(), 1);
    assert!(cache.get(&key(71, 0)).is_some());
}

#[test]
fn cached_inodes_iterator_yields_all_inodes() {
    let mut cache = PageCache::new(4096);
    cache.insert(
        key(80, 0),
        CachedPage::new(patterned_page(b'U', 4096), 4096),
    );
    cache.insert(
        key(80, 4096),
        CachedPage::new(patterned_page(b'V', 4096), 4096),
    );
    cache.insert(
        key(81, 0),
        CachedPage::new(patterned_page(b'W', 4096), 4096),
    );

    let inodes: Vec<InodeId> = cache.cached_inodes().collect();
    assert_eq!(inodes.len(), 2);
    assert!(inodes.contains(&InodeId::new(80)));
    assert!(inodes.contains(&InodeId::new(81)));
}

#[test]
fn lru_for_inode_returns_pages_in_insertion_order() {
    let mut cache = PageCache::new(4096);
    cache.insert(
        key(90, 0),
        CachedPage::new(patterned_page(b'1', 4096), 4096),
    );
    cache.insert(
        key(90, 4096),
        CachedPage::new(patterned_page(b'2', 4096), 4096),
    );
    cache.insert(
        key(90, 8192),
        CachedPage::new(patterned_page(b'3', 4096), 4096),
    );

    let lru_keys: Vec<PageKey> = cache.lru_for_inode(InodeId::new(90)).copied().collect();
    assert_eq!(lru_keys.len(), 3);
    assert_eq!(lru_keys[0].page_offset, 0);
    assert_eq!(lru_keys[1].page_offset, 4096);
    assert_eq!(lru_keys[2].page_offset, 8192);
}

#[test]
fn page_cache_default_page_size_uses_content_chunk_size() {
    let cache = PageCache::with_default_page_size();
    assert!(cache.page_size() >= 4096);
}

#[test]
fn resident_bytes_tracks_memory_usage() {
    let mut cache = PageCache::new(4096);
    assert_eq!(cache.resident_bytes(), 0);

    let data = vec![0u8; 4096];
    let approx = data.capacity() as u64 + 64;
    cache.insert(key(110, 0), CachedPage::new(data.clone(), data.len()));
    assert_eq!(cache.resident_bytes(), approx);

    cache.remove(&key(110, 0));
    assert_eq!(cache.resident_bytes(), 0);
}
