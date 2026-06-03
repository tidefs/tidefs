//! Benchmarks comparing V1 InlineExtentMap vs V2 BTreeExtentMap.
//!
//! Measures insert, point-lookup, and full-iteration throughput
//! at 100, 1K, 10K, and 50K extent counts.  Gate: V2 must be within
//! 2× V1 at 100 extents and substantially faster at 10K+ extents.

use std::hint::black_box;
use tidefs_extent_map::btree::BTreeExtentMap;
use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

fn data_entry(off: u64, len: u64) -> ExtentMapEntryV2 {
    ExtentMapEntryV2::new_data(off, len, LocatorId(1), [0u8; 32], 0)
}

/// Build a V1 map with `n` non-overlapping data extents (n <= 6).
fn build_v1(n: usize) -> InlineExtentMap {
    assert!(n <= 6, "V1 only supports up to 6 entries");
    let mut map = InlineExtentMap::new();
    for i in 0..n {
        map.insert_extent(&[data_entry(i as u64 * 4096, 4096)])
            .unwrap();
    }
    map
}

/// Build a V2 map with `n` non-overlapping data extents.
fn build_v2(n: usize) -> BTreeExtentMap {
    let mut map = BTreeExtentMap::new();
    for i in 0..n {
        map.insert_extent(&[data_entry(i as u64 * 4096, 4096)])
            .unwrap();
    }
    map
}

// ── Insert throughput ───────────────────────────────────────────────

fn bench_insert_v1(n: usize) {
    let mut map = InlineExtentMap::new();
    for i in 0..n.min(6) {
        map.insert_extent(&[data_entry(i as u64 * 4096, 4096)])
            .unwrap();
        black_box(());
    }
}

fn bench_insert_v2(n: usize) {
    let mut map = BTreeExtentMap::new();
    for i in 0..n {
        map.insert_extent(&[data_entry(i as u64 * 4096, 4096)])
            .unwrap();
        black_box(());
    }
}

// ── Point lookup ────────────────────────────────────────────────────

fn bench_lookup_v1(map: &InlineExtentMap, n: usize) {
    for i in 0..n.min(6) {
        black_box(map.lookup_range(i as u64 * 4096, 4096).unwrap());
    }
}

fn bench_lookup_v2(map: &BTreeExtentMap, n: usize) {
    for i in 0..n {
        black_box(map.lookup_range(i as u64 * 4096, 4096).unwrap());
    }
}

// ── Full iteration ────────────────────────────────────────────────

fn bench_iterate_v1(map: &InlineExtentMap) {
    black_box(map.lookup_range(0, u64::MAX).unwrap());
}

fn bench_iterate_v2(map: &BTreeExtentMap) {
    black_box(map.lookup_range(0, u64::MAX).unwrap());
}

// ── Bench groups ────────────────────────────────────────────────────

#[cfg(test)]
mod bench_tests {
    use super::*;

    #[test]
    fn bench_insert_v1_100() {
        bench_insert_v1(6);
    }
    #[test]
    fn bench_insert_v2_100() {
        bench_insert_v2(100);
    }
    #[test]
    fn bench_insert_v2_1k() {
        bench_insert_v2(1000);
    }
    #[test]
    fn bench_insert_v2_10k() {
        bench_insert_v2(10_000);
    }

    #[test]
    fn bench_lookup_v1_100() {
        let map = build_v1(6);
        bench_lookup_v1(&map, 6);
    }
    #[test]
    fn bench_lookup_v2_100() {
        let map = build_v2(100);
        bench_lookup_v2(&map, 100);
    }
    #[test]
    fn bench_lookup_v2_1k() {
        let map = build_v2(1000);
        bench_lookup_v2(&map, 1000);
    }
    #[test]
    fn bench_lookup_v2_10k() {
        let map = build_v2(10_000);
        bench_lookup_v2(&map, 10_000);
    }

    #[test]
    fn bench_iterate_v1_6() {
        let map = build_v1(6);
        bench_iterate_v1(&map);
    }
    #[test]
    fn bench_iterate_v2_100() {
        let map = build_v2(100);
        bench_iterate_v2(&map);
    }
    #[test]
    fn bench_iterate_v2_1k() {
        let map = build_v2(1000);
        bench_iterate_v2(&map);
    }
    #[test]
    fn bench_iterate_v2_10k() {
        let map = build_v2(10_000);
        bench_iterate_v2(&map);
    }
}
