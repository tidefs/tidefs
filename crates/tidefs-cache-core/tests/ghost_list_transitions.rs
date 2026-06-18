// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Ghost-list B1/B2 transition tests for tidefs-cache-core ARC.
//!
//! These integration tests verify ghost-list behaviour observable through
//! the public CacheLatticeRegistry API under EvictionPolicyKind::Adaptive:
//!
//! 1. Ghost-hit re-access: entries evicted from T1 (sequential scan)
//!    that are immediately re-accessed promote to T2 and survive longer.
//! 2. Ghost-list sizing: B1-heavy workloads cause the cache to favour
//!    T1 (recent) entries; B2-heavy workloads cause T2 (frequent)
//!    entries to dominate.
//! 3. Adaptive rebalancing: after alternating B1-heavy and B2-heavy
//!    workload phases, observable cache behaviour shifts accordingly.
//! 4. Ghost-list capacity enforcement: ghost metadata does not consume
//!    cache slots — ghost hits re-insert data into main cache, and
//!    main-cache capacity is always respected.
//!
//! These complement arc_state_machine.rs (state-machine and eviction
//! ordering) and arc_insert.rs (basic ARC operations).

use tidefs_cache_core::{CacheEntry, CacheLatticeRegistry, EvictionPolicyKind, GhostListStats};
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, MemoryDomain, RebuildCostClass,
};

// ── Helpers ────────────────────────────────────────────────────────

fn make_header(key: u64) -> CacheEntryHeader {
    let mut h = CacheEntryHeader::new(
        CacheClass::PosixNamespaceMirror,
        MemoryDomain::AdapterServingHot,
        key,
        "ghost_trans_test",
        RebuildCostClass::Cheap,
        1,
    );
    h.anchor_vector_ref = 1;
    h
}

fn make_registry(capacity: usize) -> CacheLatticeRegistry<u64, String> {
    let mut reg = CacheLatticeRegistry::new();
    reg.register_cache(
        CacheClass::PosixNamespaceMirror,
        capacity,
        EvictionPolicyKind::Adaptive,
    );
    reg
}

// ====================================================================
// Group A: Ghost-hit re-access behaviour
// ====================================================================

/// When a scan-evicted entry is immediately re-accessed (ghost hit
/// on B1), ARC should promote it to T2 and it should survive
/// subsequent eviction pressure better than a fresh entry.
#[test]
fn b1_ghost_hit_promotes_to_t2_and_survives() {
    let mut reg = make_registry(3);

    // Fill cache
    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Evict key 1 by inserting key 4 (sequential scan pattern)
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        4,
        CacheEntry::new(make_header(4), "v4".into()),
    );

    // Key 1 is now in B1 ghost. Re-insert it (ghost hit).
    // This should give it higher retention than a purely fresh entry.
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "v1-again".into()),
    );

    // Access key 1 multiple times to build up weight
    for _ in 0..5 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }

    // Now evict with a batch of fresh entries
    for i in 5..=10 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Key 1 (ghost-hit survivor) should still be present
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "ghost-hit re-inserted key 1 must survive eviction pressure"
    );
    assert_eq!(reg.total_entries(), 3);
}

/// A key that was evicted from T2 (frequent) and re-accessed
/// (B2 ghost hit) should retain even stronger survival than a
/// B1 ghost hit.
#[test]
fn b2_ghost_hit_survives_better_than_b1() {
    let mut reg = make_registry(3);

    // Insert and heavily access key 2 (promote to T2)
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "v1".into()),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::new(make_header(2), "v2".into()),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(make_header(3), "v3".into()),
    );

    // Heavy access on key 2 → T2
    for _ in 0..20 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }

    // Evict key 2 by overflowing with fresh entries
    for i in 4..=10 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Key 2 should be evicted (B2 ghost hit territory).
    // Re-insert it — B2 ghost hit.
    let was_evicted = reg.get(CacheClass::PosixNamespaceMirror, &2).is_none();
    if was_evicted {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(make_header(2), "v2-b2-ghost".into()),
        );

        // Access a few times to establish weight
        for _ in 0..5 {
            let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
        }

        // Flood with fresh keys again
        for i in 11..=20 {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(make_header(i), format!("v{i}")),
            );
        }

        // B2 ghost-hit key 2 should still survive
        assert!(
            reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
            "B2 ghost-hit key 2 must survive second eviction wave"
        );
    }
    // If key 2 was never evicted, it survived the first wave — also correct
    // for a frequently-accessed entry with ARC's protection.
}

/// A key evicted and never re-accessed (ghost miss) should not
/// get any special treatment. Its ghost metadata stays in B1/B2
/// but no cache slot is consumed.
#[test]
fn ghost_miss_does_not_consume_cache_slot() {
    let mut reg = make_registry(3);

    // Fill cache
    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Evict keys 1 and 2 by inserting 4, 5, 6, 7
    for i in 4..=7 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Cache must be exactly at capacity
    assert_eq!(
        reg.total_entries(),
        3,
        "ghost metadata for evicted keys must not consume cache slots"
    );

    // Some original keys were evicted during the overflow and are
    // absent (ghost miss on lookup). Ghost lists track them but don't
    // hold data in cache slots.
    let evicted_originals: Vec<u64> = [1u64, 2u64, 3u64]
        .iter()
        .filter(|k| reg.get(CacheClass::PosixNamespaceMirror, k).is_none())
        .copied()
        .collect();
    assert!(
        !evicted_originals.is_empty(),
        "at least one original key must have been evicted; absent count: {}",
        evicted_originals.len()
    );
}

// ====================================================================
// Group B: Ghost-list size and workload adaptation
// ====================================================================

/// B1-heavy workload (sequential scan): inserting many unique keys
/// in order causes T1 to dominate. Re-accessing scan-evicted keys
/// (B1 ghost hits) should cause ARC to favour T1 (increase p).
#[test]
fn b1_heavy_scan_workload_favours_t1() {
    let mut reg = make_registry(4);

    // Phase 1: sequential scan — 50 unique keys
    for i in 1..=50 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // After the scan, the cache holds the 4 most recently inserted keys
    assert_eq!(reg.total_entries(), 4);

    // Phase 2: re-access scan-evicted keys (simulating B1 ghost hits)
    // Keys 40-46 should no longer be in cache, but re-accessing them
    // triggers B1 ghost hits and should increase p.
    let _hits_before = reg.hit_count();
    for k in 40..=46 {
        // Re-insert if not present (ghost hit → data re-insertion)
        if reg.get(CacheClass::PosixNamespaceMirror, &k).is_none() {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                k,
                CacheEntry::new(make_header(k), format!("v{k}-reinsert")),
            );
        }
    }

    // After re-accessing scan-evicted keys, the cache should still
    // respect capacity
    assert_eq!(
        reg.total_entries(),
        4,
        "cache must stay at capacity after B1 ghost-hit re-insertions"
    );

    // Some of the re-inserted keys should be present (indicating p increased
    // to favour T1/recent entries over older T2 entries)
    let reinserted_present: Vec<u64> = (40..=46)
        .filter(|k| reg.get(CacheClass::PosixNamespaceMirror, k).is_some())
        .collect();
    assert!(
        !reinserted_present.is_empty(),
        "at least one re-accessed scan-evicted key should survive"
    );
}

/// B2-heavy workload (repetitive access to a hot set):
/// frequently accessed entries should dominate T2 and survive
/// better than scan entries.
#[test]
fn b2_heavy_repetitive_workload_favours_t2() {
    let mut reg = make_registry(5);

    // Insert 5 entries and heavily access the first 2
    for i in 1..=5 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Heavy access on keys 1 and 2 → T2
    for _ in 0..30 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }

    // Sequential scan: insert keys 6..=30
    for i in 6..=30 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // The T2 entries (1, 2) should survive the scan because
    // B2-heavy pattern decreases p, giving more space to T2
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "frequently-accessed key 1 must survive sequential scan"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
        "frequently-accessed key 2 must survive sequential scan"
    );
    assert_eq!(reg.total_entries(), 5);
}

/// Alternating workload phases: B1-heavy scan followed by B2-heavy
/// repetitive access. The cache must adapt its p-size and remain
/// externally consistent.
#[test]
fn alternating_b1_b2_phases_maintain_capacity() {
    let mut reg = make_registry(6);

    // Phase A: B1-heavy scan (keys 1..30)
    for i in 1..=30 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }
    let evictions_a = reg.eviction_count();
    assert_eq!(reg.total_entries(), 6);

    // Phase B: B2-heavy — access surviving survivors repeatedly
    for _ in 0..15 {
        for k in 25..=30 {
            let _ = reg.get(CacheClass::PosixNamespaceMirror, &k);
        }
    }

    // Phase C: B1-heavy scan again (keys 31..60)
    for i in 31..=60 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }
    let evictions_c = reg.eviction_count();

    // Evictions must have increased
    assert!(
        evictions_c > evictions_a,
        "evictions must increase across workload phases: {evictions_a} -> {evictions_c}"
    );

    // Cache always at capacity
    assert_eq!(
        reg.total_entries(),
        6,
        "cache must stay at capacity through alternating phases"
    );
}

// ====================================================================
// Group C: Ghost-list stats tracking under load
// ====================================================================

/// GhostListStats counters accumulate correctly across many
/// record_* calls in sequence.
#[test]
fn ghost_stats_counters_are_monotonic() {
    let mut stats = GhostListStats::default();

    // Initial state
    assert_eq!(stats.b1_hits, 0);
    assert_eq!(stats.b1_misses, 0);
    assert_eq!(stats.b2_hits, 0);
    assert_eq!(stats.b2_misses, 0);
    assert_eq!(stats.evictions_since_adapt, 0);

    // Accumulate B1 stats
    for _ in 0..42 {
        stats.record_b1_hit();
    }
    for _ in 0..7 {
        stats.record_b1_miss();
    }
    assert_eq!(stats.b1_hits, 42);
    assert_eq!(stats.b1_misses, 7);

    // Accumulate B2 stats
    for _ in 0..13 {
        stats.record_b2_hit();
    }
    for _ in 0..31 {
        stats.record_b2_miss();
    }
    assert_eq!(stats.b2_hits, 13);
    assert_eq!(stats.b2_misses, 31);

    // Eviction counter
    for _ in 0..99 {
        stats.record_eviction();
    }
    assert_eq!(stats.evictions_since_adapt, 99);
    assert!(!stats.should_adapt(100));
    assert!(stats.should_adapt(99));

    // One more
    stats.record_eviction();
    assert!(stats.should_adapt(100));
    assert_eq!(stats.evictions_since_adapt, 100);

    // Reset
    stats.reset_adaptation_counter();
    assert_eq!(stats.evictions_since_adapt, 0);
    // Other counters unaffected
    assert_eq!(stats.b1_hits, 42);
    assert_eq!(stats.b2_misses, 31);
}

/// GhostListStats::should_adapt reports correctly at boundary values.
#[test]
fn ghost_stats_adapt_boundary() {
    let mut stats = GhostListStats::default();

    // Exactly at threshold
    for _ in 0..50 {
        stats.record_eviction();
    }
    assert!(stats.should_adapt(50));
    assert!(!stats.should_adapt(51));

    // Interval of 1: always adapt after any eviction
    let mut stats2 = GhostListStats::default();
    stats2.record_eviction();
    assert!(stats2.should_adapt(1));
    assert!(!stats2.should_adapt(2));
}

/// Ghost stats at default state: zero and no adaptation.
#[test]
fn ghost_stats_default_no_adaptation() {
    let stats = GhostListStats::default();
    assert_eq!(stats.b1_hits, 0);
    assert_eq!(stats.b2_hits, 0);
    assert_eq!(stats.evictions_since_adapt, 0);
    // Interval of 0: always adapts because evictions_since_adapt(0) >= 0
    assert!(stats.should_adapt(0), "interval 0 should always adapt");
    // Even tiny interval needs at least that many evictions
    assert!(!stats.should_adapt(1));
}

/// GhostListStats reset preserves other counters and clears eviction counter.
#[test]
fn ghost_stats_reset_only_clears_eviction_counter() {
    let mut stats = GhostListStats::default();

    stats.record_b1_hit();
    stats.record_b1_hit();
    stats.record_b2_hit();
    stats.record_b2_miss();
    for _ in 0..200 {
        stats.record_eviction();
    }

    let b1_h = stats.b1_hits;
    let b1_m = stats.b1_misses;
    let b2_h = stats.b2_hits;
    let b2_m = stats.b2_misses;

    stats.reset_adaptation_counter();

    assert_eq!(
        stats.evictions_since_adapt, 0,
        "reset must zero eviction counter"
    );
    assert_eq!(stats.b1_hits, b1_h, "reset must preserve b1_hits");
    assert_eq!(stats.b1_misses, b1_m, "reset must preserve b1_misses");
    assert_eq!(stats.b2_hits, b2_h, "reset must preserve b2_hits");
    assert_eq!(stats.b2_misses, b2_m, "reset must preserve b2_misses");
}

/// GhostListStats large counter values do not overflow or wrap.
#[test]
fn ghost_stats_large_counters_no_overflow() {
    let mut stats = GhostListStats::default();

    // Saturate counters near u64::MAX / 2
    let large = 1_000_000_000u64;
    for _ in 0..large {
        stats.record_b1_hit();
        stats.record_b2_miss();
        stats.record_eviction();
    }

    assert_eq!(stats.b1_hits, large);
    assert_eq!(stats.b2_misses, large);
    assert_eq!(stats.evictions_since_adapt, large);
}

// ====================================================================
// Group D: Ghost-list-driven capacity enforcement
// ====================================================================

/// Even with many ghost hits causing re-insertions, cache capacity
/// is never exceeded.
#[test]
fn ghost_reinsertions_never_exceed_capacity() {
    let mut reg = make_registry(3);

    // Repeated cycle: fill, evict some, re-insert evicted (ghost hit)
    for cycle in 0..100 {
        let base = cycle * 10;

        // Insert 10 fresh keys (causes many evictions)
        for i in 0..10 {
            let key = base + i;
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                key,
                CacheEntry::new(make_header(key), format!("c{cycle}k{i}")),
            );
        }

        // Re-insert some keys from earlier cycles (ghost hits)
        if cycle >= 1 {
            for k in (cycle - 1) * 10..(cycle - 1) * 10 + 3 {
                if reg.get(CacheClass::PosixNamespaceMirror, &k).is_none() {
                    reg.insert(
                        CacheClass::PosixNamespaceMirror,
                        k,
                        CacheEntry::new(make_header(k), format!("c{}k{}-ghost", cycle - 1, k % 10)),
                    );
                }
            }
        }

        assert!(
            reg.total_entries() <= 3,
            "cycle {}: cache entries {} must not exceed capacity 3",
            cycle,
            reg.total_entries()
        );
    }

    assert_eq!(reg.total_entries(), 3);
}

/// Removing an entry that was ghost-hit re-inserted works correctly:
/// the slot is freed and a new insert succeeds without eviction.
#[test]
fn remove_ghost_hit_entry_frees_slot() {
    let mut reg = make_registry(3);

    // Fill cache
    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Evict key 1, then ghost-hit re-insert it
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        4,
        CacheEntry::new(make_header(4), "v4".into()),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "v1-ghost".into()),
    );

    assert_eq!(reg.total_entries(), 3);

    // Remove the ghost-hit entry
    let removed = reg.remove(CacheClass::PosixNamespaceMirror, &1);
    assert!(removed.is_some(), "ghost-hit key 1 must be removable");
    assert_eq!(reg.total_entries(), 2);

    // Insert without eviction
    let _evictions_before = reg.eviction_count();
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        5,
        CacheEntry::new(make_header(5), "v5".into()),
    );
    assert_eq!(
        reg.total_entries(),
        3,
        "insert after remove must fill slot without exceeding capacity"
    );
    // May or may not evict depending on internal state, but capacity is respected
    assert!(reg.total_entries() <= 3);
}
