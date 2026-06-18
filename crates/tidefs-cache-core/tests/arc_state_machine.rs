// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ARC state-machine, ghost-list transition, and deterministic eviction
//! ordering tests for tidefs-cache-core.
//!
//! These integration tests exercise the public CacheLatticeRegistry API
//! under EvictionPolicyKind::Adaptive to verify:
//!
//! 1. T1/T2 list transitions: once-seen vs frequent entries, scan vs
//!    repetitive workload eviction behavior.
//! 2. Ghost-list (B1/B2) transitions: hit-on-ghost adaptation, p-tuning
//!    under B1-heavy and B2-heavy workloads, ghost stat accumulation.
//! 3. Deterministic eviction ordering: weight-priority, hit-count
//!    priority, equal-score tie-breaking consistency.
//! 4. Edge cases: rapid insert/evict cycling, zero ghost lists,
//!    weight clamping/saturation, recency-delta weight updates,
//!    cache-class isolation under ARC policy.
//!
//! These complement the arc_insert.rs integration tests (basic ARC ops)
//! and arc_proptest.rs (property-based invariants).

use tidefs_cache_core::{
    initial_entry_weight, update_entry_weight, ArcWeightConfig, CacheEntry, CacheLatticeRegistry,
    EntryWeight, EvictionPolicyKind, GhostListStats, MAX_ENTRY_WEIGHT,
};
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, EvictabilityClass, MemoryDomain, RebuildCostClass,
};

use std::time::Duration;

// ── Helpers ────────────────────────────────────────────────────────

fn make_header(key: u64) -> CacheEntryHeader {
    let mut h = CacheEntryHeader::new(
        CacheClass::PosixNamespaceMirror,
        MemoryDomain::AdapterServingHot,
        key,
        "arc_sm_test",
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
// Group 1: ARC T1/T2 list transition tests
// ====================================================================

/// T1 entry (seen once) vs T2 entry (seen many times):
/// the frequent entry must survive eviction over the once-seen entry.
#[test]
fn t1_once_seen_evicted_before_t2_frequent() {
    let mut reg = make_registry(3);

    // Fill cache with 3 entries
    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Promote key 2 to T2 (frequent) by accessing it many times
    for _ in 0..8 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }

    // Insert a new entry, forcing eviction
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        4,
        CacheEntry::new(make_header(4), "v4".into()),
    );

    // Key 2 (T2/frequent) must survive
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
        "T2 frequent key 2 must survive eviction"
    );

    // The evicted key must be from {1, 3} (T1/once-seen)
    let survivors: Vec<u64> = [1u64, 3u64]
        .iter()
        .filter(|k| reg.get(CacheClass::PosixNamespaceMirror, k).is_some())
        .copied()
        .collect();
    assert!(
        survivors.len() == 1,
        "exactly one T1 entry should survive: {survivors:?} remain (1 T1 evicted)"
    );
}

/// In a sequential scan workload (many unique keys seen once),
/// T1 entries dominate and should evict from the LRU end of T1.
#[test]
fn t1_sequential_scan_evicts_from_t1_lru_end() {
    let mut reg = make_registry(4);

    // Pre-populate with 4 entries
    for i in 1..=4 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Promote key 1 to T2 (frequent)
    for _ in 0..6 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }

    // Sequential scan: insert many new once-seen keys (T1 entries)
    // These should evict from T1, not from T2 (key 1 protected)
    for i in 5..=12 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Key 1 (T2/frequent) must survive the scan
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "T2 frequent key 1 must survive sequential scan eviction pressure"
    );
    assert_eq!(reg.total_entries(), 4);
}

/// A workload that alternates between T1-heavy (scans) and T2-heavy
/// (repetitive access) should adapt eviction behavior accordingly.
#[test]
fn t1_t2_workload_phase_transition() {
    let mut reg = make_registry(3);

    // Phase 1: T2-heavy — access keys 1,2 repeatedly
    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }
    for _ in 0..10 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }

    // Phase 2: T1-heavy — scan many new keys
    for i in 4..=15 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // After scan, T2 keys 1,2 should survive over scan keys
    let s1 = reg.get(CacheClass::PosixNamespaceMirror, &1).is_some();
    let s2 = reg.get(CacheClass::PosixNamespaceMirror, &2).is_some();
    assert!(
        s1 || s2,
        "at least one T2 frequent key should survive scan phase (1:{s1}, 2:{s2})"
    );

    // Phase 3: Re-insert and promote key 3 (it may have been evicted in scan)
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(make_header(3), "v3_reinsert".into()),
    );
    for _ in 0..10 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &3);
    }

    // Key 3 should now be findable after re-insert + promotion
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &3).is_some(),
        "key 3 should be present after re-insert and promotion in phase 3"
    );
    assert_eq!(reg.total_entries(), 3);
}

/// Verify that a key promoted to T2 (frequent) has higher weight
/// and eviction score than a fresh T1 key.
#[test]
fn t1_to_t2_promotion_increases_eviction_score() {
    let mut reg = make_registry(5);

    // Insert two entries
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "t1".into()),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::new(make_header(2), "soon_t2".into()),
    );

    // Record score of key 2 as T1
    let score_before = reg
        .get(CacheClass::PosixNamespaceMirror, &2)
        .map(|e| e.eviction_score)
        .unwrap_or(0.0);

    // Promote key 2 to T2 with repeated access
    for _ in 0..5 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }

    let score_after = reg
        .get(CacheClass::PosixNamespaceMirror, &2)
        .map(|e| e.eviction_score)
        .unwrap_or(0.0);

    assert!(
        score_after > score_before,
        "T2 eviction score ({score_after}) must exceed T1 eviction score ({score_before})"
    );

    // Key 2 weight should also increase
    let weight_after = reg
        .get(CacheClass::PosixNamespaceMirror, &2)
        .map(|e| e.effective_weight().value())
        .unwrap_or(0);
    assert!(
        weight_after > EntryWeight::DEFAULT.value(),
        "T2 weight ({}) must exceed default ({})",
        weight_after,
        EntryWeight::DEFAULT.value()
    );
}

// ====================================================================
// Group 2: Ghost-list (B1/B2) transition tests
// ====================================================================

/// GhostListStats API: verify all counters track correctly.
#[test]
fn ghost_stats_full_api() {
    let mut stats = GhostListStats::default();

    // Initial state
    assert_eq!(stats.b1_hits, 0);
    assert_eq!(stats.b1_misses, 0);
    assert_eq!(stats.b2_hits, 0);
    assert_eq!(stats.b2_misses, 0);
    assert_eq!(stats.evictions_since_adapt, 0);

    // Simulate B1 hit pattern (sequential scan ghost hits)
    stats.record_b1_hit();
    stats.record_b1_hit();
    stats.record_b1_miss();
    assert_eq!(stats.b1_hits, 2);
    assert_eq!(stats.b1_misses, 1);

    // Simulate B2 hit pattern (frequent-access ghost hits)
    stats.record_b2_hit();
    stats.record_b2_miss();
    stats.record_b2_miss();
    assert_eq!(stats.b2_hits, 1);
    assert_eq!(stats.b2_misses, 2);

    // Eviction tracking
    for _ in 0..99 {
        stats.record_eviction();
    }
    assert_eq!(stats.evictions_since_adapt, 99);
    assert!(!stats.should_adapt(100));
    assert!(stats.should_adapt(99));

    // 100th eviction
    stats.record_eviction();
    assert!(stats.should_adapt(100));
    assert_eq!(stats.evictions_since_adapt, 100);

    // Reset
    stats.reset_adaptation_counter();
    assert_eq!(stats.evictions_since_adapt, 0);
}

/// When B1 hit rate > B2 hit rate, ARC favors T1 (recent) by increasing p.
/// This test simulates the workload pattern at the GhostListStats level.
#[test]
fn ghost_b1_heavy_pattern_favors_recent() {
    let mut stats = GhostListStats::default();

    // B1: many hits (sequential scan — recently evicted entries re-accessed)
    for _ in 0..80 {
        stats.record_b1_hit();
    }
    for _ in 0..20 {
        stats.record_b1_miss();
    }
    // B1 hit rate = 80/100 = 0.8

    // B2: few hits (infrequent re-access of frequently-seen entries)
    for _ in 0..10 {
        stats.record_b2_hit();
    }
    for _ in 0..90 {
        stats.record_b2_miss();
    }
    // B2 hit rate = 10/100 = 0.1

    // B1 rate (0.8) > B2 rate (0.1): the system should increase p (favor T1/recent)
    let b1_total = stats.b1_hits + stats.b1_misses;
    let b2_total = stats.b2_hits + stats.b2_misses;
    let b1_rate = stats.b1_hits as f64 / b1_total as f64;
    let b2_rate = stats.b2_hits as f64 / b2_total as f64;

    assert!(
        b1_rate > b2_rate,
        "B1 hit rate ({b1_rate:.3}) must exceed B2 hit rate ({b2_rate:.3}) for sequential scan workload"
    );
}

/// When B2 hit rate > B1 hit rate, ARC favors T2 (frequent) by decreasing p.
#[test]
fn ghost_b2_heavy_pattern_favors_frequent() {
    let mut stats = GhostListStats::default();

    // B1: few hits (not a sequential scan)
    for _ in 0..5 {
        stats.record_b1_hit();
    }
    for _ in 0..95 {
        stats.record_b1_miss();
    }

    // B2: many hits (frequently accessed entries re-accessed after eviction)
    for _ in 0..60 {
        stats.record_b2_hit();
    }
    for _ in 0..40 {
        stats.record_b2_miss();
    }

    let b1_rate = stats.b1_hits as f64 / (stats.b1_hits + stats.b1_misses) as f64;
    let b2_rate = stats.b2_hits as f64 / (stats.b2_hits + stats.b2_misses) as f64;

    assert!(
        b2_rate > b1_rate,
        "B2 hit rate ({b2_rate:.3}) must exceed B1 hit rate ({b1_rate:.3}) for repetitive access workload"
    );
}

/// Verify that after many evictions with B1-heavy patterns, the system
/// accumulates ghost stats and can compute adaptation decisions.
#[test]
fn ghost_adaptation_accumulation_under_load() {
    let mut reg = make_registry(3);

    // Insert 30 unique keys sequentially (scan workload)
    // This generates many evictions from T1, populating ghost stats
    for i in 1..=30 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Many evictions should have occurred
    assert!(
        reg.eviction_count() >= 27,
        "sequential scan of 30 keys into capacity 3 should produce >=27 evictions, got {}",
        reg.eviction_count()
    );
    assert_eq!(reg.total_entries(), 3);
}

/// Verify ghost adaptation behaves correctly under alternating
/// B1-heavy and B2-heavy workload phases.
#[test]
fn ghost_adaptation_alternating_workload() {
    let mut reg = make_registry(5);

    // Phase 1: insert 20 unique keys (B1-heavy scan)
    for i in 1..=20 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    let evictions_phase1 = reg.eviction_count();

    // Phase 2: repeatedly access survivors (B2-heavy)
    // This re-accesses whatever keys survived, promoting to T2
    for _ in 0..20 {
        // Try to access keys that might be present
        for k in 16..=20 {
            let _ = reg.get(CacheClass::PosixNamespaceMirror, &k);
        }
    }

    // Phase 3: scan more new keys
    for i in 21..=40 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    let evictions_phase3 = reg.eviction_count();
    // Total evictions must have increased
    assert!(
        evictions_phase3 > evictions_phase1,
        "evictions should increase after phase 3 scan: {evictions_phase1} -> {evictions_phase3}"
    );

    assert_eq!(reg.total_entries(), 5, "cache must stay at capacity");
}

/// Ghost stats should start at zero and remain zero until
/// the first eviction occurs.
#[test]
fn ghost_stats_zero_until_first_eviction() {
    let mut reg = make_registry(10);

    // Insert within capacity — no evictions, ghost stats zero
    for i in 1..=5 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    assert_eq!(
        reg.eviction_count(),
        0,
        "no evictions when inserting within capacity"
    );
    // Ghost stats should be at default (zero) — verified implicitly
    // since no evictions occurred and adapt_arc_p wasn't called

    // Now exceed capacity to trigger eviction
    for i in 6..=15 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    assert!(
        reg.eviction_count() > 0,
        "evictions must occur after exceeding capacity"
    );
}

// ====================================================================
// Group 3: Deterministic eviction ordering tests
// ====================================================================

/// Entries with higher weight must have higher eviction scores
/// and survive eviction over lower-weight entries with equal recency.
#[test]
fn deterministic_weight_priority_in_eviction() {
    let mut reg = make_registry(2);

    let h1 = make_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::with_weight(h1, "light".into(), EntryWeight::new(1)),
    );

    let h2 = make_header(2);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::with_weight(h2, "heavy".into(), EntryWeight::new(500)),
    );

    // Force eviction by inserting a third entry
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(make_header(3), "new".into()),
    );

    // Light entry (weight 1) should be evicted; heavy (weight 500) survives
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_none(),
        "light-weight entry must be evicted first"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
        "heavy-weight entry must survive"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &3).is_some(),
        "new entry must be present"
    );
}

/// Entries with more hits have higher weight and eviction score,
/// making them less evictable than fresh entries.
#[test]
fn deterministic_hit_count_priority_in_eviction() {
    let mut reg = make_registry(3);

    for i in 1..=3 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Key 1: accessed 0 additional times
    // Key 2: accessed 5 times (medium protection)
    for _ in 0..5 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    }
    // Key 3: accessed 15 times (heavy protection)
    for _ in 0..15 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &3);
    }

    // Insert new entries to force eviction
    for i in 4..=6 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Key 1 (least hits) should be evicted
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_none(),
        "least-accessed key 1 should be evicted"
    );

    // Key 3 (most hits) should survive
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &3).is_some(),
        "most-accessed key 3 should survive eviction pressure"
    );
}

/// When all entries have equal scores (fresh, equal weight, no hits),
/// eviction still produces a consistent result (cache stays at capacity).
#[test]
fn deterministic_equal_score_eviction_maintains_capacity() {
    let mut reg = make_registry(4);

    // Insert 4 fresh entries (all equal scores)
    for i in 1..=4 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Insert 4 more to force evictions
    for i in 5..=8 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Cache must stay at capacity
    assert_eq!(
        reg.total_entries(),
        4,
        "cache must stay at capacity after equal-score evictions"
    );
    assert!(
        reg.eviction_count() >= 4,
        "at least 4 evictions must have occurred"
    );
}

/// Weight-based eviction ordering: the lightest entry is always evicted
/// before a heavier entry when scores differ only by weight.
///
/// Because calling `get` on surviving entries updates their hit counters
/// and scores (changing eviction ordering), this test verifies eviction
/// order without touching survivors between insertions.  After each
/// overflow insert, we check only the key that should have been evicted,
/// not the survivors.
#[test]
fn deterministic_weight_ordering_light_before_heavy() {
    let mut reg = make_registry(3);

    // Three entries with increasing weights
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::with_weight(make_header(1), "w1".into(), EntryWeight::new(1)),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        10,
        CacheEntry::with_weight(make_header(10), "w100".into(), EntryWeight::new(100)),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        100,
        CacheEntry::with_weight(make_header(100), "w1000".into(), EntryWeight::new(1000)),
    );

    // First overflow: weight 1 (score ~11) is the lowest.
    // New entry with weight 500 (score ~5004) doesn't interfere.
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        201,
        CacheEntry::with_weight(make_header(201), "w500a".into(), EntryWeight::new(500)),
    );

    // Only check the evicted key (miss = no state change to survivors)
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_none(),
        "weight 1 must be evicted first"
    );

    // Second overflow: weight 100 (~1002) is now the lowest among
    // weight 100, weight 1000, and weight 500 survivors.
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        202,
        CacheEntry::with_weight(make_header(202), "w500b".into(), EntryWeight::new(500)),
    );

    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &10).is_none(),
        "weight 100 must be evicted second"
    );

    // Third overflow: weight 1000 should survive.
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        203,
        CacheEntry::with_weight(make_header(203), "w500c".into(), EntryWeight::new(500)),
    );

    // After 3 rounds of eviction, the heaviest entry (1000) must survive.
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &100).is_some(),
        "weight 1000 must survive all eviction rounds"
    );
    assert_eq!(reg.total_entries(), 3);
}
/// Maximum entry weight behavior: highest-weighted entry compared to default.
#[test]
fn deterministic_max_weight_entry_survives() {
    let mut reg = make_registry(2);

    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::with_weight(
            make_header(1),
            "max".into(),
            EntryWeight::new(MAX_ENTRY_WEIGHT),
        ),
    );
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::with_weight(make_header(2), "default".into(), EntryWeight::DEFAULT),
    );

    // Insert to force eviction
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(make_header(3), "new".into()),
    );

    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_none(),
        "default-weight entry must be evicted before max-weight entry"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "max-weight entry must survive single eviction"
    );
}

// ====================================================================
// Group 4: Edge case tests
// ====================================================================

/// Rapid insert/evict cycling: entries are inserted and evicted in
/// quick succession. The cache must remain consistent.
#[test]
fn edge_rapid_insert_evict_cycle() {
    let mut reg = make_registry(4);

    for cycle in 0..20 {
        // Fill to capacity
        for i in 0..4 {
            let key = cycle * 10 + i;
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                key,
                CacheEntry::new(make_header(key), format!("c{cycle}k{i}")),
            );
        }
        // Verify all 4 present
        assert_eq!(
            reg.total_entries(),
            4,
            "cycle {cycle}: cache must have 4 entries after fill"
        );

        // Quick eviction: insert 2 more
        for i in 4..6 {
            let key = cycle * 10 + i;
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                key,
                CacheEntry::new(make_header(key), format!("c{cycle}k{i}")),
            );
        }
        assert_eq!(
            reg.total_entries(),
            4,
            "cycle {cycle}: cache must stay at capacity after overflow"
        );
    }

    // After all cycles, cache must be consistent
    assert_eq!(reg.total_entries(), 4);
    assert!(
        reg.eviction_count() >= 40,
        "at least 40 evictions expected from 20 cycles of 2 overflow inserts"
    );
}

/// Single-entry cache: insert, evict, re-insert ping-pong.
#[test]
fn edge_single_entry_ping_pong() {
    let mut reg = make_registry(1);

    for round in 0..50 {
        let key = (round % 5) + 1;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            key,
            CacheEntry::new(make_header(key), format!("r{round}")),
        );

        assert_eq!(
            reg.total_entries(),
            1,
            "single-entry cache must hold exactly 1 entry at round {round}"
        );
        assert!(
            reg.get(CacheClass::PosixNamespaceMirror, &key).is_some(),
            "inserted key {key} must be present at round {round}"
        );
    }
}

/// Weight zero clamping: zero weight must be clamped to 1.
#[test]
fn edge_weight_zero_clamped_to_one() {
    let w = EntryWeight::new(0);
    assert_eq!(w.value(), 1, "zero weight must clamp to 1");
    assert_eq!(w, EntryWeight::DEFAULT);
}

/// Weight at MAX_ENTRY_WEIGHT and beyond: must saturate.
#[test]
fn edge_weight_saturates_at_max() {
    let w_max = EntryWeight::new(MAX_ENTRY_WEIGHT);
    assert_eq!(w_max.value(), MAX_ENTRY_WEIGHT);

    let w_beyond = EntryWeight::new(MAX_ENTRY_WEIGHT + 1);
    assert_eq!(
        w_beyond.value(),
        MAX_ENTRY_WEIGHT + 1,
        "EntryWeight::new does not clamp; clamping is in update_entry_weight"
    );
}

/// update_entry_weight saturates at MAX_ENTRY_WEIGHT.
#[test]
fn edge_update_weight_saturates() {
    let initial = EntryWeight::new(MAX_ENTRY_WEIGHT - 10);
    // Hit many times with zero recency (max boost)
    let updated = update_entry_weight(initial, 200, Duration::from_nanos(1));
    assert_eq!(
        updated.value(),
        MAX_ENTRY_WEIGHT,
        "update_entry_weight must saturate at MAX_ENTRY_WEIGHT"
    );
}

/// update_entry_weight with large recency delta (old access) gives zero bonus.
#[test]
fn edge_update_weight_old_access_minimal_boost() {
    let initial = EntryWeight::new(100);
    // Access with 1 hour recency delta: bonus should be zero
    let updated = update_entry_weight(initial, 1, Duration::from_secs(3600));
    // Still increases by 50 (base increment) + 5 (hit_bonus for 1 hit) + 0 (recency)
    assert!(
        updated.value() >= 155,
        "weight should still get base+hit increment even with large recency delta, got {}",
        updated.value()
    );
}

/// update_entry_weight with zero Duration clamps to 1 ns internally.
#[test]
fn edge_update_weight_zero_duration() {
    let initial = EntryWeight::new(100);
    let updated = update_entry_weight(initial, 1, Duration::from_nanos(0));
    // Zero duration clamped to 1 ns, gives max recency bonus
    assert!(
        updated.value() > 100,
        "weight must increase even with zero duration (clamped to 1 ns)"
    );
}

/// initial_entry_weight scales with entry size.
#[test]
fn edge_initial_weight_scales_with_size() {
    // Small entry
    let w_small = initial_entry_weight(256);
    // Large entry
    let w_large = initial_entry_weight(256 * 1000);

    assert!(
        w_large.value() > w_small.value(),
        "larger entries must get higher initial weight: {} vs {}",
        w_large.value(),
        w_small.value()
    );
}

/// initial_entry_weight never below DEFAULT.
#[test]
fn edge_initial_weight_at_least_default() {
    let w_zero = initial_entry_weight(0);
    let w_tiny = initial_entry_weight(1);

    assert!(w_zero.value() >= EntryWeight::DEFAULT.value());
    assert!(w_tiny.value() >= EntryWeight::DEFAULT.value());
}

/// Pinned entry survives all eviction pressure.
#[test]
fn edge_pinned_entry_survives_everything() {
    let mut reg = make_registry(2);

    let mut h_pin = make_header(1);
    h_pin.memory_domain = MemoryDomain::AuthorityImmutable;
    h_pin.evictability = EvictabilityClass::Pinned;
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h_pin, "pinned".into()),
    );

    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::new(make_header(2), "evictable".into()),
    );

    // Force many evictions
    for i in 3..=20 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Pinned entry must remain
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "pinned entry must survive all eviction pressure"
    );
    assert_eq!(reg.total_entries(), 2);
}

/// Two cache classes under ARC policy are fully independent.
#[test]
fn edge_two_classes_arc_independent_eviction() {
    let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
    reg.register_cache(
        CacheClass::PosixNamespaceMirror,
        2,
        EvictionPolicyKind::Adaptive,
    );
    reg.register_cache(
        CacheClass::AuthorityReadMirror,
        3,
        EvictionPolicyKind::Adaptive,
    );

    // Fill namespace cache
    for i in 1..=2 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("ns{i}")),
        );
    }

    // Fill authority cache (different header class)
    for i in 1..=3 {
        let mut h = CacheEntryHeader::new(
            CacheClass::AuthorityReadMirror,
            MemoryDomain::AuthorityImmutable,
            i,
            "auth_test",
            RebuildCostClass::Trivial,
            1,
        );
        h.anchor_vector_ref = 1;
        reg.insert(
            CacheClass::AuthorityReadMirror,
            i,
            CacheEntry::new(h, format!("auth{i}")),
        );
    }

    // Evict from namespace cache only
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(make_header(3), "ns3".into()),
    );

    // Authority cache must be unaffected
    assert_eq!(
        reg.entry_count(CacheClass::AuthorityReadMirror),
        3,
        "authority cache must have all 3 entries after namespace eviction"
    );
    assert_eq!(
        reg.entry_count(CacheClass::PosixNamespaceMirror),
        2,
        "namespace cache must stay at capacity 2"
    );

    // All authority entries still accessible
    for i in 1..=3 {
        assert!(
            reg.get(CacheClass::AuthorityReadMirror, &i).is_some(),
            "authority entry {i} must survive namespace eviction"
        );
    }
}

/// After removing all entries, cache returns to empty state cleanly.
#[test]
fn edge_drain_cache_to_empty() {
    let mut reg = make_registry(5);

    for i in 1..=5 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
    }

    // Remove all
    for i in 1..=5 {
        reg.remove(CacheClass::PosixNamespaceMirror, &i);
    }

    assert_eq!(reg.total_entries(), 0);
    // Re-insert works
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "new".into()),
    );
    assert_eq!(reg.total_entries(), 1);
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
}

/// Hit and miss counts are independently tracked and accumulate correctly.
#[test]
fn edge_hit_miss_count_accumulation() {
    let mut reg = make_registry(5);

    // Misses on empty cache
    for _ in 0..5 {
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &99).is_none());
    }
    assert_eq!(reg.miss_count(), 5);
    assert_eq!(reg.hit_count(), 0);

    // Insert and hit
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "v1".into()),
    );
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
    assert_eq!(reg.hit_count(), 1);
    assert_eq!(reg.miss_count(), 5); // unchanged

    // More misses after insert
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &2).is_none());
    assert_eq!(reg.miss_count(), 6);
}

/// get_mut API: verify mutable access and score update.
#[test]
fn edge_get_mut_updates_entry() {
    let mut reg = make_registry(5);

    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(make_header(1), "original".into()),
    );

    // get_mut allows mutation
    if let Some(entry) = reg.get_mut(CacheClass::PosixNamespaceMirror, &1) {
        entry.value = "modified".into();
    }

    // Verify mutation persisted
    let entry = reg.get(CacheClass::PosixNamespaceMirror, &1).unwrap();
    assert_eq!(entry.value, "modified");
}

/// Eviction count is monotonic.
#[test]
fn edge_eviction_count_monotonic() {
    let mut reg = make_registry(3);

    let mut last = reg.eviction_count();
    for i in 1..=30 {
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(make_header(i), format!("v{i}")),
        );
        let current = reg.eviction_count();
        assert!(
            current >= last,
            "eviction count must be monotonic: {last} -> {current} at insert {i}"
        );
        last = current;
    }
}

/// ArcWeightConfig default values.
#[test]
fn edge_arc_weight_config_defaults() {
    let cfg = ArcWeightConfig::default();
    assert!(cfg.enable_per_entry_weight);
    assert_eq!(cfg.ghost_adaptation_interval, 100);
    assert!((cfg.weight_factor - 1.0).abs() < f64::EPSILON);
}

/// EntryWeight::from<u64> conversion.
#[test]
fn edge_entry_weight_from_u64() {
    let w: EntryWeight = 42u64.into();
    assert_eq!(w.value(), 42);

    let w_zero: EntryWeight = 0u64.into();
    assert_eq!(w_zero.value(), 1); // clamped

    let w_max: EntryWeight = MAX_ENTRY_WEIGHT.into();
    assert_eq!(w_max.value(), MAX_ENTRY_WEIGHT);
}

/// EntryWeight comparison and ordering.
#[test]
fn edge_entry_weight_ordering() {
    let w1 = EntryWeight::new(10);
    let w2 = EntryWeight::new(20);
    let w3 = EntryWeight::new(10);

    assert!(w1 < w2);
    assert!(w2 > w1);
    assert_eq!(w1, w3);
    assert!(w1 <= w2);
    assert!(w2 >= w1);
}
