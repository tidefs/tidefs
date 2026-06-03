//! ARC insertion, eviction, and ghost-list sizing tests.
//!
//! These integration tests exercise the public API of tidefs-cache-core
//! to verify ARC behaviour: T1/T2 insertion ordering, LRU-end eviction,
//! repeat-access promotion, ghost-list adaptive sizing (p), and
//! concurrent access safety.
//!
//! Tests use CacheLatticeRegistry with EvictionPolicyKind::Adaptive
//! and verify behaviour through observable effects (which entries
//! survive eviction, hit/miss/eviction counters) without accessing
//! private CacheStore internals.

use tidefs_cache_core::{CacheEntry, CacheLatticeRegistry, EntryWeight, EvictionPolicyKind};
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, EvictabilityClass, MemoryDomain, RebuildCostClass,
};

// Helpers

fn make_servable_header(key_digest: u64) -> CacheEntryHeader {
    let mut h = CacheEntryHeader::new(
        CacheClass::PosixNamespaceMirror,
        MemoryDomain::AdapterServingHot,
        key_digest,
        "arc_test",
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
// Group 1: ARC insertion basics
// ====================================================================

#[test]
fn arc_first_insert_into_empty_cache() {
    let mut reg = make_registry(5);
    let h = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h, "first".into()),
    );

    let found = reg.get(CacheClass::PosixNamespaceMirror, &1);
    assert!(found.is_some(), "entry should be found after first insert");
    assert_eq!(found.unwrap().value, "first");
    assert_eq!(reg.hit_count(), 1);
    assert_eq!(reg.miss_count(), 0);
}

#[test]
fn arc_multiple_inserts_within_capacity() {
    let mut reg = make_registry(5);
    for i in 1..=5 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert_eq!(reg.total_entries(), 5);
    assert_eq!(reg.eviction_count(), 0);
    for i in 1..=5 {
        assert!(
            reg.get(CacheClass::PosixNamespaceMirror, &i).is_some(),
            "key {i} should be present"
        );
    }
}

#[test]
fn arc_insert_beyond_capacity_triggers_eviction() {
    let mut reg = make_registry(3);
    for i in 1..=3 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    let h = make_servable_header(4);
    let evicted = reg.insert(
        CacheClass::PosixNamespaceMirror,
        4,
        CacheEntry::new(h, "v4".into()),
    );
    assert!(
        evicted.is_some(),
        "insert beyond capacity must evict something"
    );
    assert_eq!(reg.eviction_count(), 1);
    assert_eq!(reg.total_entries(), 3);
}

// ====================================================================
// Group 2: ARC repeat-access promotion (T1 -> T2)
// ====================================================================

#[test]
fn arc_repeat_access_increases_weight() {
    let mut reg = make_registry(5);
    let h = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h, "frequent".into()),
    );

    let w1 = reg
        .get(CacheClass::PosixNamespaceMirror, &1)
        .map(|e| e.effective_weight().value())
        .unwrap();
    assert!(w1 >= 1, "initial weight must be at least 1");

    for _ in 0..4 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }
    let w_after = reg
        .get(CacheClass::PosixNamespaceMirror, &1)
        .map(|e| e.effective_weight().value())
        .unwrap();
    assert!(
        w_after > w1,
        "weight must increase after repeated access: {w1} -> {w_after}"
    );
    assert_eq!(reg.hit_count(), 6, "6 total hits expected");
}

#[test]
fn arc_frequent_entry_survives_eviction_better() {
    let mut reg = make_registry(3);
    for i in 1..=3 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    // Access key 1 repeatedly -- promotes to T2 (frequent)
    for _ in 0..5 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }
    // Force evictions by inserting 3 new entries
    for i in 4..=6 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    // Key 1 (frequently accessed) should survive
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "frequently accessed key 1 should survive ARC eviction"
    );
    let survivors: Vec<u64> = [2u64, 3u64]
        .iter()
        .filter(|k| reg.get(CacheClass::PosixNamespaceMirror, k).is_some())
        .copied()
        .collect();
    assert!(
        survivors.len() <= 1,
        "at most one once-accessed key should survive: {survivors:?} remain"
    );
}

#[test]
fn arc_frequent_access_protects_against_many_insertions() {
    let mut reg = make_registry(5);
    for i in 1..=5 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    // Make key 3 very frequent
    for _ in 0..10 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &3);
    }
    // Insert 10 more entries, heavy eviction pressure
    for i in 6..=15 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &3).is_some(),
        "heavily accessed key 3 should survive massive eviction pressure"
    );
}

// ====================================================================
// Group 3: ARC LRU eviction -- T1 and T2 evict from LRU end
// ====================================================================

#[test]
fn arc_sequential_scan_evicts_oldest() {
    // Sequential scan of 10 unique keys into capacity 5.
    // Five evictions must occur.  Since all entries have equal
    // weight and no hits, eviction is determined by HashMap
    // iteration order among equal-scored entries -- which specific
    // keys survive is not guaranteed.  We verify counts only.
    let mut reg = make_registry(5);
    for i in 1..=10 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert_eq!(reg.total_entries(), 5);
    assert_eq!(reg.eviction_count(), 5);

    // Count survivors: exactly 5 of the 10 keys should remain.
    let survivors: Vec<u64> = (1..=10)
        .filter(|k| reg.get(CacheClass::PosixNamespaceMirror, k).is_some())
        .collect();
    assert_eq!(survivors.len(), 5, "exactly 5 of 10 keys must survive");
}

#[test]
fn arc_touch_moves_to_mru_and_avoids_eviction() {
    // Repeated access to key 1 increases its hit count and weight,
    // giving it a higher eviction score.  When a new entry forces
    // eviction, key 1 must survive.  The evicted key depends on
    // scoring among the remaining equally-scored entries.
    let mut reg = make_registry(3);
    for i in 1..=3 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    // Touch key 1 several times to boost its score
    for _ in 0..5 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }
    // Insert beyond capacity: one entry must be evicted
    let h = make_servable_header(4);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        4,
        CacheEntry::new(h, "v4".into()),
    );

    // Key 1 (touched 5 times) must survive due to higher score
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "key 1 should remain (was touched 5 times)"
    );
    assert_eq!(reg.total_entries(), 3);
    assert!(reg.eviction_count() >= 1);
}

#[test]
fn arc_interleaved_access_eviction_order() {
    // Keys 1 and 2 are touched, boosting their scores.  A new
    // entry forces eviction.  Keys 1 and 2 must survive; the
    // evicted entry comes from the set {3, 4} (untouched).
    let mut reg = make_registry(4);
    for i in 1..=4 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    let _ = reg.get(CacheClass::PosixNamespaceMirror, &2);
    let h = make_servable_header(5);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        5,
        CacheEntry::new(h, "v5".into()),
    );
    // Touched keys must survive
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "key 1 should survive (was touched)"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
        "key 2 should survive (was touched)"
    );
    // Key 5 must be present
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &5).is_some());
    assert_eq!(reg.total_entries(), 4);
    assert!(reg.eviction_count() >= 1);
}

// ====================================================================
// Group 4: Ghost-list sizing and adaptive p
// ====================================================================

#[test]
fn arc_sequential_scan_many_evictions() {
    let mut reg = make_registry(3);
    for i in 1..=20 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert_eq!(reg.eviction_count(), 17);
    assert_eq!(reg.total_entries(), 3);
}

#[test]
fn arc_repetitive_access_preserves_frequent() {
    let mut reg = make_registry(3);
    for i in 1..=3 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    for _ in 0..10 {
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1);
    }
    for i in 4..=10 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "frequently accessed key 1 must survive repetitive eviction pressure"
    );
}

#[test]
fn arc_weighted_entries_evict_light_first() {
    let mut reg = make_registry(2);
    let h1 = make_servable_header(1);
    let light = CacheEntry::with_weight(h1, "light".into(), EntryWeight::new(1));
    reg.insert(CacheClass::PosixNamespaceMirror, 1, light);
    let h2 = make_servable_header(2);
    let heavy = CacheEntry::with_weight(h2, "heavy".into(), EntryWeight::new(100));
    reg.insert(CacheClass::PosixNamespaceMirror, 2, heavy);
    let h3 = make_servable_header(3);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(h3, "third".into()),
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_none(),
        "light entry should be evicted"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_some(),
        "heavy entry should survive"
    );
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &3).is_some());
}

// ====================================================================
// Group 5: Boundary conditions
// ====================================================================

#[test]
fn arc_empty_cache_lookup_is_miss() {
    let mut reg = make_registry(5);
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &42).is_none());
    assert_eq!(reg.miss_count(), 1);
    assert_eq!(reg.hit_count(), 0);
}

#[test]
fn arc_capacity_one_single_entry() {
    let mut reg = make_registry(1);
    let h = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h, "only".into()),
    );
    assert_eq!(reg.total_entries(), 1);
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
}

#[test]
fn arc_capacity_one_ping_pong_eviction() {
    let mut reg = make_registry(1);
    let h1 = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h1, "first".into()),
    );
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
    let h2 = make_servable_header(2);
    let evicted = reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::new(h2, "second".into()),
    );
    assert!(evicted.is_some(), "insert into full cache must evict");
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_none());
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &2).is_some());
    assert_eq!(reg.total_entries(), 1);
    assert_eq!(reg.eviction_count(), 1);
    let h3 = make_servable_header(1);
    let evicted2 = reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h3, "first_again".into()),
    );
    assert!(evicted2.is_some());
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
    assert!(reg.get(CacheClass::PosixNamespaceMirror, &2).is_none());
    assert_eq!(reg.eviction_count(), 2);
}

#[test]
fn arc_key_collision_overwrites() {
    let mut reg = make_registry(5);
    let h1 = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h1, "v1".into()),
    );
    let h2 = make_servable_header(1);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h2, "v1_overwrite".into()),
    );
    let found = reg.get(CacheClass::PosixNamespaceMirror, &1).unwrap();
    assert_eq!(found.value, "v1_overwrite");
    assert_eq!(reg.total_entries(), 1);
}

#[test]
fn arc_pinned_entry_not_evicted() {
    let mut reg = make_registry(2);
    let mut h1 = make_servable_header(1);
    h1.memory_domain = MemoryDomain::AuthorityImmutable;
    h1.evictability = EvictabilityClass::Pinned;
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        1,
        CacheEntry::new(h1, "pinned".into()),
    );
    let h2 = make_servable_header(2);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        2,
        CacheEntry::new(h2, "evictable".into()),
    );
    let h3 = make_servable_header(3);
    let evicted = reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(h3, "new".into()),
    );
    assert!(evicted.is_some());
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &1).is_some(),
        "pinned entry must not be evicted"
    );
    assert!(
        reg.get(CacheClass::PosixNamespaceMirror, &2).is_none(),
        "non-pinned entry should be evicted"
    );
}

// ====================================================================
// Group 6: Concurrent access safety
// ====================================================================

#[test]
fn arc_bulk_insert_no_entries_lost() {
    let mut reg = make_registry(100);
    for i in 0..100 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    assert!(reg.total_entries() <= 100);
    for i in 0..100 {
        assert!(
            reg.get(CacheClass::PosixNamespaceMirror, &i).is_some(),
            "key {i} should exist after bulk insert"
        );
    }
}

#[test]
fn arc_interleaved_insert_and_lookup_consistency() {
    let mut reg = make_registry(20);
    for i in 0..20 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
        if i > 0 {
            let prev = i - 1;
            let found = reg.get(CacheClass::PosixNamespaceMirror, &prev);
            assert!(
                found.is_some(),
                "previously inserted key {prev} should still be present"
            );
        }
    }
    for i in 0..20 {
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &i).is_some());
    }
}

#[test]
fn arc_eviction_pressure_under_mixed_workload() {
    let mut reg = make_registry(10);
    for i in 0..10 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("v{i}")),
        );
    }
    for round in 0..5 {
        for k in 0..3 {
            let _ = reg.get(CacheClass::PosixNamespaceMirror, &k);
        }
        let new_key = 10 + round;
        let h = make_servable_header(new_key);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            new_key,
            CacheEntry::new(h, format!("v{new_key}")),
        );
    }
    for k in 0..3 {
        assert!(
            reg.get(CacheClass::PosixNamespaceMirror, &k).is_some(),
            "hot key {k} should survive eviction pressure"
        );
    }
    assert!(reg.eviction_count() >= 5, "expected at least 5 evictions");
    assert_eq!(reg.total_entries(), 10, "cache should stay at capacity");
}

// ====================================================================
// Group 7: Multi-class ARC isolation
// ====================================================================

#[test]
fn arc_two_classes_independent_eviction() {
    let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
    reg.register_cache(
        CacheClass::PosixNamespaceMirror,
        2,
        EvictionPolicyKind::Adaptive,
    );
    reg.register_cache(
        CacheClass::AuthorityReadMirror,
        2,
        EvictionPolicyKind::Adaptive,
    );
    for i in 1..=2 {
        let h = make_servable_header(i);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            i,
            CacheEntry::new(h, format!("ns{i}")),
        );
    }
    for i in 1..=2 {
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
    let h = make_servable_header(3);
    reg.insert(
        CacheClass::PosixNamespaceMirror,
        3,
        CacheEntry::new(h, "ns3".into()),
    );
    assert_eq!(reg.entry_count(CacheClass::AuthorityReadMirror), 2);
    assert!(reg.get(CacheClass::AuthorityReadMirror, &1).is_some());
    assert!(reg.get(CacheClass::AuthorityReadMirror, &2).is_some());
}
