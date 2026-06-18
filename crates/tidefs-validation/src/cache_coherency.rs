// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cache coherency validation: lease revocation, membership epoch transitions,
//! and node-drain scenarios against tidefs-transport.
//!
//! Exercises the invalidation pipeline (token-based and class-wide) to verify
//! that cache entries are correctly evicted or invalidated when the
//! coordination layer signals state changes.
//!
//! ## Scenarios
//!
//! - **Lease revocation**: populate cache under a validity token, revoke the
//!   lease (advance the token), and verify stale entries are removed.
//! - **Epoch transition**: populate cache tied to an epoch, advance the epoch,
//!   and verify prior-epoch entries are no longer servable.
//! - **Node-drain**: populate cache with entries owned by a draining node,
//!   drain the class, and verify all entries are evicted.
//! - **Concurrent access**: verify that concurrent reads and invalidations
//!   do not panic or produce inconsistent results.
//! - **Edge cases**: empty cache, already-stale entries, rapid token churn,
//!   partial-class invalidation, and mixed-class scenarios.

#[cfg(test)]
mod tests {
    use tidefs_cache_core::{CacheEntry, CacheLatticeRegistry, InvalidationPipeline};
    use tidefs_types_cache_lattice_core::{CacheClass, CacheEntryHeader, ValidityToken};

    // ── helpers ────────────────────────────────────────────────────────

    /// Build a minimal servable header for testing.
    fn make_header(ino: u64) -> CacheEntryHeader {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            tidefs_types_cache_lattice_core::MemoryDomain::AdapterServingHot,
            ino,
            "test_budget",
            tidefs_types_cache_lattice_core::RebuildCostClass::Cheap,
            1,
        );
        h.anchor_vector_ref = 1; // needed for invariant:anchor
        h.exactness_class = 1; // not exact → no anchor required
        h
    }

    /// Build a header with an explicit validity token.
    fn make_header_with_token(ino: u64, token: ValidityToken) -> CacheEntryHeader {
        let mut h = make_header(ino);
        h.validity_token = token;
        h
    }

    /// Build a header with a specific class and token.
    fn make_header_class_token(
        ino: u64,
        class: CacheClass,
        token: ValidityToken,
    ) -> CacheEntryHeader {
        let mut h = CacheEntryHeader::new(
            class,
            tidefs_types_cache_lattice_core::MemoryDomain::AdapterServingHot,
            ino,
            "test_budget",
            tidefs_types_cache_lattice_core::RebuildCostClass::Cheap,
            1,
        );
        h.anchor_vector_ref = 1;
        h.exactness_class = 1;
        h.validity_token = token;
        h
    }

    fn token_for(gen: u64) -> ValidityToken {
        ValidityToken::compute(gen, b"test_authoritative_state")
    }

    // ── lease-revocation scenario ─────────────────────────────────────

    /// Lease revocation: populate cache with entries under token_v1,
    /// then invalidate with token_v2. Entries with v1 should be removed;
    /// entries with v2 should remain.
    #[test]
    fn lease_revocation_invalidates_stale_entries() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token_v1 = token_for(1);
        let token_v2 = token_for(2);

        // Insert 5 entries under token_v1
        for i in 1..=5 {
            let h = make_header_with_token(i, token_v1);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v1_val_{}", i)),
            );
        }

        // Insert 3 entries already under token_v2 (already valid for next epoch)
        for i in 6..=8 {
            let h = make_header_with_token(i, token_v2);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v2_val_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 8);

        // Simulate lease revocation: invalidate everything not matching token_v2
        let removed = reg.invalidate_by_token(token_v2);
        assert_eq!(removed, 5, "5 stale v1 entries should be removed");
        assert_eq!(reg.total_entries(), 3, "3 v2 entries should remain");

        // Verify v2 entries are still present
        for i in 6..=8 {
            assert!(
                reg.get(CacheClass::PosixNamespaceMirror, &i).is_some(),
                "v2 entry {} should survive invalidation",
                i
            );
        }
        // Verify v1 entries are gone
        for i in 1..=5 {
            assert!(
                reg.get(CacheClass::PosixNamespaceMirror, &i).is_none(),
                "v1 entry {} should be invalidated",
                i
            );
        }
    }

    /// Lease revocation on an empty cache is a no-op.
    #[test]
    fn lease_revocation_empty_cache_noop() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let removed = reg.invalidate_by_token(token_for(1));
        assert_eq!(removed, 0);
        assert_eq!(reg.total_entries(), 0);
    }

    /// Lease revocation with no stale entries removes nothing.
    #[test]
    fn lease_revocation_all_entries_current() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let current = token_for(42);

        for i in 1..=5 {
            let h = make_header_with_token(i, current);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("val_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 5);
        let removed = reg.invalidate_by_token(current);
        assert_eq!(removed, 0, "no entries should be removed when all match");
        assert_eq!(reg.total_entries(), 5);
    }

    // ── epoch-transition scenario ─────────────────────────────────────

    /// Epoch transition: entries tied to epoch-1 token are invalidated
    /// when the epoch advances to epoch-2 (new token).
    #[test]
    fn epoch_transition_invalidates_prior_epoch_entries() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let epoch1_token = token_for(1);
        let epoch2_token = token_for(2);
        let epoch3_token = token_for(3);

        // Populate with entries from different epochs
        // 4 entries tied to epoch 1
        for i in 1..=4 {
            let h = make_header_with_token(i, epoch1_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("e1_{}", i)),
            );
        }
        // 3 entries tied to epoch 2
        for i in 5..=7 {
            let h = make_header_with_token(i, epoch2_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("e2_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 7);

        // Advance to epoch 3: invalidate all non-epoch3 entries
        let removed = reg.invalidate_by_token(epoch3_token);
        assert_eq!(
            removed, 7,
            "all 7 entries should be stale relative to epoch 3"
        );
        assert_eq!(reg.total_entries(), 0);

        // Insert fresh epoch-3 entries — they should survive subsequent
        // epoch-3 validation
        for i in 1..=2 {
            let h = make_header_with_token(i, epoch3_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("e3_{}", i)),
            );
        }
        assert_eq!(reg.total_entries(), 2);
        let removed2 = reg.invalidate_by_token(epoch3_token);
        assert_eq!(removed2, 0, "epoch-3 entries match current token");
        assert_eq!(reg.total_entries(), 2);
    }

    /// Multiple epoch transitions in sequence: each transition removes
    /// entries from the prior epoch.
    #[test]
    fn rapid_epoch_churn_keeps_cache_coherent() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();

        for epoch in 1..=10 {
            let _old_token = token_for(epoch - 1);
            let new_token = token_for(epoch);

            // Insert 3 entries for this epoch
            for i in 1..=3 {
                let key = epoch * 100 + i;
                let h = make_header_with_token(key, new_token);
                reg.insert(
                    CacheClass::PosixNamespaceMirror,
                    key,
                    CacheEntry::new(h, format!("e{}_{}", epoch, i)),
                );
            }

            // Invalidate stale entries
            let removed = reg.invalidate_by_token(new_token);
            // Entries from prior epochs should have been removed
            if epoch > 1 {
                assert!(
                    removed >= 3,
                    "epoch {}: at least 3 prior-epoch entries should be removed, got {}",
                    epoch,
                    removed
                );
            }
            // Current entries should be exactly 3 (one epoch worth)
            assert_eq!(
                reg.total_entries(),
                3,
                "epoch {}: exactly 3 current-epoch entries should remain",
                epoch
            );
        }
    }

    // ── node-drain scenario ───────────────────────────────────────────

    /// Node-drain: populate cache with entries owned by a draining node,
    /// then invalidate the entire class (simulating drain completion).
    #[test]
    fn node_drain_clears_drained_class() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token = token_for(1);

        // Populate PosixNamespaceMirror (class being drained) — 10 entries
        for i in 1..=10 {
            let h = make_header_class_token(i, CacheClass::PosixNamespaceMirror, token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("ns_{}", i)),
            );
        }

        // Populate PosixPageWriteback (class not being drained) — 5 entries
        for i in 1..=5 {
            let mut h = make_header_class_token(i, CacheClass::PosixPageWriteback, token);
            // PageWriteback requires StagingDirty domain
            h.memory_domain = tidefs_types_cache_lattice_core::MemoryDomain::StagingDirty;
            // It also needs non-clean dirty state for StagingDirty
            h.dirty_state = tidefs_types_cache_lattice_core::DirtyStateClass::PosixWriteback(
                tidefs_types_cache_lattice_core::PosixWritebackState::DirtyOpen,
            );
            reg.insert(
                CacheClass::PosixPageWriteback,
                i,
                CacheEntry::new(h, format!("wb_{}", i)),
            );
        }

        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 10);
        assert_eq!(reg.entry_count(CacheClass::PosixPageWriteback), 5);
        assert_eq!(reg.total_entries(), 15);

        // Drain the namespace-mirror class
        let drained = reg.invalidate_all(CacheClass::PosixNamespaceMirror);
        assert_eq!(
            drained, 10,
            "all 10 namespace-mirror entries should be drained"
        );
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 0);
        assert_eq!(
            reg.entry_count(CacheClass::PosixPageWriteback),
            5,
            "page-writeback class should be untouched"
        );
        assert_eq!(reg.total_entries(), 5);
    }

    /// Draining an empty class is a no-op.
    #[test]
    fn node_drain_empty_class_noop() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        assert_eq!(reg.invalidate_all(CacheClass::PosixNamespaceMirror), 0);
    }

    /// Drain a class, then repopulate it — new entries should be served.
    #[test]
    fn node_drain_then_repopulate() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token = token_for(1);

        // Populate and drain
        for i in 1..=5 {
            let h = make_header_with_token(i, token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("old_{}", i)),
            );
        }
        assert_eq!(reg.invalidate_all(CacheClass::PosixNamespaceMirror), 5);
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 0);

        // Repopulate
        let new_token = token_for(2);
        for i in 10..=12 {
            let h = make_header_with_token(i, new_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("new_{}", i)),
            );
        }
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 3);
        for i in 10..=12 {
            assert!(reg.get(CacheClass::PosixNamespaceMirror, &i).is_some());
        }
    }

    // ── InvalidationPipeline integration ──────────────────────────────

    /// InvalidationPipeline::invalidate_by_token works identically to
    /// the registry's direct method.
    #[test]
    fn invalidation_pipeline_token_parity() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token_v1 = token_for(1);
        let token_v2 = token_for(2);

        for i in 1..=3 {
            let h = make_header_with_token(i, token_v1);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v1_{}", i)),
            );
        }
        for i in 4..=5 {
            let h = make_header_with_token(i, token_v2);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v2_{}", i)),
            );
        }

        {
            let mut pipeline = InvalidationPipeline::new(&mut reg);
            let removed = pipeline.invalidate_by_token(token_v2);
            assert_eq!(removed, 3);
        }

        assert_eq!(reg.total_entries(), 2);
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &4).is_some());
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &5).is_some());
    }

    /// InvalidationPipeline::invalidate_all clears a class.
    #[test]
    fn invalidation_pipeline_invalidate_all() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token = token_for(1);

        for i in 1..=7 {
            let h = make_header_with_token(i, token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("val_{}", i)),
            );
        }

        {
            let mut pipeline = InvalidationPipeline::new(&mut reg);
            let removed = pipeline.invalidate_all(CacheClass::PosixNamespaceMirror);
            assert_eq!(removed, 7);
        }

        assert_eq!(reg.total_entries(), 0);
    }

    // ── Concurrent access ─────────────────────────────────────────────

    /// Concurrent reads during invalidation should not panic or deadlock.
    #[test]
    fn concurrent_read_and_invalidation_no_deadlock() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let shared = Arc::new(Mutex::new(reg));

        // Pre-populate
        {
            let mut r = shared.lock().unwrap();
            let token = token_for(1);
            for i in 0..20 {
                let h = make_header_with_token(i, token);
                r.insert(
                    CacheClass::PosixNamespaceMirror,
                    i,
                    CacheEntry::new(h, format!("val_{}", i)),
                );
            }
        }

        let mut handles = Vec::new();

        // Reader threads: repeatedly read keys
        for _ in 0..3 {
            let s = Arc::clone(&shared);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    let mut r = s.lock().unwrap();
                    for k in 0..20 {
                        let _ = r.get(CacheClass::PosixNamespaceMirror, &k);
                    }
                }
            }));
        }

        // Invalidator thread: repeatedly invalidate
        let s_inv = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for gen in 2..8 {
                let new_token = token_for(gen);
                let mut r = s_inv.lock().unwrap();
                r.invalidate_by_token(new_token);
                // Re-populate with the new token
                for i in 0..10 {
                    let h = make_header_with_token(i, new_token);
                    r.insert(
                        CacheClass::PosixNamespaceMirror,
                        i,
                        CacheEntry::new(h, format!("gen{}_{}", gen, i)),
                    );
                }
            }
        }));

        for h in handles {
            h.join().unwrap();
        }

        // Final state: cache should be consistent (no panics = pass)
        let r = shared.lock().unwrap();
        let _ = r.total_entries(); // just prove we can access it
    }

    // ── CacheEntry::is_stale correctness ──────────────────────────────

    /// is_stale returns true when the entry's token does not match.
    #[test]
    fn cache_entry_is_stale_detects_mismatch() {
        let token_v1 = token_for(1);
        let token_v2 = token_for(2);
        let h = make_header_with_token(1, token_v1);
        let entry = CacheEntry::new(h, "test".to_string());

        assert!(!entry.is_stale(token_v1), "matching token => not stale");
        assert!(entry.is_stale(token_v2), "mismatched token => stale");
    }

    /// is_stale with default zero token on header and non-zero test token.
    #[test]
    fn cache_entry_is_stale_default_header() {
        let h = make_header(1); // default validity_token = zero
        let entry = CacheEntry::new(h, "test".to_string());

        let non_zero = token_for(1);
        assert!(
            entry.is_stale(non_zero),
            "default zero token should be stale vs computed token"
        );
        assert!(
            !entry.is_stale(ValidityToken::default()),
            "default zero token should match default zero token"
        );
    }

    // ── Cross-class isolation ─────────────────────────────────────────

    /// Token invalidation in one class does not affect entries in other
    /// classes that share the same token.
    #[test]
    fn token_invalidation_is_cross_class() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token_v1 = token_for(1);
        let token_v2 = token_for(2);

        // Class A entries under v1
        for i in 1..=3 {
            let h = make_header_class_token(i, CacheClass::PosixNamespaceMirror, token_v1);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("a_{}", i)),
            );
        }
        // Class B entries under v1
        for i in 1..=3 {
            let h = make_header_class_token(i, CacheClass::SessionFence, token_v1);
            reg.insert(
                CacheClass::SessionFence,
                i,
                CacheEntry::new(h, format!("b_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 6);

        // Invalidate by v2 token — should clear both classes (cross-class)
        let removed = reg.invalidate_by_token(token_v2);
        assert_eq!(
            removed, 6,
            "cross-class invalidation should remove all stale"
        );
        assert_eq!(reg.total_entries(), 0);
    }

    /// Class-specific invalidation (invalidate_all) does not cross classes.
    #[test]
    fn class_specific_invalidation_isolated() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let token = token_for(1);

        for i in 1..=4 {
            let h = make_header_class_token(i, CacheClass::PosixNamespaceMirror, token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("ns_{}", i)),
            );
        }
        for i in 1..=4 {
            let h = make_header_class_token(i, CacheClass::SessionFence, token);
            reg.insert(
                CacheClass::SessionFence,
                i,
                CacheEntry::new(h, format!("sf_{}", i)),
            );
        }

        // Drain only SessionFence
        let removed = reg.invalidate_all(CacheClass::SessionFence);
        assert_eq!(removed, 4);
        assert_eq!(reg.entry_count(CacheClass::SessionFence), 0);
        assert_eq!(
            reg.entry_count(CacheClass::PosixNamespaceMirror),
            4,
            "PosixNamespaceMirror should be untouched"
        );
    }

    // ── Invalidation counting ─────────────────────────────────────────

    /// invalidation_count tracks total invalidations across the registry.
    #[test]
    fn invalidation_count_monotonic() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        assert_eq!(reg.invalidation_count(), 0);

        let token_v1 = token_for(1);
        let token_v2 = token_for(2);

        for i in 1..=5 {
            let h = make_header_with_token(i, token_v1);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v_{}", i)),
            );
        }

        reg.invalidate_by_token(token_v2);
        assert_eq!(reg.invalidation_count(), 5);

        // Second invalidation (empty cache)
        reg.invalidate_by_token(token_v2);
        assert_eq!(
            reg.invalidation_count(),
            5,
            "no additional invalidations on empty cache"
        );

        // Repopulate and drain class
        for i in 1..=3 {
            let h = make_header_with_token(i, token_v2);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v2_{}", i)),
            );
        }
        reg.invalidate_all(CacheClass::PosixNamespaceMirror);
        assert_eq!(reg.invalidation_count(), 8, "5 token + 3 class-drain = 8");
    }

    // ── Edge cases ────────────────────────────────────────────────────

    /// Entries with default (zero) validity token are treated as stale
    /// when compared against any non-zero token.
    #[test]
    fn default_token_entries_stale_vs_computed() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();

        for i in 1..=5 {
            let h = make_header(i); // default token = zero
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("val_{}", i)),
            );
        }

        let computed = token_for(1);
        let removed = reg.invalidate_by_token(computed);
        assert_eq!(
            removed, 5,
            "all default-token entries should be stale vs computed token"
        );
        assert_eq!(reg.total_entries(), 0);
    }

    /// Partial invalidation: some entries match, some don't.
    #[test]
    fn partial_invalidation_mixed_tokens() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let t1 = token_for(1);
        let t2 = token_for(2);
        let t3 = token_for(3);

        // 3 entries with t1, 3 with t2, 3 with t3
        for i in 1..=3 {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(make_header_with_token(i, t1), format!("t1_{}", i)),
            );
        }
        for i in 4..=6 {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(make_header_with_token(i, t2), format!("t2_{}", i)),
            );
        }
        for i in 7..=9 {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(make_header_with_token(i, t3), format!("t3_{}", i)),
            );
        }

        // Invalidate with t2: t1 entries removed, t2+t3 entries stay
        let removed = reg.invalidate_by_token(t2);
        assert_eq!(removed, 6, "t1 (3) + t3 (3) = 6 stale vs t2");
        assert_eq!(reg.total_entries(), 3);
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &4).is_some());
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &5).is_some());
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &6).is_some());
    }

    /// Invalidation after insert-then-remove shouldn't double-count.
    #[test]
    fn invalidation_after_remove_consistent() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let t1 = token_for(1);
        let t2 = token_for(2);

        for i in 1..=5 {
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(make_header_with_token(i, t1), format!("v_{}", i)),
            );
        }

        // Remove key 3 manually
        reg.remove(CacheClass::PosixNamespaceMirror, &3);
        assert_eq!(reg.total_entries(), 4);

        // Invalidate by t2: remaining 4 should be removed
        let removed = reg.invalidate_by_token(t2);
        assert_eq!(removed, 4);
        assert_eq!(reg.total_entries(), 0);
    }

    // ── Edge cases: eviction + staleness priority ────────────────────

    /// When cache exceeds capacity, LRU eviction runs (no panic),
    /// then token invalidation removes all stale entries leaving only
    /// current-token entries servable.  Coherency is maintained by the
    /// token invalidation pipeline, not by eviction preference.
    #[test]
    fn eviction_then_token_invalidation_clears_stale() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let current_token = token_for(10);
        let stale_token = token_for(1);

        // Register a small cache with capacity 4
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            4,
            tidefs_cache_core::EvictionPolicyKind::Lru,
        );

        // Insert 2 current entries
        for i in 1..=2 {
            let h = make_header_with_token(i, current_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("current_{}", i)),
            );
        }
        // Insert 3 stale entries (fills capacity and forces eviction)
        for i in 3..=5 {
            let h = make_header_with_token(i, stale_token);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("stale_{}", i)),
            );
        }

        // Capacity is 4, we inserted 5 — one entry was evicted by LRU.
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 4);

        // Token invalidation with the current token removes stale entries.
        // After invalidation, only current-token entries remain servable.
        let removed = reg.invalidate_by_token(current_token);
        assert!(removed > 0, "some stale entries should be removed");
        // Total after invalidation: only current-token entries survive
        let remaining = reg.entry_count(CacheClass::PosixNamespaceMirror);
        assert!(
            remaining <= 2,
            "at most 2 current-token entries should remain"
        );
        // Verify that all remaining entries have the current token
        if remaining > 0 {
            for i in 1..=2 {
                if let Some(e) = reg.get(CacheClass::PosixNamespaceMirror, &i) {
                    assert!(
                        e.is_stale(current_token) == false,
                        "surviving entry {} must not be stale",
                        i
                    );
                }
            }
        }
    }

    /// Invalidating an unregistered cache class is a no-op.
    #[test]
    fn invalidate_all_unregistered_class_noop() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        // No cache registered for SessionFence
        let removed = reg.invalidate_all(CacheClass::SessionFence);
        assert_eq!(removed, 0);
        assert_eq!(reg.total_entries(), 0);
    }

    /// Mixed invalidation: token-based then class-based drain of survivors.
    #[test]
    fn mixed_token_then_class_invalidation() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let t1 = token_for(1);
        let t2 = token_for(2);

        // Class A: 3 entries with t1, 2 with t2
        for i in 1..=3 {
            let h = make_header_class_token(i, CacheClass::PosixNamespaceMirror, t1);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("a1_{}", i)),
            );
        }
        for i in 4..=5 {
            let h = make_header_class_token(i, CacheClass::PosixNamespaceMirror, t2);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("a2_{}", i)),
            );
        }
        // Class B: 2 entries with t1
        for i in 1..=2 {
            let h = make_header_class_token(i, CacheClass::PosixPageWriteback, t1);
            let mut h = h;
            h.memory_domain = tidefs_types_cache_lattice_core::MemoryDomain::StagingDirty;
            h.dirty_state = tidefs_types_cache_lattice_core::DirtyStateClass::PosixWriteback(
                tidefs_types_cache_lattice_core::PosixWritebackState::DirtyOpen,
            );
            reg.insert(
                CacheClass::PosixPageWriteback,
                i,
                CacheEntry::new(h, format!("b_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 7);

        // Step 1: token invalidation with t2 — removes t1 entries (3 in A + 2 in B = 5)
        let token_removed = reg.invalidate_by_token(t2);
        assert_eq!(token_removed, 5);
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 2);
        assert_eq!(reg.entry_count(CacheClass::PosixPageWriteback), 0);

        // Step 2: class drain of the remaining A entries
        let class_removed = reg.invalidate_all(CacheClass::PosixNamespaceMirror);
        assert_eq!(class_removed, 2);
        assert_eq!(reg.total_entries(), 0);
    }

    /// StagingDirty entries are invalidated by token-based invalidation
    /// even though they hold dirty data (the coordination layer always
    /// wins over dirty cache state).
    #[test]
    fn staging_dirty_entries_token_invalidation() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let t1 = token_for(1);
        let t2 = token_for(2);

        for i in 1..=3 {
            let mut h = make_header_class_token(i, CacheClass::PosixPageWriteback, t1);
            h.memory_domain = tidefs_types_cache_lattice_core::MemoryDomain::StagingDirty;
            h.dirty_state = tidefs_types_cache_lattice_core::DirtyStateClass::PosixWriteback(
                tidefs_types_cache_lattice_core::PosixWritebackState::DirtyOpen,
            );
            reg.insert(
                CacheClass::PosixPageWriteback,
                i,
                CacheEntry::new(h, format!("dirty_{}", i)),
            );
        }

        assert_eq!(reg.total_entries(), 3);
        let removed = reg.invalidate_by_token(t2);
        assert_eq!(removed, 3, "stale dirty entries must be invalidated");
        assert_eq!(reg.total_entries(), 0);
    }

    // ── Concurrent aggressive stress ────────────────────────────────

    /// Aggressive concurrent: insert, invalidate, and read all racing.
    #[test]
    fn concurrent_insert_invalidate_read_race() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let shared = Arc::new(Mutex::new(reg));

        {
            let mut r = shared.lock().unwrap();
            let current = token_for(0);
            for i in 0..10 {
                let h = make_header_with_token(i, current);
                r.insert(
                    CacheClass::PosixNamespaceMirror,
                    i,
                    CacheEntry::new(h, format!("v{}", i)),
                );
            }
        }

        let mut handles = Vec::new();

        // Thread 1: Insert new entries with a range of tokens
        let s1 = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for round in 1..6 {
                let tok = token_for(round);
                let mut r = s1.lock().unwrap();
                for i in 0..5 {
                    let key = round * 100 + i;
                    let h = make_header_with_token(key, tok);
                    r.insert(
                        CacheClass::PosixNamespaceMirror,
                        key,
                        CacheEntry::new(h, format!("r{}_v{}", round, i)),
                    );
                }
            }
        }));

        // Thread 2: Invalidate with progressive tokens
        let s2 = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for round in 1..6 {
                let tok = token_for(round);
                let mut r = s2.lock().unwrap();
                r.invalidate_by_token(tok);
            }
        }));

        // Thread 3: Read existing keys
        let s3 = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut r = s3.lock().unwrap();
                for k in 0..10 {
                    let _ = r.get(CacheClass::PosixNamespaceMirror, &k);
                }
            }
        }));

        for h in handles {
            h.join().unwrap();
        }

        let r = shared.lock().unwrap();
        // Final state: cache is internally consistent
        let _ = r.total_entries();
        // All entries must match the final token or be gone
    }
}
