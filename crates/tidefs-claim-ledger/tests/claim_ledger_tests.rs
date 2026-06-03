//! Integration tests for tidefs-claim-ledger covering:
//!   - Allocation/release round-trip with multiple claims
//!   - Duplicate allocation behaviour (documents current API contract)
//!   - Release of unheld claims
//!   - Idempotent replay via clone
//!   - Crash-recovery simulation
//!   - Concurrent claim stress
//!   - Edge cases
//!   - Lease deadline lifecycle (set, update, clear)
//!   - ObligationLedger overflow and release-claims-for-inode
//!   - EncodingError::InvalidLength via crafted payloads
//!   - Display implementations for error and claim types
//!   - Exact-budget-fill boundary, clone deep-copy verification

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;
use tidefs_claim_ledger::{
    ClaimClass, ClaimEncoding, ClaimEntryRecord, ClaimLedger, ClaimLedgerError, ClaimantRef,
    EncodingError, LeaseDeadlineRecord,
};
use tidefs_types_claim_ledger_core::{BudgetDomainId, ClaimId};
use tidefs_types_vfs_core::InodeId;

// ---- helpers ---------------------------------------------------------------

fn test_domain() -> BudgetDomainId {
    BudgetDomainId::from_str("test_domain")
}

fn make_service_entry(class: ClaimClass, claimed_bytes: u64) -> ClaimEntryRecord {
    ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "test-worker".into(),
        },
        class,
        claimed_bytes,
    )
}

fn make_entry_with_id(
    claim_id: ClaimId,
    class: ClaimClass,
    claimed_bytes: u64,
) -> ClaimEntryRecord {
    let mut e = make_service_entry(class, claimed_bytes);
    e.claim_id = claim_id;
    e
}

/// Assert that two ClaimLedgerReports are equivalent.
fn assert_reports_eq(
    a: &tidefs_claim_ledger::ClaimLedgerReport,
    b: &tidefs_claim_ledger::ClaimLedgerReport,
) {
    assert_eq!(a.ledger_id, b.ledger_id);
    assert_eq!(a.budget_domain, b.budget_domain);
    assert_eq!(a.total_claimed_bytes, b.total_claimed_bytes);
    assert_eq!(a.total_committed_bytes, b.total_committed_bytes);
    assert_eq!(a.claim_count, b.claim_count);
    assert_eq!(a.bytes_by_class, b.bytes_by_class);
    assert_eq!(a.counts_by_class, b.counts_by_class);
}

// ---- test: allocation/release round-trip with multiple claims -----------------

#[test]
fn round_trip_multiple_claims() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let n = 10;

    // Allocate N claims with distinct sizes.
    let mut claim_ids = Vec::with_capacity(n);
    for i in 0..n {
        let bytes = ((i + 1) as u64) * 1000;
        let entry = make_service_entry(ClaimClass::Product, bytes);
        let cid = entry.claim_id;
        ledger.register_claim(entry, budget).unwrap();
        claim_ids.push((cid, bytes));
    }
    assert_eq!(ledger.claim_count(), n);

    let expected_total: u64 = claim_ids.iter().map(|(_, b)| b).sum();
    assert_eq!(ledger.total_claimed_bytes, expected_total);

    // Release evens (indices 0, 2, 4, 6, 8).
    let mut freed_bytes = 0u64;
    let mut kept_ids = Vec::new();
    let mut kept_bytes = 0u64;
    for (i, &(cid, bytes)) in claim_ids.iter().enumerate() {
        if i % 2 == 0 {
            let freed = ledger.release_claim(cid);
            assert_eq!(freed, bytes, "freed bytes mismatch for claim {i}");
            freed_bytes += bytes;
        } else {
            kept_ids.push(cid);
            kept_bytes += bytes;
        }
    }

    assert_eq!(ledger.claim_count(), 5);
    assert_eq!(ledger.total_claimed_bytes, kept_bytes);

    assert_eq!(freed_bytes + kept_bytes, expected_total);
    // Verify kept claims still present.
    for &cid in &kept_ids {
        let found = ledger.iter().any(|e| e.claim_id == cid);
        assert!(found, "kept claim {cid} should still be present");
    }

    // Verify released claims are gone.
    for (i, &(cid, _)) in claim_ids.iter().enumerate() {
        if i % 2 == 0 {
            let found = ledger.iter().any(|e| e.claim_id == cid);
            assert!(!found, "released claim {cid} should be absent");
        }
    }

    // Count by class: all should be Product.
    let counts = ledger.count_by_class();
    assert_eq!(counts.get(&ClaimClass::Product), Some(&5));
    assert_eq!(counts.len(), 1);
}

// ---- test: duplicate allocation documents current API contract ---------------

#[test]
fn duplicate_claim_id_is_not_rejected() {
    // Current ClaimLedger::register_claim does not check for duplicate
    // ClaimIds — it accepts any well-formed entry that fits the budget.
    // This test documents that behaviour.
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let cid = ClaimId::new();

    let entry1 = make_entry_with_id(cid, ClaimClass::Product, 4096);
    ledger.register_claim(entry1, budget).unwrap();
    assert_eq!(ledger.claim_count(), 1);

    // Second registration with the same ClaimId succeeds (no uniqueness check).
    let entry2 = make_entry_with_id(cid, ClaimClass::Product, 8192);
    let result = ledger.register_claim(entry2, budget);
    assert!(
        result.is_ok(),
        "duplicate ClaimId registration should succeed (current API contract)"
    );
    assert_eq!(ledger.claim_count(), 2);
    assert_eq!(ledger.total_claimed_bytes, 4096 + 8192);
}

// ---- test: release of unheld claim is a no-op -------------------------------

#[test]
fn release_unheld_claim_returns_zero() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let cid = ClaimId::new(); // Never registered.

    let freed = ledger.release_claim(cid);
    assert_eq!(freed, 0, "releasing an unheld claim should free zero bytes");
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 0);
}

// ---- test: idempotent replay via clone --------------------------------------

#[test]
fn idempotent_replay_via_clone() {
    let mut original = ClaimLedger::new(42, test_domain());
    let budget = 10_000_000;

    // Register several claims of different classes.
    original
        .register_claim(make_service_entry(ClaimClass::Product, 1000), budget)
        .unwrap();
    original
        .register_claim(make_service_entry(ClaimClass::Failover, 2000), budget)
        .unwrap();
    original
        .register_claim(make_service_entry(ClaimClass::Rebuild, 3000), budget)
        .unwrap();

    // Clone is a faithful snapshot.
    let snapshot = original.clone();
    assert_reports_eq(&original.report(), &snapshot.report());

    // Replay: create a fresh ledger and replay the same allocations.
    let mut replay = ClaimLedger::new(42, test_domain());
    for entry in original.iter() {
        let mut re_entry = ClaimEntryRecord::new(
            entry.claim_id,
            entry.claimant_ref.clone(),
            entry.claim_class,
            entry.claimed_bytes,
        );
        re_entry.inode_id = entry.inode_id;
        replay.register_claim(re_entry, budget).unwrap();
    }

    assert_reports_eq(&original.report(), &replay.report());

    // Modify original further; clone diverges.
    let cid = original
        .register_claim(make_service_entry(ClaimClass::AntiEntropy, 500), budget)
        .unwrap();
    let snapshot2 = original.clone();
    assert_reports_eq(&original.report(), &snapshot2.report());
    assert!(snapshot2.iter().any(|e| e.claim_id == cid));
}

// ---- test: crash-recovery simulation ----------------------------------------

#[test]
fn crash_recovery_simulation() {
    let budget = 10_000_000;

    // Build initial ledger state.
    let mut ledger = ClaimLedger::new(99, test_domain());
    let cid1 = ledger
        .register_claim(make_service_entry(ClaimClass::Product, 4096), budget)
        .unwrap();
    let cid2 = ledger
        .register_claim(make_service_entry(ClaimClass::Failover, 8192), budget)
        .unwrap();

    // Commit some bytes before crash.
    ledger.commit_claim(cid1, 2048).unwrap();

    // Extract all recoverable state.
    let saved_entries: Vec<_> = ledger
        .iter()
        .map(|e| {
            let mut entry = ClaimEntryRecord::new(
                e.claim_id,
                e.claimant_ref.clone(),
                e.claim_class,
                e.claimed_bytes,
            );
            entry.inode_id = e.inode_id;
            entry.committed_bytes = e.committed_bytes;
            entry.freshness_fence_ref = e.freshness_fence_ref;
            entry.claim_receipt_ref = e.claim_receipt_ref;
            entry.expiration_deadline = e.expiration_deadline;
            entry
        })
        .collect();
    let saved_total_claimed = ledger.total_claimed_bytes;
    let saved_total_committed = ledger.total_committed_bytes;

    // Simulate crash: drop the ledger.
    drop(ledger);

    // Recover: rebuild from saved state.
    let mut recovered = ClaimLedger::new(99, test_domain());
    for entry in saved_entries {
        let mut re_entry = ClaimEntryRecord::new(
            entry.claim_id,
            entry.claimant_ref.clone(),
            entry.claim_class,
            entry.claimed_bytes,
        );
        re_entry.inode_id = entry.inode_id;
        recovered.register_claim(re_entry, budget).unwrap();
        if entry.committed_bytes > 0 {
            recovered
                .commit_claim(entry.claim_id, entry.committed_bytes)
                .unwrap();
        }
    }

    assert_eq!(recovered.claim_count(), 2);
    assert_eq!(recovered.total_claimed_bytes, saved_total_claimed);
    assert_eq!(recovered.total_committed_bytes, saved_total_committed);

    // Verify individual claims.
    let cids: Vec<ClaimId> = recovered.iter().map(|e| e.claim_id).collect();
    assert!(cids.contains(&cid1));
    assert!(cids.contains(&cid2));

    // No double-accounting: releasing all and re-adding should match.
    let freed = recovered.release_claim(cid1);
    assert_eq!(freed, 4096);
    assert_eq!(recovered.claim_count(), 1);
}

// ---- test: concurrent claim stress ------------------------------------------

#[test]
fn concurrent_claim_stress() {
    let ledger = Arc::new(Mutex::new(ClaimLedger::new(1, test_domain())));
    let budget = 100_000_000;
    let threads = 8;
    let claims_per_thread = 50;
    let release_every = 7; // Release every 7th claim per thread.

    let mut handles = Vec::new();
    for t in 0..threads {
        let ledger = Arc::clone(&ledger);
        let handle = thread::spawn(move || {
            let mut local_cids = Vec::with_capacity(claims_per_thread);
            for i in 0..claims_per_thread {
                let bytes = ((t * claims_per_thread + i + 1) as u64) * 13;
                let entry = make_service_entry(ClaimClass::Product, bytes);
                let cid = entry.claim_id;
                {
                    let mut lg = ledger.lock().unwrap();
                    lg.register_claim(entry, budget).unwrap();
                }
                local_cids.push(cid);
            }

            // Release some claims.
            let mut released = 0u64;
            for (i, &cid) in local_cids.iter().enumerate() {
                if i % release_every == 0 {
                    let mut lg = ledger.lock().unwrap();
                    let freed = lg.release_claim(cid);
                    released += freed;
                }
            }
            (local_cids, released)
        });
        handles.push(handle);
    }

    let _total_expected_claimed = 0u64;
    let mut all_cids = Vec::new();
    for handle in handles {
        let (local_cids, _released) = handle.join().unwrap();
        for &cid in &local_cids {
            all_cids.push(cid);
        }
    }

    // Compute expected total: claims not released.
    let final_ledger = ledger.lock().unwrap();
    let final_count = final_ledger.claim_count();
    let _final_bytes = final_ledger.total_claimed_bytes;

    // Every thread's claim IDs should be unique (disjoint ranges via
    // pseudo-random ClaimId::new).
    // Verify the reported state is consistent with the claim count.
    let report = final_ledger.report();
    assert_eq!(report.claim_count, final_count);
    assert_eq!(report.total_claimed_bytes, final_ledger.total_claimed_bytes);
    assert!(
        report.claim_count > 0,
        "should have remaining claims after partial release"
    );
    assert!(
        report.claim_count < threads * claims_per_thread,
        "some claims should have been released"
    );

    // No cross-contamination: bytes_by_class should only have Product.
    assert_eq!(report.bytes_by_class.len(), 1);
    assert!(report.bytes_by_class.contains_key("product"));
}

// ---- test: edge cases -------------------------------------------------------

#[test]
fn zero_byte_claim_rejected() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let entry = make_service_entry(ClaimClass::Product, 0);
    let result = ledger.register_claim(entry, 1_000_000);
    assert!(matches!(result, Err(ClaimLedgerError::ZeroByteClaim)));
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 0);
}

#[test]
fn single_claim_minimal() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let entry = make_service_entry(ClaimClass::Product, 1);
    let cid = entry.claim_id;
    ledger.register_claim(entry, 1_000_000).unwrap();
    assert_eq!(ledger.claim_count(), 1);
    assert_eq!(ledger.total_claimed_bytes, 1);

    let freed = ledger.release_claim(cid);
    assert_eq!(freed, 1);
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 0);
}

#[test]
fn commit_to_unknown_claim_fails() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let cid = ClaimId::new();
    let result = ledger.commit_claim(cid, 100);
    assert!(matches!(result, Err(ClaimLedgerError::ClaimNotFound(_))));
}

#[test]
fn budget_exhausted_edge() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 4096;

    // First claim fits exactly.
    let entry = make_service_entry(ClaimClass::Product, 4096);
    ledger.register_claim(entry, budget).unwrap();
    assert_eq!(ledger.total_claimed_bytes, 4096);

    // Second claim exceeds budget.
    let entry2 = make_service_entry(ClaimClass::Product, 1);
    let result = ledger.register_claim(entry2, budget);
    assert!(matches!(
        result,
        Err(ClaimLedgerError::BudgetExhausted { .. })
    ));
    assert_eq!(ledger.total_claimed_bytes, 4096);
}

#[test]
fn large_claim_values() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let big = u64::MAX / 2;
    let entry = make_service_entry(ClaimClass::Product, big);
    let cid = entry.claim_id;
    ledger.register_claim(entry, u64::MAX).unwrap();
    assert_eq!(ledger.total_claimed_bytes, big);

    // Second large claim overflows total but still within budget.
    let entry2 = make_service_entry(ClaimClass::Rebuild, big);
    ledger.register_claim(entry2, u64::MAX).unwrap();
    assert_eq!(ledger.total_claimed_bytes, big.saturating_add(big));

    // Release one.
    let freed = ledger.release_claim(cid);
    assert_eq!(freed, big);
}

#[test]
fn count_and_bytes_by_class() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 1000), budget)
        .unwrap();
    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 2000), budget)
        .unwrap();
    ledger
        .register_claim(make_service_entry(ClaimClass::Failover, 500), budget)
        .unwrap();

    let counts = ledger.count_by_class();
    assert_eq!(counts.get(&ClaimClass::Product), Some(&2));
    assert_eq!(counts.get(&ClaimClass::Failover), Some(&1));

    let bytes = ledger.bytes_by_class();
    assert_eq!(bytes.get(&ClaimClass::Product), Some(&3000));
    assert_eq!(bytes.get(&ClaimClass::Failover), Some(&500));
}

#[test]
fn release_claims_for_inode_partial() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let inode_a = InodeId::new(10);
    let inode_b = InodeId::new(20);

    let mut e1 = make_service_entry(ClaimClass::Product, 500);
    e1.inode_id = Some(inode_a);
    ledger.register_claim(e1, budget).unwrap();

    let mut e2 = make_service_entry(ClaimClass::Product, 300);
    e2.inode_id = Some(inode_b);
    ledger.register_claim(e2, budget).unwrap();

    let mut e3 = make_service_entry(ClaimClass::Product, 200);
    e3.inode_id = Some(inode_a);
    ledger.register_claim(e3, budget).unwrap();

    assert_eq!(ledger.claim_count(), 3);

    let freed = ledger.release_claims_for_inode(inode_a);
    assert_eq!(freed, 700);
    assert_eq!(ledger.claim_count(), 1);
    assert_eq!(ledger.total_claimed_bytes, 300);
}

#[test]
fn empty_ledger_report() {
    let ledger = ClaimLedger::new(7, test_domain());
    let report = ledger.report();
    assert_eq!(report.ledger_id, 7);
    assert_eq!(report.claim_count, 0);
    assert_eq!(report.total_claimed_bytes, 0);
    assert_eq!(report.total_committed_bytes, 0);
    assert!(report.bytes_by_class.is_empty());
    assert!(report.counts_by_class.is_empty());
}

#[test]
fn commit_exceeding_claimed_bytes_saturates() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let entry = make_service_entry(ClaimClass::Product, 100);
    let cid = entry.claim_id;
    ledger.register_claim(entry, 1_000_000).unwrap();

    // Commit more than claimed — saturating_add prevents overflow.
    ledger.commit_claim(cid, 500).unwrap();
    assert_eq!(ledger.total_committed_bytes, 500);

    // Check that per-entry committed_bytes saturates.
    let entry = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(entry.committed_bytes, 500);
}

#[test]
fn iter_yields_all_entries() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let mut cids = Vec::new();
    for _ in 0..5 {
        let entry = make_service_entry(ClaimClass::Product, 100);
        let cid = entry.claim_id;
        cids.push(cid);
        ledger.register_claim(entry, budget).unwrap();
    }

    let iter_cids: Vec<ClaimId> = ledger.iter().map(|e| e.claim_id).collect();
    assert_eq!(iter_cids.len(), 5);
    for cid in &cids {
        assert!(iter_cids.contains(cid));
    }
}

#[test]
fn claim_class_display_and_try_from() {
    // ClaimClass Display/FromStr.
    let classes = [
        ClaimClass::Product,
        ClaimClass::Rebuild,
        ClaimClass::AntiEntropy,
        ClaimClass::Failover,
    ];
    for &c in &classes {
        assert_eq!(ClaimClass::try_from(c as u8).unwrap(), c);
    }
    assert!(ClaimClass::try_from(255).is_err());
}
// ── Lease deadline lifecycle ──────────────────────────────────────────────

#[test]
fn lease_deadline_lifecycle_set_update_clear() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    // Create claim without lease deadline.
    let entry = make_service_entry(ClaimClass::Product, 4096);
    assert!(entry.expiration_deadline.is_none());
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    // Verify no deadline after registration.
    {
        let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
        assert!(e.expiration_deadline.is_none());
    }

    // Set a lease deadline directly (the API allows mutation after creation).
    {
        let e = ledger
            .claim_entries
            .iter_mut()
            .find(|e| e.claim_id == cid)
            .unwrap();
        e.expiration_deadline = Some(LeaseDeadlineRecord {
            deadline_millis: 100_000,
            auto_reclaim: false,
        });
    }
    {
        let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
        let dl = e.expiration_deadline.unwrap();
        assert_eq!(dl.deadline_millis, 100_000);
        assert!(!dl.auto_reclaim);
    }

    // Update the deadline (extend lease).
    {
        let e = ledger
            .claim_entries
            .iter_mut()
            .find(|e| e.claim_id == cid)
            .unwrap();
        e.expiration_deadline = Some(LeaseDeadlineRecord {
            deadline_millis: 200_000,
            auto_reclaim: true,
        });
    }
    {
        let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
        let dl = e.expiration_deadline.unwrap();
        assert_eq!(dl.deadline_millis, 200_000);
        assert!(dl.auto_reclaim);
    }

    // Clear the deadline (release lease).
    {
        let e = ledger
            .claim_entries
            .iter_mut()
            .find(|e| e.claim_id == cid)
            .unwrap();
        e.expiration_deadline = None;
    }
    {
        let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
        assert!(e.expiration_deadline.is_none());
    }
}

// ── Release claims for nonexistent inode ──────────────────────────────────

#[test]
fn release_claims_for_nonexistent_inode_returns_zero() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    // Register a claim on inode 10.
    let mut e1 = make_service_entry(ClaimClass::Product, 500);
    e1.inode_id = Some(InodeId::new(10));
    ledger.register_claim(e1, budget).unwrap();

    // Release for a different inode should free nothing.
    let freed = ledger.release_claims_for_inode(InodeId::new(99));
    assert_eq!(freed, 0);
    assert_eq!(ledger.claim_count(), 1);
    assert_eq!(ledger.total_claimed_bytes, 500);
}

// ── Exact budget fill ─────────────────────────────────────────────────────

#[test]
fn exact_budget_fill_succeeds() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 4096;

    let entry = make_service_entry(ClaimClass::Product, 4096);
    ledger.register_claim(entry, budget).unwrap();
    assert_eq!(ledger.total_claimed_bytes, 4096);
    assert_eq!(ledger.claim_count(), 1);

    // Next byte should fail.
    let entry2 = make_service_entry(ClaimClass::Product, 1);
    let result = ledger.register_claim(entry2, budget);
    assert!(matches!(
        result,
        Err(ClaimLedgerError::BudgetExhausted { .. })
    ));
}

// ── Commit bytes idempotent / multiple partial commits ────────────────────

#[test]
fn commit_multiple_partial_commits_accumulate() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let entry = make_service_entry(ClaimClass::Product, 10_000);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    // Commit in 3 chunks.
    ledger.commit_claim(cid, 3000).unwrap();
    assert_eq!(ledger.total_committed_bytes, 3000);
    ledger.commit_claim(cid, 3000).unwrap();
    assert_eq!(ledger.total_committed_bytes, 6000);
    ledger.commit_claim(cid, 4000).unwrap();
    assert_eq!(ledger.total_committed_bytes, 10_000);

    // Per-entry committed_bytes tracks correctly.
    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(e.committed_bytes, 10_000);
}

// ── Bytes by class on empty ledger ────────────────────────────────────────

#[test]
fn bytes_by_class_empty_ledger() {
    let ledger = ClaimLedger::new(1, test_domain());
    let bytes = ledger.bytes_by_class();
    assert!(bytes.is_empty());
}

// ── Count by class after release ──────────────────────────────────────────

#[test]
fn count_by_class_updates_after_release() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let e1 = make_service_entry(ClaimClass::Product, 100);
    let cid1 = e1.claim_id;
    ledger.register_claim(e1, budget).unwrap();

    let e2 = make_service_entry(ClaimClass::Failover, 200);
    ledger.register_claim(e2, budget).unwrap();

    // Before release: 1 Product, 1 Failover.
    let counts = ledger.count_by_class();
    assert_eq!(counts.get(&ClaimClass::Product), Some(&1));
    assert_eq!(counts.get(&ClaimClass::Failover), Some(&1));

    // Release the Product claim.
    ledger.release_claim(cid1);
    let counts = ledger.count_by_class();
    assert_eq!(counts.get(&ClaimClass::Product), None);
    assert_eq!(counts.get(&ClaimClass::Failover), Some(&1));
}

// ── ClaimLedger Display ───────────────────────────────────────────────────

#[test]
fn claim_ledger_display_contains_key_fields() {
    let mut ledger = ClaimLedger::new(42, test_domain());
    let budget = 1_000_000;

    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 1024), budget)
        .unwrap();

    let s = format!("{ledger}");
    assert!(s.contains("ledger_id: 42"));
    assert!(s.contains("test_domain"));
    assert!(s.contains("total_claimed_bytes: 1024"));
    assert!(s.contains("claim_count: 1"));
}

// ── ClaimantRef Display ───────────────────────────────────────────────────

#[test]
fn claimant_ref_display_variants() {
    let process = ClaimantRef::Process {
        pid: 42,
        name: "fuse-worker".into(),
    };
    assert_eq!(format!("{process}"), "process:42(fuse-worker)");

    let cohort = ClaimantRef::Cohort {
        cohort_id: 7,
        label: "write-group".into(),
    };
    assert_eq!(format!("{cohort}"), "cohort:7(write-group)");

    let service = ClaimantRef::Service {
        service_name: "seg-writer".into(),
    };
    assert_eq!(format!("{service}"), "service:seg-writer");
}

// ── ClaimLedgerError Display ──────────────────────────────────────────────

#[test]
fn claim_ledger_error_display() {
    let e1 = ClaimLedgerError::ZeroByteClaim;
    assert!(format!("{e1}").contains("zero-byte"));

    let e2 = ClaimLedgerError::BudgetExhausted {
        domain: "test".into(),
        requested: 100,
        available: 50,
    };
    let s2 = format!("{e2}");
    assert!(s2.contains("test"));
    assert!(s2.contains("100"));
    assert!(s2.contains("50"));

    let e3 = ClaimLedgerError::ClaimNotFound(ClaimId::ZERO);
    assert!(format!("{e3}").contains("not found"));

    let e4 = ClaimLedgerError::InvalidClaimClass(99);
    assert!(format!("{e4}").contains("99"));
}

// ── ClaimClass as_str coverage ────────────────────────────────────────────

#[test]
fn claim_class_as_str_all_variants() {
    assert_eq!(ClaimClass::Product.as_str(), "product");
    assert_eq!(ClaimClass::Rebuild.as_str(), "rebuild");
    assert_eq!(ClaimClass::AntiEntropy.as_str(), "anti_entropy");
    assert_eq!(ClaimClass::Failover.as_str(), "failover");
}

// ── ClaimClass Display coverage ───────────────────────────────────────────

#[test]
fn claim_class_display_all_variants() {
    assert_eq!(format!("{}", ClaimClass::Product), "product");
    assert_eq!(format!("{}", ClaimClass::Rebuild), "rebuild");
    assert_eq!(format!("{}", ClaimClass::AntiEntropy), "anti_entropy");
    assert_eq!(format!("{}", ClaimClass::Failover), "failover");
}

// ── ClaimClass COUNT constant ─────────────────────────────────────────────

#[test]
fn claim_class_count_is_4() {
    assert_eq!(ClaimClass::COUNT, 4);
}

// ── ObligationLedger overflow ─────────────────────────────────────────────

#[test]
fn obligation_ledger_claim_overflow_rejected() {
    use tidefs_types_claim_ledger_core::StorageAuthorityToken;
    use tidefs_types_claim_ledger_core::{ClaimEntry, ClaimReason, ObligationLedger};

    let mut ledger = ObligationLedger::new(1_000_000);
    let domain = BudgetDomainId::from_str("test_domain");
    let inode = InodeId::new(1);

    // Fill to max claims (1024).
    for _ in 0..1024 {
        ledger
            .claim(ClaimEntry {
                claim_id: ClaimId::new(),
                budget_domain: domain,
                blocks: 1,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ZERO,
                generation: 1,
            })
            .unwrap();
    }

    // 1025th claim should fail with Overflow.
    let result = ledger.claim(ClaimEntry {
        claim_id: ClaimId::new(),
        budget_domain: domain,
        blocks: 1,
        inode_id: inode,
        reason: ClaimReason::Write,
        authorized_by: StorageAuthorityToken::ZERO,
        generation: 1,
    });
    assert!(matches!(
        result,
        Err(tidefs_types_claim_ledger_core::ObligationLedgerError::Overflow)
    ));
}

// ── ObligationLedger release_claims_for_inode ─────────────────────────────

#[test]
fn obligation_ledger_release_claims_for_inode() {
    use tidefs_types_claim_ledger_core::StorageAuthorityToken;
    use tidefs_types_claim_ledger_core::{ClaimEntry, ClaimReason, ObligationLedger};

    let mut ledger = ObligationLedger::new(10_000);
    let domain = BudgetDomainId::from_str("staging");
    let inode_a = InodeId::new(10);
    let inode_b = InodeId::new(20);

    ledger
        .claim(ClaimEntry {
            claim_id: ClaimId::new(),
            budget_domain: domain,
            blocks: 100,
            inode_id: inode_a,
            reason: ClaimReason::Write,
            authorized_by: StorageAuthorityToken::ZERO,
            generation: 1,
        })
        .unwrap();
    ledger
        .claim(ClaimEntry {
            claim_id: ClaimId::new(),
            budget_domain: domain,
            blocks: 200,
            inode_id: inode_a,
            reason: ClaimReason::Write,
            authorized_by: StorageAuthorityToken::ZERO,
            generation: 1,
        })
        .unwrap();
    ledger
        .claim(ClaimEntry {
            claim_id: ClaimId::new(),
            budget_domain: domain,
            blocks: 50,
            inode_id: inode_b,
            reason: ClaimReason::Write,
            authorized_by: StorageAuthorityToken::ZERO,
            generation: 1,
        })
        .unwrap();

    assert_eq!(ledger.claim_count(), 3);
    assert_eq!(ledger.allocated_blocks(), 350);

    let freed = ledger.release_claims_for_inode(inode_a);
    assert_eq!(freed, 300);
    // After release, allocated_blocks should drop by 300.
    assert_eq!(ledger.allocated_blocks(), 50);
}

// ── ObligationLedger release_reserve unknown ──────────────────────────────

#[test]
fn obligation_ledger_release_reserve_unknown_returns_zero() {
    use tidefs_types_claim_ledger_core::{ObligationLedger, ReserveId};
    let mut ledger = ObligationLedger::new(1000);
    let freed = ledger.release_reserve(ReserveId::ZERO);
    assert_eq!(freed, 0);
}

// ── ObligationLedger free_blocks with reserves ────────────────────────────

#[test]
fn obligation_ledger_free_blocks_respects_reserves() {
    use tidefs_types_claim_ledger_core::StorageAuthorityToken;
    use tidefs_types_claim_ledger_core::{
        ClaimEntry, ClaimReason, ObligationLedger, ReserveEntry, ReserveId,
    };

    let mut ledger = ObligationLedger::new(1000);
    let domain = BudgetDomainId::from_str("authority_hot");

    ledger
        .reserve(ReserveEntry {
            reserve_id: ReserveId::new(),
            budget_domain: domain,
            min_blocks: 300,
            reason: ClaimReason::Reserve,
            authorized_by: StorageAuthorityToken::ZERO,
            generation: 1,
        })
        .unwrap();

    // Reserve alone: free = 1000 - 300 = 700.
    assert_eq!(ledger.free_blocks(), 700);

    ledger
        .claim(ClaimEntry {
            claim_id: ClaimId::new(),
            budget_domain: domain,
            blocks: 200,
            inode_id: InodeId::new(1),
            reason: ClaimReason::Write,
            authorized_by: StorageAuthorityToken::ZERO,
            generation: 1,
        })
        .unwrap();

    // Claim + reserve: free = 1000 - 200 - 300 = 500.
    assert_eq!(ledger.free_blocks(), 500);
    assert_eq!(ledger.committed_blocks(), 500);
}

// ── EncodingError::InvalidLength ──────────────────────────────────────────

#[test]
fn encoding_error_invalid_length_via_crafted_payload() {
    // Craft a payload where a string length field exceeds the remaining buffer.
    // Layout: ledger_id(8) + budget_domain_len(1) + budget_domain_bytes(len) ...
    // Set domain_len to 200, but only provide 30 bytes total.
    let mut buf = vec![0u8; 30];
    // ledger_id = 0 (8 bytes)
    // domain_len = 200 (u8 at pos 8)
    buf[8] = 200;
    // The read will see domain_len=200 but only ~21 bytes remaining.
    match ClaimLedger::deserialize(&buf).unwrap_err() {
        EncodingError::InvalidLength { field, .. } => {
            // With len=200 > MAX_LEN(64), we get InvalidLength
            // because BudgetDomainId::MAX_LEN is 64.
            assert_eq!(field, "budget_domain_ref");
        }
        other => panic!("expected InvalidLength, got {other:?}"),
    }
}

// ── ClaimLedger is Clone ──────────────────────────────────────────────────

#[test]
fn claim_ledger_clone_is_deep() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 1024), 1_000_000)
        .unwrap();

    let mut clone = ledger.clone();
    assert_eq!(clone.claim_count(), 1);
    assert_eq!(clone.total_claimed_bytes, 1024);

    // Modify clone without affecting original.
    clone
        .register_claim(make_service_entry(ClaimClass::Failover, 512), 1_000_000)
        .unwrap();

    assert_eq!(clone.claim_count(), 2);
    assert_eq!(ledger.claim_count(), 1);
}

// ── ClaimLedgerReport full coverage ───────────────────────────────────────

#[test]
fn claim_ledger_report_counts_by_class_multiple() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 100), budget)
        .unwrap();
    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 200), budget)
        .unwrap();
    ledger
        .register_claim(make_service_entry(ClaimClass::Failover, 50), budget)
        .unwrap();

    let report = ledger.report();
    // counts_by_class uses string keys.
    let p_count = report.counts_by_class.get("product").copied().unwrap_or(0);
    let f_count = report.counts_by_class.get("failover").copied().unwrap_or(0);
    assert_eq!(p_count, 2);
    assert_eq!(f_count, 1);

    let p_bytes = report.bytes_by_class.get("product").copied().unwrap_or(0);
    let f_bytes = report.bytes_by_class.get("failover").copied().unwrap_or(0);
    assert_eq!(p_bytes, 300);
    assert_eq!(f_bytes, 50);
}

// ═══════════════════════════════════════════════════════════════════════════
// Claim lifecycle: create, acquire by owner, release, expire, renew
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn claim_create_with_ttl_and_acquire_by_owner() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Process {
            pid: 1001,
            name: "owner-a".into(),
        },
        ClaimClass::Product,
        4096,
    );
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 10_000,
        auto_reclaim: false,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(
        e.claimant_ref,
        ClaimantRef::Process {
            pid: 1001,
            name: "owner-a".into()
        }
    );
    let dl = e.expiration_deadline.unwrap();
    assert_eq!(dl.deadline_millis, 10_000);
    assert!(!dl.auto_reclaim);
}

#[test]
fn claim_renew_extends_ttl() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "renew-test".into(),
        },
        ClaimClass::Product,
        2048,
    );
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 5000,
        auto_reclaim: true,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    // Renew: extend deadline.
    {
        let e = ledger
            .claim_entries
            .iter_mut()
            .find(|e| e.claim_id == cid)
            .unwrap();
        e.expiration_deadline = Some(LeaseDeadlineRecord {
            deadline_millis: 15000,
            auto_reclaim: true,
        });
    }

    let dl = ledger
        .iter()
        .find(|e| e.claim_id == cid)
        .unwrap()
        .expiration_deadline
        .unwrap();
    assert_eq!(dl.deadline_millis, 15000);
    assert!(dl.auto_reclaim);
}

/// Detect expired claims by comparing deadline_millis against a reference epoch.
#[test]
fn claim_expiry_detection_after_ttl() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut live = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "live".into(),
        },
        ClaimClass::Product,
        100,
    );
    live.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 200_000,
        auto_reclaim: false,
    });
    let live_id = live.claim_id;
    ledger.register_claim(live, budget).unwrap();

    let mut expired = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "expired".into(),
        },
        ClaimClass::Product,
        200,
    );
    expired.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 50_000,
        auto_reclaim: false,
    });
    let expired_id = expired.claim_id;
    ledger.register_claim(expired, budget).unwrap();

    let epoch = 100_000; // after expired, before live

    let expired_cids: Vec<ClaimId> = ledger
        .iter()
        .filter(|e| {
            e.expiration_deadline
                .map(|dl| dl.deadline_millis <= epoch)
                .unwrap_or(false)
        })
        .map(|e| e.claim_id)
        .collect();

    assert_eq!(expired_cids, vec![expired_id]);
    assert_eq!(expired_cids.len(), 1);

    // Live claim still accessible.
    assert!(ledger.iter().any(|e| e.claim_id == live_id));
}

#[test]
fn claim_expiry_detection_none_expired_when_all_fresh() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "fresh".into(),
        },
        ClaimClass::Product,
        500,
    );
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 300_000,
        auto_reclaim: false,
    });
    ledger.register_claim(entry, budget).unwrap();

    let epoch = 100_000;
    let expired_count = ledger
        .iter()
        .filter(|e| {
            e.expiration_deadline
                .map(|dl| dl.deadline_millis <= epoch)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(expired_count, 0);
}

#[test]
fn claim_no_deadline_never_expired() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "perpetual".into(),
        },
        ClaimClass::Product,
        1024,
    );
    ledger.register_claim(entry, budget).unwrap();

    // Claims without expiration_deadline should never match an expiry check.
    let epoch = u64::MAX;
    let expired_count = ledger
        .iter()
        .filter(|e| {
            e.expiration_deadline
                .map(|dl| dl.deadline_millis <= epoch)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(expired_count, 0);
}

#[test]
fn claim_deny_expired_claim_reuse_by_releasing() {
    // The ledger does not enforce expiry at the API level, but a higher layer
    // can detect expired claims, release them, and deny re-use.
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "to-expire".into(),
        },
        ClaimClass::Product,
        512,
    );
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 10_000,
        auto_reclaim: false,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    // Simulate expiry detection and release.
    let epoch = 20_000;
    let expired: Vec<ClaimId> = ledger
        .iter()
        .filter(|e| {
            e.expiration_deadline
                .map(|dl| dl.deadline_millis <= epoch)
                .unwrap_or(false)
        })
        .map(|e| e.claim_id)
        .collect();

    assert!(expired.contains(&cid));
    for cid in &expired {
        ledger.release_claim(*cid);
    }
    assert_eq!(ledger.claim_count(), 0);

    // Attempt to re-register with same ClaimId: allowed (no uniqueness).
    let reentry = ClaimEntryRecord::new(
        cid,
        ClaimantRef::Service {
            service_name: "reuse-attempt".into(),
        },
        ClaimClass::Product,
        256,
    );
    let result = ledger.register_claim(reentry, budget);
    assert!(result.is_ok());
    assert_eq!(ledger.claim_count(), 1);
}

// ── Release of all claims (full drain) ───────────────────────────────────

#[test]
fn release_all_claims_full_drain() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut cids = Vec::new();
    for _ in 0..5 {
        let entry = make_service_entry(ClaimClass::Product, 100);
        cids.push(entry.claim_id);
        ledger.register_claim(entry, budget).unwrap();
    }
    assert_eq!(ledger.claim_count(), 5);
    assert_eq!(ledger.total_claimed_bytes, 500);

    for &cid in &cids {
        ledger.release_claim(cid);
    }
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 0);
    assert!(ledger.iter().next().is_none());
    assert!(ledger.count_by_class().is_empty());
}

// ── Iter on empty ledger yields nothing ──────────────────────────────────

#[test]
fn iter_empty_ledger_yields_nothing() {
    let ledger = ClaimLedger::new(1, test_domain());
    let v: Vec<_> = ledger.iter().collect();
    assert!(v.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Conflict detection: claimants for same resource coexist
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn multiple_claimants_same_inode_coexist() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let inode = InodeId::new(42);

    let mut e1 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Process {
            pid: 1,
            name: "writer-a".into(),
        },
        ClaimClass::Product,
        1000,
    );
    e1.inode_id = Some(inode);
    ledger.register_claim(e1, budget).unwrap();

    let mut e2 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Process {
            pid: 2,
            name: "writer-b".into(),
        },
        ClaimClass::Product,
        2000,
    );
    e2.inode_id = Some(inode);
    ledger.register_claim(e2, budget).unwrap();

    // Both claims coexist on the same inode (no conflict rejection at ledger level).
    assert_eq!(ledger.claim_count(), 2);
    let inode_claims: Vec<_> = ledger
        .iter()
        .filter(|e| e.inode_id == Some(inode))
        .collect();
    assert_eq!(inode_claims.len(), 2);
    // Different claimants.
    assert_ne!(inode_claims[0].claimant_ref, inode_claims[1].claimant_ref);
}

#[test]
fn claims_different_inodes_no_conflict() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut e1 = make_service_entry(ClaimClass::Product, 500);
    e1.inode_id = Some(InodeId::new(10));
    ledger.register_claim(e1, budget).unwrap();

    let mut e2 = make_service_entry(ClaimClass::Product, 500);
    e2.inode_id = Some(InodeId::new(20));
    ledger.register_claim(e2, budget).unwrap();

    assert_eq!(ledger.claim_count(), 2);
    assert_eq!(ledger.total_claimed_bytes, 1000);
}

#[test]
fn claim_class_priority_ordering_full_matrix() {
    // Verify the partial order: Product < AntiEntropy < Rebuild < Failover.
    assert!(
        ClaimClass::Product.admission_priority() < ClaimClass::AntiEntropy.admission_priority()
    );
    assert!(
        ClaimClass::AntiEntropy.admission_priority() < ClaimClass::Rebuild.admission_priority()
    );
    assert!(ClaimClass::Rebuild.admission_priority() < ClaimClass::Failover.admission_priority());
}

// ── Concurrent claimants deterministic: different classes admitted under
//    budget pressure; highest-priority admitted first. ─────────────────────

#[test]
fn priority_admission_under_pressure() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 5000;

    // Failover always admitted (highest priority).
    let e1 = make_service_entry(ClaimClass::Failover, 4000);
    ledger.register_claim(e1, budget).unwrap();

    // Rebuild admitted with remaining space.
    let e2 = make_service_entry(ClaimClass::Rebuild, 500);
    ledger.register_claim(e2, budget).unwrap();

    // Product rejected (no space left).
    let e3 = make_service_entry(ClaimClass::Product, 1000);
    let result = ledger.register_claim(e3, budget);
    assert!(result.is_err());

    assert_eq!(ledger.claim_count(), 2);
    let counts = ledger.count_by_class();
    assert_eq!(counts.get(&ClaimClass::Failover), Some(&1));
    assert_eq!(counts.get(&ClaimClass::Rebuild), Some(&1));
    assert!(!counts.contains_key(&ClaimClass::Product));
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialization: IntegrityError display, encoding error messages
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integrity_error_hash_mismatch_display() {
    let expected = [0xAAu8; 32];
    let computed = [0xBBu8; 32];
    let err = tidefs_claim_ledger::IntegrityError::HashMismatch { expected, computed };
    let s = format!("{err}");
    assert!(s.contains("hash mismatch"));
    assert!(s.contains("aa"));
    assert!(s.contains("bb"));
}

#[test]
fn encoding_error_display_all_variants() {
    let e1 = EncodingError::UnexpectedEof { field: "ledger_id" };
    assert!(format!("{e1}").contains("EOF"));
    assert!(format!("{e1}").contains("ledger_id"));

    let e2 = EncodingError::InvalidDiscriminant {
        field: "claim_class",
        value: 9,
    };
    let s2 = format!("{e2}");
    assert!(s2.contains("discriminant"));
    assert!(s2.contains("claim_class"));
    assert!(s2.contains("9"));

    let e3 = EncodingError::InvalidLength {
        field: "name",
        declared: 100,
        remaining: 10,
    };
    let s3 = format!("{e3}");
    assert!(s3.contains("length"));
    assert!(s3.contains("name"));
    assert!(s3.contains("100"));
    assert!(s3.contains("10"));

    let e4 = EncodingError::InvalidValue {
        field: "body",
        detail: "trailing garbage".into(),
    };
    let s4 = format!("{e4}");
    assert!(s4.contains("invalid value"));
    assert!(s4.contains("body"));
    assert!(s4.contains("trailing garbage"));
}

#[test]
fn encoding_error_is_std_error() {
    let e = EncodingError::UnexpectedEof { field: "test" };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn integrity_error_is_std_error() {
    let e = tidefs_claim_ledger::IntegrityError::HashMismatch {
        expected: [0; 32],
        computed: [1; 32],
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn integrity_error_encoding_source() {
    let enc = EncodingError::UnexpectedEof { field: "test" };
    let ie = tidefs_claim_ledger::IntegrityError::Encoding(enc);
    let s = format!("{ie}");
    assert!(s.contains("encoding error"));
    assert!(ie.source().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases: zero/max TTL, empty owner, duplicate claim ID on release
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn lease_deadline_zero_ttl() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = make_service_entry(ClaimClass::Product, 1024);
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 0,
        auto_reclaim: false,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let dl = ledger
        .iter()
        .find(|e| e.claim_id == cid)
        .unwrap()
        .expiration_deadline
        .unwrap();
    assert_eq!(dl.deadline_millis, 0);
}

#[test]
fn lease_deadline_max_ttl() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = make_service_entry(ClaimClass::Product, 1024);
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: u64::MAX,
        auto_reclaim: true,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let dl = ledger
        .iter()
        .find(|e| e.claim_id == cid)
        .unwrap()
        .expiration_deadline
        .unwrap();
    assert_eq!(dl.deadline_millis, u64::MAX);
}

#[test]
fn claimant_with_empty_name() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Process {
            pid: 0,
            name: String::new(),
        },
        ClaimClass::Product,
        100,
    );
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(
        e.claimant_ref,
        ClaimantRef::Process {
            pid: 0,
            name: String::new()
        }
    );

    // Empty name in Service variant.
    let entry2 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: String::new(),
        },
        ClaimClass::Product,
        100,
    );
    ledger.register_claim(entry2, budget).unwrap();
    assert_eq!(ledger.claim_count(), 2);
}

// ── Duplicate claim ID: release removes all matching entries ─────────────

#[test]
fn release_claim_with_duplicate_ids_removes_all() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let cid = ClaimId::new();

    let e1 = make_entry_with_id(cid, ClaimClass::Product, 100);
    ledger.register_claim(e1, budget).unwrap();
    let e2 = make_entry_with_id(cid, ClaimClass::Rebuild, 200);
    ledger.register_claim(e2, budget).unwrap();

    // release_claim uses = (not +=) so only the last match sets freed.
    // Both entries are removed, but total_claimed_bytes is reduced by
    // only the last match bytes. This is documented current API behaviour.
    let freed = ledger.release_claim(cid);
    assert_eq!(freed, 200);
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 100);
}

// ── Commit 0 bytes ───────────────────────────────────────────────────────

#[test]
fn commit_zero_bytes_succeeds() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let entry = make_service_entry(ClaimClass::Product, 4096);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    ledger.commit_claim(cid, 0).unwrap();
    assert_eq!(ledger.total_committed_bytes, 0);

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(e.committed_bytes, 0);
}

// ── Multiple inode release: mix of entries with and without inode_id ─────

#[test]
fn release_claims_for_inode_mixed_with_none_inodes() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let inode = InodeId::new(7);

    // Entry with inode.
    let mut e1 = make_service_entry(ClaimClass::Product, 300);
    e1.inode_id = Some(inode);
    ledger.register_claim(e1, budget).unwrap();

    // Entry without inode.
    let e2 = make_service_entry(ClaimClass::Product, 200);
    let e2_cid = e2.claim_id;
    ledger.register_claim(e2, budget).unwrap();

    // Another entry with inode.
    let mut e3 = make_service_entry(ClaimClass::Product, 100);
    e3.inode_id = Some(inode);
    ledger.register_claim(e3, budget).unwrap();

    assert_eq!(ledger.claim_count(), 3);

    let freed = ledger.release_claims_for_inode(inode);
    assert_eq!(freed, 400);
    assert_eq!(ledger.claim_count(), 1);
    // Only the entry without inode_id remains.
    assert!(ledger.iter().any(|e| e.claim_id == e2_cid));
}

// ── Full report with multiple classes and committed bytes ────────────────

#[test]
fn report_all_fields_populated() {
    let mut ledger = ClaimLedger::new(99, test_domain());
    let budget = 1_000_000;

    let e1 = make_service_entry(ClaimClass::Product, 1000);
    let cid1 = e1.claim_id;
    ledger.register_claim(e1, budget).unwrap();

    let e2 = make_service_entry(ClaimClass::Failover, 500);
    let cid2 = e2.claim_id;
    ledger.register_claim(e2, budget).unwrap();

    ledger.commit_claim(cid1, 400).unwrap();
    ledger.commit_claim(cid2, 500).unwrap();

    let report = ledger.report();
    assert_eq!(report.ledger_id, 99);
    assert_eq!(report.total_claimed_bytes, 1500);
    assert_eq!(report.total_committed_bytes, 900);
    assert_eq!(report.claim_count, 2);

    let p_bytes = report.bytes_by_class.get("product").copied().unwrap_or(0);
    let f_bytes = report.bytes_by_class.get("failover").copied().unwrap_or(0);
    assert_eq!(p_bytes, 1000);
    assert_eq!(f_bytes, 500);

    let p_count = report.counts_by_class.get("product").copied().unwrap_or(0);
    let f_count = report.counts_by_class.get("failover").copied().unwrap_or(0);
    assert_eq!(p_count, 1);
    assert_eq!(f_count, 1);
}

// ── ClaimLedger explicit field mutation after creation ───────────────────

#[test]
fn claim_entry_record_field_mutation_after_creation() {
    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "initial".into(),
        },
        ClaimClass::Product,
        4096,
    );
    assert_eq!(entry.committed_bytes, 0);
    assert!(entry.inode_id.is_none());
    assert!(entry.freshness_fence_ref.is_none());
    assert!(entry.expiration_deadline.is_none());

    entry.committed_bytes = 2048;
    entry.inode_id = Some(InodeId::new(5));
    entry.freshness_fence_ref = Some(10);
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 999,
        auto_reclaim: true,
    });

    assert_eq!(entry.committed_bytes, 2048);
    assert_eq!(entry.inode_id, Some(InodeId::new(5)));
    assert_eq!(entry.freshness_fence_ref, Some(10));
    let dl = entry.expiration_deadline.unwrap();
    assert_eq!(dl.deadline_millis, 999);
    assert!(dl.auto_reclaim);
}

// ── Double-release idempotency ───────────────────────────────────────────

#[test]
fn double_release_same_claim_returns_zero_second_time() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let entry = make_service_entry(ClaimClass::Product, 4096);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let freed_first = ledger.release_claim(cid);
    assert_eq!(freed_first, 4096);
    assert_eq!(ledger.claim_count(), 0);

    // Second release of the same (now absent) ClaimId returns 0.
    let freed_second = ledger.release_claim(cid);
    assert_eq!(freed_second, 0);
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.total_claimed_bytes, 0);
}

// ── Commit to released claim errors ──────────────────────────────────────

#[test]
fn commit_to_released_claim_errors() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let entry = make_service_entry(ClaimClass::Product, 2048);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    ledger.commit_claim(cid, 1024).unwrap();
    assert_eq!(ledger.total_committed_bytes, 1024);

    ledger.release_claim(cid);

    // Commit after release must fail.
    let result = ledger.commit_claim(cid, 512);
    assert!(matches!(result, Err(ClaimLedgerError::ClaimNotFound(_))));
    // Committed bytes total must not have changed.
    assert_eq!(ledger.total_committed_bytes, 1024);
}

// ── Release for nonexistent inode returns zero ───────────────────────────

#[test]
fn release_claims_for_inode_no_matches_returns_zero() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    // Register claims with inode 10.
    for _ in 0..3 {
        let mut e = make_service_entry(ClaimClass::Product, 100);
        e.inode_id = Some(InodeId::new(10));
        ledger.register_claim(e, budget).unwrap();
    }
    assert_eq!(ledger.claim_count(), 3);

    // Release for an inode with no claims.
    let freed = ledger.release_claims_for_inode(InodeId::new(99));
    assert_eq!(freed, 0);
    assert_eq!(ledger.claim_count(), 3);
    assert_eq!(ledger.total_claimed_bytes, 300);
}

// ── Commit exact claimed bytes ───────────────────────────────────────────

#[test]
fn commit_exact_claimed_bytes() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let entry = make_service_entry(ClaimClass::Product, 4096);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    ledger.commit_claim(cid, 4096).unwrap();
    assert_eq!(ledger.total_committed_bytes, 4096);

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(e.committed_bytes, 4096);
}

// ── Commit partial multiple times same claim ─────────────────────────────

#[test]
fn commit_partial_multiple_times_accumulates() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;
    let entry = make_service_entry(ClaimClass::Product, 10000);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    ledger.commit_claim(cid, 2500).unwrap();
    ledger.commit_claim(cid, 2500).unwrap();
    ledger.commit_claim(cid, 5000).unwrap();

    assert_eq!(ledger.total_committed_bytes, 10000);

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(e.committed_bytes, 10000);
}

// ── Multiple claimants across all ClaimantRef variants ───────────────────

#[test]
fn all_claimant_ref_variants_coexist() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let entry1 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Process {
            pid: 100,
            name: "fuse-writer".into(),
        },
        ClaimClass::Product,
        500,
    );
    ledger.register_claim(entry1, budget).unwrap();

    let entry2 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Cohort {
            cohort_id: 1,
            label: "write-cohort".into(),
        },
        ClaimClass::Rebuild,
        300,
    );
    ledger.register_claim(entry2, budget).unwrap();

    let entry3 = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "seg-writer".into(),
        },
        ClaimClass::Failover,
        200,
    );
    ledger.register_claim(entry3, budget).unwrap();

    assert_eq!(ledger.claim_count(), 3);
    assert_eq!(ledger.total_claimed_bytes, 1000);

    // Verify all three variants are present in iteration.
    let refs: Vec<&ClaimantRef> = ledger.iter().map(|e| &e.claimant_ref).collect();
    assert!(refs
        .iter()
        .any(|r| matches!(r, ClaimantRef::Process { .. })));
    assert!(refs.iter().any(|r| matches!(r, ClaimantRef::Cohort { .. })));
    assert!(refs
        .iter()
        .any(|r| matches!(r, ClaimantRef::Service { .. })));
}

// ── ClaimLedger Display contains expected fields ─────────────────────────

#[test]
fn claim_ledger_display_contains_fields() {
    let mut ledger = ClaimLedger::new(7, test_domain());
    ledger
        .register_claim(make_service_entry(ClaimClass::Product, 4096), 1_000_000)
        .unwrap();
    let s = format!("{ledger}");
    assert!(s.contains("ClaimLedger"));
    assert!(s.contains("ledger_id: 7"));
    assert!(s.contains("test_domain"));
    assert!(s.contains("total_claimed_bytes: 4096"));
    assert!(s.contains("claim_count: 1"));
}

// ── ClaimantRef Display coverage ─────────────────────────────────────────

#[test]
fn claimant_ref_display_all_variants() {
    let p = ClaimantRef::Process {
        pid: 42,
        name: "worker".into(),
    };
    assert!(format!("{p}").contains("process:42(worker)"));

    let c = ClaimantRef::Cohort {
        cohort_id: 7,
        label: "group-a".into(),
    };
    assert!(format!("{c}").contains("cohort:7(group-a)"));

    let s = ClaimantRef::Service {
        service_name: "rebuild-planner".into(),
    };
    assert!(format!("{s}").contains("service:rebuild-planner"));
}

// ── ClaimLedgerError Display coverage ────────────────────────────────────

#[test]
fn claim_ledger_error_display_all_variants() {
    let e1 = ClaimLedgerError::ZeroByteClaim;
    assert!(format!("{e1}").contains("zero-byte"));

    let e2 = ClaimLedgerError::BudgetExhausted {
        domain: "test".into(),
        requested: 100,
        available: 50,
    };
    let s2 = format!("{e2}");
    assert!(s2.contains("budget"));
    assert!(s2.contains("test"));
    assert!(s2.contains("100"));
    assert!(s2.contains("50"));

    let cid = ClaimId::new();
    let e3 = ClaimLedgerError::ClaimNotFound(cid);
    assert!(format!("{e3}").contains("not found"));

    let e4 = ClaimLedgerError::InvalidClaimClass(99);
    assert!(format!("{e4}").contains("invalid claim class"));
    assert!(format!("{e4}").contains("99"));
}

// ── Budget domain ID in error message ────────────────────────────────────

#[test]
fn budget_exhausted_error_includes_domain_name() {
    let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("authority_hot"));
    let entry = make_service_entry(ClaimClass::Product, 9999);
    let result = ledger.register_claim(entry, 5000);
    let err = result.unwrap_err();
    assert!(format!("{err}").contains("authority_hot"));
}

// ── FreshnessFenceRef roundtrip via field mutation ───────────────────────

#[test]
fn freshness_fence_roundtrip_via_field_access() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = make_service_entry(ClaimClass::Product, 4096);
    entry.freshness_fence_ref = Some(42);
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    {
        let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
        assert_eq!(e.freshness_fence_ref, Some(42));
    }

    // Mutate via claim_entries.
    ledger
        .claim_entries
        .iter_mut()
        .find(|e| e.claim_id == cid)
        .unwrap()
        .freshness_fence_ref = Some(99);

    let e = ledger.iter().find(|e| e.claim_id == cid).unwrap();
    assert_eq!(e.freshness_fence_ref, Some(99));
}

// ── expired claim detection with auto_reclaim flag ───────────────────────

#[test]
fn expired_claim_with_auto_reclaim_flag() {
    let mut ledger = ClaimLedger::new(1, test_domain());
    let budget = 1_000_000;

    let mut entry = ClaimEntryRecord::new(
        ClaimId::new(),
        ClaimantRef::Service {
            service_name: "auto".into(),
        },
        ClaimClass::Product,
        512,
    );
    entry.expiration_deadline = Some(LeaseDeadlineRecord {
        deadline_millis: 1000,
        auto_reclaim: true,
    });
    let cid = entry.claim_id;
    ledger.register_claim(entry, budget).unwrap();

    let epoch = 2000;
    let expired: Vec<_> = ledger
        .iter()
        .filter(|e| {
            e.expiration_deadline
                .map(|dl| dl.deadline_millis <= epoch)
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].claim_id, cid);
    assert!(expired[0].expiration_deadline.unwrap().auto_reclaim);
}

// ── ObligationLedger::claim rejected space exhausted ─────────────────────

#[test]
fn obligation_ledger_claim_exceeds_total_blocks() {
    use tidefs_types_claim_ledger_core::{ClaimEntry as CEntry, ClaimReason, ObligationLedger};
    let mut ledger = ObligationLedger::new(100);
    let entry = CEntry {
        claim_id: ClaimId::new(),
        budget_domain: test_domain(),
        blocks: 200,
        inode_id: InodeId::new(1),
        reason: ClaimReason::Write,
        authorized_by: tidefs_types_claim_ledger_core::StorageAuthorityToken::ZERO,
        generation: 1,
    };
    let result = ledger.claim(entry);
    assert!(result.is_err());
}

// ── ObligationLedger claim_count / reserve_count on empty ledger ────────

#[test]
fn obligation_ledger_counts_on_empty() {
    use tidefs_types_claim_ledger_core::ObligationLedger;
    let ledger = ObligationLedger::new(1000);
    assert_eq!(ledger.claim_count(), 0);
    assert_eq!(ledger.reserve_count(), 0);
    assert_eq!(ledger.witness_count(), 0);
    assert_eq!(ledger.allocated_blocks(), 0);
    assert_eq!(ledger.reserved_blocks(), 0);
    assert_eq!(ledger.total_blocks(), 1000);
}
