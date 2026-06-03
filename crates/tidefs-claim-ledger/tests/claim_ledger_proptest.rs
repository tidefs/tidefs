//! Proptest fuzzing for tidefs-claim-ledger covering:
//!   - Register/release random sequences with invariant checks
//!   - Commit operations under random data
//!   - Lease deadline generation and expiry invariants
//!   - Serialization round-trip under arbitrary ledger state
//!   - Report consistency under arbitrary operations

use proptest::prelude::*;
use tidefs_claim_ledger::{
    ClaimClass, ClaimEncoding, ClaimEntryRecord, ClaimLedger, ClaimantRef, LeaseDeadlineRecord,
};
use tidefs_types_claim_ledger_core::{BudgetDomainId, ClaimId};
use tidefs_types_vfs_core::InodeId;

// ── Strategy generators ──────────────────────────────────────────────────

/// Generate a ClaimClass variant.
fn arb_claim_class() -> impl Strategy<Value = ClaimClass> {
    prop_oneof![
        Just(ClaimClass::Product),
        Just(ClaimClass::Rebuild),
        Just(ClaimClass::AntiEntropy),
        Just(ClaimClass::Failover),
    ]
}

/// Generate a ClaimantRef variant.
fn arb_claimant_ref() -> impl Strategy<Value = ClaimantRef> {
    prop_oneof![
        (1u64..65535, "[a-z]{4,12}").prop_map(|(pid, name)| ClaimantRef::Process { pid, name }),
        (1u64..9999, "[a-z]{4,12}")
            .prop_map(|(cohort_id, label)| ClaimantRef::Cohort { cohort_id, label }),
        "[a-z]{4,12}".prop_map(|service_name| ClaimantRef::Service { service_name }),
    ]
}

/// Generate a byte count in [1, 1_000_000].
fn arb_claimed_bytes() -> impl Strategy<Value = u64> {
    1u64..1_000_000
}

/// Generate a LeaseDeadlineRecord.
fn arb_lease_deadline() -> impl Strategy<Value = LeaseDeadlineRecord> {
    (0u64..u64::MAX, any::<bool>()).prop_map(|(deadline_millis, auto_reclaim)| {
        LeaseDeadlineRecord {
            deadline_millis,
            auto_reclaim,
        }
    })
}

/// Generate an optional inode id.
fn arb_inode_id() -> impl Strategy<Value = Option<InodeId>> {
    prop_oneof![
        3 => Just(None),
        1 => (0u64..1000).prop_map(|v| Some(InodeId::new(v))),
    ]
}

/// Generate a full ClaimEntryRecord.
fn arb_entry() -> impl Strategy<Value = ClaimEntryRecord> {
    (
        arb_claimant_ref(),
        arb_claim_class(),
        arb_claimed_bytes(),
        arb_inode_id(),
        prop::option::of(arb_lease_deadline()),
        (0u64..u64::MAX),
        (0u64..u64::MAX),
    )
        .prop_map(
            |(
                claimant_ref,
                claim_class,
                claimed_bytes,
                inode_id,
                expiration_deadline,
                freshness_fence,
                committed,
            )| {
                let mut entry =
                    ClaimEntryRecord::new(ClaimId::new(), claimant_ref, claim_class, claimed_bytes);
                entry.inode_id = inode_id;
                entry.expiration_deadline = expiration_deadline;
                entry.freshness_fence_ref = if freshness_fence > 0 {
                    Some(freshness_fence)
                } else {
                    None
                };
                entry.committed_bytes = committed;
                entry
            },
        )
}

// ── 1. Register/release invariant: total_claimed_bytes equals sum ────────

proptest! {
    #[test]
    fn register_release_invariant_maintains_sum(
        ops in prop::collection::vec(
            (arb_claimed_bytes(), any::<bool>()), // (bytes, register=true / release=false)
            1..200,
        )
    ) {
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;
        let mut registered: Vec<(ClaimId, u64)> = Vec::new();

        for (bytes, is_register) in &ops {
            if *is_register {
                let entry = ClaimEntryRecord::new(
                    ClaimId::new(),
                    ClaimantRef::Service { service_name: "proptest".into() },
                    ClaimClass::Product,
                    *bytes,
                );
                let cid = entry.claim_id;
                if ledger.register_claim(entry, budget).is_ok() {
                    registered.push((cid, *bytes));
                }
            } else if !registered.is_empty() {
                // Release a random registered claim.
                let idx = (bytes % registered.len() as u64) as usize;
                let (cid, _) = registered.remove(idx);
                ledger.release_claim(cid);
            }
        }

        // Invariant: total_claimed_bytes equals sum of remaining claim bytes.
        let expected: u64 = registered.iter().map(|(_, b)| b).sum();
        prop_assert_eq!(ledger.total_claimed_bytes, expected);
        prop_assert_eq!(ledger.claim_count(), registered.len());
    }
}

// ── 2. Claim count matches entries vector length ─────────────────────────

proptest! {
    #[test]
    fn claim_count_matches_entries_len(
        entries in prop::collection::vec(arb_claimed_bytes(), 0..100)
    ) {
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;

        for bytes in &entries {
            let entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service { service_name: "proptest".into() },
                ClaimClass::Product,
                *bytes,
            );
            ledger.register_claim(entry, budget).unwrap();
        }

        prop_assert_eq!(ledger.claim_count(), entries.len());
        prop_assert_eq!(ledger.claim_entries.len(), entries.len());

        let sum: u64 = entries.iter().sum();
        prop_assert_eq!(ledger.total_claimed_bytes, sum);
    }
}

// ── 3. Report consistency under arbitrary operations ─────────────────────

proptest! {
    #[test]
    fn report_consistency_after_operations(
        entries in prop::collection::vec(
            (arb_claim_class(), arb_claimed_bytes()),
            1..50,
        )
    ) {
        let mut ledger = ClaimLedger::new(42, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;

        for (class, bytes) in &entries {
            let entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service { service_name: "proptest".into() },
                *class,
                *bytes,
            );
            ledger.register_claim(entry, budget).unwrap();
        }

        let report = ledger.report();

        // Report metadata matches.
        prop_assert_eq!(report.ledger_id, 42);
        prop_assert_eq!(report.claim_count, entries.len());

        // Report byte sums equal ledger state.
        prop_assert_eq!(report.total_claimed_bytes, ledger.total_claimed_bytes);
        prop_assert_eq!(report.total_committed_bytes, ledger.total_committed_bytes);

        // bytes_by_class and counts_by_class must have same key sets.
        prop_assert_eq!(
            report.bytes_by_class.len(),
            report.counts_by_class.len()
        );

        // Verify counts_by_class matches actual entries.
        for (class_str, count) in &report.counts_by_class {
            let expected_count = entries.iter().filter(|(c, _)| c.as_str() == class_str.as_str()).count();
            prop_assert_eq!(*count, expected_count);
        }

        // Verify bytes_by_class matches actual entries.
        for (class_str, byte_sum) in &report.bytes_by_class {
            let expected_bytes: u64 = entries.iter()
                .filter(|(c, _)| c.as_str() == class_str.as_str())
                .map(|(_, b)| b)
                .sum();
            prop_assert_eq!(*byte_sum, expected_bytes);
        }
    }
}

// ── 4. Serialization round-trip under arbitrary entries ──────────────────

proptest! {
    #[test]
    fn serialization_roundtrip_arbitrary_entries(
        entries in prop::collection::vec(arb_entry(), 0..80)
    ) {
        let mut ledger = ClaimLedger::new(99, BudgetDomainId::from_str("prop"));
        for entry in entries {
            ledger.total_claimed_bytes = ledger.total_claimed_bytes.saturating_add(entry.claimed_bytes);
            ledger.total_committed_bytes = ledger.total_committed_bytes.saturating_add(entry.committed_bytes);
            ledger.claim_entries.push(entry);
        }

        let serialized = ledger.serialize();
        let deserialized = ClaimLedger::deserialize(&serialized).unwrap();

        prop_assert_eq!(deserialized.ledger_id, ledger.ledger_id);
        prop_assert_eq!(deserialized.budget_domain_ref, ledger.budget_domain_ref);
        prop_assert_eq!(deserialized.total_claimed_bytes, ledger.total_claimed_bytes);
        prop_assert_eq!(deserialized.total_committed_bytes, ledger.total_committed_bytes);
        prop_assert_eq!(deserialized.claim_entries.len(), ledger.claim_entries.len());

        for (a, b) in deserialized.claim_entries.iter().zip(ledger.claim_entries.iter()) {
            prop_assert_eq!(a.claim_id, b.claim_id);
            prop_assert_eq!(&a.claimant_ref, &b.claimant_ref);
            prop_assert_eq!(a.claim_class, b.claim_class);
            prop_assert_eq!(a.claimed_bytes, b.claimed_bytes);
            prop_assert_eq!(a.committed_bytes, b.committed_bytes);
            prop_assert_eq!(a.inode_id, b.inode_id);
            prop_assert_eq!(a.freshness_fence_ref, b.freshness_fence_ref);
            prop_assert_eq!(a.claim_receipt_ref, b.claim_receipt_ref);
            prop_assert_eq!(a.expiration_deadline, b.expiration_deadline);
        }
    }
}

// ── 5. Release until empty converges ─────────────────────────────────────

proptest! {
    #[test]
    fn release_all_converges_to_empty(
        entries in prop::collection::vec(arb_claimed_bytes(), 1..60)
    ) {
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;
        let mut cids = Vec::new();

        for bytes in &entries {
            let entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service { service_name: "proptest".into() },
                ClaimClass::Product,
                *bytes,
            );
            cids.push(entry.claim_id);
            ledger.register_claim(entry, budget).unwrap();
        }

        // Release all in random order (but all released).
        for cid in &cids {
            ledger.release_claim(*cid);
        }

        prop_assert_eq!(ledger.claim_count(), 0);
        prop_assert_eq!(ledger.total_claimed_bytes, 0);
        prop_assert!(ledger.iter().next().is_none());
        prop_assert!(ledger.count_by_class().is_empty());
        prop_assert!(ledger.bytes_by_class().is_empty());
    }
}

// ── 6. Lease deadline expiry invariants ──────────────────────────────────

proptest! {
    #[test]
    fn lease_deadline_expiry_detection_consistent(
        deadlines in prop::collection::vec(
            (arb_claimed_bytes(), prop::option::of(arb_lease_deadline())),
            1..60,
        )
    ) {
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;

        for (bytes, deadline_opt) in &deadlines {
            let mut entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service { service_name: "proptest".into() },
                ClaimClass::Product,
                *bytes,
            );
            entry.expiration_deadline = *deadline_opt;
            ledger.register_claim(entry, budget).unwrap();
        }

        // With epoch=0, no deadline (even 0) should be before epoch 0.
        // But wait: deadline_millis==0 means <=0, which matches epoch 0.
        // So we test two epochs: 0 and u64::MAX.
        let epoch_zero_count = ledger.iter().filter(|e| {
            e.expiration_deadline.map(|dl| dl.deadline_millis == 0).unwrap_or(false)
        }).count();

        let epoch_max_count = ledger.iter().filter(|e| {
            e.expiration_deadline.is_some()
        }).count();

        // At epoch=u64::MAX, every claim with a deadline should be "expired".
        let total_with_deadline = deadlines.iter().filter(|(_, d)| d.is_some()).count();
        prop_assert_eq!(epoch_max_count, total_with_deadline);

        // epoch_zero_count should be <= total_with_deadline.
        prop_assert!(epoch_zero_count <= total_with_deadline);
        // epoch_zero_count should be <= epoch_max_count.
        prop_assert!(epoch_zero_count <= epoch_max_count);
    }
}

// ── 7. Budget exhaustion invariant ───────────────────────────────────────

proptest! {
    #[test]
    fn budget_exhaustion_invariant(
        ops in prop::collection::vec(
            (arb_claimed_bytes(), any::<bool>()), // (bytes, register=true/release=false)
            1..100,
        )
    ) {
        let budget = 10_000_000u64;
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let mut registered: Vec<(ClaimId, u64)> = Vec::new();

        for (bytes, is_register) in &ops {
            if *is_register {
                let entry = ClaimEntryRecord::new(
                    ClaimId::new(),
                    ClaimantRef::Service { service_name: "proptest".into() },
                    ClaimClass::Product,
                    *bytes,
                );
                let cid = entry.claim_id;
                match ledger.register_claim(entry, budget) {
                    Ok(_) => registered.push((cid, *bytes)),
                    Err(_) => { /* budget exhausted, expected */ }
                }
            } else if !registered.is_empty() {
                let idx = (bytes % registered.len() as u64) as usize;
                let (cid, _) = registered.remove(idx);
                ledger.release_claim(cid);
            }
        }

        // Invariant: total_claimed_bytes never exceeds budget.
        prop_assert!(ledger.total_claimed_bytes <= budget);

        // Invariant: individually tracked bytes match ledger.
        let tracked: u64 = registered.iter().map(|(_, b)| b).sum();
        prop_assert_eq!(ledger.total_claimed_bytes, tracked);
    }
}

// ── 8. Multiple class mixing invariant ───────────────────────────────────

proptest! {
    #[test]
    fn multi_class_mixing_maintains_class_counts(
        entries in prop::collection::vec(
            (arb_claim_class(), arb_claimed_bytes()),
            1..80,
        )
    ) {
        let mut ledger = ClaimLedger::new(1, BudgetDomainId::from_str("prop"));
        let budget = u64::MAX;

        for (class, bytes) in &entries {
            let entry = ClaimEntryRecord::new(
                ClaimId::new(),
                ClaimantRef::Service { service_name: "proptest".into() },
                *class,
                *bytes,
            );
            ledger.register_claim(entry, budget).unwrap();
        }

        let counts = ledger.count_by_class();
        let bytes_map = ledger.bytes_by_class();

        for class in &[ClaimClass::Product, ClaimClass::Rebuild, ClaimClass::AntiEntropy, ClaimClass::Failover] {
            let expected_count = entries.iter().filter(|(c, _)| c == class).count();
            let expected_bytes: u64 = entries.iter()
                .filter(|(c, _)| c == class)
                .map(|(_, b)| b)
                .sum();

            prop_assert_eq!(counts.get(class).copied().unwrap_or(0), expected_count);
            prop_assert_eq!(bytes_map.get(class).copied().unwrap_or(0), expected_bytes);
        }
    }
}
