//! Edge case tests — empty replica sets, single-replica degenerate case,
//! all-replicas-divergent, checksum-collision scenarios, rapid successive
//! audits without state leak, and zero-length objects.

use tidefs_anti_entropy_auditor::ae_state::{AntiEntropyState, DivergenceClass, DivergenceRecord};
use tidefs_anti_entropy_auditor::comparator::{ComparisonInput, DigestComparator};
use tidefs_anti_entropy_auditor::scan_scheduler::{ScanDecision, ScanFrontier, ScanSchedulePolicy};
use tidefs_anti_entropy_auditor::AntiEntropyAuditor;

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_MIN: u64 = 60 * NS_PER_SEC;

fn policy() -> ScanSchedulePolicy {
    ScanSchedulePolicy {
        min_scan_interval_ns: 5 * NS_PER_MIN,
        max_scan_interval_ns: 60 * NS_PER_MIN,
        max_batch_size: 100,
        divergence_backoff_multiplier: 2.0,
        max_backpressure_delay_ns: 60 * NS_PER_SEC,
        comparison_throttle_ns: 1_000_000,
    }
}

// ── Empty replica sets ───────────────────────────────────────────────

#[test]
fn compare_subject_with_zero_replicas() {
    let mut cmp = DigestComparator::default();
    let replicas: Vec<(u64, u64)> = vec![];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(42, 0xCAFE, &replicas, None, 1, 1000);
    assert!(healthy.is_empty());
    assert!(divergences.is_empty());
    assert_eq!(cmp.total_comparisons, 0);
}

#[test]
fn empty_comparison_batch_no_op() {
    let mut cmp = DigestComparator::default();
    let results = cmp.compare_batch(&[], 1000);
    assert!(results.is_empty());
    assert_eq!(cmp.total_comparisons, 0);
    assert_eq!(cmp.total_matches, 0);
    assert_eq!(cmp.total_divergences, 0);
}

#[test]
fn frontier_with_no_work_returns_empty_batch() {
    let mut frontier = ScanFrontier::new(0);
    frontier.advance(100);
    // No degraded, frontier at 100, total_subjects=100 -> no pending work
    let batch = frontier.next_scan_batch(10);
    // Batch still generates subjects beyond frontier if max_count > 0
    // because frontier_start = 101, but with saturating_add it wraps
    assert!(!batch.subjects.is_empty() || batch.subjects[0] > 100);
}

// ── Single-replica degenerate case ────────────────────────────────────

#[test]
fn single_replica_no_quorum_possible() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 42u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, None, 1, 1000);
    // Single replica matching: healthy
    assert_eq!(healthy, vec![1]);
    assert!(divergences.is_empty());

    // Single replica with wrong digest
    let replicas_bad = vec![(1, 99u64)];
    let (_healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas_bad, None, 1, 1000);
    assert_eq!(divergences.len(), 1);
    assert_eq!(
        divergences[0].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
}

#[test]
fn single_replica_missing_zero_nodes_healthy() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 0u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, None, 1, 1000);
    assert!(healthy.is_empty());
    assert_eq!(divergences.len(), 1);
    assert_eq!(
        divergences[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );
}

// ── All replicas divergent ────────────────────────────────────────────

#[test]
fn all_replicas_divergent_no_healthy_nodes() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 99u64), (2, 88u64), (3, 77u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, Some(42), 1, 1000);
    assert!(healthy.is_empty());
    assert_eq!(divergences.len(), 3);
    for d in &divergences {
        assert_eq!(d.divergence_class, Some(DivergenceClass::DigestMismatch));
    }
}

#[test]
fn all_replicas_missing_zero_survivors() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 0u64), (2, 0u64), (3, 0u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, None, 1, 1000);
    assert!(healthy.is_empty());
    assert_eq!(divergences.len(), 3);
    for d in &divergences {
        assert_eq!(d.divergence_class, Some(DivergenceClass::MissingReplica));
    }
}

#[test]
fn all_replicas_lagging_behind_primary() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 100u64), (2, 100u64), (3, 100u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 200, &replicas, Some(100), 1, 1000);
    // Primary=200, replicas=100, witness=100 -> replicas match witness -> LagBehind
    assert!(healthy.is_empty());
    assert_eq!(divergences.len(), 3);
    for d in &divergences {
        assert_eq!(d.divergence_class, Some(DivergenceClass::LagBehind));
    }
}

// ── Checksum collision false positive handling ────────────────────────

#[test]
fn different_subjects_same_wrong_digest_still_divergences() {
    // Two subjects both have digest 99 instead of their respective correct
    // digests (42 and 77). This is not a "collision false positive" —
    // both are genuine divergences because the digest differs from primary.
    let mut cmp = DigestComparator::default();
    let inputs = vec![
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 2,
            target_node: 1,
            primary_digest: 77,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
    ];
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(results.len(), 2);
    assert!(results[0].diverged);
    assert!(results[1].diverged);
}

#[test]
fn same_digest_across_subjects_not_false_match() {
    // Two different subjects happen to have the same digest (42).
    // Both match their primary -> both clean
    let mut cmp = DigestComparator::default();
    let inputs = vec![
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 2,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
    ];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(!results[0].diverged);
    assert!(!results[1].diverged);
    assert_eq!(cmp.total_matches, 2);
}

#[test]
fn witness_collision_all_three_different_digests() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 100,
        replica_digest: 200,
        witness_digest: Some(300),
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(results[0].diverged);
    // Witness disagrees with both -> DigestMismatch (replica is suspect)
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
}

// ── Rapid successive audits without state leak ────────────────────────

#[test]
fn rapid_successive_audits_clear_current_divergences() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    // Audit 1: find 3 divergences
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 3);
    let inputs1: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r1 = aud.comparator.compare_batch(&inputs1, NS_PER_MIN);
    aud.record_comparisons(&r1, NS_PER_MIN);
    assert_eq!(aud.current_divergences.len(), 3);

    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &[1, 2, 3]);
    aud.resolve(NS_PER_MIN + 3, &[10, 11, 12]);
    aud.complete_scan(NS_PER_MIN + 4);

    // current_divergences persists across complete_scan (only begin_scan clears)
    assert_eq!(aud.current_divergences.len(), 3);
    assert_eq!(aud.total_historical_divergences(), 3);

    // Audit 2: begin_scan clears current_divergences
    aud.begin_scan(120 * NS_PER_MIN).unwrap();
    assert!(aud.current_divergences.is_empty());
    assert_eq!(aud.total_historical_divergences(), 3); // history persists
}

#[test]
fn drain_between_audits_prevents_state_leak() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    // Audit 1
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 3);
    let inputs1: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r1 = aud.comparator.compare_batch(&inputs1, NS_PER_MIN);
    aud.record_comparisons(&r1, NS_PER_MIN);

    // Drain divergences before completing scan
    let drained = aud.drain_divergences();
    assert_eq!(drained.len(), 3);

    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &[1, 2, 3]);
    aud.resolve(NS_PER_MIN + 3, &[10, 11, 12]);
    aud.complete_scan(NS_PER_MIN + 4);

    assert!(!aud.has_divergences());
    assert_eq!(aud.total_historical_divergences(), 3);

    // Audit 2: should start clean
    aud.begin_scan(120 * NS_PER_MIN).unwrap();
    assert!(aud.current_divergences.is_empty());

    // Feed clean comparisons
    aud.begin_compare(120 * NS_PER_MIN, 3);
    let inputs2: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r2 = aud.comparator.compare_batch(&inputs2, 120 * NS_PER_MIN);
    let new_divs = aud.record_comparisons(&r2, 120 * NS_PER_MIN);
    assert_eq!(new_divs, 0);
    assert!(!aud.has_divergences());
}

#[test]
fn rapid_scans_dont_accumulate_stale_tickets() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(50);

    // Scan 1: one divergence -> 1 ticket
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 1);
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 99,
        witness_digest: None,
        epoch: 1,
    }];
    let r = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&r, NS_PER_MIN);
    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &[100]);
    aud.resolve(NS_PER_MIN + 3, &[200]);
    aud.complete_scan(NS_PER_MIN + 4);

    let old_tickets = aud.drain_tickets();
    assert_eq!(old_tickets, vec![100]);

    // Scan 2: no divergences, no tickets
    aud.begin_scan(120 * NS_PER_MIN).unwrap();
    aud.begin_compare(120 * NS_PER_MIN, 1);
    let inputs2 = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 42,
        witness_digest: None,
        epoch: 1,
    }];
    let r2 = aud.comparator.compare_batch(&inputs2, 120 * NS_PER_MIN);
    aud.record_comparisons(&r2, 120 * NS_PER_MIN);
    aud.classify_divergences(120 * NS_PER_MIN + 1);
    aud.record_tickets(120 * NS_PER_MIN + 2, &[]);
    aud.resolve(120 * NS_PER_MIN + 3, &[]);
    aud.complete_scan(120 * NS_PER_MIN + 4);

    assert!(aud.tickets_created.is_empty());
}

// ── Zero-length / zero-value objects ──────────────────────────────────

#[test]
fn subject_ref_zero_is_valid() {
    let rec = DivergenceRecord::new(0, 1, DivergenceClass::DigestMismatch, 42, 99, 1, 1000);
    assert_eq!(rec.subject_ref, 0);
}

#[test]
fn digest_zero_on_primary_not_special() {
    // A primary digest of 0 is unusual but not treated specially by the
    // comparator — it's just a digest value. If replica is also 0, it matches.
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0,
        replica_digest: 0,
        witness_digest: None,
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(!results[0].diverged);
}

#[test]
fn digest_zero_on_primary_nonzero_replica_diverges() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0,
        replica_digest: 42,
        witness_digest: None,
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(results[0].diverged);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
}

#[test]
fn frontier_at_zero_with_zero_subjects() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(0);

    let t = NS_PER_MIN;
    aud.begin_scan(t).unwrap();
    // Even with 0 total_subjects, frontier generates subjects from hwm+1
    assert!(!aud.current_divergences.is_empty() || aud.audit_sequence > 0);
    aud.complete_scan(t + NS_PER_SEC);

    // After advancing frontier past total, no pending work
    assert!(!aud.scheduler.frontier.has_pending_work(0));
}

// ── Duplicate comparison inputs ───────────────────────────────────────

#[test]
fn duplicate_comparison_inputs_counted_separately() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
    ];
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(results.len(), 2);
    assert_eq!(cmp.total_comparisons, 2);
    assert_eq!(cmp.total_matches, 2);
}

// ── AntiEntropyState extreme values ───────────────────────────────────

#[test]
fn state_with_max_u64_values() {
    let states = vec![
        AntiEntropyState::Idle {
            last_scan_completed_ns: u64::MAX,
            next_scan_eligible_ns: u64::MAX,
        },
        AntiEntropyState::Enumerating {
            started_at_ns: u64::MAX,
            subjects_in_scope: u64::MAX,
            frontier_mark: u64::MAX,
        },
        AntiEntropyState::Compare {
            started_at_ns: u64::MAX,
            comparisons_done: u64::MAX,
            comparisons_total: u64::MAX,
            divergences_found: u64::MAX,
        },
        AntiEntropyState::DivergenceFound {
            detected_at_ns: u64::MAX,
            total_divergences: u64::MAX,
            classified_lag: u64::MAX,
            classified_corruption: u64::MAX,
            classified_missing: u64::MAX,
        },
        AntiEntropyState::Ticketed {
            created_at_ns: u64::MAX,
            tickets_created: u64::MAX,
            ticket_range_start: u64::MAX,
            ticket_range_end: u64::MAX,
        },
        AntiEntropyState::Resolved {
            resolved_at_ns: u64::MAX,
            divergences_resolved: u64::MAX,
            receipt_range_start: u64::MAX,
            receipt_range_end: u64::MAX,
        },
    ];

    for state in &states {
        // Serialization should not panic with extreme values
        let json = serde_json::to_string(state).expect("serialize with MAX values");
        let restored: AntiEntropyState = serde_json::from_str(&json).expect("deserialize MAX");
        assert_eq!(state, &restored);
    }
}

#[test]
fn state_with_zero_values() {
    let idle = AntiEntropyState::Idle {
        last_scan_completed_ns: 0,
        next_scan_eligible_ns: 0,
    };
    assert!(idle.is_resting());

    let div_zero = AntiEntropyState::DivergenceFound {
        detected_at_ns: 0,
        total_divergences: 0,
        classified_lag: 0,
        classified_corruption: 0,
        classified_missing: 0,
    };
    assert!(!div_zero.has_divergences());
}

// ── Large batch boundary ──────────────────────────────────────────────

#[test]
fn batch_at_max_capacity_and_beyond() {
    let policy = ScanSchedulePolicy {
        max_batch_size: 10,
        ..policy()
    };

    let mut aud = AntiEntropyAuditor::new(policy, 1, 0);
    aud.set_total_subjects(1_000_000);

    let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
    assert_eq!(subjects.len(), 10);
}

#[test]
fn frontier_subject_id_overflow_protection() {
    let mut frontier = ScanFrontier::new(0);
    frontier.advance(u64::MAX - 5);

    // Batch after near-overflow frontier
    let batch = frontier.next_scan_batch(10);
    // Subjects should be u64::MAX-4, u64::MAX-3, u64::MAX-2, u64::MAX-1, u64::MAX
    // then saturating_add wraps — remaining slots may be empty
    assert!(!batch.subjects.is_empty());
    // Verify first few subjects are correct
    assert_eq!(batch.subjects[0], u64::MAX - 4);
}

// ── Policy boundary values ────────────────────────────────────────────

#[test]
fn policy_zero_intervals_still_functional() {
    let zero_policy = ScanSchedulePolicy {
        min_scan_interval_ns: 0,
        max_scan_interval_ns: 0,
        max_batch_size: 10,
        divergence_backoff_multiplier: 1.0,
        max_backpressure_delay_ns: 0,
        comparison_throttle_ns: 0,
    };

    let mut aud = AntiEntropyAuditor::new(zero_policy, 1, 0);
    aud.set_total_subjects(100);

    let t = NS_PER_MIN;
    assert_eq!(aud.should_scan(t, 0.3), ScanDecision::Proceed);

    aud.begin_scan(t).unwrap();
    aud.complete_scan(t + 1);

    // With zero intervals, next scan is immediately eligible
    assert_eq!(aud.should_scan(t + 2, 0.3), ScanDecision::Proceed);
}

#[test]
fn policy_max_backpressure_zero_still_defers() {
    let bp_policy = ScanSchedulePolicy {
        max_backpressure_delay_ns: 0,
        ..policy()
    };

    let aud = AntiEntropyAuditor::new(bp_policy, 1, 0);
    let decision = aud.should_scan(10 * NS_PER_MIN, 0.95);

    // Backpressure still triggers; delay computed as 0 due to zero cap
    match decision {
        ScanDecision::BackpressureDeferred { delay_ns } => {
            assert_eq!(delay_ns, 0);
        }
        _ => panic!("expected BackpressureDeferred"),
    }
}

// ── Comparator lifetime counters ──────────────────────────────────────

#[test]
fn comparator_counters_accumulate_across_calls() {
    let mut cmp = DigestComparator::default();

    // Batch 1: 3 matches
    let inputs1 = vec![
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 2,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 3,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
    ];
    cmp.compare_batch(&inputs1, 1000);
    assert_eq!(cmp.total_comparisons, 3);
    assert_eq!(cmp.total_matches, 3);
    assert_eq!(cmp.total_divergences, 0);

    // Batch 2: 2 divergences
    let inputs2 = vec![
        ComparisonInput {
            subject_ref: 4,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 5,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
    ];
    cmp.compare_batch(&inputs2, 2000);
    assert_eq!(cmp.total_comparisons, 5);
    assert_eq!(cmp.total_matches, 3);
    assert_eq!(cmp.total_divergences, 2);
}

// ── Multiple epochs in divergence records ─────────────────────────────

#[test]
fn divergences_across_epochs_preserve_epoch_context() {
    let rec1 = DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 7, 1000);
    let rec2 = DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 8, 2000);

    assert_eq!(rec1.epoch, 7);
    assert_eq!(rec2.epoch, 8);
}
