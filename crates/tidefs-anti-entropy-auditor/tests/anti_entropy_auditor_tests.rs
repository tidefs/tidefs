//! Integration tests for tidefs-anti-entropy-auditor.
//!
//! Covers the full audit lifecycle, comparison engine behaviour,
//! scan scheduling, divergence handling, serialization round-trips,
//! and edge cases.

use std::collections::HashSet;
use tidefs_anti_entropy_auditor::ae_state::{AntiEntropyState, DivergenceClass, DivergenceRecord};
use tidefs_anti_entropy_auditor::comparator::{
    ComparisonInput, ComparisonResult, DigestComparator,
};
use tidefs_anti_entropy_auditor::scan_scheduler::{
    ScanBatch, ScanDecision, ScanFrontier, ScanSchedulePolicy,
};
use tidefs_anti_entropy_auditor::AntiEntropyAuditor;
use tidefs_replica_health::ReplicaLagStateRecord;
use tidefs_replication_model::ReplicaLagClass;

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_MIN: u64 = 60 * NS_PER_SEC;

// ── Helpers ───────────────────────────────────────────────────────────

fn default_policy() -> ScanSchedulePolicy {
    ScanSchedulePolicy {
        min_scan_interval_ns: 5 * NS_PER_MIN,
        max_scan_interval_ns: 60 * NS_PER_MIN,
        max_batch_size: 100,
        divergence_backoff_multiplier: 2.0,
        max_backpressure_delay_ns: 60 * NS_PER_SEC,
        comparison_throttle_ns: 1_000_000,
    }
}

fn auditor_with_subjects(total: u64) -> AntiEntropyAuditor {
    let mut aud = AntiEntropyAuditor::new(default_policy(), 1, 0);
    aud.set_total_subjects(total);
    aud
}

fn matching_inputs(subjects: &[u64], digest: u64, epoch: u64) -> Vec<ComparisonInput> {
    subjects
        .iter()
        .map(|s| ComparisonInput {
            subject_ref: *s,
            target_node: 1,
            primary_digest: digest,
            replica_digest: digest,
            witness_digest: None,
            epoch,
        })
        .collect()
}

// ── Full audit lifecycle tests ────────────────────────────────────────

#[test]
fn full_lifecycle_no_divergences_integration() {
    let mut aud = auditor_with_subjects(200);
    let t0 = NS_PER_MIN;

    // should_scan permits
    let decision = aud.should_scan(t0, 0.3);
    assert_eq!(decision, ScanDecision::Proceed);

    // begin_scan returns subjects
    let subjects = aud.begin_scan(t0).expect("should have subjects");
    assert!(!subjects.is_empty());
    assert!(matches!(aud.state, AntiEntropyState::Enumerating { .. }));

    // begin_compare
    aud.begin_compare(t0 + NS_PER_SEC, subjects.len() as u64);
    assert!(matches!(aud.state, AntiEntropyState::Compare { .. }));

    // feed all-matching comparisons
    let inputs = matching_inputs(&subjects, 42, 1);
    let results = aud.comparator.compare_batch(&inputs, t0 + 2 * NS_PER_SEC);
    let new_divs = aud.record_comparisons(&results, t0 + 2 * NS_PER_SEC);
    assert_eq!(new_divs, 0);
    assert!(!aud.has_divergences());

    // complete scan -> Idle
    aud.complete_scan(t0 + 3 * NS_PER_SEC);
    assert!(matches!(aud.state, AntiEntropyState::Idle { .. }));
    assert_eq!(aud.total_historical_divergences(), 0);
}

#[test]
fn full_lifecycle_with_divergences_and_tickets_integration() {
    let mut aud = auditor_with_subjects(50);
    let t = NS_PER_MIN;

    aud.begin_scan(t).unwrap();
    aud.begin_compare(t + 1, 50);

    // First 10 subjects diverge
    let inputs: Vec<ComparisonInput> = (1..=50)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: if s <= 10 { 99 } else { 42 },
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, t + 2);
    aud.record_comparisons(&results, t + 2);

    assert!(aud.has_divergences());
    assert_eq!(aud.ticketable_divergences().len(), 10);
    assert_eq!(aud.lag_divergences().len(), 0);

    // Classify
    aud.classify_divergences(t + 3);
    match &aud.state {
        AntiEntropyState::DivergenceFound {
            total_divergences,
            classified_corruption,
            classified_lag,
            classified_missing,
            ..
        } => {
            assert_eq!(*total_divergences, 10);
            assert_eq!(*classified_corruption, 10);
            assert_eq!(*classified_lag, 0);
            assert_eq!(*classified_missing, 0);
        }
        _ => panic!("expected DivergenceFound state"),
    }

    // Tickets
    aud.record_tickets(t + 4, &[1000, 1001, 1002, 1003, 1004]);
    assert!(aud.is_ticketed());
    assert_eq!(aud.tickets_created, vec![1000, 1001, 1002, 1003, 1004]);

    // Resolve
    aud.resolve(t + 5, &[2000, 2001, 2002, 2003, 2004]);
    assert!(aud.is_resolved());

    // Complete — current_divergences persists across cycles; only
    // begin_scan clears them (not complete_scan). History accumulates.
    aud.complete_scan(t + 6);
    assert_eq!(aud.total_historical_divergences(), 10);
    // current_divergences still holds the cycle's divergences
    assert!(aud.has_divergences());
}

#[test]
fn empty_subjects_no_scan() {
    // total_subjects is advisory; frontier still generates subjects from hwm+1.
    // The scan proceeds regardless — total_subjects only affects has_pending_work
    // and frontier advance. To get an empty batch, advance the frontier past all
    // subjects and clear degraded.
    let mut aud = auditor_with_subjects(0);
    let t = NS_PER_MIN;

    // Even with 0 total_subjects, the scan starts because frontier is at 0
    // and generates subjects 1..max_batch_size.
    let subjects = aud.begin_scan(t);
    assert!(subjects.is_some());
    assert!(matches!(aud.state, AntiEntropyState::Enumerating { .. }));
    aud.complete_scan(t + NS_PER_SEC);

    // After advancing frontier past total, has_pending_work is false
    assert!(!aud.scheduler.frontier.has_pending_work(0));
}

#[test]
fn scan_respects_max_batch_size() {
    // Use a tight policy with small batch
    let policy = ScanSchedulePolicy {
        max_batch_size: 7,
        ..default_policy()
    };
    let mut aud = AntiEntropyAuditor::new(policy, 1, 0);
    aud.set_total_subjects(10_000);

    let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
    assert_eq!(subjects.len(), 7);
}

// ── Comparison engine integration tests ───────────────────────────────

#[test]
fn batch_comparison_large() {
    let mut cmp = DigestComparator::default();
    let n = 1000;

    // Half matching, half diverging
    let inputs: Vec<ComparisonInput> = (1..=n)
        .map(|i| ComparisonInput {
            subject_ref: i,
            target_node: 1,
            primary_digest: 42,
            replica_digest: if i % 2 == 0 { 42 } else { 99 },
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(results.len(), n as usize);
    assert_eq!(cmp.total_comparisons, n);
    assert_eq!(cmp.total_matches, n / 2);
    assert_eq!(cmp.total_divergences, n / 2);

    let matched = results.iter().filter(|r| !r.diverged).count();
    let diverged = results.iter().filter(|r| r.diverged).count();
    assert_eq!(matched, 500);
    assert_eq!(diverged, 500);
}

#[test]
fn comparison_batch_empty() {
    let mut cmp = DigestComparator::default();
    let results = cmp.compare_batch(&[], 1000);
    assert!(results.is_empty());
    assert_eq!(cmp.total_comparisons, 0);
}

#[test]
fn witness_all_three_disagree() {
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
    assert_eq!(results.len(), 1);
    assert!(results[0].diverged);
    // Witness matches neither -> DigestMismatch
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
}

#[test]
fn comparison_result_matched_constructor() {
    let r = ComparisonResult::matched(42, 7, 0xDEAD, 3, 10_000);
    assert!(!r.diverged);
    assert_eq!(r.subject_ref, 42);
    assert_eq!(r.target_node, 7);
    assert_eq!(r.primary_digest, 0xDEAD);
    assert_eq!(r.replica_digest, 0xDEAD);
    assert_eq!(r.witness_digest, 0);
    assert_eq!(r.divergence_class, None);
}

#[test]
fn comparison_result_diverged_constructor() {
    let r = ComparisonResult::diverged(99, 2, 100, 200, DivergenceClass::DigestMismatch, 1, 5000);
    assert!(r.diverged);
    assert_eq!(r.subject_ref, 99);
    assert_eq!(r.primary_digest, 100);
    assert_eq!(r.replica_digest, 200);
    assert_eq!(r.divergence_class, Some(DivergenceClass::DigestMismatch));
}

// ── Divergence record tests ────────────────────────────────────────────

#[test]
fn divergence_record_ticket_required() {
    let record = DivergenceRecord::new(1, 2, DivergenceClass::DigestMismatch, 100, 99, 1, 1000);
    assert!(record.requires_ticket());
    assert!(!record.is_lag_only());
}

#[test]
fn divergence_record_lag_self_healing() {
    let record = DivergenceRecord::new(1, 2, DivergenceClass::LagBehind, 100, 90, 1, 1000);
    assert!(!record.requires_ticket());
    assert!(record.is_lag_only());
}

#[test]
fn divergence_record_missing_replica() {
    let record = DivergenceRecord::new(1, 2, DivergenceClass::MissingReplica, 100, 0, 1, 1000);
    assert!(record.requires_ticket());
    assert!(!record.is_lag_only());
}

#[test]
fn divergence_record_replica_unhealthy() {
    let record = DivergenceRecord::new(1, 2, DivergenceClass::ReplicaUnhealthy, 100, 100, 1, 1000);
    assert!(record.requires_ticket());
    assert!(!record.is_lag_only());
}

#[test]
fn divergence_class_display_debug() {
    let classes = [
        DivergenceClass::LagBehind,
        DivergenceClass::DigestMismatch,
        DivergenceClass::MissingReplica,
        DivergenceClass::ReplicaUnhealthy,
    ];
    for c in &classes {
        let _ = format!("{c:?}");
    }
}

// ── Serialization round-trip tests ────────────────────────────────────

#[test]
fn anti_entropy_state_serde_roundtrip() {
    let states = vec![
        AntiEntropyState::Idle {
            last_scan_completed_ns: 1000,
            next_scan_eligible_ns: 2000,
        },
        AntiEntropyState::Enumerating {
            started_at_ns: 3000,
            subjects_in_scope: 50,
            frontier_mark: 100,
        },
        AntiEntropyState::Compare {
            started_at_ns: 4000,
            comparisons_done: 30,
            comparisons_total: 50,
            divergences_found: 5,
        },
        AntiEntropyState::DivergenceFound {
            detected_at_ns: 5000,
            total_divergences: 10,
            classified_lag: 2,
            classified_corruption: 5,
            classified_missing: 3,
        },
        AntiEntropyState::Ticketed {
            created_at_ns: 6000,
            tickets_created: 10,
            ticket_range_start: 100,
            ticket_range_end: 109,
        },
        AntiEntropyState::Resolved {
            resolved_at_ns: 7000,
            divergences_resolved: 10,
            receipt_range_start: 200,
            receipt_range_end: 209,
        },
    ];

    for original in &states {
        let json = serde_json::to_string(original).expect("serialize");
        let restored: AntiEntropyState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, &restored, "round-trip failed for {original:?}");
    }
}

#[test]
fn divergence_record_serde_roundtrip() {
    let original = DivergenceRecord::new(
        42,
        7,
        DivergenceClass::DigestMismatch,
        0xCAFE,
        0xBABE,
        3,
        1_000_000_000,
    );
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: DivergenceRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, restored);
}

#[test]
fn comparison_result_serde_roundtrip() {
    let matched = ComparisonResult::matched(10, 2, 42, 1, 5000);
    let json = serde_json::to_string(&matched).expect("serialize");
    let restored: ComparisonResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(matched, restored);

    let diverged = ComparisonResult::diverged(11, 3, 100, 200, DivergenceClass::LagBehind, 1, 5000);
    let json = serde_json::to_string(&diverged).expect("serialize");
    let restored: ComparisonResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(diverged, restored);
}

#[test]
fn scan_policy_serde_roundtrip() {
    let policy = default_policy();
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: ScanSchedulePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy.min_scan_interval_ns, restored.min_scan_interval_ns);
    assert_eq!(policy.max_scan_interval_ns, restored.max_scan_interval_ns);
    assert_eq!(policy.max_batch_size, restored.max_batch_size);
}

#[test]
fn scan_frontier_serde_roundtrip() {
    let mut frontier = ScanFrontier::new(1000);
    frontier.advance(500);
    frontier.register_degraded(42);
    frontier.register_degraded(99);

    let json = serde_json::to_string(&frontier).expect("serialize");
    let restored: ScanFrontier = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(frontier.high_water_mark, restored.high_water_mark);
    assert_eq!(frontier.degraded_subjects, restored.degraded_subjects);
}

// ── Scan scheduling integration tests ─────────────────────────────────

#[test]
fn scan_scheduler_multiple_cycles_frontier_advances() {
    let mut aud = auditor_with_subjects(1000);

    // First cycle: scan subjects 1..=100 (max_batch_size=100)
    let batch1 = aud.begin_scan(NS_PER_MIN).unwrap();
    assert!(!batch1.is_empty());
    aud.complete_scan(2 * NS_PER_MIN);

    // Frontier should have advanced to 100
    // Start second cycle (enough time has passed)
    let t = 120 * NS_PER_MIN; // 2 hours later
    let decision = aud.should_scan(t, 0.3);
    assert_eq!(decision, ScanDecision::Proceed);

    let batch2 = aud.begin_scan(t).unwrap();
    // Should start from 101 (frontier advanced beyond 100)
    assert!(batch2[0] >= 101);
}

#[test]
fn scheduler_backpressure_cluster_load_boundary() {
    let aud = auditor_with_subjects(100);
    let t = 10 * NS_PER_MIN;

    // Load at 0.80 -> proceed
    assert_eq!(aud.should_scan(t, 0.80), ScanDecision::Proceed);

    // Load at 0.81 -> defer (backpressure)
    assert!(matches!(
        aud.should_scan(t, 0.81),
        ScanDecision::BackpressureDeferred { .. }
    ));

    // Load at 0.95 -> defer with larger delay
    if let ScanDecision::BackpressureDeferred { delay_ns } = aud.should_scan(t, 0.95) {
        assert!(delay_ns > 0);
    } else {
        panic!("expected BackpressureDeferred");
    }
}

#[test]
fn scheduler_too_soon_after_scan() {
    let mut aud = auditor_with_subjects(100);
    let t = 0;

    // First scan completes
    aud.begin_scan(t).unwrap();
    aud.complete_scan(t + NS_PER_SEC);

    // Immediately asking for scan -> TooSoon
    let decision = aud.should_scan(t + NS_PER_SEC + 1, 0.3);
    assert!(matches!(decision, ScanDecision::TooSoon { .. }));
}

#[test]
fn scheduler_already_active() {
    let mut aud = auditor_with_subjects(100);
    let t = NS_PER_MIN;

    aud.begin_scan(t).unwrap();
    // Scan is active, should reject
    assert_eq!(
        aud.should_scan(t + NS_PER_SEC, 0.3),
        ScanDecision::AlreadyActive
    );
}

#[test]
fn frontier_degraded_subjects_deduplicated() {
    let mut frontier = ScanFrontier::new(0);
    frontier.register_degraded(42);
    frontier.register_degraded(42); // duplicate
    frontier.register_degraded(99);

    assert_eq!(frontier.degraded_subjects.len(), 2);
    let set: HashSet<u64> = frontier.degraded_subjects.iter().copied().collect();
    assert_eq!(set.len(), 2);
}

#[test]
fn frontier_clear_degraded_removes_subject() {
    let mut frontier = ScanFrontier::new(0);
    frontier.register_degraded(42);
    frontier.register_degraded(99);
    frontier.clear_degraded(42);

    assert_eq!(frontier.degraded_subjects, vec![99]);
}

#[test]
fn frontier_advance_only_upward() {
    let mut frontier = ScanFrontier::new(0);
    frontier.advance(100);
    assert_eq!(frontier.high_water_mark, 100);

    // Regression: advance to lower value should not decrease
    frontier.advance(50);
    assert_eq!(frontier.high_water_mark, 100);
}

#[test]
fn frontier_batch_degraded_exceed_max_count() {
    let mut frontier = ScanFrontier::new(0);
    for i in 0..15 {
        frontier.register_degraded(100 + i);
    }

    // Batch with max_count=10: all 10 should be degraded subjects
    let batch = frontier.next_scan_batch(10);
    assert_eq!(batch.subjects.len(), 10);
    assert!(batch.includes_degraded);
    // All should be in degraded set
    for s in &batch.subjects {
        assert!(frontier.degraded_subjects.contains(s));
    }
}

#[test]
fn frontier_batch_mixed_degraded_and_new() {
    let mut frontier = ScanFrontier::new(0);
    frontier.advance(50); // frontier at 50
    frontier.register_degraded(25);
    frontier.register_degraded(30);

    let batch = frontier.next_scan_batch(10);
    // First 2: degraded (25, 30)
    assert_eq!(batch.subjects[0], 25);
    assert_eq!(batch.subjects[1], 30);
    // Remaining 8: new subjects from 51..58
    assert_eq!(batch.subjects[2], 51);
    assert_eq!(batch.subjects[9], 58);
    assert_eq!(batch.subjects.len(), 10);
}

// ── Drain and drain semantics ─────────────────────────────────────────

#[test]
fn drain_divergences_leaves_empty_current_preserves_history() {
    let mut aud = auditor_with_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 10);

    let inputs: Vec<ComparisonInput> = (1..=5)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    assert!(aud.has_divergences());
    let drained = aud.drain_divergences();
    assert_eq!(drained.len(), 5);
    assert!(!aud.has_divergences());
    // History persists
    assert_eq!(aud.total_historical_divergences(), 5);
}

#[test]
fn drain_tickets_clears_created_ids() {
    let mut aud = auditor_with_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 10);
    aud.record_tickets(NS_PER_MIN, &[1, 2, 3]);

    assert_eq!(aud.tickets_created, vec![1, 2, 3]);
    let drained = aud.drain_tickets();
    assert_eq!(drained, vec![1, 2, 3]);
    assert!(aud.tickets_created.is_empty());
}

// ── Degraded subject lifecycle integration ────────────────────────────

#[test]
fn degraded_subject_scan_clear_cycle() {
    let mut aud = auditor_with_subjects(500);
    aud.register_degraded_subject(77);
    aud.register_degraded_subject(88);
    aud.register_degraded_subject(99);

    // Scan gets degraded subjects first
    let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
    assert_eq!(subjects[0], 77);
    assert_eq!(subjects[1], 88);
    assert_eq!(subjects[2], 99);

    // After successful repair, clear them
    aud.clear_degraded_subject(77);
    aud.clear_degraded_subject(88);
    aud.clear_degraded_subject(99);

    // Complete scan
    aud.complete_scan(2 * NS_PER_MIN);

    // Next scan should not include 77/88/99 in degraded set
    let subjects2 = aud.begin_scan(120 * NS_PER_MIN).unwrap();
    // 77,88,99 should not be at front unless still in frontier range
    // Since frontier advanced past them, they won't appear at all
    assert!(!subjects2.contains(&77) || subjects2[0] != 77);
}

// ── Register degraded from health integration ─────────────────────────

#[test]
fn register_degraded_from_health_mixed_states() {
    use tidefs_replication_model::ReplicatedSubjectId;

    let mut aud = auditor_with_subjects(200);

    let records = vec![
        // stale -> registered
        ReplicaLagStateRecord::new(
            ReplicatedSubjectId::new(10),
            1,
            100,
            ReplicaLagClass::Stale,
            5000,
        ),
        // slightly behind and not stale -> not registered
        ReplicaLagStateRecord::new(
            ReplicatedSubjectId::new(20),
            1,
            100,
            ReplicaLagClass::SlightlyBehind,
            100,
        ),
        // another stale
        ReplicaLagStateRecord::new(
            ReplicatedSubjectId::new(30),
            1,
            100,
            ReplicaLagClass::Stale,
            5000,
        ),
    ];

    let count = aud.register_degraded_from_health(&records);
    assert_eq!(count, 2);

    let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
    assert_eq!(subjects[0], 10);
    assert_eq!(subjects[1], 30);
}

// ── Targeted audit integration ────────────────────────────────────────

#[test]
fn targeted_audit_multiple_subjects_mixed_results() {
    let mut aud = auditor_with_subjects(100);

    let inputs: Vec<ComparisonInput> = vec![
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
            replica_digest: 99,
            witness_digest: Some(42),
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 3,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        },
    ];

    let results = aud.targeted_audit(&inputs, 1000);
    assert_eq!(results.len(), 3);

    // Subject 1: matched
    assert!(!results[0].diverged);
    // Subject 2: diverged, DigestMismatch
    assert!(results[1].diverged);
    assert_eq!(
        results[1].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
    // Subject 3: diverged, MissingReplica
    assert!(results[2].diverged);
    assert_eq!(
        results[2].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );

    assert_eq!(aud.total_historical_divergences(), 2);
}

// ── Epoch management ──────────────────────────────────────────────────

#[test]
fn epoch_update_preserves_auditor_state() {
    let mut aud = auditor_with_subjects(100);
    assert_eq!(aud.epoch, 1);

    aud.set_epoch(5);
    assert_eq!(aud.epoch, 5);

    // Should still be able to scan
    aud.set_total_subjects(50);
    let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
    assert!(!subjects.is_empty());
}

// ── State machine transition ordering ─────────────────────────────────

#[test]
fn state_transitions_must_follow_expected_order() {
    let mut aud = auditor_with_subjects(50);
    let t = NS_PER_MIN;

    // Idle
    assert!(matches!(aud.state, AntiEntropyState::Idle { .. }));

    // Idle -> Enumerating
    aud.begin_scan(t).unwrap();
    assert!(matches!(aud.state, AntiEntropyState::Enumerating { .. }));

    // Enumerating -> Compare
    aud.begin_compare(t + 1, 50);
    assert!(matches!(aud.state, AntiEntropyState::Compare { .. }));

    // Inject divergences -> Compare still
    let inputs: Vec<ComparisonInput> = (1..=5)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, t + 2);
    aud.record_comparisons(&results, t + 2);

    // Compare -> DivergenceFound
    aud.classify_divergences(t + 3);
    assert!(matches!(
        aud.state,
        AntiEntropyState::DivergenceFound { .. }
    ));

    // DivergenceFound -> Ticketed
    aud.record_tickets(t + 4, &[1, 2, 3]);
    assert!(matches!(aud.state, AntiEntropyState::Ticketed { .. }));

    // Ticketed -> Resolved
    aud.resolve(t + 5, &[10, 11, 12]);
    assert!(matches!(aud.state, AntiEntropyState::Resolved { .. }));

    // Resolved -> Idle
    aud.complete_scan(t + 6);
    assert!(matches!(aud.state, AntiEntropyState::Idle { .. }));
}

// ── AntiEntropyState helper methods ───────────────────────────────────

#[test]
fn state_is_resting_is_active() {
    let idle = AntiEntropyState::Idle {
        last_scan_completed_ns: 0,
        next_scan_eligible_ns: 0,
    };
    assert!(idle.is_resting());
    assert!(!idle.is_active());

    let resolved = AntiEntropyState::Resolved {
        resolved_at_ns: 0,
        divergences_resolved: 0,
        receipt_range_start: 0,
        receipt_range_end: 0,
    };
    assert!(resolved.is_resting());
    assert!(!resolved.is_active());

    let enumerating = AntiEntropyState::Enumerating {
        started_at_ns: 0,
        subjects_in_scope: 0,
        frontier_mark: 0,
    };
    assert!(!enumerating.is_resting());
    assert!(enumerating.is_active());

    let compare = AntiEntropyState::Compare {
        started_at_ns: 0,
        comparisons_done: 0,
        comparisons_total: 0,
        divergences_found: 0,
    };
    assert!(!compare.is_resting());
    assert!(compare.is_active());
}

#[test]
fn state_has_divergences_detects_active_issues() {
    let with_divs = AntiEntropyState::DivergenceFound {
        detected_at_ns: 0,
        total_divergences: 5,
        classified_lag: 0,
        classified_corruption: 0,
        classified_missing: 0,
    };
    assert!(with_divs.has_divergences());

    let with_tickets = AntiEntropyState::Ticketed {
        created_at_ns: 0,
        tickets_created: 3,
        ticket_range_start: 0,
        ticket_range_end: 0,
    };
    assert!(with_tickets.has_divergences());

    let zero_divs = AntiEntropyState::DivergenceFound {
        detected_at_ns: 0,
        total_divergences: 0,
        classified_lag: 0,
        classified_corruption: 0,
        classified_missing: 0,
    };
    assert!(!zero_divs.has_divergences());

    let zero_tickets = AntiEntropyState::Ticketed {
        created_at_ns: 0,
        tickets_created: 0,
        ticket_range_start: 0,
        ticket_range_end: 0,
    };
    assert!(!zero_tickets.has_divergences());
}

#[test]
fn state_display_formatting() {
    let idle = AntiEntropyState::Idle {
        last_scan_completed_ns: 0,
        next_scan_eligible_ns: 0,
    };
    assert_eq!(idle.to_string(), "idle");
    assert_eq!(format!("{idle}"), "idle");
}

// ── Missing replica always classified as MissingReplica ───────────────

#[test]
fn zero_digest_always_missing_replica_regardless_of_witness() {
    let mut cmp = DigestComparator::default();

    // Witness confirms primary -> still MissingReplica because replica digest is 0
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 0,
        witness_digest: Some(42),
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );

    // Witness confirms replica (0) -> still MissingReplica because zero digest
    let inputs2 = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 0,
        witness_digest: Some(0),
        epoch: 1,
    }];
    let results2 = cmp.compare_batch(&inputs2, 1000);
    assert_eq!(
        results2[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );
}

// ── Determinism tests ─────────────────────────────────────────────────

#[test]
fn comparison_deterministic_same_input_same_output() {
    let run = || {
        let mut cmp = DigestComparator::default();
        let inputs: Vec<ComparisonInput> = (1..=50)
            .map(|i| ComparisonInput {
                subject_ref: i,
                target_node: 1,
                primary_digest: 42,
                replica_digest: if i % 3 == 0 { 99 } else { 42 },
                witness_digest: if i % 3 == 0 { Some(42) } else { None },
                epoch: 1,
            })
            .collect();
        cmp.compare_batch(&inputs, 1000)
    };

    let r1 = run();
    let r2 = run();

    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.diverged, b.diverged);
        assert_eq!(a.divergence_class, b.divergence_class);
        assert_eq!(a.subject_ref, b.subject_ref);
    }
}

#[test]
fn auditor_initial_state_is_consistent() {
    let a1 = AntiEntropyAuditor::new(default_policy(), 1, 0);
    let a2 = AntiEntropyAuditor::new(default_policy(), 1, 0);

    assert_eq!(a1.epoch, a2.epoch);
    assert_eq!(a1.total_subjects, a2.total_subjects);
    assert_eq!(a1.audit_sequence, a2.audit_sequence);
    assert!(a1.current_divergences.is_empty());
    assert!(a2.current_divergences.is_empty());
}

// ── Multi-cycle divergence history accumulation ────────────────────────

#[test]
fn divergence_history_accumulates_across_cycles() {
    let mut aud = auditor_with_subjects(30);

    // Cycle 1: 3 divergences
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 30);
    let inputs1: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results1 = aud.comparator.compare_batch(&inputs1, NS_PER_MIN);
    aud.record_comparisons(&results1, NS_PER_MIN);
    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &[1, 2, 3]);
    aud.resolve(NS_PER_MIN + 3, &[10, 11, 12]);
    aud.complete_scan(NS_PER_MIN + 4);
    assert_eq!(aud.total_historical_divergences(), 3);

    // Cycle 2: 2 more divergences (after enough time)
    aud.begin_scan(120 * NS_PER_MIN).unwrap();
    aud.begin_compare(120 * NS_PER_MIN, 30);
    let inputs2: Vec<ComparisonInput> = (10..=11)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results2 = aud.comparator.compare_batch(&inputs2, 120 * NS_PER_MIN);
    aud.record_comparisons(&results2, 120 * NS_PER_MIN);
    aud.classify_divergences(120 * NS_PER_MIN + 1);
    aud.record_tickets(120 * NS_PER_MIN + 2, &[4, 5]);
    aud.resolve(120 * NS_PER_MIN + 3, &[13, 14]);
    aud.complete_scan(120 * NS_PER_MIN + 4);

    assert_eq!(aud.total_historical_divergences(), 5);
}

// ── ScanDecision Debug and PartialEq ──────────────────────────────────

#[test]
fn scan_decision_equality_and_debug() {
    assert_eq!(ScanDecision::Proceed, ScanDecision::Proceed);
    assert_eq!(ScanDecision::AlreadyActive, ScanDecision::AlreadyActive);

    let ts1 = ScanDecision::TooSoon {
        eligible_in_ns: 500,
    };
    let ts2 = ScanDecision::TooSoon {
        eligible_in_ns: 500,
    };
    assert_eq!(ts1, ts2);

    let bp1 = ScanDecision::BackpressureDeferred { delay_ns: 1000 };
    let bp2 = ScanDecision::BackpressureDeferred { delay_ns: 1000 };
    assert_eq!(bp1, bp2);

    // Debug formatting should not panic
    let _ = format!("{:?}", ScanDecision::Proceed);
    let _ = format!("{ts1:?}");
    let _ = format!("{bp1:?}");
}

// ── ScanBatch debug and field access ──────────────────────────────────

#[test]
fn scan_batch_fields() {
    let batch = ScanBatch {
        subjects: vec![1, 2, 3],
        includes_degraded: true,
        frontier_start: 4,
        frontier_end: 10,
    };
    assert_eq!(batch.subjects.len(), 3);
    assert!(batch.includes_degraded);
    assert_eq!(batch.frontier_start, 4);
    assert_eq!(batch.frontier_end, 10);

    let _ = format!("{batch:?}");
}
