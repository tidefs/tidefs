//! Reconciliation priority ordering tests — verify that divergence
//! records can be ordered by severity, age, affected object count,
//! and data-vs-metadata distinction for reconciliation scheduling.

use tidefs_anti_entropy_auditor::ae_state::{DivergenceClass, DivergenceRecord};
use tidefs_anti_entropy_auditor::comparator::ComparisonInput;
use tidefs_anti_entropy_auditor::scan_scheduler::ScanSchedulePolicy;
use tidefs_anti_entropy_auditor::AntiEntropyAuditor;

const NS_PER_MIN: u64 = 60_000_000_000;

fn policy() -> ScanSchedulePolicy {
    ScanSchedulePolicy {
        min_scan_interval_ns: 5 * NS_PER_MIN,
        max_scan_interval_ns: 60 * NS_PER_MIN,
        max_batch_size: 100,
        divergence_backoff_multiplier: 2.0,
        max_backpressure_delay_ns: 60_000_000_000,
        comparison_throttle_ns: 1_000_000,
    }
}

/// Severity rank: lower = more urgent.
fn severity_rank(class: DivergenceClass) -> u8 {
    match class {
        DivergenceClass::DigestMismatch => 0,
        DivergenceClass::MissingReplica => 1,
        DivergenceClass::ReplicaUnhealthy => 2,
        DivergenceClass::LagBehind => 3,
        DivergenceClass::WitnessDisagreement => 4,
    }
}

// ── Ordering by severity ─────────────────────────────────────────────

#[test]
fn sort_divergences_by_severity_most_critical_first() {
    let mut records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::LagBehind, 100, 90, 1, 1000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 2000),
        DivergenceRecord::new(3, 2, DivergenceClass::MissingReplica, 300, 0, 1, 3000),
        DivergenceRecord::new(4, 3, DivergenceClass::ReplicaUnhealthy, 400, 400, 1, 4000),
        DivergenceRecord::new(5, 1, DivergenceClass::DigestMismatch, 500, 499, 1, 5000),
    ];

    records.sort_by_key(|r| severity_rank(r.class));

    // DigestMismatch first, then MissingReplica, then ReplicaUnhealthy, then LagBehind
    assert_eq!(records[0].class, DivergenceClass::DigestMismatch);
    assert_eq!(records[1].class, DivergenceClass::DigestMismatch);
    assert_eq!(records[2].class, DivergenceClass::MissingReplica);
    assert_eq!(records[3].class, DivergenceClass::ReplicaUnhealthy);
    assert_eq!(records[4].class, DivergenceClass::LagBehind);
}

#[test]
fn filter_ticketable_only_returns_urgent_divergences() {
    let records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::LagBehind, 100, 90, 1, 1000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 2000),
        DivergenceRecord::new(3, 2, DivergenceClass::MissingReplica, 300, 0, 1, 3000),
        DivergenceRecord::new(4, 3, DivergenceClass::ReplicaUnhealthy, 400, 400, 1, 4000),
        DivergenceRecord::new(5, 1, DivergenceClass::LagBehind, 500, 490, 1, 5000),
    ];

    let ticketable: Vec<_> = records.iter().filter(|r| r.requires_ticket()).collect();
    assert_eq!(ticketable.len(), 3);
    assert!(ticketable.iter().all(|r| r.requires_ticket()));
}

// ── Ordering by age ──────────────────────────────────────────────────

#[test]
fn sort_by_age_oldest_first() {
    let mut records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 1, 5000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 1000),
        DivergenceRecord::new(3, 2, DivergenceClass::DigestMismatch, 300, 299, 1, 3000),
        DivergenceRecord::new(4, 3, DivergenceClass::DigestMismatch, 400, 399, 1, 7000),
    ];

    records.sort_by_key(|r| r.detected_at_ns);

    assert_eq!(records[0].subject_ref, 2); // 1000ns = oldest
    assert_eq!(records[1].subject_ref, 3); // 3000ns
    assert_eq!(records[2].subject_ref, 1); // 5000ns
    assert_eq!(records[3].subject_ref, 4); // 7000ns = newest
}

#[test]
fn stale_divergences_older_than_threshold() {
    let now_ns: u64 = 10_000;
    let threshold_ns = 5_000;

    let records = [
        DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 1, 1000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 6000),
        DivergenceRecord::new(3, 2, DivergenceClass::DigestMismatch, 300, 299, 1, 8000),
    ];

    let stale: Vec<_> = records
        .iter()
        .filter(|r| now_ns.saturating_sub(r.detected_at_ns) > threshold_ns)
        .collect();

    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].subject_ref, 1);
}

// ── Grouping by affected object count ────────────────────────────────

#[test]
fn group_by_subject_most_divergences_first() {
    let records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 1, 1000),
        DivergenceRecord::new(1, 2, DivergenceClass::DigestMismatch, 100, 99, 1, 1000),
        DivergenceRecord::new(1, 3, DivergenceClass::DigestMismatch, 100, 99, 1, 1000),
        DivergenceRecord::new(2, 1, DivergenceClass::MissingReplica, 200, 0, 1, 2000),
        DivergenceRecord::new(3, 1, DivergenceClass::DigestMismatch, 300, 299, 1, 3000),
        DivergenceRecord::new(3, 2, DivergenceClass::DigestMismatch, 300, 299, 1, 3000),
    ];

    use std::collections::HashMap;
    let mut subject_counts: HashMap<u64, usize> = HashMap::new();
    for r in &records {
        *subject_counts.entry(r.subject_ref).or_default() += 1;
    }

    // Subject 1: 3 divergences, Subject 3: 2 divergences, Subject 2: 1
    assert_eq!(subject_counts.get(&1), Some(&3));
    assert_eq!(subject_counts.get(&2), Some(&1));
    assert_eq!(subject_counts.get(&3), Some(&2));

    // Order subjects by divergence count descending
    let mut subjects: Vec<_> = subject_counts.iter().collect();
    subjects.sort_by(|a, b| b.1.cmp(a.1));
    assert_eq!(*subjects[0].0, 1); // 3 divergences
    assert_eq!(*subjects[1].0, 3); // 2 divergences
    assert_eq!(*subjects[2].0, 2); // 1 divergence
}

// ── Combined ordering: severity then age ─────────────────────────────

#[test]
fn sort_by_severity_then_age() {
    let mut records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::LagBehind, 100, 90, 1, 5000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 3000),
        DivergenceRecord::new(3, 2, DivergenceClass::DigestMismatch, 300, 299, 1, 1000),
        DivergenceRecord::new(4, 3, DivergenceClass::LagBehind, 400, 390, 1, 2000),
        DivergenceRecord::new(5, 1, DivergenceClass::MissingReplica, 500, 0, 1, 4000),
    ];

    records.sort_by(|a, b| {
        severity_rank(a.class)
            .cmp(&severity_rank(b.class))
            .then_with(|| a.detected_at_ns.cmp(&b.detected_at_ns))
    });

    // DigestMismatch first (rank 0), then by age
    assert_eq!(records[0].subject_ref, 3); // DigestMismatch, 1000ns
    assert_eq!(records[1].subject_ref, 2); // DigestMismatch, 3000ns
                                           // MissingReplica (rank 1)
    assert_eq!(records[2].subject_ref, 5); // MissingReplica, 4000ns
                                           // LagBehind (rank 3)
    assert_eq!(records[3].subject_ref, 4); // LagBehind, 2000ns
    assert_eq!(records[4].subject_ref, 1); // LagBehind, 5000ns
}

// ── Data vs metadata distinction ─────────────────────────────────────

/// Convention: subject_ref < 1_000_000 is data, >= 1_000_000 is metadata.
fn is_metadata(subject_ref: u64) -> bool {
    subject_ref >= 1_000_000
}

#[test]
fn separate_data_and_metadata_divergences() {
    let records = vec![
        DivergenceRecord::new(100, 1, DivergenceClass::DigestMismatch, 1, 2, 1, 1000),
        DivergenceRecord::new(200, 1, DivergenceClass::DigestMismatch, 3, 4, 1, 2000),
        DivergenceRecord::new(1_000_001, 2, DivergenceClass::MissingReplica, 5, 0, 1, 3000),
        DivergenceRecord::new(1_000_002, 2, DivergenceClass::LagBehind, 6, 5, 1, 4000),
        DivergenceRecord::new(300, 1, DivergenceClass::LagBehind, 7, 6, 1, 5000),
    ];

    let data_divs: Vec<_> = records
        .iter()
        .filter(|r| !is_metadata(r.subject_ref))
        .collect();
    let meta_divs: Vec<_> = records
        .iter()
        .filter(|r| is_metadata(r.subject_ref))
        .collect();

    assert_eq!(data_divs.len(), 3);
    assert_eq!(meta_divs.len(), 2);

    // Data divergences should be all non-metadata
    for d in &data_divs {
        assert!(d.subject_ref < 1_000_000);
    }
    // Metadata divergences
    for d in &meta_divs {
        assert!(d.subject_ref >= 1_000_000);
    }
}

#[test]
fn prioritize_metadata_over_data_when_equal_severity() {
    let mut records = [
        DivergenceRecord::new(100, 1, DivergenceClass::DigestMismatch, 1, 2, 1, 1000),
        DivergenceRecord::new(1_000_001, 2, DivergenceClass::DigestMismatch, 3, 4, 1, 1000),
        DivergenceRecord::new(200, 1, DivergenceClass::DigestMismatch, 5, 6, 1, 2000),
    ];

    // Sort: severity first, then metadata before data, then age
    records.sort_by(|a, b| {
        severity_rank(a.class)
            .cmp(&severity_rank(b.class))
            .then_with(|| is_metadata(b.subject_ref).cmp(&is_metadata(a.subject_ref)))
            .then_with(|| a.detected_at_ns.cmp(&b.detected_at_ns))
    });

    // Both DigestMismatch, metadata (1_000_001) first, then data by age
    assert_eq!(records[0].subject_ref, 1_000_001);
    assert_eq!(records[1].subject_ref, 100);
    assert_eq!(records[2].subject_ref, 200);
}

// ── Reconciliation ordering within the auditor ───────────────────────

#[test]
fn auditor_divergences_ordered_by_detection_time() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 4);

    // Detect divergences at different times by calling record_comparisons
    // with results from different calls
    let inputs1 = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 99,
        witness_digest: None,
        epoch: 1,
    }];
    let results1 = aud.comparator.compare_batch(&inputs1, NS_PER_MIN + 1000);
    aud.record_comparisons(&results1, NS_PER_MIN + 1000);

    let inputs2 = vec![ComparisonInput {
        subject_ref: 2,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 99,
        witness_digest: None,
        epoch: 1,
    }];
    let results2 = aud.comparator.compare_batch(&inputs2, NS_PER_MIN + 2000);
    aud.record_comparisons(&results2, NS_PER_MIN + 2000);

    // Divergences are accumulated in order: verify by detected_at_ns
    assert_eq!(aud.current_divergences.len(), 2);
    assert!(aud.current_divergences[0].detected_at_ns <= aud.current_divergences[1].detected_at_ns);
}

#[test]
fn ticketable_and_lag_divergences_separated() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 4);

    // Mix of lag and ticketable
    let inputs = vec![
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: Some(42),
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 2,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
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
        ComparisonInput {
            subject_ref: 4,
            target_node: 1,
            primary_digest: 100,
            replica_digest: 80,
            witness_digest: Some(80),
            epoch: 1,
        },
    ];

    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    let ticketable = aud.ticketable_divergences();
    let lag = aud.lag_divergences();

    // Subjects 1 and 4 are LagBehind (witness confirms replica)
    // Subjects 2 is DigestMismatch, 3 is MissingReplica
    assert_eq!(ticketable.len(), 2);
    assert_eq!(lag.len(), 2);
}

// ── Reconciliation of empty divergence sets ──────────────────────────

#[test]
fn empty_divergence_set_no_reconciliation_needed() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 3);

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
            target_node: 1,
            primary_digest: 77,
            replica_digest: 77,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 3,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
    ];

    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    let new_divs = aud.record_comparisons(&results, NS_PER_MIN);

    assert_eq!(new_divs, 0);
    assert!(!aud.has_divergences());

    let ticketable = aud.ticketable_divergences();
    let lag = aud.lag_divergences();
    assert!(ticketable.is_empty());
    assert!(lag.is_empty());
}

// ── Batch ordering edge cases ────────────────────────────────────────

#[test]
fn single_divergence_no_ordering_conflict() {
    let records = [DivergenceRecord::new(
        1,
        1,
        DivergenceClass::DigestMismatch,
        100,
        99,
        1,
        1000,
    )];
    assert_eq!(records.len(), 1);
    let ticketable: Vec<_> = records.iter().filter(|r| r.requires_ticket()).collect();
    assert_eq!(ticketable.len(), 1);
}

#[test]
fn all_same_severity_ordering_by_age() {
    let mut records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 1, 5000),
        DivergenceRecord::new(2, 1, DivergenceClass::DigestMismatch, 200, 199, 1, 2000),
        DivergenceRecord::new(3, 2, DivergenceClass::DigestMismatch, 300, 299, 1, 8000),
        DivergenceRecord::new(4, 3, DivergenceClass::DigestMismatch, 400, 399, 1, 1000),
    ];

    records.sort_by_key(|r| r.detected_at_ns);

    assert_eq!(records[0].subject_ref, 4); // 1000ns
    assert_eq!(records[1].subject_ref, 2); // 2000ns
    assert_eq!(records[2].subject_ref, 1); // 5000ns
    assert_eq!(records[3].subject_ref, 3); // 8000ns
}

#[test]
fn all_different_severity_no_age_tiebreaker_needed() {
    let mut records = vec![
        DivergenceRecord::new(1, 1, DivergenceClass::DigestMismatch, 100, 99, 1, 9000),
        DivergenceRecord::new(2, 1, DivergenceClass::MissingReplica, 200, 0, 1, 1000),
        DivergenceRecord::new(3, 2, DivergenceClass::ReplicaUnhealthy, 300, 300, 1, 5000),
        DivergenceRecord::new(4, 3, DivergenceClass::LagBehind, 400, 390, 1, 3000),
    ];

    records.sort_by_key(|r| severity_rank(r.class));

    assert_eq!(records[0].class, DivergenceClass::DigestMismatch);
    assert_eq!(records[1].class, DivergenceClass::MissingReplica);
    assert_eq!(records[2].class, DivergenceClass::ReplicaUnhealthy);
    assert_eq!(records[3].class, DivergenceClass::LagBehind);
}
