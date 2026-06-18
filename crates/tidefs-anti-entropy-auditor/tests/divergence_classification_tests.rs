// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Divergence classification tests — replica state vector classification
//! into clean, suspect, confirmed-divergent, and lost-quorum categories
//! across varied replica counts and checksum outcomes.

use tidefs_anti_entropy_auditor::ae_state::{DivergenceClass, DivergenceRecord};
use tidefs_anti_entropy_auditor::comparator::{ComparisonInput, DigestComparator};
use tidefs_anti_entropy_auditor::scan_scheduler::ScanSchedulePolicy;
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

// ── Single-replica classification ────────────────────────────────────

#[test]
fn single_replica_clean_digests_match() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0xCAFE,
        replica_digest: 0xCAFE,
        witness_digest: None,
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(results.len(), 1);
    assert!(!results[0].diverged);
    assert_eq!(results[0].divergence_class, None);
    assert_eq!(cmp.total_matches, 1);
    assert_eq!(cmp.total_divergences, 0);
}

#[test]
fn single_replica_suspect_digests_differ_no_witness() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0xCAFE,
        replica_digest: 0xBABE,
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
fn single_replica_confirmed_divergent_witness_backs_primary() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0xCAFE,
        replica_digest: 0xBABE,
        witness_digest: Some(0xCAFE),
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
fn single_replica_lag_witness_backs_replica() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0xBABE,
        replica_digest: 0xCAFE,
        witness_digest: Some(0xCAFE),
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(results[0].diverged);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::LagBehind)
    );
}

#[test]
fn single_replica_missing_zero_digest() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 0xCAFE,
        replica_digest: 0,
        witness_digest: None,
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(results[0].diverged);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );
}

// ── Multi-replica: healthy majority ──────────────────────────────────

#[test]
fn three_replicas_two_healthy_one_divergent() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 42u64), (2, 42u64), (3, 99u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, Some(42), 1, 1000);
    assert_eq!(healthy, vec![1, 2]);
    assert_eq!(divergences.len(), 1);
    assert_eq!(divergences[0].target_node, 3);
    assert_eq!(
        divergences[0].divergence_class,
        Some(DivergenceClass::DigestMismatch)
    );
}

#[test]
fn five_replicas_four_healthy_one_missing() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![
        (1, 100u64),
        (2, 100u64),
        (3, 100u64),
        (4, 100u64),
        (5, 0u64),
    ];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(42, 100, &replicas, None, 1, 1000);
    assert_eq!(healthy.len(), 4);
    assert_eq!(divergences.len(), 1);
    assert_eq!(
        divergences[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );
}

#[test]
fn seven_replicas_six_healthy_one_lagging() {
    let mut cmp = DigestComparator::default();
    let replicas: Vec<(u64, u64)> = (1..=7)
        .map(|n| if n == 7 { (n, 99) } else { (n, 200) })
        .collect();
    // Primary=200, witness=99 (matches replica 7) -> replica 7 is LagBehind
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 200, &replicas, Some(99), 1, 1000);
    assert_eq!(healthy.len(), 6);
    assert_eq!(divergences.len(), 1);
    assert_eq!(
        divergences[0].divergence_class,
        Some(DivergenceClass::LagBehind)
    );
}

// ── Lost-quorum scenarios ────────────────────────────────────────────

#[test]
fn three_replicas_two_missing_lost_quorum() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![(1, 42u64), (2, 0u64), (3, 0u64)];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 42, &replicas, None, 1, 1000);
    // Only 1 of 3 replicas healthy: lost quorum
    assert_eq!(healthy.len(), 1);
    assert_eq!(divergences.len(), 2);
    assert!(divergences
        .iter()
        .all(|d| { d.divergence_class == Some(DivergenceClass::MissingReplica) }));
}

#[test]
fn five_replicas_three_corrupt_lost_quorum() {
    let mut cmp = DigestComparator::default();
    let replicas = vec![
        (1, 500u64),
        (2, 999u64),
        (3, 888u64),
        (4, 500u64),
        (5, 500u64),
    ];
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 500, &replicas, Some(500), 1, 1000);
    // Nodes 2 and 3 diverge (DigestMismatch), 1, 4, 5 healthy
    assert_eq!(healthy.len(), 3);
    assert_eq!(divergences.len(), 2);
    for d in &divergences {
        assert_eq!(d.divergence_class, Some(DivergenceClass::DigestMismatch));
    }
}

// ── Mixed classifications in one audit ────────────────────────────────

#[test]
fn audit_with_mixed_divergence_classes() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 5);

    let inputs = vec![
        // Clean
        ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        },
        // DigestMismatch (no witness)
        ComparisonInput {
            subject_ref: 2,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        },
        // LagBehind (witness confirms replica)
        ComparisonInput {
            subject_ref: 3,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: Some(42),
            epoch: 1,
        },
        // MissingReplica
        ComparisonInput {
            subject_ref: 4,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        },
        // Clean
        ComparisonInput {
            subject_ref: 5,
            target_node: 1,
            primary_digest: 77,
            replica_digest: 77,
            witness_digest: None,
            epoch: 1,
        },
    ];

    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    let new_divs = aud.record_comparisons(&results, NS_PER_MIN);

    assert_eq!(new_divs, 3);
    assert!(aud.has_divergences());

    aud.classify_divergences(NS_PER_MIN + 1);
    match &aud.state {
        tidefs_anti_entropy_auditor::ae_state::AntiEntropyState::DivergenceFound {
            total_divergences,
            classified_lag,
            classified_corruption,
            classified_missing,
            ..
        } => {
            assert_eq!(*total_divergences, 3);
            assert_eq!(*classified_lag, 1);
            assert_eq!(*classified_corruption, 1);
            assert_eq!(*classified_missing, 1);
        }
        _ => panic!("expected DivergenceFound"),
    }
}

// ── Replica state vector: classify entire replica set ────────────────

/// Helper: classify a replica set state from comparison results.
#[derive(Debug, PartialEq)]
enum ReplicaSetState {
    Clean,
    Suspect,
    ConfirmedDivergent,
    LostQuorum,
}

fn classify_replica_set(
    healthy_count: usize,
    total_replicas: usize,
    has_witness_divergence: bool,
) -> ReplicaSetState {
    // Strict majority: healthy > total/2 (quorum)
    if healthy_count * 2 > total_replicas {
        ReplicaSetState::Clean
    } else if healthy_count * 2 == total_replicas {
        // Exactly half: tie — suspect unless witness confirms
        if has_witness_divergence {
            ReplicaSetState::ConfirmedDivergent
        } else {
            ReplicaSetState::Suspect
        }
    } else {
        ReplicaSetState::LostQuorum
    }
}

#[test]
fn classify_replica_set_state_clean() {
    assert_eq!(classify_replica_set(5, 5, false), ReplicaSetState::Clean);
    assert_eq!(classify_replica_set(4, 5, false), ReplicaSetState::Clean);
    assert_eq!(classify_replica_set(3, 5, false), ReplicaSetState::Clean);
}

#[test]
fn classify_replica_set_state_suspect() {
    // Exactly half healthy, no witness = suspect
    assert_eq!(classify_replica_set(1, 2, false), ReplicaSetState::Suspect);
    assert_eq!(classify_replica_set(2, 4, false), ReplicaSetState::Suspect);
    assert_eq!(classify_replica_set(3, 6, false), ReplicaSetState::Suspect);
}

#[test]
fn classify_replica_set_state_confirmed_divergent() {
    // 2 of 3 healthy, witness confirms divergence
    assert_eq!(
        classify_replica_set(2, 4, true),
        ReplicaSetState::ConfirmedDivergent
    );
}

#[test]
fn classify_replica_set_state_lost_quorum() {
    assert_eq!(
        classify_replica_set(1, 3, false),
        ReplicaSetState::LostQuorum
    );
    assert_eq!(
        classify_replica_set(0, 3, false),
        ReplicaSetState::LostQuorum
    );
    assert_eq!(
        classify_replica_set(2, 5, false),
        ReplicaSetState::LostQuorum
    );
    assert_eq!(
        classify_replica_set(2, 7, false),
        ReplicaSetState::LostQuorum
    );
}

// ── DivergenceRecord classification helpers ──────────────────────────

#[test]
fn divergence_record_preserves_digests_for_audit_trail() {
    let rec = DivergenceRecord::new(
        42,
        3,
        DivergenceClass::DigestMismatch,
        0xAAAA_BBBB_CCCC_DDDD,
        0x1111_2222_3333_4444,
        7,
        9_000_000_000,
    );
    assert_eq!(rec.subject_ref, 42);
    assert_eq!(rec.target_node, 3);
    assert_eq!(rec.expected_digest, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(rec.actual_digest, 0x1111_2222_3333_4444);
    assert_eq!(rec.epoch, 7);
    assert_eq!(rec.detected_at_ns, 9_000_000_000);
}

#[test]
fn divergence_record_missing_replica_has_zero_actual_digest() {
    let rec = DivergenceRecord::new(10, 5, DivergenceClass::MissingReplica, 0xDEAD, 0, 1, 1000);
    assert_eq!(rec.actual_digest, 0);
    assert!(rec.requires_ticket());
}

#[test]
fn divergence_record_replica_unhealthy_still_ticketable() {
    let rec = DivergenceRecord::new(
        10,
        5,
        DivergenceClass::ReplicaUnhealthy,
        0xDEAD,
        0xDEAD,
        1,
        1000,
    );
    assert!(rec.requires_ticket());
    assert!(!rec.is_lag_only());
}

// ── Witness tie-breaking edge cases ──────────────────────────────────

#[test]
fn witness_disagrees_with_both_primary_and_replica() {
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
    // Neither primary nor replica matches witness -> authority-selection disagreement
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::WitnessDisagreement)
    );
}

#[test]
fn witness_matches_replica_primary_is_lagging() {
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 200,
        replica_digest: 100,
        witness_digest: Some(100),
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert!(results[0].diverged);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::LagBehind)
    );
}

#[test]
fn zero_digest_overrides_witness_to_missing() {
    // Even when witness matches the zero digest, classify as MissingReplica
    let mut cmp = DigestComparator::default();
    let inputs = vec![ComparisonInput {
        subject_ref: 1,
        target_node: 1,
        primary_digest: 42,
        replica_digest: 0,
        witness_digest: Some(0),
        epoch: 1,
    }];
    let results = cmp.compare_batch(&inputs, 1000);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::MissingReplica)
    );
}

// ── Large replica count: classification stability ────────────────────

#[test]
fn ten_replicas_nine_healthy_one_corrupt() {
    let mut cmp = DigestComparator::default();
    let mut replicas: Vec<(u64, u64)> = (1..=9).map(|n| (n, 0xBEEF)).collect();
    replicas.push((10, 0xDEAD)); // corrupt
    let (healthy, divergences) =
        cmp.compare_subject_against_replicas(1, 0xBEEF, &replicas, Some(0xBEEF), 1, 1000);
    assert_eq!(healthy.len(), 9);
    assert_eq!(divergences.len(), 1);
    assert_eq!(divergences[0].target_node, 10);
}
