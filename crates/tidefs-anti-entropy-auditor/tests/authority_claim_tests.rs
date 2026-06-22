// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Authority-claim integration tests for the anti-entropy auditor.
//!
//! These tests exercise the crate's product boundary across scan scheduling,
//! Merkle proof validation, divergence evidence recording, repair receipts,
//! SuspectLog feeding, and scrub admission.

use std::sync::atomic::Ordering;

use tidefs_anti_entropy_auditor::ae_state::{AntiEntropyState, DivergenceClass};
use tidefs_anti_entropy_auditor::merkle_exchange::{MerkleExchangeStatus, MerkleLeafRange};
use tidefs_anti_entropy_auditor::scan_scheduler::{ScanDecision, ScanSchedulePolicy};
use tidefs_anti_entropy_auditor::{AntiEntropyAuditor, CountingScrubTrigger};
use tidefs_checksum_tree::{hash_block, ChecksumTree, Digest, DEFAULT_BLOCK_SIZE};
use tidefs_local_object_store::SuspectLog;

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_MIN: u64 = 60 * NS_PER_SEC;

fn policy() -> ScanSchedulePolicy {
    ScanSchedulePolicy {
        min_scan_interval_ns: 5 * NS_PER_MIN,
        max_scan_interval_ns: 60 * NS_PER_MIN,
        max_batch_size: 6,
        divergence_backoff_multiplier: 2.0,
        max_backpressure_delay_ns: 60 * NS_PER_SEC,
        comparison_throttle_ns: 1_000_000,
    }
}

fn leaf(value: u8) -> Digest {
    hash_block(&[value; DEFAULT_BLOCK_SIZE])
}

fn tree(values: &[u8]) -> ChecksumTree {
    let leaves: Vec<Digest> = values.iter().copied().map(leaf).collect();
    ChecksumTree::from_leaves(&leaves, DEFAULT_BLOCK_SIZE)
}

#[test]
fn merkle_proof_evidence_feeds_receipts_suspect_log_and_scrub_trigger() {
    let local_tree = tree(&[1, 2, 3, 4, 5, 6]);
    let remote_tree = tree(&[1, 2, 99, 4, 42, 6]);
    let remote_proofs = (0..remote_tree.block_count)
        .map(|leaf_index| remote_tree.generate_proof(leaf_index).expect("valid proof"))
        .collect::<Vec<_>>();

    let mut auditor = AntiEntropyAuditor::new(policy(), 7, 0);
    auditor.set_total_subjects(6);

    assert_eq!(auditor.should_scan(NS_PER_MIN, 0.2), ScanDecision::Proceed);
    let subjects = auditor.begin_scan(NS_PER_MIN).expect("scan starts");
    assert_eq!(subjects, vec![1, 2, 3, 4, 5, 6]);
    auditor.begin_compare(NS_PER_MIN + NS_PER_SEC, subjects.len() as u64);

    auditor.init_merkle_exchange(local_tree.clone(), remote_tree.root_hash);
    let result = auditor
        .run_merkle_exchange_with_remote_proofs(
            MerkleLeafRange::new(subjects[0], 0, remote_tree.block_count),
            &remote_proofs,
        )
        .expect("merkle exchange is initialized");

    assert_eq!(
        result.status,
        MerkleExchangeStatus::CompleteDivergentLeafProof
    );
    assert!(result.is_repair_evidence());
    assert_eq!(result.divergent_indices, vec![2, 4]);

    let recorded = auditor.record_merkle_exchange_result(&result, 9, NS_PER_MIN + 2 * NS_PER_SEC);
    assert_eq!(recorded, 2);
    assert_eq!(auditor.ticketable_divergences().len(), 2);
    assert_eq!(auditor.total_historical_divergences(), 2);
    assert_eq!(auditor.scheduler.frontier.degraded_subjects, vec![3, 5]);

    auditor.classify_divergences(NS_PER_MIN + 3 * NS_PER_SEC);
    match &auditor.state {
        AntiEntropyState::DivergenceFound {
            total_divergences,
            classified_corruption,
            classified_lag,
            classified_missing,
            classified_witness_disagreement,
            ..
        } => {
            assert_eq!(*total_divergences, 2);
            assert_eq!(*classified_corruption, 2);
            assert_eq!(*classified_lag, 0);
            assert_eq!(*classified_missing, 0);
            assert_eq!(*classified_witness_disagreement, 0);
        }
        state => panic!("expected DivergenceFound, got {state:?}"),
    }

    let mut suspect_log = SuspectLog::new();
    assert_eq!(auditor.feed_suspect_log(&mut suspect_log), 2);
    let suspect_subjects = suspect_log
        .iter()
        .map(|entry| entry.locator_id)
        .collect::<Vec<_>>();
    assert_eq!(suspect_subjects, vec![3, 5]);

    let receipts = auditor.emit_repair_receipts("validated merkle leaf proof");
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|receipt| {
        receipt.divergence_class == DivergenceClass::DigestMismatch
            && receipt.has_full_hashes()
            && receipt.target_node == 9
    }));
    assert!(auditor.emit_repair_receipts("repeat").is_empty());

    let scrub_trigger = CountingScrubTrigger::default();
    assert_eq!(
        auditor.trigger_scrub_for_divergences(&scrub_trigger, 1, 9),
        2
    );
    assert_eq!(scrub_trigger.trigger_count.load(Ordering::Relaxed), 1);
    assert_eq!(scrub_trigger.total_subjects.load(Ordering::Relaxed), 2);

    auditor.record_tickets(NS_PER_MIN + 4 * NS_PER_SEC, &[100, 101]);
    auditor.resolve(NS_PER_MIN + 5 * NS_PER_SEC, &[200, 201]);
    auditor.complete_scan(NS_PER_MIN + 6 * NS_PER_SEC);

    match &auditor.state {
        AntiEntropyState::Idle {
            next_scan_eligible_ns,
            ..
        } => {
            assert_eq!(
                *next_scan_eligible_ns,
                NS_PER_MIN + 6 * NS_PER_SEC + (5 * NS_PER_MIN / 2)
            );
        }
        state => panic!("expected Idle, got {state:?}"),
    }
    assert!(matches!(
        auditor.should_scan(NS_PER_MIN + 6 * NS_PER_SEC + NS_PER_MIN, 0.2),
        ScanDecision::TooSoon { .. }
    ));
}

#[test]
fn comparison_history_records_each_new_divergence_once_across_batches() {
    let mut auditor = AntiEntropyAuditor::new(policy(), 3, 0);
    auditor.set_total_subjects(6);
    auditor.begin_scan(NS_PER_MIN).expect("scan starts");
    auditor.begin_compare(NS_PER_MIN + NS_PER_SEC, 3);

    let first = auditor.comparator.compare_batch(
        &[tidefs_anti_entropy_auditor::comparator::ComparisonInput {
            subject_ref: 1,
            target_node: 9,
            primary_digest: 10,
            replica_digest: 20,
            witness_digest: None,
            epoch: 3,
        }],
        NS_PER_MIN + 2 * NS_PER_SEC,
    );
    assert_eq!(
        auditor.record_comparisons(&first, NS_PER_MIN + 2 * NS_PER_SEC),
        1
    );
    assert_eq!(auditor.current_divergences.len(), 1);
    assert_eq!(auditor.total_historical_divergences(), 1);

    let second = auditor.comparator.compare_batch(
        &[
            tidefs_anti_entropy_auditor::comparator::ComparisonInput {
                subject_ref: 2,
                target_node: 9,
                primary_digest: 30,
                replica_digest: 30,
                witness_digest: None,
                epoch: 3,
            },
            tidefs_anti_entropy_auditor::comparator::ComparisonInput {
                subject_ref: 3,
                target_node: 9,
                primary_digest: 40,
                replica_digest: 0,
                witness_digest: None,
                epoch: 3,
            },
        ],
        NS_PER_MIN + 3 * NS_PER_SEC,
    );
    assert_eq!(
        auditor.record_comparisons(&second, NS_PER_MIN + 3 * NS_PER_SEC),
        1
    );

    assert_eq!(auditor.current_divergences.len(), 2);
    assert_eq!(auditor.total_historical_divergences(), 2);
    assert_eq!(
        auditor
            .divergence_history
            .iter()
            .map(|record| record.subject_ref)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
}
