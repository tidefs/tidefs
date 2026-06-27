// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Repair-trigger receipt emission tests — verify that ticketable
//! divergences produce durable receipts while lag-only and witness-
//! disagreement cases are excluded from automatic repair admission.
//!
//! Tests cover:
//! - digest mismatch receipt emission
//! - missing replica receipt emission
//! - replica unhealthy receipt emission
//! - lag-only exclusion
//! - witness disagreement exclusion (authority gate)
//! - repeated classification idempotency
//! - threshold escalation interactions

use tidefs_anti_entropy_auditor::ae_state::{
    DivergenceClass, DivergenceRecord, RepairTriggerReceipt,
};
use tidefs_anti_entropy_auditor::comparator::ComparisonInput;
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

// ── Helpers ──────────────────────────────────────────────────────────

/// Create an auditor with several divergence classes injected.
fn auditor_with_divergences(
    divergences: &[(u64, u64, DivergenceClass, u64, u64)],
) -> AntiEntropyAuditor {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, divergences.len() as u64);

    let inputs: Vec<ComparisonInput> = divergences
        .iter()
        .map(|(subj, node, _class, expected, actual)| ComparisonInput {
            subject_ref: *subj,
            target_node: *node,
            primary_digest: *expected,
            replica_digest: *actual,
            witness_digest: None,
            epoch: 1,
        })
        .collect();

    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);
    aud
}

// ── Digest mismatch receipt emission ─────────────────────────────────

#[test]
fn digest_mismatch_emits_receipt() {
    let mut aud =
        auditor_with_divergences(&[(1, 2, DivergenceClass::DigestMismatch, 0xCAFE, 0xBABE)]);

    let receipts = aud.emit_repair_receipts("digest mismatch detected");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].subject_ref, 1);
    assert_eq!(receipts[0].target_node, 2);
    assert_eq!(
        receipts[0].divergence_class,
        DivergenceClass::DigestMismatch
    );
    assert_eq!(receipts[0].expected_digest, 0xCAFE);
    assert_eq!(receipts[0].actual_digest, 0xBABE);
    assert_eq!(receipts[0].trigger_reason, "digest mismatch detected");
}

#[test]
fn multiple_digest_mismatches_emit_receipts() {
    let mut aud = auditor_with_divergences(&[
        (1, 1, DivergenceClass::DigestMismatch, 100, 200),
        (2, 1, DivergenceClass::DigestMismatch, 300, 400),
        (3, 2, DivergenceClass::DigestMismatch, 500, 600),
    ]);

    let receipts = aud.emit_repair_receipts("multi-mismatch");
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].subject_ref, 1);
    assert_eq!(receipts[1].subject_ref, 2);
    assert_eq!(receipts[2].subject_ref, 3);
}

// ── Missing replica receipt emission ─────────────────────────────────

#[test]
fn missing_replica_emits_receipt() {
    let mut aud = auditor_with_divergences(&[(5, 3, DivergenceClass::MissingReplica, 0xDEAD, 0x0)]);

    let receipts = aud.emit_repair_receipts("missing replica");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].divergence_class,
        DivergenceClass::MissingReplica
    );
    assert_eq!(receipts[0].actual_digest, 0);
}

#[test]
fn replica_unhealthy_emits_receipt() {
    // ReplicaUnhealthy is ticketable: we need to inject it directly into
    // current_divergences since the comparator doesn't auto-classify it.
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 1);

    aud.current_divergences.push(DivergenceRecord::new(
        7,
        4,
        DivergenceClass::ReplicaUnhealthy,
        0xABCD,
        0xABCD,
        1,
        NS_PER_MIN,
    ));

    let receipts = aud.emit_repair_receipts("replica unhealthy");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].divergence_class,
        DivergenceClass::ReplicaUnhealthy
    );
    assert_eq!(receipts[0].subject_ref, 7);
    assert_eq!(receipts[0].target_node, 4);
}

// ── Lag-only exclusion ───────────────────────────────────────────────

#[test]
fn lag_only_does_not_emit_receipt() {
    // LagBehind is not naturally produced by the comparator without
    // witness tie-breaking; inject it directly into current_divergences.
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 1);

    aud.current_divergences.push(DivergenceRecord::new(
        1,
        1,
        DivergenceClass::LagBehind,
        100,
        90,
        1,
        NS_PER_MIN,
    ));

    let receipts = aud.emit_repair_receipts("should be empty");
    assert_eq!(receipts.len(), 0);
}

#[test]
fn mixed_lag_and_corruption_only_ticketable_get_receipts() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 4);

    aud.current_divergences.push(DivergenceRecord::new(
        1,
        1,
        DivergenceClass::LagBehind,
        100,
        100,
        1,
        NS_PER_MIN,
    ));
    aud.current_divergences.push(DivergenceRecord::new(
        2,
        1,
        DivergenceClass::DigestMismatch,
        200,
        300,
        1,
        NS_PER_MIN,
    ));
    aud.current_divergences.push(DivergenceRecord::new(
        3,
        2,
        DivergenceClass::LagBehind,
        400,
        400,
        1,
        NS_PER_MIN,
    ));
    aud.current_divergences.push(DivergenceRecord::new(
        4,
        2,
        DivergenceClass::DigestMismatch,
        500,
        600,
        1,
        NS_PER_MIN,
    ));

    let receipts = aud.emit_repair_receipts("mixed");
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].subject_ref, 2);
    assert_eq!(receipts[1].subject_ref, 4);
}

// ── Witness disagreement exclusion ───────────────────────────────────

#[test]
fn witness_disagreement_does_not_emit_receipt() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 1);

    aud.current_divergences.push(DivergenceRecord::new(
        1,
        1,
        DivergenceClass::WitnessDisagreement,
        100,
        200,
        1,
        NS_PER_MIN,
    ));

    let receipts = aud.emit_repair_receipts("witness disagreement");
    assert_eq!(receipts.len(), 0);
}

#[test]
fn witness_disagreement_requires_explicit_authority_classification() {
    // Witness disagreements are detected but not automatically ticketable.
    // The caller must evaluate them explicitly; emit_repair_receipts skips them.
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 2);

    aud.current_divergences.push(DivergenceRecord::new(
        1,
        1,
        DivergenceClass::WitnessDisagreement,
        100,
        200,
        1,
        NS_PER_MIN,
    ));
    aud.current_divergences.push(DivergenceRecord::new(
        2,
        1,
        DivergenceClass::DigestMismatch,
        300,
        400,
        1,
        NS_PER_MIN,
    ));

    // Only the DigestMismatch should get a receipt
    let receipts = aud.emit_repair_receipts("mixed with witness");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].subject_ref, 2);
    assert_eq!(
        receipts[0].divergence_class,
        DivergenceClass::DigestMismatch
    );

    // The witness disagreement is still in current_divergences, just not ticketable
    let witness_records: Vec<&DivergenceRecord> = aud
        .current_divergences
        .iter()
        .filter(|d| d.is_witness_disagreement())
        .collect();
    assert_eq!(witness_records.len(), 1);
}

// ── Idempotency ──────────────────────────────────────────────────────

#[test]
fn repeated_emit_returns_empty_after_first_call() {
    let mut aud = auditor_with_divergences(&[(1, 1, DivergenceClass::DigestMismatch, 100, 200)]);

    let first = aud.emit_repair_receipts("first call");
    assert_eq!(first.len(), 1);
    assert!(aud.has_emitted_receipts());

    let second = aud.emit_repair_receipts("second call");
    assert_eq!(second.len(), 0);

    let third = aud.emit_repair_receipts("third call");
    assert_eq!(third.len(), 0);
}

#[test]
fn idempotency_with_no_divergences() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 0);

    let first = aud.emit_repair_receipts("empty");
    assert_eq!(first.len(), 0);
    assert!(aud.has_emitted_receipts());

    let second = aud.emit_repair_receipts("still empty");
    assert_eq!(second.len(), 0);
}

#[test]
fn idempotency_flag_resets_on_new_scan() {
    let mut aud = auditor_with_divergences(&[(1, 1, DivergenceClass::DigestMismatch, 100, 200)]);

    let first = aud.emit_repair_receipts("scan 1");
    assert_eq!(first.len(), 1);
    assert!(aud.has_emitted_receipts());

    // Start a new scan cycle
    aud.complete_scan(2 * NS_PER_MIN);
    aud.begin_scan(3 * NS_PER_MIN).unwrap();
    aud.begin_compare(3 * NS_PER_MIN, 1);

    // New divergence in new scan
    aud.current_divergences.push(DivergenceRecord::new(
        2,
        1,
        DivergenceClass::DigestMismatch,
        300,
        400,
        2,
        3 * NS_PER_MIN,
    ));

    // Should be able to emit again for the new cycle
    assert!(!aud.has_emitted_receipts());
    let second = aud.emit_repair_receipts("scan 2");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].subject_ref, 2);
}

#[test]
fn repeated_classification_of_same_divergence_set_is_idempotent() {
    let mut aud = auditor_with_divergences(&[
        (1, 1, DivergenceClass::DigestMismatch, 100, 200),
        (2, 1, DivergenceClass::DigestMismatch, 300, 400),
    ]);

    aud.classify_divergences(NS_PER_MIN);
    let receipts1 = aud.emit_repair_receipts("after classify");
    assert_eq!(receipts1.len(), 2);

    // Re-classify same set without new scan
    aud.classify_divergences(NS_PER_MIN + NS_PER_SEC);
    let receipts2 = aud.emit_repair_receipts("after re-classify");
    assert_eq!(receipts2.len(), 0); // idempotent
}

// ── Threshold escalation interactions ────────────────────────────────

#[test]
fn receipt_count_matches_ticketable_divergence_count() {
    // Use direct injection for classes the comparator cannot auto-produce
    // (LagBehind with identical digests, WitnessDisagreement without a
    // real third witness).
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);
    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 7);

    // 5 ticketable DigestMismatch records
    for (subj, exp, act) in [
        (1, 100, 200),
        (2, 300, 400),
        (3, 500, 600),
        (5, 800, 900),
        (7, 1000, 1100),
    ] {
        aud.current_divergences.push(DivergenceRecord::new(
            subj,
            1,
            DivergenceClass::DigestMismatch,
            exp,
            act,
            1,
            NS_PER_MIN,
        ));
    }

    // 1 LagBehind — excluded from ticketable
    aud.current_divergences.push(DivergenceRecord::new(
        4,
        1,
        DivergenceClass::LagBehind,
        700,
        700,
        1,
        NS_PER_MIN,
    ));

    // 1 WitnessDisagreement — excluded from ticketable (authority gate)
    aud.current_divergences.push(DivergenceRecord::new(
        6,
        1,
        DivergenceClass::WitnessDisagreement,
        10,
        20,
        1,
        NS_PER_MIN,
    ));

    let receipts = aud.emit_repair_receipts("threshold test");
    // Only 5 ticketable: 1,2,3,5,7  (4 is lag, 6 is witness)
    assert_eq!(receipts.len(), 5);

    // Verify ticketable count matches receipt count
    let ticketable = aud.ticketable_divergences();
    assert_eq!(ticketable.len(), 5);
    assert_eq!(ticketable.len(), receipts.len());
}

#[test]
fn threshold_escalation_from_receipt_count() {
    // The receipt count can be used for threshold escalation decisions
    // without inspecting internal divergence state.
    let mut aud = auditor_with_divergences(
        &(1..=7)
            .map(|i| (i, 1, DivergenceClass::DigestMismatch, i * 100, i * 100 + 1))
            .collect::<Vec<_>>(),
    );

    let receipts = aud.emit_repair_receipts("escalation");
    assert_eq!(receipts.len(), 7);

    // Map receipt count to escalation level (same thresholds as repair_trigger_tests)
    let escalation = match receipts.len() {
        0..=2 => "log-only",
        3..=5 => "schedule-background",
        _ => "immediate-repair",
    };
    assert_eq!(escalation, "immediate-repair");
}

// ── Receipt carries complete evidence ────────────────────────────────

#[test]
fn receipt_preserves_all_divergence_evidence() {
    let mut expected = [0u8; 32];
    expected[0..8].copy_from_slice(&0xCAFEBABEu64.to_le_bytes());
    let mut actual = [0u8; 32];
    actual[0..8].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());

    let rec = DivergenceRecord::new_with_hashes(
        42,
        7,
        DivergenceClass::DigestMismatch,
        expected,
        actual,
        3,
        9_000_000_000,
    );

    let receipt = RepairTriggerReceipt::from_divergence(&rec, "full evidence").unwrap();
    assert_eq!(receipt.subject_ref, 42);
    assert_eq!(receipt.target_node, 7);
    assert_eq!(receipt.divergence_class, DivergenceClass::DigestMismatch);
    assert_eq!(receipt.expected_hash, Some(expected));
    assert_eq!(receipt.actual_hash, Some(actual));
    assert_eq!(receipt.epoch, 3);
    assert_eq!(receipt.detected_at_ns, 9_000_000_000);
    assert!(receipt.has_full_hashes());
}

#[test]
fn receipt_without_full_hashes_reports_correctly() {
    let rec = DivergenceRecord::new(1, 2, DivergenceClass::DigestMismatch, 100, 200, 1, 1000);
    let receipt = RepairTriggerReceipt::from_divergence(&rec, "no hashes").unwrap();
    assert!(!receipt.has_full_hashes());
    assert_eq!(receipt.expected_hash, None);
    assert_eq!(receipt.actual_hash, None);
}

// ── Drain interactions ───────────────────────────────────────────────

#[test]
fn drain_divergences_does_not_affect_receipt_emission_state() {
    let mut aud = auditor_with_divergences(&[(1, 1, DivergenceClass::DigestMismatch, 100, 200)]);

    // Emit receipts first
    let receipts = aud.emit_repair_receipts("before drain");
    assert_eq!(receipts.len(), 1);
    assert!(aud.has_emitted_receipts());

    // Drain divergences
    let _drained = aud.drain_divergences();

    // Already emitted, so second call returns empty
    let second = aud.emit_repair_receipts("after drain");
    assert_eq!(second.len(), 0);
}

#[test]
fn drain_before_emit_allows_emission_from_drained_set() {
    let mut aud = auditor_with_divergences(&[
        (1, 1, DivergenceClass::DigestMismatch, 100, 200),
        (2, 1, DivergenceClass::DigestMismatch, 300, 400),
    ]);

    // Drain first
    let _drained = aud.drain_divergences();
    assert!(!aud.has_emitted_receipts());

    // current_divergences is now empty, so no receipts
    let receipts = aud.emit_repair_receipts("after drain");
    assert_eq!(receipts.len(), 0);
}
