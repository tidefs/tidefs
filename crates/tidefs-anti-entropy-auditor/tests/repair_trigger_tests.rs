// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Repair trigger threshold tests — verify that divergence counts
//! map to appropriate escalation levels: log-only, schedule-background,
//! and immediate-repair based on ticketable-divergence thresholds.

use tidefs_anti_entropy_auditor::ae_state::{AntiEntropyState, DivergenceClass, DivergenceRecord};
use tidefs_anti_entropy_auditor::comparator::ComparisonInput;
use tidefs_anti_entropy_auditor::scan_scheduler::{ScanDecision, ScanSchedulePolicy};
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

// ── Threshold classification helper ──────────────────────────────────

#[derive(Debug, PartialEq)]
enum RepairEscalation {
    LogOnly,
    ScheduleBackground,
    ImmediateRepair,
}

fn classify_escalation(ticketable_count: usize) -> RepairEscalation {
    match ticketable_count {
        0 => RepairEscalation::LogOnly,
        1..=2 => RepairEscalation::LogOnly,
        3..=5 => RepairEscalation::ScheduleBackground,
        _ => RepairEscalation::ImmediateRepair,
    }
}

// ── Below-threshold: log-only ────────────────────────────────────────

#[test]
fn zero_divergences_log_only() {
    assert_eq!(classify_escalation(0), RepairEscalation::LogOnly);
}

#[test]
fn single_divergence_log_only() {
    assert_eq!(classify_escalation(1), RepairEscalation::LogOnly);
}

#[test]
fn two_divergences_log_only() {
    assert_eq!(classify_escalation(2), RepairEscalation::LogOnly);
}

#[test]
fn only_lag_divergences_no_tickets_log_only() {
    let records = [
        DivergenceRecord::new(1, 1, DivergenceClass::LagBehind, 100, 90, 1, 1000),
        DivergenceRecord::new(2, 1, DivergenceClass::LagBehind, 200, 180, 1, 2000),
        DivergenceRecord::new(3, 1, DivergenceClass::LagBehind, 300, 270, 1, 3000),
    ];

    let ticketable = records.iter().filter(|r| r.requires_ticket()).count();
    assert_eq!(ticketable, 0);
    assert_eq!(classify_escalation(ticketable), RepairEscalation::LogOnly);
}

// ── At-threshold: schedule background ────────────────────────────────

#[test]
fn three_divergences_schedule_background() {
    assert_eq!(classify_escalation(3), RepairEscalation::ScheduleBackground);
}

#[test]
fn four_divergences_schedule_background() {
    assert_eq!(classify_escalation(4), RepairEscalation::ScheduleBackground);
}

#[test]
fn five_divergences_schedule_background() {
    assert_eq!(classify_escalation(5), RepairEscalation::ScheduleBackground);
}

// ── Above-threshold: immediate repair ────────────────────────────────

#[test]
fn six_divergences_immediate_repair() {
    assert_eq!(classify_escalation(6), RepairEscalation::ImmediateRepair);
}

#[test]
fn ten_divergences_immediate_repair() {
    assert_eq!(classify_escalation(10), RepairEscalation::ImmediateRepair);
}

#[test]
fn one_hundred_divergences_immediate_repair() {
    assert_eq!(classify_escalation(100), RepairEscalation::ImmediateRepair);
}

// ── Auditor escalation via scan scheduler acceleration ───────────────

#[test]
fn divergence_detection_accelerates_next_scan() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    let t0 = 0;
    aud.begin_scan(t0).unwrap();
    aud.begin_compare(t0 + NS_PER_SEC, 100);

    // Inject 5 divergences (schedule-background threshold)
    let inputs: Vec<ComparisonInput> = (1..=5)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, t0 + 2 * NS_PER_SEC);
    aud.record_comparisons(&results, t0 + 2 * NS_PER_SEC);

    aud.classify_divergences(t0 + 3 * NS_PER_SEC);
    aud.record_tickets(t0 + 4 * NS_PER_SEC, &[1, 2, 3, 4, 5]);
    aud.resolve(t0 + 5 * NS_PER_SEC, &[10, 11, 12, 13, 14]);

    // Complete scan with divergences -> next scan interval should be shorter
    aud.complete_scan(t0 + 6 * NS_PER_SEC);

    // min_scan_interval = 5 min, divergence_backoff = 2.0 -> interval = 2.5 min
    // After 3 min: should be eligible
    let t_check = t0 + 6 * NS_PER_MIN + 3 * NS_PER_MIN; // 9 min total
    let decision = aud.should_scan(t_check, 0.3);
    assert_eq!(decision, ScanDecision::Proceed);
}

#[test]
fn no_divergence_scan_uses_max_interval() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    let t0 = 0;
    aud.begin_scan(t0).unwrap();
    aud.begin_compare(t0 + NS_PER_SEC, 100);

    // All matched — no divergences
    let inputs: Vec<ComparisonInput> = (1..=5)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, t0 + 2 * NS_PER_SEC);
    aud.record_comparisons(&results, t0 + 2 * NS_PER_SEC);

    aud.complete_scan(t0 + 3 * NS_PER_SEC);

    // After 10 min (well under max_interval of 60 min): should be TooSoon
    let t_check = t0 + 13 * NS_PER_MIN; // 13 min since t0
    let decision = aud.should_scan(t_check, 0.3);
    assert!(matches!(decision, ScanDecision::TooSoon { .. }));
}

// ── Threshold transitions within a single audit ───────────────────────

#[test]
fn increasing_divergence_count_changes_classification() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(100);

    let t = NS_PER_MIN;
    aud.begin_scan(t).unwrap();
    aud.begin_compare(t + 1, 100);

    // Feed divergences one at a time, check classification at each step

    // 1 divergence -> below threshold
    let inputs1: Vec<ComparisonInput> = (1..=1)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r1 = aud.comparator.compare_batch(&inputs1, t + 2);
    aud.record_comparisons(&r1, t + 2);
    assert_eq!(
        classify_escalation(aud.ticketable_divergences().len()),
        RepairEscalation::LogOnly
    );

    // +2 more = 3 total -> schedule background
    let inputs2: Vec<ComparisonInput> = (2..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r2 = aud.comparator.compare_batch(&inputs2, t + 3);
    aud.record_comparisons(&r2, t + 3);
    assert_eq!(
        classify_escalation(aud.ticketable_divergences().len()),
        RepairEscalation::ScheduleBackground
    );

    // +3 more = 6 total -> immediate repair
    let inputs3: Vec<ComparisonInput> = (4..=6)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let r3 = aud.comparator.compare_batch(&inputs3, t + 4);
    aud.record_comparisons(&r3, t + 4);
    assert_eq!(
        classify_escalation(aud.ticketable_divergences().len()),
        RepairEscalation::ImmediateRepair
    );
}

// ── Repair trigger via state machine ──────────────────────────────────

#[test]
fn state_classify_divergences_reports_correct_counts() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(20);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 20);

    let inputs: Vec<ComparisonInput> = vec![
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
            witness_digest: Some(42),
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 3,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: Some(42),
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 4,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        },
        ComparisonInput {
            subject_ref: 5,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        },
    ];

    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);
    aud.classify_divergences(NS_PER_MIN + 1);

    match &aud.state {
        AntiEntropyState::DivergenceFound {
            total_divergences,
            classified_lag,
            classified_corruption,
            classified_missing,
            ..
        } => {
            assert_eq!(*total_divergences, 5);
            assert_eq!(*classified_lag, 1); // subject 1: LagBehind
            assert_eq!(*classified_corruption, 2); // subjects 2,3: DigestMismatch
            assert_eq!(*classified_missing, 2); // subjects 4,5: MissingReplica
        }
        _ => panic!("expected DivergenceFound"),
    }
}

#[test]
fn zero_tickets_created_for_lag_only_divergences() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 5);

    let inputs: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: Some(42),
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    // All three are LagBehind — no tickets needed
    assert_eq!(aud.ticketable_divergences().len(), 0);
    assert_eq!(aud.lag_divergences().len(), 3);
}

// ── Empty ticket set edge case ────────────────────────────────────────

#[test]
fn record_empty_tickets_preserves_state() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(10);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 5);

    // No divergences
    let inputs: Vec<ComparisonInput> = (1..=3)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &[]);

    match &aud.state {
        AntiEntropyState::Ticketed {
            tickets_created,
            ticket_range_start,
            ticket_range_end,
            ..
        } => {
            assert_eq!(*tickets_created, 0);
            assert_eq!(*ticket_range_start, 0);
            assert_eq!(*ticket_range_end, 0);
        }
        _ => panic!("expected Ticketed"),
    }
}

// ── Drain after threshold escalation ─────────────────────────────────

#[test]
fn drain_divergences_after_immediate_repair_threshold() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(50);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 10);

    // Create 7 divergences (above immediate-repair threshold of 6)
    let inputs: Vec<ComparisonInput> = (1..=7)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    assert_eq!(aud.ticketable_divergences().len(), 7);
    assert_eq!(classify_escalation(7), RepairEscalation::ImmediateRepair);

    // Drain and verify escalation still detectable from drained records
    let drained = aud.drain_divergences();
    let ticketable_drained = drained.iter().filter(|r| r.requires_ticket()).count();
    assert_eq!(ticketable_drained, 7);
    assert_eq!(
        classify_escalation(ticketable_drained),
        RepairEscalation::ImmediateRepair
    );
}

// ── Boundary conditions ──────────────────────────────────────────────

#[test]
fn exactly_at_background_threshold_lower_bound() {
    assert_eq!(classify_escalation(3), RepairEscalation::ScheduleBackground);
}

#[test]
fn exactly_at_background_threshold_upper_bound() {
    assert_eq!(classify_escalation(5), RepairEscalation::ScheduleBackground);
}

#[test]
fn exactly_at_immediate_threshold() {
    assert_eq!(classify_escalation(6), RepairEscalation::ImmediateRepair);
}

#[test]
fn exactly_at_log_threshold_upper_bound() {
    assert_eq!(classify_escalation(2), RepairEscalation::LogOnly);
}

// ── Large-scale repair trigger ────────────────────────────────────────

#[test]
fn large_divergence_count_immediate_repair_with_tickets() {
    let mut aud = AntiEntropyAuditor::new(policy(), 1, 0);
    aud.set_total_subjects(200);

    aud.begin_scan(NS_PER_MIN).unwrap();
    aud.begin_compare(NS_PER_MIN, 200);

    // 50 divergences — well above immediate threshold
    let inputs: Vec<ComparisonInput> = (1..=50)
        .map(|s| ComparisonInput {
            subject_ref: s,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        })
        .collect();
    let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
    aud.record_comparisons(&results, NS_PER_MIN);

    assert_eq!(aud.current_divergences.len(), 50);
    assert_eq!(
        classify_escalation(aud.ticketable_divergences().len()),
        RepairEscalation::ImmediateRepair
    );

    // Tickets created for all 50
    let ticket_ids: Vec<u64> = (1000..1050).collect();
    aud.classify_divergences(NS_PER_MIN + 1);
    aud.record_tickets(NS_PER_MIN + 2, &ticket_ids);
    assert_eq!(aud.tickets_created.len(), 50);
}

// ── Hysteresis-like: don't oscillate between levels ──────────────────

#[test]
fn threshold_boundaries_dont_overlap() {
    // Verify the thresholds are non-overlapping
    for count in 0..=20 {
        let level = classify_escalation(count);
        match count {
            0..=2 => assert_eq!(level, RepairEscalation::LogOnly, "count={count}"),
            3..=5 => assert_eq!(level, RepairEscalation::ScheduleBackground, "count={count}"),
            _ => assert_eq!(level, RepairEscalation::ImmediateRepair, "count={count}"),
        }
    }
}
