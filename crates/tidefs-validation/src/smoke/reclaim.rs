// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reclaim smoke: deterministic scheduler, batch planning, and completion
//! accounting checks over `tidefs-reclaim`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_reclaim::{
    plan_reclaim_completion, ReclaimCandidate, ReclaimCompletionOutcome, ReclaimConfig,
    ReclaimScheduler, ReclaimSegment,
};

/// Run the full reclaim smoke sequence and return the harness.
#[must_use]
pub fn run_reclaim_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("reclaim/smoke");

    let config = ReclaimConfig {
        waste_threshold: 0.25,
        batch_size: 2,
        cooldown_segments: 1,
    };
    let mut scheduler = ReclaimScheduler::new(config.clone());

    record_reclaim_op(&mut h, "scheduler.new", 0, Vec::new());
    h.assert_ev(
        "new reclaim scheduler starts inactive",
        !scheduler.is_active(),
    );
    h.assert_eq_ev("new scheduler has zero batches", scheduler.batches(), 0);
    h.assert_eq_ev(
        "new scheduler has zero reclaimed segments",
        scheduler.total_reclaimed(),
        0,
    );
    h.assert_ev(
        "retired scheduler exposes sentinel waste threshold",
        scheduler.waste_threshold().is_infinite(),
    );

    record_reclaim_op(&mut h, "scheduler.activate", 0, Vec::new());
    scheduler.activate();
    h.assert_ev(
        "activated retired scheduler remains inactive",
        !scheduler.is_active(),
    );
    h.assert_ev(
        "retired scheduler does not authorize reclaim",
        !scheduler.can_reclaim(10),
    );

    record_reclaim_op(&mut h, "scheduler.mark_reclaimed", 10, Vec::new());
    scheduler.mark_reclaimed(10);
    h.assert_ev(
        "retired scheduler ignores cooldown authorization",
        !scheduler.can_reclaim(11),
    );

    let segments = [
        ReclaimSegment::new(1, 80, 20),
        ReclaimSegment::new(2, 25, 75),
        ReclaimSegment::new(3, 50, 50),
        ReclaimSegment::new(4, 0, 0),
        ReclaimSegment::new(5, 5, 15),
    ];

    record_reclaim_op(
        &mut h,
        "scheduler.plan_batch",
        0,
        encode_segments(&segments),
    );
    let plan = scheduler.plan_batch(segments);
    h.assert_eq_ev("batch plan respects configured limit", plan.len(), 2);
    h.assert_eq_ev(
        "batch plan selects partial-live candidates in segment order",
        candidate_ids(&plan.candidates),
        vec![1, 2],
    );
    h.assert_eq_ev(
        "batch plan sums selected reclaimable bytes",
        plan.total_reclaimable_bytes,
        95,
    );
    h.assert_ev(
        "partial-live low-waste segment is included in handoff batch",
        candidate_ids(&plan.candidates).contains(&1),
    );
    h.assert_ev(
        "empty segment is excluded from reclaim batch",
        !candidate_ids(&plan.candidates).contains(&4),
    );

    record_reclaim_op(&mut h, "scheduler.record_batch", 2, Vec::new());
    scheduler.record_batch(plan.len() as u64);
    h.assert_eq_ev(
        "record_batch increments batch count",
        scheduler.batches(),
        1,
    );
    h.assert_eq_ev(
        "record_batch accumulates reclaimed segment count",
        scheduler.total_reclaimed(),
        2,
    );

    let completion_candidates = [
        ReclaimCandidate {
            segment_id: 2,
            live_bytes: 25,
            reclaimable_bytes: 75,
        },
        ReclaimCandidate {
            segment_id: 5,
            live_bytes: 5,
            reclaimable_bytes: 15,
        },
        ReclaimCandidate {
            segment_id: 7,
            live_bytes: 30,
            reclaimable_bytes: 70,
        },
    ];
    record_reclaim_op(
        &mut h,
        "scheduler.plan_completion",
        0,
        encode_candidates(&completion_candidates),
    );
    let completion = plan_reclaim_completion(
        completion_candidates,
        [
            ReclaimCompletionOutcome::Reclaimed { segment_id: 2 },
            ReclaimCompletionOutcome::Failed { segment_id: 5 },
        ],
    )
    .expect("mixed reclaim completion should plan successfully");

    h.assert_eq_ev(
        "completion keeps reclaimed candidates in selected order",
        candidate_ids(&completion.reclaimed_candidates),
        vec![2],
    );
    h.assert_eq_ev(
        "completion keeps failed candidates in selected order",
        candidate_ids(&completion.retained_failures),
        vec![5],
    );
    h.assert_eq_ev(
        "completion tracks pending selected candidates",
        candidate_ids(&completion.pending_candidates),
        vec![7],
    );
    h.assert_eq_ev(
        "completion makes failed and pending candidates retryable",
        candidate_ids(&completion.retryable_candidates),
        vec![5, 7],
    );
    h.assert_eq_ev(
        "completion sums only successfully reclaimed bytes",
        completion.total_reclaimed_bytes,
        75,
    );

    record_reclaim_op(&mut h, "scheduler.deactivate", 0, Vec::new());
    scheduler.deactivate();
    h.assert_ev(
        "deactivated reclaim scheduler is inactive",
        !scheduler.is_active(),
    );

    h.scenario_end("reclaim/smoke");
    h
}

fn record_reclaim_op(h: &mut SmokeHarness, op_name: &str, segment_id: u64, payload: Vec<u8>) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: segment_id,
        op_name: op_name.to_string(),
        payload,
    });
}

fn encode_segments(segments: &[ReclaimSegment]) -> Vec<u8> {
    segments
        .iter()
        .map(|segment| {
            format!(
                "{}:{}/{}",
                segment.segment_id, segment.live_bytes, segment.reclaimable_bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes()
}

fn encode_candidates(candidates: &[ReclaimCandidate]) -> Vec<u8> {
    candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}:{}/{}",
                candidate.segment_id, candidate.live_bytes, candidate.reclaimable_bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes()
}

fn candidate_ids(candidates: &[ReclaimCandidate]) -> Vec<u64> {
    candidates
        .iter()
        .map(|candidate| candidate.segment_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_reclaim_passes() {
        let h = run_reclaim_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
