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

const SEGMENT_RECLAIM_MATRIX_ROW: SegmentReclaimValidationRow = SegmentReclaimValidationRow {
    capacity_accounting: true,
    zero_visible: false,
    discard_acceptance: false,
    media_privacy: false,
    cryptographic_erase: false,
    secure_erase: false,
    sanitization: false,
    decommissioning: false,
};

const POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW: PoolDestroyLiveOwnerRefusalValidationRow =
    PoolDestroyLiveOwnerRefusalValidationRow {
        typed_refusal: true,
        state: "DestroyRefusedLiveOwnerMounted",
        code: "live-owner-pool-destroy-refused",
        mounted_dataset_refusal: true,
        allowed_state: "exported-offline-explicit-devices",
        shutdown_requested: false,
        label_superblock_action: "none",
        product_claim_evidence: false,
        capacity_free: false,
        zero_visible: false,
        discard_acceptance: false,
        media_privacy: false,
        cryptographic_erase: false,
        secure_erase: false,
        sanitization: false,
        decommissioning: false,
    };

#[derive(Clone, Copy)]
struct SegmentReclaimValidationRow {
    capacity_accounting: bool,
    zero_visible: bool,
    discard_acceptance: bool,
    media_privacy: bool,
    cryptographic_erase: bool,
    secure_erase: bool,
    sanitization: bool,
    decommissioning: bool,
}

impl SegmentReclaimValidationRow {
    fn unsupported_evidence(self) -> [(&'static str, bool); 7] {
        [
            ("zero-visible behavior", self.zero_visible),
            ("discard acceptance", self.discard_acceptance),
            ("media privacy", self.media_privacy),
            ("cryptographic erase", self.cryptographic_erase),
            ("secure erase", self.secure_erase),
            ("sanitization", self.sanitization),
            ("decommissioning readiness", self.decommissioning),
        ]
    }

    fn encode(self) -> Vec<u8> {
        format!(
            concat!(
                "row=device-lifecycle.segment-reclaim.capacity-only;",
                "capacity_accounting={};",
                "zero_visible={};",
                "discard_acceptance={};",
                "media_privacy={};",
                "cryptographic_erase={};",
                "secure_erase={};",
                "sanitization={};",
                "decommissioning={}"
            ),
            self.capacity_accounting,
            self.zero_visible,
            self.discard_acceptance,
            self.media_privacy,
            self.cryptographic_erase,
            self.secure_erase,
            self.sanitization,
            self.decommissioning
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy)]
struct PoolDestroyLiveOwnerRefusalValidationRow {
    typed_refusal: bool,
    state: &'static str,
    code: &'static str,
    mounted_dataset_refusal: bool,
    allowed_state: &'static str,
    shutdown_requested: bool,
    label_superblock_action: &'static str,
    product_claim_evidence: bool,
    capacity_free: bool,
    zero_visible: bool,
    discard_acceptance: bool,
    media_privacy: bool,
    cryptographic_erase: bool,
    secure_erase: bool,
    sanitization: bool,
    decommissioning: bool,
}

impl PoolDestroyLiveOwnerRefusalValidationRow {
    fn unsupported_evidence(self) -> [(&'static str, bool); 8] {
        [
            ("capacity free", self.capacity_free),
            ("zero-visible behavior", self.zero_visible),
            ("discard acceptance", self.discard_acceptance),
            ("media privacy", self.media_privacy),
            ("cryptographic erase", self.cryptographic_erase),
            ("secure erase", self.secure_erase),
            ("sanitization", self.sanitization),
            ("decommissioning readiness", self.decommissioning),
        ]
    }

    fn encode(self) -> Vec<u8> {
        format!(
            concat!(
                "row=device-lifecycle.pool-destroy.live-owner-refusal;",
                "typed_refusal={};",
                "state={};",
                "code={};",
                "mounted_dataset_refusal={};",
                "allowed_state={};",
                "shutdown_requested={};",
                "label_superblock_action={};",
                "product_claim_evidence={};",
                "capacity_free={};",
                "zero_visible={};",
                "discard_acceptance={};",
                "media_privacy={};",
                "cryptographic_erase={};",
                "secure_erase={};",
                "sanitization={};",
                "decommissioning={}"
            ),
            self.typed_refusal,
            self.state,
            self.code,
            self.mounted_dataset_refusal,
            self.allowed_state,
            self.shutdown_requested,
            self.label_superblock_action,
            self.product_claim_evidence,
            self.capacity_free,
            self.zero_visible,
            self.discard_acceptance,
            self.media_privacy,
            self.cryptographic_erase,
            self.secure_erase,
            self.sanitization,
            self.decommissioning
        )
        .into_bytes()
    }
}

/// Run the full reclaim smoke sequence and return the harness.
#[must_use]
pub fn run_reclaim_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("reclaim/smoke");
    record_reclaim_op(
        &mut h,
        "validation.matrix.segment_reclaim_capacity_only",
        0,
        SEGMENT_RECLAIM_MATRIX_ROW.encode(),
    );
    h.assert_ev(
        "segment reclaim smoke admits capacity accounting evidence",
        SEGMENT_RECLAIM_MATRIX_ROW.capacity_accounting,
    );
    for (evidence, admitted) in SEGMENT_RECLAIM_MATRIX_ROW.unsupported_evidence() {
        h.assert_ev(
            &format!("segment reclaim smoke does not claim {evidence} evidence"),
            !admitted,
        );
    }
    record_reclaim_op(
        &mut h,
        "validation.matrix.pool_destroy_live_owner_refusal",
        0,
        POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW.encode(),
    );
    h.assert_ev(
        "pool destroy live-owner matrix records typed refusal",
        POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW.typed_refusal,
    );
    h.assert_ev(
        "pool destroy live-owner matrix records mounted dataset refusal",
        POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW.mounted_dataset_refusal,
    );
    h.assert_ev(
        "pool destroy live-owner matrix is not product claim evidence",
        !POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW.product_claim_evidence,
    );
    for (evidence, admitted) in POOL_DESTROY_LIVE_OWNER_REFUSAL_MATRIX_ROW.unsupported_evidence() {
        h.assert_ev(
            &format!("pool destroy live-owner refusal does not claim {evidence} evidence"),
            !admitted,
        );
    }

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
    use std::collections::BTreeMap;

    use super::*;

    fn matrix_row_fields(marker: &str) -> BTreeMap<&str, &str> {
        marker
            .split(';')
            .map(|field| {
                field
                    .split_once('=')
                    .unwrap_or_else(|| panic!("matrix row field has key=value shape: {field}"))
            })
            .collect()
    }

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

    #[test]
    fn segment_reclaim_matrix_row_is_capacity_only() {
        let h = run_reclaim_smoke();
        let marker = h.trace.iter().find_map(|event| match event {
            TraceEvent::FsLifecycleOp {
                op_name, payload, ..
            } if op_name == "validation.matrix.segment_reclaim_capacity_only" => {
                Some(std::str::from_utf8(payload).expect("matrix row payload is utf-8"))
            }
            _ => None,
        });
        let marker = marker.expect("segment reclaim matrix row is recorded");
        let fields = matrix_row_fields(marker);

        assert_eq!(
            fields.get("row").copied(),
            Some("device-lifecycle.segment-reclaim.capacity-only")
        );
        assert_eq!(fields.get("capacity_accounting").copied(), Some("true"));
        assert_eq!(fields.get("zero_visible").copied(), Some("false"));
        assert_eq!(fields.get("discard_acceptance").copied(), Some("false"));
        assert_eq!(fields.get("media_privacy").copied(), Some("false"));
        assert_eq!(fields.get("cryptographic_erase").copied(), Some("false"));
        assert_eq!(fields.get("secure_erase").copied(), Some("false"));
        assert_eq!(fields.get("sanitization").copied(), Some("false"));
        assert_eq!(fields.get("decommissioning").copied(), Some("false"));
    }

    #[test]
    fn pool_destroy_live_owner_refusal_matrix_row_is_trace_only() {
        let h = run_reclaim_smoke();
        let marker = h.trace.iter().find_map(|event| match event {
            TraceEvent::FsLifecycleOp {
                op_name, payload, ..
            } if op_name == "validation.matrix.pool_destroy_live_owner_refusal" => {
                Some(std::str::from_utf8(payload).expect("matrix row payload is utf-8"))
            }
            _ => None,
        });
        let marker = marker.expect("pool destroy live-owner refusal matrix row is recorded");
        let fields = matrix_row_fields(marker);

        assert_eq!(
            fields.get("row").copied(),
            Some("device-lifecycle.pool-destroy.live-owner-refusal")
        );
        assert_eq!(fields.get("typed_refusal").copied(), Some("true"));
        assert_eq!(
            fields.get("state").copied(),
            Some("DestroyRefusedLiveOwnerMounted")
        );
        assert_eq!(
            fields.get("code").copied(),
            Some("live-owner-pool-destroy-refused")
        );
        assert_eq!(fields.get("mounted_dataset_refusal").copied(), Some("true"));
        assert_eq!(
            fields.get("allowed_state").copied(),
            Some("exported-offline-explicit-devices")
        );
        assert_eq!(fields.get("shutdown_requested").copied(), Some("false"));
        assert_eq!(fields.get("label_superblock_action").copied(), Some("none"));
        assert_eq!(fields.get("product_claim_evidence").copied(), Some("false"));
        assert_eq!(fields.get("capacity_free").copied(), Some("false"));
        assert_eq!(fields.get("zero_visible").copied(), Some("false"));
        assert_eq!(fields.get("discard_acceptance").copied(), Some("false"));
        assert_eq!(fields.get("media_privacy").copied(), Some("false"));
        assert_eq!(fields.get("cryptographic_erase").copied(), Some("false"));
        assert_eq!(fields.get("secure_erase").copied(), Some("false"));
        assert_eq!(fields.get("sanitization").copied(), Some("false"));
        assert_eq!(fields.get("decommissioning").copied(), Some("false"));
    }
}
