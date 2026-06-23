// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Deterministic model-check receipts for distributed safety evidence.

use std::collections::BTreeSet;

use serde::Serialize;

use super::{
    check_distributed_invariants, DistributedInvariantViolation, DistributedSystem,
    MAX_MODEL_EPOCH, MAX_MODEL_LEASES_PER_NODE, MAX_MODEL_NODES, MAX_MODEL_QUORUM_WRITES,
};

pub const DISTRIBUTED_COMBINED_SAFETY_EVIDENCE_CLASS: &str = "distributed-combined-safety-model";
pub const DISTRIBUTED_COMBINED_SAFETY_CLAIM_ID: &str = "distributed.combined_safety.model.v1";
pub const DISTRIBUTED_COMBINED_SAFETY_VALIDATION_TIER: &str = "source-model";

pub const REQUIRED_COMBINED_INVARIANT_IDS: [&str; 5] = [
    "no_stale_epoch_commit",
    "no_active_lease_epoch_conflict",
    "no_false_quorum_success",
    "no_conflicting_committed_writers",
    "no_rebuild_before_receipt",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DistributedSafetyInvariantReceipt {
    pub id: &'static str,
    pub family: &'static str,
    pub statement: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DistributedSafetyBounds {
    pub max_model_nodes: usize,
    pub max_model_epoch: u64,
    pub max_model_leases_per_node: usize,
    pub max_model_quorum_writes: usize,
    pub explored_nodes: usize,
    pub explored_steps: u64,
    pub epoch_advance_records: usize,
    pub active_lease_records: usize,
    pub quorum_write_records: usize,
    pub placement_receipt_records: usize,
    pub rebuild_attempts: usize,
    pub pending_network_messages: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DistributedSafetyViolationReceipt {
    pub invariant: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DistributedSafetyOutcome {
    pub passed: bool,
    pub violation_count: usize,
    pub violations: Vec<DistributedSafetyViolationReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DistributedSafetyReceipt {
    pub report_version: u64,
    pub generated_by: &'static str,
    pub evidence_class: &'static str,
    pub validation_tier: &'static str,
    pub evidence_scope: &'static str,
    pub runtime_boundary: &'static str,
    pub related_claim_ids: Vec<&'static str>,
    pub blocking_issues: Vec<&'static str>,
    pub bounds: DistributedSafetyBounds,
    pub checked_invariants: Vec<DistributedSafetyInvariantReceipt>,
    pub outcome: DistributedSafetyOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributedSafetyReceiptError {
    IncompleteCombinedInvariantSet {
        missing_invariants: Vec<&'static str>,
    },
}

impl DistributedSafetyReceipt {
    #[must_use]
    pub fn for_system(sys: &DistributedSystem) -> Result<Self, DistributedSafetyReceiptError> {
        let violations = check_distributed_invariants(sys);
        Self::new_combined(sys, checked_combined_safety_invariants(), violations)
    }

    pub fn new_combined(
        sys: &DistributedSystem,
        checked_invariants: Vec<DistributedSafetyInvariantReceipt>,
        violations: Vec<DistributedInvariantViolation>,
    ) -> Result<Self, DistributedSafetyReceiptError> {
        let missing_invariants = missing_required_combined_invariants(&checked_invariants);
        if !missing_invariants.is_empty() {
            return Err(
                DistributedSafetyReceiptError::IncompleteCombinedInvariantSet {
                    missing_invariants,
                },
            );
        }

        Ok(Self {
            report_version: 1,
            generated_by:
                "tidefs-distributed-model-check::combined_safety_receipt-v1",
            evidence_class: DISTRIBUTED_COMBINED_SAFETY_EVIDENCE_CLASS,
            validation_tier: DISTRIBUTED_COMBINED_SAFETY_VALIDATION_TIER,
            evidence_scope:
                "bounded deterministic model-check evidence for epoch, lease, quorum, and placement safety invariants",
            runtime_boundary:
                "model evidence only; this does not validate storage-node runtime, transport, RDMA, production cluster, cluster CLI, or multi-process behavior",
            related_claim_ids: vec![DISTRIBUTED_COMBINED_SAFETY_CLAIM_ID],
            blocking_issues: Vec::new(),
            bounds: DistributedSafetyBounds::from_system(sys),
            checked_invariants,
            outcome: DistributedSafetyOutcome::from_violations(violations),
        })
    }
}

impl DistributedSafetyBounds {
    #[must_use]
    pub fn from_system(sys: &DistributedSystem) -> Self {
        Self {
            max_model_nodes: MAX_MODEL_NODES,
            max_model_epoch: MAX_MODEL_EPOCH,
            max_model_leases_per_node: MAX_MODEL_LEASES_PER_NODE,
            max_model_quorum_writes: MAX_MODEL_QUORUM_WRITES,
            explored_nodes: sys.nodes.len(),
            explored_steps: sys.step_count,
            epoch_advance_records: sys.epoch_model.epoch_history.values().map(Vec::len).sum(),
            active_lease_records: active_lease_record_count(sys),
            quorum_write_records: sys.quorum_model.writes.len()
                + sys
                    .nodes
                    .iter()
                    .map(|node| node.quorum_writes.len())
                    .sum::<usize>(),
            placement_receipt_records: sys.placement_model.receipts.len()
                + sys
                    .nodes
                    .iter()
                    .map(|node| node.placement_receipts.len())
                    .sum::<usize>(),
            rebuild_attempts: sys.placement_model.rebuild_attempts.len(),
            pending_network_messages: sys.network.pending_count(),
        }
    }
}

impl DistributedSafetyOutcome {
    #[must_use]
    pub fn from_violations(violations: Vec<DistributedInvariantViolation>) -> Self {
        let mut violations: Vec<DistributedSafetyViolationReceipt> = violations
            .into_iter()
            .map(|violation| DistributedSafetyViolationReceipt {
                invariant: violation.invariant,
                description: violation.description,
            })
            .collect();
        violations.sort_by(|left, right| {
            left.invariant
                .cmp(right.invariant)
                .then(left.description.cmp(&right.description))
        });
        violations.dedup();

        Self {
            passed: violations.is_empty(),
            violation_count: violations.len(),
            violations,
        }
    }
}

#[must_use]
pub fn checked_combined_safety_invariants() -> Vec<DistributedSafetyInvariantReceipt> {
    vec![
        DistributedSafetyInvariantReceipt {
            id: "no_stale_epoch_commit",
            family: "epoch",
            statement:
                "committed object writes and quorum writes must not be older than the observing node epoch",
        },
        DistributedSafetyInvariantReceipt {
            id: "no_active_lease_epoch_conflict",
            family: "lease",
            statement:
                "active leases must not conflict for the same object and epoch, and must not be older than the holder epoch",
        },
        DistributedSafetyInvariantReceipt {
            id: "no_false_quorum_success",
            family: "quorum",
            statement:
                "committed quorum writes must carry at least the declared quorum acknowledgements",
        },
        DistributedSafetyInvariantReceipt {
            id: "no_conflicting_committed_writers",
            family: "quorum",
            statement:
                "different writers must not commit the same object in the same epoch",
        },
        DistributedSafetyInvariantReceipt {
            id: "no_rebuild_before_receipt",
            family: "placement",
            statement:
                "rebuild and reclaim attempts require a prior durable placement receipt when the model policy requires one",
        },
    ]
}

#[must_use]
pub fn missing_required_combined_invariants(
    checked_invariants: &[DistributedSafetyInvariantReceipt],
) -> Vec<&'static str> {
    let checked_ids: BTreeSet<&str> = checked_invariants
        .iter()
        .map(|invariant| invariant.id)
        .collect();
    REQUIRED_COMBINED_INVARIANT_IDS
        .iter()
        .copied()
        .filter(|required| !checked_ids.contains(required))
        .collect()
}

fn active_lease_record_count(sys: &DistributedSystem) -> usize {
    sys.lease_model
        .leases
        .iter()
        .filter(|lease| lease.granted && !lease.revoked)
        .count()
        + sys
            .nodes
            .iter()
            .map(|node| {
                node.lease_grants
                    .iter()
                    .filter(|lease| lease.granted && !lease.revoked)
                    .count()
            })
            .sum::<usize>()
}
