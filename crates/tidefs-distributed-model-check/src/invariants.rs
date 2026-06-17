// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Distributed safety invariant checks.

use super::DistributedSystem;

/// A single safety-invariant violation with a human-readable description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedInvariantViolation {
    pub invariant: &'static str,
    pub description: String,
}

impl DistributedInvariantViolation {
    #[must_use]
    pub fn new(invariant: &'static str, description: String) -> Self {
        Self { invariant, description }
    }
}

/// Run all distributed safety invariant checks.
#[must_use]
pub fn check_distributed_invariants(sys: &DistributedSystem) -> Vec<DistributedInvariantViolation> {
    let mut violations = Vec::new();
    violations.extend(no_conflicting_committed_writers(sys));
    violations.extend(no_stale_epoch_commit(sys));
    violations.extend(no_false_quorum_success(sys));
    violations.extend(no_rebuild_before_receipt(sys));
    violations
}

/// I-1: No two nodes may have committed writes for the same object
/// in the same epoch from different writer nodes.
#[must_use]
pub fn no_conflicting_committed_writers(sys: &DistributedSystem) -> Vec<DistributedInvariantViolation> {
    let mut violations = Vec::new();

    for node in &sys.nodes {
        for write in &node.committed_object_writes {
            for other in &sys.nodes {
                if other.node_id == node.node_id {
                    continue;
                }
                for ow in &other.committed_object_writes {
                    if ow.object_key == write.object_key
                        && ow.epoch == write.epoch
                        && ow.writer_node_id != write.writer_node_id
                    {
                        violations.push(DistributedInvariantViolation::new(
                            "no_conflicting_committed_writers",
                            format!(
                                "conflict: node {} committed write_id {} on object {} epoch {}, \
                                 but node {} already committed write_id {} on same object/epoch",
                                write.writer_node_id, write.write_id,
                                write.object_key, write.epoch,
                                ow.writer_node_id, ow.write_id,
                            ),
                        ));
                    }
                }
            }
        }
    }

    violations.sort_by(|a, b| a.description.cmp(&b.description));
    violations.dedup_by(|a, b| a.description == b.description);
    violations
}

/// I-2: No node may have a committed write at an epoch older than
/// the node's current epoch (stale-epoch commit).
#[must_use]
pub fn no_stale_epoch_commit(sys: &DistributedSystem) -> Vec<DistributedInvariantViolation> {
    let mut violations = Vec::new();

    for node in &sys.nodes {
        for write in &node.committed_object_writes {
            if write.epoch < node.current_epoch {
                violations.push(DistributedInvariantViolation::new(
                    "no_stale_epoch_commit",
                    format!(
                        "node {} committed write_id {} on object {} at epoch {}, \
                         but current epoch is {}",
                        node.node_id, write.write_id,
                        write.object_key, write.epoch,
                        node.current_epoch,
                    ),
                ));
            }
        }
        for qw in &node.quorum_writes {
            if qw.committed && qw.epoch < node.current_epoch {
                violations.push(DistributedInvariantViolation::new(
                    "no_stale_epoch_commit",
                    format!(
                        "node {} has committed quorum write_id {} on object {} at epoch {}, \
                         but current epoch is {}",
                        node.node_id, qw.write_id,
                        qw.object_key, qw.epoch,
                        node.current_epoch,
                    ),
                ));
            }
        }
    }

    violations
}

/// I-3: No committed quorum write may have fewer acks than its
/// declared quorum size (false quorum success).
#[must_use]
pub fn no_false_quorum_success(sys: &DistributedSystem) -> Vec<DistributedInvariantViolation> {
    let mut violations = Vec::new();

    for node in &sys.nodes {
        for qw in &node.quorum_writes {
            if qw.committed && qw.acks_received < qw.quorum_size {
                violations.push(DistributedInvariantViolation::new(
                    "no_false_quorum_success",
                    format!(
                        "node {} quorum write_id {} on object {} is committed but has \
                         {} acks (need >= {})",
                        node.node_id, qw.write_id,
                        qw.object_key, qw.acks_received,
                        qw.quorum_size,
                    ),
                ));
            }
        }
    }

    for qw in &sys.quorum_model.writes {
        if qw.committed && qw.acks_received < qw.quorum_size {
            violations.push(DistributedInvariantViolation::new(
                "no_false_quorum_success",
                format!(
                    "quorum model write_id {} on object {} is committed but has \
                     {} acks (need >= {})",
                    qw.write_id, qw.object_key,
                    qw.acks_received, qw.quorum_size,
                ),
            ));
        }
    }

    violations
}

/// I-4: No rebuild/reclaim attempt may be permitted without a prior
/// durable placement receipt.
#[must_use]
pub fn no_rebuild_before_receipt(sys: &DistributedSystem) -> Vec<DistributedInvariantViolation> {
    let mut violations = Vec::new();

    for attempt in &sys.placement_model.rebuild_attempts {
        if attempt.allowed && !attempt.had_durable_receipt {
            if matches!(
                sys.placement_model.policy,
                super::placement::RebuildPolicy::RequireDurableReceipt
            ) {
                violations.push(DistributedInvariantViolation::new(
                    "no_rebuild_before_receipt",
                    format!(
                        "rebuild on object {} at node {} epoch {} was allowed \
                         without a durable placement receipt",
                        attempt.object_key, attempt.target_node, attempt.epoch,
                    ),
                ));
            }
        }
    }

    violations
}
