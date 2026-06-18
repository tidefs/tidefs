// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Deterministic distributed safety model checker.
//!
//! This crate models membership epoch advancement, lease grant/revoke,
//! quorum write commit, and placement/receipt durability in a bounded
//! distributed system with controllable network reorder/drop/delay/duplicate
//! assumptions.  Safety invariants are checked after every state transition;
//! violations are returned as structured errors so model-check tests can
//! assert on expected safety properties.
//!
//! Placement/receipt identity and locator types are sourced from the
//! settled authority crates (`tidefs-replication-model`,
//! `tidefs-membership-epoch`) rather than inventing parallel types.
//! The model itself remains deterministic and self-contained for lease,
//! quorum-write, and network behaviour.
//!
//! # Safety invariants
//!
//! - No conflicting committed writers for the same object/epoch.
//! - No stale-epoch commit.
//! - No active lease conflict or stale active lease across epochs.
//! - No false quorum success (commit with fewer acks than quorum requires).
//! - No rebuild/reclaim before replacement receipt durability.
//!
//! # Trace artifacts
//!
//! Trace artifacts feed the claim catalog as model-check evidence only;
//! runtime distributed correctness remains separately gated.

pub mod epoch;
pub mod invariants;
pub mod lease;
pub mod network;
pub mod placement;
pub mod quorum;
pub mod receipt;

#[cfg(test)]
mod tests;

pub use epoch::{EpochState, MembershipEpochModel};
pub use invariants::{
    check_distributed_invariants, no_active_lease_epoch_conflict, no_conflicting_committed_writers,
    no_false_quorum_success, no_rebuild_before_receipt, no_stale_epoch_commit,
    DistributedInvariantViolation,
};
pub use lease::{LeaseModel, LeaseOutcome, LeaseState};
pub use network::{DeliveryPolicy, DistributedMessage, NetworkModel, NodeAddress};
pub use placement::{
    model_placement_receipt_ref, receipt_ref_to_model_key, PlacementModel, PlacementReceiptRef,
    PlacementReceiptState, RebuildAttempt, RebuildPolicy,
};
pub use quorum::{QuorumWriteModel, QuorumWriteOutcome, QuorumWriteRequest, QuorumWriteState};
pub use receipt::{
    checked_combined_safety_invariants, missing_required_combined_invariants,
    DistributedSafetyBounds, DistributedSafetyInvariantReceipt, DistributedSafetyOutcome,
    DistributedSafetyReceipt, DistributedSafetyReceiptError, DistributedSafetyViolationReceipt,
    DISTRIBUTED_COMBINED_SAFETY_EVIDENCE_CLASS, DISTRIBUTED_COMBINED_SAFETY_VALIDATION_TIER,
    REQUIRED_COMBINED_INVARIANT_IDS,
};

/// Maximum number of nodes in a model-check scenario (keeps state space bounded).
pub const MAX_MODEL_NODES: usize = 7;

/// Maximum epoch value for bounded model checking.
pub const MAX_MODEL_EPOCH: u64 = 16;

/// Maximum lease count per node for bounded model checking.
pub const MAX_MODEL_LEASES_PER_NODE: usize = 8;

/// Maximum outstanding quorum writes for bounded model checking.
pub const MAX_MODEL_QUORUM_WRITES: usize = 16;

/// Top-level distributed system under model check.
#[derive(Clone, Debug)]
pub struct DistributedSystem {
    pub nodes: Vec<NodeState>,
    pub network: NetworkModel,
    pub epoch_model: MembershipEpochModel,
    pub lease_model: LeaseModel,
    pub quorum_model: QuorumWriteModel,
    pub placement_model: PlacementModel,
    pub step_count: u64,
}

impl DistributedSystem {
    #[must_use]
    pub fn new(node_count: usize) -> Self {
        assert!(
            node_count >= 1 && node_count <= MAX_MODEL_NODES,
            "node_count {node_count} out of range [1, {MAX_MODEL_NODES}]",
        );
        let nodes: Vec<NodeState> = (0..node_count as u64).map(NodeState::new).collect();
        Self {
            nodes: nodes.clone(),
            network: NetworkModel::new(node_count),
            epoch_model: MembershipEpochModel::new(node_count),
            lease_model: LeaseModel::new(),
            quorum_model: QuorumWriteModel::new(),
            placement_model: PlacementModel::new(node_count),
            step_count: 0,
        }
    }

    /// Advance the model by one step, applying any pending network delivery
    /// and checking all invariants.
    ///
    /// Returns any invariant violations found.
    pub fn step(&mut self) -> Vec<DistributedInvariantViolation> {
        self.step_count += 1;
        self.network
            .deliver_pending(&mut self.nodes, &mut self.epoch_model);
        check_distributed_invariants(self)
    }

    /// Advance by `n` steps, checking invariants after each step.
    /// Returns all violations aggregated.
    pub fn step_n(&mut self, n: u64) -> Vec<DistributedInvariantViolation> {
        let mut all = Vec::new();
        for _ in 0..n {
            all.extend(self.step());
        }
        all
    }

    /// Advance until the network queue is empty, checking invariants.
    pub fn drain_network(&mut self) -> Vec<DistributedInvariantViolation> {
        let mut all = Vec::new();
        while !self.network.is_empty() {
            all.extend(self.step());
        }
        all
    }
}

/// Per-node state within the distributed model.
#[derive(Clone, Debug)]
pub struct NodeState {
    pub node_id: u64,
    pub current_epoch: u64,
    pub lease_grants: Vec<LeaseState>,
    pub quorum_writes: Vec<QuorumWriteState>,
    pub placement_receipts: Vec<PlacementReceiptState>,
    pub committed_object_writes: Vec<CommittedObjectWrite>,
}

impl NodeState {
    #[must_use]
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            current_epoch: 0,
            lease_grants: Vec::new(),
            quorum_writes: Vec::new(),
            placement_receipts: Vec::new(),
            committed_object_writes: Vec::new(),
        }
    }
}

/// Record of a committed write for a specific object in a specific epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedObjectWrite {
    pub object_key: String,
    pub epoch: u64,
    pub writer_node_id: u64,
    pub write_id: u64,
    /// The settled placement receipt ref that authorises this write.
    /// Carries the receipt identity from `tidefs-replication-model`.
    pub placement_receipt_ref: PlacementReceiptRef,
}
