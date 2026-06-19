// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::evacuation_receipt::{EvacuationReceipt, EvacuationReceiptError};
use std::fmt;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// Node lifecycle states
// ---------------------------------------------------------------------------

/// The lifecycle state of a node in the cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeState {
    /// Node is active and participating normally.
    Active,
    /// Node is in the process of draining.
    Draining,
    /// Node has completed drain, no duties remain.
    Drained,
    /// Node has been fully decommissioned.
    Decommissioned,
    /// Node has been forcibly fenced from the cluster.
    Fenced,
}

impl NodeState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Drained => "drained",
            Self::Decommissioned => "decommissioned",
            Self::Fenced => "fenced",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Decommissioned | Self::Fenced)
    }

    #[must_use]
    pub const fn can_transition_from(self) -> bool {
        !self.is_terminal()
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::Active
    }
}

// ---------------------------------------------------------------------------
// Drain stages
// ---------------------------------------------------------------------------

/// Ordered stages of a graceful node drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DrainStage {
    /// Operator initiated drain; preflight checks pending.
    DrainRequested,
    /// Releasing all leases held by this node.
    DrainingLeases,
    /// Migrating all primary data replicas to other nodes.
    DrainingData,
    /// Invalidating all cache entries, redirecting clients.
    DrainingCache,
    /// Transferring admin/coordinator roles.
    DrainingAdmin,
    /// Node has no remaining duties, safe to decommission.
    Drained,
    /// Operator cancelled drain mid-flow.
    Cancelled,
}

impl DrainStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DrainRequested => "drain_requested",
            Self::DrainingLeases => "draining_leases",
            Self::DrainingData => "draining_data",
            Self::DrainingCache => "draining_cache",
            Self::DrainingAdmin => "draining_admin",
            Self::Drained => "drained",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Drained | Self::Cancelled)
    }

    /// Return the next stage in the drain sequence, or None if at terminal.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::DrainRequested => Some(Self::DrainingLeases),
            Self::DrainingLeases => Some(Self::DrainingData),
            Self::DrainingData => Some(Self::DrainingCache),
            Self::DrainingCache => Some(Self::DrainingAdmin),
            Self::DrainingAdmin => Some(Self::Drained),
            Self::Drained | Self::Cancelled => None,
        }
    }

    /// Return the previous stage (for cancellation rollback).
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        match self {
            Self::DrainingLeases => Some(Self::DrainRequested),
            Self::DrainingData => Some(Self::DrainingLeases),
            Self::DrainingCache => Some(Self::DrainingData),
            Self::DrainingAdmin => Some(Self::DrainingCache),
            Self::Drained => Some(Self::DrainingAdmin),
            Self::DrainRequested | Self::Cancelled => None,
        }
    }
}

impl Default for DrainStage {
    fn default() -> Self {
        Self::DrainRequested
    }
}

// ---------------------------------------------------------------------------
// Drain progress
// ---------------------------------------------------------------------------

/// Per-stage progress counters for a drain operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainProgress {
    /// Bytes of data still to migrate.
    pub bytes_remaining: u64,
    /// Number of objects still to migrate.
    pub objects_remaining: u64,
    /// Number of leases still to release.
    pub leases_remaining: u64,
    /// Estimated milliseconds until completion.
    pub estimated_completion_ms: u64,
}

impl DrainProgress {
    pub const ZERO: Self = Self {
        bytes_remaining: 0,
        objects_remaining: 0,
        leases_remaining: 0,
        estimated_completion_ms: 0,
    };

    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.bytes_remaining == 0 && self.objects_remaining == 0 && self.leases_remaining == 0
    }

    /// Progress as a fraction [0.0, 1.0] across the current stage.
    #[must_use]
    pub fn fraction(self) -> f64 {
        let total = self.bytes_remaining as f64
            + self.objects_remaining as f64
            + self.leases_remaining as f64;
        if total == 0.0 {
            return 1.0;
        }
        let remaining = self.bytes_remaining as f64
            + self.objects_remaining as f64
            + self.leases_remaining as f64;
        1.0 - (remaining / total.max(1.0))
    }
}

// ---------------------------------------------------------------------------
// Drain errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainError {
    /// Node is not in a state that allows drain.
    NotDrainable { node_id: MemberId, state: NodeState },
    /// Drain is already in progress.
    AlreadyDraining { node_id: MemberId },
    /// Cannot advance because the current stage is not complete.
    StageNotComplete {
        node_id: MemberId,
        stage: DrainStage,
        progress: DrainProgress,
    },
    /// Cannot cancel a drain that is already terminal.
    CannotCancelTerminal {
        node_id: MemberId,
        stage: DrainStage,
    },
    /// Node was fenced and cannot be drained.
    Fenced { node_id: MemberId },
    /// The drain operation timed out.
    Timeout { node_id: MemberId, timeout_ms: u64 },
    /// An evacuation receipt is required for this drain phase transition.
    RequiresEvacuationReceipt {
        node_id: MemberId,
        stage: DrainStage,
    },
    /// The evacuation receipt is not yet committed.
    EvacuationReceiptNotCommitted { node_id: MemberId },
    /// The evacuation receipt failed validation.
    EvacuationReceiptInvalid {
        node_id: MemberId,
        error: EvacuationReceiptError,
    },
}

impl From<String> for DrainError {
    fn from(_s: String) -> Self {
        DrainError::StageNotComplete {
            node_id: MemberId::ZERO,
            stage: DrainStage::DrainRequested,
            progress: DrainProgress::ZERO,
        }
    }
}

impl fmt::Display for DrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDrainable { node_id, state } => {
                write!(
                    f,
                    "node {} is in state {:?} and cannot be drained",
                    node_id.0, state
                )
            }
            Self::AlreadyDraining { node_id } => {
                write!(f, "node {} is already draining", node_id.0)
            }
            Self::StageNotComplete {
                node_id,
                stage,
                progress,
            } => {
                write!(
                    f,
                    "node {} stage {:?} not complete: {:?}",
                    node_id.0, stage, progress
                )
            }
            Self::CannotCancelTerminal { node_id, stage } => {
                write!(
                    f,
                    "cannot cancel drain for node {} at terminal stage {:?}",
                    node_id.0, stage
                )
            }
            Self::Fenced { node_id } => {
                write!(f, "node {} is fenced and cannot be drained", node_id.0)
            }
            Self::Timeout {
                node_id,
                timeout_ms,
            } => {
                write!(
                    f,
                    "node {} drain timed out after {}ms",
                    node_id.0, timeout_ms
                )
            }
            Self::RequiresEvacuationReceipt { node_id, stage } => {
                write!(
                    f,
                    "node {} requires an evacuation receipt to advance from stage {:?}",
                    node_id.0, stage
                )
            }
            Self::EvacuationReceiptNotCommitted { node_id } => {
                write!(
                    f,
                    "node {} evacuation receipt is not yet committed",
                    node_id.0
                )
            }
            Self::EvacuationReceiptInvalid { node_id, error } => {
                write!(
                    f,
                    "node {} evacuation receipt invalid: {}",
                    node_id.0, error
                )
            }
        }
    }
}

impl std::error::Error for DrainError {}

// ---------------------------------------------------------------------------
// NodeDrain — drain state machine
// ---------------------------------------------------------------------------

/// The drain state machine for a single node.
#[derive(Clone, Debug)]
pub struct NodeDrain {
    node_id: MemberId,
    state: NodeState,
    stage: DrainStage,
    progress: DrainProgress,
    epoch: u64,
    /// Whether an operator initiated this drain.
    operator_initiated: bool,
    /// Milliseconds since drain was requested (wall clock).
    elapsed_ms: u64,
    /// Configurable timeout for the entire drain operation.
    timeout_ms: u64,
    /// Whether the data stage observed relocated data and therefore requires
    /// a committed evacuation receipt before advancing.
    data_relocation_required: bool,
    /// Committed evacuation receipt gating drain completion.
    evacuation_receipt: Option<EvacuationReceipt>,
}

impl NodeDrain {
    /// Create a new drain for the given node.
    #[must_use]
    pub fn new(node_id: MemberId, operator_initiated: bool) -> Self {
        Self {
            node_id,
            state: NodeState::Draining,
            stage: DrainStage::DrainRequested,
            progress: DrainProgress::ZERO,
            epoch: 0,
            operator_initiated,
            elapsed_ms: 0,
            timeout_ms: 0,
            data_relocation_required: false,
            evacuation_receipt: None,
        }
    }

    /// Start draining the given node. Returns the drain handle.
    #[must_use]
    pub fn drain(node_id: MemberId) -> (Self, DrainHandle) {
        let drain = Self::new(node_id, true);
        let handle = DrainHandle::new(node_id);
        (drain, handle)
    }

    // Accessors

    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn state(&self) -> NodeState {
        self.state
    }

    #[must_use]
    pub fn stage(&self) -> DrainStage {
        self.stage
    }

    #[must_use]
    pub fn progress(&self) -> DrainProgress {
        self.progress
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn operator_initiated(&self) -> bool {
        self.operator_initiated
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
    }

    /// Return a reference to the evacuation receipt, if attached.
    pub fn evacuation_receipt(&self) -> Option<&EvacuationReceipt> {
        self.evacuation_receipt.as_ref()
    }

    /// Attach a committed evacuation receipt to this drain.
    pub fn set_evacuation_receipt(&mut self, receipt: EvacuationReceipt) {
        if !receipt.is_empty() {
            self.data_relocation_required = true;
        }
        self.evacuation_receipt = Some(receipt);
    }

    /// Mark that the data stage relocated objects and must be receipt-gated.
    pub fn mark_data_relocation_required(&mut self) {
        self.data_relocation_required = true;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Update progress counters for the current stage.
    pub fn update_progress(&mut self, progress: DrainProgress) {
        if self.stage == DrainStage::DrainingData && progress.objects_remaining > 0 {
            self.data_relocation_required = true;
        }
        self.progress = progress;
    }

    /// Advance elapsed time counter.
    pub fn tick(&mut self, delta_ms: u64) {
        self.elapsed_ms = self.elapsed_ms.saturating_add(delta_ms);
    }

    /// Check if the drain has timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        self.timeout_ms > 0 && self.elapsed_ms >= self.timeout_ms
    }

    /// Advance to the next drain stage.
    ///
    /// Returns an error if the current stage preflight checks aren't met.
    pub fn advance_stage(&mut self) -> Result<DrainStage, DrainError> {
        if self.stage.is_terminal() {
            return Err(DrainError::CannotCancelTerminal {
                node_id: self.node_id,
                stage: self.stage,
            });
        }

        if self.state == NodeState::Fenced {
            return Err(DrainError::Fenced {
                node_id: self.node_id,
            });
        }

        // Preflight: verify the current stage is complete
        match self.stage {
            DrainStage::DrainingLeases => {
                if self.progress.leases_remaining > 0 {
                    return Err(DrainError::StageNotComplete {
                        node_id: self.node_id,
                        stage: self.stage,
                        progress: self.progress,
                    });
                }
            }
            DrainStage::DrainingData => {
                if self.progress.objects_remaining > 0 {
                    return Err(DrainError::StageNotComplete {
                        node_id: self.node_id,
                        stage: self.stage,
                        progress: self.progress,
                    });
                }
                // Data-to-cache transition requires a committed evacuation
                // receipt when this drain observed relocated data. Empty-node
                // drains keep `data_relocation_required` false.
                if self.data_relocation_required && self.evacuation_receipt.is_none() {
                    return Err(DrainError::RequiresEvacuationReceipt {
                        node_id: self.node_id,
                        stage: self.stage,
                    });
                }
                if let Some(receipt) = &self.evacuation_receipt {
                    if receipt.is_empty() {
                        return Err(DrainError::EvacuationReceiptInvalid {
                            node_id: self.node_id,
                            error: EvacuationReceiptError::EmptyEvacuation {
                                draining_node: self.node_id,
                            },
                        });
                    }
                    if !receipt.is_committed() {
                        return Err(DrainError::EvacuationReceiptNotCommitted {
                            node_id: self.node_id,
                        });
                    }
                }
            }
            DrainStage::DrainingCache => {
                if self.progress.bytes_remaining > 0 {
                    return Err(DrainError::StageNotComplete {
                        node_id: self.node_id,
                        stage: self.stage,
                        progress: self.progress,
                    });
                }
            }
            DrainStage::DrainingAdmin => {
                if self.progress.bytes_remaining > 0
                    || self.progress.objects_remaining > 0
                    || self.progress.leases_remaining > 0
                {
                    return Err(DrainError::StageNotComplete {
                        node_id: self.node_id,
                        stage: self.stage,
                        progress: self.progress,
                    });
                }
            }
            _ => {}
        }

        if let Some(next_stage) = self.stage.next() {
            if next_stage == DrainStage::Drained {
                // Drained transition requires committed epoch boundary when
                // an evacuation receipt exists (data was migrated).
                if let Some(ref receipt) = self.evacuation_receipt {
                    if receipt.committed_epoch_boundary.is_none() {
                        return Err(DrainError::EvacuationReceiptInvalid {
                            node_id: self.node_id,
                            error: EvacuationReceiptError::EpochBoundaryNotCommitted {
                                draining_node: self.node_id,
                            },
                        });
                    }
                }
            }

            self.stage = next_stage;
            // Reset progress for the new stage
            self.progress = DrainProgress::ZERO;
            if self.stage == DrainStage::Drained {
                self.state = NodeState::Drained;
            }
        }

        Ok(self.stage)
    }

    /// Cancel the drain, transitioning the node back to Active.
    ///
    /// Cannot cancel if already at a terminal stage (Drained, Cancelled, Fenced).
    pub fn cancel(&mut self) -> Result<DrainStage, DrainError> {
        if self.stage.is_terminal() {
            return Err(DrainError::CannotCancelTerminal {
                node_id: self.node_id,
                stage: self.stage,
            });
        }
        if self.state == NodeState::Fenced {
            return Err(DrainError::Fenced {
                node_id: self.node_id,
            });
        }

        self.stage = DrainStage::Cancelled;
        self.state = NodeState::Active;
        self.progress = DrainProgress::ZERO;
        self.data_relocation_required = false;
        Ok(self.stage)
    }

    /// Transition the node to the Fenced state (called by ForcedFencing).
    pub fn mark_fenced(&mut self) {
        self.state = NodeState::Fenced;
        self.stage = DrainStage::Cancelled;
    }

    /// Transition the node to Decommissioned.
    pub fn mark_decommissioned(&mut self) {
        self.state = NodeState::Decommissioned;
    }

    /// Return a handle for monitoring this drain.
    #[must_use]
    pub fn handle(&self) -> DrainHandle {
        DrainHandle {
            node_id: self.node_id,
            state: self.state,
            stage: self.stage,
            progress: self.progress,
        }
    }
}

// ---------------------------------------------------------------------------
// DrainHandle — read-only view of drain progress
// ---------------------------------------------------------------------------

/// A read-only handle for monitoring drain progress.
#[derive(Clone, Copy, Debug)]
pub struct DrainHandle {
    pub node_id: MemberId,
    pub state: NodeState,
    pub stage: DrainStage,
    pub progress: DrainProgress,
}

impl DrainHandle {
    #[must_use]
    pub const fn new(node_id: MemberId) -> Self {
        Self {
            node_id,
            state: NodeState::Active,
            stage: DrainStage::DrainRequested,
            progress: DrainProgress::ZERO,
        }
    }

    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn state(&self) -> NodeState {
        self.state
    }

    #[must_use]
    pub fn stage(&self) -> DrainStage {
        self.stage
    }

    #[must_use]
    pub fn progress(&self) -> DrainProgress {
        self.progress
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.stage == DrainStage::Drained && self.progress.is_complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn drain_lifecycle_advance_all_stages() {
        let (mut drain, handle) = NodeDrain::drain(node_id(1));
        assert_eq!(drain.state(), NodeState::Draining);
        assert_eq!(drain.stage(), DrainStage::DrainRequested);
        assert_eq!(handle.node_id(), node_id(1));

        // Advance to DrainingLeases
        let stage = drain.advance_stage().unwrap();
        assert_eq!(stage, DrainStage::DrainingLeases);

        // Update progress to simulate lease draining complete
        drain.update_progress(DrainProgress {
            leases_remaining: 0,
            ..DrainProgress::ZERO
        });

        // Advance to DrainingData
        let stage = drain.advance_stage().unwrap();
        assert_eq!(stage, DrainStage::DrainingData);

        drain.update_progress(DrainProgress {
            objects_remaining: 0,
            ..DrainProgress::ZERO
        });

        // Advance to DrainingCache
        let stage = drain.advance_stage().unwrap();
        assert_eq!(stage, DrainStage::DrainingCache);

        drain.update_progress(DrainProgress {
            bytes_remaining: 0,
            ..DrainProgress::ZERO
        });

        // Advance to DrainingAdmin
        let stage = drain.advance_stage().unwrap();
        assert_eq!(stage, DrainStage::DrainingAdmin);

        drain.update_progress(DrainProgress::ZERO);

        // Advance to Drained
        let stage = drain.advance_stage().unwrap();
        assert_eq!(stage, DrainStage::Drained);
        assert_eq!(drain.state(), NodeState::Drained);
    }

    #[test]
    fn drain_blocked_when_leases_remain() {
        let (mut drain, _) = NodeDrain::drain(node_id(2));
        drain.advance_stage().unwrap(); // -> DrainingLeases

        // Set progress showing leases still remaining
        drain.update_progress(DrainProgress {
            leases_remaining: 5,
            ..DrainProgress::ZERO
        });

        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(err, DrainError::StageNotComplete { .. }));
    }

    #[test]
    fn drain_blocked_when_objects_remain() {
        let (mut drain, _) = NodeDrain::drain(node_id(3));
        drain.advance_stage().unwrap(); // -> DrainingLeases
        drain.update_progress(DrainProgress::ZERO); // leases done
        drain.advance_stage().unwrap(); // -> DrainingData

        drain.update_progress(DrainProgress {
            objects_remaining: 3,
            ..DrainProgress::ZERO
        });

        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(err, DrainError::StageNotComplete { .. }));
    }

    #[test]
    fn drain_cancel_mid_drain() {
        let (mut drain, _) = NodeDrain::drain(node_id(4));
        drain.advance_stage().unwrap(); // -> DrainingLeases
        drain.advance_stage().unwrap(); // -> DrainingData

        let stage = drain.cancel().unwrap();
        assert_eq!(stage, DrainStage::Cancelled);
        assert_eq!(drain.state(), NodeState::Active);
    }

    #[test]
    fn drain_cannot_cancel_drained() {
        let (mut drain, _) = NodeDrain::drain(node_id(5));
        // Advance through all stages to Drained
        for _ in 0..5 {
            drain.update_progress(DrainProgress::ZERO);
            drain.advance_stage().unwrap();
        }
        assert_eq!(drain.stage(), DrainStage::Drained);

        let err = drain.cancel().unwrap_err();
        assert!(matches!(err, DrainError::CannotCancelTerminal { .. }));
    }

    #[test]
    fn drain_noop_when_no_data() {
        let (mut drain, _) = NodeDrain::drain(node_id(6));
        // Simulate a node with nothing to drain — advance with zero progress
        for _ in 0..5 {
            drain.update_progress(DrainProgress::ZERO);
            drain.advance_stage().unwrap();
        }
        assert_eq!(drain.stage(), DrainStage::Drained);
        assert_eq!(drain.state(), NodeState::Drained);
    }

    #[test]
    fn drain_cannot_advance_from_terminal() {
        let (mut drain, _) = NodeDrain::drain(node_id(7));
        for _ in 0..5 {
            drain.update_progress(DrainProgress::ZERO);
            drain.advance_stage().unwrap();
        }
        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(err, DrainError::CannotCancelTerminal { .. }));
    }

    #[test]
    fn data_to_cache_rejects_empty_evacuation_receipt() {
        let (mut drain, _) = NodeDrain::drain(node_id(11));
        drain.advance_stage().unwrap();
        drain.update_progress(DrainProgress::ZERO);
        drain.advance_stage().unwrap();
        assert_eq!(drain.stage(), DrainStage::DrainingData);

        let receipt = EvacuationReceipt::new(
            node_id(11),
            tidefs_membership_epoch::EpochId::new(5),
            "test".to_string(),
        );
        drain.set_evacuation_receipt(receipt);
        drain.update_progress(DrainProgress::ZERO);

        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(
            err,
            DrainError::EvacuationReceiptInvalid {
                error: EvacuationReceiptError::EmptyEvacuation { .. },
                ..
            }
        ));
        assert_eq!(drain.stage(), DrainStage::DrainingData);
    }

    #[test]
    fn data_to_cache_requires_receipt_after_relocated_data() {
        let (mut drain, _) = NodeDrain::drain(node_id(13));
        drain.advance_stage().unwrap();
        drain.update_progress(DrainProgress::ZERO);
        drain.advance_stage().unwrap();
        assert_eq!(drain.stage(), DrainStage::DrainingData);

        drain.update_progress(DrainProgress {
            objects_remaining: 2,
            ..DrainProgress::ZERO
        });
        drain.update_progress(DrainProgress::ZERO);

        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(
            err,
            DrainError::RequiresEvacuationReceipt {
                stage: DrainStage::DrainingData,
                ..
            }
        ));
        assert_eq!(drain.stage(), DrainStage::DrainingData);
    }

    #[test]
    fn drained_transition_rejects_missing_epoch_boundary_without_advancing() {
        let (mut drain, _) = NodeDrain::drain(node_id(12));
        drain.advance_stage().unwrap();
        drain.update_progress(DrainProgress::ZERO);
        drain.advance_stage().unwrap();

        let mut receipt = EvacuationReceipt::new(
            node_id(12),
            tidefs_membership_epoch::EpochId::new(5),
            "test".to_string(),
        );
        receipt.record_relocated_receipts([tidefs_replication_model::ReplicatedReceiptId(42)]);
        drain.set_evacuation_receipt(receipt);

        drain.update_progress(DrainProgress::ZERO);
        drain.advance_stage().unwrap();
        drain.update_progress(DrainProgress::ZERO);
        drain.advance_stage().unwrap();

        assert_eq!(drain.stage(), DrainStage::DrainingAdmin);
        let err = drain.advance_stage().unwrap_err();
        assert!(matches!(
            err,
            DrainError::EvacuationReceiptInvalid {
                error: EvacuationReceiptError::EpochBoundaryNotCommitted { .. },
                ..
            }
        ));
        assert_eq!(drain.stage(), DrainStage::DrainingAdmin);
        assert_eq!(drain.state(), NodeState::Draining);
    }

    #[test]
    fn drain_mark_fenced_transitions_state() {
        let (mut drain, _) = NodeDrain::drain(node_id(8));
        drain.advance_stage().unwrap();
        drain.mark_fenced();
        assert_eq!(drain.state(), NodeState::Fenced);
        assert_eq!(drain.stage(), DrainStage::Cancelled);
    }

    #[test]
    fn drain_progress_fraction() {
        let p = DrainProgress {
            bytes_remaining: 50,
            objects_remaining: 50,
            leases_remaining: 0,
            estimated_completion_ms: 0,
        };
        assert!((p.fraction() - 0.0).abs() < 0.01);
    }

    #[test]
    fn drain_progress_complete_fraction() {
        let p = DrainProgress {
            bytes_remaining: 0,
            objects_remaining: 0,
            leases_remaining: 0,
            estimated_completion_ms: 0,
        };
        assert_eq!(p.fraction(), 1.0);
        assert!(p.is_complete());
    }

    #[test]
    fn drain_tick_and_timeout() {
        let (mut drain, _) = NodeDrain::drain(node_id(9));
        drain.set_timeout(1000);
        assert!(!drain.is_timed_out());
        drain.tick(500);
        assert!(!drain.is_timed_out());
        drain.tick(500);
        assert!(drain.is_timed_out());
    }

    #[test]
    fn drain_stage_next_and_prev() {
        assert_eq!(
            DrainStage::DrainRequested.next(),
            Some(DrainStage::DrainingLeases)
        );
        assert_eq!(
            DrainStage::DrainingLeases.next(),
            Some(DrainStage::DrainingData)
        );
        assert_eq!(
            DrainStage::DrainingData.next(),
            Some(DrainStage::DrainingCache)
        );
        assert_eq!(
            DrainStage::DrainingCache.next(),
            Some(DrainStage::DrainingAdmin)
        );
        assert_eq!(DrainStage::DrainingAdmin.next(), Some(DrainStage::Drained));
        assert_eq!(DrainStage::Drained.next(), None);
        assert_eq!(DrainStage::Cancelled.next(), None);

        assert_eq!(
            DrainStage::DrainingLeases.prev(),
            Some(DrainStage::DrainRequested)
        );
        assert_eq!(DrainStage::Drained.prev(), Some(DrainStage::DrainingAdmin));
        assert_eq!(DrainStage::DrainRequested.prev(), None);
    }

    #[test]
    fn drain_node_state_transitions() {
        assert!(NodeState::Active.can_transition_from());
        assert!(NodeState::Draining.can_transition_from());
        assert!(!NodeState::Decommissioned.can_transition_from());
        assert!(!NodeState::Fenced.can_transition_from());
    }

    #[test]
    fn drain_error_display() {
        let err = DrainError::NotDrainable {
            node_id: node_id(42),
            state: NodeState::Fenced,
        };
        let s = format!("{err}");
        assert!(s.contains("42"));
        assert!(s.contains("Fenced"));
    }

    #[test]
    fn drain_handle_readonly() {
        let (mut drain, _) = NodeDrain::drain(node_id(10));
        drain.advance_stage().unwrap();
        let handle = drain.handle();
        assert_eq!(handle.stage(), DrainStage::DrainingLeases);
        assert_eq!(handle.node_id(), node_id(10));

        // Handle is a snapshot, doesn't change when drain does
        drain.advance_stage().unwrap();
        assert_eq!(handle.stage(), DrainStage::DrainingLeases);
    }
}
