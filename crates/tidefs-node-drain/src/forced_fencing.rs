// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::drain::{NodeDrain, NodeState};
use crate::epoch_gate::DrainFenceEpochTransition;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochAdvanceError, EpochId, EpochTransitionBarrier, MemberId};
use tidefs_replication_model::ReplicatedReceiptId;

// ---------------------------------------------------------------------------
// FenceToken — monotonically increasing counter per node
// ---------------------------------------------------------------------------

/// A fence token is a monotonically increasing counter per node that is
/// incremented each time the node is forcibly fenced. A node trying to rejoin
/// with an old fence token is rejected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FenceToken(pub u64);

impl FenceToken {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Increment the fence token, returning the new value.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns true if `self` is strictly newer than `other`.
    #[must_use]
    pub const fn is_newer_than(self, other: Self) -> bool {
        self.0 > other.0
    }
}

// ---------------------------------------------------------------------------
// FenceTrigger — what caused the fence
// ---------------------------------------------------------------------------

/// What triggered a forced fence operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FenceTrigger {
    /// Node was unresponsive beyond the fence timeout.
    Timeout,
    /// Operator manually initiated a fence via `tidefs node fence <node>`.
    Operator,
}

impl FenceTrigger {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Operator => "operator",
        }
    }
}

// ---------------------------------------------------------------------------
// FencingStats — metrics for fencing operations
// ---------------------------------------------------------------------------

/// Tracks statistics about forced fencing operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingStats {
    /// Total number of nodes that have been forcibly fenced.
    pub nodes_fenced: u64,
    /// Number of fences triggered by timeout.
    pub fence_triggers_timeout: u64,
    /// Number of fences triggered by operator command.
    pub fence_triggers_manual: u64,
    /// Number of data rebuilds triggered as a result of fencing.
    pub rebuilds_triggered: u64,
}

impl FencingStats {
    pub const ZERO: Self = Self {
        nodes_fenced: 0,
        fence_triggers_timeout: 0,
        fence_triggers_manual: 0,
        rebuilds_triggered: 0,
    };

    /// Record a fence event with the given trigger.
    pub fn record_fence(&mut self, trigger: FenceTrigger) {
        self.nodes_fenced += 1;
        match trigger {
            FenceTrigger::Timeout => self.fence_triggers_timeout += 1,
            FenceTrigger::Operator => self.fence_triggers_manual += 1,
        }
    }

    /// Record a rebuild triggered by a fence.
    pub fn record_rebuild(&mut self) {
        self.rebuilds_triggered += 1;
    }

    /// Total fence triggers across all sources.
    #[must_use]
    pub fn total_triggers(&self) -> u64 {
        self.fence_triggers_timeout + self.fence_triggers_manual
    }
}

// ---------------------------------------------------------------------------
// ForcedFencing — manages fencing of unresponsive nodes
// ---------------------------------------------------------------------------

/// Configuration for forced fencing behavior.
#[derive(Clone, Copy, Debug)]
pub struct ForcedFencingConfig {
    /// Default timeout in milliseconds before a node is considered unresponsive
    /// and eligible for forced fencing. Default: 60_000 (60s).
    pub fence_timeout_ms: u64,
    /// Maximum number of consecutive fences before the node is permanently
    /// excluded (requires operator intervention).
    pub max_consecutive_fences: u32,
}

impl Default for ForcedFencingConfig {
    fn default() -> Self {
        Self {
            fence_timeout_ms: 60_000,
            max_consecutive_fences: 5,
        }
    }
}

/// Errors returned by forced fencing operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FencingError {
    /// Node is not in a fence-eligible state.
    NotEligible {
        node_id: MemberId,
        state: NodeState,
        reason: String,
    },
    /// Node is already fenced.
    AlreadyFenced {
        node_id: MemberId,
        token: FenceToken,
    },
    /// A fenced node tried to rejoin with an outdated or invalid token.
    InvalidFenceToken {
        node_id: MemberId,
        presented: FenceToken,
        expected_min: FenceToken,
    },
    /// Membership-epoch transition barrier could not be acquired.
    EpochBarrierRefused {
        node_id: MemberId,
        from_epoch: EpochId,
        to_epoch: EpochId,
        reason: EpochAdvanceError,
    },
    /// Maximum consecutive fences reached — operator intervention required.
    MaxFencesExceeded { node_id: MemberId, consecutive: u32 },
}

impl std::fmt::Display for FencingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEligible {
                node_id,
                state,
                reason,
            } => {
                write!(
                    f,
                    "node {} not eligible for fencing (state={:?}): {}",
                    node_id.0, state, reason
                )
            }
            Self::AlreadyFenced { node_id, token } => {
                write!(
                    f,
                    "node {} is already fenced with token {}",
                    node_id.0, token.0
                )
            }
            Self::InvalidFenceToken {
                node_id,
                presented,
                expected_min,
            } => {
                write!(
                    f,
                    "node {} presented fence token {} but minimum expected is {}",
                    node_id.0, presented.0, expected_min.0
                )
            }
            Self::EpochBarrierRefused {
                node_id,
                from_epoch,
                to_epoch,
                reason,
            } => {
                write!(
                    f,
                    "node {} forced fence refused: epoch transition {:?}->{:?} barrier acquisition failed: {:?}",
                    node_id.0, from_epoch, to_epoch, reason
                )
            }
            Self::MaxFencesExceeded {
                node_id,
                consecutive,
            } => {
                write!(
                    f,
                    "node {} has been fenced {} consecutive times; operator intervention required",
                    node_id.0, consecutive
                )
            }
        }
    }
}

impl std::error::Error for FencingError {}

// ---------------------------------------------------------------------------
// ForcedFencing — fence orchestrator
// ---------------------------------------------------------------------------

/// The forced fencing orchestrator.
///
/// When a node is unresponsive (beyond `fence_timeout_ms`) or an operator
/// issues a manual fence, ForcedFencing:
///
/// 1. Increments the node's fence token.
/// 2. Proposes an epoch transition excluding the fenced node.
/// 3. Triggers data rebuild from redundant copies.
/// 4. Rejects the fenced node's rejoin attempts with an old token.
pub struct ForcedFencing {
    config: ForcedFencingConfig,
    stats: FencingStats,
    /// Per-node fence tokens: current epoch-validated token.
    tokens: std::collections::BTreeMap<u64, FenceToken>,
    /// Per-node consecutive fence count for max-fence guard.
    consecutive_fences: std::collections::BTreeMap<u64, u32>,
    /// Nodes currently fenced (node_id -> (token, epoch_when_fenced)).
    fenced_nodes: std::collections::BTreeMap<u64, (FenceToken, u64)>,
    /// Placement receipt ids that referenced the node at the time of
    /// the last fence, keyed by node_id. Captured for audit/recovery.
    placement_evidence: std::collections::BTreeMap<u64, Vec<ReplicatedReceiptId>>,
    /// Membership-epoch transition barrier held while a forced fence advances.
    epoch_barrier: EpochTransitionBarrier,
    /// Active forced-fence transition guarded by `epoch_barrier`.
    active_epoch_transition: Option<DrainFenceEpochTransition>,
}

impl ForcedFencing {
    /// Create a new ForcedFencing instance with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ForcedFencingConfig::default(),
            stats: FencingStats::ZERO,
            tokens: std::collections::BTreeMap::new(),
            consecutive_fences: std::collections::BTreeMap::new(),
            fenced_nodes: std::collections::BTreeMap::new(),
            placement_evidence: std::collections::BTreeMap::new(),
            epoch_barrier: EpochTransitionBarrier::new(),
            active_epoch_transition: None,
        }
    }

    /// Create a new ForcedFencing with the given configuration.
    #[must_use]
    pub fn with_config(config: ForcedFencingConfig) -> Self {
        Self {
            config,
            stats: FencingStats::ZERO,
            tokens: std::collections::BTreeMap::new(),
            consecutive_fences: std::collections::BTreeMap::new(),
            fenced_nodes: std::collections::BTreeMap::new(),
            placement_evidence: std::collections::BTreeMap::new(),
            epoch_barrier: EpochTransitionBarrier::new(),
            active_epoch_transition: None,
        }
    }

    // Accessors

    #[must_use]
    pub fn config(&self) -> ForcedFencingConfig {
        self.config
    }

    #[must_use]
    pub fn stats(&self) -> FencingStats {
        self.stats
    }

    #[must_use]
    pub fn fence_timeout_ms(&self) -> u64 {
        self.config.fence_timeout_ms
    }

    /// Update the fence timeout for testing or runtime reconfiguration.
    pub fn set_fence_timeout_ms(&mut self, ms: u64) {
        self.config.fence_timeout_ms = ms;
    }

    /// Get the current fence token for a node.
    #[must_use]
    pub fn token_for(&self, node_id: MemberId) -> FenceToken {
        self.tokens
            .get(&node_id.0)
            .copied()
            .unwrap_or(FenceToken::ZERO)
    }

    /// Check if a node is currently fenced.
    #[must_use]
    pub fn is_fenced(&self, node_id: MemberId) -> bool {
        self.fenced_nodes.contains_key(&node_id.0)
    }

    /// List all currently fenced nodes.
    #[must_use]
    pub fn fenced_node_ids(&self) -> Vec<u64> {
        self.fenced_nodes.keys().copied().collect()
    }

    /// Returns true while forced fencing is holding the membership epoch
    /// transition barrier and lease acquisition must be refused.
    #[must_use]
    pub fn lease_acquisition_blocked(&self) -> bool {
        self.epoch_barrier.is_blocked()
    }

    /// Return the pending membership epoch targeted by the held barrier.
    #[must_use]
    pub fn pending_epoch(&self) -> Option<EpochId> {
        self.epoch_barrier.pending_epoch()
    }

    /// Return the active forced-fence epoch transition, if one is held.
    #[must_use]
    pub fn active_epoch_transition(&self) -> Option<DrainFenceEpochTransition> {
        self.active_epoch_transition
    }

    /// Release the forced-fence epoch barrier after the membership runtime
    /// commits or aborts the transition.
    pub fn release_epoch_barrier(&mut self) {
        self.epoch_barrier.release();
        self.active_epoch_transition = None;
    }

    // -----------------------------------------------------------------------
    // Fencing lifecycle
    // -----------------------------------------------------------------------

    /// Perform a forced fence on a node.
    ///
    /// Increments the node's fence token, records the fence in stats, marks
    /// the drain as fenced, and registers the node as fenced.
    ///
    /// Returns the new fence token on success.
    pub fn fence(
        &mut self,
        node_id: MemberId,
        trigger: FenceTrigger,
        drain: &mut NodeDrain,
        from_epoch: u64,
    ) -> Result<FenceToken, FencingError> {
        let placement_evidence = drain
            .evacuation_receipt()
            .map(|r| r.placement_receipt_refs.clone())
            .unwrap_or_default();

        self.fence_with_placement_evidence(node_id, trigger, drain, from_epoch, placement_evidence)
    }

    /// Perform a forced fence while recording explicit placement evidence
    /// captured from the committed placement authority.
    ///
    /// Callers that can query live placement receipts should use this path so
    /// the fence event records the last committed receipts known to reference
    /// the fenced node.
    pub fn fence_with_placement_evidence(
        &mut self,
        node_id: MemberId,
        trigger: FenceTrigger,
        drain: &mut NodeDrain,
        from_epoch: u64,
        placement_evidence: Vec<ReplicatedReceiptId>,
    ) -> Result<FenceToken, FencingError> {
        let nid = node_id.0;

        let consecutive = self.validate_fence_eligibility(node_id, drain)?;
        let transition = DrainFenceEpochTransition::next(node_id, EpochId::new(from_epoch));
        let barrier_hold = transition
            .acquire(&mut self.epoch_barrier)
            .map_err(|reason| FencingError::EpochBarrierRefused {
                node_id,
                from_epoch: transition.from_epoch(),
                to_epoch: transition.to_epoch(),
                reason,
            })?;
        self.active_epoch_transition = Some(barrier_hold.transition());

        Ok(self.apply_fence_after_barrier(
            nid,
            trigger,
            drain,
            transition.to_epoch(),
            placement_evidence,
            consecutive,
        ))
    }

    fn validate_fence_eligibility(
        &self,
        node_id: MemberId,
        drain: &NodeDrain,
    ) -> Result<u32, FencingError> {
        let nid = node_id.0;

        if self.is_fenced(node_id) {
            let (token, _) = self.fenced_nodes[&nid];
            return Err(FencingError::AlreadyFenced { node_id, token });
        }

        if drain.state() == NodeState::Decommissioned {
            return Err(FencingError::NotEligible {
                node_id,
                state: NodeState::Decommissioned,
                reason: "node is decommissioned".to_string(),
            });
        }

        let consecutive = self.consecutive_fences.get(&nid).copied().unwrap_or(0) + 1;
        if consecutive > self.config.max_consecutive_fences {
            return Err(FencingError::MaxFencesExceeded {
                node_id,
                consecutive: consecutive - 1,
            });
        }

        Ok(consecutive)
    }

    fn apply_fence_after_barrier(
        &mut self,
        nid: u64,
        trigger: FenceTrigger,
        drain: &mut NodeDrain,
        fenced_epoch: EpochId,
        placement_evidence: Vec<ReplicatedReceiptId>,
        consecutive: u32,
    ) -> FenceToken {
        let current_token = self.tokens.get(&nid).copied().unwrap_or(FenceToken::ZERO);
        let new_token = current_token.next();
        self.tokens.insert(nid, new_token);
        self.consecutive_fences.insert(nid, consecutive);

        // Mark the node as fenced
        drain.mark_fenced();

        // Record placement evidence captured at fence time so the fencing
        // event carries the last committed placement evidence known for the
        // node. This is used for post-fence audit and recovery.
        self.record_placement_evidence(nid, placement_evidence);
        self.fenced_nodes.insert(nid, (new_token, fenced_epoch.0));

        // Record stats
        self.stats.record_fence(trigger);

        // A rebuild will be triggered externally via placement-runtime
        self.stats.record_rebuild();

        new_token
    }

    /// Validate a fence token presented by a node attempting to rejoin.
    ///
    /// Returns `Ok(())` if the token is acceptable, or `FencingError`
    /// if the node must be rejected.
    pub fn validate_fence_token(
        &self,
        node_id: MemberId,
        presented: FenceToken,
    ) -> Result<(), FencingError> {
        let nid = node_id.0;

        if let Some(&(current_token, _)) = self.fenced_nodes.get(&nid) {
            // Node is currently fenced; must present at least the current token
            if presented < current_token {
                return Err(FencingError::InvalidFenceToken {
                    node_id,
                    presented,
                    expected_min: current_token,
                });
            }
        }
        // If not currently fenced, any token is acceptable (or zero)

        Ok(())
    }

    /// Record placement receipt evidence captured at fence time.
    fn record_placement_evidence(&mut self, node_id: u64, receipt_ids: Vec<ReplicatedReceiptId>) {
        self.placement_evidence.insert(node_id, receipt_ids);
    }

    /// Return the placement receipt ids referencing `node_id` at the
    /// time it was last fenced, if any.
    #[must_use]
    pub fn placement_evidence_for(&self, node_id: MemberId) -> Option<&[ReplicatedReceiptId]> {
        self.placement_evidence
            .get(&node_id.0)
            .map(|v| v.as_slice())
    }

    /// Returns true if placement evidence was recorded for this node.
    #[must_use]
    pub fn has_placement_evidence(&self, node_id: MemberId) -> bool {
        self.placement_evidence.contains_key(&node_id.0)
    }

    /// Clear a node's fenced status — called when the node successfully
    /// rejoins after catching up.
    ///
    /// The presented token must be at least the current token.
    pub fn clear_fence(
        &mut self,
        node_id: MemberId,
        presented: FenceToken,
    ) -> Result<(), FencingError> {
        let nid = node_id.0;

        match self.fenced_nodes.get(&nid) {
            Some(&(current_token, _)) => {
                if presented < current_token {
                    return Err(FencingError::InvalidFenceToken {
                        node_id,
                        presented,
                        expected_min: current_token,
                    });
                }
            }
            None => {
                // Not currently fenced — nothing to clear
                return Ok(());
            }
        }

        self.fenced_nodes.remove(&nid);
        // Keep consecutive_fences so repeated fences are counted even after clear
        // Keep the token in self.tokens so future fences increment from here
        Ok(())
    }

    /// Propose an epoch transition to exclude a fenced node.
    ///
    /// This returns the proposal metadata that the caller (membership runtime)
    /// uses to construct and broadcast an EpochTransitionProposal.
    #[must_use]
    pub fn build_exclusion_proposal(
        &self,
        node_id: MemberId,
        from_epoch: EpochId,
        to_epoch: EpochId,
    ) -> FenceExclusionProposal {
        FenceExclusionProposal {
            node_id,
            from_epoch,
            to_epoch,
            fence_token: self.token_for(node_id),
            reason: "forced_fence".to_string(),
        }
    }
}

impl Default for ForcedFencing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FenceExclusionProposal — metadata for epoch transition proposal
// ---------------------------------------------------------------------------

/// Metadata for building an [`EpochTransitionProposal`] that excludes a fenced
/// node. The caller (membership-live runtime) constructs and signs the actual
/// wire message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceExclusionProposal {
    pub node_id: MemberId,
    pub from_epoch: EpochId,
    pub to_epoch: EpochId,
    pub fence_token: FenceToken,
    pub reason: String,
}

impl FenceExclusionProposal {
    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn from_epoch(&self) -> EpochId {
        self.from_epoch
    }

    #[must_use]
    pub fn to_epoch(&self) -> EpochId {
        self.to_epoch
    }

    #[must_use]
    pub fn fence_token(&self) -> FenceToken {
        self.fence_token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn fence_token_monotonic() {
        let t0 = FenceToken::ZERO;
        let t1 = t0.next();
        let t2 = t1.next();
        assert_eq!(t1.value(), 1);
        assert_eq!(t2.value(), 2);
        assert!(t2.is_newer_than(t1));
        assert!(t1.is_newer_than(t0));
        assert!(!t0.is_newer_than(t1));
    }

    #[test]
    fn forced_fence_node() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(1));

        let token = ff
            .fence(node(1), FenceTrigger::Operator, &mut drain, 5)
            .unwrap();
        assert_eq!(token.value(), 1);
        assert!(ff.is_fenced(node(1)));
        assert!(ff.lease_acquisition_blocked());
        assert_eq!(ff.pending_epoch(), Some(EpochId::new(6)));
        assert_eq!(ff.stats().nodes_fenced, 1);
        assert_eq!(ff.stats().fence_triggers_manual, 1);
        assert_eq!(ff.stats().rebuilds_triggered, 1);
        assert_eq!(drain.state(), NodeState::Fenced);
    }

    #[test]
    fn forced_fence_records_explicit_placement_evidence() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(12));
        let evidence = vec![ReplicatedReceiptId(40), ReplicatedReceiptId(41)];

        let token = ff
            .fence_with_placement_evidence(
                node(12),
                FenceTrigger::Timeout,
                &mut drain,
                5,
                evidence.clone(),
            )
            .unwrap();

        assert_eq!(token.value(), 1);
        assert!(ff.lease_acquisition_blocked());
        assert!(ff.has_placement_evidence(node(12)));
        assert_eq!(ff.placement_evidence_for(node(12)).unwrap(), evidence);
    }

    #[test]
    fn forced_fence_already_fenced_error() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(2));

        ff.fence(node(2), FenceTrigger::Timeout, &mut drain, 1)
            .unwrap();

        let (mut drain2, _) = NodeDrain::drain(node(2));
        let err = ff
            .fence(node(2), FenceTrigger::Timeout, &mut drain2, 1)
            .unwrap_err();
        assert!(matches!(err, FencingError::AlreadyFenced { .. }));
    }

    #[test]
    fn fenced_node_rejoin_rejected_with_old_token() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(3));

        let token = ff
            .fence(node(3), FenceTrigger::Timeout, &mut drain, 1)
            .unwrap();
        assert_eq!(token.value(), 1);

        // Try to rejoin with token 0 (old) — should fail
        let result = ff.validate_fence_token(node(3), FenceToken::new(0));
        assert!(result.is_err());
        match result.unwrap_err() {
            FencingError::InvalidFenceToken {
                presented,
                expected_min,
                ..
            } => {
                assert_eq!(presented.value(), 0);
                assert_eq!(expected_min.value(), 1);
            }
            _ => panic!("expected InvalidFenceToken"),
        }
    }

    #[test]
    fn fenced_node_rejoin_accepted_with_new_token() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(4));

        ff.fence(node(4), FenceTrigger::Timeout, &mut drain, 1)
            .unwrap();

        // Try to rejoin with token 1 (current) — should succeed
        let result = ff.validate_fence_token(node(4), FenceToken::new(1));
        assert!(result.is_ok());

        // Also token 2 (ahead) should succeed
        let result = ff.validate_fence_token(node(4), FenceToken::new(2));
        assert!(result.is_ok());
    }

    #[test]
    fn clear_fence_allows_rejoin() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(5));

        ff.fence(node(5), FenceTrigger::Timeout, &mut drain, 1)
            .unwrap();
        assert!(ff.is_fenced(node(5)));

        ff.clear_fence(node(5), FenceToken::new(1)).unwrap();
        assert!(!ff.is_fenced(node(5)));
        // consecutive_fences is kept after clear for max-fence tracking
        assert_eq!(ff.consecutive_fences.get(&5), Some(&1));
    }

    #[test]
    fn clear_fence_wrong_token_fails() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _handle) = NodeDrain::drain(node(6));

        ff.fence(node(6), FenceTrigger::Timeout, &mut drain, 1)
            .unwrap();

        let err = ff.clear_fence(node(6), FenceToken::new(0)).unwrap_err();
        assert!(matches!(err, FencingError::InvalidFenceToken { .. }));
    }

    #[test]
    fn max_consecutive_fences_enforced() {
        let mut ff = ForcedFencing::with_config(ForcedFencingConfig {
            max_consecutive_fences: 2,
            ..Default::default()
        });

        let (mut drain1, _) = NodeDrain::drain(node(7));
        let token1 = ff
            .fence(node(7), FenceTrigger::Timeout, &mut drain1, 1)
            .unwrap();
        assert_eq!(token1.value(), 1);
        ff.clear_fence(node(7), FenceToken::new(1)).unwrap();
        ff.release_epoch_barrier();

        let (mut drain2, _) = NodeDrain::drain(node(7));
        let token2 = ff
            .fence(node(7), FenceTrigger::Timeout, &mut drain2, 2)
            .unwrap();
        assert_eq!(token2.value(), 2);
        ff.clear_fence(node(7), FenceToken::new(2)).unwrap();
        ff.release_epoch_barrier();

        let (mut drain3, _) = NodeDrain::drain(node(7));
        let err = ff
            .fence(node(7), FenceTrigger::Timeout, &mut drain3, 3)
            .unwrap_err();
        assert!(matches!(err, FencingError::MaxFencesExceeded { .. }));
    }

    #[test]
    fn fence_timeout_vs_operator_stats() {
        let mut ff = ForcedFencing::new();

        let (mut d1, _) = NodeDrain::drain(node(10));
        ff.fence(node(10), FenceTrigger::Timeout, &mut d1, 1)
            .unwrap();
        ff.clear_fence(node(10), FenceToken::new(1)).unwrap();
        ff.release_epoch_barrier();

        let (mut d2, _) = NodeDrain::drain(node(10));
        ff.fence(node(10), FenceTrigger::Operator, &mut d2, 2)
            .unwrap();

        assert_eq!(ff.stats().fence_triggers_timeout, 1);
        assert_eq!(ff.stats().fence_triggers_manual, 1);
        assert_eq!(ff.stats().total_triggers(), 2);
        assert_eq!(ff.stats().nodes_fenced, 2);
    }

    #[test]
    fn fencing_stats_default_zero() {
        let stats = FencingStats::ZERO;
        assert_eq!(stats.nodes_fenced, 0);
        assert_eq!(stats.total_triggers(), 0);
    }

    #[test]
    fn build_exclusion_proposal() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _) = NodeDrain::drain(node(11));
        ff.fence(node(11), FenceTrigger::Operator, &mut drain, 3)
            .unwrap();

        let proposal = ff.build_exclusion_proposal(node(11), EpochId::new(3), EpochId::new(4));
        assert_eq!(proposal.node_id(), node(11));
        assert_eq!(proposal.from_epoch(), EpochId::new(3));
        assert_eq!(proposal.to_epoch(), EpochId::new(4));
        assert_eq!(proposal.fence_token().value(), 1);
    }

    #[test]
    fn non_fenced_node_validate_always_ok() {
        let ff = ForcedFencing::new();
        // A node that was never fenced should accept any token
        assert!(ff.validate_fence_token(node(99), FenceToken::ZERO).is_ok());
        assert!(ff
            .validate_fence_token(node(99), FenceToken::new(5))
            .is_ok());
    }

    #[test]
    fn fenced_node_ids_returns_currently_fenced() {
        let mut ff = ForcedFencing::new();
        let (mut d1, _) = NodeDrain::drain(node(20));
        let (mut d2, _) = NodeDrain::drain(node(21));

        ff.fence(node(20), FenceTrigger::Timeout, &mut d1, 1)
            .unwrap();
        ff.release_epoch_barrier();
        ff.fence(node(21), FenceTrigger::Operator, &mut d2, 1)
            .unwrap();

        let ids = ff.fenced_node_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&20));
        assert!(ids.contains(&21));

        ff.clear_fence(node(20), FenceToken::new(1)).unwrap();
        assert_eq!(ff.fenced_node_ids(), vec![21]);
    }

    #[test]
    fn consecutive_fence_counter_tracks() {
        let mut ff = ForcedFencing::new();
        let (mut d, _) = NodeDrain::drain(node(30));
        ff.fence(node(30), FenceTrigger::Timeout, &mut d, 1)
            .unwrap();
        assert_eq!(ff.consecutive_fences.get(&30), Some(&1));
        ff.clear_fence(node(30), FenceToken::new(1)).unwrap();
        ff.release_epoch_barrier();

        let (mut d2, _) = NodeDrain::drain(node(30));
        ff.fence(node(30), FenceTrigger::Timeout, &mut d2, 2)
            .unwrap();
        assert_eq!(ff.consecutive_fences.get(&30), Some(&2));
    }

    #[test]
    fn forced_fence_acquires_epoch_transition_barrier() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _) = NodeDrain::drain(node(40));

        let token = ff
            .fence(node(40), FenceTrigger::Operator, &mut drain, 9)
            .unwrap();

        assert_eq!(token, FenceToken::new(1));
        assert!(ff.lease_acquisition_blocked());
        assert_eq!(ff.pending_epoch(), Some(EpochId::new(10)));
        assert_eq!(
            ff.active_epoch_transition().unwrap(),
            DrainFenceEpochTransition::next(node(40), EpochId::new(9))
        );
    }

    #[test]
    fn barrier_held_blocks_lease_acquisition_until_released() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _) = NodeDrain::drain(node(41));

        ff.fence(node(41), FenceTrigger::Timeout, &mut drain, 4)
            .unwrap();

        assert!(ff.lease_acquisition_blocked());
        assert_eq!(ff.pending_epoch(), Some(EpochId::new(5)));

        ff.release_epoch_barrier();

        assert!(!ff.lease_acquisition_blocked());
        assert_eq!(ff.pending_epoch(), None);
        assert_eq!(ff.active_epoch_transition(), None);
    }

    #[test]
    fn barrier_acquisition_failure_refuses_without_advancing() {
        let mut ff = ForcedFencing::new();
        let (mut first, _) = NodeDrain::drain(node(42));
        let (mut second, _) = NodeDrain::drain(node(43));

        ff.fence(node(42), FenceTrigger::Timeout, &mut first, 12)
            .unwrap();

        let err = ff
            .fence(node(43), FenceTrigger::Operator, &mut second, 12)
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::EpochBarrierRefused {
                node_id: node(43),
                from_epoch: EpochId::new(12),
                to_epoch: EpochId::new(13),
                reason: EpochAdvanceError::TransitionInProgress,
            }
        );
        assert!(!ff.is_fenced(node(43)));
        assert_eq!(ff.token_for(node(43)), FenceToken::ZERO);
        assert_eq!(ff.stats().nodes_fenced, 1);
        assert_eq!(ff.pending_epoch(), Some(EpochId::new(13)));
    }

    #[test]
    fn forced_fence_records_advanced_epoch_only_after_barrier_is_held() {
        let mut ff = ForcedFencing::new();
        let (mut drain, _) = NodeDrain::drain(node(44));

        ff.fence(node(44), FenceTrigger::Operator, &mut drain, 21)
            .unwrap();

        assert!(ff.lease_acquisition_blocked());
        assert_eq!(ff.pending_epoch(), Some(EpochId::new(22)));
        assert_eq!(
            ff.fenced_nodes.get(&44).copied(),
            Some((FenceToken::new(1), 22))
        );
    }
}
