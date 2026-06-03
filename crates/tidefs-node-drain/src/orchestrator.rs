//! Top-level drain orchestrator.
//!
//! [`drain_node()`] is the public entry point that composes the drain state
//! machine ([`DrainExecutor`]), data migration ([`MigrationDriver`]), and
//! epoch-bound membership transition ([`EpochGate`]) into a single
//! deterministic node drain pipeline.

use crate::drain::{DrainError, DrainHandle, NodeDrain};
use crate::drain_state::{DrainRequest, DrainStateMachine, MembershipVerificationOps};
use crate::epoch_gate::{EpochGate, EpochGateConfig, EpochGateOps, EpochGateResult};
use crate::executor::DrainExecutor;
use crate::health_verify::{DrainHealthVerifier, HealthVerifyOps, HealthVerifyResult};
use crate::migration::{MigrationDriver, MigrationOps, MigrationOutcome};
use crate::pool_label::PoolLabelResult;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// NodeDrainConfig
// ---------------------------------------------------------------------------

/// Configuration for a node drain operation.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NodeDrainConfig {
    /// The node being drained.
    pub node_id: MemberId,
    /// The node proposing the epoch transition (may be the same as node_id
    /// or a designated coordinator).
    pub proposer: MemberId,
    /// Surviving nodes that will receive migrated data.
    pub target_nodes: Vec<MemberId>,
    /// Cohort/voter members for the epoch quorum transition.
    pub voter_members: Vec<MemberId>,
    /// Timeout for the entire drain operation in milliseconds.
    pub drain_timeout_ms: u64,
    /// Epoch gate quorum timeout in milliseconds.
    pub quorum_timeout_ms: u64,
    /// Epoch gate cohort size (used for quorum threshold).
    pub cohort_size: usize,
    /// Whether to BLAKE3-verify migrated objects.
    pub verify_checksums: bool,
    /// Human-readable reason for the drain.
    pub reason: String,
}

impl NodeDrainConfig {
    /// Create a minimal config for draining a node.
    #[must_use]
    pub fn new(node_id: MemberId) -> Self {
        Self {
            node_id,
            proposer: node_id,
            target_nodes: Vec::new(),
            voter_members: Vec::new(),
            drain_timeout_ms: 300_000,
            quorum_timeout_ms: 30_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "graceful_drain".to_string(),
        }
    }

    /// Validate the configuration before use.
    pub fn validate(&self) -> Result<(), DrainNodeError> {
        if self.target_nodes.is_empty() {
            return Err(DrainNodeError::NoTargetNodes {
                node_id: self.node_id,
            });
        }
        if self.target_nodes.contains(&self.node_id) {
            return Err(DrainNodeError::SelfAsTarget {
                node_id: self.node_id,
            });
        }
        if self.voter_members.len() < self.cohort_size {
            return Err(DrainNodeError::InsufficientVoters {
                node_id: self.node_id,
                have: self.voter_members.len(),
                need: self.cohort_size,
            });
        }
        if !self.voter_members.contains(&self.proposer) {
            return Err(DrainNodeError::ProposerNotVoter {
                node_id: self.node_id,
                proposer: self.proposer,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DrainNodeError
// ---------------------------------------------------------------------------

/// Errors returned by the top-level [`drain_node()`] function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainNodeError {
    /// Configuration validation failed.
    ConfigError { node_id: MemberId, reason: String },
    /// No target nodes specified for data migration.
    NoTargetNodes { node_id: MemberId },
    /// The draining node is listed as a target.
    SelfAsTarget { node_id: MemberId },
    /// Not enough voter members for epoch quorum.
    InsufficientVoters {
        node_id: MemberId,
        have: usize,
        need: usize,
    },
    /// The proposer node is not in the voter set.
    ProposerNotVoter {
        node_id: MemberId,
        proposer: MemberId,
    },
    /// The drain stage failed.
    DrainFailed {
        node_id: MemberId,
        error: DrainError,
    },
    /// The data migration phase failed.
    MigrationFailed { node_id: MemberId, reason: String },
    /// The epoch gate transition failed.
    EpochGateFailed { node_id: MemberId, reason: String },
    /// The drain was cancelled before completion.
    Cancelled { node_id: MemberId },
    /// The drain timed out.
    TimedOut {
        node_id: MemberId,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// BLAKE3-verified membership drain request validation failed.
    DrainRequestValidationFailed { node_id: MemberId, reason: String },
}

impl std::fmt::Display for DrainNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigError { node_id, reason } => {
                write!(f, "node {} drain config error: {}", node_id.0, reason)
            }
            Self::NoTargetNodes { node_id } => {
                write!(f, "node {} drain: no target nodes", node_id.0)
            }
            Self::SelfAsTarget { node_id } => {
                write!(f, "node {} drain: self listed as target", node_id.0)
            }
            Self::InsufficientVoters {
                node_id,
                have,
                need,
            } => {
                write!(
                    f,
                    "node {} drain: need {} voters, have {}",
                    node_id.0, need, have
                )
            }
            Self::ProposerNotVoter { node_id, proposer } => {
                write!(
                    f,
                    "node {} drain: proposer {} not in voter set",
                    node_id.0, proposer.0
                )
            }
            Self::DrainFailed { node_id, error } => {
                write!(f, "node {} drain failed: {}", node_id.0, error)
            }
            Self::MigrationFailed { node_id, reason } => {
                write!(f, "node {} migration failed: {}", node_id.0, reason)
            }
            Self::EpochGateFailed { node_id, reason } => {
                write!(f, "node {} epoch gate failed: {}", node_id.0, reason)
            }
            Self::Cancelled { node_id } => {
                write!(f, "node {} drain cancelled", node_id.0)
            }
            Self::TimedOut {
                node_id,
                elapsed_ms,
                timeout_ms,
            } => {
                write!(
                    f,
                    "node {} drain timed out ({}ms / {}ms)",
                    node_id.0, elapsed_ms, timeout_ms
                )
            }
            Self::DrainRequestValidationFailed { node_id, reason } => {
                write!(
                    f,
                    "node {} drain request validation failed: {}",
                    node_id.0, reason
                )
            }
        }
    }
}

impl std::error::Error for DrainNodeError {}

// ---------------------------------------------------------------------------
// DrainNodeOutcome
// ---------------------------------------------------------------------------

/// Summary of a completed node drain operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainNodeOutcome {
    /// The node that was drained.
    pub node_id: MemberId,
    /// Whether all phases completed successfully.
    pub success: bool,
    /// Outcome of the drain executor (leases, data, cache, admin stages).
    pub drain_outcome: Option<DrainError>,
    /// Outcome of the data migration phase (if run separately).
    pub migration_outcome: Option<MigrationOutcome>,
    /// Outcome of the epoch gate transition.
    pub epoch_gate_result: Option<EpochGateResult>,
    /// Outcome of the replication health verification.
    pub health_verify_result: Option<HealthVerifyResult>,
    /// Outcome of the pool label update.
    pub pool_label_result: Option<PoolLabelResult>,
    /// Total elapsed wall-clock milliseconds.
    pub elapsed_ms: u64,
}

impl DrainNodeOutcome {
    /// Create an outcome for a successful drain.
    #[must_use]
    pub fn success(
        node_id: MemberId,
        migration: Option<MigrationOutcome>,
        gate: Option<EpochGateResult>,
        elapsed_ms: u64,
    ) -> Self {
        let gate_ok = gate.as_ref().is_none_or(|g| g.success);
        let mig_ok = migration.as_ref().is_none_or(|m| m.success);
        let success = gate_ok && mig_ok;
        Self {
            node_id,
            success,
            drain_outcome: None,
            migration_outcome: migration,
            epoch_gate_result: gate,
            health_verify_result: None,
            pool_label_result: None,
            elapsed_ms,
        }
    }

    /// Create an outcome for a failed drain.
    #[must_use]
    pub fn failure(node_id: MemberId, error: DrainError, elapsed_ms: u64) -> Self {
        Self {
            node_id,
            success: false,
            drain_outcome: Some(error),
            migration_outcome: None,
            epoch_gate_result: None,
            health_verify_result: None,
            pool_label_result: None,
            elapsed_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// drain_node() public entry point
// ---------------------------------------------------------------------------

/// Execute a full node drain: leases, data migration, epoch gate transition,
/// cache invalidation, and admin transfer.
///
/// This is the top-level public entry point for the node drain protocol.
/// It composes:
///
/// 1. [`DrainExecutor`] for stage-by-stage drain (leases, cache, admin)
/// 2. [`MigrationDriver`] for object-store data migration with placement
/// 3. [`EpochGate`] for the membership epoch transition
///
/// Production callers wire real implementations of [`DrainOps`],
/// [`MigrationOps`], [`HealthVerifyOps`], [`PoolLabelOps`], and
/// [`EpochGateOps`]. Tests use mocks.
#[allow(clippy::too_many_arguments)]
pub fn drain_node(
    config: &NodeDrainConfig,
    drain_ops: &mut dyn crate::DrainOps,
    migration_ops: &mut dyn MigrationOps,
    health_verify_ops: &dyn HealthVerifyOps,
    gate_ops: &mut dyn EpochGateOps,
    verify_ops: &dyn MembershipVerificationOps,
) -> Result<DrainNodeOutcome, DrainNodeError> {
    config.validate().map_err(|e| DrainNodeError::ConfigError {
        node_id: config.node_id,
        reason: e.to_string(),
    })?;

    let start = std::time::Instant::now();

    // -------------------------------------------------------------------
    // Phase 0: Validate drain request against live membership
    // -------------------------------------------------------------------
    let request = DrainRequest::new(
        config.node_id,
        config.proposer,
        verify_ops.current_epoch(),
        0, // fresh drain_sequence
    );

    let mut state_machine = DrainStateMachine::new();
    state_machine
        .validate_drain_request(&request, verify_ops)
        .map_err(|e| DrainNodeError::DrainRequestValidationFailed {
            node_id: config.node_id,
            reason: e.to_string(),
        })?;

    state_machine
        .initiate_drain()
        .map_err(|e| DrainNodeError::DrainRequestValidationFailed {
            node_id: config.node_id,
            reason: e.to_string(),
        })?;

    // -------------------------------------------------------------------
    // Phase 1: Drain executor (leases, cache, admin stages)
    // -------------------------------------------------------------------
    let (mut drain, _handle) = NodeDrain::drain(config.node_id);
    drain.set_timeout(config.drain_timeout_ms);

    let mut executor = DrainExecutor::new(drain);

    executor
        .execute(drain_ops)
        .map_err(|e| DrainNodeError::DrainFailed {
            node_id: config.node_id,
            error: e,
        })?;

    // -------------------------------------------------------------------
    // Phase 2: Data migration via MigrationDriver
    // -------------------------------------------------------------------
    let mut migration_driver = MigrationDriver::new(config.node_id);

    // Build migration plan using the ops trait
    match migration_driver.build_plan(migration_ops, &config.target_nodes) {
        Ok(_) => {
            // Execute migration
            migration_driver.execute(migration_ops).map_err(|e| {
                DrainNodeError::MigrationFailed {
                    node_id: config.node_id,
                    reason: e.to_string(),
                }
            })?;
        }
        Err(crate::migration::MigrationError::NothingToMigrate { .. }) => {
            // No objects to migrate — this is fine (empty node)
        }
        Err(e) => {
            return Err(DrainNodeError::MigrationFailed {
                node_id: config.node_id,
                reason: e.to_string(),
            });
        }
    }

    let migration_outcome = Some(migration_driver.outcome());

    // -------------------------------------------------------------------
    // Phase 2.5: Replication health verification
    // -------------------------------------------------------------------
    let health_verify_result = {
        let mut verifier = DrainHealthVerifier::new(config.node_id);
        match verifier.verify(health_verify_ops, &config.target_nodes) {
            Ok(()) => Some(verifier.result()),
            Err(e) => {
                return Err(DrainNodeError::ConfigError {
                    node_id: config.node_id,
                    reason: format!("health verification failed: {e}"),
                });
            }
        }
    };

    // -------------------------------------------------------------------
    // Phase 3: Epoch gate transition
    // -------------------------------------------------------------------
    let gate_config = EpochGateConfig {
        quorum_timeout_ms: config.quorum_timeout_ms,
        cohort_size: config.cohort_size,
    };

    let mut gate = EpochGate::new(config.node_id, gate_config);

    let gate_result = match gate.execute(
        gate_ops,
        config.proposer,
        &config.voter_members,
        &config.reason,
    ) {
        Ok(_) => {
            let result = EpochGateResult::from_gate(&gate);
            // Signal drain completion to the state machine
            let _ = state_machine.complete_drain();
            Some(result)
        }
        Err(e) => {
            return Err(DrainNodeError::EpochGateFailed {
                node_id: config.node_id,
                reason: e.to_string(),
            });
        }
    };

    // -------------------------------------------------------------------
    // Done: mark node as decommissioned
    // -------------------------------------------------------------------
    executor.decommission();

    let elapsed_ms = start.elapsed().as_millis() as u64;

    let mut outcome =
        DrainNodeOutcome::success(config.node_id, migration_outcome, gate_result, elapsed_ms);
    outcome.health_verify_result = health_verify_result;
    Ok(outcome)
}

/// Cancel an in-progress drain. Returns the drain handle for inspection.
#[allow(dead_code)]
pub fn cancel_drain(
    executor: &mut DrainExecutor,
    gate: &mut EpochGate,
    gate_ops: &mut dyn EpochGateOps,
) -> Result<DrainHandle, DrainNodeError> {
    executor.cancel().map_err(|e| DrainNodeError::DrainFailed {
        node_id: executor.drain().node_id(),
        error: e,
    })?;

    let _ = gate.cancel(gate_ops);

    Ok(executor.handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::drain_state::MembershipVerificationOps;
    use crate::executor::DrainOps;
    use std::collections::BTreeMap;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // mock membership verifier used in integration tests
    struct TestVerifyOps {
        live_nodes: Vec<MemberId>,
        members: Vec<MemberId>,
        epoch: tidefs_membership_epoch::EpochId,
    }

    impl TestVerifyOps {
        fn new(epoch: u64) -> Self {
            Self {
                live_nodes: Vec::new(),
                members: Vec::new(),
                epoch: tidefs_membership_epoch::EpochId(epoch),
            }
        }
        fn add_member(&mut self, id: MemberId, live: bool) {
            self.members.push(id);
            if live {
                self.live_nodes.push(id);
            }
        }
    }

    impl MembershipVerificationOps for TestVerifyOps {
        fn is_node_live(&self, node_id: MemberId) -> bool {
            self.live_nodes.contains(&node_id)
        }
        fn is_member(&self, node_id: MemberId) -> bool {
            self.members.contains(&node_id)
        }
        fn current_epoch(&self) -> tidefs_membership_epoch::EpochId {
            self.epoch
        }
    }

    struct TestDrainOps;
    impl DrainOps for TestDrainOps {
        fn lease_ids_for_node(&self, _: MemberId) -> Vec<u64> {
            vec![]
        }
        fn release_lease(&mut self, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn object_count_for_node(&self, _: MemberId) -> u64 {
            0
        }
        fn cache_bytes_for_node(&self, _: MemberId) -> u64 {
            0
        }
        fn migrate_one_object(&mut self, _: MemberId) -> Result<bool, String> {
            Ok(false)
        }
        fn invalidate_cache_chunk(&mut self, _: MemberId, _: u64) -> Result<(u64, u64), String> {
            Ok((0, 0))
        }
        fn transfer_admin(&mut self, _: MemberId, _: MemberId) -> Result<(), String> {
            Ok(())
        }
    }

    struct TestMigrationOps {
        objects: Vec<(u64, u64)>,
    }

    impl MigrationOps for TestMigrationOps {
        fn enumerate_objects(&self, _source_node: MemberId) -> Result<Vec<(u64, u64)>, String> {
            Ok(self.objects.clone())
        }
        fn placement_target_for(
            &self,
            _source_node: MemberId,
            _object_id: u64,
            targets: &[MemberId],
        ) -> Result<MemberId, String> {
            if targets.is_empty() {
                Err("no targets".to_string())
            } else {
                Ok(targets[0])
            }
        }
        fn transfer_object(
            &mut self,
            _source_node: MemberId,
            _target: MemberId,
            _object_id: u64,
        ) -> Result<u64, String> {
            Ok(1024)
        }
        fn verify_checksum(&self, _target: MemberId, _object_id: u64) -> Result<(), String> {
            Ok(())
        }
    }

    struct TestGateOps {
        proposals: BTreeMap<u64, MemberId>,
        next_pid: u64,
        committed: Vec<u64>,
    }

    impl TestGateOps {
        fn new() -> Self {
            Self {
                proposals: BTreeMap::new(),
                next_pid: 100,
                committed: Vec::new(),
            }
        }
    }

    impl EpochGateOps for TestGateOps {
        fn propose_exclusion(
            &mut self,
            node_to_remove: MemberId,
            _proposer: MemberId,
            _reason: &str,
        ) -> Result<u64, String> {
            let pid = self.next_pid;
            self.next_pid += 1;
            self.proposals.insert(pid, node_to_remove);
            Ok(pid)
        }
        fn collect_accepts(
            &mut self,
            _proposal_id: u64,
            voter_members: &[MemberId],
        ) -> Result<usize, String> {
            Ok(voter_members.len())
        }
        fn quorum_reached(&self, _proposal_id: u64, _threshold: usize) -> bool {
            // Simulate: quorum always met in tests
            true
        }
        fn commit_transition(&mut self, proposal_id: u64) -> Result<(), String> {
            self.committed.push(proposal_id);
            Ok(())
        }
        fn cancel_proposal(&mut self, proposal_id: u64) -> Result<(), String> {
            self.proposals.remove(&proposal_id);
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn drain_node_full_happy_path() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(2),
            target_nodes: vec![mid(3), mid(4)],
            voter_members: vec![mid(2), mid(3), mid(4)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "maintenance".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps {
            objects: vec![(10, 1024), (20, 2048), (30, 512)],
        };
        let mut gate_ops = TestGateOps::new();

        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(1), true);
        verify_ops.add_member(mid(2), true);
        verify_ops.add_member(mid(3), true);
        verify_ops.add_member(mid(4), true);
        let outcome = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.node_id, mid(1));
        assert!(outcome.migration_outcome.is_some());
        assert!(outcome.epoch_gate_result.is_some());
        let _elapsed_ms = outcome.elapsed_ms;
    }

    #[test]
    fn drain_node_empty_node_no_objects() {
        let config = NodeDrainConfig {
            node_id: mid(5),
            proposer: mid(6),
            target_nodes: vec![mid(6)],
            voter_members: vec![mid(6), mid(7), mid(8)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "drain".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps { objects: vec![] };
        let mut gate_ops = TestGateOps::new();

        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(5), true);
        verify_ops.add_member(mid(6), true);
        verify_ops.add_member(mid(7), true);
        verify_ops.add_member(mid(8), true);
        let outcome = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.node_id, mid(5));
    }

    #[test]
    fn drain_node_config_rejects_empty_targets() {
        let config = NodeDrainConfig::new(mid(1));
        let err = config.validate().unwrap_err();
        assert!(matches!(err, DrainNodeError::NoTargetNodes { .. }));
    }

    #[test]
    fn drain_node_config_rejects_self_target() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(1),
            target_nodes: vec![mid(1)],
            voter_members: vec![mid(1), mid(2), mid(3)],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, DrainNodeError::SelfAsTarget { .. }));
    }

    #[test]
    fn drain_node_config_rejects_insufficient_voters() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(1),
            target_nodes: vec![mid(2)],
            voter_members: vec![mid(1)],
            cohort_size: 3,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, DrainNodeError::InsufficientVoters { .. }));
    }

    #[test]
    fn drain_node_config_rejects_proposer_not_voter() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(99),
            target_nodes: vec![mid(2)],
            voter_members: vec![mid(1), mid(2), mid(3)],
            cohort_size: 3,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, DrainNodeError::ProposerNotVoter { .. }));
    }

    #[test]
    fn drain_node_outcome_failure() {
        let outcome =
            DrainNodeOutcome::failure(mid(1), DrainError::AlreadyDraining { node_id: mid(1) }, 500);
        assert!(!outcome.success);
        assert_eq!(outcome.elapsed_ms, 500);
        assert!(outcome.drain_outcome.is_some());
    }

    // --- DrainRequest validation integration tests ---

    #[test]
    fn drain_node_rejects_stale_epoch() {
        // The drain_node() builds DrainRequest from verify_ops.current_epoch(),
        // so we need a mock where the epoch is behind the membership epoch.
        // We simulate this by having two TestVerifyOps with different epochs:
        // one "current" at 10 and a "request" at 5. Since drain_node() uses
        // the same ops for both building and validating, we instead test the
        // validation path directly via the state machine.
        //
        // Integration test: use a mock where the epoch is behind what the
        // request carries. We can do this by constructing a DrainRequest
        // with epoch 10, but providing verify_ops that report epoch 5 (stale).
        // However, drain_node() builds the request from the same ops, so
        // the request epoch will always match the ops epoch. Thus stale-epoch
        // detection is tested at the unit level in drain_state.rs.
        //
        // For integration coverage, we test a node-not-found scenario.
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(2),
            target_nodes: vec![mid(3)],
            voter_members: vec![mid(2), mid(3), mid(4)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "test".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps { objects: vec![] };
        let mut gate_ops = TestGateOps::new();
        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        // Only node 2 is a member, node 1 is NOT a member
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(2), true);
        verify_ops.add_member(mid(3), true);
        verify_ops.add_member(mid(4), true);

        let err = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            DrainNodeError::DrainRequestValidationFailed { .. }
        ));
        let msg = format!("{err}");
        assert!(msg.contains("not found in membership"));
    }

    #[test]
    fn drain_node_rejects_self_drain() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(1), // self-drain
            target_nodes: vec![mid(2)],
            voter_members: vec![mid(1), mid(2), mid(3)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "test".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps { objects: vec![] };
        let mut gate_ops = TestGateOps::new();
        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(1), true);
        verify_ops.add_member(mid(2), true);

        let err = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            DrainNodeError::DrainRequestValidationFailed { .. }
        ));
        let msg = format!("{err}");
        assert!(msg.contains("cannot drain itself"));
    }

    #[test]
    fn drain_node_rejects_non_live_node() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(2),
            target_nodes: vec![mid(3)],
            voter_members: vec![mid(2), mid(3), mid(4)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "test".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps { objects: vec![] };
        let mut gate_ops = TestGateOps::new();
        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        // node 1 is member but NOT live
        verify_ops.add_member(mid(1), false);
        verify_ops.add_member(mid(2), true);

        let err = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            DrainNodeError::DrainRequestValidationFailed { .. }
        ));
        let msg = format!("{err}");
        assert!(msg.contains("not live"));
    }

    #[test]
    fn drain_node_rejects_initiator_not_member() {
        // proposer 99 passes config.validate() (it's in voter_members),
        // but is NOT in the membership verification ops.
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(99), // not a membership member
            target_nodes: vec![mid(3)],
            voter_members: vec![mid(99), mid(2), mid(3), mid(4)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "test".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps { objects: vec![] };
        let mut gate_ops = TestGateOps::new();
        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(1), true);
        verify_ops.add_member(mid(2), true);
        // Node 99 is NOT added to verify_ops — it's not a membership member

        let err = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            DrainNodeError::DrainRequestValidationFailed { .. }
        ));
        let msg = format!("{err}");
        assert!(msg.contains("not a cluster member"));
    }

    #[test]
    fn drain_node_full_lifecycle_with_state_machine() {
        let config = NodeDrainConfig {
            node_id: mid(1),
            proposer: mid(2),
            target_nodes: vec![mid(3), mid(4)],
            voter_members: vec![mid(2), mid(3), mid(4)],
            drain_timeout_ms: 60_000,
            quorum_timeout_ms: 10_000,
            cohort_size: 3,
            verify_checksums: true,
            reason: "maintenance".to_string(),
        };

        let mut drain_ops = TestDrainOps;
        let mut migration_ops = TestMigrationOps {
            objects: vec![(10, 1024), (20, 2048), (30, 512)],
        };
        let mut gate_ops = TestGateOps::new();
        let health_verify_ops = crate::health_verify::NoOpHealthVerifyOps;
        let mut verify_ops = TestVerifyOps::new(5);
        verify_ops.add_member(mid(1), true);
        verify_ops.add_member(mid(2), true);
        verify_ops.add_member(mid(3), true);
        verify_ops.add_member(mid(4), true);

        let outcome = drain_node(
            &config,
            &mut drain_ops,
            &mut migration_ops,
            &health_verify_ops,
            &mut gate_ops,
            &verify_ops,
        )
        .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.node_id, mid(1));
        assert!(outcome.migration_outcome.is_some());
        assert!(outcome.epoch_gate_result.is_some());
    }
}
