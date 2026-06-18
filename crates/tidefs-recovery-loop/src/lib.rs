// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Continuous failure recovery loop: detect, scope, plan, execute, verify — PC-010.5.
//!
//! The [`recovery_loop`] module provides committed-root-validated crash recovery
//! with BLAKE3 chain verification, intent-log record replay dispatch, and
//! health-gated rebuild decisions (#5315).
//!
//! TideFS failure recovery is chunk-scoped, health-gated, and receipt-backed.
//! The recovery loop is a continuous 5-phase cycle that composes the health
//! tracker (#895), rebuild planner (#893), transfer orchestrator (#901),
//! and flow commit coordinator (#902) into a coordinated failure recovery runtime.

#![forbid(unsafe_code)]
pub mod recovery_loop;
pub use recovery_loop::compute_committed_root_digest;
pub use recovery_loop::validate_committed_root;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::path::Path;

// ── RecoveryPolicy ───────────────────────────────────────────────────

/// Policy gate that controls which recovery operations are permitted
/// during mount and open paths.
///
/// Every recovery code path (committed-root selection, intent-log replay,
/// scrub, repair writeback) must consult this policy before mutating
/// durable state. The policy replaces the prior implicit repair behavior
/// with explicit, testable branches.
///
/// # Variants
///
/// - \`ReadOnly\`: No mutation allowed. Mount inspects state and returns
///   validation but never writes. Suitable for forensics and online
///   verification.
/// - \`ReplayOnly\`: Intent-log replay to the last committed state is
///   permitted. Scrub inspection runs read-only. Repair writeback and
///   metadata fixup are skipped. This is the safe production default.
/// - \`RepairWriteback\`: Full recovery including intent-log replay,
///   scrub repair, and metadata fixup. Requires explicit operator
///   opt-in and validation output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPolicy {
    /// No mutation allowed — inspect and report only.
    ReadOnly,
    /// Replay intent-log to committed state; no repair writeback.
    ReplayOnly,
    /// Full repair: replay, scrub repair, and metadata fixup.
    RepairWriteback,
}

impl RecoveryPolicy {
    /// Returns \`true\` when this policy permits intent-log replay.
    #[must_use]
    pub fn allows_replay(&self) -> bool {
        matches!(self, Self::ReplayOnly | Self::RepairWriteback)
    }

    /// Returns \`true\` when this policy permits repair writeback
    /// (scrub repair, metadata fixup, or any durable mutation beyond
    /// intent-log replay).
    #[must_use]
    pub fn allows_repair_writeback(&self) -> bool {
        matches!(self, Self::RepairWriteback)
    }

    /// Returns \`true\` when this policy permits any mutation at all
    /// (replay or repair).
    #[must_use]
    pub fn allows_any_mutation(&self) -> bool {
        !matches!(self, Self::ReadOnly)
    }

    /// Human-readable label for diagnostics and validation recording.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReplayOnly => "replay-only",
            Self::RepairWriteback => "repair-writeback",
        }
    }
}

impl Default for RecoveryPolicy {
    /// The safe production default: replay intent-log to committed
    /// state without silent repair writeback.
    fn default() -> Self {
        Self::ReplayOnly
    }
}

use tidefs_membership_epoch::{DomainId, HealthClass};
use tidefs_rebuild_planner::RebuildPlanner;
use tidefs_replica_health::{tracker::ReplicaHealthTracker, ChunkId, NodeId};

use tidefs_commit_group::{
    CommitGroupReader, CommitGroupRecovery, CommittedRootBlock, RecoveryResult,
};
use tidefs_local_object_store::LocalObjectStore;
use tidefs_vfs_engine::VfsEngine;

/// Gate constant for PC-010.5 failure recovery loop.
pub const FAILURE_RECOVERY_LOOP_GATE_PC_010_5: &str =
    "PC-010.5 failure recovery loop covers detect, scope, plan, execute, verify phases";

// ── Recovery priority ────────────────────────────────────────────────

/// Priority tiers for the continuous failure recovery loop.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RecoveryPriority {
    /// Normal steady-state replication. Priority 0.
    SteadyReplication = 0,
    /// Replica lagging — needs catchup but quorum is intact. Priority 1.
    CatchupRepair = 1,
    /// Durability at risk — quorum may be degraded. Priority 2.
    LossRebuild = 2,
}

// ── Recovery trigger ─────────────────────────────────────────────────

/// Events that can trigger a recovery response.
///
/// Classified into priority tiers by [`classify_trigger`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecoveryTrigger {
    /// A storage node has failed or become unreachable.
    /// Data at risk — highest urgency.
    NodeFailure { node_id: NodeId },
    /// A backing device has failed or been removed.
    /// Redundancy degraded — rebuild needed.
    DeviceFailure { node_id: NodeId, device_index: u32 },
    /// Scrub detected data corruption.
    /// Data integrity at risk — immediate repair needed.
    CorruptionDetected { source: String, segment_id: u64 },
}

/// Classify a recovery trigger into its urgency tier.
///
/// - `NodeFailure` maps to `LossRebuild` (data at risk).
/// - `DeviceFailure` maps to `CatchupRepair` (redundancy degraded).
/// - `CorruptionDetected` maps to `LossRebuild` (integrity at risk).
#[must_use]
pub fn classify_trigger(trigger: &RecoveryTrigger) -> RecoveryPriority {
    match trigger {
        RecoveryTrigger::NodeFailure { .. } => RecoveryPriority::LossRebuild,
        RecoveryTrigger::DeviceFailure { .. } => RecoveryPriority::CatchupRepair,
        RecoveryTrigger::CorruptionDetected { .. } => RecoveryPriority::LossRebuild,
    }
}
// ── Recovery phase ───────────────────────────────────────────────────

/// Phase of the 5-phase continuous recovery loop.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    Detect,
    Scope,
    Plan,
    Execute,
    Verify,
}

// ── RecoveryThrottle ─────────────────────────────────────────────────

/// Adaptive recovery rate limiter.
///
/// When clients are slow, recovery slows down; when clients are idle,
/// recovery speeds up. Explicit, not opaque like Ceph mclock weights.
#[derive(Debug)]
pub struct RecoveryThrottle {
    pub max_concurrent_per_domain: usize,
    pub recovery_bandwidth_budget: u64,
    pub recovery_bandwidth_consumed: u64,
    pub client_latency_p50_ms: f64,
    pub client_latency_baseline_ms: f64,
    pub throttle_aggressiveness: f64,
}

impl RecoveryThrottle {
    #[must_use]
    pub fn new(
        max_concurrent_per_domain: usize,
        recovery_bandwidth_budget: u64,
        client_latency_p50_ms: f64,
        client_latency_baseline_ms: f64,
        throttle_aggressiveness: f64,
    ) -> Self {
        RecoveryThrottle {
            max_concurrent_per_domain,
            recovery_bandwidth_budget,
            recovery_bandwidth_consumed: 0,
            client_latency_p50_ms,
            client_latency_baseline_ms,
            throttle_aggressiveness,
        }
    }

    #[must_use]
    pub fn admit_recovery_ticket(&self, ticket_cost: u64) -> bool {
        let adjusted = self.compute_adjusted_budget();
        (self.recovery_bandwidth_consumed + ticket_cost) <= adjusted
    }

    pub fn consume(&mut self, amount: u64) {
        self.recovery_bandwidth_consumed = self.recovery_bandwidth_consumed.saturating_add(amount);
    }

    pub fn release(&mut self, amount: u64) {
        self.recovery_bandwidth_consumed = self.recovery_bandwidth_consumed.saturating_sub(amount);
    }

    #[must_use]
    pub fn compute_adjusted_budget(&self) -> u64 {
        let baseline = self.client_latency_baseline_ms.max(0.001);
        let latency_ratio = self.client_latency_p50_ms / baseline;
        let scale = 1.0 / (latency_ratio * self.throttle_aggressiveness).max(1.0);
        let adjusted = (self.recovery_bandwidth_budget as f64 * scale) as u64;
        adjusted.max(1)
    }

    #[must_use]
    pub fn should_pause_recovery(&self) -> bool {
        let baseline = self.client_latency_baseline_ms.max(0.001);
        self.client_latency_p50_ms > baseline * 3.0
    }

    pub fn update_client_latency(&mut self, p50_ms: f64) {
        self.client_latency_p50_ms = p50_ms;
    }
}

// ── CascadingFailureGuard ────────────────────────────────────────────

/// Domain-scoped recovery admission guard.
///
/// Prevents all replicas in a failure domain from being recovered
/// simultaneously, and enforces an aggregate cluster-wide limit.
#[derive(Debug)]
pub struct CascadingFailureGuard {
    pub domain_batch_limits: BTreeMap<DomainId, usize>,
    pub active_domain_batches: BTreeMap<DomainId, usize>,
    pub max_aggregate_recovery_load: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Admitted,
    DomainAtCapacity {
        domain: DomainId,
        limit: usize,
        active: usize,
    },
    ClusterAtRecoveryCapacity {
        total_active: usize,
    },
}

impl CascadingFailureGuard {
    #[must_use]
    pub fn new(max_aggregate_recovery_load: usize) -> Self {
        CascadingFailureGuard {
            domain_batch_limits: BTreeMap::new(),
            active_domain_batches: BTreeMap::new(),
            max_aggregate_recovery_load,
        }
    }

    pub fn set_domain_limit(&mut self, domain: DomainId, limit: usize) {
        self.domain_batch_limits.insert(domain, limit);
    }

    pub fn admit_recovery_flow(&mut self, domain: DomainId) -> AdmissionDecision {
        let active = self
            .active_domain_batches
            .get(&domain)
            .copied()
            .unwrap_or(0);
        let limit = self.domain_batch_limits.get(&domain).copied().unwrap_or(3);

        if active >= limit && limit > 0 {
            return AdmissionDecision::DomainAtCapacity {
                domain,
                limit,
                active,
            };
        }

        let total_active: usize = self.active_domain_batches.values().sum();
        if self.max_aggregate_recovery_load > 0 && total_active >= self.max_aggregate_recovery_load
        {
            return AdmissionDecision::ClusterAtRecoveryCapacity { total_active };
        }

        *self.active_domain_batches.entry(domain).or_insert(0) += 1;
        AdmissionDecision::Admitted
    }

    pub fn complete_recovery_flow(&mut self, domain: DomainId) {
        self.active_domain_batches
            .entry(domain)
            .and_modify(|c| *c = c.saturating_sub(1));
    }

    #[must_use]
    pub fn total_active_batches(&self) -> usize {
        self.active_domain_batches.values().sum()
    }
}

// ── NodeRecoveryBudget ───────────────────────────────────────────────

/// Per-node recovery resource budget.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct NodeRecoveryBudget {
    pub node_id: NodeId,
    pub max_recovery_iops: u64,
    pub max_recovery_bandwidth_bytes: u64,
    pub max_recovery_memory_bytes: u64,
    pub current_recovery_iops: u64,
    pub current_recovery_bandwidth: u64,
    pub current_recovery_memory: u64,
}

impl NodeRecoveryBudget {
    #[must_use]
    pub fn new(
        node_id: NodeId,
        max_recovery_iops: u64,
        max_recovery_bandwidth_bytes: u64,
        max_recovery_memory_bytes: u64,
    ) -> Self {
        NodeRecoveryBudget {
            node_id,
            max_recovery_iops,
            max_recovery_bandwidth_bytes,
            max_recovery_memory_bytes,
            current_recovery_iops: 0,
            current_recovery_bandwidth: 0,
            current_recovery_memory: 0,
        }
    }

    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.current_recovery_iops < self.max_recovery_iops
            && self.current_recovery_bandwidth < self.max_recovery_bandwidth_bytes
            && self.current_recovery_memory < self.max_recovery_memory_bytes
    }

    pub fn reserve(&mut self, iops: u64, bandwidth: u64, memory: u64) {
        self.current_recovery_iops = self.current_recovery_iops.saturating_add(iops);
        self.current_recovery_bandwidth = self.current_recovery_bandwidth.saturating_add(bandwidth);
        self.current_recovery_memory = self.current_recovery_memory.saturating_add(memory);
    }

    pub fn release(&mut self, iops: u64, bandwidth: u64, memory: u64) {
        self.current_recovery_iops = self.current_recovery_iops.saturating_sub(iops);
        self.current_recovery_bandwidth = self.current_recovery_bandwidth.saturating_sub(bandwidth);
        self.current_recovery_memory = self.current_recovery_memory.saturating_sub(memory);
    }

    pub fn reset_consumption(&mut self) {
        self.current_recovery_iops = 0;
        self.current_recovery_bandwidth = 0;
        self.current_recovery_memory = 0;
    }
}

// ── Rebuild scope ───────────────────────────────────────────────────

/// Scoped loss assessment determining how many replicas to rebuild.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildScope {
    pub chunks_affected: usize,
    pub replicas_needed: usize,
    pub priority: RecoveryPriority,
    pub quorum_intact: bool,
}

/// Compute how many replicas need rebuilding to restore quorum.
#[must_use]
pub fn compute_rebuild_scope(
    required_replicas: usize,
    surviving_count: usize,
    chunks_affected: usize,
) -> RebuildScope {
    let quorum = (required_replicas / 2) + 1;
    let needed = required_replicas.saturating_sub(surviving_count);
    let quorum_intact = surviving_count >= quorum;

    let priority = if surviving_count < quorum {
        RecoveryPriority::LossRebuild
    } else if needed > 0 {
        RecoveryPriority::CatchupRepair
    } else {
        RecoveryPriority::SteadyReplication
    };

    RebuildScope {
        chunks_affected,
        replicas_needed: needed,
        priority,
        quorum_intact,
    }
}

// ── Recovery action ─────────────────────────────────────────────────

/// A recovery action for a single chunk.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    NoAction,
    Backfill {
        source_nodes: Vec<NodeId>,
        target_node: NodeId,
    },
    ImmediateRebuild {
        source_node: NodeId,
        target_nodes: Vec<NodeId>,
    },
    DataLossAlert {
        reason: String,
    },
}

impl RecoveryAction {
    /// Derive the recovery priority tier for this action.
    ///
    /// - `NoAction` → `SteadyReplication`
    /// - `Backfill` → `CatchupRepair`
    /// - `ImmediateRebuild` → `LossRebuild`
    /// - `DataLossAlert` → `LossRebuild`
    #[must_use]
    pub fn priority(&self) -> RecoveryPriority {
        match self {
            Self::NoAction => RecoveryPriority::SteadyReplication,
            Self::Backfill { .. } => RecoveryPriority::CatchupRepair,
            Self::ImmediateRebuild { .. } => RecoveryPriority::LossRebuild,
            Self::DataLossAlert { .. } => RecoveryPriority::LossRebuild,
        }
    }
}

/// Records the recovery action taken and its rationale.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RecoveryActionReceipt {
    pub chunk_id: ChunkId,
    pub action: RecoveryAction,
    pub priority: RecoveryPriority,
    pub phase: RecoveryPhase,
    pub epoch: u64,
    pub rationale: String,
}

/// Select the appropriate recovery action for a degraded chunk.
#[must_use]
pub fn select_recovery_action(
    chunk_id: ChunkId,
    required_replicas: usize,
    healthy_replicas: &[(NodeId, HealthClass)],
) -> RecoveryActionReceipt {
    let healthy_count = healthy_replicas.len();
    let quorum = (required_replicas / 2) + 1;

    if healthy_count == 0 {
        return RecoveryActionReceipt {
            chunk_id,
            action: RecoveryAction::DataLossAlert {
                reason: "all replicas lost".to_string(),
            },
            priority: RecoveryPriority::LossRebuild,
            phase: RecoveryPhase::Scope,
            epoch: 0,
            rationale: "No surviving replicas — operator must restore from backup".to_string(),
        };
    }

    if healthy_count < quorum {
        let source_node = healthy_replicas
            .iter()
            .max_by_key(|(_, hc)| *hc)
            .map(|(n, _)| *n)
            .unwrap();
        RecoveryActionReceipt {
            chunk_id,
            action: RecoveryAction::ImmediateRebuild {
                source_node,
                target_nodes: vec![],
            },
            priority: RecoveryPriority::LossRebuild,
            phase: RecoveryPhase::Scope,
            epoch: 0,
            rationale: format!(
                "Quorum degraded: {healthy_count}/{required_replicas} replicas healthy"
            ),
        }
    } else if healthy_count < required_replicas {
        let source_nodes: Vec<NodeId> = healthy_replicas.iter().map(|(n, _)| *n).collect();
        RecoveryActionReceipt {
            chunk_id,
            action: RecoveryAction::Backfill {
                source_nodes,
                target_node: NodeId::new(0),
            },
            priority: RecoveryPriority::CatchupRepair,
            phase: RecoveryPhase::Scope,
            epoch: 0,
            rationale: format!(
                "Quorum intact but {healthy_count}/{required_replicas} — backfill needed"
            ),
        }
    } else {
        RecoveryActionReceipt {
            chunk_id,
            action: RecoveryAction::NoAction,
            priority: RecoveryPriority::SteadyReplication,
            phase: RecoveryPhase::Scope,
            epoch: 0,
            rationale: format!("All {required_replicas} replicas healthy"),
        }
    }
}

// ── RecoveryProgressReceipt ──────────────────────────────────────────

/// External observability: emitted periodically, reports recovery progress.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProgressReceipt {
    pub epoch: u64,
    pub phase: RecoveryPhase,
    pub chunks_pending: u64,
    pub chunks_scoped: u64,
    pub chunks_in_flight: u64,
    pub chunks_recovered: u64,
    pub chunks_verified: u64,
    pub chunks_failed: u64,
    pub priority_distribution: BTreeMap<RecoveryPriority, u64>,
}

impl RecoveryProgressReceipt {
    #[must_use]
    pub fn new(epoch: u64, phase: RecoveryPhase) -> Self {
        RecoveryProgressReceipt {
            epoch,
            phase,
            chunks_pending: 0,
            chunks_scoped: 0,
            chunks_in_flight: 0,
            chunks_recovered: 0,
            chunks_verified: 0,
            chunks_failed: 0,
            priority_distribution: BTreeMap::new(),
        }
    }
}

// ── RecoveryPlan ──────────────────────────────────────────────────────

/// A computed recovery plan for a specific trigger.
///
/// For each trigger, the plan computes affected objects via locator-table
/// reverse-lookup and schedules rebuilds via the placement algorithm.
#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    /// The trigger that initiated this plan.
    pub trigger: RecoveryTrigger,
    /// Classified priority tier.
    pub priority: RecoveryPriority,
    /// Affected chunk IDs discovered via locator-table reverse-lookup.
    pub affected_chunks: Vec<ChunkId>,
    /// The recovery actions to execute for each affected chunk.
    pub actions: Vec<RecoveryActionReceipt>,
    /// Time the plan was created (nanoseconds since epoch).
    pub created_at_ns: u64,
}

impl RecoveryPlan {
    /// Create a new recovery plan from a trigger.
    #[must_use]
    pub fn new(trigger: RecoveryTrigger, created_at_ns: u64) -> Self {
        let priority = classify_trigger(&trigger);
        RecoveryPlan {
            trigger,
            priority,
            affected_chunks: Vec::new(),
            actions: Vec::new(),
            created_at_ns,
        }
    }

    /// Compute affected chunks via reverse-lookup from the health
    /// tracker, then compute recovery actions for each chunk.
    pub fn scope(&mut self, health_tracker: &ReplicaHealthTracker, required_replicas: usize) {
        self.affected_chunks = health_tracker.degraded_chunk_ids();
        self.actions.clear();
        for &chunk_id in &self.affected_chunks {
            let replicas = health_tracker.replica_states_for_chunk(chunk_id);
            // Count non-retired, healthy replicas
            let healthy: Vec<(NodeId, HealthClass)> = replicas
                .iter()
                .filter(|(_, s)| !s.is_retired() && s.is_healthy())
                .map(|(n, _)| (*n, HealthClass::Healthy))
                .collect();
            let receipt = select_recovery_action(chunk_id, required_replicas, &healthy);
            self.actions.push(receipt);
        }
    }

    /// Number of affected chunks in this plan.
    #[must_use]
    pub fn affected_count(&self) -> usize {
        self.affected_chunks.len()
    }

    /// Estimated bytes affected (chunks × assumed average chunk size).
    #[must_use]
    pub fn estimated_bytes(&self, avg_chunk_bytes: u64) -> u64 {
        self.affected_chunks.len() as u64 * avg_chunk_bytes
    }
}

// ── RecoveryStats ─────────────────────────────────────────────────────

/// Aggregated recovery statistics for observability and progress tracking.
#[derive(Clone, Debug, Default)]
pub struct RecoveryStats {
    /// Number of distinct recovery triggers currently active.
    pub triggers_active: u64,
    /// Number of objects (chunks) currently undergoing recovery.
    pub objects_recovering: u64,
    /// Number of objects (chunks) that have been recovered.
    pub objects_recovered: u64,
    /// Total bytes currently being recovered.
    pub bytes_recovering: u64,
    /// Estimated wall-clock seconds until completion, or f64::INFINITY if
    /// no estimate is available.
    pub estimated_completion_secs: f64,
}

impl RecoveryStats {
    /// Create a new zeroed stats accumulator.
    #[must_use]
    pub fn new() -> Self {
        RecoveryStats {
            triggers_active: 0,
            objects_recovering: 0,
            objects_recovered: 0,
            bytes_recovering: 0,
            estimated_completion_secs: f64::INFINITY,
        }
    }

    /// Mark the start of recovery for a set of objects totaling `bytes`.
    pub fn start_recovery(&mut self, trigger_count: u64, objects: u64, bytes: u64) {
        self.triggers_active = self.triggers_active.saturating_add(trigger_count);
        self.objects_recovering = self.objects_recovering.saturating_add(objects);
        self.bytes_recovering = self.bytes_recovering.saturating_add(bytes);
    }

    /// Mark a batch of objects as recovered.
    pub fn record_recovered(&mut self, objects: u64, bytes: u64) {
        self.objects_recovering = self.objects_recovering.saturating_sub(objects);
        self.objects_recovered = self.objects_recovered.saturating_add(objects);
        self.bytes_recovering = self.bytes_recovering.saturating_sub(bytes);
    }

    /// Complete a trigger (decrement active trigger count).
    pub fn complete_trigger(&mut self) {
        self.triggers_active = self.triggers_active.saturating_sub(1);
    }

    /// Update the estimated completion time.
    pub fn set_estimated_completion(&mut self, secs: f64) {
        self.estimated_completion_secs = secs;
    }

    /// Returns `true` if no recovery work is in progress.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.triggers_active == 0 && self.objects_recovering == 0
    }
}

// ── RecoveryLoop ─────────────────────────────────────────────────────

/// The continuous failure recovery loop orchestrator.
#[derive(Debug)]
pub struct RecoveryLoop {
    pub phase: RecoveryPhase,
    pub health_tracker: ReplicaHealthTracker,
    pub rebuild_planner: RebuildPlanner,
    pub cascading_guard: CascadingFailureGuard,
    pub throttle: RecoveryThrottle,
    pub node_budgets: BTreeMap<NodeId, NodeRecoveryBudget>,
    pub actions: Vec<RecoveryActionReceipt>,
    pub progress: RecoveryProgressReceipt,
    pub iterations: u64,
    pub pending_work: BinaryHeap<RecoveryWorkItem>,
    pub dedup_seen: HashSet<RecoveryTrigger>,
    pub paused: bool,
    pub stats: RecoveryStats,
}

impl RecoveryLoop {
    #[must_use]
    pub fn new(
        health_tracker: ReplicaHealthTracker,
        rebuild_planner: RebuildPlanner,
        max_aggregate_recovery_load: usize,
        throttle: RecoveryThrottle,
    ) -> Self {
        RecoveryLoop {
            phase: RecoveryPhase::Detect,
            health_tracker,
            rebuild_planner,
            cascading_guard: CascadingFailureGuard::new(max_aggregate_recovery_load),
            throttle,
            node_budgets: BTreeMap::new(),
            actions: Vec::new(),
            progress: RecoveryProgressReceipt::new(0, RecoveryPhase::Detect),
            iterations: 0,
            pending_work: BinaryHeap::new(),
            dedup_seen: HashSet::new(),
            paused: false,
            stats: RecoveryStats::new(),
        }
    }

    /// Advance the recovery loop through detect → scope → plan → execute → verify.
    pub fn advance(
        &mut self,
        now_ns: u64,
        epoch: u64,
    ) -> Result<RecoveryProgressReceipt, RecoveryLoopError> {
        if self.paused {
            return Err(RecoveryLoopError::Paused);
        }

        self.iterations = self.iterations.saturating_add(1);
        self.progress.epoch = epoch;

        // Phase 1: Detect
        self.phase = RecoveryPhase::Detect;
        self.progress.phase = RecoveryPhase::Detect;

        // Check for expired flap backoffs
        let _expired = self.health_tracker.check_backoff_expiry(now_ns);

        // Drain pending alerts for external observability
        let _alerts = self.health_tracker.drain_alerts();

        // Collect degraded chunk IDs from the health tracker
        let degraded_chunks = self.health_tracker.degraded_chunk_ids();

        // Phase 2: Scope
        self.phase = RecoveryPhase::Scope;

        // For each degraded chunk, determine the recovery action and scope
        let mut scoped_actions: Vec<RecoveryActionReceipt> = Vec::new();
        for chunk_id in &degraded_chunks {
            let replicas = self.health_tracker.replica_states_for_chunk(*chunk_id);

            // Count total non-retired replicas and identify healthy ones
            let mut required_replicas: usize = 0;
            let mut healthy_replicas: Vec<(NodeId, HealthClass)> = Vec::new();

            for (node_id, state) in &replicas {
                if state.is_retired() {
                    continue;
                }
                required_replicas += 1;
                if state.is_healthy() {
                    healthy_replicas.push((*node_id, HealthClass::Healthy));
                }
            }

            // Default quorum if no replicas were tracked
            if required_replicas == 0 {
                required_replicas = 3;
            }

            let receipt = select_recovery_action(*chunk_id, required_replicas, &healthy_replicas);

            if !matches!(receipt.action, RecoveryAction::NoAction) {
                scoped_actions.push(receipt);
            }
        }

        let scoped_count = scoped_actions.len() as u64;

        // Phase 3: Plan — check throttle
        self.phase = RecoveryPhase::Plan;
        if self.throttle.should_pause_recovery() {
            return Err(RecoveryLoopError::ThrottlePaused);
        }

        // Apply cascading failure guard — admit up to the aggregate recovery limit
        let max_load = self.cascading_guard.max_aggregate_recovery_load;
        let active = self.cascading_guard.total_active_batches();
        let capacity = if max_load == 0 {
            scoped_actions.len()
        } else {
            max_load.saturating_sub(active)
        };

        let admitted: Vec<RecoveryActionReceipt> =
            scoped_actions.into_iter().take(capacity).collect();

        // Phase 4: Execute
        self.phase = RecoveryPhase::Execute;

        for action in admitted {
            self.record_action(action);
        }

        // Remaining scoped but unadmitted chunks stay pending for next iteration
        self.progress.chunks_pending = scoped_count.saturating_sub(self.progress.chunks_scoped);

        // Phase 5: Verify
        self.phase = RecoveryPhase::Verify;
        self.progress.phase = RecoveryPhase::Verify;

        Ok(self.progress.clone())
    }

    /// Build a [`RecoveryPlan`] for a specific trigger by computing
    /// affected objects via locator-table reverse-lookup and scheduling
    /// rebuilds via the placement algorithm.
    #[must_use]
    pub fn plan_for_trigger(&self, trigger: RecoveryTrigger, created_at_ns: u64) -> RecoveryPlan {
        let mut plan = RecoveryPlan::new(trigger, created_at_ns);
        plan.scope(&self.health_tracker, 3);
        plan
    }

    /// Return a snapshot of the current recovery statistics.
    #[must_use]
    pub fn snapshot_stats(&self) -> RecoveryStats {
        self.stats.clone()
    }

    /// Return a mutable reference to the recovery stats for inline updates.
    pub fn stats_mut(&mut self) -> &mut RecoveryStats {
        &mut self.stats
    }

    pub fn add_node_budget(&mut self, budget: NodeRecoveryBudget) {
        self.node_budgets.insert(budget.node_id, budget);
    }

    /// Submit a recovery trigger for priority-scheduled dispatch.
    ///
    /// The trigger is classified into a priority tier and enqueued.
    /// Duplicate triggers (identical [`RecoveryTrigger`] values) are
    /// silently skipped to avoid redundant work items. Higher-priority
    /// items (`LossRebuild`) are dispatched before lower-priority ones
    /// (`CatchupRepair`, `SteadyReplication`).
    pub fn submit(&mut self, trigger: RecoveryTrigger, description: String) {
        // Skip duplicate triggers to avoid redundant work items.
        if self.dedup_seen.contains(&trigger) {
            return;
        }
        self.dedup_seen.insert(trigger.clone());
        let item = RecoveryWorkItem::new(trigger, description);
        self.pending_work.push(item);
    }

    /// Dispatch all pending recovery work items in priority order
    /// (highest first), returning the list of dispatched items.
    ///
    /// Clears the deduplication set so that the same triggers can be
    /// resubmitted in future recovery iterations. Each dispatched item
    /// is returned for the caller to wire to concrete action handlers
    /// (backfill, rebuild, alert).
    #[must_use]
    pub fn dispatch(&mut self) -> Vec<RecoveryWorkItem> {
        let mut dispatched: Vec<RecoveryWorkItem> = Vec::new();
        while let Some(item) = self.pending_work.pop() {
            dispatched.push(item);
        }
        self.dedup_seen.clear();
        dispatched
    }

    /// Return the number of pending work items without dispatching.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_work.len()
    }
    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn resume(&mut self) {
        self.paused = false;
    }

    pub fn record_action(&mut self, receipt: RecoveryActionReceipt) {
        self.progress.chunks_scoped = self.progress.chunks_scoped.saturating_add(1);
        *self
            .progress
            .priority_distribution
            .entry(receipt.priority)
            .or_insert(0) += 1;
        self.actions.push(receipt);
    }
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RecoveryLoopError {
    Paused,
    ThrottlePaused,
}

impl std::fmt::Display for RecoveryLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paused => write!(f, "recovery loop paused"),
            Self::ThrottlePaused => write!(f, "recovery throttle paused due to client latency"),
        }
    }
}
// ── Recovery work item ───────────────────────────────────────────────

/// A unit of recovery work queued by priority.
///
/// Higher-priority items (`LossRebuild`) are dispatched before
/// lower-priority ones (`CatchupRepair`, `SteadyReplication`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecoveryWorkItem {
    /// The event that triggered this work item.
    pub trigger: RecoveryTrigger,
    /// Classified priority tier.
    pub priority: RecoveryPriority,
    /// Human-readable description for logging and diagnostics.
    pub description: String,
}

impl RecoveryWorkItem {
    /// Create a new work item, classifying the trigger into its
    /// priority tier automatically.
    #[must_use]
    pub fn new(trigger: RecoveryTrigger, description: String) -> Self {
        let priority = classify_trigger(&trigger);
        Self {
            trigger,
            priority,
            description,
        }
    }
}

impl Ord for RecoveryWorkItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for RecoveryWorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::HealthClass;

    // ── Rebuild scope ───────────────────────────────────────────

    #[test]
    fn rebuild_scope_quorum_degraded() {
        let scope = compute_rebuild_scope(3, 1, 10);
        assert_eq!(scope.replicas_needed, 2);
        assert!(!scope.quorum_intact);
        assert_eq!(scope.priority, RecoveryPriority::LossRebuild);
    }

    #[test]
    fn rebuild_scope_quorum_intact() {
        let scope = compute_rebuild_scope(3, 2, 10);
        assert_eq!(scope.replicas_needed, 1);
        assert!(scope.quorum_intact);
        assert_eq!(scope.priority, RecoveryPriority::CatchupRepair);
    }

    #[test]
    fn rebuild_scope_fully_replicated() {
        let scope = compute_rebuild_scope(3, 3, 10);
        assert_eq!(scope.replicas_needed, 0);
        assert_eq!(scope.priority, RecoveryPriority::SteadyReplication);
    }

    // ── RecoveryThrottle ─────────────────────────────────────────

    #[test]
    fn throttle_admits_under_budget() {
        let t = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        assert!(t.admit_recovery_ticket(500));
    }

    #[test]
    fn throttle_denies_over_budget() {
        let t = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        assert!(!t.admit_recovery_ticket(1500));
    }

    #[test]
    fn throttle_scales_with_latency() {
        let mut t = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 2.0);
        // latency_ratio=1.0, scale=1/(1*2)=0.5, adjusted=500
        assert_eq!(t.compute_adjusted_budget(), 500);
        t.update_client_latency(20.0);
        // latency_ratio=2.0, scale=1/(2*2)=0.25, adjusted=250
        assert_eq!(t.compute_adjusted_budget(), 250);
    }

    #[test]
    fn throttle_pauses_at_3x() {
        let t = RecoveryThrottle::new(10, 1000, 30.1, 10.0, 1.0);
        assert!(t.should_pause_recovery());
    }

    #[test]
    fn throttle_consume_release() {
        let mut t = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        t.consume(500);
        assert_eq!(t.recovery_bandwidth_consumed, 500);
        t.release(200);
        assert_eq!(t.recovery_bandwidth_consumed, 300);
    }

    // ── CascadingFailureGuard ────────────────────────────────────

    #[test]
    fn guard_admits_first_flow() {
        let mut g = CascadingFailureGuard::new(10);
        let d = DomainId::new(1);
        g.set_domain_limit(d, 3);
        assert_eq!(g.admit_recovery_flow(d), AdmissionDecision::Admitted);
    }

    #[test]
    fn guard_denies_at_domain_limit() {
        let mut g = CascadingFailureGuard::new(10);
        let d = DomainId::new(1);
        g.set_domain_limit(d, 2);
        g.admit_recovery_flow(d);
        g.admit_recovery_flow(d);
        assert_eq!(
            g.admit_recovery_flow(d),
            AdmissionDecision::DomainAtCapacity {
                domain: d,
                limit: 2,
                active: 2
            }
        );
    }

    #[test]
    fn guard_denies_at_cluster_limit() {
        let mut g = CascadingFailureGuard::new(2);
        let d1 = DomainId::new(1);
        let d2 = DomainId::new(2);
        let d3 = DomainId::new(3);
        g.set_domain_limit(d1, 10);
        g.set_domain_limit(d2, 10);
        g.set_domain_limit(d3, 10);
        g.admit_recovery_flow(d1);
        g.admit_recovery_flow(d2);
        assert_eq!(
            g.admit_recovery_flow(d3),
            AdmissionDecision::ClusterAtRecoveryCapacity { total_active: 2 }
        );
    }

    #[test]
    fn guard_complete_releases_capacity() {
        let mut g = CascadingFailureGuard::new(10);
        let d = DomainId::new(1);
        g.set_domain_limit(d, 3);
        g.admit_recovery_flow(d);
        g.complete_recovery_flow(d);
        assert_eq!(g.total_active_batches(), 0);
    }

    // ── NodeRecoveryBudget ───────────────────────────────────────

    #[test]
    fn budget_has_capacity_initially() {
        let b = NodeRecoveryBudget::new(NodeId::new(1), 100, 100_000, 1024);
        assert!(b.has_capacity());
    }

    #[test]
    fn budget_exhausted() {
        let mut b = NodeRecoveryBudget::new(NodeId::new(1), 100, 100_000, 1024);
        b.reserve(100, 100_000, 1024);
        assert!(!b.has_capacity());
    }

    // ── Recovery action selection ────────────────────────────────

    #[test]
    fn select_all_healthy_no_action() {
        let healthy = vec![
            (NodeId::new(1), HealthClass::Healthy),
            (NodeId::new(2), HealthClass::Healthy),
            (NodeId::new(3), HealthClass::Healthy),
        ];
        let r = select_recovery_action(ChunkId::new(100), 3, &healthy);
        assert_eq!(r.action, RecoveryAction::NoAction);
        assert_eq!(r.priority, RecoveryPriority::SteadyReplication);
    }

    #[test]
    fn select_quorum_degraded_rebuild() {
        let healthy = vec![(NodeId::new(1), HealthClass::Healthy)];
        let r = select_recovery_action(ChunkId::new(100), 3, &healthy);
        assert!(matches!(r.action, RecoveryAction::ImmediateRebuild { .. }));
        assert_eq!(r.priority, RecoveryPriority::LossRebuild);
    }

    #[test]
    fn select_quorum_intact_backfill() {
        let healthy = vec![
            (NodeId::new(1), HealthClass::Healthy),
            (NodeId::new(2), HealthClass::Suspect),
        ];
        let r = select_recovery_action(ChunkId::new(100), 3, &healthy);
        assert!(matches!(r.action, RecoveryAction::Backfill { .. }));
        assert_eq!(r.priority, RecoveryPriority::CatchupRepair);
    }

    #[test]
    fn select_all_lost_data_loss() {
        let healthy: Vec<(NodeId, HealthClass)> = vec![];
        let r = select_recovery_action(ChunkId::new(100), 3, &healthy);
        assert!(matches!(r.action, RecoveryAction::DataLossAlert { .. }));
    }

    // ── Priority ordering ───────────────────────────────────────

    #[test]
    fn priorities_ordered_correctly() {
        assert!(RecoveryPriority::LossRebuild > RecoveryPriority::CatchupRepair);
        assert!(RecoveryPriority::CatchupRepair > RecoveryPriority::SteadyReplication);
    }

    // ── RecoveryLoop ─────────────────────────────────────────────

    #[test]
    fn loop_advances_through_phases() {
        let ht = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let rp = RebuildPlanner::new();
        let th = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        let mut l = RecoveryLoop::new(ht, rp, 10, th);
        let r = l.advance(1_000_000_000, 1).unwrap();
        assert_eq!(r.phase, RecoveryPhase::Verify);
        assert_eq!(l.iterations, 1);
    }

    #[test]
    fn loop_paused_errors() {
        let ht = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let rp = RebuildPlanner::new();
        let th = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        let mut l = RecoveryLoop::new(ht, rp, 10, th);
        l.pause();
        assert!(l.advance(1_000_000_000, 1).is_err());
    }

    #[test]
    fn loop_throttle_pause() {
        let ht = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let rp = RebuildPlanner::new();
        let th = RecoveryThrottle::new(10, 1000, 301.0, 100.0, 1.0);
        let mut l = RecoveryLoop::new(ht, rp, 10, th);
        assert!(l.advance(1_000_000_000, 1).is_err());
    }

    #[test]
    fn record_action_updates_progress() {
        let ht = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let rp = RebuildPlanner::new();
        let th = RecoveryThrottle::new(10, 1000, 10.0, 10.0, 1.0);
        let mut l = RecoveryLoop::new(ht, rp, 10, th);

        let action = RecoveryActionReceipt {
            chunk_id: ChunkId::new(1),
            action: RecoveryAction::ImmediateRebuild {
                source_node: NodeId::new(1),
                target_nodes: vec![NodeId::new(3)],
            },
            priority: RecoveryPriority::LossRebuild,
            phase: RecoveryPhase::Scope,
            epoch: 0,
            rationale: "test".to_string(),
        };

        l.record_action(action);
        assert_eq!(l.progress.chunks_scoped, 1);
        assert_eq!(
            l.progress.priority_distribution[&RecoveryPriority::LossRebuild],
            1
        );
    }

    #[test]
    fn progress_receipt_defaults() {
        let rpr = RecoveryProgressReceipt::new(5, RecoveryPhase::Detect);
        assert_eq!(rpr.epoch, 5);
        assert_eq!(rpr.chunks_pending, 0);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Crash recovery state machine — mount-time recovery orchestration
// ═══════════════════════════════════════════════════════════════════════

/// Persistent mount-state flag used by the daemon to detect whether the
/// previous shutdown was clean or the pool needs crash recovery.
///
/// Written at daemon start (before serving FUSE/ublk) and cleared on
/// clean shutdown.  On start, if the flag reads `Dirty`, the previous
/// shutdown was not clean and the crash recovery loop must run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MountState {
    /// Filesystem was cleanly unmounted; no recovery needed.
    Clean,
    /// Previous shutdown was not clean; intent-log replay is required.
    Dirty,
}

impl MountState {
    /// Serialize to the canonical wire format: a single byte.
    /// `Clean` → `0x00`, `Dirty` → `0x01`.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Clean => 0x00,
            Self::Dirty => 0x01,
        }
    }

    /// Deserialize from the canonical wire format.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Clean),
            0x01 => Some(Self::Dirty),
            _ => None,
        }
    }

    /// Persist this mount state to a file at `path`.
    ///
    /// The file is written atomically (write to temp + rename) so that
    /// a crash during the write does not leave a partial state on disk.
    pub fn write_to_path(self, path: &Path) -> Result<(), CrashRecoveryError> {
        use std::io::Write;
        let parent = path.parent().ok_or(CrashRecoveryError::InvalidPath)?;
        let mut tmp_path = parent.to_path_buf();
        tmp_path.push(".mount_state_tmp");
        {
            let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
                CrashRecoveryError::Io(format!("create mount-state tmp {:?}: {e}", &tmp_path))
            })?;
            f.write_all(&[self.to_byte()])
                .map_err(|e| CrashRecoveryError::Io(format!("write mount-state: {e}")))?;
            f.sync_all()
                .map_err(|e| CrashRecoveryError::Io(format!("fsync mount-state: {e}")))?;
        }
        std::fs::rename(&tmp_path, path).map_err(|e| {
            CrashRecoveryError::Io(format!(
                "rename mount-state {:?} -> {:?}: {e}",
                &tmp_path, path
            ))
        })?;
        // fsync the parent directory so the rename is durable.
        if let Some(parent) = path.parent() {
            let dir = std::fs::File::open(parent)
                .map_err(|e| CrashRecoveryError::Io(format!("open parent dir for fsync: {e}")))?;
            dir.sync_all()
                .map_err(|e| CrashRecoveryError::Io(format!("fsync parent dir: {e}")))?;
        }
        Ok(())
    }

    /// Read the persisted mount state from `path`.
    ///
    /// Returns `None` if the file does not exist (treated as a fresh
    /// filesystem → `Clean`).
    pub fn read_from_path(path: &Path) -> Result<Option<Self>, CrashRecoveryError> {
        use std::io::Read;
        match std::fs::File::open(path) {
            Ok(mut f) => {
                let mut buf = [0u8; 1];
                f.read_exact(&mut buf)
                    .map_err(|e| CrashRecoveryError::Io(format!("read mount-state: {e}")))?;
                match Self::from_byte(buf[0]) {
                    Some(s) => Ok(Some(s)),
                    None => Err(CrashRecoveryError::CorruptMountState),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CrashRecoveryError::Io(format!("open mount-state: {e}"))),
        }
    }
}

/// States of the crash recovery state machine.
///
/// ```text
/// Detection ──(dirty)──► Replay ──► Reconcile ──► Ready
///     │                                              ▲
///     └──────────────(clean)─────────────────────────┘
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRecoveryState {
    /// Initial state: detecting whether recovery is needed by reading
    /// the persistent mount-state flag.
    Detection,
    /// Replaying uncommitted intent-log segments via #4580's replay
    /// mechanism.
    Replay,
    /// Reconciling transaction group state from replayed records
    /// (updating the commit_group id, dirty tracker, and committed
    /// root pointer).
    Reconcile,
    /// Pool is ready for normal operation; the daemon may serve FUSE
    /// and ublk requests.
    Ready,
}

impl CrashRecoveryState {
    /// Human-readable label for logging and diagnostics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Replay => "replay",
            Self::Reconcile => "reconcile",
            Self::Ready => "ready",
        }
    }
}

/// Orchestrates mount-time crash recovery: detects unclean shutdown,
/// drives intent-log replay, reconciles commit_group state, and transitions the
/// pool to normal operation.
#[derive(Debug)]
pub struct CrashRecoveryLoop {
    /// Current state of the recovery machine.
    pub state: CrashRecoveryState,
    /// Detected (or persisted) mount-state flag.
    pub mount_state: MountState,
    /// Result of the intent-log scan and replay (populated during
    /// the Replay phase by [`run_replay`]).
    pub recovery_result: Option<RecoveryResult>,
    /// The BLAKE3-verified committed-root block read after successful
    /// journal replay (populated by [`read_committed_root`]).
    pub committed_root: Option<CommittedRootBlock>,
}

impl CrashRecoveryLoop {
    /// Create a new crash recovery loop, reading the mount-state flag
    /// from `path`.  If the file does not exist, the state is treated
    /// as `Clean` (fresh filesystem or first mount).
    ///
    /// After construction the loop is in `Detection` state; call
    /// [`Self::advance`] to transition.
    pub fn detect(path: &Path) -> Result<Self, CrashRecoveryError> {
        let mount_state = MountState::read_from_path(path)?.unwrap_or(MountState::Clean);
        Ok(Self {
            state: CrashRecoveryState::Detection,
            mount_state,
            recovery_result: None,
            committed_root: None,
        })
    }

    /// Create a recovery loop with an explicit mount-state (useful for
    /// testing without touching the filesystem).
    #[must_use]
    pub fn with_mount_state(mount_state: MountState) -> Self {
        Self {
            state: CrashRecoveryState::Detection,
            mount_state,
            recovery_result: None,
            committed_root: None,
        }
    }

    /// Advance the state machine based on the detected mount state.
    ///
    /// - If `mount_state` is `Dirty` and current state is `Detection`,
    ///   transitions to `Replay`.
    /// - If `mount_state` is `Clean` and current state is `Detection`,
    ///   transitions directly to `Ready` (no recovery needed).
    /// - `Replay` transitions to `Reconcile`.
    /// - `Reconcile` transitions to `Ready`.
    /// - `Ready` is the terminal state.
    ///
    /// Returns the new state.
    pub fn advance(&mut self) -> CrashRecoveryState {
        self.state = match self.state {
            CrashRecoveryState::Detection => match self.mount_state {
                MountState::Dirty => CrashRecoveryState::Replay,
                MountState::Clean => CrashRecoveryState::Ready,
            },
            CrashRecoveryState::Replay => CrashRecoveryState::Reconcile,
            CrashRecoveryState::Reconcile => CrashRecoveryState::Ready,
            CrashRecoveryState::Ready => CrashRecoveryState::Ready,
        };
        self.state
    }

    /// Run the intent-log replay phase by calling into
    /// [`CommitGroupRecovery::recover`].  On success the loop advances
    /// to `Reconcile` and stores the recovery result for reconciliation.
    ///
    /// # Panics
    ///
    /// Panics if called when the state machine is not in the `Replay`
    /// state.
    ///
    /// # Errors
    ///
    /// Returns `CrashRecoveryError::RecoveryFailed` if the underlying
    /// scan/replay fails.
    pub fn run_replay(
        &mut self,
        store: &LocalObjectStore,
    ) -> Result<CrashRecoveryState, CrashRecoveryError> {
        assert!(
            self.state == CrashRecoveryState::Replay,
            "run_replay called in state {:?}, expected Replay",
            self.state
        );
        let result = CommitGroupRecovery::recover(store)
            .map_err(|e| CrashRecoveryError::RecoveryFailed(e.to_string()))?;
        self.recovery_result = Some(result);
        self.state = CrashRecoveryState::Reconcile;
        Ok(self.state)
    }

    /// Run namespace intent-log replay for unapplied intent-log segments.
    ///
    /// Replays BLAKE3-verified namespace intent-log records (create, unlink,
    /// rename, mkdir, rmdir, symlink, truncate, setattr, etc.) through the
    /// provided [`VfsEngine`] to bring the namespace to a consistent state
    /// after a crash. This is the namespace counterpart to [`run_replay`],
    /// which handles commit_group journal (data-path) recovery.
    ///
    /// Uses [`crate::replay::ReplayEngine`] with [`crate::replay::VfsReplayHandler`]
    /// for per-segment iteration, LSN filtering, and dispatch orchestration.
    ///
    /// Must be called during the `Replay` state, before [`run_replay`] (which
    /// advances to `Reconcile`). If the intent_log_dir does not exist or is
    /// empty, the method succeeds with no replay.
    ///
    /// # Panics
    ///
    /// Panics if called when the state machine is not in the `Replay` state.
    ///
    /// # Errors
    ///
    /// Returns `CrashRecoveryError::RecoveryFailed` if replay encounters
    /// a non-recoverable error (integrity failure, VfsEngine dispatch failure,
    /// or I/O error reading segments).
    pub fn run_namespace_replay(
        &mut self,
        intent_log_dir: &Path,
        vfs: &dyn VfsEngine,
    ) -> Result<(), CrashRecoveryError> {
        assert!(
            self.state == CrashRecoveryState::Replay,
            "run_namespace_replay called in state {:?}, expected Replay",
            self.state
        );

        let applied_txg = self
            .recovery_result
            .as_ref()
            .map(|r| r.highest_committed_commit_group.0)
            .unwrap_or(0);

        let mut engine = crate::replay::ReplayEngine::new(applied_txg);
        engine
            .replay_intent_log(intent_log_dir, vfs)
            .map_err(|e| CrashRecoveryError::RecoveryFailed(e.to_string()))?;

        Ok(())
    }

    /// Read and verify the committed-root block from stable storage
    /// using the highest committed commit-group ID discovered during
    /// journal replay.
    ///
    /// Must be called after [`run_replay`] when `recovery_result` is
    /// populated. On success, the verified [`CommittedRootBlock`] is
    /// stored in [`self.committed_root`] and its five root handles
    /// (namespace, inode-table, extent-map, intent-log-tail) are
    /// available for bootstrapping the in-memory filesystem state.
    ///
    /// If the highest commit-group ID is NIL (fresh filesystem), this
    /// method returns `Ok(None)` and no root block is stored.
    ///
    /// # Errors
    ///
    /// Returns `CrashRecoveryError::RecoveryFailed` if no recovery
    /// result is available (call [`run_replay`] first) or if the
    /// underlying read fails (I/O error or BLAKE3 verification
    /// failure).
    pub fn read_committed_root(
        &mut self,
        store: &LocalObjectStore,
    ) -> Result<Option<CommittedRootBlock>, CrashRecoveryError> {
        let result = self.recovery_result.as_ref().ok_or_else(|| {
            CrashRecoveryError::RecoveryFailed(
                "no recovery result — call run_replay first".to_string(),
            )
        })?;
        let cgid = result.highest_committed_commit_group;
        if !cgid.is_valid() {
            return Ok(None);
        }
        let block = CommitGroupReader::require_root_block(store, cgid)
            .map_err(CrashRecoveryError::RecoveryFailed)?;
        self.committed_root = Some(block.clone());
        Ok(Some(block))
    }

    /// Finalize reconciliation of replayed commit_groups and transition
    /// to `Ready`.  After this call the pool is open for normal
    /// operation.
    ///
    /// # Panics
    ///
    /// Panics if called when the state machine is not in the
    /// `Reconcile` state.
    pub fn reconcile_and_finish(&mut self) -> CrashRecoveryState {
        assert!(
            self.state == CrashRecoveryState::Reconcile,
            "reconcile_and_finish called in state {:?}, expected Reconcile",
            self.state
        );
        self.state = CrashRecoveryState::Ready;
        self.state
    }

    /// Mark the mount state as clean and persist it to `path`.
    ///
    /// Called after successful recovery (`Ready` state) or after a
    /// clean shutdown to signal that the next start does not need
    /// recovery.
    pub fn mark_clean(&mut self, path: &Path) -> Result<(), CrashRecoveryError> {
        self.mount_state = MountState::Clean;
        MountState::Clean.write_to_path(path)
    }

    /// Returns `true` if the state machine has reached the terminal
    /// `Ready` state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == CrashRecoveryState::Ready
    }

    /// Returns `true` if crash recovery is needed (mount state is
    /// `Dirty`).
    #[must_use]
    pub fn recovery_needed(&self) -> bool {
        self.mount_state == MountState::Dirty
    }
}

/// Errors produced by the crash recovery loop.
#[derive(Debug)]
pub enum CrashRecoveryError {
    /// An I/O operation on the mount-state flag failed.
    Io(String),
    /// The mount-state file contained an unrecognized byte value.
    CorruptMountState,
    /// The provided path has no parent directory.
    InvalidPath,
    /// Intent-log scan or replay failed during recovery.
    RecoveryFailed(String),
}

impl std::fmt::Display for CrashRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "crash-recovery I/O error: {msg}"),
            Self::CorruptMountState => {
                write!(f, "crash-recovery mount-state file is corrupt")
            }
            Self::InvalidPath => {
                write!(f, "crash-recovery mount-state path has no parent directory")
            }
            Self::RecoveryFailed(msg) => {
                write!(f, "crash-recovery failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CrashRecoveryError {}

// ═══════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
// Trigger classification and priority-queue dispatch tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod trigger_tests {
    use super::*;

    #[test]
    fn node_failure_classifies_as_loss_rebuild() {
        let trigger = RecoveryTrigger::NodeFailure {
            node_id: NodeId::new(1),
        };
        assert_eq!(classify_trigger(&trigger), RecoveryPriority::LossRebuild);
    }

    #[test]
    fn device_failure_classifies_as_catchup_repair() {
        let trigger = RecoveryTrigger::DeviceFailure {
            node_id: NodeId::new(2),
            device_index: 0,
        };
        assert_eq!(classify_trigger(&trigger), RecoveryPriority::CatchupRepair);
    }

    #[test]
    fn corruption_detected_classifies_as_loss_rebuild() {
        let trigger = RecoveryTrigger::CorruptionDetected {
            source: "scrub".into(),
            segment_id: 42,
        };
        assert_eq!(classify_trigger(&trigger), RecoveryPriority::LossRebuild);
    }

    #[test]
    fn work_item_ordering_loss_rebuild_before_catchup() {
        let critical = RecoveryWorkItem::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "node down".into(),
        );
        let high = RecoveryWorkItem::new(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "device failed".into(),
        );
        assert!(critical > high);
        assert!(high < critical);
    }

    #[test]
    fn work_item_ordering_catchup_before_critical() {
        let high = RecoveryWorkItem::new(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "device failed".into(),
        );
        let critical = RecoveryWorkItem::new(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 1,
            },
            "corruption".into(),
        );
        assert!(critical > high);
    }

    #[test]
    fn work_item_equal_priority_triggers_are_equal() {
        let a = RecoveryWorkItem::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "first".into(),
        );
        let b = RecoveryWorkItem::new(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 99,
            },
            "second".into(),
        );
        assert_eq!(a.priority, b.priority);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn submit_enqueues_work_item() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        assert_eq!(loop_.pending_count(), 0);
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(3),
            },
            "test node failure".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
    }

    #[test]
    fn dispatch_returns_items_in_priority_order() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "device failure".into(),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(2),
            },
            "node failure".into(),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(3),
                device_index: 1,
            },
            "another device failure".into(),
        );
        let dispatched = loop_.dispatch();
        assert_eq!(dispatched.len(), 3);
        assert_eq!(dispatched[0].priority, RecoveryPriority::LossRebuild);
        assert_eq!(dispatched[1].priority, RecoveryPriority::CatchupRepair);
        assert_eq!(dispatched[2].priority, RecoveryPriority::CatchupRepair);
        assert_eq!(loop_.pending_count(), 0);
    }

    #[test]
    fn dispatch_on_empty_queue_returns_empty() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        let dispatched = loop_.dispatch();
        assert!(dispatched.is_empty());
    }

    #[test]
    fn multiple_submits_then_dispatch_drains_all() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        for i in 0..5 {
            loop_.submit(
                RecoveryTrigger::DeviceFailure {
                    node_id: NodeId::new(i as u64),
                    device_index: 0,
                },
                format!("device {i}"),
            );
        }
        assert_eq!(loop_.pending_count(), 5);
        let dispatched = loop_.dispatch();
        assert_eq!(dispatched.len(), 5);
        assert_eq!(loop_.pending_count(), 0);
    }

    #[test]
    fn trigger_debug_and_clone() {
        let t = RecoveryTrigger::NodeFailure {
            node_id: NodeId::new(7),
        };
        let t3 = t.clone();
        assert_eq!(
            t3,
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(7),
            }
        );
        assert_ne!(
            t3,
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(7),
                device_index: 0,
            }
        );
        let _ = format!("{t3:?}");
    }

    #[test]
    fn corruption_detected_equality() {
        let a = RecoveryTrigger::CorruptionDetected {
            source: "scrub".into(),
            segment_id: 10,
        };
        let b = RecoveryTrigger::CorruptionDetected {
            source: "scrub".into(),
            segment_id: 10,
        };
        let c = RecoveryTrigger::CorruptionDetected {
            source: "scrub".into(),
            segment_id: 11,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn classify_trigger_covers_all_variants() {
        let triggers = [
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(0),
            },
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(0),
                device_index: 0,
            },
            RecoveryTrigger::CorruptionDetected {
                source: String::new(),
                segment_id: 0,
            },
        ];
        for t in &triggers {
            let p = classify_trigger(t);
            assert!(matches!(
                p,
                RecoveryPriority::LossRebuild | RecoveryPriority::CatchupRepair
            ));
        }
    }

    #[test]
    fn submit_does_not_auto_dispatch() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "test".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(2),
                device_index: 0,
            },
            "test2".into(),
        );
        assert_eq!(loop_.pending_count(), 2);
    }

    // ── Deduplication ────────────────────────────────────────

    #[test]
    fn submit_deduplicates_same_node_failure() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(7),
            },
            "first alert".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(7),
            },
            "duplicate alert".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
    }

    #[test]
    fn submit_allows_different_node_failures() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(3),
            },
            "node 3".into(),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(5),
            },
            "node 5".into(),
        );
        assert_eq!(loop_.pending_count(), 2);
    }

    #[test]
    fn submit_deduplicates_same_device_failure() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "sda failed".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "sda still failed".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
    }

    #[test]
    fn submit_allows_different_devices_on_same_node() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "sda".into(),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 1,
            },
            "sdb".into(),
        );
        assert_eq!(loop_.pending_count(), 2);
    }

    #[test]
    fn submit_deduplicates_same_corruption_segment() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 42,
            },
            "segment 42 corrupt".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
        loop_.submit(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 42,
            },
            "still corrupt".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
    }

    #[test]
    fn submit_allows_different_corruption_segments() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 10,
            },
            "seg 10".into(),
        );
        loop_.submit(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 20,
            },
            "seg 20".into(),
        );
        assert_eq!(loop_.pending_count(), 2);
    }

    #[test]
    fn dispatch_clears_dedup_set() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "node down".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
        let _ = loop_.dispatch();
        assert_eq!(loop_.pending_count(), 0);
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "node down again".into(),
        );
        assert_eq!(loop_.pending_count(), 1);
    }

    #[test]
    fn cross_variant_triggers_do_not_dedup() {
        let mut loop_ = RecoveryLoop::new(
            ReplicaHealthTracker::new(1024, 1024 * 1024),
            RebuildPlanner::new(),
            16,
            RecoveryThrottle::new(8, 1_000_000_000, 1.0, 1.0, 0.5),
        );
        loop_.submit(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            "node".into(),
        );
        loop_.submit(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(1),
                device_index: 0,
            },
            "device".into(),
        );
        loop_.submit(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 99,
            },
            "corruption".into(),
        );
        assert_eq!(loop_.pending_count(), 3);
    }

    // ── RecoveryAction::priority() ────────────────────────────────

    #[test]
    fn recovery_action_priority_no_action_is_steady() {
        assert_eq!(
            RecoveryAction::NoAction.priority(),
            RecoveryPriority::SteadyReplication
        );
    }

    #[test]
    fn recovery_action_priority_backfill_is_catchup() {
        assert_eq!(
            RecoveryAction::Backfill {
                source_nodes: vec![],
                target_node: NodeId::new(0),
            }
            .priority(),
            RecoveryPriority::CatchupRepair
        );
    }

    #[test]
    fn recovery_action_priority_immediate_rebuild_is_loss_rebuild() {
        assert_eq!(
            RecoveryAction::ImmediateRebuild {
                source_node: NodeId::new(0),
                target_nodes: vec![],
            }
            .priority(),
            RecoveryPriority::LossRebuild
        );
    }

    #[test]
    fn recovery_action_priority_data_loss_alert_is_loss_rebuild() {
        assert_eq!(
            RecoveryAction::DataLossAlert {
                reason: "gone".into(),
            }
            .priority(),
            RecoveryPriority::LossRebuild
        );
    }
}
// Crash recovery tests
// ═══════════════════════════════════════════════════════════════════════

// RecoveryPlan and RecoveryStats tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod recovery_plan_tests {
    use super::*;

    // ── RecoveryPlan construction ─────────────────────────────────

    #[test]
    fn plan_has_correct_priority_from_trigger() {
        let plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            1000,
        );
        assert_eq!(plan.priority, RecoveryPriority::LossRebuild);
    }

    #[test]
    fn plan_device_failure_has_catchup_priority() {
        let plan = RecoveryPlan::new(
            RecoveryTrigger::DeviceFailure {
                node_id: NodeId::new(2),
                device_index: 0,
            },
            2000,
        );
        assert_eq!(plan.priority, RecoveryPriority::CatchupRepair);
    }

    #[test]
    fn plan_corruption_has_lossrebuild_priority() {
        let plan = RecoveryPlan::new(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 42,
            },
            3000,
        );
        assert_eq!(plan.priority, RecoveryPriority::LossRebuild);
    }

    #[test]
    fn plan_created_at_ns_is_preserved() {
        let plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(3),
            },
            123456789,
        );
        assert_eq!(plan.created_at_ns, 123456789);
    }

    #[test]
    fn empty_plan_has_zero_affected_count() {
        let plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(4),
            },
            0,
        );
        assert_eq!(plan.affected_count(), 0);
    }

    // ── RecoveryPlan::scope ────────────────────────────────────────

    #[test]
    fn scope_populates_affected_chunks_and_actions() {
        let mut health = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(100);
        health.register_chunk(chunk, NodeId::new(1), 1, 1000);
        health.mark_degraded(chunk, NodeId::new(1), 2000, 0, 1);

        let mut plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            0,
        );
        plan.scope(&health, 3);

        assert!(!plan.affected_chunks.is_empty());
        assert!(!plan.actions.is_empty());
        // With only 1 degraded replica out of 3 required, action should
        // be a DataLossAlert (0 healthy)
        assert!(matches!(
            plan.actions[0].action,
            RecoveryAction::DataLossAlert { .. }
        ));
    }

    #[test]
    fn scope_with_healthy_replicas_suggests_backfill() {
        let mut health = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(200);
        // Register 3 replicas: 2 healthy + 1 degraded (quorum intact, below full)
        health.register_chunk(chunk, NodeId::new(1), 1, 1000);
        health.register_chunk(chunk, NodeId::new(2), 2, 1000);
        health.register_chunk(chunk, NodeId::new(3), 3, 1000);
        health.mark_healthy(chunk, NodeId::new(1), 1, 2000);
        health.mark_healthy(chunk, NodeId::new(2), 2, 2000);
        health.mark_degraded(chunk, NodeId::new(3), 3000, 0, 1);

        let mut plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(3),
            },
            0,
        );
        plan.scope(&health, 3);

        assert!(!plan.affected_chunks.is_empty());
        assert!(!plan.actions.is_empty());
        // 2 healthy out of 3 → quorum intact → Backfill
        assert!(matches!(
            plan.actions[0].action,
            RecoveryAction::Backfill { .. }
        ));
    }

    #[test]
    fn scope_with_all_healthy_no_action() {
        let mut health = ReplicaHealthTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(300);
        health.register_chunk(chunk, NodeId::new(1), 1, 1000);
        health.register_chunk(chunk, NodeId::new(2), 2, 1000);
        health.register_chunk(chunk, NodeId::new(3), 3, 1000);
        health.mark_healthy(chunk, NodeId::new(1), 1, 2000);
        health.mark_healthy(chunk, NodeId::new(2), 2, 2000);
        health.mark_healthy(chunk, NodeId::new(3), 3, 2000);

        let mut plan = RecoveryPlan::new(
            RecoveryTrigger::CorruptionDetected {
                source: "scrub".into(),
                segment_id: 99,
            },
            0,
        );
        plan.scope(&health, 3);

        // All healthy means no degraded chunks → empty scope
        assert!(plan.affected_chunks.is_empty());
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn estimated_bytes_scales_with_avg_chunk_size() {
        let mut plan = RecoveryPlan::new(
            RecoveryTrigger::NodeFailure {
                node_id: NodeId::new(1),
            },
            0,
        );
        // Manually set affected chunks for testing (bypass scope)
        plan.affected_chunks = vec![ChunkId::new(1), ChunkId::new(2), ChunkId::new(3)];
        assert_eq!(plan.estimated_bytes(4096), 3 * 4096);
        assert_eq!(plan.estimated_bytes(0), 0);
    }
}

#[cfg(test)]
mod recovery_stats_tests {
    use super::*;

    #[test]
    fn new_stats_are_zeroed() {
        let stats = RecoveryStats::new();
        assert_eq!(stats.triggers_active, 0);
        assert_eq!(stats.objects_recovering, 0);
        assert_eq!(stats.objects_recovered, 0);
        assert_eq!(stats.bytes_recovering, 0);
        assert!(stats.estimated_completion_secs.is_infinite());
        assert!(stats.is_idle());
    }

    #[test]
    fn default_stats_are_zeroed() {
        let stats = RecoveryStats::default();
        assert_eq!(stats.triggers_active, 0);
        assert_eq!(stats.objects_recovering, 0);
        assert!(stats.is_idle());
    }

    #[test]
    fn start_recovery_increments_counters() {
        let mut stats = RecoveryStats::new();
        stats.start_recovery(2, 100, 409600);
        assert_eq!(stats.triggers_active, 2);
        assert_eq!(stats.objects_recovering, 100);
        assert_eq!(stats.bytes_recovering, 409600);
        assert!(!stats.is_idle());
    }

    #[test]
    fn record_recovered_decrements_in_flight() {
        let mut stats = RecoveryStats::new();
        stats.start_recovery(1, 50, 200000);
        stats.record_recovered(30, 120000);
        assert_eq!(stats.objects_recovering, 20);
        assert_eq!(stats.objects_recovered, 30);
        assert_eq!(stats.bytes_recovering, 80000);
        assert!(!stats.is_idle());
    }

    #[test]
    fn complete_trigger_decrements_active() {
        let mut stats = RecoveryStats::new();
        stats.start_recovery(3, 10, 1000);
        stats.complete_trigger();
        assert_eq!(stats.triggers_active, 2);
        stats.complete_trigger();
        stats.complete_trigger();
        assert_eq!(stats.triggers_active, 0);
        // objects_recovering still >0, so not idle
        assert!(!stats.is_idle());
    }

    #[test]
    fn full_recovery_cycle_reaches_idle() {
        let mut stats = RecoveryStats::new();
        stats.start_recovery(1, 10, 10000);
        stats.record_recovered(10, 10000);
        stats.complete_trigger();
        assert!(stats.is_idle());
        assert_eq!(stats.triggers_active, 0);
        assert_eq!(stats.objects_recovering, 0);
        assert_eq!(stats.objects_recovered, 10);
        assert_eq!(stats.bytes_recovering, 0);
    }

    #[test]
    fn estimated_completion_can_be_set() {
        let mut stats = RecoveryStats::new();
        stats.set_estimated_completion(42.5);
        assert!((stats.estimated_completion_secs - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn is_idle_returns_true_when_no_work() {
        let stats = RecoveryStats::new();
        assert!(stats.is_idle());

        let mut active = RecoveryStats::new();
        active.start_recovery(0, 1, 1);
        assert!(!active.is_idle());
    }
}

#[cfg(test)]
mod crash_recovery_tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_commit_group::CommitGroupId;

    // ── MountState serialization ─────────────────────────────────────

    #[test]
    fn mount_state_byte_roundtrip() {
        for state in [MountState::Clean, MountState::Dirty] {
            let byte = state.to_byte();
            let decoded = MountState::from_byte(byte);
            assert_eq!(decoded, Some(state));
        }
    }

    #[test]
    fn mount_state_from_byte_rejects_invalid() {
        assert_eq!(MountState::from_byte(0xFF), None);
        assert_eq!(MountState::from_byte(0x02), None);
    }

    #[test]
    fn mount_state_persist_and_read() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("mount_state");

        // Write dirty, read back
        MountState::Dirty.write_to_path(&path).expect("write dirty");
        let read = MountState::read_from_path(&path).expect("read back");
        assert_eq!(read, Some(MountState::Dirty));

        // Overwrite with clean, read back
        MountState::Clean.write_to_path(&path).expect("write clean");
        let read = MountState::read_from_path(&path).expect("read back");
        assert_eq!(read, Some(MountState::Clean));
    }

    #[test]
    fn mount_state_read_missing_file_is_none() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("nonexistent");
        let read = MountState::read_from_path(&path).expect("read missing");
        assert_eq!(read, None);
    }

    // ── Detection → Replay (dirty) ───────────────────────────────────

    #[test]
    fn detection_dirty_transitions_to_replay() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        assert_eq!(loop_.state, CrashRecoveryState::Detection);
        assert!(loop_.recovery_needed());
        assert!(!loop_.is_ready());

        let new_state = loop_.advance();
        assert_eq!(new_state, CrashRecoveryState::Replay);
        assert_eq!(loop_.state, CrashRecoveryState::Replay);
        assert!(loop_.recovery_needed());
    }

    #[test]
    fn detection_dirty_full_path_to_ready() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        assert_eq!(loop_.advance(), CrashRecoveryState::Replay);
        assert_eq!(loop_.advance(), CrashRecoveryState::Reconcile);
        assert_eq!(loop_.advance(), CrashRecoveryState::Ready);
        assert!(loop_.is_ready());
        // Ready is terminal
        assert_eq!(loop_.advance(), CrashRecoveryState::Ready);
    }

    // ── Detection → Ready (clean) ────────────────────────────────────

    #[test]
    fn detection_clean_transitions_directly_to_ready() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Clean);
        assert_eq!(loop_.state, CrashRecoveryState::Detection);
        assert!(!loop_.recovery_needed());
        assert!(!loop_.is_ready());

        let new_state = loop_.advance();
        assert_eq!(new_state, CrashRecoveryState::Ready);
        assert_eq!(loop_.state, CrashRecoveryState::Ready);
        assert!(loop_.is_ready());
    }

    #[test]
    fn detection_clean_skips_replay_and_reconcile() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Clean);
        // One advance takes it directly to Ready
        loop_.advance();
        assert_eq!(loop_.state, CrashRecoveryState::Ready);
        assert!(!loop_.recovery_needed());
    }

    // ── detect from filesystem ───────────────────────────────────────

    #[test]
    fn detect_dirty_from_file() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("mount_state");
        MountState::Dirty.write_to_path(&path).expect("write");

        let loop_ = CrashRecoveryLoop::detect(&path).expect("detect");
        assert_eq!(loop_.mount_state, MountState::Dirty);
        assert_eq!(loop_.state, CrashRecoveryState::Detection);
    }

    #[test]
    fn detect_clean_from_file() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("mount_state");
        MountState::Clean.write_to_path(&path).expect("write");

        let loop_ = CrashRecoveryLoop::detect(&path).expect("detect");
        assert_eq!(loop_.mount_state, MountState::Clean);
        assert_eq!(loop_.state, CrashRecoveryState::Detection);
    }

    #[test]
    fn detect_missing_file_defaults_clean() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("nonexistent_mount_state");

        let loop_ = CrashRecoveryLoop::detect(&path).expect("detect");
        assert_eq!(loop_.mount_state, MountState::Clean);
    }

    // ── mark_clean ───────────────────────────────────────────────────

    #[test]
    fn mark_clean_persists_and_updates_state() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("mount_state");

        // Start dirty, advance through recovery, mark clean at end
        MountState::Dirty.write_to_path(&path).expect("write");
        let mut loop_ = CrashRecoveryLoop::detect(&path).expect("detect");
        assert!(loop_.recovery_needed());

        // Simulate full recovery path
        loop_.advance(); // Detection → Replay
        loop_.advance(); // Replay → Reconcile
        loop_.advance(); // Reconcile → Ready

        loop_.mark_clean(&path).expect("mark_clean");
        assert_eq!(loop_.mount_state, MountState::Clean);
        assert!(!loop_.recovery_needed());

        // Verify persistence
        let read = MountState::read_from_path(&path).expect("read");
        assert_eq!(read, Some(MountState::Clean));
    }

    // ── CrashRecoveryState labels ────────────────────────────────────

    #[test]
    fn state_labels_are_distinct() {
        let labels: Vec<&str> = [
            CrashRecoveryState::Detection,
            CrashRecoveryState::Replay,
            CrashRecoveryState::Reconcile,
            CrashRecoveryState::Ready,
        ]
        .iter()
        .map(|s| s.label())
        .collect();
        // All labels must be unique
        let mut unique = labels.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), labels.len());
    }

    // ── CrashRecoveryError Display ───────────────────────────────────

    #[test]
    fn error_display_is_human_readable() {
        let io = CrashRecoveryError::Io("test error".to_string());
        assert!(format!("{io}").contains("test error"));

        let corrupt = CrashRecoveryError::CorruptMountState;
        assert!(format!("{corrupt}").contains("corrupt"));

        let invalid = CrashRecoveryError::InvalidPath;
        assert!(format!("{invalid}").contains("parent directory"));
    }

    // ── RecoveryFailed Display ───────────────────────────────────────

    #[test]
    fn recovery_failed_error_is_human_readable() {
        let err = CrashRecoveryError::RecoveryFailed("something broke".to_string());
        let s = format!("{err}");
        assert!(s.contains("recovery failed"));
        assert!(s.contains("something broke"));
    }

    // ── Store-backed replay tests ────────────────────────────────────

    #[test]
    fn run_replay_empty_store_succeeds() {
        let dir = TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");

        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        assert_eq!(loop_.advance(), CrashRecoveryState::Replay);

        let state = loop_.run_replay(&store).expect("run_replay");
        assert_eq!(state, CrashRecoveryState::Reconcile);

        let result = loop_.recovery_result.as_ref().unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId::NIL);
        assert_eq!(result.next_commit_group_id, CommitGroupId::FIRST);
        assert!(result.torn_commit_groups.is_empty());
        assert!(result.replayed_commit_groups.is_empty());
    }

    #[test]
    fn reconcile_after_replay_transitions_to_ready() {
        let dir = TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");

        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        loop_.advance();
        loop_.run_replay(&store).expect("run_replay");

        let state = loop_.reconcile_and_finish();
        assert_eq!(state, CrashRecoveryState::Ready);
        assert!(loop_.is_ready());
    }

    #[test]
    fn full_recovery_cycle_dirty_to_ready_with_store() {
        let dir = TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");

        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        // Detection -> Replay
        assert_eq!(loop_.advance(), CrashRecoveryState::Replay);
        // Replay -> Reconcile (via run_replay on empty store)
        assert_eq!(
            loop_.run_replay(&store).expect("run_replay"),
            CrashRecoveryState::Reconcile
        );
        // Reconcile -> Ready
        assert_eq!(loop_.reconcile_and_finish(), CrashRecoveryState::Ready);
        assert!(loop_.is_ready());
        assert!(loop_.recovery_result.is_some());
    }

    #[test]
    fn clean_detection_skips_replay_and_store() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Clean);
        assert_eq!(loop_.advance(), CrashRecoveryState::Ready);
        assert!(loop_.is_ready());
        assert!(loop_.recovery_result.is_none());
    }

    #[test]
    #[should_panic(expected = "run_replay called in state Ready")]
    fn run_replay_panics_when_not_in_replay_state() {
        let dir = TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Clean);
        loop_.advance(); // Clean -> Ready
        let _ = loop_.run_replay(&store);
    }

    #[test]
    #[should_panic(expected = "reconcile_and_finish called in state Replay")]
    fn reconcile_panics_when_not_in_reconcile_state() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        loop_.advance(); // Dirty -> Replay
        loop_.reconcile_and_finish(); // should panic
    }

    #[test]
    fn recovery_result_is_none_until_replay_runs() {
        let mut loop_ = CrashRecoveryLoop::with_mount_state(MountState::Dirty);
        assert!(loop_.recovery_result.is_none());
        loop_.advance(); // Detection -> Replay
        assert!(loop_.recovery_result.is_none());
        // (can't run replay without a store, but field stays None)
    }
}
pub mod replay;

#[cfg(test)]
mod recovery_policy_tests {
    use super::*;

    #[test]
    fn default_is_replay_only() {
        assert_eq!(RecoveryPolicy::default(), RecoveryPolicy::ReplayOnly);
    }

    #[test]
    fn read_only_allows_no_mutation() {
        let p = RecoveryPolicy::ReadOnly;
        assert!(!p.allows_replay());
        assert!(!p.allows_repair_writeback());
        assert!(!p.allows_any_mutation());
    }

    #[test]
    fn replay_only_allows_replay_not_repair() {
        let p = RecoveryPolicy::ReplayOnly;
        assert!(p.allows_replay());
        assert!(!p.allows_repair_writeback());
        assert!(p.allows_any_mutation());
    }

    #[test]
    fn repair_writeback_allows_everything() {
        let p = RecoveryPolicy::RepairWriteback;
        assert!(p.allows_replay());
        assert!(p.allows_repair_writeback());
        assert!(p.allows_any_mutation());
    }

    #[test]
    fn labels_are_distinct() {
        let labels: Vec<&str> = [
            RecoveryPolicy::ReadOnly,
            RecoveryPolicy::ReplayOnly,
            RecoveryPolicy::RepairWriteback,
        ]
        .iter()
        .map(|p| p.label())
        .collect();
        let mut unique = labels.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn debug_format_is_human_readable() {
        let expected = [
            (RecoveryPolicy::ReadOnly, "ReadOnly"),
            (RecoveryPolicy::ReplayOnly, "ReplayOnly"),
            (RecoveryPolicy::RepairWriteback, "RepairWriteback"),
        ];
        for (policy, variant_name) in expected {
            let s = format!("{policy:?}");
            assert!(!s.is_empty());
            assert!(
                s.contains(variant_name),
                "{s} does not contain {variant_name}"
            );
        }
    }
}
