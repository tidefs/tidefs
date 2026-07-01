// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rebuild planner: loss/suspect event rebuild flow orchestration for data_copy_4.
//!
//! The rebuild planner is the recovery-side counterpart of the relocation
//! planner. While relocation moves data for policy, tiering, or reclaim
//! reasons, rebuild restores lost replication after node failures, disk
//! failures, corruption, or administrative decommission.
//!
//! # Rebuild flow state machine (6 states)
//!
//! ```text
//! Open → Planning → Transferring → Verifying → Restored
//! ```
//!
//! Exception paths: any state → BlockedNoSource, BlockedNoTarget,
//! BlockedNoCapacity, Cancelled.
//!
//! Core algorithms:
//! - `open_rebuild_flow_from_loss_event()` — derive rebuild scope from
//!   a loss/suspect event, freeze loss scope and degraded class
//! - `schedule_rebuild_batches_from_witness_sets()` — choose source
//!   bundles and batch order from available witness members
//! - `advance_rebuild_flow_state()` — state machine transition logic
//! - `detect_stale_chunks_for_backfill()` — detect lagged chunks needing catchup
//! - `detect_capacity_skew_for_rebalance()` — detect utilization skew needing rebalancing
//!
//! # Comparison to ZFS / Ceph
//!
//! - ZFS: no native distributed rebuild — resilver is local disk-to-disk
//!   within a single pool; no failure-domain-aware source selection
//! - Ceph: backfill is PG-scoped, triggered by OSD health changes; rebuild
//!   source selection is topology-based but not receipt-backed
//! - TideFS: loss-event-scoped rebuild with receipt-backed source
//!   verification, witness-set-driven batch scheduling, degradation-class
//!   propagation, and explicit no-source/no-target refusal

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use tidefs_durability_layout::{DurabilityLayoutV1, DurabilityPolicy};
use tidefs_membership_epoch::{HealthClass, MemberId};
use tidefs_replica_health::{BytesBehind, ChunkId, NodeId, ReplicaLagStateRecord};
use tidefs_replication_model::{
    DegradedVisibilityClass, FlowScopeSelector, LossEventClass, RebuildBatchRecord,
    RebuildDegradedClass, RebuildFlowRecord, RebuildFlowState, ReplicatedReceiptId,
};
use tidefs_transport::{self, ObjectPlacementEntry, PerNodeObjectDelta};

pub mod plan;
pub mod planner;

/// Gate constant for the data_copy_4 rebuild planner.
pub const REBUILD_PLANNER_GATE_DATA_COPY_4: &str =
    "data_copy_4 rebuild planner covers loss-event flow open, witness-set batch scheduling, and state machine transitions";

/// Gate constant for OW-305 backfill/rebalance.
pub const REBUILD_PLANNER_GATE_OW_305_BACKFILL_REBALANCE: &str =
    "OW-305 backfill lag detection and capacity rebalance skew detection";

// ── Loss event ───────────────────────────────────────────────────────

/// A loss event — the trigger that opens a rebuild flow.
///
/// Loss events classify what was lost, how severely, and what scope
/// of data needs to be rebuilt.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct LossEvent {
    /// Unique event identifier.
    pub loss_event_id: u64,
    /// Class of loss (node failure, disk failure, corruption, etc.).
    pub loss_class: LossEventClass,
    /// Severity of the degradation caused by this event.
    pub degraded_class: RebuildDegradedClass,
    /// Scope selector for which subjects/domains/cohort are affected.
    pub scope: FlowScopeSelector,
    /// Members that were lost (the rebuild targets).
    pub lost_members: Vec<MemberId>,
    /// Epoch when the loss was detected.
    pub detected_epoch: u64,
    /// Timestamp when the loss was detected (ns).
    pub detected_at_ns: u64,
    /// Known replica lag state for candidate source evaluation.
    pub lag_records: Vec<ReplicaLagStateRecord>,
    /// Available member IDs with their health classes.
    pub available_members: BTreeMap<MemberId, HealthClass>,
    /// Affected chunk count for capacity planning.
    pub affected_chunk_count: u64,
    /// Total bytes needing rebuild.
    pub affected_bytes: u64,
}

/// Priority class for rebuild flows.
///
/// Higher priority rebuilds preempt lower ones. Administrative
/// decommission is lowest (planned), corruption is highest (data at risk).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RebuildPriority {
    /// Administrative decommission — planned, can wait.
    Administrative = 1,
    /// Node failure — needs attention but has other replicas.
    NodeFailure = 2,
    /// Disk failure — local redundancy lost.
    DiskFailure = 3,
    /// Suspect/unreachable — may come back, but prepare rebuild.
    SuspectUnreachable = 4,
    /// Corruption detected — data integrity at risk, highest priority.
    CorruptionDetected = 5,
}

// ── Recovery priority — failure recovery loop classification ────────

/// Recovery priority for the continuous failure recovery loop.
///
/// Determines scheduling order across the three recovery tiers.
/// LossRebuild restores durability-risk chunks first (missing above
/// quorum floor), CatchupRepair catches up lagging replicas, and
/// SteadyReplication handles normal steady-state placement work.
///
/// This is distinct from `RebuildPriority` (which classifies
/// individual rebuild flows by trigger source) — this classifies
/// which tier of the recovery loop should run.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RecoveryPriority {
    /// Chunks that lost durability (below quorum floor) — rebuild immediately.
    LossRebuild = 2,
    /// Chunks that are lagging but not lost — catch up when possible.
    CatchupRepair = 1,
    /// Normal steady-state replication — background priority.
    SteadyReplication = 0,
}

impl RecoveryPriority {
    /// Map to a `RebuildPriority` for transfer scheduling through #901.
    #[must_use]
    pub fn to_rebuild_priority(self) -> RebuildPriority {
        match self {
            RecoveryPriority::LossRebuild => RebuildPriority::CorruptionDetected,
            RecoveryPriority::CatchupRepair => RebuildPriority::SuspectUnreachable,
            RecoveryPriority::SteadyReplication => RebuildPriority::Administrative,
        }
    }
}

impl From<LossEventClass> for RebuildPriority {
    fn from(c: LossEventClass) -> Self {
        match c {
            LossEventClass::AdministrativeDecommission => RebuildPriority::Administrative,
            LossEventClass::NodeFailure => RebuildPriority::NodeFailure,
            LossEventClass::DiskFailure => RebuildPriority::DiskFailure,
            LossEventClass::SuspectUnreachable => RebuildPriority::SuspectUnreachable,
            LossEventClass::CorruptionDetected => RebuildPriority::CorruptionDetected,
        }
    }
}

// ── Witness set ─────────────────────────────────────────────────────

/// A witness set bundles the source candidates available for a rebuild scope.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct WitnessSet {
    /// Members that hold verified replicas of the affected data.
    pub verified_sources: Vec<MemberId>,
    /// Members with degraded-but-valid replicas (usable as fallback).
    pub degraded_sources: Vec<MemberId>,
    /// Members that are stale or unreachable (not usable).
    pub unavailable_sources: Vec<MemberId>,
}

impl WitnessSet {
    /// Build a witness set from available member health and lag records.
    #[must_use]
    pub fn from_health_and_lag(
        available_members: &BTreeMap<MemberId, HealthClass>,
        lag_records: &[ReplicaLagStateRecord],
    ) -> Self {
        let mut verified = Vec::new();
        let mut degraded = Vec::new();
        let mut unavailable = Vec::new();

        for (member_id, health) in available_members {
            let lag = lag_records.iter().find(|r| r.target_ref == member_id.0);

            match health {
                HealthClass::Healthy => match lag {
                    Some(r) if r.degraded_visibility_class == DegradedVisibilityClass::None => {
                        verified.push(*member_id);
                    }
                    Some(r)
                        if r.degraded_visibility_class
                            == DegradedVisibilityClass::DegradedReadPossible =>
                    {
                        degraded.push(*member_id);
                    }
                    _ => verified.push(*member_id), // Healthy with no lag record = verified
                },
                HealthClass::Suspect => {
                    degraded.push(*member_id);
                }
                HealthClass::Down => {
                    unavailable.push(*member_id);
                }
            }
        }

        WitnessSet {
            verified_sources: verified,
            degraded_sources: degraded,
            unavailable_sources: unavailable,
        }
    }

    /// Best available source: prefer verified, fall back to degraded.
    #[must_use]
    pub fn best_source(&self) -> Option<MemberId> {
        self.verified_sources
            .first()
            .or_else(|| self.degraded_sources.first())
            .copied()
    }

    /// Whether any usable source exists.
    #[must_use]
    pub fn has_usable_source(&self) -> bool {
        !self.verified_sources.is_empty() || !self.degraded_sources.is_empty()
    }

    /// Total number of usable sources.
    #[must_use]
    pub fn usable_count(&self) -> usize {
        self.verified_sources.len() + self.degraded_sources.len()
    }
}

// ── Rebuild trigger ─────────────────────────────────────────────────

/// What triggered a rebuild flow.
///
/// Rebuilds can originate from different sources: node loss detected
/// through the health tracker, anti-entropy repair tickets that discover
/// missing replicas, or explicit operator requests.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum RebuildTrigger {
    /// Node loss detected by health tracker (#895).
    NodeLoss {
        suspect_event_id: u64,
        lost_node_id: NodeId,
    },
    /// Anti-entropy repair ticket discovered missing/damaged replicas (#888).
    AntiEntropyRepair { repair_ticket_id: u64 },
    /// Operator-initiated rebuild (e.g., decommission, manual repair).
    OperatorInitiated { reason: String },
}

impl RebuildTrigger {
    /// Whether this trigger is urgent (requires reserve budget).
    #[must_use]
    pub fn is_urgent(&self) -> bool {
        matches!(self, RebuildTrigger::NodeLoss { .. })
    }

    /// Whether this trigger may preempt product writes.
    #[must_use]
    pub fn may_preempt_product_work(&self) -> bool {
        matches!(
            self,
            RebuildTrigger::NodeLoss { .. } | RebuildTrigger::AntiEntropyRepair { .. }
        )
    }
}

// ── Rebuild phase ────────────────────────────────────────────────────

/// Operational phase of a rebuild plan.
///
/// The rebuild state machine (OW-305 §4):
/// ```text
/// Planned → SourceSelection → Inflight → Verifying → Committing → Complete
/// ```
///
/// Any state may transition to Paused or Cancelled.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RebuildPhase {
    /// Plan created, awaiting capacity reservation and admission.
    Planned,
    /// Selecting source replicas for each target chunk.
    SourceSelection,
    /// Transfer tickets submitted, data in flight.
    Inflight,
    /// Verifying transferred chunks via placement receipts (#887).
    Verifying,
    /// Committing verified placements into the placement registry (#892).
    Committing,
    /// Rebuild complete — all replicas restored.
    Complete,
    /// Rebuild paused (operator request or backpressure).
    Paused,
    /// Rebuild cancelled (operator request or fatal error).
    Cancelled,
}

impl RebuildPhase {
    /// Whether the phase is terminal (no further transitions).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, RebuildPhase::Complete | RebuildPhase::Cancelled)
    }

    /// Whether the phase is active (work is in progress).
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            RebuildPhase::SourceSelection
                | RebuildPhase::Inflight
                | RebuildPhase::Verifying
                | RebuildPhase::Committing
        )
    }

    /// Whether the phase represents a blocked state.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, RebuildPhase::Paused)
    }
}

// ── Rebuild chunk priority ───────────────────────────────────────────

/// Priority class for individual chunks in a rebuild plan.
///
/// Sorted from most urgent to least urgent. Chunks with active degraded
/// reads are rebuilt first to protect client I/O.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RebuildChunkPriority {
    /// Chunks with active degraded reads — rebuild immediately.
    DegradedRead = 0,
    /// Chunks that lost quorum — correctness-urgent.
    QuorumLost = 1,
    /// Chunks with reduced but not lost quorum.
    QuorumReduced = 2,
    /// Background rebuild.
    Background = 3,
}

// ── Chunk source ─────────────────────────────────────────────────────

/// Where to get chunk data for rebuilding a replica.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ChunkSource {
    /// Single source node with a healthy replica.
    SingleSource { node_id: NodeId },
    /// Reconstruct from multiple sources (erasure coding, future).
    Reconstruction { sources: Vec<NodeId> },
}

impl ChunkSource {
    /// Returns the primary source node, if available.
    #[must_use]
    pub fn primary_source(&self) -> Option<NodeId> {
        match self {
            ChunkSource::SingleSource { node_id } => Some(*node_id),
            ChunkSource::Reconstruction { sources } => sources.first().copied(),
        }
    }

    /// Returns all source nodes.
    #[must_use]
    pub fn all_sources(&self) -> Vec<NodeId> {
        match self {
            ChunkSource::SingleSource { node_id } => vec![*node_id],
            ChunkSource::Reconstruction { sources } => sources.clone(),
        }
    }
}

// ── Rebuild target ───────────────────────────────────────────────────

/// A single chunk that needs rebuilding, with its source and target.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildTarget {
    /// The chunk that needs to be rebuilt.
    pub chunk_id: ChunkId,
    /// Where to source the chunk data.
    pub source: ChunkSource,
    /// Where to place the rebuilt replica (failure-domain-separated).
    pub target_nodes: Vec<NodeId>,
    /// Priority for this specific chunk.
    pub priority: RebuildChunkPriority,
}

// ── Rebuild progress ─────────────────────────────────────────────────

/// Tracks rebuild progress for a single rebuild plan.
///
/// Progress is tracked per-budget-domain and per-replica-set, providing
/// bytes remaining, throughput, and ETA for operator visibility (#898).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildProgress {
    /// Total chunks that need rebuilding.
    pub total_chunks: u64,
    /// Chunks completed so far.
    pub completed_chunks: u64,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Chunks currently in flight.
    pub chunks_inflight: u64,
    /// Chunks that failed and need retry.
    pub chunks_failed: u64,
    /// Chunks by priority class.
    pub chunks_by_priority: BTreeMap<RebuildChunkPriority, u64>,
    /// When progress was last updated (ns).
    pub last_updated_ns: u64,
}

impl RebuildProgress {
    /// Create empty progress for a rebuild plan.
    #[must_use]
    pub fn new(total_chunks: u64, total_bytes: u64) -> Self {
        Self {
            total_chunks,
            completed_chunks: 0,
            total_bytes,
            bytes_transferred: 0,
            chunks_inflight: 0,
            chunks_failed: 0,
            chunks_by_priority: BTreeMap::new(),
            last_updated_ns: 0,
        }
    }

    /// Fraction complete (0.0 to 1.0).
    #[must_use]
    pub fn fraction_complete(&self) -> f64 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        self.completed_chunks as f64 / self.total_chunks as f64
    }

    /// Number of chunks remaining.
    #[must_use]
    pub fn chunks_remaining(&self) -> u64 {
        self.total_chunks.saturating_sub(self.completed_chunks)
    }

    /// Bytes remaining to transfer.
    #[must_use]
    pub fn bytes_remaining(&self) -> u64 {
        self.total_bytes.saturating_sub(self.bytes_transferred)
    }

    /// Estimated throughput in bytes/sec (0 if no transfers yet).
    #[must_use]
    pub fn estimated_throughput(&self, elapsed_ns: u64) -> f64 {
        if elapsed_ns == 0 {
            return 0.0;
        }
        self.bytes_transferred as f64 / (elapsed_ns as f64 / 1_000_000_000.0)
    }

    /// Estimated time to completion in seconds.
    #[must_use]
    pub fn eta_seconds(&self, elapsed_ns: u64) -> Option<f64> {
        let throughput = self.estimated_throughput(elapsed_ns);
        if throughput == 0.0 {
            return None;
        }
        let remaining = self.bytes_remaining() as f64;
        Some(remaining / throughput)
    }

    /// Record a completed chunk.
    pub fn record_chunk_completed(
        &mut self,
        chunk_bytes: u64,
        priority: RebuildChunkPriority,
        now_ns: u64,
    ) {
        self.completed_chunks = self.completed_chunks.saturating_add(1);
        self.bytes_transferred = self.bytes_transferred.saturating_add(chunk_bytes);
        self.chunks_inflight = self.chunks_inflight.saturating_sub(1);
        *self.chunks_by_priority.entry(priority).or_insert(0) += 1;
        self.last_updated_ns = now_ns;
    }

    /// Record a chunk failure (needs retry).
    pub fn record_chunk_failed(&mut self, _priority: RebuildChunkPriority, now_ns: u64) {
        self.chunks_failed = self.chunks_failed.saturating_add(1);
        self.chunks_inflight = self.chunks_inflight.saturating_sub(1);
        self.last_updated_ns = now_ns;
    }

    /// Record chunks entering inflight.
    pub fn record_chunks_inflight(&mut self, count: u64) {
        self.chunks_inflight = self.chunks_inflight.saturating_add(count);
    }
}

// ── Rebuild backpressure ─────────────────────────────────────────────

/// Controls rebuild rate based on client I/O latency.
///
/// When client I/O latency exceeds the configured threshold, rebuild
/// throughput is throttled to avoid starving product workloads.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildBackpressure {
    /// Maximum client I/O latency before throttling (ns).
    pub max_client_latency_ns: u64,
    /// Current rebuild throughput limit in bytes/sec.
    pub throttle_bytes_per_sec: u64,
    /// Whether backpressure is currently active.
    pub active: bool,
    /// When backpressure was last evaluated (ns).
    pub last_evaluated_ns: u64,
}

impl RebuildBackpressure {
    /// Create default backpressure config.
    #[must_use]
    pub fn new(max_client_latency_ns: u64, throttle_bytes_per_sec: u64) -> Self {
        Self {
            max_client_latency_ns,
            throttle_bytes_per_sec,
            active: false,
            last_evaluated_ns: 0,
        }
    }

    /// Evaluate whether backpressure should activate.
    ///
    /// Returns true if backpressure is currently active.
    pub fn evaluate(&mut self, current_client_latency_ns: u64, now_ns: u64) -> bool {
        self.last_evaluated_ns = now_ns;
        self.active = current_client_latency_ns > self.max_client_latency_ns;
        self.active
    }

    /// Get the effective throughput limit (0 = unlimited).
    #[must_use]
    pub fn effective_throttle(&self) -> u64 {
        if self.active {
            self.throttle_bytes_per_sec
        } else {
            0
        }
    }

    /// Whether rebuild is currently throttled.
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        self.active
    }
}

// ── Backfill state ───────────────────────────────────────────────────

/// Detected backfill requirement for a lagged node.
///
/// Backfill catches up nodes that fell behind (lagged). Unlike rebuild,
/// which restores lost replicas, backfill copies data that exists but
/// is stale on a specific node.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct BackfillState {
    /// The node that needs backfill.
    pub target_node: NodeId,
    /// How far behind the node is.
    pub bytes_behind: BytesBehind,
    /// Chunks that need catchup.
    pub stale_chunks: Vec<ChunkId>,
    /// Source nodes for catchup data.
    pub source_candidates: Vec<NodeId>,
    /// When backfill was detected (ns).
    pub detected_at_ns: u64,
    /// Lag class severity.
    pub lag_class: tidefs_replication_model::ReplicaLagClass,
}

impl BackfillState {
    /// Create a new backfill state.
    #[must_use]
    pub fn new(
        target_node: NodeId,
        bytes_behind: BytesBehind,
        stale_chunks: Vec<ChunkId>,
        source_candidates: Vec<NodeId>,
        detected_at_ns: u64,
        lag_class: tidefs_replication_model::ReplicaLagClass,
    ) -> Self {
        Self {
            target_node,
            bytes_behind,
            stale_chunks,
            source_candidates,
            detected_at_ns,
            lag_class,
        }
    }

    /// Whether backfill is urgent (severely behind or stale).
    #[must_use]
    pub fn is_urgent(&self) -> bool {
        matches!(
            self.lag_class,
            tidefs_replication_model::ReplicaLagClass::SeverelyBehind
                | tidefs_replication_model::ReplicaLagClass::Stale
        )
    }

    /// Number of chunks needing catchup.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.stale_chunks.len()
    }

    /// Whether there are source candidates available.
    #[must_use]
    pub fn has_sources(&self) -> bool {
        !self.source_candidates.is_empty()
    }
}

// ── Capacity rebalance ───────────────────────────────────────────────

/// Detected capacity skew across nodes that needs rebalancing.
///
/// Rebalance redistributes chunks for capacity fairness. Unlike
/// rebuild (restore lost data) and backfill (catch up lag), rebalance
/// moves data between healthy nodes to equalize utilization.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CapacityRebalanceSkew {
    /// Nodes with above-average utilization (should move data out).
    pub over_utilized_nodes: Vec<NodeId>,
    /// Nodes with below-average utilization (should receive data).
    pub under_utilized_nodes: Vec<NodeId>,
    /// Maximum utilization difference (most over - least under).
    pub max_utilization_delta_pct: u64,
    /// Threshold above which rebalance is triggered (e.g., 20%).
    pub rebalance_threshold_pct: u64,
    /// Estimated bytes to move for convergence.
    pub estimated_bytes_to_move: u64,
    /// Number of chunks that would need relocation.
    pub estimated_chunks_to_move: u64,
    /// When the skew was detected (ns).
    pub detected_at_ns: u64,
}

impl CapacityRebalanceSkew {
    /// Create a new capacity skew state.
    #[must_use]
    pub fn new(
        over_utilized_nodes: Vec<NodeId>,
        under_utilized_nodes: Vec<NodeId>,
        max_utilization_delta_pct: u64,
        rebalance_threshold_pct: u64,
        estimated_bytes_to_move: u64,
        estimated_chunks_to_move: u64,
        detected_at_ns: u64,
    ) -> Self {
        Self {
            over_utilized_nodes,
            under_utilized_nodes,
            max_utilization_delta_pct,
            rebalance_threshold_pct,
            estimated_bytes_to_move,
            estimated_chunks_to_move,
            detected_at_ns,
        }
    }

    /// Whether rebalance is needed (skew exceeds threshold).
    #[must_use]
    pub fn is_rebalance_needed(&self) -> bool {
        self.max_utilization_delta_pct > self.rebalance_threshold_pct
    }

    /// Whether there are viable source and target nodes.
    #[must_use]
    pub fn has_viable_movement(&self) -> bool {
        !self.over_utilized_nodes.is_empty() && !self.under_utilized_nodes.is_empty()
    }

    /// Average utilization (estimated midpoint).
    #[must_use]
    pub fn estimated_average_utilization_pct(&self) -> u64 {
        if self.max_utilization_delta_pct == 0 {
            return 0;
        }
        // Below-average + half the delta
        self.rebalance_threshold_pct
            .saturating_sub(self.max_utilization_delta_pct / 2)
    }
}

// ── Helper functions ──────────────────────────────────────────────────

/// Classify lag into ReplicaLagClass based on bytes behind.
///
/// Mirrors the classification logic in `tidefs-replica-health` for use
/// in backfill detection.
#[must_use]
pub fn classify_lag_for_backfill(bytes_behind: u64) -> tidefs_replication_model::ReplicaLagClass {
    if bytes_behind == 0 {
        tidefs_replication_model::ReplicaLagClass::Current
    } else if bytes_behind < 1024 * 1024 {
        tidefs_replication_model::ReplicaLagClass::SlightlyBehind
    } else if bytes_behind < 16 * 1024 * 1024 {
        tidefs_replication_model::ReplicaLagClass::ModeratelyBehind
    } else if bytes_behind < 256 * 1024 * 1024 {
        tidefs_replication_model::ReplicaLagClass::SeverelyBehind
    } else {
        tidefs_replication_model::ReplicaLagClass::Stale
    }
}

// ── Durability-layout-driven admission ─────────────────────────────
//
// DurabilityLayoutV1 from tidefs-durability-layout drives rebuild and
// backfill admission decisions for the single durability-layout mechanism
// required by v0.262. This avoids separate local-vs-cluster redundancy
// stacks by making the canonical layout the only policy input.

/// Survivability assessment of a durability layout under current failure
/// counts across device and node failure domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutSurvivability {
    /// Whether the layout can survive the current failure counts without
    /// data loss.
    pub can_survive: bool,
    /// How many *additional* failures the layout can tolerate before data
    /// loss becomes possible. Zero means any further loss is dangerous.
    pub redundancy_headroom: u32,
    /// Whether degraded reads are possible (at least one healthy replica
    /// or sufficient parity shards for reconstruction).
    pub degraded_reads_possible: bool,
    /// Whether a rebuild is needed to restore redundancy headroom above
    /// zero.
    pub needs_rebuild: bool,
    /// Whether a backfill is needed for lagged replicas (headroom is
    /// below the policy minimum).
    pub needs_backfill: bool,
}

/// Reason why a rebuild or backfill admission was rejected by the layout
/// policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRejectionReason {
    /// Admission is fine (no rejection).
    None,
    /// The durability layout would still survive the current loss —
    /// rebuild is not urgently needed, it can be deferred.
    LayoutWouldSurviveLoss,
    /// There is no redundancy headroom remaining; any rebuild attempt
    /// risks data loss and should be escalated.
    NoRedundancyHeadroom,
    /// Not enough healthy sources to rebuild from.
    InsufficientSources,
    /// Cluster-wide capacity exhausted.
    CapacityExhausted,
    /// The durability layout policy version is unknown or unsupported.
    UnknownLayoutVersion,
}

/// Admission decision for a rebuild or backfill flow, driven by the
/// durability layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutAdmissionDecision {
    /// Whether the flow was admitted.
    pub admitted: bool,
    /// Reason if not admitted.
    pub reason: AdmissionRejectionReason,
}

impl LayoutAdmissionDecision {
    /// Admitted with no rejection.
    pub const ADMITTED: Self = Self {
        admitted: true,
        reason: AdmissionRejectionReason::None,
    };

    /// Rejected for the given reason.
    #[must_use]
    pub fn rejected(reason: AdmissionRejectionReason) -> Self {
        Self {
            admitted: false,
            reason,
        }
    }
}

// ── Layout survivability evaluation ─────────────────────────────────

/// Evaluate whether a durability layout can survive the current failure
/// counts across device and node failure domains.
///
/// This is the primary entry point for layout-driven admission. It
/// delegates to `DurabilityLayoutV1::survives_failure()` and computes
/// headroom and derived flags.
#[must_use]
pub fn evaluate_layout_survivability(
    layout: &DurabilityLayoutV1,
    failed_devices: u32,
    failed_nodes: u32,
) -> LayoutSurvivability {
    let can_survive = layout.survives_failure(failed_devices, failed_nodes);
    let headroom = redundancy_headroom(layout);
    let total_failures = failed_devices + failed_nodes;

    LayoutSurvivability {
        can_survive,
        redundancy_headroom: headroom,
        degraded_reads_possible: can_survive,
        needs_rebuild: headroom == 0 && can_survive,
        needs_backfill: headroom > 0 && total_failures > 0,
    }
}

/// Compute how many additional failures the durability layout can
/// tolerate before data loss becomes possible.
///
/// For Mirror{N}: N-1 failures total. For ErasureStyle{k,m}: m failures.
#[must_use]
pub fn redundancy_headroom(layout: &DurabilityLayoutV1) -> u32 {
    match &layout.policy {
        DurabilityPolicy::Mirror { copies } => (*copies as u32).saturating_sub(1),
        DurabilityPolicy::ErasureStyle { parity_shards, .. } => *parity_shards as u32,
        DurabilityPolicy::Hybrid { parity_shards, .. } => *parity_shards as u32,
    }
}

/// Determine the maximum failure count the layout can survive across
/// both device and node failure domains combined.
#[must_use]
pub fn max_tolerable_failures(layout: &DurabilityLayoutV1) -> u32 {
    redundancy_headroom(layout)
}

// ── Rebuild admission ───────────────────────────────────────────────

/// Check whether a rebuild flow should be admitted for a loss event,
/// driven by the durability layout.
///
/// A rebuild is admitted when:
/// - The layout exists and is valid
/// - The current failure counts exceed what the layout can survive
///   (rebuild is urgently needed), OR
/// - Headroom is zero (any further failure would cause data loss),
///   requiring immediate rebuild to restore headroom.
#[must_use]
pub fn check_rebuild_admission(
    layout: Option<&DurabilityLayoutV1>,
    failed_devices: u32,
    failed_nodes: u32,
    healthy_source_count: usize,
) -> LayoutAdmissionDecision {
    let layout = match layout {
        Some(l) => l,
        None => {
            return LayoutAdmissionDecision::rejected(
                AdmissionRejectionReason::UnknownLayoutVersion,
            )
        }
    };

    let survivability = evaluate_layout_survivability(layout, failed_devices, failed_nodes);

    if healthy_source_count == 0 {
        return LayoutAdmissionDecision::rejected(AdmissionRejectionReason::InsufficientSources);
    }

    if !survivability.can_survive || survivability.redundancy_headroom == 0 {
        return LayoutAdmissionDecision::ADMITTED;
    }

    LayoutAdmissionDecision::rejected(AdmissionRejectionReason::LayoutWouldSurviveLoss)
}

/// Check whether a backfill flow should be admitted for a lagged
/// replica, driven by the durability layout.
///
/// A backfill is always admitted for stale/severely-behind replicas.
/// Slightly-behind replicas are backfilled only when headroom is low
/// or lag is significant.
#[must_use]
pub fn check_backfill_admission(
    layout: Option<&DurabilityLayoutV1>,
    bytes_behind: u64,
    healthy_source_count: usize,
    lag_class: tidefs_replication_model::ReplicaLagClass,
) -> LayoutAdmissionDecision {
    let layout = match layout {
        Some(l) => l,
        None => {
            return LayoutAdmissionDecision::rejected(
                AdmissionRejectionReason::UnknownLayoutVersion,
            )
        }
    };

    if healthy_source_count == 0 {
        return LayoutAdmissionDecision::rejected(AdmissionRejectionReason::InsufficientSources);
    }

    let headroom = redundancy_headroom(layout);

    match lag_class {
        tidefs_replication_model::ReplicaLagClass::Current => {
            LayoutAdmissionDecision::rejected(AdmissionRejectionReason::LayoutWouldSurviveLoss)
        }
        tidefs_replication_model::ReplicaLagClass::SlightlyBehind => {
            if headroom <= 1 || bytes_behind > 100_000_000 {
                LayoutAdmissionDecision::ADMITTED
            } else {
                LayoutAdmissionDecision::rejected(AdmissionRejectionReason::LayoutWouldSurviveLoss)
            }
        }
        tidefs_replication_model::ReplicaLagClass::ModeratelyBehind
        | tidefs_replication_model::ReplicaLagClass::SeverelyBehind
        | tidefs_replication_model::ReplicaLagClass::Stale => LayoutAdmissionDecision::ADMITTED,
    }
}

// ── Rebuild planner ──────────────────────────────────────────────────

/// The rebuild planner orchestrates rebuild flows from loss events
/// through batch scheduling and state transitions.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RebuildPlanner {
    /// Active rebuild flows, keyed by flow ID.
    pub flows: BTreeMap<u64, RebuildFlowRecord>,
    /// Scheduled rebuild batches, keyed by batch ID.
    pub batches: BTreeMap<u64, RebuildBatchRecord>,
    /// Next available flow ID.
    next_flow_id: u64,
    /// Next available batch ID.
    next_batch_id: u64,
}

impl RebuildPlanner {
    /// Create a new empty rebuild planner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: BTreeMap::new(),
            batches: BTreeMap::new(),
            next_flow_id: 1,
            next_batch_id: 1,
        }
    }

    /// Open a rebuild flow from a loss event.
    ///
    /// Returns the created `RebuildFlowRecord` or an error string if
    /// the flow cannot be opened (e.g., no usable sources).
    ///
    /// # State: Open
    pub fn open_rebuild_flow_from_loss_event(
        &mut self,
        event: &LossEvent,
    ) -> Result<RebuildFlowRecord, String> {
        let flow_id = self.next_flow_id;
        self.next_flow_id += 1;

        let witness = WitnessSet::from_health_and_lag(&event.available_members, &event.lag_records);

        // Filter lost members from available sources
        let source_candidates: Vec<MemberId> = witness
            .verified_sources
            .iter()
            .chain(witness.degraded_sources.iter())
            .filter(|m| !event.lost_members.contains(m))
            .copied()
            .collect();

        if source_candidates.is_empty() {
            let flow = RebuildFlowRecord {
                rebuild_flow_id: flow_id,
                loss_event_ref: event.loss_event_id,
                loss_event_class: event.loss_class,
                scope_selector: event.scope,
                source_candidate_refs: Vec::new(),
                target_refs: event.lost_members.clone(),
                state: RebuildFlowState::BlockedNoSource,
                degraded_class: event.degraded_class,
            };
            self.flows.insert(flow_id, flow.clone());
            return Err(format!(
                "No usable source candidates for rebuild flow {}: all {} candidates are lost or unavailable",
                flow_id,
                witness.usable_count()
            ));
        }

        let flow = RebuildFlowRecord {
            rebuild_flow_id: flow_id,
            loss_event_ref: event.loss_event_id,
            loss_event_class: event.loss_class,
            scope_selector: event.scope,
            source_candidate_refs: source_candidates.clone(),
            target_refs: event.lost_members.clone(),
            state: RebuildFlowState::Open,
            degraded_class: event.degraded_class,
        };

        self.flows.insert(flow_id, flow.clone());
        Ok(flow)
    }

    /// Schedule rebuild batches from the witness sets of an open rebuild flow.
    ///
    /// Batches are sized according to the chunk count. Each source
    /// candidate gets its own batch to allow parallel transfer.
    ///
    /// # State: Open → Planning
    pub fn schedule_rebuild_batches_from_witness_sets(
        &mut self,
        flow_id: u64,
        chunks_per_batch: u64,
    ) -> Result<Vec<RebuildBatchRecord>, String> {
        let flow = self
            .flows
            .get(&flow_id)
            .ok_or_else(|| format!("Rebuild flow {flow_id} not found"))?;

        if flow.state != RebuildFlowState::Open {
            return Err(format!(
                "Rebuild flow {} is not in Open state (current: {:?})",
                flow_id, flow.state
            ));
        }

        if flow.source_candidate_refs.is_empty() {
            return Err(format!("Rebuild flow {flow_id} has no source candidates"));
        }

        let mut batches = Vec::new();

        for (i, source) in flow.source_candidate_refs.iter().enumerate() {
            let batch_id = self.next_batch_id;
            self.next_batch_id += 1;

            // Assign a proportional share of chunks to each source
            let source_count = flow.source_candidate_refs.len() as u64;
            let batch_chunks = if i == source_count as usize - 1 {
                // Last source gets remainder
                chunks_per_batch
                    .saturating_sub((source_count - 1) * (chunks_per_batch / source_count))
            } else {
                chunks_per_batch / source_count
            };

            if batch_chunks == 0 {
                continue;
            }

            let batch = RebuildBatchRecord {
                batch_id,
                rebuild_flow_ref: flow_id,
                chunk_refs: (0..batch_chunks)
                    .map(|c| c + (i as u64 * batch_chunks))
                    .collect(),
                source_bundle_refs: vec![*source],
                target_refs: flow.target_refs.clone(),
                verification_requirements: tidefs_replication_model::VerificationStatus::Verified,
            };

            batches.push(batch.clone());
            self.batches.insert(batch_id, batch);
        }

        // Advance state to Planning
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            flow.state = RebuildFlowState::Planning;
        }

        Ok(batches)
    }

    /// Advance a rebuild flow through its state machine.
    ///
    /// Returns the new state after the transition, or an error if the
    /// transition is invalid.
    pub fn advance_rebuild_flow_state(
        &mut self,
        flow_id: u64,
        target_state: RebuildFlowState,
    ) -> Result<RebuildFlowState, String> {
        let flow = self
            .flows
            .get(&flow_id)
            .ok_or_else(|| format!("Rebuild flow {flow_id} not found"))?;

        let valid = match (flow.state, target_state) {
            // Happy path
            (RebuildFlowState::Open, RebuildFlowState::Planning) => true,
            (RebuildFlowState::Planning, RebuildFlowState::Transferring) => true,
            (RebuildFlowState::Transferring, RebuildFlowState::Verifying) => true,
            (RebuildFlowState::Verifying, RebuildFlowState::Restored) => true,

            // Exception paths: any non-terminal to blocked/cancelled
            (current, RebuildFlowState::BlockedNoSource)
            | (current, RebuildFlowState::BlockedNoTarget)
            | (current, RebuildFlowState::BlockedNoCapacity)
            | (current, RebuildFlowState::Cancelled)
                if !matches!(
                    current,
                    RebuildFlowState::Restored | RebuildFlowState::Cancelled
                ) =>
            {
                true
            }

            // Allow re-entering open from blocked (retry)
            (RebuildFlowState::BlockedNoSource, RebuildFlowState::Open) => true,
            (RebuildFlowState::BlockedNoTarget, RebuildFlowState::Open) => true,
            (RebuildFlowState::BlockedNoCapacity, RebuildFlowState::Open) => true,

            _ => false,
        };

        if !valid {
            return Err(format!(
                "Invalid state transition for rebuild flow {}: {:?} → {:?}",
                flow_id, flow.state, target_state
            ));
        }

        match self.flows.get_mut(&flow_id) {
            Some(flow) => {
                flow.state = target_state;
                Ok(target_state)
            }
            None => Err(format!("Rebuild flow {flow_id} disappeared")),
        }
    }

    /// Get the current state of a rebuild flow.
    #[must_use]
    pub fn flow_state(&self, flow_id: u64) -> Option<RebuildFlowState> {
        self.flows.get(&flow_id).map(|f| f.state)
    }

    /// Get all batches for a rebuild flow.
    #[must_use]
    pub fn flow_batches(&self, flow_id: u64) -> Vec<&RebuildBatchRecord> {
        self.batches
            .values()
            .filter(|b| b.rebuild_flow_ref == flow_id)
            .collect()
    }

    /// List active flow IDs (not restored or cancelled).
    #[must_use]
    pub fn active_flow_ids(&self) -> Vec<u64> {
        self.flows
            .iter()
            .filter(|(_, f)| {
                !matches!(
                    f.state,
                    RebuildFlowState::Restored | RebuildFlowState::Cancelled
                )
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Count flows by state.
    #[must_use]
    pub fn flow_count_by_state(&self, state: RebuildFlowState) -> usize {
        self.flows.values().filter(|f| f.state == state).count()
    }

    /// Select source replicas with failure-domain separation from target nodes.
    ///
    /// For each target node, prefer source candidates in a different failure
    /// domain. This prevents a single rack/power failure from destroying both
    /// the source replica and the rebuilt target.
    ///
    /// Returns a map from target node to its best source candidate.
    #[must_use]
    pub fn select_sources_with_failure_domain_separation(
        &self,
        source_candidates: &[NodeId],
        target_nodes: &[NodeId],
        failure_domains: &BTreeMap<NodeId, tidefs_membership_epoch::DomainId>,
    ) -> BTreeMap<NodeId, Vec<NodeId>> {
        let mut result: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();

        for target in target_nodes {
            let target_domain = failure_domains.get(target);
            let mut candidates: Vec<NodeId> = source_candidates
                .iter()
                .filter(|s| {
                    // Prefer sources in different failure domains
                    if let (Some(td), Some(sd)) = (target_domain, failure_domains.get(s)) {
                        td != sd
                    } else {
                        true // no domain info, accept any source
                    }
                })
                .copied()
                .collect();

            // Fallback: if no cross-domain source, accept same-domain
            if candidates.is_empty() {
                candidates = source_candidates.to_vec();
            }

            result.insert(*target, candidates);
        }

        result
    }

    /// Detect stale chunks that need backfill on a lagged node.
    ///
    /// Backfill catches up nodes that fell behind. This method compares
    /// receipt frontiers to find chunks where a node is behind the cluster
    /// consensus.
    #[must_use]
    pub fn detect_stale_chunks_for_backfill(
        &self,
        target_node: NodeId,
        lag_records: &[ReplicaLagStateRecord],
        bytes_behind: BytesBehind,
        source_candidates: &[NodeId],
        detected_at_ns: u64,
    ) -> BackfillState {
        let lag_class = classify_lag_for_backfill(bytes_behind.0);

        let stale_chunks: Vec<ChunkId> = lag_records
            .iter()
            .map(|r| ChunkId(r.subject_ref.0))
            .collect();

        BackfillState::new(
            target_node,
            bytes_behind,
            stale_chunks,
            source_candidates.to_vec(),
            detected_at_ns,
            lag_class,
        )
    }

    /// Detect capacity skew across nodes that needs rebalancing.
    ///
    /// Compares utilization across nodes to find imbalance. Returns `None`
    /// if the utilization is balanced within the threshold.
    #[must_use]
    pub fn detect_capacity_skew_for_rebalance(
        &self,
        node_utilization: &BTreeMap<NodeId, u64>, // NodeId -> utilization_pct
        rebalance_threshold_pct: u64,
        total_bytes: u64,
        detected_at_ns: u64,
    ) -> Option<CapacityRebalanceSkew> {
        if node_utilization.is_empty() {
            return None;
        }

        let max_util = node_utilization.values().copied().max().unwrap_or(0);
        let min_util = node_utilization.values().copied().min().unwrap_or(0);
        let delta = max_util.saturating_sub(min_util);

        if delta <= rebalance_threshold_pct {
            return None;
        }

        // Compute average utilization; nodes above average are over-utilized,
        // nodes below average are under-utilized.
        let avg_util: u64 = node_utilization.values().sum::<u64>() / node_utilization.len() as u64;

        let over_utilized: Vec<NodeId> = node_utilization
            .iter()
            .filter(|(_, &util)| util > avg_util)
            .map(|(node_id, _)| *node_id)
            .collect();

        let under_utilized: Vec<NodeId> = node_utilization
            .iter()
            .filter(|(_, &util)| util < avg_util)
            .map(|(node_id, _)| *node_id)
            .collect();

        let node_count = node_utilization.len() as u64;
        let estimated_bytes_to_move = (delta * total_bytes) / 100;
        let estimated_chunks_to_move = node_count.saturating_mul(10); // rough estimate

        Some(CapacityRebalanceSkew::new(
            over_utilized,
            under_utilized,
            delta,
            rebalance_threshold_pct,
            estimated_bytes_to_move,
            estimated_chunks_to_move,
            detected_at_ns,
        ))
    }

    /// Compute per-node object deltas from an object enumeration and
    /// per-node current-object sets.
    ///
    /// Delegates to `tidefs_transport::compute_per_node_object_deltas`
    /// and returns the same `BTreeMap<MemberId, PerNodeObjectDelta>`.
    ///
    /// This is an integration point: the rebuild planner consumes
    /// enumerations produced by any `ObjectEnumerator` and computes
    /// the per-node work sets for rebuild/backfill scheduling.
    #[must_use]
    pub fn compute_object_deltas_from_enumeration(
        &self,
        enumeration: &[ObjectPlacementEntry],
        current_node_objects: &BTreeMap<MemberId, BTreeSet<u64>>,
    ) -> BTreeMap<MemberId, PerNodeObjectDelta> {
        tidefs_transport::compute_per_node_object_deltas(enumeration, current_node_objects)
    }

    /// Return the set of member IDs that need work (missing or excess
    /// objects) based on an enumeration and current-node state.
    ///
    /// This is a convenience function: it computes deltas and filters
    /// to nodes where `PerNodeObjectDelta::has_work()` is true.
    #[must_use]
    pub fn nodes_needing_work(
        enumeration: &[ObjectPlacementEntry],
        current_node_objects: &BTreeMap<MemberId, BTreeSet<u64>>,
    ) -> BTreeSet<MemberId> {
        let deltas =
            tidefs_transport::compute_per_node_object_deltas(enumeration, current_node_objects);
        deltas
            .into_iter()
            .filter(|(_, delta)| delta.has_work())
            .map(|(member_id, _)| member_id)
            .collect()
    }
}

// ── Cascading failure guard ─────────────────────────────────────────

/// Guards against cascading failure: limits recovery concurrency
/// within each failure domain to prevent one domain's recovery from
/// overwhelming the cluster.
///
/// When a rack failure triggers rebuild for many chunks, the guard
/// batches recovery per domain so the rebuild itself doesn't trigger
/// more overload, which would trigger more rebuild — the canonical
/// distributed storage cascading failure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CascadingFailureGuard {
    /// Maximum concurrent recovery flows per failure domain.
    pub max_recovery_per_domain: usize,
    /// Active recovery flows grouped by failure domain.
    pub active_by_domain: BTreeMap<tidefs_membership_epoch::DomainId, Vec<u64>>,
    /// Total active recovery flows cluster-wide.
    pub total_active: usize,
    /// Maximum total recovery flows cluster-wide.
    pub max_total_recovery: usize,
}

impl CascadingFailureGuard {
    /// Create a new cascading failure guard.
    ///
    /// `max_per_domain` limits recovery concurrency within any single
    /// failure domain. `max_total` is the cluster-wide recovery cap.
    #[must_use]
    pub fn new(max_per_domain: usize, max_total: usize) -> Self {
        Self {
            max_recovery_per_domain: max_per_domain,
            active_by_domain: BTreeMap::new(),
            total_active: 0,
            max_total_recovery: max_total,
        }
    }

    /// Try to admit a recovery flow for a specific failure domain.
    ///
    /// Returns `true` if the recovery was admitted, `false` if it was
    /// rejected due to domain or cluster-wide limits.
    pub fn admit_recovery(
        &mut self,
        domain_id: tidefs_membership_epoch::DomainId,
        flow_id: u64,
    ) -> bool {
        if self.total_active >= self.max_total_recovery {
            return false;
        }
        let domain_flows = self.active_by_domain.entry(domain_id).or_default();
        if domain_flows.len() >= self.max_recovery_per_domain {
            return false;
        }
        domain_flows.push(flow_id);
        self.total_active += 1;
        true
    }

    /// Release a completed recovery flow.
    pub fn release_recovery(&mut self, domain_id: tidefs_membership_epoch::DomainId, flow_id: u64) {
        if let Some(domain_flows) = self.active_by_domain.get_mut(&domain_id) {
            if let Some(pos) = domain_flows.iter().position(|&id| id == flow_id) {
                domain_flows.remove(pos);
                self.total_active = self.total_active.saturating_sub(1);
            }
            if domain_flows.is_empty() {
                self.active_by_domain.remove(&domain_id);
            }
        }
    }

    /// Whether a new recovery can be admitted for the given domain.
    #[must_use]
    pub fn can_admit(&self, domain_id: tidefs_membership_epoch::DomainId) -> bool {
        if self.total_active >= self.max_total_recovery {
            return false;
        }
        self.active_by_domain
            .get(&domain_id)
            .is_none_or(|flows| flows.len() < self.max_recovery_per_domain)
    }

    /// Number of active recovery flows in a domain.
    #[must_use]
    pub fn domain_active(&self, domain_id: tidefs_membership_epoch::DomainId) -> usize {
        self.active_by_domain
            .get(&domain_id)
            .map_or(0, |flows| flows.len())
    }
}

// ── Quorum-aware rebuild helpers ─────────────────────────────────────

/// Determine the minimum replicas needed to restore quorum for a chunk.
///
/// Given the original replica count, computes how many replicas are
/// needed to satisfy the quorum floor. For example, with 3 replicas
/// (quorum=2), losing 2 replicas requires rebuilding only 1 to
/// restore quorum — not both.
///
/// Quorum == (replica_count / 2) + 1.
#[must_use]
pub fn min_replicas_for_quorum(original_replica_count: usize) -> usize {
    if original_replica_count == 0 {
        return 0;
    }
    (original_replica_count / 2) + 1
}

/// Compute how many replicas must be rebuilt to restore quorum.
///
/// `remaining_healthy` is the count of replicas still healthy.
/// Returns the minimum number of replicas to rebuild.
#[must_use]
pub fn replicas_to_restore_quorum(
    original_replica_count: usize,
    remaining_healthy: usize,
) -> usize {
    let quorum_floor = min_replicas_for_quorum(original_replica_count);
    if remaining_healthy >= quorum_floor {
        return 0; // Quorum already satisfied
    }
    quorum_floor.saturating_sub(remaining_healthy)
}

/// Classify the recovery priority for a set of lost replicas.
///
/// Returns `LossRebuild` if quorum is lost, `CatchupRepair` if
/// replicas are lagged but quorum holds, and `SteadyReplication`
/// for normal placement work.
#[must_use]
pub fn classify_recovery_priority(
    original_replica_count: usize,
    remaining_healthy: usize,
    has_data_loss: bool,
) -> RecoveryPriority {
    let quorum_floor = min_replicas_for_quorum(original_replica_count);

    if has_data_loss || remaining_healthy < quorum_floor {
        RecoveryPriority::LossRebuild
    } else if remaining_healthy < original_replica_count {
        RecoveryPriority::CatchupRepair
    } else {
        RecoveryPriority::SteadyReplication
    }
}

// ── Recovery loop ────────────────────────────────────────────────────

/// Context for a single recovery flow tracked by the recovery loop.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFlowContext {
    /// Unique flow identifier assigned by the recovery loop.
    pub flow_id: u64,
    /// The loss event that triggered this flow.
    pub loss_event: LossEvent,
    /// Rebuild trigger classification.
    pub trigger: RebuildTrigger,
    /// Recovery priority tier.
    pub priority: RecoveryPriority,
    /// Chunks recovered so far.
    pub chunks_recovered: u64,
    /// Total chunks to recover.
    pub chunks_total: u64,
    /// Placement receipts produced for recovered chunks.
    pub receipts_produced: Vec<ReplicatedReceiptId>,
    /// When the flow was started (ns).
    pub started_at_ns: u64,
}

/// The continuous failure recovery loop.
///
/// Composes the health tracker state transitions, rebuild planner,
/// cascading failure guard, and backpressure into a single continuous
/// loop: detect → scope → plan → execute → verify → loop.
///
/// # Design
///
/// - **Chunk-scoped**: one slow chunk does not stall others
/// - **Priority-ordered**: LossRebuild > CatchupRepair > SteadyReplication
/// - **Blast-radius-contained**: `CascadingFailureGuard` limits per-domain
///   recovery concurrency
/// - **Receipt-verified**: every recovered chunk produces a placement receipt
/// - **Continuous**: loop polls health transitions and drives recovery
///   without requiring external orchestration
///
/// Determine the next logical state for a rebuild flow in the recovery loop.
///
/// Maps the current  to its natural successor.
/// Blocked states retry to Open. The recovery loop drives flows
/// through Open → Planning → Transferring → Verifying → Restored.
#[must_use]
pub fn next_rebuild_state(current: RebuildFlowState) -> RebuildFlowState {
    match current {
        RebuildFlowState::Open => RebuildFlowState::Planning,
        RebuildFlowState::Planning => RebuildFlowState::Transferring,
        RebuildFlowState::Transferring => RebuildFlowState::Verifying,
        RebuildFlowState::Verifying => RebuildFlowState::Restored,
        // Blocked flows retry from Open
        RebuildFlowState::BlockedNoSource
        | RebuildFlowState::BlockedNoTarget
        | RebuildFlowState::BlockedNoCapacity => RebuildFlowState::Open,
        // Terminal states stay put
        RebuildFlowState::Restored | RebuildFlowState::Cancelled => current,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoveryLoop {
    /// Inner rebuild planner for flow management.
    pub planner: RebuildPlanner,
    /// Cascading failure guard for blast-radius containment.
    pub cascading_guard: CascadingFailureGuard,
    /// Backpressure for client-latency-adaptive throttling.
    pub backpressure: RebuildBackpressure,
    /// Active recovery flows.
    pub active_recovery_flows: BTreeMap<u64, RecoveryFlowContext>,
    /// Loss events that are pending admission (blocked by guard).
    pub pending_loss_events: Vec<LossEvent>,
    /// Completed flow IDs (for verification).
    pub completed_recovery_ids: Vec<u64>,
    /// Monotonic flow ID counter.
    next_flow_id: u64,
    /// Durability layout driving admission decisions (the single
    /// TideFS-native mechanism for mirror and erasure-style policies).
    #[serde(skip)]
    pub durability_layout: Option<DurabilityLayoutV1>,
    /// Quorum size used for rebuild decisions.
    quorum_size: usize,
}

impl RecoveryLoop {
    /// Create a new recovery loop.
    ///
    /// `quorum_size` is the minimum number of replicas needed for
    /// quorum. `max_per_domain` and `max_total` control the
    /// cascading failure guard limits. `max_client_latency_ns` and
    /// `throttle_bytes_per_sec` configure backpressure.
    #[must_use]
    pub fn new(
        quorum_size: usize,
        max_per_domain: usize,
        max_total: usize,
        max_client_latency_ns: u64,
        throttle_bytes_per_sec: u64,
    ) -> Self {
        Self::with_layout(
            quorum_size,
            max_per_domain,
            max_total,
            max_client_latency_ns,
            throttle_bytes_per_sec,
            None,
        )
    }

    /// Create a new recovery loop with an explicit durability layout.
    ///
    /// When a `DurabilityLayoutV1` is provided, rebuild and backfill
    /// admission decisions are driven by the layout's survivability
    /// model instead of generic quorum heuristics.
    #[must_use]
    pub fn with_layout(
        quorum_size: usize,
        max_per_domain: usize,
        max_total: usize,
        max_client_latency_ns: u64,
        throttle_bytes_per_sec: u64,
        durability_layout: Option<DurabilityLayoutV1>,
    ) -> Self {
        Self {
            planner: RebuildPlanner::new(),
            cascading_guard: CascadingFailureGuard::new(max_per_domain, max_total),
            backpressure: RebuildBackpressure::new(max_client_latency_ns, throttle_bytes_per_sec),
            active_recovery_flows: BTreeMap::new(),
            pending_loss_events: Vec::new(),
            completed_recovery_ids: Vec::new(),
            next_flow_id: 1,
            durability_layout,
            quorum_size,
        }
    }
    /// Feed a loss event into the recovery loop (step: detect).
    ///
    /// The event is admitted if the cascading failure guard allows
    /// it. Otherwise it's queued as pending.
    pub fn detect_loss(&mut self, loss_event: LossEvent, now_ns: u64) -> bool {
        if self.backpressure.is_throttled() {
            return false;
        }

        // Consult the durability layout before admission.
        // If a layout is configured, run the layout-driven rebuild
        // admission check. If the layout would survive the loss,
        // defer the rebuild (it's not urgent).
        if let Some(ref layout) = self.durability_layout {
            let healthy_sources = loss_event
                .available_members
                .values()
                .filter(|h| matches!(h, HealthClass::Healthy))
                .count();
            // Count failed devices as lost members (conservative: each
            // lost member is a failed device for layout purposes).
            let failed_devices = loss_event.lost_members.len() as u32;
            let decision = check_rebuild_admission(
                Some(layout),
                failed_devices,
                0, // node failures tracked separately; use 0 for local
                healthy_sources,
            );
            if !decision.admitted {
                self.pending_loss_events.push(loss_event);
                return false;
            }
        }

        // Classify priority from the loss event
        let remaining_healthy = loss_event
            .available_members
            .values()
            .filter(|h| matches!(h, HealthClass::Healthy))
            .count();
        let original_count = remaining_healthy + loss_event.lost_members.len();
        let priority = classify_recovery_priority(
            original_count,
            remaining_healthy,
            matches!(
                loss_event.loss_class,
                LossEventClass::CorruptionDetected | LossEventClass::DiskFailure
            ),
        );

        let domain_id = match &loss_event.scope {
            FlowScopeSelector::Domain(d) => *d,
            _ => tidefs_membership_epoch::DomainId::ZERO,
        };

        let flow_id = self.next_flow_id;
        self.next_flow_id += 1;

        if !self.cascading_guard.admit_recovery(domain_id, flow_id) {
            self.pending_loss_events.push(loss_event);
            return false;
        }

        // Open the rebuild flow in the planner
        let _ = self.planner.open_rebuild_flow_from_loss_event(&loss_event);

        let trigger = match &loss_event.loss_class {
            LossEventClass::NodeFailure | LossEventClass::SuspectUnreachable => {
                RebuildTrigger::NodeLoss {
                    suspect_event_id: flow_id,
                    lost_node_id: NodeId(0), // Placeholder — actual node IDs come from lost_members
                }
            }
            LossEventClass::CorruptionDetected => RebuildTrigger::AntiEntropyRepair {
                repair_ticket_id: flow_id,
            },
            _ => RebuildTrigger::OperatorInitiated {
                reason: format!("loss_event_{}", loss_event.loss_event_id),
            },
        };

        let chunks_total = loss_event.affected_chunk_count;

        let context = RecoveryFlowContext {
            flow_id,
            loss_event,
            trigger,
            priority,
            chunks_recovered: 0,
            chunks_total,
            receipts_produced: Vec::new(),
            started_at_ns: now_ns,
        };

        self.active_recovery_flows.insert(flow_id, context);
        true
    }

    /// Scope a loss event into a rebuild plan (step: scope).
    ///
    /// Uses the rebuild planner to identify affected chunks, source
    /// candidates, and target nodes with failure-domain separation.
    #[must_use]
    pub fn scope_loss(
        &mut self,
        flow_id: u64,
        source_candidates: &[NodeId],
        target_nodes: &[NodeId],
        failure_domains: &BTreeMap<NodeId, tidefs_membership_epoch::DomainId>,
    ) -> Option<Vec<RebuildTarget>> {
        let context = self.active_recovery_flows.get(&flow_id)?;

        let sources = self.planner.select_sources_with_failure_domain_separation(
            source_candidates,
            target_nodes,
            failure_domains,
        );

        let rebuild_targets: Vec<RebuildTarget> = target_nodes
            .iter()
            .flat_map(|target| {
                let source_set: Vec<NodeId> = sources.get(target).cloned().unwrap_or_default();
                source_set.into_iter().map(move |source| RebuildTarget {
                    chunk_id: ChunkId(0), // Scoped per-chunk during execution
                    source: ChunkSource::SingleSource { node_id: source },
                    target_nodes: vec![*target],
                    priority: match context.priority {
                        RecoveryPriority::LossRebuild => RebuildChunkPriority::QuorumLost,
                        RecoveryPriority::CatchupRepair => RebuildChunkPriority::QuorumReduced,
                        RecoveryPriority::SteadyReplication => RebuildChunkPriority::Background,
                    },
                })
            })
            .collect();

        Some(rebuild_targets)
    }

    /// Plan the recovery: compute the rebuild operation set (step: plan).
    ///
    /// Returns a list of chunk ids that need to be rebuilt, ordered by
    /// priority (LossRebuild first).
    #[must_use]
    pub fn plan_recovery(&self) -> Vec<u64> {
        let mut ordered_flows: Vec<&RecoveryFlowContext> =
            self.active_recovery_flows.values().collect();
        ordered_flows.sort_by_key(|ctx| std::cmp::Reverse(ctx.priority));

        ordered_flows.iter().map(|ctx| ctx.flow_id).collect()
    }

    /// Execute one tick of the recovery loop (step: execute).
    ///
    /// Advances flows through the rebuild state machine. Returns the
    /// number of flows advanced.
    pub fn execute_tick(&mut self, now_ns: u64, client_latency_ns: u64) -> usize {
        // Evaluate backpressure
        self.backpressure.evaluate(client_latency_ns, now_ns);

        // Process pending loss events first (blast-radius containment)
        let mut admitted = 0;
        let now_ns_copy = now_ns;
        // Take ownership of pending events to avoid borrow conflicts with detect_loss
        let pending: Vec<LossEvent> = std::mem::take(&mut self.pending_loss_events);
        let mut to_retry: Vec<LossEvent> = Vec::new();
        for event in pending {
            if self.detect_loss(event.clone(), now_ns_copy) {
                admitted += 1;
            } else {
                to_retry.push(event);
            }
        }
        self.pending_loss_events = to_retry;

        if self.backpressure.is_throttled() {
            return admitted;
        }

        // Advance flows
        let flow_ids: Vec<u64> = self.active_recovery_flows.keys().copied().collect();
        let mut advanced = 0;
        for flow_id in flow_ids {
            if let Some(prev_state) = self.planner.flow_state(flow_id) {
                let next_state = next_rebuild_state(prev_state);
                let new_state = self.planner.advance_rebuild_flow_state(flow_id, next_state);
                if new_state != Ok(prev_state) {
                    advanced += 1;
                }
                // Check for completion
                if matches!(new_state, Ok(RebuildFlowState::Restored)) {
                    if let Some(ctx) = self.active_recovery_flows.get(&flow_id) {
                        let domain_id = match &ctx.loss_event.scope {
                            FlowScopeSelector::Domain(d) => *d,
                            _ => tidefs_membership_epoch::DomainId::ZERO,
                        };
                        self.cascading_guard.release_recovery(domain_id, flow_id);
                    }
                    self.completed_recovery_ids.push(flow_id);
                }
            }
        }

        admitted + advanced
    }

    /// Verify recovered chunks produce placement receipts (step: verify).
    ///
    /// This is the receipt-verification gate. Every recovered chunk
    /// must produce a `ReplicaPlacementReceipt` before the flow is
    /// considered restored.
    #[must_use]
    pub fn verify_recovery(
        &self,
        flow_id: u64,
        receipts: &[tidefs_replication_model::ReplicaPlacementReceipt],
    ) -> bool {
        let Some(context) = self.active_recovery_flows.get(&flow_id) else {
            return false;
        };

        // Every chunk in the flow should have a placement receipt.
        let receipt_chunk_count: usize = receipts.iter().map(|r| r.subjects_placed as usize).sum();

        receipt_chunk_count >= context.chunks_total as usize
    }

    /// Record recovered chunks with their placement receipts.
    pub fn record_recovery_progress(
        &mut self,
        flow_id: u64,
        chunks_completed: u64,
        receipt_ids: Vec<ReplicatedReceiptId>,
    ) {
        if let Some(context) = self.active_recovery_flows.get_mut(&flow_id) {
            context.chunks_recovered = context.chunks_recovered.saturating_add(chunks_completed);
            context.receipts_produced.extend(receipt_ids);
        }
    }

    /// Full recovery loop iteration: detect → scope → plan → execute → verify → loop.
    ///
    /// Returns the number of actions taken (detections admitted + flows advanced).
    pub fn iterate(&mut self, now_ns: u64, client_latency_ns: u64) -> usize {
        self.execute_tick(now_ns, client_latency_ns)
    }

    /// Whether there is pending work.
    #[must_use]
    pub fn has_pending_work(&self) -> bool {
        !self.pending_loss_events.is_empty()
            || self
                .active_recovery_flows
                .values()
                .any(|ctx| ctx.chunks_recovered < ctx.chunks_total)
    }

    /// Number of active recovery flows.
    #[must_use]
    pub fn active_flow_count(&self) -> usize {
        self.active_recovery_flows.len()
    }

    /// Number of flows completed (ready for closeout).
    #[must_use]
    pub fn completed_flow_count(&self) -> usize {
        self.completed_recovery_ids.len()
    }

    /// Flows awaiting cascading-failure-guard admission.
    #[must_use]
    pub fn pending_flow_count(&self) -> usize {
        self.pending_loss_events.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replica_health::ReplicaLagStateRecord;
    use tidefs_replication_model::{
        DegradedVisibilityClass, FlowScopeSelector, ReplicaLagClass, ReplicatedReceiptId,
        ReplicatedSubjectId,
    };

    fn make_lag_record(target: u64, visibility: DegradedVisibilityClass) -> ReplicaLagStateRecord {
        ReplicaLagStateRecord {
            subject_ref: ReplicatedSubjectId(1),
            target_ref: target,
            freshness_fence_frontier: 100,
            lag_class: ReplicaLagClass::SlightlyBehind,
            bytes_behind: 1024,
            oldest_missing_receipt_ref: ReplicatedReceiptId(0),
            degraded_visibility_class: visibility,
        }
    }

    fn make_loss_event(
        lost: Vec<MemberId>,
        available: BTreeMap<MemberId, HealthClass>,
        lag: Vec<ReplicaLagStateRecord>,
    ) -> LossEvent {
        LossEvent {
            loss_event_id: 1,
            loss_class: LossEventClass::NodeFailure,
            degraded_class: RebuildDegradedClass::DegradedReadPossible,
            scope: FlowScopeSelector::Cluster,
            lost_members: lost,
            detected_epoch: 5,
            detected_at_ns: 1_000_000,
            lag_records: lag,
            available_members: available,
            affected_chunk_count: 16,
            affected_bytes: 65536,
        }
    }

    // ── open_rebuild_flow_from_loss_event ──────────────────────────

    #[test]
    fn open_flow_with_healthy_sources() {
        let mut planner = RebuildPlanner::new();
        let lost = vec![MemberId(10)];
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        available.insert(MemberId(2), HealthClass::Healthy);
        let event = make_loss_event(lost, available, vec![]);

        let flow = planner.open_rebuild_flow_from_loss_event(&event).unwrap();
        assert_eq!(flow.rebuild_flow_id, 1);
        assert_eq!(flow.loss_event_ref, 1);
        assert_eq!(flow.loss_event_class, LossEventClass::NodeFailure);
        assert_eq!(flow.state, RebuildFlowState::Open);
        assert_eq!(flow.source_candidate_refs.len(), 2);
        assert_eq!(flow.target_refs, vec![MemberId(10)]);
        assert_eq!(
            flow.degraded_class,
            RebuildDegradedClass::DegradedReadPossible
        );
    }

    #[test]
    fn open_flow_fails_with_no_usable_sources() {
        let mut planner = RebuildPlanner::new();
        let lost = vec![MemberId(1)];
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy); // lost = not a source
        let event = make_loss_event(lost, available, vec![]);

        let result = planner.open_rebuild_flow_from_loss_event(&event);
        assert!(result.is_err());
        // Flow should be recorded as BlockedNoSource
        assert_eq!(planner.flows.len(), 1);
        assert_eq!(
            planner.flow_state(1),
            Some(RebuildFlowState::BlockedNoSource)
        );
    }

    #[test]
    fn open_flow_excludes_lost_members_from_sources() {
        let mut planner = RebuildPlanner::new();
        let lost = vec![MemberId(10)];
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        available.insert(MemberId(10), HealthClass::Healthy); // lost
        let event = make_loss_event(lost, available, vec![]);

        let flow = planner.open_rebuild_flow_from_loss_event(&event).unwrap();
        assert_eq!(flow.source_candidate_refs.len(), 1);
        assert_eq!(flow.source_candidate_refs[0], MemberId(1));
        // lost member 10 should not appear as source
        assert!(!flow.source_candidate_refs.contains(&MemberId(10)));
    }

    #[test]
    fn open_flow_uses_degraded_sources_as_fallback() {
        let mut planner = RebuildPlanner::new();
        let lost = vec![MemberId(10)];
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Suspect); // degraded
        available.insert(MemberId(2), HealthClass::Down); // unavailable
        let event = make_loss_event(lost, available, vec![]);

        let flow = planner.open_rebuild_flow_from_loss_event(&event).unwrap();
        assert_eq!(flow.source_candidate_refs.len(), 1);
        assert_eq!(flow.source_candidate_refs[0], MemberId(1));
    }

    // ── schedule_rebuild_batches_from_witness_sets ──────────────────

    #[test]
    fn schedule_batches_from_open_flow() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        available.insert(MemberId(2), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        let batches = planner
            .schedule_rebuild_batches_from_witness_sets(1, 16)
            .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].rebuild_flow_ref, 1);
        assert_eq!(batches[1].rebuild_flow_ref, 1);
        assert_eq!(planner.flow_state(1), Some(RebuildFlowState::Planning));
    }

    #[test]
    fn schedule_batches_fails_on_non_open_state() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        // Advance past Open
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Planning)
            .unwrap();

        let result = planner.schedule_rebuild_batches_from_witness_sets(1, 16);
        assert!(result.is_err());
    }

    #[test]
    fn schedule_batches_unknown_flow() {
        let mut planner = RebuildPlanner::new();
        let result = planner.schedule_rebuild_batches_from_witness_sets(999, 16);
        assert!(result.is_err());
    }

    // ── advance_rebuild_flow_state ──────────────────────────────────

    #[test]
    fn happy_path_open_to_restored() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Planning)
                .unwrap(),
            RebuildFlowState::Planning
        );
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Transferring)
                .unwrap(),
            RebuildFlowState::Transferring
        );
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Verifying)
                .unwrap(),
            RebuildFlowState::Verifying
        );
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Restored)
                .unwrap(),
            RebuildFlowState::Restored
        );
    }

    #[test]
    fn invalid_transition_rejected() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        // Open → Verifying is invalid (skip steps)
        let result = planner.advance_rebuild_flow_state(1, RebuildFlowState::Verifying);
        assert!(result.is_err());
    }

    #[test]
    fn cancelled_from_any_nonterminal_state() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        // Advance to Planning first, then cancel
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Planning)
            .unwrap();
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Cancelled)
                .unwrap(),
            RebuildFlowState::Cancelled
        );
    }

    #[test]
    fn cancelled_cannot_transition_further() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Cancelled)
            .unwrap();

        let result = planner.advance_rebuild_flow_state(1, RebuildFlowState::Planning);
        assert!(result.is_err());
    }

    #[test]
    fn block_on_no_source_and_retry() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let event = make_loss_event(vec![MemberId(10)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        // Block on no source
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::BlockedNoSource)
                .unwrap(),
            RebuildFlowState::BlockedNoSource
        );
        // Retry via Open
        assert_eq!(
            planner
                .advance_rebuild_flow_state(1, RebuildFlowState::Open)
                .unwrap(),
            RebuildFlowState::Open
        );
    }

    #[test]
    fn unknown_flow_rejected() {
        let mut planner = RebuildPlanner::new();
        let result = planner.advance_rebuild_flow_state(999, RebuildFlowState::Planning);
        assert!(result.is_err());
    }

    // ── Multi-flow scenarios ────────────────────────────────────────

    #[test]
    fn multiple_independent_flows() {
        let mut planner = RebuildPlanner::new();

        // Flow 1: node failure
        let mut avail1: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        avail1.insert(MemberId(1), HealthClass::Healthy);
        let event1 = make_loss_event(vec![MemberId(10)], avail1.clone(), vec![]);
        planner.open_rebuild_flow_from_loss_event(&event1).unwrap();

        // Flow 2: separate disk failure
        let event2 = make_loss_event(vec![MemberId(20)], avail1, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event2).unwrap();

        assert_eq!(planner.flows.len(), 2);
        assert_eq!(planner.flow_state(1), Some(RebuildFlowState::Open));
        assert_eq!(planner.flow_state(2), Some(RebuildFlowState::Open));

        // Advance flow 1 independently
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Planning)
            .unwrap();
        assert_eq!(planner.flow_state(1), Some(RebuildFlowState::Planning));
        assert_eq!(planner.flow_state(2), Some(RebuildFlowState::Open));
    }

    #[test]
    fn active_flow_ids_excludes_restored_and_cancelled() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);

        // Flow 1: complete
        let event = make_loss_event(vec![MemberId(10)], available.clone(), vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Planning)
            .unwrap();
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Transferring)
            .unwrap();
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Verifying)
            .unwrap();
        planner
            .advance_rebuild_flow_state(1, RebuildFlowState::Restored)
            .unwrap();

        // Flow 2: cancelled
        let event2 = make_loss_event(vec![MemberId(20)], available.clone(), vec![]);
        planner.open_rebuild_flow_from_loss_event(&event2).unwrap();
        planner
            .advance_rebuild_flow_state(2, RebuildFlowState::Cancelled)
            .unwrap();

        // Flow 3: still open
        let event3 = make_loss_event(vec![MemberId(30)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event3).unwrap();

        let active = planner.active_flow_ids();
        assert_eq!(active, vec![3]);
    }

    // ── WitnessSet tests ────────────────────────────────────────────

    #[test]
    fn witness_set_healthy_member_is_verified() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert_eq!(witness.verified_sources, vec![MemberId(1)]);
        assert!(witness.degraded_sources.is_empty());
    }

    #[test]
    fn witness_set_suspect_member_is_degraded() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Suspect);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert!(witness.verified_sources.is_empty());
        assert_eq!(witness.degraded_sources, vec![MemberId(1)]);
    }

    #[test]
    fn witness_set_down_member_is_unavailable() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Down);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert_eq!(witness.unavailable_sources, vec![MemberId(1)]);
    }

    #[test]
    fn witness_set_lag_record_overrides_healthy_to_degraded() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let lag = vec![make_lag_record(
            1,
            DegradedVisibilityClass::DegradedReadPossible,
        )];
        let witness = WitnessSet::from_health_and_lag(&available, &lag);
        assert!(witness.verified_sources.is_empty());
        assert_eq!(witness.degraded_sources, vec![MemberId(1)]);
    }

    #[test]
    fn witness_set_best_source_prefers_verified() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(2), HealthClass::Suspect);
        available.insert(MemberId(1), HealthClass::Healthy);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert_eq!(witness.best_source(), Some(MemberId(1)));
    }

    #[test]
    fn witness_set_has_usable_source() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert!(witness.has_usable_source());
    }

    #[test]
    fn witness_set_no_usable_source() {
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Down);
        let witness = WitnessSet::from_health_and_lag(&available, &[]);
        assert!(!witness.has_usable_source());
    }

    // ── RebuildPriority ─────────────────────────────────────────────

    #[test]
    fn priority_from_loss_event_class() {
        assert_eq!(
            RebuildPriority::from(LossEventClass::CorruptionDetected),
            RebuildPriority::CorruptionDetected
        );
        assert_eq!(
            RebuildPriority::from(LossEventClass::AdministrativeDecommission),
            RebuildPriority::Administrative
        );
        assert!(RebuildPriority::CorruptionDetected > RebuildPriority::Administrative);
    }

    // ── Flow count by state ─────────────────────────────────────────

    #[test]
    fn flow_count_by_state_with_mixed_flows() {
        let mut planner = RebuildPlanner::new();
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);

        // Flow 1: Open
        let event = make_loss_event(vec![MemberId(10)], available.clone(), vec![]);
        planner.open_rebuild_flow_from_loss_event(&event).unwrap();

        // Flow 2: Restored
        let event2 = make_loss_event(vec![MemberId(20)], available.clone(), vec![]);
        planner.open_rebuild_flow_from_loss_event(&event2).unwrap();
        planner
            .advance_rebuild_flow_state(2, RebuildFlowState::Planning)
            .unwrap();
        planner
            .advance_rebuild_flow_state(2, RebuildFlowState::Transferring)
            .unwrap();
        planner
            .advance_rebuild_flow_state(2, RebuildFlowState::Verifying)
            .unwrap();
        planner
            .advance_rebuild_flow_state(2, RebuildFlowState::Restored)
            .unwrap();

        // Flow 3: Open
        let event3 = make_loss_event(vec![MemberId(30)], available, vec![]);
        planner.open_rebuild_flow_from_loss_event(&event3).unwrap();

        assert_eq!(planner.flow_count_by_state(RebuildFlowState::Open), 2);
        assert_eq!(planner.flow_count_by_state(RebuildFlowState::Restored), 1);
        assert_eq!(planner.flow_count_by_state(RebuildFlowState::Cancelled), 0);
    }

    // ── RebuildTrigger ──────────────────────────────────────────

    #[test]
    fn rebuild_trigger_node_loss_is_urgent() {
        let trigger = RebuildTrigger::NodeLoss {
            suspect_event_id: 1,
            lost_node_id: NodeId(10),
        };
        assert!(trigger.is_urgent());
        assert!(trigger.may_preempt_product_work());
    }

    #[test]
    fn rebuild_trigger_anti_entropy_repair_preempts_work() {
        let trigger = RebuildTrigger::AntiEntropyRepair {
            repair_ticket_id: 100,
        };
        assert!(!trigger.is_urgent());
        assert!(trigger.may_preempt_product_work());
    }

    #[test]
    fn rebuild_trigger_operator_initiated_not_urgent() {
        let trigger = RebuildTrigger::OperatorInitiated {
            reason: "decommission".to_string(),
        };
        assert!(!trigger.is_urgent());
        assert!(!trigger.may_preempt_product_work());
    }

    // ── RebuildPhase ────────────────────────────────────────────

    #[test]
    fn rebuild_phase_terminal_states() {
        assert!(RebuildPhase::Complete.is_terminal());
        assert!(RebuildPhase::Cancelled.is_terminal());
        assert!(!RebuildPhase::Planned.is_terminal());
        assert!(!RebuildPhase::Inflight.is_terminal());
    }

    #[test]
    fn rebuild_phase_active_states() {
        assert!(RebuildPhase::SourceSelection.is_active());
        assert!(RebuildPhase::Inflight.is_active());
        assert!(RebuildPhase::Verifying.is_active());
        assert!(RebuildPhase::Committing.is_active());
        assert!(!RebuildPhase::Planned.is_active());
        assert!(!RebuildPhase::Complete.is_active());
    }

    #[test]
    fn rebuild_phase_blocked() {
        assert!(RebuildPhase::Paused.is_blocked());
        assert!(!RebuildPhase::Inflight.is_blocked());
        assert!(!RebuildPhase::Complete.is_blocked());
    }

    // ── RebuildChunkPriority ────────────────────────────────────

    #[test]
    fn chunk_priority_ordering() {
        assert!(RebuildChunkPriority::DegradedRead < RebuildChunkPriority::QuorumLost);
        assert!(RebuildChunkPriority::QuorumLost < RebuildChunkPriority::QuorumReduced);
        assert!(RebuildChunkPriority::QuorumReduced < RebuildChunkPriority::Background);
    }

    // ── ChunkSource ─────────────────────────────────────────────

    #[test]
    fn chunk_source_single_primary() {
        let source = ChunkSource::SingleSource {
            node_id: NodeId(42),
        };
        assert_eq!(source.primary_source(), Some(NodeId(42)));
        assert_eq!(source.all_sources(), vec![NodeId(42)]);
    }

    #[test]
    fn chunk_source_reconstruction_primary() {
        let source = ChunkSource::Reconstruction {
            sources: vec![NodeId(1), NodeId(2), NodeId(3)],
        };
        assert_eq!(source.primary_source(), Some(NodeId(1)));
        assert_eq!(source.all_sources(), vec![NodeId(1), NodeId(2), NodeId(3)]);
    }

    #[test]
    fn chunk_source_reconstruction_empty() {
        let source = ChunkSource::Reconstruction { sources: vec![] };
        assert_eq!(source.primary_source(), None);
        assert!(source.all_sources().is_empty());
    }

    // ── RebuildProgress ─────────────────────────────────────────

    #[test]
    fn rebuild_progress_initial_state() {
        let progress = RebuildProgress::new(100, 1_000_000);
        assert_eq!(progress.total_chunks, 100);
        assert_eq!(progress.completed_chunks, 0);
        assert_eq!(progress.total_bytes, 1_000_000);
        assert_eq!(progress.bytes_transferred, 0);
        assert_eq!(progress.chunks_remaining(), 100);
        assert_eq!(progress.bytes_remaining(), 1_000_000);
        assert_eq!(progress.fraction_complete(), 0.0);
    }

    #[test]
    fn rebuild_progress_record_completed() {
        let mut progress = RebuildProgress::new(10, 10_000);
        progress.record_chunk_completed(1_000, RebuildChunkPriority::QuorumLost, 1_000_000);
        assert_eq!(progress.completed_chunks, 1);
        assert_eq!(progress.bytes_transferred, 1_000);
        assert_eq!(progress.chunks_remaining(), 9);
        assert_eq!(progress.bytes_remaining(), 9_000);
        assert_eq!(progress.fraction_complete(), 0.1);
        assert_eq!(progress.last_updated_ns, 1_000_000);
    }

    #[test]
    fn rebuild_progress_record_failed() {
        let mut progress = RebuildProgress::new(10, 10_000);
        progress.record_chunks_inflight(1);
        progress.record_chunk_failed(RebuildChunkPriority::Background, 2_000_000);
        assert_eq!(progress.chunks_failed, 1);
        assert_eq!(progress.chunks_inflight, 0);
    }

    #[test]
    fn rebuild_progress_throughput_and_eta() {
        let mut progress = RebuildProgress::new(100, 1_000_000_000);
        // Transfer 500 MB in 10 seconds
        progress.record_chunk_completed(
            500_000_000,
            RebuildChunkPriority::Background,
            10_000_000_000,
        );
        let throughput = progress.estimated_throughput(10_000_000_000);
        assert!((throughput - 50_000_000.0).abs() < 1_000_000.0); // ~50 MB/s
        let eta = progress.eta_seconds(10_000_000_000);
        assert!(eta.is_some());
        assert!((eta.unwrap() - 10.0).abs() < 1.0); // ~10s remaining
    }

    #[test]
    fn rebuild_progress_zero_chunks() {
        let progress = RebuildProgress::new(0, 0);
        assert_eq!(progress.fraction_complete(), 1.0);
        assert_eq!(progress.chunks_remaining(), 0);
    }

    // ── RebuildBackpressure ─────────────────────────────────────

    #[test]
    fn backpressure_inactive_when_latency_ok() {
        let mut bp = RebuildBackpressure::new(100_000_000, 10_000_000);
        let active = bp.evaluate(50_000_000, 1_000_000_000);
        assert!(!active);
        assert!(!bp.is_throttled());
        assert_eq!(bp.effective_throttle(), 0);
    }

    #[test]
    fn backpressure_active_when_latency_exceeds_threshold() {
        let mut bp = RebuildBackpressure::new(100_000_000, 10_000_000);
        let active = bp.evaluate(150_000_000, 1_000_000_000);
        assert!(active);
        assert!(bp.is_throttled());
        assert_eq!(bp.effective_throttle(), 10_000_000);
    }

    // ── BackfillState ───────────────────────────────────────────

    #[test]
    fn backfill_state_urgent_when_stale() {
        let state = BackfillState::new(
            NodeId(1),
            BytesBehind(500_000_000),
            vec![ChunkId(100), ChunkId(101)],
            vec![NodeId(2)],
            1_000_000_000,
            tidefs_replication_model::ReplicaLagClass::Stale,
        );
        assert!(state.is_urgent());
        assert_eq!(state.chunk_count(), 2);
        assert!(state.has_sources());
    }

    #[test]
    fn backfill_state_not_urgent_when_current() {
        let state = BackfillState::new(
            NodeId(1),
            BytesBehind(0),
            vec![],
            vec![],
            1_000_000_000,
            tidefs_replication_model::ReplicaLagClass::Current,
        );
        assert!(!state.is_urgent());
        assert_eq!(state.chunk_count(), 0);
        assert!(!state.has_sources());
    }

    // ── CapacityRebalanceSkew ───────────────────────────────────

    #[test]
    fn rebalance_needed_when_skew_exceeds_threshold() {
        let skew = CapacityRebalanceSkew::new(
            vec![NodeId(1)],
            vec![NodeId(2)],
            30,
            20,
            1_000_000,
            100,
            1_000_000_000,
        );
        assert!(skew.is_rebalance_needed());
        assert!(skew.has_viable_movement());
    }

    #[test]
    fn rebalance_not_needed_within_threshold() {
        let skew = CapacityRebalanceSkew::new(vec![], vec![], 10, 20, 0, 0, 1_000_000_000);
        assert!(!skew.is_rebalance_needed());
        assert!(!skew.has_viable_movement());
    }

    #[test]
    fn rebalance_no_viable_movement_when_no_sources() {
        let skew = CapacityRebalanceSkew::new(
            vec![],
            vec![NodeId(2)],
            30,
            20,
            1_000_000,
            100,
            1_000_000_000,
        );
        assert!(!skew.has_viable_movement());
    }

    // ── classify_lag_for_backfill ───────────────────────────────

    #[test]
    fn classify_lag_current() {
        assert_eq!(
            classify_lag_for_backfill(0),
            tidefs_replication_model::ReplicaLagClass::Current
        );
    }

    #[test]
    fn classify_lag_slightly_behind() {
        assert_eq!(
            classify_lag_for_backfill(500_000),
            tidefs_replication_model::ReplicaLagClass::SlightlyBehind
        );
    }

    #[test]
    fn classify_lag_severely_behind() {
        assert_eq!(
            classify_lag_for_backfill(20_000_000),
            tidefs_replication_model::ReplicaLagClass::SeverelyBehind
        );
    }

    #[test]
    fn classify_lag_stale() {
        assert_eq!(
            classify_lag_for_backfill(300_000_000),
            tidefs_replication_model::ReplicaLagClass::Stale
        );
    }

    // ── Source selection with failure domains ────────────────────

    #[test]
    fn source_selection_cross_domain_preference() {
        let planner = RebuildPlanner::new();
        let source_candidates = vec![NodeId(1), NodeId(2)];
        let target_nodes = vec![NodeId(3)];

        let mut domains: BTreeMap<NodeId, tidefs_membership_epoch::DomainId> = BTreeMap::new();
        domains.insert(NodeId(1), tidefs_membership_epoch::DomainId::new(10));
        domains.insert(NodeId(2), tidefs_membership_epoch::DomainId::new(20));
        domains.insert(NodeId(3), tidefs_membership_epoch::DomainId::new(10));

        let result = planner.select_sources_with_failure_domain_separation(
            &source_candidates,
            &target_nodes,
            &domains,
        );

        // Target node 3 is in domain 10, source 2 is in domain 20 (cross-domain preferred)
        assert_eq!(result.get(&NodeId(3)).unwrap(), &vec![NodeId(2)]);
    }

    #[test]
    fn source_selection_fallback_same_domain() {
        let planner = RebuildPlanner::new();
        let source_candidates = vec![NodeId(1)];
        let target_nodes = vec![NodeId(3)];

        let mut domains: BTreeMap<NodeId, tidefs_membership_epoch::DomainId> = BTreeMap::new();
        domains.insert(NodeId(1), tidefs_membership_epoch::DomainId::new(10));
        domains.insert(NodeId(3), tidefs_membership_epoch::DomainId::new(10));

        let result = planner.select_sources_with_failure_domain_separation(
            &source_candidates,
            &target_nodes,
            &domains,
        );

        // Only same-domain source available — fallback
        assert_eq!(result.get(&NodeId(3)).unwrap(), &vec![NodeId(1)]);
    }

    // ── Backfill detection ──────────────────────────────────────

    #[test]
    fn detect_backfill_for_lagged_node() {
        let planner = RebuildPlanner::new();
        let lag_records = vec![
            ReplicaLagStateRecord::new(
                tidefs_replication_model::ReplicatedSubjectId(100),
                1,
                100,
                tidefs_replication_model::ReplicaLagClass::ModeratelyBehind,
                10_000_000,
            ),
            ReplicaLagStateRecord::new(
                tidefs_replication_model::ReplicatedSubjectId(200),
                1,
                100,
                tidefs_replication_model::ReplicaLagClass::ModeratelyBehind,
                5_000_000,
            ),
        ];

        let state = planner.detect_stale_chunks_for_backfill(
            NodeId(1),
            &lag_records,
            BytesBehind(15_000_000),
            &[NodeId(2)],
            1_000_000_000,
        );

        assert_eq!(state.target_node, NodeId(1));
        assert_eq!(state.bytes_behind, BytesBehind(15_000_000));
        assert_eq!(state.chunk_count(), 2);
        assert!(state.has_sources());
    }

    // ── Capacity skew detection ─────────────────────────────────

    #[test]
    fn detect_capacity_skew_needs_rebalance() {
        let planner = RebuildPlanner::new();
        let mut node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        node_util.insert(NodeId(1), 90); // 90% utilized (over)
        node_util.insert(NodeId(2), 40); // 40% utilized (under)
        node_util.insert(NodeId(3), 60); // 60% utilized

        let skew = planner.detect_capacity_skew_for_rebalance(
            &node_util,
            20,
            1_000_000_000,
            1_000_000_000,
        );

        assert!(skew.is_some());
        let s = skew.unwrap();
        assert!(s.is_rebalance_needed());
        assert!(s.has_viable_movement());
        assert_eq!(s.max_utilization_delta_pct, 50);
    }

    #[test]
    fn detect_capacity_skew_balanced() {
        let planner = RebuildPlanner::new();
        let mut node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        node_util.insert(NodeId(1), 55);
        node_util.insert(NodeId(2), 50);
        node_util.insert(NodeId(3), 52);

        let skew = planner.detect_capacity_skew_for_rebalance(
            &node_util,
            20,
            1_000_000_000,
            1_000_000_000,
        );

        assert!(skew.is_none());
    }

    #[test]
    fn detect_capacity_skew_empty_cluster() {
        let planner = RebuildPlanner::new();
        let node_util: BTreeMap<NodeId, u64> = BTreeMap::new();

        let skew = planner.detect_capacity_skew_for_rebalance(
            &node_util,
            20,
            1_000_000_000,
            1_000_000_000,
        );

        assert!(skew.is_none());
    }

    // ── Object enumeration integration tests ─────────────────────

    #[test]
    fn compute_deltas_from_enumeration_all_current() {
        let planner = RebuildPlanner::new();
        let enumeration = vec![
            tidefs_transport::ObjectPlacementEntry::new(
                1,
                MemberId(10),
                tidefs_transport::ShardKind::Primary,
            ),
            tidefs_transport::ObjectPlacementEntry::new(
                1,
                MemberId(20),
                tidefs_transport::ShardKind::Replica,
            ),
        ];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(MemberId(10), [1].into());
        current.insert(MemberId(20), [1].into());

        let deltas = planner.compute_object_deltas_from_enumeration(&enumeration, &current);
        assert!(!deltas[&MemberId(10)].has_work());
        assert!(!deltas[&MemberId(20)].has_work());
    }

    #[test]
    fn compute_deltas_from_enumeration_missing_and_excess() {
        let planner = RebuildPlanner::new();
        let enumeration = vec![
            tidefs_transport::ObjectPlacementEntry::new(
                42,
                MemberId(1),
                tidefs_transport::ShardKind::Primary,
            ),
            tidefs_transport::ObjectPlacementEntry::new(
                99,
                MemberId(2),
                tidefs_transport::ShardKind::Primary,
            ),
        ];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(MemberId(1), [99].into());
        current.insert(MemberId(2), BTreeSet::new());

        let deltas = planner.compute_object_deltas_from_enumeration(&enumeration, &current);

        assert_eq!(deltas[&MemberId(1)].missing, [42].into());
        assert_eq!(deltas[&MemberId(1)].excess, [99].into());
        assert!(deltas[&MemberId(1)].has_work());

        assert_eq!(deltas[&MemberId(2)].missing, [99].into());
        assert!(deltas[&MemberId(2)].excess.is_empty());
        assert!(deltas[&MemberId(2)].has_work());
    }

    #[test]
    fn nodes_needing_work_filters_non_work() {
        let enumeration = vec![
            tidefs_transport::ObjectPlacementEntry::new(
                1,
                MemberId(10),
                tidefs_transport::ShardKind::Primary,
            ),
            tidefs_transport::ObjectPlacementEntry::new(
                2,
                MemberId(20),
                tidefs_transport::ShardKind::Primary,
            ),
        ];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(MemberId(10), [1].into());
        current.insert(MemberId(20), BTreeSet::new());

        let needy = RebuildPlanner::nodes_needing_work(&enumeration, &current);
        assert_eq!(needy.len(), 1);
        assert!(needy.contains(&MemberId(20)));
        assert!(!needy.contains(&MemberId(10)));
    }

    #[test]
    fn nodes_needing_work_empty_when_all_current() {
        let enumeration = vec![tidefs_transport::ObjectPlacementEntry::new(
            7,
            MemberId(1),
            tidefs_transport::ShardKind::Primary,
        )];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(MemberId(1), [7].into());

        let needy = RebuildPlanner::nodes_needing_work(&enumeration, &current);
        assert!(needy.is_empty());
    }

    #[test]
    fn nodes_needing_work_empty_enumeration() {
        let enumeration: Vec<tidefs_transport::ObjectPlacementEntry> = vec![];
        let current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();

        let needy = RebuildPlanner::nodes_needing_work(&enumeration, &current);
        assert!(needy.is_empty());

        // ── Layout-driven admission tests ─────────────────────────────
    }

    // ── redundancy_headroom ────────────────────────────────────

    #[test]
    fn headroom_mirror_3_copies() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        assert_eq!(redundancy_headroom(&layout), 2);
    }

    #[test]
    fn headroom_mirror_1_copy() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        assert_eq!(redundancy_headroom(&layout), 0);
    }

    #[test]
    fn headroom_erasure_8_3() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        assert_eq!(redundancy_headroom(&layout), 3);
    }

    #[test]
    fn headroom_is_max_tolerable_failures() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        assert_eq!(
            redundancy_headroom(&layout),
            max_tolerable_failures(&layout)
        );
    }

    // ── evaluate_layout_survivability: local (device) failure domain ──

    #[test]
    fn survivability_mirror_3_survives_2_device() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let s = evaluate_layout_survivability(&layout, 2, 0);
        assert!(s.can_survive);
        assert_eq!(s.redundancy_headroom, 2);
        assert!(s.degraded_reads_possible);
        assert!(!s.needs_rebuild);
        assert!(s.needs_backfill);
    }

    #[test]
    fn survivability_mirror_2_survives_1_device() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let s = evaluate_layout_survivability(&layout, 1, 0);
        assert!(s.can_survive);
        assert_eq!(s.redundancy_headroom, 1);
        assert!(!s.needs_rebuild);
        assert!(s.needs_backfill);
    }

    #[test]
    fn survivability_mirror_2_fails_2_devices() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let s = evaluate_layout_survivability(&layout, 2, 0);
        assert!(!s.can_survive);
        assert!(!s.degraded_reads_possible);
    }

    #[test]
    fn survivability_mirror_1_fails_any() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        assert!(!evaluate_layout_survivability(&layout, 1, 0).can_survive);
        assert!(evaluate_layout_survivability(&layout, 0, 0).can_survive);
    }

    // ── evaluate_layout_survivability: node failure domain ──

    #[test]
    fn survivability_erasure_8_3_survives_3_node() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let s = evaluate_layout_survivability(&layout, 0, 3);
        assert!(s.can_survive);
        assert_eq!(s.redundancy_headroom, 3);
    }

    #[test]
    fn survivability_erasure_8_3_fails_4_node() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let s = evaluate_layout_survivability(&layout, 0, 4);
        assert!(!s.can_survive);
    }

    #[test]
    fn survivability_mixed_device_and_node() {
        let layout = DurabilityLayoutV1::mirror(5).unwrap();
        let s = evaluate_layout_survivability(&layout, 2, 2);
        assert!(s.can_survive);
    }

    #[test]
    fn survivability_mixed_exceeds_headroom() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let s = evaluate_layout_survivability(&layout, 2, 0);
        assert!(!s.can_survive);
    }
    // ── check_rebuild_admission ──────────────────────────────────

    #[test]
    fn rebuild_admitted_when_cannot_survive() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 2, 0, 3);
        assert!(decision.admitted);
    }

    #[test]
    fn rebuild_admitted_when_headroom_zero() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 0, 0, 3);
        assert!(decision.admitted);
    }

    #[test]
    fn rebuild_deferred_when_would_survive() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 1, 0, 3);
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason,
            AdmissionRejectionReason::LayoutWouldSurviveLoss
        );
    }

    #[test]
    fn rebuild_rejected_no_sources() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 2, 0, 0);
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason,
            AdmissionRejectionReason::InsufficientSources
        );
    }

    #[test]
    fn rebuild_rejected_unknown_layout() {
        let decision = check_rebuild_admission(None, 1, 0, 3);
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason,
            AdmissionRejectionReason::UnknownLayoutVersion
        );
    }

    #[test]
    fn rebuild_erasure_admitted_cannot_survive_nodes() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 0, 4, 5);
        assert!(decision.admitted);
    }

    #[test]
    fn rebuild_erasure_deferred_survives() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let decision = check_rebuild_admission(Some(&layout), 0, 2, 5);
        assert!(!decision.admitted);
    }

    // ── check_backfill_admission ─────────────────────────────────

    #[test]
    fn backfill_admitted_for_stale() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            500_000_000,
            2,
            tidefs_replication_model::ReplicaLagClass::Stale,
        );
        assert!(decision.admitted);
    }

    #[test]
    fn backfill_admitted_for_severely_behind() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            200_000_000,
            2,
            tidefs_replication_model::ReplicaLagClass::SeverelyBehind,
        );
        assert!(decision.admitted);
    }

    #[test]
    fn backfill_admitted_for_moderately_behind() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            10_000_000,
            2,
            tidefs_replication_model::ReplicaLagClass::ModeratelyBehind,
        );
        assert!(decision.admitted);
    }

    #[test]
    fn backfill_admitted_slightly_behind_low_headroom() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            500_000,
            2,
            tidefs_replication_model::ReplicaLagClass::SlightlyBehind,
        );
        assert!(decision.admitted);
    }

    #[test]
    fn backfill_deferred_slightly_behind_sufficient_headroom() {
        let layout = DurabilityLayoutV1::mirror(5).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            500_000,
            2,
            tidefs_replication_model::ReplicaLagClass::SlightlyBehind,
        );
        assert!(!decision.admitted);
    }

    #[test]
    fn backfill_deferred_current() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            0,
            2,
            tidefs_replication_model::ReplicaLagClass::Current,
        );
        assert!(!decision.admitted);
    }

    #[test]
    fn backfill_rejected_no_sources() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let decision = check_backfill_admission(
            Some(&layout),
            500_000_000,
            0,
            tidefs_replication_model::ReplicaLagClass::Stale,
        );
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason,
            AdmissionRejectionReason::InsufficientSources
        );
    }

    #[test]
    fn backfill_rejected_unknown_layout() {
        let decision = check_backfill_admission(
            None,
            0,
            2,
            tidefs_replication_model::ReplicaLagClass::Current,
        );
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason,
            AdmissionRejectionReason::UnknownLayoutVersion
        );
    }

    // ── RecoveryLoop with durability layout ──────────────────────

    #[test]
    fn loop_with_mirror_rejects_survivable_loss() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let mut loop_ = RecoveryLoop::with_layout(2, 5, 20, 100_000_000, 10_000_000, Some(layout));
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(1), HealthClass::Healthy);
        available.insert(MemberId(2), HealthClass::Healthy);
        available.insert(MemberId(3), HealthClass::Healthy);
        let event = LossEvent {
            loss_event_id: 1,
            loss_class: LossEventClass::NodeFailure,
            degraded_class: RebuildDegradedClass::DegradedReadOnly,
            scope: FlowScopeSelector::Cluster,
            lost_members: vec![MemberId(1)],
            detected_epoch: 1,
            detected_at_ns: 1_000_000_000,
            lag_records: vec![],
            available_members: available,
            affected_chunk_count: 10,
            affected_bytes: 100_000,
        };
        let admitted = loop_.detect_loss(event, 1_000_000_000);
        assert!(!admitted);
        assert_eq!(loop_.pending_loss_events.len(), 1);
    }

    #[test]
    fn loop_with_mirror_admits_unsurvivable() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let mut loop_ = RecoveryLoop::with_layout(2, 5, 20, 100_000_000, 10_000_000, Some(layout));
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(3), HealthClass::Healthy);
        let event = LossEvent {
            loss_event_id: 2,
            loss_class: LossEventClass::NodeFailure,
            degraded_class: RebuildDegradedClass::FullyUnavailable,
            scope: FlowScopeSelector::Cluster,
            lost_members: vec![MemberId(1), MemberId(2)],
            detected_epoch: 1,
            detected_at_ns: 1_000_000_000,
            lag_records: vec![],
            available_members: available,
            affected_chunk_count: 10,
            affected_bytes: 100_000,
        };
        let admitted = loop_.detect_loss(event, 1_000_000_000);
        assert!(admitted);
        assert_eq!(loop_.active_recovery_flows.len(), 1);
    }

    #[test]
    fn loop_without_layout_uses_default() {
        let mut loop_ = RecoveryLoop::new(2, 5, 20, 100_000_000, 10_000_000);
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(2), HealthClass::Healthy);
        let event = LossEvent {
            loss_event_id: 3,
            loss_class: LossEventClass::NodeFailure,
            degraded_class: RebuildDegradedClass::DegradedReadOnly,
            scope: FlowScopeSelector::Cluster,
            lost_members: vec![MemberId(1)],
            detected_epoch: 1,
            detected_at_ns: 1_000_000_000,
            lag_records: vec![],
            available_members: available,
            affected_chunk_count: 10,
            affected_bytes: 100_000,
        };
        let admitted = loop_.detect_loss(event, 1_000_000_000);
        assert!(admitted);
    }

    #[test]
    fn loop_with_erasure_node_failure_domain() {
        // erasure(4,2): headroom=2. 4 node failures exceed headroom, must rebuild.
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let mut loop_ = RecoveryLoop::with_layout(3, 5, 20, 100_000_000, 10_000_000, Some(layout));
        let mut available: BTreeMap<MemberId, HealthClass> = BTreeMap::new();
        available.insert(MemberId(5), HealthClass::Healthy);
        available.insert(MemberId(6), HealthClass::Healthy);
        let event = LossEvent {
            loss_event_id: 4,
            loss_class: LossEventClass::NodeFailure,
            degraded_class: RebuildDegradedClass::FullyUnavailable,
            scope: FlowScopeSelector::Cluster,
            lost_members: vec![MemberId(1), MemberId(2), MemberId(3), MemberId(4)],
            detected_epoch: 1,
            detected_at_ns: 1_000_000_000,
            lag_records: vec![],
            available_members: available,
            affected_chunk_count: 50,
            affected_bytes: 500_000,
        };
        let admitted = loop_.detect_loss(event, 1_000_000_000);
        assert!(admitted, "4 failures against headroom=2 must admit rebuild");
    }
}
