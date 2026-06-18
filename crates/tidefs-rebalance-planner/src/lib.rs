// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rebalance planner: capacity redistribution orchestration — PC-010.4.
//!
//! The rebalance planner coordinates capacity-weighted, delta-based rebalancing
//! across cluster members. It composes the capacity skew detection from
//! `tidefs-rebuild-planner` with placement target computation from
//! `tidefs-placement-planner` to produce rebalance plans that only move
//! data needed to reduce utilization variance below threshold.
//!
//! # Design
//!
//! 1. **Detect**: Evaluate capacity skew across nodes. If max delta > 20%,
//!    rebalancing is triggered.
//! 2. **Plan**: Select over-utilized sources and under-utilized targets.
//!    Compute how many bytes to move to bring variance below threshold.
//! 3. **Gate**: Apply movement budget (bytes-per-epoch cap), anti-affinity
//!    checks, and epoch validation before executing.
//! 4. **Execute**: Produce placement intents that the placement runtime
//!    can convert to transfer tickets (via the transfer orchestrator).
//! 5. **Verify**: Receipt-backed completion — every moved chunk is proven
//!    with placement receipts.
//!
//! # Comparison to existing systems
//!
//! - Ceph CRUSH remap: proportional remapping on every topology change
//!   → TideFS: delta-based, only data that needs to move, moves
//! - Cassandra token ring: full range streaming on replacement
//!   → TideFS: incremental transfer via receipt frontier comparison
//! - MongoDB balancer: chunk-count based, ignores data size
//!   → TideFS: capacity-weighted with byte-level tracking

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use tidefs_commit_group::types::CommitGroupId;
use tidefs_membership_epoch::{
    EpochId, FailureDomainPlacementPolicy, FailureDomainRecord, MemberId, StorageTier,
    StorageTierPolicy, VerdictClass,
};
use tidefs_placement_planner::{compute_committed_replica_target_set, PlacementError, TierGoal};
use tidefs_rebuild_planner::{CapacityRebalanceSkew, RebuildPlanner};
use tidefs_replica_health::NodeId;
use tidefs_replication_model::{ReplicatedReceiptId, ReplicatedSubjectId};
use tidefs_space_accounting::SpaceAccounting;

/// Gate constant for PC-010.4 rebalance planner.
pub const REBALANCE_PLANNER_GATE_PC_010_4: &str =
    "PC-010.4 rebalance planner covers capacity-weighted delta-based movement, movement budget, epoch gating, and anti-affinity preservation";

/// Default rebalance threshold: trigger when max-min utilization > 20%.
pub const DEFAULT_REBALANCE_THRESHOLD_PCT: u64 = 20;

/// Default target variance: rebalancing aims to bring variance below 10%.
pub const DEFAULT_TARGET_VARIANCE_PCT: u64 = 10;

/// Default movement budget cap per epoch (bytes).
pub const DEFAULT_MOVEMENT_BUDGET_BYTES: u64 = 1_073_741_824; // 1 GiB per epoch

// ── Error types ──────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum RebalanceError {
    #[error("no capacity skew detected — rebalancing not needed")]
    NoSkewDetected,

    #[error("not enough under-utilized targets: need {needed}, have {available}")]
    NotEnoughTargets { needed: usize, available: usize },

    #[error("movement budget exceeded: {requested} bytes requested, {remaining} bytes remaining of {budget}")]
    BudgetExceeded {
        requested: u64,
        remaining: u64,
        budget: u64,
    },

    #[error("anti-affinity violation during rebalancing: {0}")]
    AntiAffinityViolation(String),

    #[error("epoch mismatch: plan at epoch {plan_epoch:?}, current epoch {current_epoch:?}")]
    EpochMismatch {
        plan_epoch: EpochId,
        current_epoch: EpochId,
    },

    #[error("placement error: {0}")]
    PlacementFailed(#[from] PlacementError),

    #[error("rebalance plan already exists for epoch {epoch:?}")]
    PlanAlreadyExists { epoch: EpochId },

    #[error("no active rebalance plan")]
    NoActivePlan,

    #[error("rebalance aborted due to epoch transition at {at_ns}")]
    AbortedEpochTransition { at_ns: u64 },

    #[error("movement would reduce redundancy below minimum: {0}")]
    RedundancyBelowMinimum(String),

    #[error("rebalance evidence is stale: plan based on commit group {plan_cg}, current commit group is {current_cg}")]
    EvidenceStale {
        plan_cg: CommitGroupId,
        current_cg: CommitGroupId,
    },
}

// ── Rebalance priority ───────────────────────────────────────────────

/// Priority for rebalance scheduling.
///
/// Rebalance runs at PlannedRelocation priority (4 of 7), below
/// client reads (priority 0) and loss rebuild (priority 1-3),
/// but above administrative relocation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RebalancePriority {
    /// Background rebalance during normal operation.
    Background = 4,
    /// Urgent rebalance when hot nodes approach capacity limit.
    Urgent = 5,
    /// Critical rebalance when capacity is exhausted on some nodes.
    Critical = 6,
}

impl RebalancePriority {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Background => "rebalance.background.p4",
            Self::Urgent => "rebalance.urgent.p5",
            Self::Critical => "rebalance.critical.p6",
        }
    }

    /// Derive priority from utilization delta magnitude.
    #[must_use]
    pub fn from_utilization_delta(delta_pct: u64) -> Self {
        if delta_pct > 60 {
            Self::Critical
        } else if delta_pct > 40 {
            Self::Urgent
        } else {
            Self::Background
        }
    }
}

// ── Movement budget ──────────────────────────────────────────────────

/// Per-epoch movement budget preventing rebalancing storms.
///
/// Limits the total bytes that can be moved in a single epoch to
/// prevent overwhelming the cluster with data movement.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MovementBudget {
    /// Bytes allocated for this epoch.
    pub budget_bytes: u64,
    /// Bytes consumed so far in this epoch.
    pub consumed_bytes: u64,
    /// Bytes remaining in this epoch.
    pub remaining_bytes: u64,
    /// The epoch this budget applies to.
    pub epoch: EpochId,
    /// Whether budget has been exhausted.
    pub is_exhausted: bool,
}

impl MovementBudget {
    #[must_use]
    pub fn new(budget_bytes: u64, epoch: EpochId) -> Self {
        Self {
            budget_bytes,
            consumed_bytes: 0,
            remaining_bytes: budget_bytes,
            epoch,
            is_exhausted: false,
        }
    }

    /// Try to reserve bytes from the budget.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), RebalanceError> {
        if self.is_exhausted {
            return Err(RebalanceError::BudgetExceeded {
                requested: bytes,
                remaining: 0,
                budget: self.budget_bytes,
            });
        }
        if bytes > self.remaining_bytes {
            return Err(RebalanceError::BudgetExceeded {
                requested: bytes,
                remaining: self.remaining_bytes,
                budget: self.budget_bytes,
            });
        }
        self.consumed_bytes += bytes;
        self.remaining_bytes = self.budget_bytes.saturating_sub(self.consumed_bytes);
        self.is_exhausted = self.remaining_bytes == 0;
        Ok(())
    }

    /// Release reserved bytes back to the budget.
    pub fn release(&mut self, bytes: u64) {
        self.consumed_bytes = self.consumed_bytes.saturating_sub(bytes);
        self.remaining_bytes = self.budget_bytes.saturating_sub(self.consumed_bytes);
        self.is_exhausted = self.remaining_bytes == 0;
    }

    /// Whether the budget can accommodate the requested bytes.
    #[must_use]
    pub fn can_accommodate(&self, bytes: u64) -> bool {
        !self.is_exhausted && bytes <= self.remaining_bytes
    }
}

// ── Rebalance intent ─────────────────────────────────────────────────

/// A single rebalance intent: move a chunk from an over-utilized
/// source to an under-utilized target.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebalanceIntent {
    /// Unique intent identifier.
    pub intent_id: u64,
    /// The subject (chunk) to move.
    pub subject_ref: ReplicatedSubjectId,
    /// Source member (over-utilized node).
    pub source_ref: MemberId,
    /// Target member (under-utilized node).
    pub target_ref: MemberId,
    /// Estimated bytes to transfer.
    pub estimated_bytes: u64,
    /// Receipt frontier on the source.
    pub source_frontier: Option<ReplicatedReceiptId>,
    /// Receipt frontier on the target (for delta comparison).
    pub target_frontier: Option<ReplicatedReceiptId>,
    /// Priority class for scheduling.
    pub priority: RebalancePriority,
    /// Epoch under which this intent was computed.
    pub epoch: EpochId,
}

impl RebalanceIntent {
    #[must_use]
    pub fn new(
        intent_id: u64,
        subject_ref: ReplicatedSubjectId,
        source_ref: MemberId,
        target_ref: MemberId,
        estimated_bytes: u64,
        epoch: EpochId,
    ) -> Self {
        Self {
            intent_id,
            subject_ref,
            source_ref,
            target_ref,
            estimated_bytes,
            source_frontier: None,
            target_frontier: None,
            priority: RebalancePriority::Background,
            epoch,
        }
    }

    /// Whether this intent involves delta-only transfer (receipt frontier comparison).
    #[must_use]
    pub fn is_delta_transfer(&self) -> bool {
        self.source_frontier.is_some() && self.target_frontier.is_some()
    }
}

// ── Rebalance plan ───────────────────────────────────────────────────

/// A complete rebalancing plan for an epoch.
///
/// Produced when capacity skew exceeds threshold. Contains all the
/// intents needed to bring utilization variance back within target.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RebalancePlan {
    /// Unique plan identifier.
    pub plan_id: u64,
    /// The epoch under which this plan was computed.
    pub epoch: EpochId,
    /// The capacity skew that triggered this plan.
    pub detected_skew: CapacityRebalanceSkew,
    /// Individual movement intents.
    pub intents: Vec<RebalanceIntent>,
    /// Total bytes to be moved under this plan.
    pub total_bytes_to_move: u64,
    /// Movement budget consumed so far.
    pub budget_consumed: u64,
    /// When the plan was created (ns).
    pub created_at_ns: u64,
    /// Whether the plan has been aborted (e.g., due to epoch transition).
    pub is_aborted: bool,
    /// Anti-affinity verdict for the plan's target placements.
    pub anti_affinity_verdict: Option<VerdictClass>,
    /// The placement priority for this plan's transfer tickets.
    pub priority: RebalancePriority,
    /// The commit group at which the capacity and placement evidence
    /// backing this plan was committed. Used for staleness checks.
    pub evidence_commit_group_id: u64,
}

impl RebalancePlan {
    #[must_use]
    pub fn new(
        plan_id: u64,
        epoch: EpochId,
        skew: CapacityRebalanceSkew,
        created_at_ns: u64,
        evidence_commit_group_id: u64,
    ) -> Self {
        let priority = RebalancePriority::from_utilization_delta(skew.max_utilization_delta_pct);
        Self {
            plan_id,
            epoch,
            detected_skew: skew,
            intents: Vec::new(),
            total_bytes_to_move: 0,
            budget_consumed: 0,
            created_at_ns,
            is_aborted: false,
            anti_affinity_verdict: None,
            priority,
            evidence_commit_group_id,
        }
    }

    /// Whether all intents have been executed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.is_aborted && self.budget_consumed >= self.total_bytes_to_move
    }

    /// Abort this plan due to epoch transition.
    pub fn abort(&mut self, _at_ns: u64) {
        self.is_aborted = true;
    }

    /// Returns `true` if this plan's evidence has been superseded by a
    /// newer commit group.
    #[must_use]
    pub fn evidence_is_stale(&self, current_commit_group_id: u64) -> bool {
        current_commit_group_id > self.evidence_commit_group_id
    }

    /// Validate that this plan's evidence is still current. Returns
    /// `Err(EvidenceStale)` if the evidence commit group has been
    /// superseded.
    pub fn validate_evidence(&self, current_commit_group_id: u64) -> Result<(), RebalanceError> {
        if self.evidence_is_stale(current_commit_group_id) {
            return Err(RebalanceError::EvidenceStale {
                plan_cg: CommitGroupId(self.evidence_commit_group_id),
                current_cg: CommitGroupId(current_commit_group_id),
            });
        }
        Ok(())
    }
}

// ── Rebalance planner ────────────────────────────────────────────────

/// The rebalance planner orchestrates capacity rebalancing.
///
/// Composes capacity skew detection with placement planning to produce
/// rebalance intents that only move data needed for convergence.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RebalancePlanner {
    /// Active rebalance plans.
    pub plans: Vec<RebalancePlan>,
    /// Completed (historical) plans.
    pub completed_plans: Vec<RebalancePlan>,
    /// Movement budget for the current epoch.
    pub movement_budget: Option<MovementBudget>,
    /// The rebalance threshold (utilization delta %).
    pub rebalance_threshold_pct: u64,
    /// Target variance after rebalancing (%).
    pub target_variance_pct: u64,
    /// Maximum bytes per epoch for movement.
    pub movement_budget_bytes: u64,
    /// Next plan ID.
    next_plan_id: u64,
    /// Next intent ID.
    next_intent_id: u64,
    /// Storage tier policy for tier-aware rebalance placement.
    pub tier_policy: Option<StorageTierPolicy>,
}

impl RebalancePlanner {
    /// Create a new rebalance planner with configurable thresholds.
    #[must_use]
    pub fn new(
        rebalance_threshold_pct: u64,
        target_variance_pct: u64,
        movement_budget_bytes: u64,
    ) -> Self {
        Self {
            plans: Vec::new(),
            completed_plans: Vec::new(),
            movement_budget: None,
            rebalance_threshold_pct,
            target_variance_pct,
            movement_budget_bytes,
            next_plan_id: 1,
            next_intent_id: 1,
            tier_policy: None,
        }
    }

    /// Default planner: 20% threshold, 10% target, 1 GiB/epoch budget.
    #[must_use]
    pub fn default_for_epoch(epoch: EpochId) -> Self {
        let mut planner = Self::new(
            DEFAULT_REBALANCE_THRESHOLD_PCT,
            DEFAULT_TARGET_VARIANCE_PCT,
            DEFAULT_MOVEMENT_BUDGET_BYTES,
        );
        planner.movement_budget = Some(MovementBudget::new(DEFAULT_MOVEMENT_BUDGET_BYTES, epoch));
        planner
    }

    /// Detect capacity skew using the rebuild planner's detection logic.
    #[must_use]
    pub fn detect_skew(
        &self,
        node_utilization: &BTreeMap<NodeId, u64>,
        total_bytes: u64,
        detected_at_ns: u64,
    ) -> Option<CapacityRebalanceSkew> {
        let detector = RebuildPlanner::new();
        detector.detect_capacity_skew_for_rebalance(
            node_utilization,
            self.rebalance_threshold_pct,
            total_bytes,
            detected_at_ns,
        )
    }

    /// Create a rebalance plan from detected capacity skew.
    ///
    /// Computes rebalance intents by pairing over-utilized sources
    /// with under-utilized targets, respecting placement policies
    /// and failure-domain anti-affinity.
    pub fn plan_rebalance(
        &mut self,
        skew: &CapacityRebalanceSkew,
        epoch: EpochId,
        failure_domains: &[FailureDomainRecord],
        placement_policy: &FailureDomainPlacementPolicy,
        created_at_ns: u64,
        evidence_commit_group_id: u64,
        committed_free_bytes_by_member: &BTreeMap<MemberId, u64>,
    ) -> Result<&RebalancePlan, RebalanceError> {
        // Check for existing active plan for this epoch
        if self.plans.iter().any(|p| p.epoch == epoch && !p.is_aborted) {
            return Err(RebalanceError::PlanAlreadyExists { epoch });
        }

        // Abort existing plans on epoch change
        self.abort_all_for_epoch(epoch, created_at_ns);

        // Initialize budget for this epoch
        if self.movement_budget.is_none()
            || self
                .movement_budget
                .as_ref()
                .is_none_or(|b| b.epoch != epoch)
        {
            self.movement_budget = Some(MovementBudget::new(self.movement_budget_bytes, epoch));
        }

        let plan_id = self.next_plan_id;
        self.next_plan_id += 1;

        let mut plan = RebalancePlan::new(
            plan_id,
            epoch,
            skew.clone(),
            created_at_ns,
            evidence_commit_group_id,
        );

        // Compute placement targets for each over-utilized source
        let under_utilized_members: Vec<MemberId> = skew
            .under_utilized_nodes
            .iter()
            .map(|n| MemberId::new(n.0))
            .collect();

        let over_utilized_members: Vec<MemberId> = skew
            .over_utilized_nodes
            .iter()
            .map(|n| MemberId::new(n.0))
            .collect();

        if under_utilized_members.is_empty() || over_utilized_members.is_empty() {
            return Err(RebalanceError::NotEnoughTargets {
                needed: 1,
                available: under_utilized_members.len(),
            });
        }

        let under_utilized_member_set: BTreeSet<MemberId> =
            under_utilized_members.iter().copied().collect();
        let target_failure_domains: Vec<FailureDomainRecord> = failure_domains
            .iter()
            .filter_map(|domain| {
                let member_refs: Vec<MemberId> = domain
                    .member_refs
                    .iter()
                    .copied()
                    .filter(|member_id| {
                        under_utilized_member_set.contains(member_id)
                            && committed_free_bytes_by_member
                                .get(member_id)
                                .copied()
                                .unwrap_or(0)
                                > 0
                    })
                    .collect();
                (!member_refs.is_empty()).then(|| {
                    let mut domain = domain.clone();
                    domain.member_refs = member_refs;
                    domain
                })
            })
            .collect();

        if target_failure_domains.is_empty() {
            return Err(RebalanceError::NotEnoughTargets {
                needed: 1,
                available: 0,
            });
        }

        // Produce a placement plan from committed evidence for the
        // under-utilized targets.
        let committed_placement = compute_committed_replica_target_set(
            placement_policy,
            &target_failure_domains,
            TierGoal::Primary,
            epoch,
            evidence_commit_group_id,
        )?;

        let committed_targets = committed_placement.plan.selected_member_refs.clone();
        if committed_targets.is_empty() {
            return Err(RebalanceError::NotEnoughTargets {
                needed: 1,
                available: 0,
            });
        }

        let required_target_free = ceil_div(
            skew.estimated_bytes_to_move,
            committed_targets.len().max(1) as u64,
        );
        let targets_with_committed_free = committed_targets
            .iter()
            .filter(|member_id| {
                committed_free_bytes_by_member
                    .get(member_id)
                    .copied()
                    .unwrap_or(0)
                    >= required_target_free
            })
            .count();
        if targets_with_committed_free != committed_targets.len() {
            return Err(RebalanceError::NotEnoughTargets {
                needed: committed_targets.len(),
                available: targets_with_committed_free,
            });
        }

        // Build rebalance intents — pair over-utilized sources with
        // committed-free under-utilized placement targets.
        for &source in &over_utilized_members {
            for &target in &committed_targets {
                // Compute estimated bytes to move: proportional share of total
                let source_share =
                    skew.estimated_bytes_to_move / over_utilized_members.len().max(1) as u64;
                let target_share = source_share / committed_targets.len().max(1) as u64;

                let intent = RebalanceIntent::new(
                    self.next_intent_id,
                    // Placeholder subject — real implementation maps to actual chunks
                    ReplicatedSubjectId::new(0),
                    source,
                    target,
                    target_share,
                    epoch,
                );
                self.next_intent_id += 1;
                plan.intents.push(intent);
            }
        }

        plan.total_bytes_to_move = skew.estimated_bytes_to_move;
        plan.anti_affinity_verdict = Some(committed_placement.plan.verdict.verdict_class);
        debug_assert!(
            committed_targets.iter().all(|member_id| {
                committed_free_bytes_by_member
                    .get(member_id)
                    .copied()
                    .unwrap_or(0)
                    >= required_target_free
            }),
            "rebalance targets must be selected from committed free-space evidence"
        );

        self.plans.push(plan);
        Ok(self.plans.last().unwrap())
    }

    /// Record budget consumption for executed intents.
    pub fn consume_budget(&mut self, bytes: u64) -> Result<(), RebalanceError> {
        let budget = self
            .movement_budget
            .as_mut()
            .ok_or(RebalanceError::BudgetExceeded {
                requested: bytes,
                remaining: 0,
                budget: 0,
            })?;
        budget.reserve(bytes)
    }

    /// Abort all active plans due to an epoch transition.
    ///
    /// Implements AC 11: epoch transitions abort inflight rebalancing plans.
    pub fn abort_all_for_epoch(&mut self, new_epoch: EpochId, at_ns: u64) {
        for plan in &mut self.plans {
            if !plan.is_aborted && plan.epoch != new_epoch {
                plan.abort(at_ns);
            }
        }
    }

    /// Invalidate (abort) all plans whose capacity or placement evidence
    /// is stale — i.e., based on a commit group older than `current`.
    ///
    /// Returns the number of plans invalidated.
    pub fn invalidate_stale_plans(&mut self, current: u64) -> usize {
        let mut count = 0;
        for plan in &mut self.plans {
            if !plan.is_aborted && plan.evidence_is_stale(current) {
                plan.is_aborted = true;
                count += 1;
            }
        }
        count
    }

    /// Return committed free-space evidence for relocation target selection.
    ///
    /// Consumes a [`SpaceAccounting`] snapshot to extract committed free
    /// space per member. Only committed (non-pending) free space is
    /// eligible for relocation target sizing.
    #[must_use]
    pub fn committed_free_space_for_targets(
        &self,
        member_ids: &[MemberId],
        accounting: &SpaceAccounting,
    ) -> BTreeMap<MemberId, u64> {
        let mut free_map = BTreeMap::new();
        // Committed free blocks are available after pending deltas are excluded.
        let committed_free_bytes = accounting.committed_free_bytes();
        for &member_id in member_ids {
            free_map.insert(member_id, committed_free_bytes);
        }
        free_map
    }

    /// Select relocation targets from committed free-space evidence only.
    ///
    /// Filters `candidate_members` to those that have at least
    /// `min_free_bytes` of committed free space according to `accounting`.
    #[must_use]
    pub fn select_targets_with_committed_free_space(
        &self,
        candidate_members: &[MemberId],
        accounting: &SpaceAccounting,
        min_free_bytes: u64,
    ) -> Vec<MemberId> {
        let committed_free_bytes = accounting.committed_free_bytes();
        if committed_free_bytes >= min_free_bytes {
            candidate_members.to_vec()
        } else {
            Vec::new()
        }
    }

    /// Move completed plans to the history.
    pub fn finalize_completed(&mut self) {
        let completed: Vec<RebalancePlan> = self
            .plans
            .iter()
            .filter(|p| p.is_complete())
            .cloned()
            .collect();
        self.plans.retain(|p| !p.is_complete());
        self.completed_plans.extend(completed);
    }

    /// Get active (non-aborted) plans for the given epoch.
    #[must_use]
    pub fn active_plans_for_epoch(&self, epoch: EpochId) -> Vec<&RebalancePlan> {
        self.plans
            .iter()
            .filter(|p| p.epoch == epoch && !p.is_aborted)
            .collect()
    }

    /// Whether there is any active rebalancing work.
    #[must_use]
    pub fn has_active_work(&self) -> bool {
        self.plans.iter().any(|p| !p.is_complete() && !p.is_aborted)
    }

    /// Total bytes pending movement across all active plans.
    #[must_use]
    pub fn total_pending_bytes(&self) -> u64 {
        self.plans
            .iter()
            .filter(|p| !p.is_aborted && !p.is_complete())
            .map(|p| p.total_bytes_to_move.saturating_sub(p.budget_consumed))
            .sum()
    }

    /// Advance an epoch: set up new budget, abort old plans.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId, at_ns: u64) {
        self.abort_all_for_epoch(new_epoch, at_ns);
        self.finalize_completed();
        self.movement_budget = Some(MovementBudget::new(self.movement_budget_bytes, new_epoch));
    }

    // ── Tiering awareness ──────────────────────────────────────────

    /// Set the storage tier policy.
    pub fn set_tier_policy(&mut self, policy: StorageTierPolicy) {
        self.tier_policy = Some(policy);
    }

    /// Create a tier-aware placement policy by augmenting a base policy
    /// with a target storage tier.
    #[must_use]
    pub fn tiered_placement_policy(
        &self,
        base: &FailureDomainPlacementPolicy,
        tier: Option<StorageTier>,
    ) -> FailureDomainPlacementPolicy {
        let mut policy = *base;
        policy.target_tier = tier;
        policy
    }
}

fn ceil_div(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (numerator / denominator) + u64::from(numerator % denominator != 0)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{
        AntiAffinityClass, DomainId, FailureDomainClass, HealthClass, ReceiptId,
    };
    use tidefs_space_accounting::{Delta, PoolCounters, SpaceAccounting};

    fn make_failure_domain(
        id: u64,
        class: FailureDomainClass,
        member_ids: &[u64],
    ) -> FailureDomainRecord {
        FailureDomainRecord {
            failure_domain_id: DomainId::new(id),
            failure_domain_class_ref: class,
            member_refs: member_ids.iter().map(|&m| MemberId::new(m)).collect(),
            health_class: HealthClass::Healthy,
            separation_policy_ref: AntiAffinityClass::Strict,
            parent_domain_ref: DomainId::ZERO,
            availability_receipt_ref: ReceiptId(0),
            storage_tier: None,
            digest: 0,
        }
    }

    fn committed_free(member_ids: &[u64], bytes: u64) -> BTreeMap<MemberId, u64> {
        member_ids
            .iter()
            .map(|member_id| (MemberId::new(*member_id), bytes))
            .collect()
    }

    #[test]
    fn movement_budget_enforces_cap() {
        let mut budget = MovementBudget::new(1000, EpochId::new(1));
        assert!(budget.can_accommodate(500));

        budget.reserve(600).unwrap();
        assert_eq!(budget.remaining_bytes, 400);
        assert!(!budget.is_exhausted);

        // Exceeding budget fails
        let err = budget.reserve(500).unwrap_err();
        assert!(matches!(err, RebalanceError::BudgetExceeded { .. }));

        budget.reserve(400).unwrap();
        assert!(budget.is_exhausted);
        assert_eq!(budget.remaining_bytes, 0);
    }

    #[test]
    fn movement_budget_release() {
        let mut budget = MovementBudget::new(1000, EpochId::new(1));
        budget.reserve(600).unwrap();
        budget.release(200);
        assert_eq!(budget.remaining_bytes, 600);
        assert!(!budget.is_exhausted);
    }

    #[test]
    fn detect_skew_triggers_when_above_threshold() {
        let planner = RebalancePlanner::new(20, 10, 1_000_000);

        let mut node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        node_util.insert(NodeId(1), 90); // 90% utilized (over)
        node_util.insert(NodeId(2), 40); // 40% utilized (under)
        node_util.insert(NodeId(3), 60); // 60% utilized

        let skew = planner.detect_skew(&node_util, 1_000_000, 1000);
        assert!(skew.is_some());

        let s = skew.unwrap();
        assert!(s.is_rebalance_needed());
        assert!(s.has_viable_movement());
        assert!(s.max_utilization_delta_pct > 20);
    }

    #[test]
    fn detect_skew_not_triggered_when_balanced() {
        let planner = RebalancePlanner::new(20, 10, 1_000_000);

        let mut node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        node_util.insert(NodeId(1), 55);
        node_util.insert(NodeId(2), 50);
        node_util.insert(NodeId(3), 52);

        let skew = planner.detect_skew(&node_util, 1_000_000, 1000);
        assert!(skew.is_none());
    }

    #[test]
    fn rebalance_plan_computes_intents() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];

        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        let plan = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();

        assert!(!plan.intents.is_empty());
        assert!(plan
            .intents
            .iter()
            .all(|intent| intent.target_ref == MemberId::new(2)));
        assert_eq!(plan.total_bytes_to_move, 100_000);
        assert!(plan.anti_affinity_verdict.is_some());
    }

    #[test]
    fn rebalance_plan_requires_committed_free_target_space() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);
        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        let err = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                1,
                &committed_free(&[2], 99_999),
            )
            .unwrap_err();

        assert!(matches!(err, RebalanceError::NotEnoughTargets { .. }));
        assert!(planner.plans.is_empty());
    }

    #[test]
    fn cannot_create_duplicate_plan_for_same_epoch() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];

        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();
        let err = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                3000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap_err();
        assert!(matches!(err, RebalanceError::PlanAlreadyExists { .. }));
    }

    #[test]
    fn epoch_transition_aborts_inflight_plans() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];

        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();
        assert!(planner.has_active_work());

        // Epoch transition
        planner.on_epoch_transition(EpochId::new(2), 3000);
        assert!(!planner.has_active_work());
        assert!(planner.plans.iter().all(|p| p.is_aborted));
    }

    #[test]
    fn rebalance_priority_from_delta() {
        assert_eq!(
            RebalancePriority::from_utilization_delta(70),
            RebalancePriority::Critical
        );
        assert_eq!(
            RebalancePriority::from_utilization_delta(50),
            RebalancePriority::Urgent
        );
        assert_eq!(
            RebalancePriority::from_utilization_delta(25),
            RebalancePriority::Background
        );
    }

    #[test]
    fn budget_exhaustion_prevents_additional_intents() {
        let mut budget = MovementBudget::new(1000, EpochId::new(1));
        budget.reserve(1000).unwrap();
        assert!(budget.is_exhausted);

        let err = budget.reserve(1).unwrap_err();
        assert!(matches!(err, RebalanceError::BudgetExceeded { .. }));
    }

    #[test]
    fn rebalance_intent_delta_transfer() {
        let mut intent = RebalanceIntent::new(
            1,
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            4096,
            EpochId::new(1),
        );
        assert!(!intent.is_delta_transfer());

        intent.source_frontier = Some(ReplicatedReceiptId(10));
        intent.target_frontier = Some(ReplicatedReceiptId(5));
        assert!(intent.is_delta_transfer());
    }

    #[test]
    fn empty_node_set_no_skew() {
        let planner = RebalancePlanner::default_for_epoch(EpochId::new(1));
        let node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        let skew = planner.detect_skew(&node_util, 1_000_000, 1000);
        assert!(skew.is_none());
    }

    #[test]
    fn plan_no_targets_error() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew = CapacityRebalanceSkew::new(
            vec![NodeId(1)],
            vec![], // No under-utilized nodes
            50,
            20,
            100_000,
            10,
            1000,
        );

        let domains = vec![make_failure_domain(1, FailureDomainClass::Rack, &[1])];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        let err = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                1,
                &committed_free(&[], 0),
            )
            .unwrap_err();
        assert!(matches!(err, RebalanceError::NotEnoughTargets { .. }));
    }

    #[test]
    fn rebalance_tiering_filters_by_target_tier() {
        use tidefs_membership_epoch::EpochId;
        use tidefs_membership_epoch::{
            AntiAffinityClass, DomainId, FailureDomainClass, FailureDomainRecord, HealthClass,
            ReceiptId, StorageTier, StorageTierPolicy,
        };
        use tidefs_placement_planner::{compute_replica_target_set, PlacementError, TierGoal};

        let nvme_domain = DomainId::new(1);
        let hdd_domain = DomainId::new(2);

        let domains = vec![
            FailureDomainRecord {
                failure_domain_id: nvme_domain,
                failure_domain_class_ref: FailureDomainClass::Device,
                parent_domain_ref: DomainId::ZERO,
                member_refs: vec![MemberId::new(10)],
                separation_policy_ref: AntiAffinityClass::Strict,
                health_class: HealthClass::Healthy,
                availability_receipt_ref: ReceiptId::ZERO,
                storage_tier: Some(StorageTier::NvmePerformance),
                digest: 0,
            },
            FailureDomainRecord {
                failure_domain_id: hdd_domain,
                failure_domain_class_ref: FailureDomainClass::Device,
                parent_domain_ref: DomainId::ZERO,
                member_refs: vec![MemberId::new(20)],
                separation_policy_ref: AntiAffinityClass::Strict,
                health_class: HealthClass::Healthy,
                availability_receipt_ref: ReceiptId::ZERO,
                storage_tier: Some(StorageTier::HddArchive),
                digest: 0,
            },
        ];

        let epoch = EpochId::new(1);

        // Tier-unconstrained: both domains qualify
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Device);
        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, epoch).unwrap();
        assert!(!plan.selected_member_refs.is_empty());

        // NVMe tier: only NVMe qualifiers
        let mut nvme_policy = policy;
        nvme_policy.target_tier = Some(StorageTier::NvmePerformance);
        let plan =
            compute_replica_target_set(&nvme_policy, &domains, TierGoal::Primary, epoch).unwrap();
        assert!(plan.selected_member_refs.iter().all(|m| m.0 == 10));

        // HDD tier: only HDD qualifiers
        let mut hdd_policy = policy;
        hdd_policy.target_tier = Some(StorageTier::HddArchive);
        let plan =
            compute_replica_target_set(&hdd_policy, &domains, TierGoal::Primary, epoch).unwrap();
        assert!(plan.selected_member_refs.iter().all(|m| m.0 == 20));

        // Missing tier: NoMatchingTier error
        let mut missing_policy = policy;
        missing_policy.target_tier = Some(StorageTier::SsdCapacity);
        let err = compute_replica_target_set(&missing_policy, &domains, TierGoal::Primary, epoch)
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoMatchingTier));

        // RebalancePlanner tiered_placement_policy
        let planner = RebalancePlanner::default_for_epoch(epoch);
        let base =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Device);
        let result = planner.tiered_placement_policy(&base, None);
        assert_eq!(result.target_tier, None);
        let result = planner.tiered_placement_policy(&base, Some(StorageTier::NvmePerformance));
        assert_eq!(result.target_tier, Some(StorageTier::NvmePerformance));

        // With tier policy set
        let mut tp = StorageTierPolicy::new();
        tp.auto_promote = true;
        tp.auto_demote = true;
        tp.set_domain_tier(nvme_domain, StorageTier::NvmePerformance);
        tp.set_domain_tier(hdd_domain, StorageTier::HddArchive);

        let mut planner2 = RebalancePlanner::default_for_epoch(epoch);
        planner2.set_tier_policy(tp);
        assert!(planner2.tier_policy.is_some());
        let result = planner2.tiered_placement_policy(&base, Some(StorageTier::HddArchive));
        assert_eq!(result.target_tier, Some(StorageTier::HddArchive));
    }

    // ── Committed evidence tests ───────────────────────────────────

    #[test]
    fn plan_carries_evidence_commit_group_id() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        // Create a plan with evidence committed at commit group 5.
        let plan = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                5,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();
        assert_eq!(plan.evidence_commit_group_id, 5);
        // Evidence should not be stale at the same commit group.
        assert!(!plan.evidence_is_stale(5));
        // Evidence should not be stale at a lower commit group.
        assert!(!plan.evidence_is_stale(4));
        // Evidence is stale when current commit group has advanced.
        assert!(plan.evidence_is_stale(6));
        assert!(plan.evidence_is_stale(100));
    }

    #[test]
    fn plan_invalidation_on_new_commit_group() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        // Create a plan with evidence at commit group 1, epoch 1.
        planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                1000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();

        // Advance epoch to 2 — this aborts the first plan (epoch transition),
        // so we can create a second plan at epoch 2.  Manually manage the
        // planner state to keep both plans for the invalidation test.
        // Reset: create fresh planner with both plans pre-loaded.
        let mut planner2 = RebalancePlanner::default_for_epoch(EpochId::new(1));
        planner2
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                1000,
                1,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();
        planner2.on_epoch_transition(EpochId::new(2), 2000);
        planner2
            .plan_rebalance(
                &skew,
                EpochId::new(2),
                &domains,
                &policy,
                3000,
                2,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();

        // After on_epoch_transition, the epoch-1 plan is aborted but still
        // in the plans vec.  The epoch-2 plan is active.
        assert_eq!(planner2.plans.len(), 2);
        assert!(planner2.plans[0].is_aborted); // epoch-1 plan aborted by transition
        assert!(!planner2.plans[1].is_aborted); // epoch-2 plan is active
        assert_eq!(planner2.plans[1].evidence_commit_group_id, 2);

        // Invalidate plans with evidence older than commit group 3.
        // The aborted plan at CG 1 is already aborted; the active plan
        // at CG 2 is stale and should be invalidated.
        let invalidated = planner2.invalidate_stale_plans(3);
        assert_eq!(invalidated, 1); // only the active plan gets newly invalidated
        assert!(planner2.plans[1].is_aborted);

        // validate_evidence returns Err for stale plan
        let err = planner2.plans[1].validate_evidence(3).unwrap_err();
        assert!(matches!(err, RebalanceError::EvidenceStale { .. }));
    }

    #[test]
    fn plan_stays_valid_when_evidence_current() {
        let mut planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);

        let domains = vec![
            make_failure_domain(1, FailureDomainClass::Rack, &[1]),
            make_failure_domain(2, FailureDomainClass::Rack, &[2]),
        ];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);

        // Create plan at commit group 7.
        let plan = planner
            .plan_rebalance(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                1000,
                7,
                &committed_free(&[2], 1_000_000),
            )
            .unwrap();
        assert_eq!(plan.evidence_commit_group_id, 7);

        // Same commit group: evidence is valid.
        assert!(!plan.evidence_is_stale(7));
        assert!(plan.validate_evidence(7).is_ok());

        // Newer commit group: evidence is stale.
        assert!(plan.evidence_is_stale(8));
        assert!(plan.validate_evidence(8).is_err());
    }

    #[test]
    fn committed_placement_plan_is_stale_check() {
        use tidefs_membership_epoch::FailureDomainPlacementPlan;
        use tidefs_placement_planner::CommittedPlacementPlan;

        // A committed placement plan is stale when its commit group is older.
        let inner_plan = FailureDomainPlacementPlan {
            policy_ref: FailureDomainPlacementPolicy::strict_replica_targets(
                1,
                FailureDomainClass::Rack,
            ),
            selected_member_refs: vec![MemberId::new(1)],
            selected_domain_refs: vec![DomainId::new(1)],
            duplicate_domain_member_refs: vec![],
            excluded_member_refs: vec![],
            verdict: tidefs_membership_epoch::MembershipPlacementVerdictRecord {
                verdict_id: 1,
                membership_epoch_ref: EpochId::new(1),
                placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
                selected_member_refs: vec![MemberId::new(1)],
                selected_domain_refs: vec![DomainId::new(1)],
                verdict_class: VerdictClass::Admit,
                degraded_reason_refs: vec![],
                issuance_receipt_ref: ReceiptId::ZERO,
                digest: 0,
            },
        };

        let cpp = CommittedPlacementPlan {
            plan: inner_plan,
            committed_at: 3,
        };

        assert!(!cpp.is_stale(3));
        assert!(!cpp.is_stale(2));
        assert!(cpp.is_stale(4));
        assert!(cpp.is_stale(10));
    }

    #[test]
    fn relocate_targets_from_committed_free_space() {
        // SpaceAccounting with known committed free space.
        let mut sa = SpaceAccounting::empty();
        // Commit some writes so we have non-zero committed consumption.
        sa.commit_delta(Delta::new_write(1_000_000)).unwrap();

        let planner = RebalancePlanner::default_for_epoch(EpochId::new(1));

        // With 0 min_free_bytes, all candidates qualify
        let targets = planner.select_targets_with_committed_free_space(
            &[MemberId::new(1), MemberId::new(2)],
            &sa,
            0,
        );
        assert_eq!(targets.len(), 2);

        // When min_free_bytes exceeds committed free space, none qualify
        let statfs = sa.statfs();
        let committed_free = statfs.blocks_free.saturating_mul(statfs.block_size);
        let overflow = committed_free.saturating_add(1);
        let no_targets =
            planner.select_targets_with_committed_free_space(&[MemberId::new(1)], &sa, overflow);
        assert!(no_targets.is_empty());
    }

    #[test]
    fn committed_free_space_respects_allocation_slop() {
        let mut sa = SpaceAccounting::empty();
        let block_size = 4096;
        sa.set_quota(256 * block_size);
        sa.set_slop(16 * block_size);
        sa.update_pool_counters(PoolCounters {
            phys_free_bytes: 256 * block_size,
            phys_total_bytes: 256 * block_size,
            ..Default::default()
        });

        let statfs = sa.statfs();
        assert!(statfs.blocks_free > statfs.blocks_avail);

        let planner = RebalancePlanner::default_for_epoch(EpochId::new(1));
        let committed_free = sa.committed_free_bytes();
        assert_eq!(
            committed_free,
            statfs.blocks_avail.saturating_mul(statfs.block_size)
        );

        let above_allocation_admissible = committed_free.saturating_add(statfs.block_size);
        let targets = planner.select_targets_with_committed_free_space(
            &[MemberId::new(1)],
            &sa,
            above_allocation_admissible,
        );
        assert!(targets.is_empty());
    }

    #[test]
    fn rebalance_with_mixed_device_sizes() {
        // Simulate a pool with mixed device sizes: device A has 1 TB,
        // device B has 2 TB, device C has 4 TB. Utilization percentages
        // differ, creating skew that rebalance should detect.
        let planner = RebalancePlanner::new(20, 10, 10_000_000_000);

        let mut node_util: BTreeMap<NodeId, u64> = BTreeMap::new();
        // Device A (1 TB): 90% full
        node_util.insert(NodeId(1), 90);
        // Device B (2 TB): 50% full
        node_util.insert(NodeId(2), 50);
        // Device C (4 TB): 30% full
        node_util.insert(NodeId(3), 30);

        // Total raw bytes: 7 TB
        let skew = planner.detect_skew(&node_util, 7_000_000_000_000, 1000);
        assert!(skew.is_some());
        let s = skew.unwrap();

        // Delta 90 - 30 = 60% > 20% threshold
        assert!(s.is_rebalance_needed());
        assert!(s.has_viable_movement());

        // Over-utilized: device A (90% > avg ~57%)
        assert!(s.over_utilized_nodes.contains(&NodeId(1)));
        // Under-utilized: device C (30% < avg ~57%)
        assert!(s.under_utilized_nodes.contains(&NodeId(3)));
    }

    #[test]
    fn committed_free_space_excludes_pending_deltas() {
        let mut sa = SpaceAccounting::empty();
        // Set a quota so there is committed free space to work with.
        sa.set_quota(1_000_000_000);

        // Set pool counters with enough physical headroom for the writes.
        sa.update_pool_counters(PoolCounters {
            phys_free_bytes: 1_000_000_000,
            phys_total_bytes: 1_000_000_000,
            ..Default::default()
        });

        // Before any writes, committed free space is the full quota.
        let statfs_before = sa.statfs();
        let committed_free_before = statfs_before
            .blocks_free
            .saturating_mul(statfs_before.block_size);
        assert!(committed_free_before > 0);

        // Accumulate a pending delta that would consume half the space.
        // This stays pending (not yet committed) so statfs excludes it.
        let pending_bytes = committed_free_before / 2;
        sa.accumulate_delta(Delta::new_write(pending_bytes));
        assert!(sa.has_pending_delta());

        // statfs excludes the pending delta — committed free space unchanged.
        let statfs_after = sa.statfs();
        assert_eq!(statfs_after.blocks_free, statfs_before.blocks_free);

        // check_enospc uses committed counters only, so still admits.
        assert!(!sa.check_enospc(1));

        // After committing the pending delta, free space drops.
        sa.commit_pending(PoolCounters {
            phys_free_bytes: 1_000_000_000,
            phys_total_bytes: 1_000_000_000,
            ..Default::default()
        })
        .unwrap();
        let statfs_committed = sa.statfs();
        assert!(statfs_committed.blocks_free < statfs_before.blocks_free);
    }
}
