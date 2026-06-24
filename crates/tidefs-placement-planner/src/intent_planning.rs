// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Storage-intent-aware placement admission.
//!
//! This module is the first #843 planner-facing bridge from broad [`TierGoal`]
//! selection into storage-intent roles. It does not execute movement, emit
//! receipts, or recompute compiled policy precedence. Instead it consumes
//! `tidefs-storage-intent-core` policy, receipt, evidence, media, trust,
//! data-shape, layout, and cost records as hard-gate inputs and preserves the
//! typed refusal reasons that explanation and performance rows need later.

use std::collections::BTreeSet;

use tidefs_storage_intent_core::{
    ack_receipt_satisfies_requested_floor, evaluate_receipt_against_policy,
    media_capability_satisfies_role, prefetch_residency_decision_is_cache_only,
    prefetch_residency_decision_may_request_authority_change, trust_domain_role_requirement,
    trust_domain_role_satisfies, AllocationClass, CostWearRecord, DataShapeRecord,
    EvidenceFamilyFreshnessState, LayoutAllocatorRecord, MediaRoleMask, MediaRoleRequirement,
    PredictionConfidence, PrefetchResidencyDecisionOutcome, PrefetchResidencyDecisionRecord,
    ReceiptPredicateResult, SkippedMoveReason, StorageIntentActionClass, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef, StorageIntentGuaranteeClass,
    StorageIntentPolicy, StorageIntentReceipt, StorageIntentReceiptId, StorageIntentRefusalReason,
    StorageIntentTrustRole, StorageMediaRole, TransformRefusalClass, TrustDomainRequirement,
    TrustEvidenceRecord,
};

use crate::TierGoal;

const AUTHORITY_HARD_GATE_EVIDENCE: &[StorageIntentEvidenceKind] = &[
    StorageIntentEvidenceKind::MembershipEvidence,
    StorageIntentEvidenceKind::OrderingEvidence,
    StorageIntentEvidenceKind::MediaCapabilityEvidence,
    StorageIntentEvidenceKind::TrustDomainEvidence,
    StorageIntentEvidenceKind::TransportPathEvidence,
    StorageIntentEvidenceKind::CapacityAdmissionEvidence,
    StorageIntentEvidenceKind::RecoveryDegradationEvidence,
    StorageIntentEvidenceKind::PolicyRolloutEvidence,
    StorageIntentEvidenceKind::TenantIsolationEvidence,
    StorageIntentEvidenceKind::TemporalEvidence,
    StorageIntentEvidenceKind::DataShapeEvidence,
    StorageIntentEvidenceKind::LayoutAllocatorEvidence,
    StorageIntentEvidenceKind::ServiceObjectiveEvidence,
    StorageIntentEvidenceKind::DecisionFrontierEvidence,
];

const CACHE_ONLY_HARD_GATE_EVIDENCE: &[StorageIntentEvidenceKind] = &[
    StorageIntentEvidenceKind::MediaCapabilityEvidence,
    StorageIntentEvidenceKind::TrustDomainEvidence,
    StorageIntentEvidenceKind::TransportPathEvidence,
    StorageIntentEvidenceKind::WorkloadEvidence,
    StorageIntentEvidenceKind::DecisionFrontierEvidence,
];

const MOVEMENT_HARD_GATE_EVIDENCE: &[StorageIntentEvidenceKind] = &[
    StorageIntentEvidenceKind::MediaCostWearLedger,
    StorageIntentEvidenceKind::RelocationReceipt,
    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
];

/// Placement role requested by storage intent.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum StorageIntentPlacementRole {
    /// Durable sync-intent target.
    SyncIntentTarget,
    /// Cache-only hot read-serving trial; never satisfies authority.
    CacheOnlyHotServingTrial,
    /// Hot serving replica that is allowed to carry authority.
    AuthoritativeHotServingReplica,
    /// Durable full-placement replica or shard.
    DurableFullPlacement,
    /// Cold/archive placement.
    ColdArchivePlacement,
    /// WAN/geo delta or remote intent role.
    GeoDeltaRemoteIntent,
    /// Temporary repair, relocation, defrag, or rebake target.
    RepairRelocationTemporary,
}

impl StorageIntentPlacementRole {
    /// Media role required for this storage-intent role.
    #[must_use]
    pub const fn media_role(self) -> StorageMediaRole {
        match self {
            Self::SyncIntentTarget => StorageMediaRole::SyncIntent,
            Self::CacheOnlyHotServingTrial => StorageMediaRole::ReadCache,
            Self::AuthoritativeHotServingReplica => StorageMediaRole::ServingDataHot,
            Self::DurableFullPlacement => StorageMediaRole::PlacementAuthority,
            Self::ColdArchivePlacement => StorageMediaRole::ArchiveEc,
            Self::GeoDeltaRemoteIntent => StorageMediaRole::GeoAsyncReplica,
            Self::RepairRelocationTemporary => StorageMediaRole::RepairTemp,
        }
    }

    /// Scheduler action class used when an admitted plan is handed to execution.
    #[must_use]
    pub const fn action_class(self) -> StorageIntentActionClass {
        match self {
            Self::SyncIntentTarget => StorageIntentActionClass::NewWriteShaping,
            Self::CacheOnlyHotServingTrial => StorageIntentActionClass::CacheOnlyServingTrial,
            Self::AuthoritativeHotServingReplica => StorageIntentActionClass::AuthorityPromotion,
            Self::DurableFullPlacement => StorageIntentActionClass::DurablePlacementMovement,
            Self::ColdArchivePlacement => StorageIntentActionClass::ArchiveMigration,
            Self::GeoDeltaRemoteIntent => StorageIntentActionClass::GeoCatchup,
            Self::RepairRelocationTemporary => StorageIntentActionClass::ReadTriggeredRepair,
        }
    }

    /// Trust/domain role required for this placement role.
    #[must_use]
    pub const fn trust_role(self) -> StorageIntentTrustRole {
        match self {
            Self::SyncIntentTarget => StorageIntentTrustRole::SyncIntent,
            Self::CacheOnlyHotServingTrial | Self::AuthoritativeHotServingReplica => {
                StorageIntentTrustRole::ReadServing
            }
            Self::DurableFullPlacement => StorageIntentTrustRole::DurablePlacement,
            Self::ColdArchivePlacement => StorageIntentTrustRole::ArchiveRestore,
            Self::GeoDeltaRemoteIntent => StorageIntentTrustRole::GeoIntent,
            Self::RepairRelocationTemporary => StorageIntentTrustRole::RelocationTarget,
        }
    }

    /// Minimum receipt floor implied by this role.
    #[must_use]
    pub const fn guarantee_floor(self) -> StorageIntentGuaranteeClass {
        match self {
            Self::CacheOnlyHotServingTrial | Self::RepairRelocationTemporary => {
                StorageIntentGuaranteeClass::VolatileLocal
            }
            Self::SyncIntentTarget => StorageIntentGuaranteeClass::LocalIntent,
            Self::AuthoritativeHotServingReplica | Self::DurableFullPlacement => {
                StorageIntentGuaranteeClass::FullPlacement
            }
            Self::ColdArchivePlacement => StorageIntentGuaranteeClass::ArchiveEc,
            Self::GeoDeltaRemoteIntent => StorageIntentGuaranteeClass::GeoAsync,
        }
    }

    /// Whether this role can satisfy authority-changing placement.
    #[must_use]
    pub const fn requires_authority_role(self) -> bool {
        !matches!(
            self,
            Self::CacheOnlyHotServingTrial | Self::RepairRelocationTemporary
        )
    }

    /// Whether the role is intentionally cache-only.
    #[must_use]
    pub const fn is_cache_only(self) -> bool {
        matches!(self, Self::CacheOnlyHotServingTrial)
    }

    /// Whether the role requires WAN/geo evidence.
    #[must_use]
    pub const fn requires_geo_or_remote(self) -> bool {
        matches!(self, Self::GeoDeltaRemoteIntent)
    }

    /// Whether movement/payback evidence is a hard gate.
    #[must_use]
    pub const fn requires_movement_payback(self) -> bool {
        matches!(
            self,
            Self::AuthoritativeHotServingReplica
                | Self::RepairRelocationTemporary
                | Self::GeoDeltaRemoteIntent
        )
    }

    /// Evidence families that must be fresh before this role can be used.
    #[must_use]
    pub const fn hard_gate_evidence(self) -> &'static [StorageIntentEvidenceKind] {
        if self.is_cache_only() {
            CACHE_ONLY_HARD_GATE_EVIDENCE
        } else {
            AUTHORITY_HARD_GATE_EVIDENCE
        }
    }
}

/// A typed evidence state at a hard-gate boundary.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PlacementEvidenceState {
    /// Fresh evidence from the producer.
    Fresh,
    /// A compiled-policy conservative default is being applied.
    ConservativeDefault,
    /// Explicit degraded state that remains visible.
    DegradedVisible,
    /// No known state.
    #[default]
    Unknown,
    /// Producer or ref is missing.
    Missing,
    /// Producer evidence is stale.
    Stale,
    /// Producer evidence contradicts another input.
    Contradictory,
    /// Producer evidence was compacted or redacted away.
    Compacted,
    /// Producer refused the evidence.
    Refused,
}

impl PlacementEvidenceState {
    /// Convert a storage-intent freshness row into a planner hard-gate state.
    #[must_use]
    pub const fn from_family_state(state: EvidenceFamilyFreshnessState) -> Self {
        match state {
            EvidenceFamilyFreshnessState::Fresh => Self::Fresh,
            EvidenceFamilyFreshnessState::Missing => Self::Missing,
            EvidenceFamilyFreshnessState::Stale => Self::Stale,
            EvidenceFamilyFreshnessState::Contradictory => Self::Contradictory,
            EvidenceFamilyFreshnessState::Compacted | EvidenceFamilyFreshnessState::Redacted => {
                Self::Compacted
            }
            EvidenceFamilyFreshnessState::Refused => Self::Refused,
            EvidenceFamilyFreshnessState::Unknown
            | EvidenceFamilyFreshnessState::Superseded
            | EvidenceFamilyFreshnessState::Unavailable => Self::Unknown,
        }
    }

    /// Returns true only when the state may be consumed as hard-gate evidence.
    #[must_use]
    pub const fn permits_hard_gate(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Returns true when a compiled-policy default is explicit and visible.
    #[must_use]
    pub const fn is_conservative_default(self) -> bool {
        matches!(self, Self::ConservativeDefault)
    }
}

/// Storage-intent placement request consumed by the hard-gate planner.
#[derive(Debug, Clone)]
pub struct StorageIntentPlacementRequest {
    /// Compiled storage-intent policy snapshot consumed from #855/#841.
    pub policy: StorageIntentPolicy,
    /// Specific storage-intent role requested for this plan.
    pub role: StorageIntentPlacementRole,
    /// Optional broad legacy tier hint. This never replaces `role`.
    pub tier_goal: Option<TierGoal>,
    /// Number of legal candidates required by the requested placement.
    pub required_target_count: usize,
    /// Number of distinct failure-domain keys the selected set must span.
    pub min_distinct_failure_domains: usize,
    /// Bounded evidence query cut used for hard-gate admission.
    pub evidence_query: StorageIntentEvidenceQuerySnapshot,
    /// State of the compiled policy input when the #855 producer is absent.
    pub compiled_policy_state: PlacementEvidenceState,
}

impl StorageIntentPlacementRequest {
    /// Construct a storage-intent placement request.
    #[must_use]
    pub const fn new(
        policy: StorageIntentPolicy,
        role: StorageIntentPlacementRole,
        required_target_count: usize,
        min_distinct_failure_domains: usize,
        evidence_query: StorageIntentEvidenceQuerySnapshot,
    ) -> Self {
        Self {
            policy,
            role,
            tier_goal: None,
            required_target_count,
            min_distinct_failure_domains,
            evidence_query,
            compiled_policy_state: PlacementEvidenceState::Fresh,
        }
    }
}

/// Candidate target with the evidence dimensions #843 needs before scoring.
#[derive(Debug, Clone)]
pub struct StorageIntentPlacementCandidate {
    /// Device or target identifier.
    pub target_id: u64,
    /// Failure-domain key at the request's domain level.
    pub failure_domain_key: u64,
    /// Earned or provisional storage-intent receipt projection.
    pub receipt: StorageIntentReceipt,
    /// Media-capability record for the target.
    pub media_capability: tidefs_storage_intent_core::StorageIntentMediaCapabilityRecord,
    /// Data-shape compatibility evidence.
    pub data_shape: Option<DataShapeRecord>,
    /// Allocator/layout compatibility evidence.
    pub layout_allocator: Option<LayoutAllocatorRecord>,
    /// Cost/wear and movement-debt evidence.
    pub cost_wear: Option<CostWearRecord>,
    /// Optional #967 prefetch/residency decision input.
    pub prefetch_residency: Option<PrefetchResidencyDecisionRecord>,
    /// #897 authenticated peer/domain evidence for the candidate.
    pub trust_domain_evidence: Option<TrustEvidenceRecord>,
    /// Predictor confidence for authority-changing movement.
    pub prediction_confidence: PredictionConfidence,
    /// Capacity/admission gate.
    pub capacity_admission: PlacementEvidenceState,
    /// Transport/proximity gate.
    pub transport_path: PlacementEvidenceState,
    /// Trust/domain gate.
    pub trust_domain: PlacementEvidenceState,
    /// Data-shape evidence gate.
    pub data_shape_state: PlacementEvidenceState,
    /// Layout/allocator evidence gate.
    pub layout_allocator_state: PlacementEvidenceState,
    /// Decision-frontier evidence gate.
    pub decision_frontier: PlacementEvidenceState,
}

impl StorageIntentPlacementCandidate {
    /// Construct a candidate from the required evidence-bearing records.
    #[must_use]
    pub fn new(
        target_id: u64,
        failure_domain_key: u64,
        receipt: StorageIntentReceipt,
        media_capability: tidefs_storage_intent_core::StorageIntentMediaCapabilityRecord,
    ) -> Self {
        Self {
            target_id,
            failure_domain_key,
            receipt,
            media_capability,
            data_shape: None,
            layout_allocator: None,
            cost_wear: None,
            prefetch_residency: None,
            trust_domain_evidence: None,
            prediction_confidence: PredictionConfidence::Unknown,
            capacity_admission: PlacementEvidenceState::Unknown,
            transport_path: PlacementEvidenceState::Unknown,
            trust_domain: PlacementEvidenceState::Unknown,
            data_shape_state: PlacementEvidenceState::Unknown,
            layout_allocator_state: PlacementEvidenceState::Unknown,
            decision_frontier: PlacementEvidenceState::Unknown,
        }
    }

    /// Mark ordinary candidate gates fresh for focused tests and simple callers.
    #[must_use]
    pub fn with_fresh_hard_gates(mut self) -> Self {
        self.capacity_admission = PlacementEvidenceState::Fresh;
        self.transport_path = PlacementEvidenceState::Fresh;
        self.trust_domain = PlacementEvidenceState::Fresh;
        self.data_shape_state = PlacementEvidenceState::Fresh;
        self.layout_allocator_state = PlacementEvidenceState::Fresh;
        self.decision_frontier = PlacementEvidenceState::Fresh;
        self
    }
}

/// Reason preserved by hard-gate evaluation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StorageIntentPlacementReason {
    /// Broad legacy tier was carried only as a hint.
    TierGoalIsNotStorageIntentModel(TierGoal),
    /// Compiled policy evidence was missing, stale, or refused.
    CompiledPolicyEvidence { state: PlacementEvidenceState },
    /// A conservative policy default was explicitly carried.
    CompiledPolicyConservativeDefault,
    /// The evidence cut itself cannot authorize this use.
    EvidenceCutRefused { refusal: StorageIntentRefusalReason },
    /// Required evidence family was absent or not fresh.
    EvidenceFamilyNotFresh {
        kind: StorageIntentEvidenceKind,
        state: PlacementEvidenceState,
    },
    /// Fresh #926 preflight output cannot replace a live placement frontier.
    PreflightSimulationNotAuthoritative,
    /// Candidate receipt failed the compiled policy predicate.
    CandidateReceiptRefused {
        target_id: u64,
        refusal: StorageIntentRefusalReason,
    },
    /// Candidate media role is not the requested storage-intent role.
    CandidateRoleMismatch {
        target_id: u64,
        expected: StorageMediaRole,
        actual: StorageMediaRole,
    },
    /// Candidate cannot satisfy the role's guarantee floor.
    CandidateGuaranteeFloorNotMet {
        target_id: u64,
        required: StorageIntentGuaranteeClass,
        actual: StorageIntentGuaranteeClass,
    },
    /// Media capability predicates rejected the target.
    CandidateMediaCapabilityRefused {
        target_id: u64,
        refusal: StorageIntentRefusalReason,
    },
    /// Candidate gate state was not fresh.
    CandidateEvidenceGateRefused {
        target_id: u64,
        gate: CandidateGate,
        state: PlacementEvidenceState,
        refusal: StorageIntentRefusalReason,
    },
    /// Data-shape transform evidence rejected the target.
    CandidateDataShapeRefused {
        target_id: u64,
        refusal: TransformRefusalClass,
    },
    /// Layout/allocator evidence rejected the target.
    CandidateLayoutRefused {
        target_id: u64,
        refusal: LayoutRefusal,
    },
    /// Cache-only or trial state attempted to satisfy durable authority.
    CandidateCacheOnlyCannotSatisfyAuthority { target_id: u64 },
    /// Geo or remote role lacked geo/remote evidence.
    CandidateGeoRemoteEvidenceMissing { target_id: u64 },
    /// Trust/domain evidence rejected the role before scoring.
    CandidateTrustDomainRefused {
        target_id: u64,
        role: StorageIntentTrustRole,
        refusal: StorageIntentRefusalReason,
    },
    /// Authority movement lacked predictor confidence.
    CandidateLowPredictionConfidence {
        target_id: u64,
        confidence: PredictionConfidence,
    },
    /// Authority movement lacked payback or cost evidence.
    CandidateMovementDebtRefused {
        target_id: u64,
        refusal: StorageIntentRefusalReason,
    },
    /// Not enough legal candidates remained after hard gates.
    NotEnoughLegalCandidates { required: usize, available: usize },
    /// Candidate set does not span enough failure domains.
    NotEnoughFailureDomains { required: usize, available: usize },
}

impl StorageIntentPlacementReason {
    /// Return the storage-intent refusal carried by this reason, if any.
    #[must_use]
    pub const fn refusal_reason(&self) -> Option<StorageIntentRefusalReason> {
        match self {
            Self::EvidenceCutRefused { refusal }
            | Self::CandidateReceiptRefused { refusal, .. }
            | Self::CandidateMediaCapabilityRefused { refusal, .. }
            | Self::CandidateEvidenceGateRefused { refusal, .. }
            | Self::CandidateTrustDomainRefused { refusal, .. }
            | Self::CandidateMovementDebtRefused { refusal, .. } => Some(*refusal),
            Self::PreflightSimulationNotAuthoritative => {
                Some(StorageIntentRefusalReason::EvidenceNotUsable)
            }
            Self::CandidateGuaranteeFloorNotMet { .. } => {
                Some(StorageIntentRefusalReason::GuaranteeFloorNotMet)
            }
            Self::CandidateCacheOnlyCannotSatisfyAuthority { .. } => {
                Some(StorageIntentRefusalReason::CacheCannotBeAuthority)
            }
            Self::CandidateGeoRemoteEvidenceMissing { .. } => {
                Some(StorageIntentRefusalReason::FailureDomainNotMet)
            }
            Self::NotEnoughLegalCandidates { .. } => {
                Some(StorageIntentRefusalReason::NoLegalReceiptSet)
            }
            Self::NotEnoughFailureDomains { .. } => {
                Some(StorageIntentRefusalReason::FailureDomainNotMet)
            }
            _ => None,
        }
    }
}

/// Candidate evidence gates named in planner reasons.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum CandidateGate {
    CapacityAdmission,
    TransportPath,
    TrustDomain,
    DataShape,
    LayoutAllocator,
    DecisionFrontier,
}

/// Layout/allocator refusal classes preserved for explanation.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum LayoutRefusal {
    MissingEvidence,
    UnknownAllocationClass,
    PendingFreeUnsafe,
    StaleMirror,
}

/// Result of storage-intent placement hard-gate admission.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageIntentPlacementEvaluation {
    /// Whether all hard gates passed for the requested target count.
    pub admitted: bool,
    /// Target ids that survived all candidate-level gates.
    pub legal_targets: Vec<u64>,
    /// Preserved hard-gate and refusal reasons.
    pub reasons: Vec<StorageIntentPlacementReason>,
}

impl StorageIntentPlacementEvaluation {
    /// First storage-intent refusal reason, if any.
    #[must_use]
    pub fn first_refusal(&self) -> Option<StorageIntentRefusalReason> {
        self.reasons
            .iter()
            .find_map(|reason| reason.refusal_reason())
    }

    /// Returns true when any reason carries `refusal`.
    #[must_use]
    pub fn has_refusal(&self, refusal: StorageIntentRefusalReason) -> bool {
        self.reasons
            .iter()
            .any(|reason| reason.refusal_reason() == Some(refusal))
    }
}

/// Per-candidate scoring or rejection detail preserved for explanation rows.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StorageIntentPlacementCandidateReason {
    /// Candidate failed one of the hard gates.
    HardGate(StorageIntentPlacementReason),
    /// Predictor confidence is not enough to treat a candidate as ordinary.
    LowPredictionConfidence { confidence: PredictionConfidence },
    /// A one-pass scan signal must not train placement upward.
    OnePassScan,
    /// Workload evidence contradicts the requested placement phase.
    PhaseChangeContradiction {
        contradiction: tidefs_storage_intent_core::ContradictionState,
    },
    /// Movement debt remains visible to scoring/explanation consumers.
    MovementDebt { bytes: u64 },
    /// Failed payback or anti-thrash cooldown remains visible.
    FailedPaybackCooldown { cooldown_until_ms: u64 },
    /// Cost evidence was absent or unpriced, so it cannot be scored as free.
    UnknownCost,
    /// Critical reserve or wear protection blocked or penalized the target.
    CriticalReserveProtection { skipped_reason: SkippedMoveReason },
}

impl StorageIntentPlacementCandidateReason {
    /// Return the storage-intent refusal carried by this reason, if any.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<StorageIntentRefusalReason> {
        match self {
            Self::HardGate(reason) => reason.refusal_reason(),
            Self::LowPredictionConfidence { .. }
            | Self::OnePassScan
            | Self::PhaseChangeContradiction { .. }
            | Self::UnknownCost => Some(StorageIntentRefusalReason::EvidenceNotUsable),
            Self::MovementDebt { .. } | Self::FailedPaybackCooldown { .. } => {
                Some(StorageIntentRefusalReason::MovementDebtNotPaidBack)
            }
            Self::CriticalReserveProtection { skipped_reason } => {
                Some(skipped_move_refusal(*skipped_reason))
            }
        }
    }
}

/// Planner decision row for one candidate.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageIntentPlacementCandidateReport {
    /// Candidate target id.
    pub target_id: u64,
    /// Failure-domain key at the request's selected level.
    pub failure_domain_key: u64,
    /// Whether candidate-level hard gates passed.
    pub legal: bool,
    /// Whether this candidate was selected into the returned plan.
    pub selected: bool,
    /// Conservative score used only after hard gates pass.
    pub score: i64,
    /// Hard-gate and scoring reasons for #849/#850 consumers.
    pub reasons: Vec<StorageIntentPlacementCandidateReason>,
}

impl StorageIntentPlacementCandidateReport {
    /// First storage-intent refusal reason, if any.
    #[must_use]
    pub fn first_refusal(&self) -> Option<StorageIntentRefusalReason> {
        self.reasons
            .iter()
            .find_map(StorageIntentPlacementCandidateReason::refusal_reason)
    }

    /// Returns true when any report reason carries `refusal`.
    #[must_use]
    pub fn has_refusal(&self, refusal: StorageIntentRefusalReason) -> bool {
        self.reasons
            .iter()
            .any(|reason| reason.refusal_reason() == Some(refusal))
    }
}

/// Storage-intent-aware placement plan with preserved candidate reports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageIntentPlacementPlan {
    /// Whether request-level gates passed and enough legal targets were selected.
    pub admitted: bool,
    /// Deterministically selected target ids.
    pub selected_targets: Vec<u64>,
    /// Request-level reasons such as missing evidence families or short width.
    pub reasons: Vec<StorageIntentPlacementReason>,
    /// Candidate-level hard-gate and scoring rows.
    pub candidate_reports: Vec<StorageIntentPlacementCandidateReport>,
}

impl StorageIntentPlacementPlan {
    /// Target ids that survived all candidate-level hard gates.
    #[must_use]
    pub fn legal_targets(&self) -> Vec<u64> {
        self.candidate_reports
            .iter()
            .filter(|report| report.legal)
            .map(|report| report.target_id)
            .collect()
    }

    /// First storage-intent refusal reason, if any.
    #[must_use]
    pub fn first_refusal(&self) -> Option<StorageIntentRefusalReason> {
        self.reasons
            .iter()
            .find_map(StorageIntentPlacementReason::refusal_reason)
            .or_else(|| {
                self.candidate_reports
                    .iter()
                    .find_map(StorageIntentPlacementCandidateReport::first_refusal)
            })
    }
}

/// Scheduler handoff for one selected storage-intent placement target.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageIntentPlacementDispatchRecord {
    /// Selected target id from the placement plan.
    pub target_id: u64,
    /// Failure-domain key preserved from planner selection.
    pub failure_domain_key: u64,
    /// Storage-intent role being dispatched.
    pub role: StorageIntentPlacementRole,
    /// Coarse scheduler action class for the selected role.
    pub action_class: StorageIntentActionClass,
    /// Receipt id from the selected candidate input; this is not a new receipt.
    pub receipt_id: StorageIntentReceiptId,
    /// #905 decision-frontier artifact that made the selected set replayable.
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    /// Scheduler admission artifact that authorizes queueing this action.
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    /// #911 action execution is still pending; the planner never fabricates it.
    pub action_execution_ref: Option<StorageIntentEvidenceRef>,
}

/// Reason a placement plan could not be handed to an execution scheduler.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StorageIntentPlacementDispatchReason {
    /// The underlying placement plan did not satisfy hard gates.
    PlacementPlanNotAdmitted { refusal: StorageIntentRefusalReason },
    /// The #905 decision-frontier replay anchor is absent or not fresh.
    DecisionFrontierEvidenceNotFresh { state: PlacementEvidenceState },
    /// Scheduler admission evidence is absent or not fresh.
    SchedulerAdmissionEvidenceNotFresh { state: PlacementEvidenceState },
    /// A selected report no longer has a matching input candidate.
    SelectedCandidateMissing { target_id: u64 },
}

impl StorageIntentPlacementDispatchReason {
    /// Storage-intent refusal represented by this scheduler handoff reason.
    #[must_use]
    pub const fn refusal_reason(self) -> StorageIntentRefusalReason {
        match self {
            Self::PlacementPlanNotAdmitted { refusal } => refusal,
            Self::DecisionFrontierEvidenceNotFresh { .. }
            | Self::SchedulerAdmissionEvidenceNotFresh { .. } => {
                StorageIntentRefusalReason::EvidenceNotUsable
            }
            Self::SelectedCandidateMissing { .. } => StorageIntentRefusalReason::NoLegalReceiptSet,
        }
    }
}

/// Pre-execution handoff from storage-intent placement into scheduler intents.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageIntentPlacementDispatchPlan {
    /// Whether every selected target can be queued for execution.
    pub dispatchable: bool,
    /// Underlying placement decision and candidate reports.
    pub placement_plan: StorageIntentPlacementPlan,
    /// Scheduler intent records for selected targets.
    pub records: Vec<StorageIntentPlacementDispatchRecord>,
    /// Reasons execution dispatch was refused or deferred.
    pub reasons: Vec<StorageIntentPlacementDispatchReason>,
}

impl StorageIntentPlacementDispatchPlan {
    /// First storage-intent refusal reason, if any.
    #[must_use]
    pub fn first_refusal(&self) -> Option<StorageIntentRefusalReason> {
        self.reasons
            .iter()
            .map(|reason| reason.refusal_reason())
            .find(|refusal| *refusal != StorageIntentRefusalReason::None)
            .or_else(|| self.placement_plan.first_refusal())
    }
}

/// Evaluate hard constraints for one storage-intent placement request.
#[must_use]
pub fn evaluate_storage_intent_placement(
    request: &StorageIntentPlacementRequest,
    candidates: &[StorageIntentPlacementCandidate],
) -> StorageIntentPlacementEvaluation {
    let plan = plan_storage_intent_placement(request, candidates);
    let mut reasons = plan.reasons.clone();
    for report in &plan.candidate_reports {
        reasons.extend(report.reasons.iter().filter_map(|reason| match reason {
            StorageIntentPlacementCandidateReason::HardGate(reason) => Some(reason.clone()),
            _ => None,
        }));
    }

    StorageIntentPlacementEvaluation {
        admitted: plan.admitted,
        legal_targets: plan.legal_targets(),
        reasons,
    }
}

/// Build a deterministic storage-intent placement plan after hard gates.
#[must_use]
pub fn plan_storage_intent_placement(
    request: &StorageIntentPlacementRequest,
    candidates: &[StorageIntentPlacementCandidate],
) -> StorageIntentPlacementPlan {
    let mut reasons = request_level_reasons(request);
    if has_blocking_request_reason(&reasons) {
        return StorageIntentPlacementPlan {
            admitted: false,
            selected_targets: Vec::new(),
            reasons,
            candidate_reports: Vec::new(),
        };
    }

    let mut candidate_reports: Vec<StorageIntentPlacementCandidateReport> = candidates
        .iter()
        .map(|candidate| candidate_report(request, candidate))
        .collect();

    let legal_targets = candidate_reports
        .iter()
        .filter(|report| report.legal)
        .count();
    if legal_targets < request.required_target_count {
        reasons.push(StorageIntentPlacementReason::NotEnoughLegalCandidates {
            required: request.required_target_count,
            available: legal_targets,
        });
    }

    let legal_domains: BTreeSet<u64> = candidate_reports
        .iter()
        .filter(|report| report.legal)
        .map(|report| report.failure_domain_key)
        .collect();
    let selectable_failure_domains = legal_domains.len().min(request.required_target_count);
    if selectable_failure_domains < request.min_distinct_failure_domains {
        reasons.push(StorageIntentPlacementReason::NotEnoughFailureDomains {
            required: request.min_distinct_failure_domains,
            available: selectable_failure_domains,
        });
    }

    let selected_indices = select_candidate_reports(
        &candidate_reports,
        request.required_target_count,
        request.min_distinct_failure_domains,
    );
    let selected_failure_domains: BTreeSet<u64> = selected_indices
        .iter()
        .map(|index| candidate_reports[*index].failure_domain_key)
        .collect();
    let selected_index_set: BTreeSet<usize> = selected_indices.iter().copied().collect();
    for (index, report) in candidate_reports.iter_mut().enumerate() {
        report.selected = selected_index_set.contains(&index);
    }

    let selected_targets = selected_indices
        .iter()
        .map(|index| candidate_reports[*index].target_id)
        .collect::<Vec<_>>();

    let admitted = selected_targets.len() == request.required_target_count
        && selected_failure_domains.len() >= request.min_distinct_failure_domains
        && !has_blocking_request_reason(&reasons);

    StorageIntentPlacementPlan {
        admitted,
        selected_targets,
        reasons,
        candidate_reports,
    }
}

/// Build scheduler handoff records for an admitted storage-intent placement plan.
///
/// This is a model-level dispatch surface only: it preserves the selected
/// #905 decision frontier and scheduler-admission refs, but leaves #911 action
/// execution unset so callers cannot treat a queued action as a receipt,
/// cutover, or source-retirement proof.
#[must_use]
pub fn plan_storage_intent_dispatch(
    request: &StorageIntentPlacementRequest,
    candidates: &[StorageIntentPlacementCandidate],
) -> StorageIntentPlacementDispatchPlan {
    let placement_plan = plan_storage_intent_placement(request, candidates);
    let mut reasons = Vec::new();

    if !placement_plan.admitted {
        reasons.push(
            StorageIntentPlacementDispatchReason::PlacementPlanNotAdmitted {
                refusal: placement_plan
                    .first_refusal()
                    .unwrap_or(StorageIntentRefusalReason::NoLegalReceiptSet),
            },
        );
        return StorageIntentPlacementDispatchPlan {
            dispatchable: false,
            placement_plan,
            records: Vec::new(),
            reasons,
        };
    }

    let decision_frontier_ref =
        match fresh_family_ref(request, StorageIntentEvidenceKind::DecisionFrontierEvidence) {
            Some(evidence_ref) => evidence_ref,
            None => {
                reasons.push(
                    StorageIntentPlacementDispatchReason::DecisionFrontierEvidenceNotFresh {
                        state: family_state(
                            request,
                            StorageIntentEvidenceKind::DecisionFrontierEvidence,
                        ),
                    },
                );
                StorageIntentEvidenceRef::default()
            }
        };
    let scheduler_admission_ref =
        match fresh_family_ref(request, StorageIntentEvidenceKind::SchedulerAdmissionRecord) {
            Some(evidence_ref) => evidence_ref,
            None => {
                reasons.push(
                    StorageIntentPlacementDispatchReason::SchedulerAdmissionEvidenceNotFresh {
                        state: family_state(
                            request,
                            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                        ),
                    },
                );
                StorageIntentEvidenceRef::default()
            }
        };

    if !reasons.is_empty() {
        return StorageIntentPlacementDispatchPlan {
            dispatchable: false,
            placement_plan,
            records: Vec::new(),
            reasons,
        };
    }

    let mut records = Vec::with_capacity(request.required_target_count);
    for report in placement_plan
        .candidate_reports
        .iter()
        .filter(|report| report.selected)
    {
        let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.target_id == report.target_id)
        else {
            reasons.push(
                StorageIntentPlacementDispatchReason::SelectedCandidateMissing {
                    target_id: report.target_id,
                },
            );
            continue;
        };

        records.push(StorageIntentPlacementDispatchRecord {
            target_id: report.target_id,
            failure_domain_key: report.failure_domain_key,
            role: request.role,
            action_class: request.role.action_class(),
            receipt_id: candidate.receipt.receipt_id,
            decision_frontier_ref,
            scheduler_admission_ref,
            action_execution_ref: None,
        });
    }

    let dispatchable = reasons.is_empty() && records.len() == request.required_target_count;
    StorageIntentPlacementDispatchPlan {
        dispatchable,
        placement_plan,
        records,
        reasons,
    }
}

fn fresh_family_ref(
    request: &StorageIntentPlacementRequest,
    kind: StorageIntentEvidenceKind,
) -> Option<StorageIntentEvidenceRef> {
    request
        .evidence_query
        .family_freshness
        .fresh_ref_for_kind(kind)
}

fn family_state(
    request: &StorageIntentPlacementRequest,
    kind: StorageIntentEvidenceKind,
) -> PlacementEvidenceState {
    PlacementEvidenceState::from_family_state(
        request.evidence_query.family_freshness.state_for_kind(kind),
    )
}

fn request_level_reasons(
    request: &StorageIntentPlacementRequest,
) -> Vec<StorageIntentPlacementReason> {
    let mut reasons = Vec::new();

    if let Some(tier_goal) = request.tier_goal {
        reasons.push(StorageIntentPlacementReason::TierGoalIsNotStorageIntentModel(tier_goal));
    }

    match request.compiled_policy_state {
        PlacementEvidenceState::Fresh => {}
        PlacementEvidenceState::ConservativeDefault => {
            reasons.push(StorageIntentPlacementReason::CompiledPolicyConservativeDefault);
        }
        state => {
            reasons.push(StorageIntentPlacementReason::CompiledPolicyEvidence { state });
            return reasons;
        }
    }

    if let Some(refusal) = evidence_cut_refusal(request) {
        reasons.push(StorageIntentPlacementReason::EvidenceCutRefused { refusal });
        return reasons;
    }

    for kind in request.role.hard_gate_evidence() {
        require_fresh_evidence_family(&mut reasons, request, *kind);
    }
    if request.role.requires_movement_payback() {
        for kind in MOVEMENT_HARD_GATE_EVIDENCE {
            require_fresh_evidence_family(&mut reasons, request, *kind);
        }
    }
    if reasons.iter().any(|reason| {
        matches!(
            reason,
            StorageIntentPlacementReason::EvidenceFamilyNotFresh { .. }
        )
    }) {
        return reasons;
    }

    reasons
}

fn request_reason_is_non_blocking(reason: &StorageIntentPlacementReason) -> bool {
    matches!(
        reason,
        StorageIntentPlacementReason::TierGoalIsNotStorageIntentModel(_)
            | StorageIntentPlacementReason::CompiledPolicyConservativeDefault
    )
}

fn has_blocking_request_reason(reasons: &[StorageIntentPlacementReason]) -> bool {
    reasons
        .iter()
        .any(|reason| !request_reason_is_non_blocking(reason))
}

fn candidate_report(
    request: &StorageIntentPlacementRequest,
    candidate: &StorageIntentPlacementCandidate,
) -> StorageIntentPlacementCandidateReport {
    let mut hard_reasons = Vec::new();
    evaluate_candidate(request, candidate, &mut hard_reasons);

    let legal = hard_reasons.is_empty();
    let mut reasons = hard_reasons
        .into_iter()
        .map(StorageIntentPlacementCandidateReason::HardGate)
        .collect::<Vec<_>>();
    let score = score_candidate(request, candidate, &mut reasons);

    StorageIntentPlacementCandidateReport {
        target_id: candidate.target_id,
        failure_domain_key: candidate.failure_domain_key,
        legal,
        selected: false,
        score: if legal { score } else { 0 },
        reasons,
    }
}

fn select_candidate_reports(
    reports: &[StorageIntentPlacementCandidateReport],
    required: usize,
    min_distinct_domains: usize,
) -> Vec<usize> {
    let mut sorted = reports
        .iter()
        .enumerate()
        .filter_map(|(index, report)| report.legal.then_some(index))
        .collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        reports[*right]
            .score
            .cmp(&reports[*left].score)
            .then_with(|| reports[*left].target_id.cmp(&reports[*right].target_id))
    });

    let mut selected = Vec::with_capacity(required);
    let mut selected_set = BTreeSet::new();
    let mut selected_domains = BTreeSet::new();

    for index in sorted.iter().copied() {
        if selected.len() >= required || selected_domains.len() >= min_distinct_domains {
            break;
        }
        if selected_domains.insert(reports[index].failure_domain_key) {
            selected.push(index);
            selected_set.insert(index);
        }
    }

    for index in sorted {
        if selected.len() >= required {
            break;
        }
        if selected_set.insert(index) {
            selected.push(index);
        }
    }

    selected
}

fn score_candidate(
    request: &StorageIntentPlacementRequest,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementCandidateReason>,
) -> i64 {
    let mut score = confidence_score(candidate.prediction_confidence, reasons);

    if request.policy.workload.shape
        == tidefs_storage_intent_core::WorkloadShape::SequentialReadScan
        || candidate.prefetch_residency.is_some_and(|decision| {
            decision.access_pattern == tidefs_storage_intent_core::AccessPatternClass::OnePassScan
        })
    {
        reasons.push(StorageIntentPlacementCandidateReason::OnePassScan);
        score -= 1_000;
    }

    if request.policy.workload.contradiction != tidefs_storage_intent_core::ContradictionState::None
    {
        reasons.push(
            StorageIntentPlacementCandidateReason::PhaseChangeContradiction {
                contradiction: request.policy.workload.contradiction,
            },
        );
        score -= 1_000;
    }

    if let Some(layout) = candidate.layout_allocator {
        score += i64::from(layout.locality_score_ppm.min(1_000_000) / 10_000);
        score -= i64::from(layout.free_run_pressure_ppm.min(1_000_000) / 10_000);
        score -= i64::from(layout.fragmentation_ppm.min(1_000_000) / 20_000);
        if layout.reclaim_debt_bytes > 0 {
            reasons.push(StorageIntentPlacementCandidateReason::MovementDebt {
                bytes: layout.reclaim_debt_bytes,
            });
            score -= bounded_byte_penalty(layout.reclaim_debt_bytes);
        }
    }

    score_cost_wear(candidate.cost_wear, reasons, &mut score);

    if let Some(decision) = candidate.prefetch_residency {
        score_prefetch_decision(decision, reasons, &mut score);
    }

    score
}

fn confidence_score(
    confidence: PredictionConfidence,
    reasons: &mut Vec<StorageIntentPlacementCandidateReason>,
) -> i64 {
    match confidence {
        PredictionConfidence::High => 300,
        PredictionConfidence::Medium => 100,
        PredictionConfidence::Low | PredictionConfidence::Unknown => {
            reasons.push(
                StorageIntentPlacementCandidateReason::LowPredictionConfidence { confidence },
            );
            -500
        }
    }
}

fn score_cost_wear(
    cost_wear: Option<CostWearRecord>,
    reasons: &mut Vec<StorageIntentPlacementCandidateReason>,
    score: &mut i64,
) {
    let Some(cost_wear) = cost_wear else {
        reasons.push(StorageIntentPlacementCandidateReason::UnknownCost);
        *score -= 1_000;
        return;
    };

    if !cost_wear.evidence.is_bound()
        || (cost_wear.expected_write_bytes > 0 && cost_wear.write_amplification_ppm == 0)
    {
        reasons.push(StorageIntentPlacementCandidateReason::UnknownCost);
        *score -= 1_000;
    } else {
        *score -= i64::from(cost_wear.write_amplification_ppm / 100_000);
    }

    if cost_wear.movement_debt_bytes > 0 {
        reasons.push(StorageIntentPlacementCandidateReason::MovementDebt {
            bytes: cost_wear.movement_debt_bytes,
        });
        *score -= bounded_byte_penalty(cost_wear.movement_debt_bytes);
    }

    if cost_wear.cooldown_until_ms > 0 || !cost_wear.payback_evidence.is_bound() {
        reasons.push(
            StorageIntentPlacementCandidateReason::FailedPaybackCooldown {
                cooldown_until_ms: cost_wear.cooldown_until_ms,
            },
        );
        *score -= 1_000;
    }

    match cost_wear.skipped_reason {
        SkippedMoveReason::None => {}
        SkippedMoveReason::MovementDebtTooHigh | SkippedMoveReason::PaybackWindowTooLong => {
            reasons.push(StorageIntentPlacementCandidateReason::MovementDebt {
                bytes: cost_wear.movement_debt_bytes,
            });
            *score -= 1_000;
        }
        SkippedMoveReason::CooldownActive => {
            reasons.push(
                StorageIntentPlacementCandidateReason::FailedPaybackCooldown {
                    cooldown_until_ms: cost_wear.cooldown_until_ms,
                },
            );
            *score -= 1_000;
        }
        SkippedMoveReason::FlashWearBudgetExceeded
        | SkippedMoveReason::ReclaimReserveUnavailable
        | SkippedMoveReason::CostBudgetExceeded => {
            reasons.push(
                StorageIntentPlacementCandidateReason::CriticalReserveProtection {
                    skipped_reason: cost_wear.skipped_reason,
                },
            );
            *score -= 10_000;
        }
        _ => {
            reasons.push(StorageIntentPlacementCandidateReason::UnknownCost);
            *score -= 1_000;
        }
    }
}

fn score_prefetch_decision(
    decision: PrefetchResidencyDecisionRecord,
    reasons: &mut Vec<StorageIntentPlacementCandidateReason>,
    score: &mut i64,
) {
    if decision.confidence < PredictionConfidence::Medium {
        reasons.push(
            StorageIntentPlacementCandidateReason::LowPredictionConfidence {
                confidence: decision.confidence,
            },
        );
        *score -= 500;
    }

    if decision.access_pattern == tidefs_storage_intent_core::AccessPatternClass::OnePassScan {
        reasons.push(StorageIntentPlacementCandidateReason::OnePassScan);
        *score -= 1_000;
    }

    if matches!(
        decision.outcome,
        PrefetchResidencyDecisionOutcome::Cooldown
            | PrefetchResidencyDecisionOutcome::NeedMoreEvidence
    ) {
        reasons.push(
            StorageIntentPlacementCandidateReason::FailedPaybackCooldown {
                cooldown_until_ms: 0,
            },
        );
        *score -= 1_000;
    }
}

fn bounded_byte_penalty(bytes: u64) -> i64 {
    i64::try_from((bytes / 4096).min(10_000)).expect("bounded byte penalty fits i64")
}

fn evidence_cut_refusal(
    request: &StorageIntentPlacementRequest,
) -> Option<StorageIntentRefusalReason> {
    if request.role.requires_authority_role() || request.role.requires_movement_payback() {
        let refusal = request.evidence_query.authority_refusal();
        return (refusal != StorageIntentRefusalReason::None).then_some(refusal);
    }

    if request.evidence_query.is_authority_admissible()
        || request.evidence_query.allows_non_authority_visibility()
    {
        None
    } else {
        Some(StorageIntentRefusalReason::EvidenceNotUsable)
    }
}

fn require_fresh_evidence_family(
    reasons: &mut Vec<StorageIntentPlacementReason>,
    request: &StorageIntentPlacementRequest,
    kind: StorageIntentEvidenceKind,
) {
    if request.evidence_query.authorizes_fresh_evidence_kind(kind) {
        return;
    }

    let state = request.evidence_query.family_freshness.state_for_kind(kind);
    reasons.push(StorageIntentPlacementReason::EvidenceFamilyNotFresh {
        kind,
        state: PlacementEvidenceState::from_family_state(state),
    });
    if kind == StorageIntentEvidenceKind::DecisionFrontierEvidence
        && request
            .evidence_query
            .family_freshness
            .family_is_fresh_for_authority(StorageIntentEvidenceKind::PreflightSimulationEvidence)
    {
        reasons.push(StorageIntentPlacementReason::PreflightSimulationNotAuthoritative);
    }
}

fn evaluate_candidate(
    request: &StorageIntentPlacementRequest,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    let role = request.role;
    let expected_role = role.media_role();

    if candidate.receipt.media_role != expected_role {
        reasons.push(StorageIntentPlacementReason::CandidateRoleMismatch {
            target_id: candidate.target_id,
            expected: expected_role,
            actual: candidate.receipt.media_role,
        });
    }

    if !ack_receipt_satisfies_requested_floor(role.guarantee_floor(), candidate.receipt.ack_class) {
        reasons.push(
            StorageIntentPlacementReason::CandidateGuaranteeFloorNotMet {
                target_id: candidate.target_id,
                required: role.guarantee_floor(),
                actual: candidate.receipt.ack_class,
            },
        );
    }

    let receipt = evaluate_receipt_against_policy(request.policy, candidate.receipt);
    push_predicate_refusal(
        reasons,
        candidate.target_id,
        receipt,
        |target_id, refusal| StorageIntentPlacementReason::CandidateReceiptRefused {
            target_id,
            refusal,
        },
    );

    let role_requirement = MediaRoleRequirement {
        allowed_roles: MediaRoleMask::from_role(expected_role),
        require_authority_role: role.requires_authority_role(),
    };
    let media = media_capability_satisfies_role(
        role_requirement,
        candidate.receipt.ack_class,
        expected_role,
        candidate.media_capability,
    );
    push_predicate_refusal(reasons, candidate.target_id, media, |target_id, refusal| {
        StorageIntentPlacementReason::CandidateMediaCapabilityRefused { target_id, refusal }
    });

    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::CapacityAdmission,
        candidate.capacity_admission,
        StorageIntentRefusalReason::NoLegalReceiptSet,
    );
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::TransportPath,
        candidate.transport_path,
        StorageIntentRefusalReason::EvidenceNotUsable,
    );
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::TrustDomain,
        candidate.trust_domain,
        StorageIntentRefusalReason::EvidenceNotUsable,
    );
    evaluate_trust_domain(request, candidate, reasons);
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::DecisionFrontier,
        candidate.decision_frontier,
        StorageIntentRefusalReason::EvidenceNotUsable,
    );

    evaluate_data_shape(role_requires_data_shape(role), candidate, reasons);
    evaluate_layout(role_requires_layout_allocator(role), candidate, reasons);
    evaluate_cache_authority_boundary(role, candidate, reasons);
    evaluate_geo_remote_boundary(role, candidate, reasons);
    evaluate_movement_debt(role, candidate, reasons);
}

fn push_predicate_refusal<F>(
    reasons: &mut Vec<StorageIntentPlacementReason>,
    target_id: u64,
    result: ReceiptPredicateResult,
    build: F,
) where
    F: FnOnce(u64, StorageIntentRefusalReason) -> StorageIntentPlacementReason,
{
    if !result.satisfied {
        reasons.push(build(target_id, result.refusal));
    }
}

fn require_candidate_gate(
    reasons: &mut Vec<StorageIntentPlacementReason>,
    target_id: u64,
    gate: CandidateGate,
    state: PlacementEvidenceState,
    refusal: StorageIntentRefusalReason,
) {
    if !state.permits_hard_gate() {
        reasons.push(StorageIntentPlacementReason::CandidateEvidenceGateRefused {
            target_id,
            gate,
            state,
            refusal,
        });
    }
}

fn evaluate_trust_domain(
    request: &StorageIntentPlacementRequest,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    let role = request.role.trust_role();
    let Some(observed) = candidate.trust_domain_evidence else {
        reasons.push(StorageIntentPlacementReason::CandidateTrustDomainRefused {
            target_id: candidate.target_id,
            role,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
        });
        return;
    };

    let result =
        trust_domain_role_satisfies(role, trust_domain_requirement(request, role), observed);
    push_predicate_refusal(
        reasons,
        candidate.target_id,
        result,
        |target_id, refusal| StorageIntentPlacementReason::CandidateTrustDomainRefused {
            target_id,
            role,
            refusal,
        },
    );
}

fn trust_domain_requirement(
    request: &StorageIntentPlacementRequest,
    role: StorageIntentTrustRole,
) -> TrustDomainRequirement {
    let mut requirement = trust_domain_role_requirement(role);
    requirement.base.required_flags = requirement
        .base
        .required_flags
        .union(request.policy.trust.required_flags);
    requirement.base.min_session_security = request.policy.trust.min_session_security;
    requirement.base.min_key_epoch = request.policy.trust.min_key_epoch;
    requirement.base.admin_domain = request.policy.trust.admin_domain;
    requirement.base.security_domain = request.policy.trust.security_domain;
    requirement.base.tenant_domain = request.policy.trust.tenant_domain;
    requirement.base.residency = request.policy.trust.residency;
    requirement.base.sharing_domain = request.policy.trust.sharing_domain;
    requirement
}

fn role_requires_data_shape(role: StorageIntentPlacementRole) -> bool {
    !role.is_cache_only()
}

fn role_requires_layout_allocator(role: StorageIntentPlacementRole) -> bool {
    !role.is_cache_only()
}

fn evaluate_data_shape(
    required: bool,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    if !required {
        return;
    }

    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::DataShape,
        candidate.data_shape_state,
        StorageIntentRefusalReason::EvidenceNotUsable,
    );

    let Some(data_shape) = candidate.data_shape else {
        reasons.push(StorageIntentPlacementReason::CandidateEvidenceGateRefused {
            target_id: candidate.target_id,
            gate: CandidateGate::DataShape,
            state: PlacementEvidenceState::Missing,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
        });
        return;
    };

    if data_shape.transform_refusal != TransformRefusalClass::None {
        reasons.push(StorageIntentPlacementReason::CandidateDataShapeRefused {
            target_id: candidate.target_id,
            refusal: data_shape.transform_refusal,
        });
    }
}

fn evaluate_layout(
    required: bool,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    if !required {
        return;
    }

    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::LayoutAllocator,
        candidate.layout_allocator_state,
        StorageIntentRefusalReason::EvidenceNotUsable,
    );

    let Some(layout) = candidate.layout_allocator else {
        reasons.push(StorageIntentPlacementReason::CandidateLayoutRefused {
            target_id: candidate.target_id,
            refusal: LayoutRefusal::MissingEvidence,
        });
        return;
    };

    if layout.allocation_class == AllocationClass::Unknown {
        reasons.push(StorageIntentPlacementReason::CandidateLayoutRefused {
            target_id: candidate.target_id,
            refusal: LayoutRefusal::UnknownAllocationClass,
        });
    }
    if layout.pending_free_bytes > 0 && !layout.pending_free_is_safe() {
        reasons.push(StorageIntentPlacementReason::CandidateLayoutRefused {
            target_id: candidate.target_id,
            refusal: LayoutRefusal::PendingFreeUnsafe,
        });
    }
    if layout.stale_pointer_refusal {
        reasons.push(StorageIntentPlacementReason::CandidateLayoutRefused {
            target_id: candidate.target_id,
            refusal: LayoutRefusal::StaleMirror,
        });
    }
}

fn evaluate_cache_authority_boundary(
    role: StorageIntentPlacementRole,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    if !role.requires_authority_role() {
        return;
    }

    if candidate.receipt.media_role.is_cache_only() {
        reasons.push(
            StorageIntentPlacementReason::CandidateCacheOnlyCannotSatisfyAuthority {
                target_id: candidate.target_id,
            },
        );
    }

    if let Some(decision) = candidate.prefetch_residency {
        if prefetch_residency_decision_is_cache_only(decision) {
            reasons.push(
                StorageIntentPlacementReason::CandidateCacheOnlyCannotSatisfyAuthority {
                    target_id: candidate.target_id,
                },
            );
        }
    }
}

fn evaluate_geo_remote_boundary(
    role: StorageIntentPlacementRole,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    if !role.requires_geo_or_remote() {
        return;
    }

    let receipt_has_remote_or_geo = candidate.receipt.failure_domains.0
        & (tidefs_storage_intent_core::FailureDomainMask::WAN.0
            | tidefs_storage_intent_core::FailureDomainMask::INTERNET.0
            | tidefs_storage_intent_core::FailureDomainMask::GEO.0)
        != 0;
    if !receipt_has_remote_or_geo {
        reasons.push(
            StorageIntentPlacementReason::CandidateGeoRemoteEvidenceMissing {
                target_id: candidate.target_id,
            },
        );
    }
}

fn evaluate_movement_debt(
    role: StorageIntentPlacementRole,
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    let decision_requests_authority = candidate
        .prefetch_residency
        .is_some_and(prefetch_residency_decision_may_request_authority_change);

    if !role.requires_movement_payback() && !decision_requests_authority {
        return;
    }

    if matches!(
        candidate.prediction_confidence,
        PredictionConfidence::Unknown | PredictionConfidence::Low
    ) {
        reasons.push(
            StorageIntentPlacementReason::CandidateLowPredictionConfidence {
                target_id: candidate.target_id,
                confidence: candidate.prediction_confidence,
            },
        );
    }

    let Some(cost_wear) = candidate.cost_wear else {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
        });
        return;
    };

    if !cost_wear.evidence.is_bound()
        || !cost_wear.payback_evidence.is_bound()
        || cost_wear.payback_window_ms == 0
    {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: StorageIntentRefusalReason::MovementDebtNotPaidBack,
        });
    }

    if cost_wear.expected_write_bytes > 0 && cost_wear.write_amplification_ppm == 0 {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
        });
    }

    if cost_wear.flash_wear_cost_ppm == u32::MAX {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: StorageIntentRefusalReason::FlashWearBudgetExceeded,
        });
    }

    if cost_wear.skipped_reason != SkippedMoveReason::None {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: skipped_move_refusal(cost_wear.skipped_reason),
        });
    }
}

fn skipped_move_refusal(reason: SkippedMoveReason) -> StorageIntentRefusalReason {
    match reason {
        SkippedMoveReason::FlashWearBudgetExceeded => {
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        }
        SkippedMoveReason::ReceiptWouldWeaken => StorageIntentRefusalReason::ReceiptWouldWeaken,
        SkippedMoveReason::SourceQuarantined => StorageIntentRefusalReason::QuarantinedSource,
        SkippedMoveReason::NoLegalTarget => StorageIntentRefusalReason::NoLegalReceiptSet,
        SkippedMoveReason::StaleEvidence => StorageIntentRefusalReason::EvidenceNotUsable,
        SkippedMoveReason::None => StorageIntentRefusalReason::None,
        _ => StorageIntentRefusalReason::MovementDebtNotPaidBack,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        CompromiseState, DedupSharingCompatibilityState, DurabilityReceiptState,
        DurabilityRequirement, DurabilityState, EvidenceCompletenessVerdict, EvidenceConsumerClass,
        EvidenceFamilyFreshness, EvidenceFamilyFreshnessSet, EvidenceQueryContextClass,
        EvidenceQuerySubjectScope, EvidenceQuerySubjectScopeClass, FailureDomainMask,
        MediaArchiveRestoreSemantics, MediaAtomicityClass, MediaCapabilityFlags,
        MediaCapabilityFreshnessState, MediaFlushOrderingClass, MediaHealthState,
        MediaPersistenceDomain, MediaProtocolGeometryClass, MediaRemoteCommitSemantics,
        PendingFreeSafetyClass, PrefetchResidencyCandidateClass,
        PrefetchResidencyDecisionEvidenceRefs, PrefetchResidencyDecisionOutcome,
        PrefetchResidencyStateClass, ProximityClass, QuarantineState, ReadServingSourceClass,
        ResidencyScope, SegmentRegionClass, SessionSecurityClass, SharingDomainClass,
        StorageIntentActionClass, StorageIntentDomainId, StorageIntentEvidenceId,
        StorageIntentEvidenceRef, StorageIntentEvidenceRefs, StorageIntentMediaCapabilityRecord,
        StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
        StorageIntentReceiptId, StorageMediaClass, TrustEvidenceFlags,
        TrustEvidenceFreshnessState, TrustEvidenceState, TrustKeyLifecycleState, TrustRequirement,
        TrustRevocationState,
    };

    const POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId([7_u8; 16]);
    const DOMAIN_A: StorageIntentDomainId = StorageIntentDomainId([1_u8; 16]);
    const DOMAIN_B: StorageIntentDomainId = StorageIntentDomainId([2_u8; 16]);
    const ALL_TEST_EVIDENCE: &[StorageIntentEvidenceKind] = &[
        StorageIntentEvidenceKind::MembershipEvidence,
        StorageIntentEvidenceKind::OrderingEvidence,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
        StorageIntentEvidenceKind::TrustDomainEvidence,
        StorageIntentEvidenceKind::TransportPathEvidence,
        StorageIntentEvidenceKind::CapacityAdmissionEvidence,
        StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        StorageIntentEvidenceKind::PolicyRolloutEvidence,
        StorageIntentEvidenceKind::TenantIsolationEvidence,
        StorageIntentEvidenceKind::SchedulerAdmissionRecord,
        StorageIntentEvidenceKind::TemporalEvidence,
        StorageIntentEvidenceKind::DataShapeEvidence,
        StorageIntentEvidenceKind::LayoutAllocatorEvidence,
        StorageIntentEvidenceKind::ServiceObjectiveEvidence,
        StorageIntentEvidenceKind::DecisionFrontierEvidence,
        StorageIntentEvidenceKind::MediaCostWearLedger,
        StorageIntentEvidenceKind::RelocationReceipt,
        StorageIntentEvidenceKind::MeasurementAttributionEvidence,
        StorageIntentEvidenceKind::WorkloadEvidence,
    ];

    fn evidence_id(byte: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([byte; 32])
    }

    fn evidence_ref(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, evidence_id(byte), 1, 1)
    }

    fn evidence_cut(policy: StorageIntentPolicy) -> StorageIntentEvidenceQuerySnapshot {
        evidence_cut_filter(policy, |_| true)
    }

    fn evidence_cut_without(
        policy: StorageIntentPolicy,
        missing: StorageIntentEvidenceKind,
    ) -> StorageIntentEvidenceQuerySnapshot {
        evidence_cut_filter(policy, |kind| kind != missing)
    }

    fn evidence_cut_with_preflight_without_decision_frontier(
        policy: StorageIntentPolicy,
    ) -> StorageIntentEvidenceQuerySnapshot {
        evidence_cut_filter_with(
            policy,
            &[StorageIntentEvidenceKind::PreflightSimulationEvidence],
            |kind| kind != StorageIntentEvidenceKind::DecisionFrontierEvidence,
        )
    }

    fn evidence_cut_filter<F>(
        policy: StorageIntentPolicy,
        keep: F,
    ) -> StorageIntentEvidenceQuerySnapshot
    where
        F: Fn(StorageIntentEvidenceKind) -> bool,
    {
        evidence_cut_filter_with(policy, &[], keep)
    }

    fn evidence_cut_filter_with<F>(
        policy: StorageIntentPolicy,
        extra: &[StorageIntentEvidenceKind],
        keep: F,
    ) -> StorageIntentEvidenceQuerySnapshot
    where
        F: Fn(StorageIntentEvidenceKind) -> bool,
    {
        let mut included = StorageIntentEvidenceRefs::EMPTY;
        let mut freshness = EvidenceFamilyFreshnessSet::EMPTY;
        let mut byte = 10_u8;
        for kind in all_test_evidence().chain(extra.iter().copied()) {
            if !keep(kind) {
                byte = byte.wrapping_add(1);
                continue;
            }
            let evidence = evidence_ref(kind, byte);
            included.push(evidence).unwrap();
            freshness
                .push(EvidenceFamilyFreshness {
                    kind,
                    state: EvidenceFamilyFreshnessState::Fresh,
                    source_index_generation: 1,
                    producer_generation: 1,
                    freshness_frontier_ms: 1,
                    allowed_staleness_ms: 0,
                    evidence_ref: evidence,
                })
                .unwrap();
            byte = byte.wrapping_add(1);
        }

        StorageIntentEvidenceQuerySnapshot {
            snapshot_id: evidence_id(1),
            query_id: evidence_id(2),
            consumer: EvidenceConsumerClass::Planner,
            context: EvidenceQueryContextClass::ActionAdmission,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::Request,
                request_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 3),
                ..EvidenceQuerySubjectScope::default()
            },
            policy_id: policy.policy_id,
            policy_revision: policy.revision,
            temporal_frontier_ms: 1,
            freshness_frontier_ms: 1,
            allowed_staleness_ms: 0,
            source_catalog_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 4),
            source_index_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 5),
            source_index_generation: 1,
            producer_generation: 1,
            producer_watermark_ms: 1,
            compaction_generation: 0,
            redaction_generation: 0,
            included_refs: included,
            family_freshness: freshness,
            completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
            retention: tidefs_storage_intent_core::EvidenceRetentionClass::ExactRequired,
            retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 6),
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn all_test_evidence() -> impl Iterator<Item = StorageIntentEvidenceKind> {
        ALL_TEST_EVIDENCE.iter().copied()
    }

    fn policy(
        guarantee: StorageIntentGuaranteeClass,
        domains: FailureDomainMask,
    ) -> StorageIntentPolicy {
        StorageIntentPolicy {
            policy_id: POLICY_ID,
            revision: StorageIntentPolicyRevision(1),
            requested_guarantee: guarantee,
            required_failure_domains: domains,
            max_proximity: ProximityClass::Geo,
            durability: DurabilityRequirement {
                min_state: DurabilityState::FullPlacement,
                max_lag_ms: 0,
                allow_unknown_lag: false,
            },
            trust: TrustRequirement {
                required_flags: TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL
                    .union(TrustEvidenceFlags::TENANT_DOMAIN)
                    .union(TrustEvidenceFlags::AUTHORIZATION)
                    .union(TrustEvidenceFlags::NOT_QUARANTINED),
                tenant_domain: DOMAIN_A,
                ..TrustRequirement::NONE
            },
            media: MediaRoleRequirement::AUTHORITY,
            ..StorageIntentPolicy::default()
        }
    }

    fn cache_only_policy() -> StorageIntentPolicy {
        StorageIntentPolicy {
            policy_id: POLICY_ID,
            revision: StorageIntentPolicyRevision(1),
            requested_guarantee: StorageIntentGuaranteeClass::VolatileLocal,
            max_proximity: ProximityClass::Geo,
            media: MediaRoleRequirement {
                allowed_roles: MediaRoleMask::from_role(StorageMediaRole::ReadCache),
                require_authority_role: false,
            },
            ..StorageIntentPolicy::default()
        }
    }

    fn trust(domain: StorageIntentDomainId) -> TrustEvidenceState {
        TrustEvidenceState {
            flags: TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL
                .union(TrustEvidenceFlags::TENANT_DOMAIN)
                .union(TrustEvidenceFlags::AUTHORIZATION)
                .union(TrustEvidenceFlags::NOT_QUARANTINED),
            session_security: SessionSecurityClass::Authenticated,
            key_epoch: 1,
            admin_domain: StorageIntentDomainId::ZERO,
            security_domain: StorageIntentDomainId::ZERO,
            tenant_domain: domain,
            residency: ResidencyScope::GeoReplicaAllowed,
            sharing_domain: SharingDomainClass::PrivateDataset,
            compromise_state: CompromiseState::Clear,
            quarantine_state: QuarantineState::Clear,
        }
    }

    fn trust_role_for_media(role: StorageMediaRole) -> StorageIntentTrustRole {
        match role {
            StorageMediaRole::SyncIntent => StorageIntentTrustRole::SyncIntent,
            StorageMediaRole::ReadCache | StorageMediaRole::ServingDataHot => {
                StorageIntentTrustRole::ReadServing
            }
            StorageMediaRole::GeoAsyncReplica => StorageIntentTrustRole::GeoIntent,
            StorageMediaRole::ArchiveEc => StorageIntentTrustRole::ArchiveRestore,
            StorageMediaRole::RepairTemp => StorageIntentTrustRole::RelocationTarget,
            _ => StorageIntentTrustRole::DurablePlacement,
        }
    }

    fn trust_record(role: StorageIntentTrustRole) -> TrustEvidenceRecord {
        let requirement = trust_domain_role_requirement(role);
        let trust_ref = evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 53);

        TrustEvidenceRecord {
            state: TrustEvidenceState {
                flags: requirement.base.required_flags,
                session_security: requirement.base.min_session_security,
                key_epoch: 1,
                admin_domain: DOMAIN_A,
                security_domain: DOMAIN_A,
                tenant_domain: DOMAIN_A,
                residency: ResidencyScope::GeoReplicaAllowed,
                sharing_domain: SharingDomainClass::PrivateDataset,
                compromise_state: CompromiseState::Clear,
                quarantine_state: QuarantineState::Clear,
            },
            principal_ref: trust_ref,
            peer_identity_ref: trust_ref,
            admin_domain_ref: trust_ref,
            security_domain_ref: trust_ref,
            tenant_domain_ref: trust_ref,
            dataset_domain: DOMAIN_A,
            dataset_domain_ref: trust_ref,
            policy_domain: DOMAIN_A,
            policy_domain_ref: trust_ref,
            budget_owner_domain: DOMAIN_A,
            budget_owner_domain_ref: trust_ref,
            encryption_domain: DOMAIN_A,
            encryption_domain_ref: trust_ref,
            session_security_ref: trust_ref,
            key_epoch_ref: trust_ref,
            key_lifecycle: TrustKeyLifecycleState::Active,
            key_lifecycle_ref: trust_ref,
            key_lease_ref: trust_ref,
            authorization_ref: trust_ref,
            audit_ref: trust_ref,
            residency_ref: trust_ref,
            sharing_domain_ref: trust_ref,
            sharing_compatibility: DedupSharingCompatibilityState::Compatible,
            sharing_compatibility_ref: trust_ref,
            allowed_domain_classes: requirement.allowed_domain_classes,
            regulatory_domain_ref: trust_ref,
            operator_allowed_domain_ref: trust_ref,
            trust_epoch: 1,
            trust_epoch_ref: trust_ref,
            evidence_age_ms: 1,
            freshness_state: TrustEvidenceFreshnessState::Fresh,
            freshness_ref: trust_ref,
            revocation_state: TrustRevocationState::Clear,
            revocation_ref: trust_ref,
            compromise_ref: trust_ref,
            quarantine_ref: trust_ref,
            refusal_ref: trust_ref,
        }
    }

    fn receipt(
        role: StorageMediaRole,
        guarantee: StorageIntentGuaranteeClass,
        domains: FailureDomainMask,
        media: StorageMediaClass,
    ) -> StorageIntentReceipt {
        StorageIntentReceipt {
            receipt_id: StorageIntentReceiptId([9_u8; 16]),
            policy_id: POLICY_ID,
            policy_revision: StorageIntentPolicyRevision(1),
            ack_class: guarantee,
            failure_domains: domains,
            proximity: ProximityClass::Wan,
            durability: DurabilityReceiptState {
                state: DurabilityState::FullPlacement,
                observed_lag_ms: 0,
                lag_known: true,
            },
            trust: trust(DOMAIN_A),
            media_role: role,
            media_class: media,
            read_source: ReadServingSourceClass::PlacementReceipt,
            action_class: StorageIntentActionClass::DurablePlacementMovement,
            evidence_refs: StorageIntentEvidenceRefs::EMPTY,
        }
    }

    fn durable_media(media_class: StorageMediaClass) -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class,
            flags: MediaCapabilityFlags::STABLE_DEVICE_IDENTITY
                .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
                .union(MediaCapabilityFlags::POOL_MEMBER_BINDING)
                .union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION)
                .union(MediaCapabilityFlags::PERSISTENCE_DOMAIN)
                .union(MediaCapabilityFlags::FLUSH_FUA_ORDERING)
                .union(MediaCapabilityFlags::ATOMICITY_GRANULARITY)
                .union(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
                .union(MediaCapabilityFlags::HEALTH)
                .union(MediaCapabilityFlags::FRESHNESS)
                .union(MediaCapabilityFlags::REMOTE_COMMIT)
                .union(MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION),
            persistence: MediaPersistenceDomain::OrdinaryPersistent,
            flush_ordering: MediaFlushOrderingClass::FlushAndFua,
            atomicity: MediaAtomicityClass::LogicalBlockAtomic,
            geometry: MediaProtocolGeometryClass::RandomBlock,
            health: MediaHealthState::Healthy,
            freshness: MediaCapabilityFreshnessState::Fresh,
            remote_commit: MediaRemoteCommitSemantics::DurableAck,
            archive_restore: MediaArchiveRestoreSemantics::RestoreRetained,
            logical_block_bytes: 4096,
            physical_block_bytes: 4096,
            atomic_write_unit_bytes: 4096,
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 44),
            stable_identity_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                45,
            ),
            namespace_identity_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                46,
            ),
            persistence_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 47),
            flush_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 48),
            atomicity_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 49),
            geometry_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 50),
            health_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 51),
            freshness_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 52),
            remote_commit_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 53),
            archive_restore_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                54,
            ),
            ..StorageIntentMediaCapabilityRecord::default()
        }
    }

    fn volatile_media() -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::SystemRam,
            flags: MediaCapabilityFlags::PERSISTENCE_DOMAIN
                .union(MediaCapabilityFlags::HEALTH)
                .union(MediaCapabilityFlags::FRESHNESS),
            persistence: MediaPersistenceDomain::VolatileRam,
            health: MediaHealthState::Healthy,
            freshness: MediaCapabilityFreshnessState::Fresh,
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 55),
            ..StorageIntentMediaCapabilityRecord::default()
        }
    }

    fn data_shape() -> DataShapeRecord {
        DataShapeRecord {
            record_size_bytes: 131_072,
            evidence: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 60),
            ..DataShapeRecord::default()
        }
    }

    fn layout() -> LayoutAllocatorRecord {
        LayoutAllocatorRecord {
            allocation_class: AllocationClass::LargeSequential,
            region_class: SegmentRegionClass::Warm,
            pending_free_safety: PendingFreeSafetyClass::Safe,
            evidence: evidence_ref(StorageIntentEvidenceKind::LayoutAllocatorEvidence, 61),
            ..LayoutAllocatorRecord::default()
        }
    }

    fn cost_wear() -> CostWearRecord {
        CostWearRecord {
            expected_write_bytes: 4096,
            flash_wear_cost_ppm: 1,
            write_amplification_ppm: 1_000_000,
            payback_window_ms: 1,
            payback_evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 70),
            skipped_reason: SkippedMoveReason::None,
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 71),
            ..CostWearRecord::default()
        }
    }

    fn candidate(
        target_id: u64,
        domain: u64,
        role: StorageMediaRole,
        guarantee: StorageIntentGuaranteeClass,
        domains: FailureDomainMask,
        media_class: StorageMediaClass,
    ) -> StorageIntentPlacementCandidate {
        StorageIntentPlacementCandidate::new(
            target_id,
            domain,
            receipt(role, guarantee, domains, media_class),
            durable_media(media_class),
        )
        .with_fresh_hard_gates()
        .with_records()
    }

    trait CandidateTestExt {
        fn with_records(self) -> Self;
    }

    impl CandidateTestExt for StorageIntentPlacementCandidate {
        fn with_records(mut self) -> Self {
            self.data_shape = Some(data_shape());
            self.layout_allocator = Some(layout());
            self.cost_wear = Some(cost_wear());
            self.trust_domain_evidence =
                Some(trust_record(trust_role_for_media(self.receipt.media_role)));
            self.prediction_confidence = PredictionConfidence::High;
            self
        }
    }

    fn request(
        policy: StorageIntentPolicy,
        role: StorageIntentPlacementRole,
        required: usize,
        domains: usize,
    ) -> StorageIntentPlacementRequest {
        StorageIntentPlacementRequest::new(policy, role, required, domains, evidence_cut(policy))
    }

    #[test]
    fn volatile_only_media_rejects_durable_floor() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::SystemRam,
        );
        candidate.media_capability = volatile_media();

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::PersistentMediaRequired));
    }

    #[test]
    fn local_only_candidates_reject_geo_floor() {
        let policy = policy(
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
        );
        let candidate = candidate(
            1,
            10,
            StorageMediaRole::GeoAsyncReplica,
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::GeoDeltaRemoteIntent,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::FailureDomainNotMet));
    }

    #[test]
    fn under_width_failure_domain_placement_rejects() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let candidates = [
            candidate(
                1,
                10,
                StorageMediaRole::PlacementAuthority,
                StorageIntentGuaranteeClass::FullPlacement,
                FailureDomainMask::NODE,
                StorageMediaClass::NvmeFlash,
            ),
            candidate(
                2,
                10,
                StorageMediaRole::PlacementAuthority,
                StorageIntentGuaranteeClass::FullPlacement,
                FailureDomainMask::NODE,
                StorageMediaClass::NvmeFlash,
            ),
        ];

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                2,
                2,
            ),
            &candidates,
        );

        assert!(!result.admitted);
        assert!(matches!(
            result.reasons.last(),
            Some(StorageIntentPlacementReason::NotEnoughFailureDomains {
                required: 2,
                available: 1
            })
        ));
    }

    #[test]
    fn cache_only_serving_state_does_not_satisfy_durable_request() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let candidate = candidate(
            1,
            10,
            StorageMediaRole::ReadCache,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::CacheCannotBeAuthority));
    }

    #[test]
    fn cache_only_trial_does_not_require_layout_or_data_shape_records() {
        let policy = cache_only_policy();
        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::ReadCache,
            StorageIntentGuaranteeClass::VolatileLocal,
            FailureDomainMask::EMPTY,
            StorageMediaClass::SystemRam,
        );
        candidate.media_capability = volatile_media();
        candidate.data_shape = None;
        candidate.data_shape_state = PlacementEvidenceState::Unknown;
        candidate.layout_allocator = None;
        candidate.layout_allocator_state = PlacementEvidenceState::Unknown;

        let request = StorageIntentPlacementRequest::new(
            policy,
            StorageIntentPlacementRole::CacheOnlyHotServingTrial,
            1,
            1,
            evidence_cut_filter(policy, |kind| {
                !matches!(
                    kind,
                    StorageIntentEvidenceKind::DataShapeEvidence
                        | StorageIntentEvidenceKind::LayoutAllocatorEvidence
                )
            }),
        );

        let plan = plan_storage_intent_placement(&request, &[candidate]);

        assert!(plan.admitted, "{plan:?}");
        assert_eq!(plan.selected_targets, vec![1]);
        let report = plan
            .candidate_reports
            .first()
            .expect("selected candidate report exists");
        assert!(report.legal);
        assert!(!report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::HardGate(
                StorageIntentPlacementReason::CandidateEvidenceGateRefused {
                    gate: CandidateGate::DataShape | CandidateGate::LayoutAllocator,
                    ..
                } | StorageIntentPlacementReason::CandidateDataShapeRefused { .. }
                    | StorageIntentPlacementReason::CandidateLayoutRefused { .. }
            )
        )));
    }

    #[test]
    fn durable_placement_still_requires_layout_allocator_record() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        candidate.layout_allocator = None;
        candidate.layout_allocator_state = PlacementEvidenceState::Unknown;

        let plan = plan_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!plan.admitted);
        let report = plan
            .candidate_reports
            .first()
            .expect("candidate report exists");
        assert!(!report.legal);
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::HardGate(
                StorageIntentPlacementReason::CandidateEvidenceGateRefused {
                    gate: CandidateGate::LayoutAllocator,
                    state: PlacementEvidenceState::Unknown,
                    ..
                }
            )
        )));
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::HardGate(
                StorageIntentPlacementReason::CandidateLayoutRefused {
                    refusal: LayoutRefusal::MissingEvidence,
                    ..
                }
            )
        )));
    }

    #[test]
    fn wrong_domain_or_unauthorized_remote_peer_rejects_quorum_geo_repair() {
        let policy = policy(
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
        );
        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::GeoAsyncReplica,
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
            StorageMediaClass::NvmeFlash,
        );
        candidate.receipt.trust = trust(DOMAIN_B);

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::GeoDeltaRemoteIntent,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::WrongDomain));
    }

    #[test]
    fn trust_domain_record_refuses_quarantined_or_unauthorized_candidate() {
        let policy = policy(
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
        );
        let mut quarantined = candidate(
            1,
            10,
            StorageMediaRole::GeoAsyncReplica,
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
            StorageMediaClass::NvmeFlash,
        );
        let trust = quarantined
            .trust_domain_evidence
            .as_mut()
            .expect("candidate fixture carries trust/domain evidence");
        trust.state.quarantine_state = QuarantineState::Quarantined;

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::GeoDeltaRemoteIntent,
                1,
                1,
            ),
            &[quarantined],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::QuarantinedSource));
        assert!(result.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementReason::CandidateTrustDomainRefused {
                role: StorageIntentTrustRole::GeoIntent,
                refusal: StorageIntentRefusalReason::QuarantinedSource,
                ..
            }
        )));

        let mut unauthorized = candidate(
            2,
            20,
            StorageMediaRole::GeoAsyncReplica,
            StorageIntentGuaranteeClass::GeoAsync,
            FailureDomainMask::GEO,
            StorageMediaClass::NvmeFlash,
        );
        unauthorized
            .trust_domain_evidence
            .as_mut()
            .expect("candidate fixture carries trust/domain evidence")
            .authorization_ref = StorageIntentEvidenceRef::default();

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::GeoDeltaRemoteIntent,
                1,
                1,
            ),
            &[unauthorized],
        );

        assert!(!result.admitted);
        assert!(result.has_refusal(StorageIntentRefusalReason::MissingAuthorization));
    }

    #[test]
    fn authority_movement_requires_confidence_and_payback() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::ServingDataHot,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        candidate.prediction_confidence = PredictionConfidence::Low;
        candidate.cost_wear = Some(CostWearRecord {
            payback_window_ms: 0,
            skipped_reason: SkippedMoveReason::MovementDebtTooHigh,
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 80),
            ..CostWearRecord::default()
        });
        candidate.prefetch_residency = Some(PrefetchResidencyDecisionRecord {
            policy_id: POLICY_ID,
            policy_revision: StorageIntentPolicyRevision(1),
            scope: StorageIntentObjectScope::default(),
            pool_id: DOMAIN_A,
            budget_owner: DOMAIN_A,
            access_pattern: tidefs_storage_intent_core::AccessPatternClass::SmallRandomHotset,
            confidence: PredictionConfidence::Low,
            requested_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            selected_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            selected_residency: PrefetchResidencyStateClass::FlashHotServing,
            outcome: PrefetchResidencyDecisionOutcome::PromotionCandidate,
            refusal: StorageIntentRefusalReason::None,
            source_media: StorageMediaClass::HddRotational,
            target_media: StorageMediaClass::NvmeFlash,
            source_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 81),
            target_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 82),
            topology_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 83),
            max_prefetch_window_bytes: 0,
            max_staging_bytes: 0,
            evidence_refs: PrefetchResidencyDecisionEvidenceRefs::default(),
        });

        let result = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::AuthoritativeHotServingReplica,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(!result.admitted);
        assert!(result.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementReason::CandidateLowPredictionConfidence { .. }
        )));
        assert!(result.has_refusal(StorageIntentRefusalReason::MovementDebtNotPaidBack));
    }

    #[test]
    fn plan_admits_enough_legal_targets_while_reporting_rejected_candidates() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let legal = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        let mut rejected = candidate(
            2,
            20,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::SystemRam,
        );
        rejected.media_capability = volatile_media();

        let request = request(
            policy,
            StorageIntentPlacementRole::DurableFullPlacement,
            1,
            1,
        );
        let plan = plan_storage_intent_placement(&request, &[legal, rejected]);

        assert!(plan.admitted);
        assert_eq!(plan.selected_targets, vec![1]);
        assert_eq!(plan.legal_targets(), vec![1]);
        let rejected_report = plan
            .candidate_reports
            .iter()
            .find(|report| report.target_id == 2)
            .expect("rejected candidate report exists");
        assert!(!rejected_report.legal);
        assert!(rejected_report.has_refusal(StorageIntentRefusalReason::PersistentMediaRequired));

        let legacy = evaluate_storage_intent_placement(
            &request,
            &[
                candidate(
                    1,
                    10,
                    StorageMediaRole::PlacementAuthority,
                    StorageIntentGuaranteeClass::FullPlacement,
                    FailureDomainMask::NODE,
                    StorageMediaClass::NvmeFlash,
                ),
                {
                    let mut candidate = candidate(
                        2,
                        20,
                        StorageMediaRole::PlacementAuthority,
                        StorageIntentGuaranteeClass::FullPlacement,
                        FailureDomainMask::NODE,
                        StorageMediaClass::SystemRam,
                    );
                    candidate.media_capability = volatile_media();
                    candidate
                },
            ],
        );
        assert!(legacy.admitted);
        assert_eq!(legacy.legal_targets, vec![1]);
        assert!(legacy.has_refusal(StorageIntentRefusalReason::PersistentMediaRequired));
    }

    #[test]
    fn plan_selects_distinct_failure_domains_before_same_domain_score() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut first = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        first.layout_allocator.as_mut().unwrap().locality_score_ppm = 900_000;
        let mut same_domain = candidate(
            2,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        same_domain
            .layout_allocator
            .as_mut()
            .unwrap()
            .locality_score_ppm = 800_000;
        let mut other_domain = candidate(
            3,
            20,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        other_domain
            .layout_allocator
            .as_mut()
            .unwrap()
            .locality_score_ppm = 100_000;

        let plan = plan_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                2,
                2,
            ),
            &[first, same_domain, other_domain],
        );

        assert!(plan.admitted);
        assert_eq!(plan.selected_targets, vec![1, 3]);
        assert!(plan
            .candidate_reports
            .iter()
            .any(|report| report.target_id == 2 && report.legal && !report.selected));
    }

    #[test]
    fn plan_rejects_failure_domain_floor_wider_than_selected_set() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let first = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        let second = candidate(
            2,
            20,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        let plan = plan_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                2,
            ),
            &[first, second],
        );

        assert!(!plan.admitted);
        assert_eq!(plan.selected_targets.len(), 1);
        assert_eq!(plan.legal_targets(), vec![1, 2]);
        assert!(matches!(
            plan.reasons.last(),
            Some(StorageIntentPlacementReason::NotEnoughFailureDomains {
                required: 2,
                available: 1
            })
        ));

        let legacy = evaluate_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                2,
            ),
            &[
                candidate(
                    1,
                    10,
                    StorageMediaRole::PlacementAuthority,
                    StorageIntentGuaranteeClass::FullPlacement,
                    FailureDomainMask::NODE,
                    StorageMediaClass::NvmeFlash,
                ),
                candidate(
                    2,
                    20,
                    StorageMediaRole::PlacementAuthority,
                    StorageIntentGuaranteeClass::FullPlacement,
                    FailureDomainMask::NODE,
                    StorageMediaClass::NvmeFlash,
                ),
            ],
        );
        assert!(!legacy.admitted);
        assert!(legacy.has_refusal(StorageIntentRefusalReason::FailureDomainNotMet));
    }

    #[test]
    fn candidate_reports_preserve_degraded_scoring_reasons() {
        let mut policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        policy.workload.shape = tidefs_storage_intent_core::WorkloadShape::SequentialReadScan;
        policy.workload.contradiction =
            tidefs_storage_intent_core::ContradictionState::StrongContradiction;

        let mut candidate = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );
        candidate.prediction_confidence = PredictionConfidence::Low;
        candidate.cost_wear = Some(CostWearRecord {
            movement_debt_bytes: 8192,
            expected_write_bytes: 4096,
            write_amplification_ppm: 0,
            cooldown_until_ms: 123,
            skipped_reason: SkippedMoveReason::ReclaimReserveUnavailable,
            payback_evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 90),
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 91),
            ..CostWearRecord::default()
        });

        let plan = plan_storage_intent_placement(
            &request(
                policy,
                StorageIntentPlacementRole::DurableFullPlacement,
                1,
                1,
            ),
            &[candidate],
        );

        assert!(plan.admitted);
        let report = &plan.candidate_reports[0];
        assert!(report.legal);
        assert!(report.selected);
        assert!(report.score < 0);
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::LowPredictionConfidence { .. }
        )));
        assert!(report
            .reasons
            .iter()
            .any(|reason| matches!(reason, StorageIntentPlacementCandidateReason::OnePassScan)));
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::PhaseChangeContradiction { .. }
        )));
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::MovementDebt { bytes: 8192 }
        )));
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::FailedPaybackCooldown {
                cooldown_until_ms: 123
            }
        )));
        assert!(report
            .reasons
            .iter()
            .any(|reason| matches!(reason, StorageIntentPlacementCandidateReason::UnknownCost)));
        assert!(report.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementCandidateReason::CriticalReserveProtection {
                skipped_reason: SkippedMoveReason::ReclaimReserveUnavailable
            }
        )));
    }

    #[test]
    fn dispatch_records_preserve_scheduler_and_decision_refs_without_execution_receipts() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let request = request(
            policy,
            StorageIntentPlacementRole::DurableFullPlacement,
            2,
            2,
        );
        let candidates = [
            candidate(
                1,
                10,
                StorageMediaRole::PlacementAuthority,
                StorageIntentGuaranteeClass::FullPlacement,
                FailureDomainMask::NODE,
                StorageMediaClass::NvmeFlash,
            ),
            candidate(
                2,
                20,
                StorageMediaRole::PlacementAuthority,
                StorageIntentGuaranteeClass::FullPlacement,
                FailureDomainMask::NODE,
                StorageMediaClass::NvmeFlash,
            ),
        ];

        let dispatch = plan_storage_intent_dispatch(&request, &candidates);

        assert!(dispatch.dispatchable);
        assert!(dispatch.placement_plan.admitted);
        assert_eq!(dispatch.records.len(), 2);
        assert_eq!(
            dispatch
                .records
                .iter()
                .map(|record| record.target_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        for record in &dispatch.records {
            assert_eq!(
                record.role,
                StorageIntentPlacementRole::DurableFullPlacement
            );
            assert_eq!(
                record.action_class,
                StorageIntentActionClass::DurablePlacementMovement
            );
            assert_eq!(
                record.decision_frontier_ref.kind,
                StorageIntentEvidenceKind::DecisionFrontierEvidence
            );
            assert!(record.decision_frontier_ref.is_bound());
            assert_eq!(
                record.scheduler_admission_ref.kind,
                StorageIntentEvidenceKind::SchedulerAdmissionRecord
            );
            assert!(record.scheduler_admission_ref.is_bound());
            assert!(record.action_execution_ref.is_none());
        }
        assert_eq!(dispatch.first_refusal(), None);
    }

    #[test]
    fn dispatch_refuses_admitted_plan_without_scheduler_admission_evidence() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut request = request(
            policy,
            StorageIntentPlacementRole::DurableFullPlacement,
            1,
            1,
        );
        request.evidence_query =
            evidence_cut_without(policy, StorageIntentEvidenceKind::SchedulerAdmissionRecord);
        let candidate = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        let placement = plan_storage_intent_placement(&request, &[candidate.clone()]);
        assert!(placement.admitted);

        let dispatch = plan_storage_intent_dispatch(&request, &[candidate]);

        assert!(!dispatch.dispatchable);
        assert!(dispatch.placement_plan.admitted);
        assert!(dispatch.records.is_empty());
        assert_eq!(
            dispatch.first_refusal(),
            Some(StorageIntentRefusalReason::EvidenceNotUsable)
        );
        assert!(matches!(
            dispatch.reasons.as_slice(),
            [
                StorageIntentPlacementDispatchReason::SchedulerAdmissionEvidenceNotFresh {
                    state: PlacementEvidenceState::Unknown
                }
            ]
        ));
    }

    #[test]
    fn preflight_simulation_cannot_replace_live_decision_frontier() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let mut request = request(
            policy,
            StorageIntentPlacementRole::DurableFullPlacement,
            1,
            1,
        );
        request.evidence_query = evidence_cut_with_preflight_without_decision_frontier(policy);
        let candidate = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        let plan = plan_storage_intent_placement(&request, &[candidate]);

        assert!(!plan.admitted);
        assert!(plan.candidate_reports.is_empty());
        assert_eq!(
            plan.first_refusal(),
            Some(StorageIntentRefusalReason::EvidenceNotUsable)
        );
        assert!(matches!(
            plan.reasons.as_slice(),
            [
                StorageIntentPlacementReason::EvidenceFamilyNotFresh {
                    kind: StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    state: PlacementEvidenceState::Unknown
                },
                StorageIntentPlacementReason::PreflightSimulationNotAuthoritative
            ]
        ));
    }

    #[test]
    fn tier_goal_compatibility_emits_non_blocking_warning() {
        let policy = policy(
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
        );
        let cand = candidate(
            1,
            10,
            StorageMediaRole::PlacementAuthority,
            StorageIntentGuaranteeClass::FullPlacement,
            FailureDomainMask::NODE,
            StorageMediaClass::NvmeFlash,
        );

        // Request with a TierGoal set alongside a storage-intent role; the
        // planner should still admit the candidate but emit a non-blocking
        // TierGoalIsNotStorageIntentModel warning so that explanation and
        // performance consumers can see the legacy intent.
        let mut request = request(
            policy,
            StorageIntentPlacementRole::DurableFullPlacement,
            1,
            1,
        );
        request.tier_goal = Some(TierGoal::Primary);

        let plan = plan_storage_intent_placement(&request, &[cand]);
        assert!(plan.admitted);
        assert_eq!(plan.selected_targets, vec![1]);
        assert!(plan.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementReason::TierGoalIsNotStorageIntentModel(TierGoal::Primary)
        )));

        // The evaluation wrapper must also succeed and carry the same reason.
        let eval = evaluate_storage_intent_placement(
            &request,
            &[candidate(
                1,
                10,
                StorageMediaRole::PlacementAuthority,
                StorageIntentGuaranteeClass::FullPlacement,
                FailureDomainMask::NODE,
                StorageMediaClass::NvmeFlash,
            )],
        );
        assert!(eval.admitted);
        assert!(eval.reasons.iter().any(|reason| matches!(
            reason,
            StorageIntentPlacementReason::TierGoalIsNotStorageIntentModel(TierGoal::Primary)
        )));
    }
}
