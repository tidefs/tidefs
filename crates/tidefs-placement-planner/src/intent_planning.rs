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
    prefetch_residency_decision_may_request_authority_change, AllocationClass, CostWearRecord,
    DataShapeRecord, EvidenceFamilyFreshnessState, LayoutAllocatorRecord, MediaRoleMask,
    MediaRoleRequirement, PredictionConfidence, PrefetchResidencyDecisionRecord,
    ReceiptPredicateResult, SkippedMoveReason, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentGuaranteeClass, StorageIntentPolicy,
    StorageIntentReceipt, StorageIntentRefusalReason, StorageIntentRefusalReason::*,
    StorageMediaRole, TransformRefusalClass,
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
            | Self::CandidateMovementDebtRefused { refusal, .. } => Some(*refusal),
            Self::CandidateGuaranteeFloorNotMet { .. } => Some(GuaranteeFloorNotMet),
            Self::CandidateCacheOnlyCannotSatisfyAuthority { .. } => Some(CacheCannotBeAuthority),
            Self::CandidateGeoRemoteEvidenceMissing { .. } => Some(FailureDomainNotMet),
            Self::NotEnoughLegalCandidates { .. } => Some(NoLegalReceiptSet),
            Self::NotEnoughFailureDomains { .. } => Some(FailureDomainNotMet),
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

/// Evaluate hard constraints for one storage-intent placement request.
#[must_use]
pub fn evaluate_storage_intent_placement(
    request: &StorageIntentPlacementRequest,
    candidates: &[StorageIntentPlacementCandidate],
) -> StorageIntentPlacementEvaluation {
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
            return StorageIntentPlacementEvaluation {
                admitted: false,
                legal_targets: Vec::new(),
                reasons,
            };
        }
    }

    if let Some(refusal) = evidence_cut_refusal(request) {
        reasons.push(StorageIntentPlacementReason::EvidenceCutRefused { refusal });
        return StorageIntentPlacementEvaluation {
            admitted: false,
            legal_targets: Vec::new(),
            reasons,
        };
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
        return StorageIntentPlacementEvaluation {
            admitted: false,
            legal_targets: Vec::new(),
            reasons,
        };
    }

    let mut legal_targets = Vec::new();
    let mut legal_domains = BTreeSet::new();

    for candidate in candidates {
        let before = reasons.len();
        evaluate_candidate(request, candidate, &mut reasons);
        if reasons.len() == before {
            legal_targets.push(candidate.target_id);
            legal_domains.insert(candidate.failure_domain_key);
        }
    }

    if legal_targets.len() < request.required_target_count {
        reasons.push(StorageIntentPlacementReason::NotEnoughLegalCandidates {
            required: request.required_target_count,
            available: legal_targets.len(),
        });
    }

    if legal_domains.len() < request.min_distinct_failure_domains {
        reasons.push(StorageIntentPlacementReason::NotEnoughFailureDomains {
            required: request.min_distinct_failure_domains,
            available: legal_domains.len(),
        });
    }

    let admitted = reasons.iter().all(|reason| {
        matches!(
            reason,
            StorageIntentPlacementReason::TierGoalIsNotStorageIntentModel(_)
                | StorageIntentPlacementReason::CompiledPolicyConservativeDefault
        )
    });

    StorageIntentPlacementEvaluation {
        admitted,
        legal_targets,
        reasons,
    }
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
        Some(EvidenceNotUsable)
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
        NoLegalReceiptSet,
    );
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::TransportPath,
        candidate.transport_path,
        EvidenceNotUsable,
    );
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::TrustDomain,
        candidate.trust_domain,
        EvidenceNotUsable,
    );
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::DecisionFrontier,
        candidate.decision_frontier,
        EvidenceNotUsable,
    );

    evaluate_data_shape(role_requires_data_shape(role), candidate, reasons);
    evaluate_layout(candidate, reasons);
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

fn role_requires_data_shape(role: StorageIntentPlacementRole) -> bool {
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
        EvidenceNotUsable,
    );

    let Some(data_shape) = candidate.data_shape else {
        reasons.push(StorageIntentPlacementReason::CandidateEvidenceGateRefused {
            target_id: candidate.target_id,
            gate: CandidateGate::DataShape,
            state: PlacementEvidenceState::Missing,
            refusal: EvidenceNotUsable,
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
    candidate: &StorageIntentPlacementCandidate,
    reasons: &mut Vec<StorageIntentPlacementReason>,
) {
    require_candidate_gate(
        reasons,
        candidate.target_id,
        CandidateGate::LayoutAllocator,
        candidate.layout_allocator_state,
        EvidenceNotUsable,
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
    if layout.pending_free_bytes > 0 && !layout.pending_free_safe {
        reasons.push(StorageIntentPlacementReason::CandidateLayoutRefused {
            target_id: candidate.target_id,
            refusal: LayoutRefusal::PendingFreeUnsafe,
        });
    }
    if layout.stale_mirror_refusal {
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
            refusal: EvidenceNotUsable,
        });
        return;
    };

    if !cost_wear.evidence.is_bound()
        || !cost_wear.payback_evidence.is_bound()
        || cost_wear.payback_window_ms == 0
    {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: MovementDebtNotPaidBack,
        });
    }

    if cost_wear.expected_write_bytes > 0 && cost_wear.write_amplification_ppm == 0 {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: EvidenceNotUsable,
        });
    }

    if cost_wear.flash_wear_cost_ppm == u32::MAX {
        reasons.push(StorageIntentPlacementReason::CandidateMovementDebtRefused {
            target_id: candidate.target_id,
            refusal: FlashWearBudgetExceeded,
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
        SkippedMoveReason::FlashWearBudgetExceeded => FlashWearBudgetExceeded,
        SkippedMoveReason::ReceiptWouldWeaken => ReceiptWouldWeaken,
        SkippedMoveReason::SourceQuarantined => QuarantinedSource,
        SkippedMoveReason::NoLegalTarget => NoLegalReceiptSet,
        SkippedMoveReason::StaleEvidence => EvidenceNotUsable,
        SkippedMoveReason::None => StorageIntentRefusalReason::None,
        _ => MovementDebtNotPaidBack,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        CompromiseState, DurabilityReceiptState, DurabilityRequirement, DurabilityState,
        EvidenceCompletenessVerdict, EvidenceConsumerClass, EvidenceFamilyFreshness,
        EvidenceFamilyFreshnessSet, EvidenceQueryContextClass, EvidenceQuerySubjectScope,
        EvidenceQuerySubjectScopeClass, FailureDomainMask, MediaArchiveRestoreSemantics,
        MediaAtomicityClass, MediaCapabilityFlags, MediaCapabilityFreshnessState,
        MediaFlushOrderingClass, MediaHealthState, MediaPersistenceDomain,
        MediaProtocolGeometryClass, MediaRemoteCommitSemantics, PrefetchResidencyCandidateClass,
        PrefetchResidencyDecisionEvidenceRefs, PrefetchResidencyDecisionOutcome,
        PrefetchResidencyStateClass, ProximityClass, ReadServingSourceClass, ResidencyScope,
        SegmentRegionClass, SessionSecurityClass, SharingDomainClass, StorageIntentActionClass,
        StorageIntentDomainId, StorageIntentEvidenceId, StorageIntentEvidenceRef,
        StorageIntentEvidenceRefs, StorageIntentMediaCapabilityRecord, StorageIntentObjectScope,
        StorageIntentPolicyId, StorageIntentPolicyRevision, StorageIntentReceiptId,
        StorageMediaClass, TrustEvidenceFlags, TrustEvidenceState, TrustRequirement,
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
        let mut included = StorageIntentEvidenceRefs::EMPTY;
        let mut freshness = EvidenceFamilyFreshnessSet::EMPTY;
        let mut byte = 10_u8;
        for kind in all_test_evidence() {
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
            quarantine_state: tidefs_storage_intent_core::QuarantineState::Clear,
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
            pending_free_safe: true,
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
        assert!(result.has_refusal(PersistentMediaRequired));
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
        assert!(result.has_refusal(FailureDomainNotMet));
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
        assert!(result.has_refusal(CacheCannotBeAuthority));
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
        assert!(result.has_refusal(WrongDomain));
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
        assert!(result.has_refusal(MovementDebtNotPaidBack));
    }
}
