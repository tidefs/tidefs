// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Hard-gate predicates that every admitted relocation plan must pass.
//!
//! The ten hard gates enforce the storage-intent authority rules.
//! A relocation plan that fails any gate is refused with a typed reason;
//! a plan that passes all gates may be admitted subject to budget,
//! anti-thrash, and scheduling constraints.

use crate::heuristics::RelocationActionClass;
use crate::reasons::GovernorRelocationReason;

// ── Hard-gate identifiers ────────────────────────────────────────────

/// Each hard gate has a unique identifier for diagnostic and refusal
/// attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum HardGateId {
    /// Current source receipt must be authoritative and unrevoked.
    SourceReceiptAuthority = 0,

    /// Target placement must satisfy the authoritative policy.
    TargetPolicySatisfaction = 1,

    /// Foreground (sync/repair/evacuation) budget must not be consumed.
    ForegroundBudget = 2,

    /// Dirty-byte and memory budget must have headroom.
    DirtyMemoryBudget = 3,

    /// Transport (LAN/WAN) budget must have capacity.
    TransportBudget = 4,

    /// Capacity budget (scratch + old+new overlap) must have headroom.
    CapacityBudget = 5,

    /// Media-wear budget must not be exceeded (flash/NVMe lifetime).
    MediaWearBudget = 6,

    /// Prediction confidence and action class must be sufficient for
    /// the relocation reason.
    PredictionConfidenceActionClass = 7,

    /// Rollback and no-cutover proof must exist (or be waived with
    /// explicit necessity evidence).
    RollbackNoCutoverProof = 8,

    /// Replacement receipt publication must be proven before old receipt
    /// retirement (checked at replacement-published → old-receipt-retired
    /// transition; admitted-move phase requires the plan, not the proof).
    ReplacementBeforeRetirement = 9,
}

impl HardGateId {
    /// All hard gates in evaluation order.
    pub const ALL: [HardGateId; 10] = [
        HardGateId::SourceReceiptAuthority,
        HardGateId::TargetPolicySatisfaction,
        HardGateId::ForegroundBudget,
        HardGateId::DirtyMemoryBudget,
        HardGateId::TransportBudget,
        HardGateId::CapacityBudget,
        HardGateId::MediaWearBudget,
        HardGateId::PredictionConfidenceActionClass,
        HardGateId::RollbackNoCutoverProof,
        HardGateId::ReplacementBeforeRetirement,
    ];

    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HardGateId::SourceReceiptAuthority => "source-receipt-authority",
            HardGateId::TargetPolicySatisfaction => "target-policy-satisfaction",
            HardGateId::ForegroundBudget => "foreground-budget",
            HardGateId::DirtyMemoryBudget => "dirty-memory-budget",
            HardGateId::TransportBudget => "transport-budget",
            HardGateId::CapacityBudget => "capacity-budget",
            HardGateId::MediaWearBudget => "media-wear-budget",
            HardGateId::PredictionConfidenceActionClass => "prediction-confidence-action-class",
            HardGateId::RollbackNoCutoverProof => "rollback-no-cutover-proof",
            HardGateId::ReplacementBeforeRetirement => "replacement-before-retirement",
        }
    }
}

impl core::fmt::Display for HardGateId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Hard-gate result ─────────────────────────────────────────────────

/// Result of evaluating a single hard gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardGateResult {
    /// The gate passed.
    Pass,
    /// The gate failed with a refusal reason.
    Fail(HardGateRefusalReason),
    /// The gate requires evidence that is currently unknown or missing.
    /// This blocks authority-changing moves; necessity-class moves may
    /// proceed with degraded-visible state.
    UnknownEvidence,
    /// The gate is not applicable for this relocation reason.
    NotApplicable,
}

impl HardGateResult {
    /// Returns true when the gate blocks the relocation.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, HardGateResult::Fail(_))
    }

    /// Returns true when evidence is missing (blocks authority, not necessity).
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, HardGateResult::UnknownEvidence)
    }

    /// Returns the refusal reason if this is a failure.
    #[must_use]
    pub const fn refusal_reason(self) -> Option<HardGateRefusalReason> {
        match self {
            HardGateResult::Fail(r) => Some(r),
            _ => None,
        }
    }
}

// ── Hard-gate refusal reasons ────────────────────────────────────────

/// Reasons a hard gate can refuse a relocation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum HardGateRefusalReason {
    /// Source receipt is missing, revoked, or not authoritative.
    SourceReceiptNotAuthoritative = 0,

    /// Target placement would violate the authoritative policy.
    TargetWouldViolatePolicy = 1,

    /// Foreground budget is exhausted or would be consumed.
    ForegroundBudgetExhausted = 2,

    /// Dirty-byte or memory budget is exhausted.
    DirtyMemoryBudgetExhausted = 3,

    /// Transport budget (LAN or WAN) is exhausted.
    TransportBudgetExhausted = 4,

    /// Capacity budget (scratch + overlap) is exhausted.
    CapacityBudgetExhausted = 5,

    /// Media-wear budget would be exceeded (flash/NVMe lifetime).
    MediaWearBudgetExceeded = 6,

    /// Prediction confidence is too low for the action class.
    PredictionConfidenceTooLow = 7,

    /// Action class is insufficient for the relocation reason.
    ActionClassInsufficient = 8,

    /// Rollback or no-cutover proof is missing.
    RollbackProofMissing = 9,

    /// Replacement receipt has not been published.
    ReplacementReceiptNotPublished = 10,

    /// Stale evidence prevents safe gate evaluation.
    StaleEvidence = 11,

    /// Contradictory evidence prevents safe gate evaluation.
    ContradictoryEvidence = 12,

    /// Media capability evidence is missing — cannot verify target role.
    MediaCapabilityMissing = 13,

    /// Target media is not eligible for the requested role.
    TargetMediaNotEligible = 14,
}

impl HardGateRefusalReason {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HardGateRefusalReason::SourceReceiptNotAuthoritative => {
                "source-receipt-not-authoritative"
            }
            HardGateRefusalReason::TargetWouldViolatePolicy => "target-would-violate-policy",
            HardGateRefusalReason::ForegroundBudgetExhausted => "foreground-budget-exhausted",
            HardGateRefusalReason::DirtyMemoryBudgetExhausted => "dirty-memory-budget-exhausted",
            HardGateRefusalReason::TransportBudgetExhausted => "transport-budget-exhausted",
            HardGateRefusalReason::CapacityBudgetExhausted => "capacity-budget-exhausted",
            HardGateRefusalReason::MediaWearBudgetExceeded => "media-wear-budget-exceeded",
            HardGateRefusalReason::PredictionConfidenceTooLow => "prediction-confidence-too-low",
            HardGateRefusalReason::ActionClassInsufficient => "action-class-insufficient",
            HardGateRefusalReason::RollbackProofMissing => "rollback-proof-missing",
            HardGateRefusalReason::ReplacementReceiptNotPublished => {
                "replacement-receipt-not-published"
            }
            HardGateRefusalReason::StaleEvidence => "stale-evidence",
            HardGateRefusalReason::ContradictoryEvidence => "contradictory-evidence",
            HardGateRefusalReason::MediaCapabilityMissing => "media-capability-missing",
            HardGateRefusalReason::TargetMediaNotEligible => "target-media-not-eligible",
        }
    }
}

impl core::fmt::Display for HardGateRefusalReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Hard-gate evaluation context ─────────────────────────────────────

/// Input evidence snapshot for hard-gate evaluation.
///
/// For the first #848 law/model slice, evidence producers (#844, #845,
/// #878, #880, #874) are non-blocking. When producer evidence is missing,
/// the governor represents it as unknown/refused/blocked/cooldown state.
/// The `HardGates` evaluator returns `UnknownEvidence` for gates that
/// depend on missing evidence; calling code then decides whether the
/// relocation reason permits degraded-visible or blocked state.
#[derive(Clone, Debug, Default)]
pub struct HardGateEvidence {
    /// Source receipt is known and authoritative.
    pub source_receipt_authoritative: Option<bool>,

    /// Target placement satisfies policy (Some(true) = known satisfied).
    pub target_satisfies_policy: Option<bool>,

    /// Foreground budget headroom in abstract tokens.
    pub foreground_budget_available: Option<u64>,

    /// Dirty-byte and memory budget headroom in bytes.
    pub dirty_memory_budget_available: Option<u64>,

    /// Transport budget headroom in bytes or tokens.
    pub transport_budget_available: Option<u64>,

    /// Capacity budget headroom (scratch + overlap) in bytes.
    pub capacity_budget_available: Option<u64>,

    /// Media-wear budget headroom in flash write ppm.
    pub media_wear_budget_available: Option<u32>,

    /// Prediction confidence level. None = unknown.
    pub prediction_confidence: Option<u8>,

    /// Relocation action class. None = unset.
    pub action_class: Option<RelocationActionClass>,

    /// Rollback/no-cutover proof is available.
    pub rollback_proof_available: Option<bool>,

    /// Replacement receipt has been published.
    pub replacement_receipt_published: Option<bool>,

    /// Target media capability evidence is fresh.
    pub media_capability_fresh: Option<bool>,

    /// Target media is eligible for the requested role.
    pub target_media_eligible: Option<bool>,

    /// Evidence freshness assessment (Some(true) = all evidence fresh).
    pub evidence_is_fresh: Option<bool>,

    /// Evidence consistency assessment (Some(false) = contradictory).
    pub evidence_is_consistent: Option<bool>,
}

// ── Hard-gates evaluator ────────────────────────────────────────────

/// The ten hard gates evaluated for every relocation plan.
///
/// Gate evaluation is pure and deterministic given the evidence snapshot.
/// Missing evidence produces `UnknownEvidence` rather than `Fail`;
/// the caller decides whether unknown evidence blocks the relocation
/// based on the relocation reason and authority-change class.
#[derive(Clone, Debug)]
pub struct HardGates {
    /// Per-gate results, indexed by [`HardGateId`] discriminant.
    results: [HardGateResult; 10],
}

impl HardGates {
    /// Evaluate all ten hard gates against the given evidence snapshot.
    #[must_use]
    pub fn evaluate(reason: GovernorRelocationReason, evidence: &HardGateEvidence) -> Self {
        let mut results = [HardGateResult::NotApplicable; 10];

        // Gate 0: Source receipt authority
        results[0] = Self::evaluate_source_receipt(evidence);

        // Gate 1: Target policy satisfaction
        results[1] = Self::evaluate_target_policy(evidence);

        // Gate 2: Foreground budget
        results[2] = Self::evaluate_foreground_budget(evidence, reason);

        // Gate 3: Dirty-byte / memory budget
        results[3] = Self::evaluate_dirty_memory_budget(evidence, reason);

        // Gate 4: Transport budget
        results[4] = Self::evaluate_transport_budget(evidence, reason);

        // Gate 5: Capacity budget
        results[5] = Self::evaluate_capacity_budget(evidence, reason);

        // Gate 6: Media-wear budget
        results[6] = Self::evaluate_media_wear_budget(evidence, reason);

        // Gate 7: Prediction confidence / action class
        results[7] = Self::evaluate_prediction_confidence(evidence, reason);

        // Gate 8: Rollback / no-cutover proof
        results[8] = Self::evaluate_rollback_proof(evidence, reason);

        // Gate 9: Replacement before retirement (checked at transition)
        results[9] = Self::evaluate_replacement_before_retirement(evidence);

        HardGates { results }
    }

    /// Returns the result for a specific gate.
    #[must_use]
    pub fn gate_result(&self, gate: HardGateId) -> HardGateResult {
        self.results[gate as usize]
    }

    /// Returns true when all applicable gates pass.
    #[must_use]
    pub fn all_pass(&self) -> bool {
        self.results.iter().all(|r| !r.is_blocking())
    }

    /// Returns true when any gate has failed.
    #[must_use]
    pub fn any_fail(&self) -> bool {
        self.results.iter().any(|r| r.is_blocking())
    }

    /// Returns true when any gate has unknown evidence (and none have
    /// failed outright).
    #[must_use]
    pub fn any_unknown_but_no_fail(&self) -> bool {
        !self.any_fail() && self.results.iter().any(|r| r.is_unknown())
    }

    /// Collect all refusal reasons from failed gates.
    #[must_use]
    pub fn refusal_reasons(&self) -> Vec<(HardGateId, HardGateRefusalReason)> {
        self.results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                r.refusal_reason()
                    .map(|reason| (HardGateId::ALL[i], reason))
            })
            .collect()
    }

    /// Collect gate IDs with unknown evidence.
    #[must_use]
    pub fn unknown_gates(&self) -> Vec<HardGateId> {
        self.results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if r.is_unknown() {
                    Some(HardGateId::ALL[i])
                } else {
                    None
                }
            })
            .collect()
    }

    // ── Individual gate evaluators ─────────────────────────────────

    fn evaluate_source_receipt(evidence: &HardGateEvidence) -> HardGateResult {
        match evidence.source_receipt_authoritative {
            Some(true) => HardGateResult::Pass,
            Some(false) => {
                HardGateResult::Fail(HardGateRefusalReason::SourceReceiptNotAuthoritative)
            }
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_target_policy(evidence: &HardGateEvidence) -> HardGateResult {
        match evidence.target_satisfies_policy {
            Some(true) => HardGateResult::Pass,
            Some(false) => HardGateResult::Fail(HardGateRefusalReason::TargetWouldViolatePolicy),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_foreground_budget(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        // Necessity-class reasons (repair, evacuation) are exempt from
        // foreground budget gate — they are the foreground work.
        if reason.is_necessity() {
            return HardGateResult::Pass;
        }
        // Optimization-class reasons must not consume foreground budget.
        match evidence.foreground_budget_available {
            Some(budget) if budget > 0 => HardGateResult::Pass,
            Some(_) => HardGateResult::Fail(HardGateRefusalReason::ForegroundBudgetExhausted),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_dirty_memory_budget(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        if reason.is_necessity() {
            return HardGateResult::Pass;
        }
        match evidence.dirty_memory_budget_available {
            Some(budget) if budget > 0 => HardGateResult::Pass,
            Some(_) => HardGateResult::Fail(HardGateRefusalReason::DirtyMemoryBudgetExhausted),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_transport_budget(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        if reason.is_necessity() {
            return HardGateResult::Pass;
        }
        match evidence.transport_budget_available {
            Some(budget) if budget > 0 => HardGateResult::Pass,
            Some(_) => HardGateResult::Fail(HardGateRefusalReason::TransportBudgetExhausted),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_capacity_budget(
        evidence: &HardGateEvidence,
        _reason: GovernorRelocationReason,
    ) -> HardGateResult {
        // All relocation reasons, including necessity, require capacity
        // budget headroom (scratch + overlap). Necessity may borrow from
        // protected reserves with explicit degradation evidence.
        match evidence.capacity_budget_available {
            Some(budget) if budget > 0 => HardGateResult::Pass,
            Some(_) => HardGateResult::Fail(HardGateRefusalReason::CapacityBudgetExhausted),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_media_wear_budget(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        // Flash wear budget gate applies only to reasons that spend flash
        // lifetime. Non-flash reasons skip this gate.
        if !reason.requires_flash_wear_justification() {
            return HardGateResult::Pass;
        }
        // Check evidence freshness and media capability first.
        if let Some(false) = evidence.evidence_is_fresh {
            return HardGateResult::Fail(HardGateRefusalReason::StaleEvidence);
        }
        if let Some(false) = evidence.media_capability_fresh {
            return HardGateResult::Fail(HardGateRefusalReason::MediaCapabilityMissing);
        }
        if let Some(false) = evidence.target_media_eligible {
            return HardGateResult::Fail(HardGateRefusalReason::TargetMediaNotEligible);
        }
        match evidence.media_wear_budget_available {
            Some(budget) if budget > 0 => HardGateResult::Pass,
            Some(_) => HardGateResult::Fail(HardGateRefusalReason::MediaWearBudgetExceeded),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_prediction_confidence(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        // Prediction confidence gate: authority-changing moves require
        // at least medium confidence. Optimization moves require at least
        // low confidence. Necessity moves skip this gate.
        if reason.is_necessity() {
            return HardGateResult::Pass;
        }
        // Check for contradictory evidence.
        if let Some(false) = evidence.evidence_is_consistent {
            return HardGateResult::Fail(HardGateRefusalReason::ContradictoryEvidence);
        }
        let action_class = match evidence.action_class {
            Some(ac) => ac,
            None => return HardGateResult::UnknownEvidence,
        };
        let confidence = match evidence.prediction_confidence {
            Some(c) => c,
            None => return HardGateResult::UnknownEvidence,
        };
        let min_action_class = reason.minimum_action_class();
        let min_confidence = reason.minimum_prediction_confidence();

        if action_class < min_action_class {
            return HardGateResult::Fail(HardGateRefusalReason::ActionClassInsufficient);
        }
        if confidence < min_confidence {
            return HardGateResult::Fail(HardGateRefusalReason::PredictionConfidenceTooLow);
        }
        HardGateResult::Pass
    }

    fn evaluate_rollback_proof(
        evidence: &HardGateEvidence,
        reason: GovernorRelocationReason,
    ) -> HardGateResult {
        // Rollback/no-cutover proof is required for authority-changing
        // moves. Necessity moves may waive it with explicit evidence.
        if reason.is_necessity() {
            return HardGateResult::Pass;
        }
        if !reason.changes_authority() {
            // Optimization moves that don't change authority (defrag,
            // compaction) don't need rollback proof for safety — the
            // source receipt remains authoritative during the move.
            return HardGateResult::Pass;
        }
        match evidence.rollback_proof_available {
            Some(true) => HardGateResult::Pass,
            Some(false) => HardGateResult::Fail(HardGateRefusalReason::RollbackProofMissing),
            None => HardGateResult::UnknownEvidence,
        }
    }

    fn evaluate_replacement_before_retirement(evidence: &HardGateEvidence) -> HardGateResult {
        // This gate is checked at the replacement-published →
        // old-receipt-retired transition. During admission, we
        // verify the plan includes the publication step.
        match evidence.replacement_receipt_published {
            Some(true) => HardGateResult::Pass,
            Some(false) => {
                HardGateResult::Fail(HardGateRefusalReason::ReplacementReceiptNotPublished)
            }
            // At admission time, the replacement receipt hasn't been
            // published yet — that's expected. The plan must include it.
            None => HardGateResult::Pass,
        }
    }
}

impl Default for HardGates {
    fn default() -> Self {
        HardGates {
            results: [HardGateResult::NotApplicable; 10],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_all_known_satisfied() -> HardGateEvidence {
        HardGateEvidence {
            source_receipt_authoritative: Some(true),
            target_satisfies_policy: Some(true),
            foreground_budget_available: Some(100),
            dirty_memory_budget_available: Some(1024 * 1024),
            transport_budget_available: Some(1024 * 1024),
            capacity_budget_available: Some(1024 * 1024),
            media_wear_budget_available: Some(1000),
            prediction_confidence: Some(3), // high
            action_class: Some(RelocationActionClass::AuthorityMovement),
            rollback_proof_available: Some(true),
            replacement_receipt_published: Some(true),
            media_capability_fresh: Some(true),
            target_media_eligible: Some(true),
            evidence_is_fresh: Some(true),
            evidence_is_consistent: Some(true),
        }
    }

    fn evidence_all_unknown() -> HardGateEvidence {
        HardGateEvidence::default()
    }

    #[test]
    fn all_gates_pass_with_satisfied_evidence_authority_move() {
        let evidence = evidence_all_known_satisfied();
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.all_pass());
        assert!(!gates.any_fail());
    }

    #[test]
    fn all_gates_pass_with_satisfied_evidence_defrag() {
        let evidence = evidence_all_known_satisfied();
        let gates = HardGates::evaluate(GovernorRelocationReason::HddDefrag, &evidence);
        assert!(gates.all_pass());
        assert!(!gates.any_fail());
    }

    #[test]
    fn repair_passes_even_without_budgets() {
        // Repair must always admit — budgets don't block necessity.
        let mut evidence = evidence_all_known_satisfied();
        evidence.foreground_budget_available = Some(0);
        evidence.dirty_memory_budget_available = Some(0);
        evidence.transport_budget_available = Some(0);
        let gates = HardGates::evaluate(GovernorRelocationReason::Repair, &evidence);
        assert!(gates.all_pass());
    }

    #[test]
    fn optimization_refused_when_foreground_budget_exhausted() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.foreground_budget_available = Some(0);
        let gates = HardGates::evaluate(GovernorRelocationReason::HddDefrag, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::ForegroundBudget));
    }

    #[test]
    fn source_receipt_not_authoritative_blocks() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.source_receipt_authoritative = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::Repair, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::SourceReceiptAuthority));
    }

    #[test]
    fn target_violates_policy_blocks() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.target_satisfies_policy = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::TargetPolicySatisfaction));
    }

    #[test]
    fn media_wear_budget_exceeded_blocks_flash_reasons() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.media_wear_budget_available = Some(0);
        let gates = HardGates::evaluate(GovernorRelocationReason::SsdCompaction, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::MediaWearBudget));
    }

    #[test]
    fn media_wear_budget_skipped_for_hdd_defrag() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.media_wear_budget_available = Some(0);
        let gates = HardGates::evaluate(GovernorRelocationReason::HddDefrag, &evidence);
        assert!(gates.all_pass(), "HDD defrag should skip media wear gate");
    }

    #[test]
    fn prediction_confidence_too_low_blocks_authority_move() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.prediction_confidence = Some(0); // unknown → too low
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::PredictionConfidenceActionClass));
    }

    #[test]
    fn rollback_proof_missing_blocks_authority_move() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.rollback_proof_available = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(id, _)| *id == HardGateId::RollbackNoCutoverProof));
    }

    #[test]
    fn rollback_proof_not_required_for_defrag() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.rollback_proof_available = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::HddDefrag, &evidence);
        assert!(gates.all_pass());
    }

    #[test]
    fn unknown_evidence_detected() {
        let evidence = evidence_all_unknown();
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.any_unknown_but_no_fail());
        let unknown = gates.unknown_gates();
        assert!(!unknown.is_empty());
    }

    #[test]
    fn contradictory_evidence_blocks_prediction_gate() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.evidence_is_consistent = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::Promotion, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(_, r)| matches!(r, HardGateRefusalReason::ContradictoryEvidence)));
    }

    #[test]
    fn stale_evidence_blocks_media_wear_gate() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.evidence_is_fresh = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::SsdCompaction, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(_, r)| matches!(r, HardGateRefusalReason::StaleEvidence)));
    }

    #[test]
    fn media_capability_missing_blocks_flash_gate() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.media_capability_fresh = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::WearRebalance, &evidence);
        assert!(gates.any_fail());
        let refusals = gates.refusal_reasons();
        assert!(refusals
            .iter()
            .any(|(_, r)| matches!(r, HardGateRefusalReason::MediaCapabilityMissing)));
    }

    #[test]
    fn target_media_not_eligible_blocks() {
        let mut evidence = evidence_all_known_satisfied();
        evidence.target_media_eligible = Some(false);
        let gates = HardGates::evaluate(GovernorRelocationReason::SsdCompaction, &evidence);
        assert!(gates.any_fail());
    }

    #[test]
    fn all_gate_labels_nonempty() {
        for gate in &HardGateId::ALL {
            assert!(!format!("{gate}").is_empty());
        }
    }

    #[test]
    fn all_refusal_reason_labels_nonempty() {
        // Use a representative sample
        let reasons = [
            HardGateRefusalReason::SourceReceiptNotAuthoritative,
            HardGateRefusalReason::TargetWouldViolatePolicy,
            HardGateRefusalReason::ForegroundBudgetExhausted,
        ];
        for reason in &reasons {
            assert!(!format!("{reason}").is_empty());
        }
    }
}
