// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Relocation admission: the decision layer that evaluates evidence,
//! hard gates, anti-thrash rules, and heuristics to admit or refuse
//! a relocation plan.


use crate::anti_thrash::{AntiThrashDecision, AntiThrashState};
use crate::hard_gates::{HardGateEvidence, HardGateId, HardGates};
use crate::heuristics::{HeuristicInput, HeuristicResult, RelocationActionClass};
use crate::lifecycle::GovernorLifecycleState;
use crate::reasons::GovernorRelocationReason;
use crate::{hdd_heuristics, ssd_heuristics, wan_heuristics};

// ── Admission decision ───────────────────────────────────────────────

/// The governor's admission decision for a relocation proposal.
#[derive(Clone, Debug)]
pub struct AdmissionDecision {
    /// Whether the relocation is admitted.
    pub verdict: AdmissionVerdict,

    /// The recommended action class.
    pub action_class: RelocationActionClass,

    /// The relocation reason.
    pub reason: GovernorRelocationReason,

    /// Target lifecycle state after admission (or current state if refused).
    pub target_state: GovernorLifecycleState,

    /// Hard-gate evaluation results.
    pub hard_gates: HardGates,

    /// Anti-thrash evaluation outcome.
    pub anti_thrash: AntiThrashDecision,

    /// Media-specific heuristic result, if applicable.
    pub heuristic: Option<HeuristicResult>,

    /// Human-readable summary.
    pub summary: &'static str,
}

/// Admission verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionVerdict {
    /// The relocation is admitted for execution.
    Admitted,

    /// The relocation is refused (hard gate, anti-thrash, or heuristic).
    Refused,

    /// Evidence is missing or unknown; authority-changing moves are
    /// blocked, necessity moves may proceed with degraded state.
    BlockedPendingEvidence,

    /// The relocation enters cooldown with a skip reason.
    Cooldown,

    /// The relocation plan is acknowledged as a cache-only serving trial.
    ServingTrialOnly,
}

impl AdmissionVerdict {
    /// Returns true when the relocation may proceed (admitted or trial).
    #[must_use]
    pub const fn may_proceed(self) -> bool {
        matches!(
            self,
            AdmissionVerdict::Admitted | AdmissionVerdict::ServingTrialOnly
        )
    }

    /// Returns true when authority-changing execution is permitted.
    #[must_use]
    pub const fn permits_authority_change(self) -> bool {
        matches!(self, AdmissionVerdict::Admitted)
    }
}

// ── Admission record ─────────────────────────────────────────────────

/// A durable record of a relocation admission decision.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdmissionRecord {
    /// Unique identifier for this admission decision.
    pub admission_id: u64,

    /// The relocation reason.
    pub reason: GovernorRelocationReason,

    /// The admission verdict.
    pub verdict: AdmissionVerdict,

    /// The assigned action class.
    pub action_class: RelocationActionClass,

    /// Source receipt identity.
    pub source_receipt_id: [u8; 16],

    /// Target placement identity.
    pub target_placement_id: [u8; 16],

    /// Timestamp of admission (ms since epoch).
    pub admitted_at_ms: u64,

    /// Hard-gate refusal reasons (empty if all pass).
    pub refusal_reasons: Vec<(HardGateId, crate::hard_gates::HardGateRefusalReason)>,

    /// Anti-thrash skip reason (None if admitted).
    pub anti_thrash_skip_reason: Option<&'static str>,

    /// Heuristic summary.
    pub heuristic_summary: Option<&'static str>,

    /// Payback window if applicable.
    pub payback_window_ms: Option<u64>,

    /// Payback benefit type if applicable.
    pub payback_benefit_type: Option<crate::anti_thrash::PaybackBenefitType>,
}

// ── Admission evaluation ─────────────────────────────────────────────

/// Evaluate a relocation proposal for admission.
///
/// This is the central admission function: it runs anti-thrash checks,
/// media-specific heuristics, and hard-gate evaluation in order.
/// The result determines whether the relocation proceeds and at what
/// action class.
#[must_use]
pub fn evaluate_relocation_admission(
    reason: GovernorRelocationReason,
    anti_thrash: &AntiThrashState,
    heuristic_input: &HeuristicInput,
    gate_evidence: &HardGateEvidence,
    now_ms: u64,
) -> AdmissionDecision {
    // 1. Anti-thrash evaluation
    let at_decision = anti_thrash.evaluate(now_ms, reason);
    if at_decision.is_blocking() {
        return AdmissionDecision {
            verdict: AdmissionVerdict::Refused,
            action_class: RelocationActionClass::None,
            reason,
            target_state: GovernorLifecycleState::Cooldown,
            hard_gates: HardGates::default(),
            anti_thrash: at_decision,
            heuristic: None,
            summary: "blocked-by-anti-thrash",
        };
    }

    // 2. Media-specific heuristic evaluation
    let heuristic = match reason {
        GovernorRelocationReason::HddDefrag => Some(hdd_heuristics::evaluate_hdd_defrag(
            heuristic_input,
        )),
        GovernorRelocationReason::SsdCompaction => Some(ssd_heuristics::evaluate_ssd_compaction(
            heuristic_input,
        )),
        GovernorRelocationReason::WearRebalance => Some(
            ssd_heuristics::evaluate_ssd_wear_rebalance(heuristic_input),
        ),
        GovernorRelocationReason::GeoCatchup => {
            Some(wan_heuristics::evaluate_geo_catchup(heuristic_input))
        }
        _ => None,
    };

    if let Some(ref h) = heuristic {
        if !h.recommend && h.evidence_sufficient {
            // Heuristic blocks with sufficient evidence → refuse.
            return AdmissionDecision {
                verdict: AdmissionVerdict::Refused,
                action_class: RelocationActionClass::None,
                reason,
                target_state: GovernorLifecycleState::Refused,
                hard_gates: HardGates::default(),
                anti_thrash: at_decision,
                heuristic: Some(h.clone()),
                summary: h.summary,
            };
        }
    }

    // 3. Hard-gate evaluation
    let hard_gates = HardGates::evaluate(reason, gate_evidence);

    if hard_gates.any_fail() {
        return AdmissionDecision {
            verdict: AdmissionVerdict::Refused,
            action_class: RelocationActionClass::None,
            reason,
            target_state: GovernorLifecycleState::Refused,
            hard_gates,
            anti_thrash: at_decision,
            heuristic,
            summary: "blocked-by-hard-gate",
        };
    }

    if hard_gates.any_unknown_but_no_fail() {
        // Unknown evidence: authority-changing moves are blocked;
        // necessity moves may proceed with degraded-visible state.
        if reason.changes_authority() && !reason.is_necessity() {
            return AdmissionDecision {
                verdict: AdmissionVerdict::BlockedPendingEvidence,
                action_class: RelocationActionClass::None,
                reason,
                target_state: GovernorLifecycleState::Observed,
                hard_gates,
                anti_thrash: at_decision,
                heuristic,
                summary: "blocked-pending-evidence",
            };
        }
        // Necessity moves or non-authority optimization may proceed
        // with unknown evidence (degraded-visible state).
    }

    // 4. Determine action class
    let action_class = reason.minimum_action_class();

    // 5. Determine verdict and target state
    let (verdict, target_state, summary) = match action_class {
        RelocationActionClass::CacheOnly | RelocationActionClass::ServingTrial => {
            (
                AdmissionVerdict::ServingTrialOnly,
                GovernorLifecycleState::ServingTrial,
                "admitted-serving-trial",
            )
        }
        _ => {
            let is_authority = action_class.changes_authority();
            if is_authority && hard_gates.any_unknown_but_no_fail() && !reason.is_necessity() {
                // Authority move with unknown evidence → shadow-evaluated,
                // cannot admit.
                (
                    AdmissionVerdict::BlockedPendingEvidence,
                    GovernorLifecycleState::ShadowEvaluated,
                    "shadow-evaluated-pending-evidence",
                )
            } else {
                (
                    AdmissionVerdict::Admitted,
                    GovernorLifecycleState::AdmittedMove,
                    "admitted",
                )
            }
        }
    };

    AdmissionDecision {
        verdict,
        action_class,
        reason,
        target_state,
        hard_gates,
        anti_thrash: at_decision,
        heuristic,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hard_gates::HardGateEvidence;

    fn clean_evidence() -> HardGateEvidence {
        HardGateEvidence {
            source_receipt_authoritative: Some(true),
            target_satisfies_policy: Some(true),
            foreground_budget_available: Some(100),
            dirty_memory_budget_available: Some(1024 * 1024),
            transport_budget_available: Some(1024 * 1024),
            capacity_budget_available: Some(1024 * 1024),
            media_wear_budget_available: Some(1000),
            prediction_confidence: Some(3),
            action_class: Some(RelocationActionClass::AuthorityMovement),
            rollback_proof_available: Some(true),
            replacement_receipt_published: Some(true),
            media_capability_fresh: Some(true),
            target_media_eligible: Some(true),
            evidence_is_fresh: Some(true),
            evidence_is_consistent: Some(true),
        }
    }

    fn hdd_defrag_heuristic_input() -> HeuristicInput {
        HeuristicInput {
            hdd_seek_distance: Some(1000),
            hdd_expected_seek_distance: Some(400),
            hdd_fragmentation_ratio: Some(0.6),
            hdd_expected_fragmentation_ratio: Some(0.2),
            ..HeuristicInput::default()
        }
    }

    #[test]
    fn admits_clean_hdd_defrag() {
        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::HddDefrag,
            &AntiThrashState::default(),
            &hdd_defrag_heuristic_input(),
            &clean_evidence(),
            0,
        );
        assert!(
            decision.verdict.may_proceed(),
            "should admit: {:?}",
            decision.verdict
        );
        assert_eq!(decision.action_class, RelocationActionClass::Optimization);
    }

    #[test]
    fn admits_repair_even_with_unknown_evidence() {
        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::Repair,
            &AntiThrashState::default(),
            &HeuristicInput::default(),
            &HardGateEvidence::default(), // all unknown
            0,
        );
        // Repair is necessity: passes even with unknown evidence
        assert!(decision.verdict.may_proceed());
        assert_eq!(decision.action_class, RelocationActionClass::Necessity);
    }

    #[test]
    fn blocks_promotion_with_unknown_evidence() {
        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::Promotion,
            &AntiThrashState::default(),
            &HeuristicInput::default(),
            &HardGateEvidence::default(), // all unknown
            0,
        );
        assert!(!decision.verdict.may_proceed());
        assert!(matches!(
            decision.verdict,
            AdmissionVerdict::BlockedPendingEvidence
        ));
    }

    #[test]
    fn refuses_hdd_defrag_when_heuristic_blocks() {
        let mut input = hdd_defrag_heuristic_input();
        input.hdd_seek_distance = Some(100);
        input.hdd_expected_seek_distance = Some(90);
        input.hdd_fragmentation_ratio = Some(0.05);
        input.hdd_expected_fragmentation_ratio = Some(0.04);

        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::HddDefrag,
            &AntiThrashState::default(),
            &input,
            &clean_evidence(),
            0,
        );
        assert!(!decision.verdict.may_proceed());
        assert!(matches!(decision.verdict, AdmissionVerdict::Refused));
    }

    #[test]
    fn blocks_when_anti_thrash_active() {
        let mut state = AntiThrashState::default();
        state.enter_cooldown(crate::anti_thrash::CooldownRecord {
            cooldown_start_ms: 0,
            cooldown_until_ms: 100_000,
            skip_reason: "test",
            reason: GovernorRelocationReason::Promotion,
            from_failed_payback: false,
        });

        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::Promotion,
            &state,
            &HeuristicInput::default(),
            &clean_evidence(),
            50_000,
        );
        assert!(!decision.verdict.may_proceed());
        assert!(matches!(decision.verdict, AdmissionVerdict::Refused));
    }

    #[test]
    fn refuses_when_hard_gate_fails() {
        let mut evidence = clean_evidence();
        evidence.source_receipt_authoritative = Some(false);

        let decision = evaluate_relocation_admission(
            GovernorRelocationReason::Promotion,
            &AntiThrashState::default(),
            &HeuristicInput::default(),
            &evidence,
            0,
        );
        assert!(!decision.verdict.may_proceed());
        assert!(matches!(decision.verdict, AdmissionVerdict::Refused));
    }

    #[test]
    fn refused_verdict_does_not_permit_authority_change() {
        assert!(!AdmissionVerdict::Refused.permits_authority_change());
        assert!(!AdmissionVerdict::BlockedPendingEvidence.permits_authority_change());
        assert!(!AdmissionVerdict::Cooldown.permits_authority_change());
        assert!(!AdmissionVerdict::ServingTrialOnly.permits_authority_change());
        assert!(AdmissionVerdict::Admitted.permits_authority_change());
    }
}
