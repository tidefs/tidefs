// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Relocation governor: the top-level admission and scheduling model.
//!
//! The [`RelocationGovernor`] is the single entry point for relocation
//! proposals. It consumes storage-intent evidence, evaluates anti-thrash
//! rules, media-specific heuristics, and hard gates, and produces an
//! [`AdmissionDecision`].

use crate::admission::{evaluate_relocation_admission, AdmissionDecision, AdmissionRecord};
use crate::anti_thrash::{AntiThrashState, CooldownRecord};
use crate::hard_gates::HardGateEvidence;
use crate::heuristics::HeuristicInput;
use crate::lifecycle::GovernorLifecycleState;
use crate::reasons::GovernorRelocationReason;

/// Configuration for the relocation governor.
#[derive(Clone, Debug)]
pub struct RelocationGovernorConfig {
    /// Maximum concurrent admitted relocations.
    pub max_concurrent_relocations: usize,

    /// Maximum concurrent serving trials.
    pub max_concurrent_serving_trials: usize,

    /// Maximum bytes in flight across all relocations.
    pub max_bytes_in_flight: u64,

    /// Whether shadow evaluation (preflight simulation) is enabled.
    pub shadow_evaluation_enabled: bool,

    /// Default cooldown duration for refused relocations (ms).
    pub default_cooldown_ms: u64,
}

impl Default for RelocationGovernorConfig {
    fn default() -> Self {
        RelocationGovernorConfig {
            max_concurrent_relocations: 4,
            max_concurrent_serving_trials: 8,
            max_bytes_in_flight: 256 * 1024 * 1024, // 256 MiB
            shadow_evaluation_enabled: true,
            default_cooldown_ms: 300_000, // 5 minutes
        }
    }
}

/// The relocation governor.
///
/// Maintains per-subject anti-thrash state and processes relocation
/// proposals through the full admission pipeline.
pub struct RelocationGovernor {
    /// Governor configuration.
    pub config: RelocationGovernorConfig,

    /// Next admission record ID (monotonic).
    next_admission_id: u64,

    /// Anti-thrash state per relocation subject.
    /// Keyed by a subject identifier (e.g., extent range hash).
    anti_thrash_states: Vec<(u64, AntiThrashState)>,

    /// Currently admitted relocation subjects.
    admitted_subjects: Vec<AdmittedSubject>,

    /// Admission history (bounded).
    admission_history: Vec<AdmissionRecord>,
}

/// An admitted relocation subject tracked by the governor.
#[allow(dead_code)]
struct AdmittedSubject {
    #[allow(dead_code)]
    /// Admission record.
    record: AdmissionRecord,

    /// Current lifecycle state.
    state: GovernorLifecycleState,

    /// Bytes in flight for this relocation.
    bytes_in_flight: u64,
}

impl RelocationGovernor {
    /// Create a new governor with the given configuration.
    #[must_use]
    pub fn new(config: RelocationGovernorConfig) -> Self {
        RelocationGovernor {
            config,
            next_admission_id: 1,
            anti_thrash_states: Vec::new(),
            admitted_subjects: Vec::new(),
            admission_history: Vec::new(),
        }
    }

    /// Evaluate a relocation proposal for admission.
    ///
    /// Returns an [`AdmissionDecision`] and, if admitted, creates an
    /// [`AdmissionRecord`] and updates anti-thrash state.
    #[must_use]
    pub fn evaluate_proposal(
        &mut self,
        subject_id: u64,
        reason: GovernorRelocationReason,
        heuristic_input: &HeuristicInput,
        gate_evidence: &HardGateEvidence,
        now_ms: u64,
        source_receipt_id: [u8; 16],
        target_placement_id: [u8; 16],
    ) -> AdmissionDecision {
        // Look up or create anti-thrash state for this subject.
        let at_state = self.get_or_create_anti_thrash(subject_id);

        let decision = evaluate_relocation_admission(
            reason,
            at_state,
            heuristic_input,
            gate_evidence,
            now_ms,
        );

        // If admitted, create an admission record.
        if decision.verdict.may_proceed() {
            let record = AdmissionRecord {
                admission_id: self.next_admission_id,
                reason,
                verdict: decision.verdict,
                action_class: decision.action_class,
                source_receipt_id,
                target_placement_id,
                admitted_at_ms: now_ms,
                refusal_reasons: decision.hard_gates.refusal_reasons(),
                anti_thrash_skip_reason: decision.anti_thrash.skip_reason(),
                heuristic_summary: decision.heuristic.as_ref().map(|h| h.summary),
                payback_window_ms: decision.heuristic.as_ref().and_then(|h| h.estimated_payback_ms),
                payback_benefit_type: None,
            };

            self.next_admission_id += 1;

            // Track admitted subject.
            if decision.verdict == crate::admission::AdmissionVerdict::Admitted {
                self.admitted_subjects.push(AdmittedSubject {
                    record: record.clone(),
                    state: decision.target_state,
                    bytes_in_flight: heuristic_input.relocation_bytes.unwrap_or(0),
                });
            }

            self.admission_history.push(record);
        }

        // If refused or cooldown, update anti-thrash state.
        if !decision.verdict.may_proceed() {
            let skip_reason = decision
                .anti_thrash
                .skip_reason()
                .unwrap_or("hard-gate-or-heuristic-refusal");
            self.enter_cooldown_for_subject(
                subject_id,
                now_ms,
                reason,
                skip_reason,
                false,
            );
        }

        decision
    }

    /// Record that a relocation has completed successfully.
    pub fn record_relocation_completed(
        &mut self,
        subject_id: u64,
        bytes: u64,
        now_ms: u64,
        reason: GovernorRelocationReason,
    ) {
        let at_state = self.get_or_create_anti_thrash(subject_id);
        at_state.movement_debt.record_relocation(bytes, now_ms, reason);

        // Remove from admitted subjects.
        self.admitted_subjects.retain(|s| {
            s.record.source_receipt_id != [0u8; 16]
                || s.record.admission_id != 0
        });
        // In practice, match by admission_id; simplified for first slice.
        self.admitted_subjects.clear(); // stub
    }

    /// Record a failed payback for a subject.
    pub fn record_failed_payback(&mut self, subject_id: u64) {
        let at_state = self.get_or_create_anti_thrash(subject_id);
        at_state.movement_debt.record_failed_payback();

        // Enter cooldown if max failed paybacks reached.
        if at_state.movement_debt.is_in_indefinite_cooldown() {
            at_state.enter_cooldown(CooldownRecord {
                cooldown_start_ms: 0, // caller should provide now_ms
                cooldown_until_ms: u64::MAX,
                skip_reason: "failed-payback-indefinite-cooldown",
                reason: GovernorRelocationReason::PolicySatisfaction, // generic
                from_failed_payback: true,
            });
        }
    }

    /// Enter cooldown for a subject.
    pub(crate) fn enter_cooldown_for_subject(
        &mut self,
        subject_id: u64,
        now_ms: u64,
        reason: GovernorRelocationReason,
        skip_reason: &'static str,
        from_failed_payback: bool,
    ) {
        let cooldown_ms = self.config.default_cooldown_ms;
        let at_state = self.get_or_create_anti_thrash(subject_id);
        at_state.enter_cooldown(CooldownRecord {
            cooldown_start_ms: now_ms,
            cooldown_until_ms: now_ms.saturating_add(cooldown_ms),
            skip_reason,
            reason,
            from_failed_payback,
        });
    }

    /// Clear cooldown for a subject (e.g., on expiry or manual override).
    pub fn clear_cooldown(&mut self, subject_id: u64) {
        if let Some((_, state)) = self
            .anti_thrash_states
            .iter_mut()
            .find(|(id, _)| *id == subject_id)
        {
            state.clear_cooldown();
        }
    }

    /// Evaluate all cooldown expirations at the given time.
    pub fn expire_cooldowns(&mut self, now_ms: u64) {
        for (_id, state) in &mut self.anti_thrash_states {
            if let Some(ref cooldown) = state.cooldown {
                if !cooldown.is_active(now_ms) && !cooldown.is_indefinite() {
                    state.clear_cooldown();
                }
            }
        }
    }

    /// Get the number of currently admitted relocations.
    #[must_use]
    pub fn admitted_count(&self) -> usize {
        self.admitted_subjects.len()
    }

    /// Get the total bytes in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.admitted_subjects
            .iter()
            .map(|s| s.bytes_in_flight)
            .sum()
    }

    /// Returns true when the governor can admit another relocation.
    #[must_use]
    pub fn can_admit(&self) -> bool {
        self.admitted_subjects.len() < self.config.max_concurrent_relocations
            && self.bytes_in_flight() < self.config.max_bytes_in_flight
    }

    /// Get or create anti-thrash state for a subject.
    fn get_or_create_anti_thrash(&mut self, subject_id: u64) -> &mut AntiThrashState {
        let pos = self
            .anti_thrash_states
            .iter()
            .position(|(id, _)| *id == subject_id);
        match pos {
            Some(idx) => &mut self.anti_thrash_states[idx].1,
            None => {
                self.anti_thrash_states
                    .push((subject_id, AntiThrashState::default()));
                &mut self.anti_thrash_states.last_mut().unwrap().1
            }
        }
    }
}

impl Default for RelocationGovernor {
    fn default() -> Self {
        RelocationGovernor::new(RelocationGovernorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use crate::RelocationActionClass;
    use super::*;
    use crate::hard_gates::HardGateEvidence;
    use crate::heuristics::HeuristicInput;

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

    fn defrag_input() -> HeuristicInput {
        HeuristicInput {
            hdd_seek_distance: Some(1000),
            hdd_expected_seek_distance: Some(400),
            hdd_fragmentation_ratio: Some(0.6),
            hdd_expected_fragmentation_ratio: Some(0.2),
            relocation_bytes: Some(1024 * 1024),
            ..HeuristicInput::default()
        }
    }

    #[test]
    fn admits_clean_defrag() {
        let mut gov = RelocationGovernor::default();
        let decision = gov.evaluate_proposal(
            1,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &clean_evidence(),
            0,
            [1u8; 16],
            [2u8; 16],
        );
        assert!(decision.verdict.may_proceed());
    }

    #[test]
    fn cooldown_prevents_second_attempt() {
        let mut gov = RelocationGovernor::new(RelocationGovernorConfig {
            default_cooldown_ms: 100_000,
            ..RelocationGovernorConfig::default()
        });

        // First attempt: refuse by failing source receipt.
        let mut bad_evidence = clean_evidence();
        bad_evidence.source_receipt_authoritative = Some(false);
        let d1 = gov.evaluate_proposal(
            1,
            GovernorRelocationReason::Promotion,
            &HeuristicInput::default(),
            &bad_evidence,
            0,
            [1u8; 16],
            [2u8; 16],
        );
        assert!(!d1.verdict.may_proceed());

        // Second attempt within cooldown window: anti-thrash should block.
        let d2 = gov.evaluate_proposal(
            1,
            GovernorRelocationReason::Promotion,
            &HeuristicInput::default(),
            &clean_evidence(),
            50_000, // within cooldown
            [1u8; 16],
            [2u8; 16],
        );
        assert!(!d2.verdict.may_proceed(), "should be blocked by cooldown");
    }

    #[test]
    fn cooldown_expiry_allows_retry() {
        let mut gov = RelocationGovernor::new(RelocationGovernorConfig {
            default_cooldown_ms: 100_000,
            ..RelocationGovernorConfig::default()
        });

        // Refuse.
        let mut bad_evidence = clean_evidence();
        bad_evidence.source_receipt_authoritative = Some(false);
        gov.evaluate_proposal(
            1,
            GovernorRelocationReason::Promotion,
            &HeuristicInput::default(),
            &bad_evidence,
            0,
            [1u8; 16],
            [2u8; 16],
        );

        // Expire cooldown.
        gov.expire_cooldowns(200_000);

        // Now should admit (with clean evidence).
        let d = gov.evaluate_proposal(
            1,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &clean_evidence(),
            200_000,
            [1u8; 16],
            [2u8; 16],
        );
        assert!(d.verdict.may_proceed(), "should admit after cooldown expiry");
    }

    #[test]
    fn records_relocation_updates_debt() {
        let mut gov = RelocationGovernor::default();
        gov.record_relocation_completed(
            1,
            1024 * 1024,
            500_000,
            GovernorRelocationReason::HddDefrag,
        );
        let state = gov.get_or_create_anti_thrash(1);
        assert_eq!(state.movement_debt.bytes_moved, 1024 * 1024);
        assert_eq!(state.movement_debt.last_move_completed_ms, 500_000);
    }

    #[test]
    fn failed_payback_enters_cooldown() {
        let mut gov = RelocationGovernor::default();
        gov.record_failed_payback(1);
        gov.record_failed_payback(1);
        gov.record_failed_payback(1); // 3 failed → indefinite cooldown
        let state = gov.get_or_create_anti_thrash(1);
        assert!(state.movement_debt.is_in_indefinite_cooldown());
    }

    #[test]
    fn capacity_limits_enforced() {
        let mut gov = RelocationGovernor::new(RelocationGovernorConfig {
            max_concurrent_relocations: 2,
            ..RelocationGovernorConfig::default()
        });
        assert!(gov.can_admit());

        // Admit first two.
        let mut ev = clean_evidence();
        ev.action_class = Some(RelocationActionClass::Optimization);

        gov.evaluate_proposal(
            1,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &ev,
            0,
            [1u8; 16],
            [2u8; 16],
        );
        gov.evaluate_proposal(
            2,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &ev,
            0,
            [3u8; 16],
            [4u8; 16],
        );
        // Both admitted.
        assert_eq!(gov.admitted_count(), 2);
        assert!(!gov.can_admit());
    }
}
