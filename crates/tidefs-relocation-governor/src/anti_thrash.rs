// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Anti-thrash rules for the relocation governor.
//!
//! Prevents flip-flop churn, movement-debt abuse, failed-payback loops,
//! and one-off hotness from triggering authority movement.


use crate::reasons::GovernorRelocationReason;

// ── Movement debt ────────────────────────────────────────────────────

/// Accumulated movement debt for a relocated subject.
///
/// After a subject is moved, it carries movement debt that must be
/// amortized before another ordinary relocation is admitted.
/// Necessity-class moves (repair, evacuation) bypass debt but
/// increment it for audit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MovementDebt {
    /// Bytes moved in the last relocation.
    pub bytes_moved: u64,

    /// Wall-clock time of the last relocation completion (ms since epoch).
    pub last_move_completed_ms: u64,

    /// Number of times this subject has been relocated.
    pub relocation_count: u64,

    /// Accumulated payback failure count.
    pub failed_payback_count: u64,

    /// Reason for the last relocation.
    pub last_reason: Option<GovernorRelocationReason>,
}

impl MovementDebt {
    /// Minimum dwell time between ordinary relocations (milliseconds).
    pub const MIN_DWELL_MS: u64 = 300_000; // 5 minutes

    /// Minimum dwell after a failed payback (milliseconds).
    pub const FAILED_PAYBACK_DWELL_MS: u64 = 1_800_000; // 30 minutes

    /// Maximum consecutive failed paybacks before indefinite cooldown.
    pub const MAX_FAILED_PAYBACKS: u64 = 3;

    /// Returns true when movement debt blocks a new ordinary relocation.
    #[must_use]
    pub fn blocks_relocation(&self, now_ms: u64, reason: GovernorRelocationReason) -> bool {
        // Never-relocated subjects have no debt.
        if self.relocation_count == 0 {
            return false;
        }

        // Necessity moves always bypass debt.
        if reason.is_necessity() {
            return false;
        }

        // Failed payback → extended dwell.
        if self.failed_payback_count > 0 {
            let required_dwell = if self.failed_payback_count >= Self::MAX_FAILED_PAYBACKS {
                u64::MAX // indefinite cooldown
            } else {
                Self::FAILED_PAYBACK_DWELL_MS * self.failed_payback_count
            };
            if now_ms.saturating_sub(self.last_move_completed_ms) < required_dwell {
                return true;
            }
        }

        // Ordinary dwell.
        if now_ms.saturating_sub(self.last_move_completed_ms) < Self::MIN_DWELL_MS {
            return true;
        }

        false
    }

    pub fn is_in_indefinite_cooldown(&self) -> bool {
        self.failed_payback_count >= Self::MAX_FAILED_PAYBACKS
    }

    /// Record a completed relocation.
    pub fn record_relocation(&mut self, bytes: u64, now_ms: u64, reason: GovernorRelocationReason) {
        self.bytes_moved = self.bytes_moved.saturating_add(bytes);
        self.last_move_completed_ms = now_ms;
        self.relocation_count = self.relocation_count.saturating_add(1);
        self.last_reason = Some(reason);
    }

    /// Record a failed payback.
    pub fn record_failed_payback(&mut self) {
        self.failed_payback_count = self.failed_payback_count.saturating_add(1);
    }

    /// Reset payback failure count (successful payback closure).
    pub fn reset_payback_failures(&mut self) {
        self.failed_payback_count = 0;
    }
}

// ── Payback record ───────────────────────────────────────────────────

/// A payback window: the benefit the relocation must deliver within the
/// window to justify the move cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PaybackRecord {
    /// The relocation reason that created this payback obligation.
    pub reason: GovernorRelocationReason,

    /// Payback window duration (milliseconds).
    pub window_ms: u64,

    /// Payback window start time (ms since epoch).
    pub window_start_ms: u64,

    /// Benefit type: what the payback is measured in.
    pub benefit_type: PaybackBenefitType,

    /// Expected benefit value within the window.
    pub expected_benefit: u64,

    /// Actual benefit delivered so far.
    pub delivered_benefit: u64,

    /// Whether the payback window has been satisfied.
    pub satisfied: bool,

    /// Whether the payback has failed (window closed, benefit not met).
    pub failed: bool,
}

impl PaybackRecord {
    /// Create a new payback record.
    #[must_use]
    pub fn new(
        reason: GovernorRelocationReason,
        window_ms: u64,
        now_ms: u64,
        benefit_type: PaybackBenefitType,
        expected_benefit: u64,
    ) -> Self {
        PaybackRecord {
            reason,
            window_ms,
            window_start_ms: now_ms,
            benefit_type,
            expected_benefit,
            delivered_benefit: 0,
            satisfied: false,
            failed: false,
        }
    }

    /// Check whether the payback window has closed.
    #[must_use]
    pub fn window_closed(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.window_start_ms) >= self.window_ms
    }

    /// Evaluate payback status at the given time.
    pub fn evaluate(&mut self, now_ms: u64) {
        if self.satisfied || self.failed {
            return;
        }
        self.satisfied = self.delivered_benefit >= self.expected_benefit;
        if !self.satisfied && self.window_closed(now_ms) {
            self.failed = true;
        }
    }

    /// Record delivered benefit.
    pub fn deliver(&mut self, benefit: u64, now_ms: u64) {
        self.delivered_benefit = self.delivered_benefit.saturating_add(benefit);
        self.evaluate(now_ms);
    }
}

/// What the payback benefit is measured in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum PaybackBenefitType {
    /// Wall-clock time saved (milliseconds).
    TimeSaved = 0,

    /// Bytes read avoided.
    BytesReadAvoided = 1,

    /// Seeks avoided (HDD).
    SeeksAvoided = 2,

    /// Media writes avoided (flash/NVMe).
    MediaWritesAvoided = 3,

    /// RPO lag reduced (milliseconds).
    RpoLagReduced = 4,

    /// Capacity saved (bytes).
    CapacitySaved = 5,

    /// Write amplification reduced (ppm).
    WriteAmplificationReduced = 6,

    /// Wear delta reduced (ppm).
    WearDeltaReduced = 7,
}

impl PaybackBenefitType {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PaybackBenefitType::TimeSaved => "time-saved",
            PaybackBenefitType::BytesReadAvoided => "bytes-read-avoided",
            PaybackBenefitType::SeeksAvoided => "seeks-avoided",
            PaybackBenefitType::MediaWritesAvoided => "media-writes-avoided",
            PaybackBenefitType::RpoLagReduced => "rpo-lag-reduced",
            PaybackBenefitType::CapacitySaved => "capacity-saved",
            PaybackBenefitType::WriteAmplificationReduced => "write-amplification-reduced",
            PaybackBenefitType::WearDeltaReduced => "wear-delta-reduced",
        }
    }
}

impl core::fmt::Display for PaybackBenefitType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Cooldown record ──────────────────────────────────────────────────

/// A cooldown record: why a relocation subject is in cooldown and when
/// it may be reconsidered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CooldownRecord {
    /// When the cooldown started (ms since epoch).
    pub cooldown_start_ms: u64,

    /// When the cooldown expires (ms since epoch). `u64::MAX` = indefinite.
    pub cooldown_until_ms: u64,

    /// Operator-visible skip reason.
    pub skip_reason: &'static str,

    /// The relocation reason that entered cooldown.
    pub reason: GovernorRelocationReason,

    /// Whether this cooldown was caused by failed payback.
    pub from_failed_payback: bool,
}

impl CooldownRecord {
    /// Returns true when the cooldown is still active at the given time.
    #[must_use]
    pub fn is_active(&self, now_ms: u64) -> bool {
        now_ms < self.cooldown_until_ms
    }

    /// Returns true when this is an indefinite cooldown.
    #[must_use]
    pub fn is_indefinite(&self) -> bool {
        self.cooldown_until_ms == u64::MAX
    }
}

// ── Anti-thrash state ─────────────────────────────────────────────────

/// Aggregate anti-thrash state for a relocation subject.
#[derive(Clone, Debug, Default)]
pub struct AntiThrashState {
    /// Current movement debt.
    pub movement_debt: MovementDebt,

    /// Active payback records (may be multiple for different benefit types).
    pub payback_records: Vec<PaybackRecord>,

    /// Active cooldown record, if any.
    pub cooldown: Option<CooldownRecord>,

    /// Whether the last prediction was contradicted by outcome.
    pub last_prediction_contradicted: bool,

    /// Confidence trend: decreasing confidence lowers action class.
    pub confidence_trend: Option<ConfidenceTrend>,
}

/// Confidence trend direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfidenceTrend {
    Improving,
    Stable,
    Declining,
    Collapsed,
}

impl AntiThrashState {
    /// Evaluate whether a new relocation proposal should be blocked by
    /// anti-thrash rules at the given time.
    #[must_use]
    pub fn evaluate(
        &self,
        now_ms: u64,
        reason: GovernorRelocationReason,
    ) -> AntiThrashDecision {
        // 1. Cooldown check
        if let Some(ref cooldown) = self.cooldown {
            if cooldown.is_active(now_ms) {
                return AntiThrashDecision::CooldownActive {
                    skip_reason: cooldown.skip_reason,
                    cooldown_until_ms: cooldown.cooldown_until_ms,
                };
            }
        }

        // 2. Movement debt check
        if self.movement_debt.blocks_relocation(now_ms, reason) {
            if self.movement_debt.is_in_indefinite_cooldown() {
                return AntiThrashDecision::IndefiniteCooldown {
                    skip_reason: "failed-payback-indefinite-cooldown",
                };
            }
            return AntiThrashDecision::MovementDebtActive {
                dwell_remaining_ms: self
                    .movement_debt
                    .last_move_completed_ms
                    .saturating_add(MovementDebt::MIN_DWELL_MS)
                    .saturating_sub(now_ms),
                failed_payback_count: self.movement_debt.failed_payback_count,
            };
        }

        // 3. Failed payback check
        if reason.changes_authority() {
            for pr in &self.payback_records {
                if pr.failed {
                    return AntiThrashDecision::PaybackFailed {
                        benefit_type: pr.benefit_type,
                        expected: pr.expected_benefit,
                        delivered: pr.delivered_benefit,
                    };
                }
            }
        }

        // 4. Contradictory signal check
        if self.last_prediction_contradicted && reason.changes_authority() {
            return AntiThrashDecision::ContradictorySignal {
                skip_reason: "last-prediction-contradicted",
            };
        }

        // 5. Confidence trend check
        if let Some(ConfidenceTrend::Collapsed) = self.confidence_trend {
            if reason.changes_authority() {
                return AntiThrashDecision::ConfidenceCollapsed {
                    skip_reason: "prediction-confidence-collapsed",
                };
            }
        }
        if let Some(ConfidenceTrend::Declining) = self.confidence_trend {
            if reason.changes_authority() {
                return AntiThrashDecision::ConfidenceDeclining {
                    skip_reason: "prediction-confidence-declining",
                };
            }
        }

        AntiThrashDecision::Admit
    }

    /// Enter cooldown for this subject.
    pub fn enter_cooldown(&mut self, record: CooldownRecord) {
        self.cooldown = Some(record);
    }

    /// Clear cooldown (e.g., on expiry).
    pub fn clear_cooldown(&mut self) {
        self.cooldown = None;
    }
}

/// Outcome of anti-thrash evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AntiThrashDecision {
    /// No anti-thrash blocker: the proposal may proceed to hard gates.
    Admit,

    /// Active cooldown prevents relocation.
    CooldownActive {
        skip_reason: &'static str,
        cooldown_until_ms: u64,
    },

    /// Movement debt prevents relocation.
    MovementDebtActive {
        dwell_remaining_ms: u64,
        failed_payback_count: u64,
    },

    /// Indefinite cooldown (too many failed paybacks).
    IndefiniteCooldown {
        skip_reason: &'static str,
    },

    /// A previous payback failed.
    PaybackFailed {
        benefit_type: PaybackBenefitType,
        expected: u64,
        delivered: u64,
    },

    /// Last prediction was contradicted by observed outcome.
    ContradictorySignal {
        skip_reason: &'static str,
    },

    /// Prediction confidence has collapsed.
    ConfidenceCollapsed {
        skip_reason: &'static str,
    },

    /// Prediction confidence is declining.
    ConfidenceDeclining {
        skip_reason: &'static str,
    },
}

impl AntiThrashDecision {
    /// Returns true when the decision blocks relocation.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        !matches!(self, AntiThrashDecision::Admit)
    }

    /// Returns the skip reason if blocking.
    #[must_use]
    pub fn skip_reason(&self) -> Option<&'static str> {
        match self {
            AntiThrashDecision::Admit => None,
            AntiThrashDecision::CooldownActive { skip_reason, .. }
            | AntiThrashDecision::IndefiniteCooldown { skip_reason, .. }
            | AntiThrashDecision::ContradictorySignal { skip_reason, .. }
            | AntiThrashDecision::ConfidenceCollapsed { skip_reason, .. }
            | AntiThrashDecision::ConfidenceDeclining { skip_reason, .. } => {
                Some(skip_reason)
            }
            AntiThrashDecision::MovementDebtActive { .. } => {
                Some("movement-debt-active")
            }
            AntiThrashDecision::PaybackFailed { .. } => Some("payback-failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn movement_debt_blocks_ordinary_relocation() {
        let debt = MovementDebt {
            bytes_moved: 1024,
            last_move_completed_ms: 100_000,
            relocation_count: 1,
            failed_payback_count: 0,
            last_reason: Some(GovernorRelocationReason::HddDefrag),
        };
        // 100_000 + 300_000 = 400_000 — at time 200_000, debt blocks.
        assert!(debt.blocks_relocation(200_000, GovernorRelocationReason::HddDefrag));
        // At time 500_000, debt is cleared.
        assert!(!debt.blocks_relocation(500_000, GovernorRelocationReason::HddDefrag));
    }

    #[test]
    fn movement_debt_allows_necessity() {
        let debt = MovementDebt {
            bytes_moved: 1024,
            last_move_completed_ms: 100_000,
            relocation_count: 1,
            failed_payback_count: 0,
            last_reason: Some(GovernorRelocationReason::HddDefrag),
        };
        // Repair always passes even during dwell.
        assert!(!debt.blocks_relocation(200_000, GovernorRelocationReason::Repair));
    }

    #[test]
    fn failed_payback_increases_dwell() {
        let debt = MovementDebt {
            bytes_moved: 1024,
            last_move_completed_ms: 100_000,
            relocation_count: 1,
            failed_payback_count: 1,
            last_reason: Some(GovernorRelocationReason::Promotion),
        };
        // 100_000 + 1_800_000 = 1_900_000
        assert!(debt.blocks_relocation(1_000_000, GovernorRelocationReason::Promotion));
        assert!(!debt.blocks_relocation(2_000_000, GovernorRelocationReason::Promotion));
    }

    #[test]
    fn indefinite_cooldown_after_max_failed_paybacks() {
        let debt = MovementDebt {
            bytes_moved: 1024,
            last_move_completed_ms: 100_000,
            relocation_count: 1,
            failed_payback_count: 3,
            last_reason: Some(GovernorRelocationReason::Promotion),
        };
        assert!(debt.is_in_indefinite_cooldown());
        assert!(debt.blocks_relocation(u64::MAX, GovernorRelocationReason::Promotion));
    }

    #[test]
    fn record_relocation_updates_debt() {
        let mut debt = MovementDebt::default();
        debt.record_relocation(1024, 500_000, GovernorRelocationReason::HddDefrag);
        assert_eq!(debt.bytes_moved, 1024);
        assert_eq!(debt.last_move_completed_ms, 500_000);
        assert_eq!(debt.relocation_count, 1);
    }

    #[test]
    fn payback_satisfaction() {
        let mut pr = PaybackRecord::new(
            GovernorRelocationReason::Promotion,
            60_000, // 1 min window
            100_000,
            PaybackBenefitType::SeeksAvoided,
            100,
        );
        assert!(!pr.satisfied);
        pr.deliver(50, 120_000);
        assert!(!pr.satisfied);
        pr.deliver(60, 140_000);
        assert!(pr.satisfied);
        assert!(!pr.failed);
    }

    #[test]
    fn payback_failure_when_window_closes() {
        let mut pr = PaybackRecord::new(
            GovernorRelocationReason::Promotion,
            60_000,
            100_000,
            PaybackBenefitType::SeeksAvoided,
            100,
        );
        pr.deliver(30, 170_000); // after window close, only 30 of 100
        assert!(pr.failed);
    }

    #[test]
    fn anti_thrash_admits_clean_state() {
        let state = AntiThrashState::default();
        let decision = state.evaluate(0, GovernorRelocationReason::HddDefrag);
        assert!(!decision.is_blocking());
    }

    #[test]
    fn anti_thrash_blocks_during_cooldown() {
        let mut state = AntiThrashState::default();
        state.enter_cooldown(CooldownRecord {
            cooldown_start_ms: 100_000,
            cooldown_until_ms: 200_000,
            skip_reason: "test-cooldown",
            reason: GovernorRelocationReason::Promotion,
            from_failed_payback: true,
        });
        let decision = state.evaluate(150_000, GovernorRelocationReason::Promotion);
        assert!(decision.is_blocking());
    }

    #[test]
    fn anti_thrash_clears_after_cooldown_expiry() {
        let mut state = AntiThrashState::default();
        state.enter_cooldown(CooldownRecord {
            cooldown_start_ms: 100_000,
            cooldown_until_ms: 200_000,
            skip_reason: "test-cooldown",
            reason: GovernorRelocationReason::Promotion,
            from_failed_payback: false,
        });
        let decision = state.evaluate(250_000, GovernorRelocationReason::Promotion);
        assert!(!decision.is_blocking());
    }

    #[test]
    fn anti_thrash_blocks_authority_move_on_contradicted_prediction() {
        let mut state = AntiThrashState::default();
        state.last_prediction_contradicted = true;
        let decision = state.evaluate(0, GovernorRelocationReason::Promotion);
        assert!(decision.is_blocking());
        // Defrag (non-authority) should not be blocked
        let decision2 = state.evaluate(0, GovernorRelocationReason::HddDefrag);
        assert!(!decision2.is_blocking());
    }

    #[test]
    fn anti_thrash_blocks_on_collapsed_confidence() {
        let mut state = AntiThrashState::default();
        state.confidence_trend = Some(ConfidenceTrend::Collapsed);
        let decision = state.evaluate(0, GovernorRelocationReason::Promotion);
        assert!(decision.is_blocking());
        let decision2 = state.evaluate(0, GovernorRelocationReason::HddDefrag);
        assert!(!decision2.is_blocking());
    }

    #[test]
    fn payback_benefit_type_labels_nonempty() {
        let types = [
            PaybackBenefitType::TimeSaved,
            PaybackBenefitType::BytesReadAvoided,
            PaybackBenefitType::SeeksAvoided,
            PaybackBenefitType::MediaWritesAvoided,
        ];
        for t in &types {
            assert!(!format!("{t}").is_empty());
        }
    }
}
