// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Relocation lifecycle states: observed, shadow-evaluated, serving-trial,
//! admitted-move, replacement-published, old-receipt-retired, cooldown.

use tidefs_storage_intent_core::RelocationLifecycleState;

/// Governor-level relocation lifecycle state.
///
/// The governor lifecycle is richer than the core record state machine.
/// It adds `Observed`, `ShadowEvaluated`, `ServingTrial`, and splits
/// the core states into finer admission/receipt/retirement phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum GovernorLifecycleState {
    /// The relocation candidate has been observed but not yet evaluated.
    /// No shadow simulation has run.
    Observed = 0,

    /// Shadow evaluation (preflight simulation) has completed.
    /// The governor has a predicted outcome but has not admitted the move.
    ShadowEvaluated = 1,

    /// A cache-only, droppable serving trial is active. This state is
    /// non-authoritative: reads may be served from the trial copy but
    /// the source receipt remains the authority.
    ServingTrial = 2,

    /// The relocation plan has passed all hard gates and been admitted
    /// for execution. Data copying may begin.
    AdmittedMove = 3,

    /// The replacement receipt has been published and is durable.
    /// The new placement is now authoritative.
    ReplacementPublished = 4,

    /// The old source receipt has been retired. The relocation is
    /// complete from the governor's perspective.
    OldReceiptRetired = 5,

    /// The relocation subject is in cooldown. No new relocation proposals
    /// will be admitted for this subject until the cooldown expires.
    /// A skip reason must be operator-visible.
    Cooldown = 6,

    /// The relocation plan was refused by a hard gate. The reason is
    /// preserved in the admission record.
    Refused = 7,

    /// The relocation was aborted after admission (e.g., member lost,
    /// policy change invalidated the plan).
    Aborted = 8,
}

impl GovernorLifecycleState {
    /// All lifecycle states in order.
    pub const ALL: [GovernorLifecycleState; 9] = [
        GovernorLifecycleState::Observed,
        GovernorLifecycleState::ShadowEvaluated,
        GovernorLifecycleState::ServingTrial,
        GovernorLifecycleState::AdmittedMove,
        GovernorLifecycleState::ReplacementPublished,
        GovernorLifecycleState::OldReceiptRetired,
        GovernorLifecycleState::Cooldown,
        GovernorLifecycleState::Refused,
        GovernorLifecycleState::Aborted,
    ];

    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GovernorLifecycleState::Observed => "observed",
            GovernorLifecycleState::ShadowEvaluated => "shadow-evaluated",
            GovernorLifecycleState::ServingTrial => "serving-trial",
            GovernorLifecycleState::AdmittedMove => "admitted-move",
            GovernorLifecycleState::ReplacementPublished => "replacement-published",
            GovernorLifecycleState::OldReceiptRetired => "old-receipt-retired",
            GovernorLifecycleState::Cooldown => "cooldown",
            GovernorLifecycleState::Refused => "refused",
            GovernorLifecycleState::Aborted => "aborted",
        }
    }

    /// Returns true when this state is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            GovernorLifecycleState::OldReceiptRetired
                | GovernorLifecycleState::Refused
                | GovernorLifecycleState::Aborted
        )
    }

    /// Returns true when relocation work is still in progress.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            GovernorLifecycleState::AdmittedMove
                | GovernorLifecycleState::ReplacementPublished
        )
    }

    /// Returns true when this is a non-authoritative serving state.
    #[must_use]
    pub const fn is_serving_trial(self) -> bool {
        matches!(self, GovernorLifecycleState::ServingTrial)
    }

    /// Map to the storage-intent-core `RelocationLifecycleState`.
    #[must_use]
    pub const fn to_storage_intent_state(self) -> RelocationLifecycleState {
        match self {
            GovernorLifecycleState::Observed => RelocationLifecycleState::Proposed,
            GovernorLifecycleState::ShadowEvaluated => RelocationLifecycleState::Proposed,
            GovernorLifecycleState::ServingTrial => RelocationLifecycleState::Proposed,
            GovernorLifecycleState::AdmittedMove => RelocationLifecycleState::Admitted,
            GovernorLifecycleState::ReplacementPublished => {
                RelocationLifecycleState::PublishingReceipt
            }
            GovernorLifecycleState::OldReceiptRetired => RelocationLifecycleState::Complete,
            GovernorLifecycleState::Cooldown => RelocationLifecycleState::Cooldown,
            GovernorLifecycleState::Refused => RelocationLifecycleState::Refused,
            GovernorLifecycleState::Aborted => RelocationLifecycleState::Aborted,
        }
    }

    /// Map from a storage-intent-core `RelocationLifecycleState`.
    #[must_use]
    pub const fn from_storage_intent_state(
        state: RelocationLifecycleState,
    ) -> GovernorLifecycleState {
        match state {
            RelocationLifecycleState::Proposed => GovernorLifecycleState::Observed,
            RelocationLifecycleState::Admitted => GovernorLifecycleState::AdmittedMove,
            RelocationLifecycleState::Copying => GovernorLifecycleState::AdmittedMove,
            RelocationLifecycleState::Verifying => GovernorLifecycleState::AdmittedMove,
            RelocationLifecycleState::PublishingReceipt => {
                GovernorLifecycleState::ReplacementPublished
            }
            RelocationLifecycleState::RetiringSource => {
                GovernorLifecycleState::ReplacementPublished
            }
            RelocationLifecycleState::Complete => GovernorLifecycleState::OldReceiptRetired,
            RelocationLifecycleState::Cooldown => GovernorLifecycleState::Cooldown,
            RelocationLifecycleState::Refused => GovernorLifecycleState::Refused,
            RelocationLifecycleState::Aborted => GovernorLifecycleState::Aborted,
        }
    }
}

/// A valid lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleTransition {
    pub from: GovernorLifecycleState,
    pub to: GovernorLifecycleState,
}

impl LifecycleTransition {
    /// Returns true when this transition is legal per the governor state
    /// machine.
    #[must_use]
    pub const fn is_legal(self) -> bool {
        matches!(
            (self.from, self.to),
            // Happy path
            (GovernorLifecycleState::Observed, GovernorLifecycleState::ShadowEvaluated)
                | (GovernorLifecycleState::ShadowEvaluated, GovernorLifecycleState::ServingTrial)
                | (GovernorLifecycleState::ShadowEvaluated, GovernorLifecycleState::AdmittedMove)
                | (GovernorLifecycleState::ServingTrial, GovernorLifecycleState::AdmittedMove)
                | (GovernorLifecycleState::AdmittedMove, GovernorLifecycleState::ReplacementPublished)
                | (GovernorLifecycleState::ReplacementPublished, GovernorLifecycleState::OldReceiptRetired)
                // Refusal / abort from any non-terminal state
                | (GovernorLifecycleState::Observed, GovernorLifecycleState::Refused)
                | (GovernorLifecycleState::ShadowEvaluated, GovernorLifecycleState::Refused)
                | (GovernorLifecycleState::ServingTrial, GovernorLifecycleState::Refused)
                | (GovernorLifecycleState::AdmittedMove, GovernorLifecycleState::Aborted)
                | (GovernorLifecycleState::ReplacementPublished, GovernorLifecycleState::Aborted)
                // Cooldown from any refused/aborted state, or from active states
                | (GovernorLifecycleState::Refused, GovernorLifecycleState::Cooldown)
                | (GovernorLifecycleState::Aborted, GovernorLifecycleState::Cooldown)
                | (GovernorLifecycleState::AdmittedMove, GovernorLifecycleState::Cooldown)
                // Cooldown expiry → re-observed
                | (GovernorLifecycleState::Cooldown, GovernorLifecycleState::Observed)
        )
    }
}

impl core::fmt::Display for GovernorLifecycleState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_states_have_unique_discriminants() {
        let mut seen = [false; 9];
        for state in &GovernorLifecycleState::ALL {
            let idx = *state as usize;
            assert!(!seen[idx], "duplicate discriminant for {state}");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    #[test]
    fn state_display_nonempty() {
        for state in &GovernorLifecycleState::ALL {
            assert!(!format!("{state}").is_empty());
        }
    }

    #[test]
    fn happy_path_transitions_are_legal() {
        let happy_path = [
            (GovernorLifecycleState::Observed, GovernorLifecycleState::ShadowEvaluated),
            (
                GovernorLifecycleState::ShadowEvaluated,
                GovernorLifecycleState::ServingTrial,
            ),
            (
                GovernorLifecycleState::ShadowEvaluated,
                GovernorLifecycleState::AdmittedMove,
            ),
            (
                GovernorLifecycleState::ServingTrial,
                GovernorLifecycleState::AdmittedMove,
            ),
            (
                GovernorLifecycleState::AdmittedMove,
                GovernorLifecycleState::ReplacementPublished,
            ),
            (
                GovernorLifecycleState::ReplacementPublished,
                GovernorLifecycleState::OldReceiptRetired,
            ),
        ];
        for (from, to) in &happy_path {
            assert!(
                LifecycleTransition { from: *from, to: *to }.is_legal(),
                "transition {from} -> {to} should be legal"
            );
        }
    }

    #[test]
    fn illegal_transitions_rejected() {
        // Can't jump from observed directly to old-receipt-retired
        assert!(!LifecycleTransition {
            from: GovernorLifecycleState::Observed,
            to: GovernorLifecycleState::OldReceiptRetired,
        }
        .is_legal());

        // Can't go backward
        assert!(!LifecycleTransition {
            from: GovernorLifecycleState::OldReceiptRetired,
            to: GovernorLifecycleState::Observed,
        }
        .is_legal());

        // Can't go from terminal to active
        assert!(!LifecycleTransition {
            from: GovernorLifecycleState::Refused,
            to: GovernorLifecycleState::AdmittedMove,
        }
        .is_legal());
    }

    #[test]
    fn refusal_from_early_states() {
        for from in &[
            GovernorLifecycleState::Observed,
            GovernorLifecycleState::ShadowEvaluated,
            GovernorLifecycleState::ServingTrial,
        ] {
            assert!(
                LifecycleTransition {
                    from: *from,
                    to: GovernorLifecycleState::Refused,
                }
                .is_legal(),
                "refusal from {from} should be legal"
            );
        }
    }

    #[test]
    fn terminal_states() {
        assert!(GovernorLifecycleState::OldReceiptRetired.is_terminal());
        assert!(GovernorLifecycleState::Refused.is_terminal());
        assert!(GovernorLifecycleState::Aborted.is_terminal());
        assert!(!GovernorLifecycleState::AdmittedMove.is_terminal());
        assert!(!GovernorLifecycleState::Observed.is_terminal());
    }

    #[test]
    fn serving_trial_is_not_authoritative() {
        assert!(GovernorLifecycleState::ServingTrial.is_serving_trial());
        assert!(!GovernorLifecycleState::AdmittedMove.is_serving_trial());
    }

    #[test]
    fn cooldown_reentry() {
        // Cooldown → Observed is legal (cooldown expires)
        assert!(LifecycleTransition {
            from: GovernorLifecycleState::Cooldown,
            to: GovernorLifecycleState::Observed,
        }
        .is_legal());
    }

    #[test]
    fn round_trip_storage_intent_state() {
        for state in &GovernorLifecycleState::ALL {
            let core_state = state.to_storage_intent_state();
            let back = GovernorLifecycleState::from_storage_intent_state(core_state);
            // Multiple governor states may map to the same core state,
            // so we only check that the round trip produces a valid state
            // and that the second mapping is idempotent.
            let back_core = back.to_storage_intent_state();
            assert_eq!(back_core, core_state, "non-idempotent mapping for {state}");
        }
    }
}
