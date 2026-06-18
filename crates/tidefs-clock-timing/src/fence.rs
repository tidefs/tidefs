// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Freshness fence evaluation and epoch-timing attestation (P8-04 Sections 4-7).
//!
//! Provides the canonical freshness evaluation algorithms:
//! - `evaluate_freshness_against_fence`: determine if a source is fresh
//! - `evaluate_transfer_ticket_freshness`: gate transfer admission on fence state
//! - `attest_epoch_timing_and_bind_to_config_epoch`: produce timing attestation
//! - `detect_drift_exceeded_and_trigger_safety_actions`: drift-safety enforcement
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::types::{
    ClockClass, ClockResynchronizationReceipt, DriftClass, DriftSuspicionState,
    EpochTimingAttestation, FenceClass, FreshnessFenceRecord, FreshnessVerdict, HlcValue,
    SourceQuorum,
};

// ---------------------------------------------------------------------------
// evaluate_freshness_against_fence (P8-04 Section 7.1)
// ---------------------------------------------------------------------------

/// Evaluate whether a source position is fresh under the given fence.
///
/// # Arguments
/// - `source_epoch`: the logical epoch of the source data
/// - `source_wall_ns`: the wall-clock timestamp of the source data (nanoseconds)
/// - `fence`: the freshness fence to evaluate against
/// - `current_ns`: current time (boottime nanoseconds) for expiry check
/// - `current_drift_class`: current drift classification for slack computation
///
/// # Returns
/// A `FreshnessVerdict` indicating whether the source is fresh, stale, degraded,
/// or the fence has expired.
pub fn evaluate_freshness_against_fence(
    source_epoch: u64,
    source_wall_ns: u64,
    fence: &FreshnessFenceRecord,
    current_ns: u64,
    current_drift_class: DriftClass,
) -> FreshnessVerdict {
    // 1. Check fence expiry first.
    if fence.is_expired(current_ns) {
        return FreshnessVerdict::Expired;
    }

    // 2. Source is behind the fence frontier.
    let epoch_behind = source_epoch < fence.fence_frontier_epoch;
    let wall_behind = source_wall_ns < fence.fence_frontier_wall_ns;

    if !epoch_behind && !wall_behind {
        // Source is at or ahead of the fence frontier: fresh.
        return FreshnessVerdict::WithinBound;
    }

    // 3. Source is behind. Determine what to do based on fence class.
    match fence.fence_class {
        FenceClass::Strict => {
            // Strict fence: no reads behind the frontier.
            FreshnessVerdict::StaleSource
        }
        FenceClass::Bounded => {
            // Bounded fence: check if lag is within the declared window.
            let lag_ns = if wall_behind {
                fence.fence_frontier_wall_ns.saturating_sub(source_wall_ns)
            } else {
                // Epoch behind but wall clock ok — still count as lag.
                // Use the drift slack as an approximation.
                (fence.fence_frontier_epoch.saturating_sub(source_epoch))
                    .saturating_mul(1_000_000_000) // assume ~1s per epoch
            };

            // Apply drift-class slack to the lag window.
            let effective_lag_window =
                (fence.lag_window_ns as f64 * current_drift_class.slack_multiplier()) as u64;

            if lag_ns <= effective_lag_window {
                // Within the bounded degradation window.
                FreshnessVerdict::DegradedAdmission
            } else {
                FreshnessVerdict::StaleSource
            }
        }
        FenceClass::Soft => {
            // Soft fence: admit with degradation regardless of lag amount.
            FreshnessVerdict::DegradedAdmission
        }
    }
}

// ---------------------------------------------------------------------------
// evaluate_transfer_ticket_freshness (P8-04 Section 7.1, Section 6)
// ---------------------------------------------------------------------------

/// Evaluate whether a transfer ticket may proceed based on freshness.
///
/// Transfer tickets carry a freshness fence that must be satisfied before
/// data movement may begin. This function evaluates the ticket against the
/// current clock state.
///
/// # Arguments
/// - `source_epoch`: logical epoch of the source replica
/// - `source_wall_ns`: wall-clock time of the source replica's last commit
/// - `ticket_fence_ref`: the freshness fence attached to the transfer ticket
/// - `current_ns`: current boottime for expiry evaluation
/// - `current_drift_class`: current drift state
///
/// # Returns
/// The freshness verdict — if `permits_operation()`, the transfer may proceed.
pub fn evaluate_transfer_ticket_freshness(
    source_epoch: u64,
    source_wall_ns: u64,
    ticket_fence_ref: &FreshnessFenceRecord,
    current_ns: u64,
    current_drift_class: DriftClass,
) -> FreshnessVerdict {
    // Under severe/untrusted drift, all transfers are held.
    if current_drift_class.requires_hold() {
        return FreshnessVerdict::StaleSource;
    }

    evaluate_freshness_against_fence(
        source_epoch,
        source_wall_ns,
        ticket_fence_ref,
        current_ns,
        current_drift_class,
    )
}

// ---------------------------------------------------------------------------
// attest_epoch_timing_and_bind_to_config_epoch (P8-04 Section 7.1, Section 5)
// ---------------------------------------------------------------------------

/// Produce a timing attestation for a membership config epoch transition.
///
/// # Rules (P8-04 Section 5):
/// - No membership epoch transition may proceed without wall-clock and
///   logical-clock attestation.
/// - A config epoch that started with `drift_class::exceeded` may only enter
///   `c3.quarantined`.
///
/// # Arguments
/// - `epoch_id`: the new epoch being entered
/// - `previous_epoch_ref`: the previous epoch (None if initial)
/// - `fence`: the freshness fence that was satisfied
/// - `clock_sources`: clock sources used for attestation
/// - `drift_bound`: measured drift at the time of transition
/// - `hlc`: current HLC value
/// - `now_ns`: current boottime
///
/// # Returns
/// An `EpochTimingAttestation`. If `drift_bound` does not permit authority
/// movement, the attestation will be invalid (`is_valid == false`) and the
/// epoch transition must not proceed.
pub fn attest_epoch_timing_and_bind_to_config_epoch(
    epoch_id: u64,
    previous_epoch_ref: Option<u64>,
    fence: &FreshnessFenceRecord,
    clock_sources: Vec<ClockClass>,
    drift_bound: DriftClass,
    hlc: HlcValue,
    now_ns: u64,
) -> EpochTimingAttestation {
    let mut attestation = EpochTimingAttestation::new(
        epoch_id,
        clock_sources,
        drift_bound,
        previous_epoch_ref,
        fence.fence_id,
        hlc,
        now_ns,
    );

    // Additional check: if the fence has expired, invalidate the attestation.
    if fence.is_expired(now_ns) {
        attestation.is_valid = false;
    }

    attestation
}

// ---------------------------------------------------------------------------
// detect_drift_exceeded_and_trigger_safety_actions (P8-04 Section 7.1, Section 7)
// ---------------------------------------------------------------------------

/// Result of drift safety evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftSafetyResult {
    /// The updated drift suspicion state.
    pub new_suspicion_state: DriftSuspicionState,
    /// Whether sensitive authority actions should be held.
    pub hold_sensitive_actions: bool,
    /// Whether a resynchronization receipt was produced (recovery).
    pub resync_receipt: Option<ClockResynchronizationReceipt>,
    /// Whether the drift is severe enough to block new transfer tickets.
    pub block_new_transfers: bool,
    /// Whether new config epoch transitions should be blocked.
    pub block_epoch_transitions: bool,
}

/// Detect whether drift has exceeded configured bounds and trigger safety actions.
///
/// # Arguments
/// - `current_drift_class`: the drift classification from the DriftEstimator
/// - `previous_suspicion_state`: the current suspicion state before evaluation
/// - `node_ref`: the local node identifier
/// - `hlc`: current HLC value
/// - `now_ns`: current boottime
///
/// # Returns
/// A `DriftSafetyResult` with the updated suspicion state and safety actions.
pub fn detect_drift_exceeded_and_trigger_safety_actions(
    current_drift_class: DriftClass,
    previous_suspicion_state: DriftSuspicionState,
    node_ref: &str,
    hlc: HlcValue,
    now_ns: u64,
) -> DriftSafetyResult {
    let (new_state, hold, block_transfers, block_epochs) = match current_drift_class {
        DriftClass::TrustedLocal | DriftClass::NominalCluster => {
            // Nominal or trusted: no safety actions needed.
            // Check for recovery from a previous degraded state.
            if previous_suspicion_state != DriftSuspicionState::Nominal {
                (DriftSuspicionState::Recovered, false, false, false)
            } else {
                (DriftSuspicionState::Nominal, false, false, false)
            }
        }
        DriftClass::ElevatedCluster => {
            // Elevated drift: degrade freshness on non-critical paths,
            // but do not block transfers or epoch transitions.
            (DriftSuspicionState::Elevated, false, false, false)
        }
        DriftClass::SevereCluster => {
            // Severe drift: hold sensitive actions, block transfers and epochs.
            (DriftSuspicionState::Severe, true, true, true)
        }
        DriftClass::UntrustedTime => {
            // Untrusted time: freeze all authority movement.
            (DriftSuspicionState::HoldSensitiveActions, true, true, true)
        }
    };
    // Produce a resynchronization receipt if we recovered.
    let resync_receipt = if new_state == DriftSuspicionState::Recovered
        && previous_suspicion_state != DriftSuspicionState::Recovered
    {
        Some(ClockResynchronizationReceipt::new(
            0, // caller should assign a real ID
            node_ref.to_string(),
            SourceQuorum::new(1, 1),
            // Map suspicion state back to a drift class for the receipt.
            match previous_suspicion_state {
                DriftSuspicionState::Elevated => DriftClass::ElevatedCluster,
                DriftSuspicionState::Severe | DriftSuspicionState::HoldSensitiveActions => {
                    DriftClass::SevereCluster
                }
                _ => DriftClass::NominalCluster,
            },
            current_drift_class,
            hlc,
            now_ns,
        ))
    } else {
        None
    };

    DriftSafetyResult {
        new_suspicion_state: new_state,
        hold_sensitive_actions: hold,
        resync_receipt,
        block_new_transfers: block_transfers,
        block_epoch_transitions: block_epochs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FenceFrontier;

    fn make_fence(
        frontier_epoch: u64,
        frontier_wall_ns: u64,
        class: FenceClass,
        lag_window_ns: u64,
        issue_time_ns: u64,
        max_drift_ns: u64,
    ) -> FreshnessFenceRecord {
        let frontier = FenceFrontier::new(frontier_epoch, frontier_wall_ns);
        let timing = crate::FenceTiming {
            issue_time_ns,
            max_drift_window_ns: max_drift_ns,
        };
        FreshnessFenceRecord::new(
            1,
            "test_domain".into(),
            frontier,
            class,
            lag_window_ns,
            timing,
            DriftClass::NominalCluster,
        )
    }

    // ------------------------------------------------------------------
    // evaluate_freshness_against_fence tests
    // ------------------------------------------------------------------

    #[test]
    fn fresh_source_within_bound() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v = evaluate_freshness_against_fence(15, 1500, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::WithinBound);
    }

    #[test]
    fn fresh_source_at_frontier() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v = evaluate_freshness_against_fence(10, 1000, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::WithinBound);
    }

    #[test]
    fn strict_fence_blocks_stale() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v = evaluate_freshness_against_fence(5, 500, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::StaleSource);
    }

    #[test]
    fn bounded_fence_admits_within_lag() {
        let fence = make_fence(10, 1000, FenceClass::Bounded, 500, 0, 10_000);
        // Source is 100ns behind wall frontier — within 500ns lag window.
        let v = evaluate_freshness_against_fence(10, 900, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::DegradedAdmission);
    }

    #[test]
    fn bounded_fence_blocks_outside_lag() {
        let fence = make_fence(10, 1000, FenceClass::Bounded, 100, 0, 10_000);
        // Source is 500ns behind — outside 100ns lag window.
        let v = evaluate_freshness_against_fence(5, 500, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::StaleSource);
    }

    #[test]
    fn soft_fence_always_degrades() {
        let fence = make_fence(10, 1000, FenceClass::Soft, 0, 0, 10_000);
        let v = evaluate_freshness_against_fence(1, 100, &fence, 500, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::DegradedAdmission);
    }

    #[test]
    fn fence_expiry_returns_expired() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 1000);
        // Current time 2000 > expiry (1000).
        let v = evaluate_freshness_against_fence(15, 1500, &fence, 2000, DriftClass::TrustedLocal);
        assert_eq!(v, FreshnessVerdict::Expired);
    }

    #[test]
    fn drift_slack_widens_bounded_window() {
        let fence = make_fence(10, 1000, FenceClass::Bounded, 100, 0, 10_000);
        // Under SevereCluster (slack=5.0), effective lag window = 500ns.
        let v = evaluate_freshness_against_fence(10, 600, &fence, 500, DriftClass::SevereCluster);
        // 400ns lag — within 500ns effective window → degraded.
        assert_eq!(v, FreshnessVerdict::DegradedAdmission);

        // Under TrustedLocal (slack=1.0), effective lag window = 100ns.
        let v2 = evaluate_freshness_against_fence(10, 600, &fence, 500, DriftClass::TrustedLocal);
        // 400ns lag — outside 100ns window → stale.
        assert_eq!(v2, FreshnessVerdict::StaleSource);
    }

    // ------------------------------------------------------------------
    // evaluate_transfer_ticket_freshness tests
    // ------------------------------------------------------------------

    #[test]
    fn transfer_held_under_severe_drift() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v =
            evaluate_transfer_ticket_freshness(15, 1500, &fence, 500, DriftClass::SevereCluster);
        assert_eq!(v, FreshnessVerdict::StaleSource);
    }

    #[test]
    fn transfer_held_under_untrusted() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v =
            evaluate_transfer_ticket_freshness(15, 1500, &fence, 500, DriftClass::UntrustedTime);
        assert_eq!(v, FreshnessVerdict::StaleSource);
    }

    #[test]
    fn transfer_proceeds_under_nominal() {
        let fence = make_fence(10, 1000, FenceClass::Strict, 0, 0, 10_000);
        let v =
            evaluate_transfer_ticket_freshness(15, 1500, &fence, 500, DriftClass::NominalCluster);
        assert_eq!(v, FreshnessVerdict::WithinBound);
    }

    // ------------------------------------------------------------------
    // attest_epoch_timing_and_bind_to_config_epoch tests
    // ------------------------------------------------------------------

    #[test]
    fn attestation_valid_under_nominal_drift() {
        let fence = make_fence(5, 500, FenceClass::Strict, 0, 0, 10_000);
        let att = attest_epoch_timing_and_bind_to_config_epoch(
            2,
            Some(1),
            &fence,
            vec![ClockClass::BoottimeLocal, ClockClass::HlcCluster],
            DriftClass::NominalCluster,
            HlcValue::new(100, 0),
            1000,
        );
        assert!(att.permits_transition());
        assert_eq!(att.epoch_id, 2);
        assert_eq!(att.previous_epoch_ref, Some(1));
        assert_eq!(att.transition_fence_ref, 1);
    }

    #[test]
    fn attestation_invalid_under_severe_drift() {
        let fence = make_fence(5, 500, FenceClass::Strict, 0, 0, 10_000);
        let att = attest_epoch_timing_and_bind_to_config_epoch(
            2,
            Some(1),
            &fence,
            vec![ClockClass::BoottimeLocal],
            DriftClass::SevereCluster,
            HlcValue::new(100, 0),
            1000,
        );
        assert!(!att.permits_transition());
        assert!(!att.is_valid);
    }

    #[test]
    fn attestation_invalid_when_fence_expired() {
        let fence = make_fence(5, 500, FenceClass::Strict, 0, 0, 100);
        let att = attest_epoch_timing_and_bind_to_config_epoch(
            2,
            Some(1),
            &fence,
            vec![ClockClass::BoottimeLocal],
            DriftClass::NominalCluster,
            HlcValue::new(100, 0),
            5000, // after expiry
        );
        assert!(!att.permits_transition());
    }

    // ------------------------------------------------------------------
    // detect_drift_exceeded_and_trigger_safety_actions tests
    // ------------------------------------------------------------------

    #[test]
    fn nominal_drift_no_safety_actions() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::TrustedLocal,
            DriftSuspicionState::Nominal,
            "node1",
            HlcValue::new(100, 0),
            1000,
        );
        assert_eq!(result.new_suspicion_state, DriftSuspicionState::Nominal);
        assert!(!result.hold_sensitive_actions);
        assert!(!result.block_new_transfers);
        assert!(!result.block_epoch_transitions);
        assert!(result.resync_receipt.is_none());
    }

    #[test]
    fn elevated_drift_no_blocks() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::ElevatedCluster,
            DriftSuspicionState::Nominal,
            "node1",
            HlcValue::new(100, 0),
            1000,
        );
        assert_eq!(result.new_suspicion_state, DriftSuspicionState::Elevated);
        assert!(!result.hold_sensitive_actions);
        assert!(!result.block_new_transfers);
    }

    #[test]
    fn severe_drift_blocks_all() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::SevereCluster,
            DriftSuspicionState::Nominal,
            "node1",
            HlcValue::new(100, 0),
            1000,
        );
        assert_eq!(result.new_suspicion_state, DriftSuspicionState::Severe);
        assert!(result.hold_sensitive_actions);
        assert!(result.block_new_transfers);
        assert!(result.block_epoch_transitions);
    }

    #[test]
    fn untrusted_freezes_everything() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::UntrustedTime,
            DriftSuspicionState::Severe,
            "node1",
            HlcValue::new(100, 0),
            1000,
        );
        assert_eq!(
            result.new_suspicion_state,
            DriftSuspicionState::HoldSensitiveActions
        );
        assert!(result.hold_sensitive_actions);
        assert!(result.block_new_transfers);
        assert!(result.block_epoch_transitions);
    }

    #[test]
    fn recovery_produces_resync_receipt() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::NominalCluster,
            DriftSuspicionState::Severe,
            "node1",
            HlcValue::new(100, 0),
            1000,
        );
        assert_eq!(result.new_suspicion_state, DriftSuspicionState::Recovered);
        assert!(result.resync_receipt.is_some());
        let receipt = result.resync_receipt.unwrap();
        assert_eq!(receipt.node_ref, "node1");
        assert!(receipt.is_majority_recovery());
    }
}
