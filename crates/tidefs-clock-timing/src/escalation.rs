// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Timeout escalation (source-owned timing model: `classify_deadline_miss_and_escalate`).
//!
//! Converts deadline misses into hold/degrade/failover/stop actions under
//! policy. Every escalation produces a receipt for auditability.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::types::{
    DeadlineEscalationReceipt, DerivedDeadline, DriftClass, EscalationAction, HlcValue,
};

/// Monotonic receipt ID counter.
static RECEIPT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn next_receipt_id() -> u64 {
    RECEIPT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// TimeoutEscalator
// ---------------------------------------------------------------------------

/// Classifies deadline misses and chooses escalation actions.
///
/// The escalator converts timing events into policy actions. It never creates
/// authority truth — it only classifies health, issues deadlines, and emits
/// receipts/findings (source-owned timing model).
#[derive(Debug, Clone)]
pub struct TimeoutEscalator {
    /// Escalation receipts emitted by this escalator.
    receipts: Vec<DeadlineEscalationReceipt>,
    /// Current drift class (used for slack computation).
    drift_class: DriftClass,
}

impl TimeoutEscalator {
    /// Create a new escalator.
    pub fn new(drift_class: DriftClass) -> Self {
        TimeoutEscalator {
            receipts: Vec::new(),
            drift_class,
        }
    }

    /// Return all emitted receipts.
    pub fn receipts(&self) -> &[DeadlineEscalationReceipt] {
        &self.receipts
    }

    /// Return receipt count.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Update the drift class used for slack computation.
    pub fn set_drift_class(&mut self, drift_class: DriftClass) {
        self.drift_class = drift_class;
    }

    /// Classify a deadline miss and produce an escalation action.
    ///
    /// `deadline` is the deadline that was evaluated.
    /// `current_ns` is the current clock reading.
    /// `hlc` is the HLC value at the time of escalation.
    /// `old_state` and `new_state` describe the state transition.
    pub fn classify_miss(
        &mut self,
        deadline: &DerivedDeadline,
        current_ns: u64,
        hlc: HlcValue,
        old_state: &str,
        new_state: &str,
    ) -> EscalationAction {
        let action = self.choose_action(deadline, current_ns);

        let receipt = DeadlineEscalationReceipt {
            receipt_id: next_receipt_id(),
            hlc_at_escalation: hlc,
            deadline_ns: deadline.effective_deadline_ns,
            detected_at_ns: current_ns,
            drift_class: self.drift_class,
            action,
            old_state: old_state.to_string(),
            new_state: new_state.to_string(),
        };

        self.receipts.push(receipt);
        action
    }

    /// Classify a lease expiry for failover staging.
    ///
    /// Lease expiry alone does not move authority — it opens the path to
    /// failover, which must still satisfy witness/quorum law.
    pub fn classify_lease_expiry(
        &mut self,
        deadline: &DerivedDeadline,
        current_ns: u64,
        hlc: HlcValue,
    ) -> (EscalationAction, &DeadlineEscalationReceipt) {
        let action = if self.drift_class.requires_hold() {
            // Under severe drift, hold failover even if lease expired.
            EscalationAction::Hold
        } else {
            EscalationAction::Failover
        };

        let receipt = DeadlineEscalationReceipt {
            receipt_id: next_receipt_id(),
            hlc_at_escalation: hlc,
            deadline_ns: deadline.effective_deadline_ns,
            detected_at_ns: current_ns,
            drift_class: self.drift_class,
            action,
            old_state: "expired".to_string(),
            new_state: "failover_staged".to_string(),
        };

        self.receipts.push(receipt);
        let last_idx = self.receipts.len() - 1;
        (action, &self.receipts[last_idx])
    }

    /// Classify a fence escalation.
    ///
    /// Fence escalations degrade product visibility and may escalate to
    /// operator notification.
    pub fn classify_fence_escalation(
        &mut self,
        deadline: &DerivedDeadline,
        current_ns: u64,
        hlc: HlcValue,
    ) -> (EscalationAction, &DeadlineEscalationReceipt) {
        let action = match self.drift_class {
            DriftClass::TrustedLocal | DriftClass::NominalCluster => EscalationAction::Degrade,
            DriftClass::ElevatedCluster => EscalationAction::Degrade,
            DriftClass::SevereCluster => EscalationAction::Hold,
            DriftClass::UntrustedTime => EscalationAction::Stop,
        };

        let receipt = DeadlineEscalationReceipt {
            receipt_id: next_receipt_id(),
            hlc_at_escalation: hlc,
            deadline_ns: deadline.effective_deadline_ns,
            detected_at_ns: current_ns,
            drift_class: self.drift_class,
            action,
            old_state: "escalated".to_string(),
            new_state: format!(
                "fence_{}",
                match action {
                    EscalationAction::Degrade => "degraded",
                    EscalationAction::Hold => "held",
                    EscalationAction::Stop => "stopped",
                    _ => "unknown",
                }
            ),
        };

        self.receipts.push(receipt);
        let last_idx = self.receipts.len() - 1;
        (action, &self.receipts[last_idx])
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn choose_action(&self, deadline: &DerivedDeadline, current_ns: u64) -> EscalationAction {
        let overdue_ns = current_ns.saturating_sub(deadline.effective_deadline_ns);

        match self.drift_class {
            DriftClass::TrustedLocal => {
                if overdue_ns > 10_000_000_000 {
                    // >10s overdue under trusted local: escalate to stop.
                    EscalationAction::Stop
                } else if overdue_ns > 1_000_000_000 {
                    // >1s overdue: failover.
                    EscalationAction::Failover
                } else {
                    EscalationAction::Degrade
                }
            }
            DriftClass::NominalCluster => {
                if overdue_ns > 30_000_000_000 {
                    EscalationAction::Stop
                } else if overdue_ns > 5_000_000_000 {
                    EscalationAction::Failover
                } else {
                    EscalationAction::Degrade
                }
            }
            DriftClass::ElevatedCluster => {
                if overdue_ns > 60_000_000_000 {
                    EscalationAction::Stop
                } else if overdue_ns > 10_000_000_000 {
                    EscalationAction::Failover
                } else {
                    EscalationAction::Hold
                }
            }
            DriftClass::SevereCluster => {
                if overdue_ns > 120_000_000_000 {
                    EscalationAction::Stop
                } else {
                    EscalationAction::Hold
                }
            }
            DriftClass::UntrustedTime => {
                // Under untrusted time, always stop movement.
                EscalationAction::Stop
            }
        }
    }
}

impl Default for TimeoutEscalator {
    fn default() -> Self {
        TimeoutEscalator::new(DriftClass::TrustedLocal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_local_small_overdue_degrades() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let action = esc.classify_miss(&dd, 1500, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Degrade);
        assert_eq!(esc.receipt_count(), 1);
    }

    #[test]
    fn trusted_local_large_overdue_escalates_to_stop() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        // 20s overdue
        let action = esc.classify_miss(&dd, 21_000_000_000, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Stop);
    }

    #[test]
    fn untrusted_time_always_stops() {
        let mut esc = TimeoutEscalator::new(DriftClass::UntrustedTime);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let action = esc.classify_miss(&dd, 1500, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Stop);
    }

    #[test]
    fn lease_expiry_normal() {
        let mut esc = TimeoutEscalator::new(DriftClass::NominalCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::LeaseDeadline, 1000, 100);
        let (action, receipt) = esc.classify_lease_expiry(&dd, 2000, HlcValue::zero());
        assert_eq!(action, EscalationAction::Failover);
        assert_eq!(receipt.action, EscalationAction::Failover);
    }

    #[test]
    fn lease_expiry_under_severe_drift_holds() {
        let mut esc = TimeoutEscalator::new(DriftClass::SevereCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::LeaseDeadline, 1000, 100);
        let (action, _receipt) = esc.classify_lease_expiry(&dd, 2000, HlcValue::zero());
        assert_eq!(action, EscalationAction::Hold);
    }

    #[test]
    fn fence_escalation_under_untrusted_stops() {
        let mut esc = TimeoutEscalator::new(DriftClass::UntrustedTime);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::FenceDeadline, 1000, 100);
        let (action, receipt) = esc.classify_fence_escalation(&dd, 2000, HlcValue::zero());
        assert_eq!(action, EscalationAction::Stop);
        assert!(receipt.new_state.contains("stopped"));
    }

    #[test]
    fn fence_escalation_under_nominal_degrades() {
        let mut esc = TimeoutEscalator::new(DriftClass::NominalCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::FenceDeadline, 1000, 100);
        let (action, _receipt) = esc.classify_fence_escalation(&dd, 2000, HlcValue::zero());
        assert_eq!(action, EscalationAction::Degrade);
    }

    #[test]
    fn receipt_chain_accumulates() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);

        esc.classify_miss(&dd, 1500, HlcValue::zero(), "s0", "s1");
        esc.classify_miss(&dd, 1600, HlcValue::new(1, 0), "s1", "s2");
        esc.classify_miss(&dd, 1700, HlcValue::new(2, 0), "s2", "s3");

        assert_eq!(esc.receipt_count(), 3);
        // Receipt IDs are strictly increasing, but may not be sequential
        // due to the shared global RECEIPT_ID atomic counter (tests run in parallel).
        assert!(esc.receipts()[0].receipt_id < esc.receipts()[1].receipt_id);
        assert!(esc.receipts()[1].receipt_id < esc.receipts()[2].receipt_id);
    }

    #[test]
    fn drift_class_update_affects_action() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);

        let action1 = esc.classify_miss(&dd, 1500, HlcValue::zero(), "s0", "s1");
        assert_eq!(action1, EscalationAction::Degrade);

        esc.set_drift_class(DriftClass::UntrustedTime);
        let action2 = esc.classify_miss(&dd, 1500, HlcValue::zero(), "s1", "s2");
        assert_eq!(action2, EscalationAction::Stop);
    }
    // ------------------------------------------------------------------
    // Threshold boundary tests: each drift class just above/below
    // ------------------------------------------------------------------

    #[test]
    fn trusted_local_just_below_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 999_999_999;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Degrade);
    }

    #[test]
    fn trusted_local_just_above_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 1_000_000_001;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Failover);
    }

    #[test]
    fn trusted_local_just_below_stop() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 9_999_999_999;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Failover);
    }

    #[test]
    fn trusted_local_just_above_stop() {
        let mut esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 10_000_000_001;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Stop);
    }

    #[test]
    fn nominal_cluster_just_below_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::NominalCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 4_999_999_999;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Degrade);
    }

    #[test]
    fn nominal_cluster_just_above_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::NominalCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 5_000_000_001;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Failover);
    }

    #[test]
    fn nominal_cluster_just_below_stop() {
        let mut esc = TimeoutEscalator::new(DriftClass::NominalCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 29_999_999_999;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Failover);
    }

    #[test]
    fn elevated_cluster_small_overdue_holds() {
        let mut esc = TimeoutEscalator::new(DriftClass::ElevatedCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 100;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Hold);
    }

    #[test]
    fn elevated_cluster_just_below_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::ElevatedCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 9_999_999_999;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Hold);
    }

    #[test]
    fn elevated_cluster_just_above_failover() {
        let mut esc = TimeoutEscalator::new(DriftClass::ElevatedCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 10_000_000_001;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Failover);
    }

    #[test]
    fn severe_cluster_large_overdue_hold() {
        let mut esc = TimeoutEscalator::new(DriftClass::SevereCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 100_000_000_000;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Hold);
    }

    #[test]
    fn severe_cluster_just_above_stop() {
        let mut esc = TimeoutEscalator::new(DriftClass::SevereCluster);
        let dd = DerivedDeadline::with_slack(crate::types::ClockClass::BoottimeLocal, 1000, 100);
        let overdue = 1000 + 100 + 120_000_000_001;
        let action = esc.classify_miss(&dd, overdue, HlcValue::zero(), "open", "grace");
        assert_eq!(action, EscalationAction::Stop);
    }

    #[test]
    fn default_equals_new_trusted_local() {
        let e1 = TimeoutEscalator::new(DriftClass::TrustedLocal);
        let e2 = TimeoutEscalator::default();
        assert_eq!(e1.receipt_count(), e2.receipt_count());
    }
}
