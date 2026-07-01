// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease and fence deadline tracking (source-owned timing model).
//!
//! Tracks lease expirations and fence ack deadlines. Deadlines are always
//! derived from a base clock plus drift slack. Expiry alone does not move
//! authority — it only opens the legal path to failover staging under
//! witness/quorum law.

use crate::types::{
    ClockClass, DerivedDeadline, DriftClass, FenceDeadlineRecord, FenceDeadlineState,
    LeaseDeadlineRecord, LeaseDeadlineState,
};

// ---------------------------------------------------------------------------
// LeaseDeadline
// ---------------------------------------------------------------------------

/// Tracks a lease deadline through its lifecycle (source-owned timing model).
///
/// A lease is held by a node for a scarce authority object. The lease must be
/// renewed before expiry. Expiry opens the path to failover staging but does
/// not by itself transfer authority.
#[derive(Debug, Clone)]
pub struct LeaseDeadline {
    record: LeaseDeadlineRecord,
}

impl LeaseDeadline {
    /// Open a new lease with the given parameters.
    ///
    /// All times are in nanoseconds from the appropriate clock source
    /// (typically `CLOCK_BOOTTIME` for suspend-aware lease tracking).
    pub fn open(
        lease_deadline_id: u64,
        opened_at_ns: u64,
        renew_period_ns: u64,
        expiry_period_ns: u64,
        grace_period_ns: u64,
        drift_slack_class: DriftClass,
    ) -> Self {
        let slack_mult = drift_slack_class.slack_multiplier();
        let renew_deadline =
            opened_at_ns.saturating_add((renew_period_ns as f64 * slack_mult) as u64);
        let expiry_deadline =
            opened_at_ns.saturating_add((expiry_period_ns as f64 * slack_mult) as u64);
        let grace_deadline = opened_at_ns
            .saturating_add(((expiry_period_ns + grace_period_ns) as f64 * slack_mult) as u64);

        let record = LeaseDeadlineRecord {
            lease_deadline_id,
            clock_class: ClockClass::LeaseDeadline,
            opened_at_ns,
            renew_deadline_ns: renew_deadline,
            expiry_deadline_ns: expiry_deadline,
            grace_deadline_ns: grace_deadline,
            drift_slack_class,
            state: LeaseDeadlineState::Open,
        };

        LeaseDeadline { record }
    }

    /// Return a reference to the underlying record.
    pub fn record(&self) -> &LeaseDeadlineRecord {
        &self.record
    }

    /// Evaluate the lease state against a current clock reading.
    ///
    /// Returns the new state (may be unchanged). Call this periodically to
    /// detect expiry transitions.
    pub fn evaluate(&mut self, current_ns: u64) -> LeaseDeadlineState {
        let new_state = if current_ns >= self.record.grace_deadline_ns {
            LeaseDeadlineState::Expired
        } else if current_ns >= self.record.expiry_deadline_ns {
            LeaseDeadlineState::Grace
        } else if current_ns >= self.record.renew_deadline_ns {
            LeaseDeadlineState::Warning
        } else {
            LeaseDeadlineState::Open
        };

        // Avoid reversing: never go from Expired → Grace, etc.
        self.record.state = transition_lease(self.record.state, new_state);
        self.record.state
    }

    /// Renew the lease, extending deadlines from the current time.
    pub fn renew(
        &mut self,
        current_ns: u64,
        renew_period_ns: u64,
        expiry_period_ns: u64,
        grace_period_ns: u64,
    ) {
        let slack_mult = self.record.drift_slack_class.slack_multiplier();
        self.record.opened_at_ns = current_ns;
        self.record.renew_deadline_ns =
            current_ns.saturating_add((renew_period_ns as f64 * slack_mult) as u64);
        self.record.expiry_deadline_ns =
            current_ns.saturating_add((expiry_period_ns as f64 * slack_mult) as u64);
        self.record.grace_deadline_ns = current_ns
            .saturating_add(((expiry_period_ns + grace_period_ns) as f64 * slack_mult) as u64);
        self.record.state = LeaseDeadlineState::Open;
    }

    /// Stage failover — only legal when the lease has expired.
    ///
    /// Returns `Some(new_record)` if successfully staged, `None` if the lease
    /// has not yet expired.
    pub fn stage_failover(&mut self) -> Option<&LeaseDeadlineRecord> {
        if self.record.state == LeaseDeadlineState::Expired {
            self.record.state = LeaseDeadlineState::FailoverStaged;
            Some(&self.record)
        } else {
            None
        }
    }

    /// Build a derived deadline for the renewal time.
    pub fn renew_deadline(&self) -> DerivedDeadline {
        DerivedDeadline::with_slack(
            ClockClass::LeaseDeadline,
            self.record.renew_deadline_ns,
            self.record
                .renew_deadline_ns
                .saturating_sub(self.record.opened_at_ns),
        )
    }
}

fn transition_lease(old: LeaseDeadlineState, new: LeaseDeadlineState) -> LeaseDeadlineState {
    use LeaseDeadlineState::*;
    match (old, new) {
        // Only advance forward; never regress.
        (Expired, _) => Expired,
        (FailoverStaged, _) => FailoverStaged,
        (Grace, Expired) => Expired,
        (Grace, _) => Grace,
        (Warning, Grace | Expired) => new,
        (Warning, _) => Warning,
        (Renewing, Warning | Grace | Expired) => new,
        (Renewing, _) => Renewing,
        (Open, _) => new,
    }
}

// ---------------------------------------------------------------------------
// FenceDeadline
// ---------------------------------------------------------------------------

/// Tracks a freshness fence deadline through its lifecycle (source-owned timing model).
///
/// A freshness fence is issued to a cohort when a frontier advances. Cohort
/// members must acknowledge within the ack deadline. Late or missing acks
/// escalate through degraded visibility to operator notification.
#[derive(Debug, Clone)]
pub struct FenceDeadline {
    record: FenceDeadlineRecord,
}

impl FenceDeadline {
    /// Issue a new freshness fence.
    pub fn issue(
        fence_deadline_id: u64,
        issued_at_ns: u64,
        ack_period_ns: u64,
        grace_period_ns: u64,
        drift_slack_class: DriftClass,
    ) -> Self {
        let slack_mult = drift_slack_class.slack_multiplier();
        let ack_deadline = issued_at_ns.saturating_add((ack_period_ns as f64 * slack_mult) as u64);
        let grace_deadline = issued_at_ns
            .saturating_add(((ack_period_ns + grace_period_ns) as f64 * slack_mult) as u64);

        let record = FenceDeadlineRecord {
            fence_deadline_id,
            clock_class: ClockClass::FenceDeadline,
            issued_at_ns,
            ack_deadline_ns: ack_deadline,
            grace_deadline_ns: grace_deadline,
            drift_slack_class,
            state: FenceDeadlineState::Issued,
        };

        FenceDeadline { record }
    }

    /// Return a reference to the underlying record.
    pub fn record(&self) -> &FenceDeadlineRecord {
        &self.record
    }

    /// Record that acks are in flight.
    pub fn acks_inflight(&mut self) {
        if self.record.state == FenceDeadlineState::Issued {
            self.record.state = FenceDeadlineState::AcksInflight;
        }
    }

    /// Evaluate the fence state against a current clock reading and ack count.
    ///
    /// `acks_received` is the number of acks received; `acks_expected` is the
    /// total expected. Returns the new state.
    pub fn evaluate(
        &mut self,
        current_ns: u64,
        acks_received: usize,
        acks_expected: usize,
    ) -> FenceDeadlineState {
        if acks_received >= acks_expected {
            // All acks received — nothing to escalate.
            return self.record.state;
        }

        let new_state = if current_ns >= self.record.grace_deadline_ns {
            // Past grace: escalate from DegradedVisibility, else go to DegradedVisibility first
            if self.record.state == FenceDeadlineState::DegradedVisibility {
                FenceDeadlineState::Escalated
            } else {
                FenceDeadlineState::DegradedVisibility
            }
        } else if current_ns >= self.record.ack_deadline_ns {
            if self.record.state == FenceDeadlineState::GraceExtension {
                FenceDeadlineState::DegradedVisibility
            } else {
                FenceDeadlineState::GraceExtension
            }
        } else if acks_received > 0 && acks_received < acks_expected {
            FenceDeadlineState::PartialLag
        } else {
            FenceDeadlineState::AcksInflight
        };

        self.record.state = transition_fence(self.record.state, new_state);
        self.record.state
    }

    /// Build a derived deadline for the ack time.
    pub fn ack_deadline(&self) -> DerivedDeadline {
        DerivedDeadline::with_slack(
            ClockClass::FenceDeadline,
            self.record.ack_deadline_ns,
            self.record
                .ack_deadline_ns
                .saturating_sub(self.record.issued_at_ns),
        )
    }
}

fn transition_fence(old: FenceDeadlineState, new: FenceDeadlineState) -> FenceDeadlineState {
    use FenceDeadlineState::*;
    match (old, new) {
        (Escalated, _) => Escalated,
        (DegradedVisibility, Escalated) => Escalated,
        (DegradedVisibility, _) => DegradedVisibility,
        (GraceExtension, DegradedVisibility | Escalated) => new,
        (GraceExtension, _) => GraceExtension,
        (PartialLag, GraceExtension | DegradedVisibility | Escalated) => new,
        (PartialLag, _) => PartialLag,
        (AcksInflight, _) => new,
        (Issued, _) => new,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // LeaseDeadline tests
    // ------------------------------------------------------------------

    #[test]
    fn lease_opens_correctly() {
        let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        assert_eq!(lease.record().state, LeaseDeadlineState::Open);
        assert_eq!(lease.record().clock_class, ClockClass::LeaseDeadline);
    }

    #[test]
    fn lease_transitions_through_states() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        // slack_mult=1.0, so:
        // renew_deadline = 1500
        // expiry_deadline = 3000
        // grace_deadline = 4000

        assert_eq!(lease.evaluate(1200), LeaseDeadlineState::Open);
        assert_eq!(lease.evaluate(1600), LeaseDeadlineState::Warning);
        assert_eq!(lease.evaluate(3100), LeaseDeadlineState::Grace);
        assert_eq!(lease.evaluate(4100), LeaseDeadlineState::Expired);
    }

    #[test]
    fn lease_renewal_resets_state() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        lease.evaluate(3100); // grace
        assert_eq!(lease.record().state, LeaseDeadlineState::Grace);

        lease.renew(5000, 500, 2000, 1000);
        assert_eq!(lease.record().state, LeaseDeadlineState::Open);
        assert_eq!(lease.record().opened_at_ns, 5000);
    }

    #[test]
    fn failover_only_after_expiry() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        assert!(lease.stage_failover().is_none()); // not expired

        lease.evaluate(5000); // expired
        assert!(lease.stage_failover().is_some());
        assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
    }

    #[test]
    fn drift_slack_extends_deadlines() {
        let lease_trusted =
            LeaseDeadline::open(1, 1000, 1000, 5000, 1000, DriftClass::TrustedLocal);
        let lease_elevated =
            LeaseDeadline::open(2, 1000, 1000, 5000, 1000, DriftClass::ElevatedCluster);

        // Elevated should have longer deadlines (2.5x vs 1.0x multiplier)
        assert!(
            lease_elevated.record().renew_deadline_ns > lease_trusted.record().renew_deadline_ns
        );
        assert!(
            lease_elevated.record().expiry_deadline_ns > lease_trusted.record().expiry_deadline_ns
        );
    }

    // ------------------------------------------------------------------
    // FenceDeadline tests
    // ------------------------------------------------------------------

    #[test]
    fn fence_issues_correctly() {
        let fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        assert_eq!(fence.record().state, FenceDeadlineState::Issued);
    }

    #[test]
    fn fence_acks_inflight() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        fence.acks_inflight();
        assert_eq!(fence.record().state, FenceDeadlineState::AcksInflight);
    }

    #[test]
    fn fence_partial_lag() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        // ack_deadline = 1500, grace = 1800
        // current=1200: some acks received but not all
        assert_eq!(fence.evaluate(1200, 1, 3), FenceDeadlineState::PartialLag);
    }

    #[test]
    fn fence_grace_extension() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        // ack_deadline = 1500, grace = 1800
        // current=1600: past ack deadline, before grace
        assert_eq!(
            fence.evaluate(1600, 1, 3),
            FenceDeadlineState::GraceExtension
        );
    }

    #[test]
    fn fence_degraded_then_escalated() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        // Go through grace extension first
        fence.evaluate(1600, 1, 3);
        assert_eq!(fence.record().state, FenceDeadlineState::GraceExtension);

        // Now past grace deadline → degraded visibility
        assert_eq!(
            fence.evaluate(1900, 1, 3),
            FenceDeadlineState::DegradedVisibility
        );

        // Past grace with no change → escalated
        // Actually, once in GraceExtension, past grace_deadline → DegradedVisibility
        // Past grace deadline: escalated. But we need state to be DegradedVisibility first.
        // Let me re-check: once at DegradedVisibility, going past grace stays DegradedVisibility.
        // To get Escalated we need to evaluate past grace again from DegradedVisibility.
        let new_state = fence.evaluate(2000, 1, 3);
        assert_eq!(new_state, FenceDeadlineState::Escalated);
    }

    #[test]
    fn fence_all_acks_received_no_escalation() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        // All acks received — stays in current state
        assert_eq!(fence.evaluate(2000, 3, 3), FenceDeadlineState::Issued);
    }
    // ------------------------------------------------------------------
    // LeaseDeadline::renew_deadline() tests
    // ------------------------------------------------------------------

    #[test]
    fn lease_renew_deadline_derived() {
        let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        let dd = lease.renew_deadline();
        assert_eq!(dd.clock_class, ClockClass::LeaseDeadline);
        assert_eq!(dd.base_deadline_ns, lease.record().renew_deadline_ns);
        assert!(dd.effective_deadline_ns >= dd.base_deadline_ns);
    }

    // ------------------------------------------------------------------
    // FenceDeadline::ack_deadline() tests
    // ------------------------------------------------------------------

    #[test]
    fn fence_ack_deadline_derived() {
        let fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        let dd = fence.ack_deadline();
        assert_eq!(dd.clock_class, ClockClass::FenceDeadline);
        assert_eq!(dd.base_deadline_ns, fence.record().ack_deadline_ns);
        assert!(dd.effective_deadline_ns >= dd.base_deadline_ns);
    }

    // ------------------------------------------------------------------
    // LeaseDeadline edge case: open with zero periods
    // ------------------------------------------------------------------

    #[test]
    fn lease_open_zero_periods() {
        let lease = LeaseDeadline::open(1, 1000, 0, 0, 0, DriftClass::TrustedLocal);
        assert_eq!(lease.record().renew_deadline_ns, 1000);
        assert_eq!(lease.record().expiry_deadline_ns, 1000);
        assert_eq!(lease.record().grace_deadline_ns, 1000);
    }

    // ------------------------------------------------------------------
    // LeaseDeadline: expired does not regress
    // ------------------------------------------------------------------

    #[test]
    fn lease_expired_never_goes_back() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        lease.evaluate(5000); // expired
        assert_eq!(lease.record().state, LeaseDeadlineState::Expired);
        lease.evaluate(100); // low time should not regress
        assert_eq!(lease.record().state, LeaseDeadlineState::Expired);
    }

    // ------------------------------------------------------------------
    // FenceDeadline: escalated never goes back
    // ------------------------------------------------------------------

    #[test]
    fn fence_escalated_never_goes_back() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        fence.evaluate(1600, 1, 3); // GraceExtension
        fence.evaluate(1900, 1, 3); // DegradedVisibility
        fence.evaluate(2000, 1, 3); // Escalated
        assert_eq!(fence.record().state, FenceDeadlineState::Escalated);
        fence.evaluate(100, 3, 3); // all acks, low time — stays escalated
        assert_eq!(fence.record().state, FenceDeadlineState::Escalated);
    }

    // ------------------------------------------------------------------
    // FenceDeadline: acks_inflight only from Issued state
    // ------------------------------------------------------------------

    #[test]
    fn fence_acks_inflight_only_from_issued() {
        let mut fence = FenceDeadline::issue(1, 1000, 500, 300, DriftClass::TrustedLocal);
        fence.evaluate(1200, 1, 3); // PartialLag
        assert_eq!(fence.record().state, FenceDeadlineState::PartialLag);
        fence.acks_inflight(); // should not transition from PartialLag
        assert_eq!(fence.record().state, FenceDeadlineState::PartialLag);
    }

    #[test]
    fn fence_issue_at_u64_max_saturates() {
        let fence = FenceDeadline::issue(1, u64::MAX, 1000, 500, DriftClass::TrustedLocal);
        let r = fence.record();
        assert_eq!(r.issued_at_ns, u64::MAX);
        assert_eq!(r.ack_deadline_ns, u64::MAX);
        assert_eq!(r.grace_deadline_ns, u64::MAX);
    }

    #[test]
    fn lease_stage_failover_twice_is_idempotent() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        lease.evaluate(5000); // expired
        assert!(lease.stage_failover().is_some());
        assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
        // Second call: already FailoverStaged, should return None
        assert!(lease.stage_failover().is_none());
        assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
    }

    #[test]
    fn lease_evaluate_before_open_with_backward_time_no_regression() {
        let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        // Time before open: should not regress to a state before Open
        assert_eq!(lease.evaluate(500), LeaseDeadlineState::Open);
    }
}
