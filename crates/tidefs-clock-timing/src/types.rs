// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Canonical clock, drift, health, and deadline types (P8-04 Sections 2-6).
//!
//! Authority ordering is receipt/epoch/anchor-based; time only gates waiting,
//! liveness, escalation, and narrative rendering.

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Clock classes (P8-04 Section 2)
// ---------------------------------------------------------------------------

/// Seven canonical clock classes.
///
/// Rule: `time_clock_3.realtime_narrative` is **never** authoritative ordering.
/// `time_clock_4.hlc_cluster` may appear in receipts and validation bundles, but
/// authority still depends on receipts, epochs, and anchor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockClass {
    /// `time_clock_0` — local elapsed-time measurement, no wall-clock semantics.
    MonoRawLocal,
    /// `time_clock_1` — local service deadlines, queue wait, short worker budgets.
    MonoServiceLocal,
    /// `time_clock_2` — suspend-aware lease/heartbeat/cutover deadlines.
    BoottimeLocal,
    /// `time_clock_3` — human/operator timestamps only; NOT authoritative.
    RealtimeNarrative,
    /// `time_clock_4` — hybrid logical time for cross-node narrative ordering.
    HlcCluster,
    /// `time_clock_5` — freshness/transition deadline derived from local clock + drift slack.
    FenceDeadline,
    /// `time_clock_6` — lease/quorum/failover deadline derived from local clock + drift slack.
    LeaseDeadline,
}

impl ClockClass {
    /// Whether this clock class may carry authoritative ordering weight.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, ClockClass::HlcCluster)
    }

    /// Whether this clock class is derived rather than directly sampled.
    pub fn is_derived(&self) -> bool {
        matches!(self, ClockClass::FenceDeadline | ClockClass::LeaseDeadline)
    }
}

impl fmt::Display for ClockClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ClockClass::MonoRawLocal => "time_clock_0.mono_raw_local",
            ClockClass::MonoServiceLocal => "time_clock_1.mono_service_local",
            ClockClass::BoottimeLocal => "time_clock_2.boottime_local",
            ClockClass::RealtimeNarrative => "time_clock_3.realtime_narrative",
            ClockClass::HlcCluster => "time_clock_4.hlc_cluster",
            ClockClass::FenceDeadline => "time_clock_5.fence_deadline",
            ClockClass::LeaseDeadline => "time_clock_6.lease_deadline",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Drift and trust classes (P8-04 Section 3)
// ---------------------------------------------------------------------------

/// Five canonical drift / trust classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DriftClass {
    /// `drift_time_0` — local monotonic source healthy; no anomalies.
    TrustedLocal = 0,
    /// `drift_time_1` — cluster skew within ordinary slack budget.
    NominalCluster = 1,
    /// `drift_time_2` — drift larger than target; deadlines widened.
    ElevatedCluster = 2,
    /// `drift_time_3` — drift/pause large enough to hold sensitive actions.
    SevereCluster = 3,
    /// `drift_time_4` — time source unhealthy; authority movement must freeze.
    UntrustedTime = 4,
}

impl DriftClass {
    /// Whether sensitive authority movement is permitted under this drift class.
    pub fn allows_authority_movement(&self) -> bool {
        *self <= DriftClass::ElevatedCluster
    }

    /// Whether failover-sensitive actions must be held or downgraded.
    pub fn requires_hold(&self) -> bool {
        *self >= DriftClass::SevereCluster
    }

    /// Slack multiplier for deriving deadline extensions from drift.
    pub fn slack_multiplier(&self) -> f64 {
        match self {
            DriftClass::TrustedLocal => 1.0,
            DriftClass::NominalCluster => 1.5,
            DriftClass::ElevatedCluster => 2.5,
            DriftClass::SevereCluster => 5.0,
            DriftClass::UntrustedTime => 10.0,
        }
    }
}

impl fmt::Display for DriftClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DriftClass::TrustedLocal => "drift_time_0.trusted_local",
            DriftClass::NominalCluster => "drift_time_1.nominal_cluster",
            DriftClass::ElevatedCluster => "drift_time_2.elevated_cluster",
            DriftClass::SevereCluster => "drift_time_3.severe_cluster",
            DriftClass::UntrustedTime => "drift_time_4.untrusted_time",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Clock source health (P8-04 Section 5.1)
// ---------------------------------------------------------------------------

/// Five local time-health states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeHealth {
    /// `time_health_0` — all local clocks operating normally.
    Healthy,
    /// `time_health_1` — jitter observed above nominal threshold.
    Jittered,
    /// `time_health_2` — suspend or prolonged CPU pause suspected.
    SuspendOrPauseSuspect,
    /// `time_health_3` — step regression detected (backward jump or forward leap).
    StepRegressed,
    /// `time_health_4` — time source cannot be trusted for any deadline.
    Untrusted,
}

impl TimeHealth {
    /// Whether sensitive operations may proceed under this health state.
    pub fn allows_sensitive_operations(&self) -> bool {
        matches!(self, TimeHealth::Healthy | TimeHealth::Jittered)
    }
}

// ---------------------------------------------------------------------------
// HLC state (P8-04 Section 5.2)
// ---------------------------------------------------------------------------

/// HLC lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HlcState {
    /// `hlc0` — HLC initialized but no events yet.
    Idle,
    /// `hlc1` — HLC advanced by a local event.
    LocalAdvanced,
    /// `hlc2` — HLC merged with a remote value from a received message.
    RemoteMerged,
    /// `hlc3` — HLC persisted into a receipt for validation/audit.
    PersistedForReceipt,
}

// ---------------------------------------------------------------------------
// Lease deadline state (P8-04 Section 5.3)
// ---------------------------------------------------------------------------

/// Six lease deadline lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseDeadlineState {
    /// `lease_state_0` — lease is open and active.
    Open,
    /// `lease_state_1` — lease is being renewed.
    Renewing,
    /// `lease_state_2` — lease approaching expiry; warning threshold crossed.
    Warning,
    /// `lease_state_3` — lease in grace period; renewal still possible.
    Grace,
    /// `lease_state_4` — lease expired; authority handoff may be staged.
    Expired,
    /// `lease_state_5` — failover staged; new authority being established.
    FailoverStaged,
}

impl LeaseDeadlineState {
    /// Whether the lease is still legally held (can be renewed).
    pub fn is_held(&self) -> bool {
        matches!(
            self,
            LeaseDeadlineState::Open
                | LeaseDeadlineState::Renewing
                | LeaseDeadlineState::Warning
                | LeaseDeadlineState::Grace
        )
    }
}

// ---------------------------------------------------------------------------
// Fence deadline state (P8-04 Section 5.4)
// ---------------------------------------------------------------------------

/// Six fence deadline lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FenceDeadlineState {
    /// `failure_domain_0` — freshness fence issued to cohort.
    Issued,
    /// `failure_domain_1` — waiting for acks from cohort members.
    AcksInflight,
    /// `failure_domain_2` — some acks missing; partial lag detected.
    PartialLag,
    /// `failure_domain_3` — grace extension granted.
    GraceExtension,
    /// `failure_domain_4` — products visible but freshness degraded.
    DegradedVisibility,
    /// `failure_domain_5` — escalation triggered; operator or policy action required.
    Escalated,
}

// ---------------------------------------------------------------------------
// Drift suspicion state (P8-04 Section 5.5)
// ---------------------------------------------------------------------------

/// Six drift suspicion lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriftSuspicionState {
    /// `drift_state_0` — no drift concerns.
    Nominal,
    /// `drift_state_1` — drift elevated above baseline.
    Elevated,
    /// `drift_state_2` — drift severe; sensitive actions held.
    Severe,
    /// `drift_state_3` — sensitive actions explicitly held.
    HoldSensitiveActions,
    /// `drift_state_4` — drift recovered to acceptable bounds.
    Recovered,
}

// ---------------------------------------------------------------------------
// Escalation action class (P8-04 Section 4, time_manager_8)
// ---------------------------------------------------------------------------

/// Actions a timeout escalator may choose when a deadline is missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscalationAction {
    /// No action needed; within tolerance.
    None,
    /// Hold the affected operation; wait for recovery.
    Hold,
    /// Degrade product visibility or freshness.
    Degrade,
    /// Stage failover to a successor authority.
    Failover,
    /// Stop the affected path; requires operator intervention.
    Stop,
}

// ---------------------------------------------------------------------------
// Finding severity class
// ---------------------------------------------------------------------------

/// Severity of a time-health or drift finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingSeverity {
    /// Informational only; no action required.
    Info,
    /// Elevated attention; may affect scheduling.
    Warning,
    /// Action required; sensitive operations impacted.
    Critical,
    /// Immediate stop; authority movement frozen.
    Emergency,
}

// ---------------------------------------------------------------------------
// Record types (P8-04 Section 6)
// ---------------------------------------------------------------------------

/// Snapshot of local clock source readings at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockSourceSample {
    /// Monotonic raw timestamp (nanoseconds).
    pub mono_raw_ns: u64,
    /// Monotonic service timestamp (nanoseconds).
    pub mono_service_ns: u64,
    /// Boottime timestamp (nanoseconds, suspend-aware).
    pub boottime_ns: u64,
    /// Realtime timestamp (nanoseconds, for narrative only).
    pub realtime_ns: u64,
}

/// HLC value: (physical_component_ns, logical_counter).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    Default,
)]
pub struct HlcValue {
    /// Physical component — wall-clock nanoseconds from an HLC-aware source.
    pub physical_ns: u64,
    /// Logical counter — distinguishes events at the same physical time.
    pub logical: u64,
}

impl HlcValue {
    /// Create a new HLC value.
    pub fn new(physical_ns: u64, logical: u64) -> Self {
        HlcValue {
            physical_ns,
            logical,
        }
    }

    /// Zero/initial HLC value.
    pub fn zero() -> Self {
        HlcValue {
            physical_ns: 0,
            logical: 0,
        }
    }

    /// Returns the physical nanosecond component.
    ///
    /// This is the preferred accessor; prefer it over direct field access
    /// to avoid recurring compile errors from method-call syntax on fields.
    #[must_use]
    pub fn physical_ns(&self) -> u64 {
        self.physical_ns
    }

    /// Returns the logical counter component.
    #[must_use]
    pub fn logical(&self) -> u64 {
        self.logical
    }
}

impl fmt::Display for HlcValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.physical_ns(), self.logical())
    }
}

/// A deadline derived from a base clock + drift slack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedDeadline {
    /// The clock class this deadline is derived from.
    pub clock_class: ClockClass,
    /// Base deadline in nanoseconds (monotonic or boottime).
    pub base_deadline_ns: u64,
    /// Additional drift slack in nanoseconds.
    pub drift_slack_ns: u64,
    /// Total effective deadline: base + slack.
    pub effective_deadline_ns: u64,
}

impl DerivedDeadline {
    /// Create a deadline with drift slack.
    pub fn with_slack(clock_class: ClockClass, base_deadline_ns: u64, drift_slack_ns: u64) -> Self {
        DerivedDeadline {
            clock_class,
            base_deadline_ns,
            drift_slack_ns,
            effective_deadline_ns: base_deadline_ns.saturating_add(drift_slack_ns),
        }
    }

    /// Whether this deadline has passed given a current time.
    pub fn has_passed(&self, current_ns: u64) -> bool {
        current_ns >= self.effective_deadline_ns
    }

    /// Remaining time until this deadline, or zero if passed.
    pub fn remaining_ns(&self, current_ns: u64) -> u64 {
        self.effective_deadline_ns.saturating_sub(current_ns)
    }
}

/// A lease deadline record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseDeadlineRecord {
    /// Monotonic identifier.
    pub lease_deadline_id: u64,
    /// The clock class used for this deadline.
    pub clock_class: ClockClass,
    /// Time the lease was opened (nanoseconds).
    pub opened_at_ns: u64,
    /// Renewal deadline (nanoseconds).
    pub renew_deadline_ns: u64,
    /// Expiry deadline (nanoseconds).
    pub expiry_deadline_ns: u64,
    /// Grace period deadline (nanoseconds).
    pub grace_deadline_ns: u64,
    /// Drift slack applied.
    pub drift_slack_class: DriftClass,
    /// Current deadline state.
    pub state: LeaseDeadlineState,
}

/// A fence deadline record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceDeadlineRecord {
    /// Monotonic identifier.
    pub fence_deadline_id: u64,
    /// The clock class used for this deadline.
    pub clock_class: ClockClass,
    /// Time the fence was issued (nanoseconds).
    pub issued_at_ns: u64,
    /// Ack deadline (nanoseconds).
    pub ack_deadline_ns: u64,
    /// Grace period deadline (nanoseconds), if any.
    pub grace_deadline_ns: u64,
    /// Drift slack applied.
    pub drift_slack_class: DriftClass,
    /// Current fence state.
    pub state: FenceDeadlineState,
}

/// A heartbeat epoch record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatEpochRecord {
    /// Monotonic identifier.
    pub heartbeat_epoch_id: u64,
    /// Time the epoch opened (nanoseconds).
    pub opened_at_ns: u64,
    /// Expected heartbeat period (nanoseconds).
    pub heartbeat_period_ns: u64,
    /// Maximum consecutive misses before suspicion.
    pub miss_budget: u32,
    /// Count of heartbeats seen in this epoch.
    pub seen_counter: u64,
    /// Current suspicion state.
    pub suspicion_state: DriftSuspicionState,
}

/// An escalation receipt — canonical validation that a timeout crossed a policy boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlineEscalationReceipt {
    /// Monotonic receipt identifier.
    pub receipt_id: u64,
    /// The HLC value at time of escalation.
    pub hlc_at_escalation: HlcValue,
    /// The deadline that was missed.
    pub deadline_ns: u64,
    /// The current time when the miss was detected.
    pub detected_at_ns: u64,
    /// Drift class at time of detection.
    pub drift_class: DriftClass,
    /// Escalation action taken.
    pub action: EscalationAction,
    /// Previous deadline state.
    pub old_state: String,
    /// New deadline state.
    pub new_state: String,
}

/// A time-health finding record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeHealthFinding {
    /// Monotonic finding identifier.
    pub finding_id: u64,
    /// The clock class that triggered the finding.
    pub clock_class: ClockClass,
    /// Severity of the finding.
    pub severity: FindingSeverity,
    /// Description of the finding.
    pub description: String,
    /// HLC value when the finding was recorded.
    pub hlc_at_finding: HlcValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_class_authoritative() {
        assert!(!ClockClass::MonoRawLocal.is_authoritative());
        assert!(!ClockClass::RealtimeNarrative.is_authoritative());
        assert!(ClockClass::HlcCluster.is_authoritative());
    }

    #[test]
    fn clock_class_derived() {
        assert!(ClockClass::FenceDeadline.is_derived());
        assert!(ClockClass::LeaseDeadline.is_derived());
        assert!(!ClockClass::MonoServiceLocal.is_derived());
    }

    #[test]
    fn drift_class_ordering() {
        assert!(DriftClass::TrustedLocal < DriftClass::UntrustedTime);
        assert!(DriftClass::NominalCluster < DriftClass::SevereCluster);
    }

    #[test]
    fn drift_allows_movement() {
        assert!(DriftClass::TrustedLocal.allows_authority_movement());
        assert!(DriftClass::NominalCluster.allows_authority_movement());
        assert!(DriftClass::ElevatedCluster.allows_authority_movement());
        assert!(!DriftClass::SevereCluster.allows_authority_movement());
        assert!(!DriftClass::UntrustedTime.allows_authority_movement());
    }

    #[test]
    fn drift_slack_multipliers_increase() {
        assert!(
            DriftClass::TrustedLocal.slack_multiplier()
                < DriftClass::NominalCluster.slack_multiplier()
        );
        assert!(
            DriftClass::NominalCluster.slack_multiplier()
                < DriftClass::ElevatedCluster.slack_multiplier()
        );
        assert!(
            DriftClass::ElevatedCluster.slack_multiplier()
                < DriftClass::SevereCluster.slack_multiplier()
        );
        assert!(
            DriftClass::SevereCluster.slack_multiplier()
                < DriftClass::UntrustedTime.slack_multiplier()
        );
    }

    #[test]
    fn time_health_sensitive_ops() {
        assert!(TimeHealth::Healthy.allows_sensitive_operations());
        assert!(TimeHealth::Jittered.allows_sensitive_operations());
        assert!(!TimeHealth::SuspendOrPauseSuspect.allows_sensitive_operations());
        assert!(!TimeHealth::StepRegressed.allows_sensitive_operations());
        assert!(!TimeHealth::Untrusted.allows_sensitive_operations());
    }

    #[test]
    fn lease_states_held() {
        assert!(LeaseDeadlineState::Open.is_held());
        assert!(LeaseDeadlineState::Renewing.is_held());
        assert!(LeaseDeadlineState::Warning.is_held());
        assert!(LeaseDeadlineState::Grace.is_held());
        assert!(!LeaseDeadlineState::Expired.is_held());
        assert!(!LeaseDeadlineState::FailoverStaged.is_held());
    }

    #[test]
    fn derived_deadline_has_passed() {
        let dd = DerivedDeadline::with_slack(ClockClass::BoottimeLocal, 1000, 200);
        assert!(!dd.has_passed(500));
        assert!(!dd.has_passed(1199));
        assert!(dd.has_passed(1200));
        assert!(dd.has_passed(2000));
    }

    #[test]
    fn derived_deadline_remaining() {
        let dd = DerivedDeadline::with_slack(ClockClass::BoottimeLocal, 1000, 200);
        assert_eq!(dd.remaining_ns(500), 700);
        assert_eq!(dd.remaining_ns(1200), 0);
    }

    #[test]
    fn hlc_value_ordering() {
        let a = HlcValue::new(100, 5);
        let b = HlcValue::new(100, 10);
        let c = HlcValue::new(200, 0);
        assert!(a < b); // same physical, lower logical
        assert!(b < c); // lower physical
        assert!(a < c);
    }

    #[test]
    fn hlc_display() {
        assert_eq!(format!("{}", HlcValue::new(100, 42)), "100.42");
    }
    // ------------------------------------------------------------------
    // HeartbeatEpochRecord tests
    // ------------------------------------------------------------------

    #[test]
    fn heartbeat_epoch_construction() {
        let hb = HeartbeatEpochRecord {
            heartbeat_epoch_id: 1,
            opened_at_ns: 1000,
            heartbeat_period_ns: 100_000_000,
            miss_budget: 3,
            seen_counter: 0,
            suspicion_state: DriftSuspicionState::Nominal,
        };
        assert_eq!(hb.heartbeat_epoch_id, 1);
        assert_eq!(hb.miss_budget, 3);
        assert_eq!(hb.suspicion_state, DriftSuspicionState::Nominal);
    }

    #[test]
    fn heartbeat_epoch_clone_eq() {
        let hb = HeartbeatEpochRecord {
            heartbeat_epoch_id: 2,
            opened_at_ns: 2000,
            heartbeat_period_ns: 200_000_000,
            miss_budget: 5,
            seen_counter: 10,
            suspicion_state: DriftSuspicionState::Elevated,
        };
        let hb2 = hb.clone();
        assert_eq!(hb, hb2);
    }

    // ------------------------------------------------------------------
    // ClockResynchronizationReceipt tests
    // ------------------------------------------------------------------

    #[test]
    fn resync_receipt_construction() {
        let receipt = ClockResynchronizationReceipt::new(
            1,
            "node-a".into(),
            SourceQuorum::new(3, 5),
            DriftClass::SevereCluster,
            DriftClass::NominalCluster,
            HlcValue::new(500, 1),
            10_000,
        );
        assert_eq!(receipt.receipt_id, 1);
        assert_eq!(receipt.node_ref, "node-a");
        assert_eq!(receipt.confirmed_sources, 3);
        assert_eq!(receipt.total_sources, 5);
        assert_eq!(receipt.previous_drift_class, DriftClass::SevereCluster);
        assert_eq!(receipt.new_drift_class, DriftClass::NominalCluster);
        assert_eq!(receipt.hlc_at_resync, HlcValue::new(500, 1));
        assert_eq!(receipt.resync_time_ns, 10_000);
    }

    #[test]
    fn resync_receipt_majority_recovery() {
        let receipt = ClockResynchronizationReceipt::new(
            1,
            "n1".into(),
            SourceQuorum::new(3, 5),
            DriftClass::SevereCluster,
            DriftClass::NominalCluster,
            HlcValue::zero(),
            0,
        );
        assert!(receipt.is_majority_recovery());

        let receipt2 = ClockResynchronizationReceipt::new(
            2,
            "n2".into(),
            SourceQuorum::new(2, 5),
            DriftClass::SevereCluster,
            DriftClass::NominalCluster,
            HlcValue::zero(),
            0,
        );
        assert!(!receipt2.is_majority_recovery());
    }

    #[test]
    fn resync_receipt_exact_tie() {
        let receipt = ClockResynchronizationReceipt::new(
            3,
            "n3".into(),
            SourceQuorum::new(2, 4),
            DriftClass::SevereCluster,
            DriftClass::NominalCluster,
            HlcValue::zero(),
            0,
        );
        assert!(!receipt.is_majority_recovery());
    }

    #[test]
    fn resync_receipt_unanimous() {
        let receipt = ClockResynchronizationReceipt::new(
            4,
            "n4".into(),
            SourceQuorum::new(5, 5),
            DriftClass::UntrustedTime,
            DriftClass::TrustedLocal,
            HlcValue::new(999, 42),
            777,
        );
        assert!(receipt.is_majority_recovery());
    }

    #[test]
    fn resync_receipt_single_source() {
        let receipt = ClockResynchronizationReceipt::new(
            5,
            "n5".into(),
            SourceQuorum::new(1, 1),
            DriftClass::ElevatedCluster,
            DriftClass::NominalCluster,
            HlcValue::zero(),
            0,
        );
        assert!(receipt.is_majority_recovery());
    }

    // ------------------------------------------------------------------
    // SourceQuorum tests
    // ------------------------------------------------------------------

    #[test]
    fn source_quorum_construction() {
        let sq = SourceQuorum::new(3, 7);
        assert_eq!(sq.confirmed, 3);
        assert_eq!(sq.total, 7);
    }

    // ------------------------------------------------------------------
    // EpochTimingAttestation tests
    // ------------------------------------------------------------------

    #[test]
    fn epoch_attestation_valid() {
        let att = EpochTimingAttestation::new(
            5,
            vec![ClockClass::BoottimeLocal, ClockClass::HlcCluster],
            DriftClass::NominalCluster,
            Some(4),
            10,
            HlcValue::new(200, 0),
            1000,
        );
        assert!(att.permits_transition());
        assert!(att.is_valid);
        assert_eq!(att.epoch_id, 5);
        assert_eq!(att.previous_epoch_ref, Some(4));
    }

    #[test]
    fn epoch_attestation_initial_epoch() {
        let att = EpochTimingAttestation::new(
            1,
            vec![ClockClass::BoottimeLocal],
            DriftClass::NominalCluster,
            None,
            1,
            HlcValue::zero(),
            0,
        );
        assert!(att.permits_transition());
        assert!(att.previous_epoch_ref.is_none());
    }

    #[test]
    fn epoch_attestation_invalid_under_severe_drift() {
        let att = EpochTimingAttestation::new(
            10,
            vec![ClockClass::HlcCluster],
            DriftClass::SevereCluster,
            Some(9),
            5,
            HlcValue::new(300, 1),
            2000,
        );
        assert!(!att.permits_transition());
        assert!(!att.is_valid);
    }

    #[test]
    fn epoch_attestation_invalid_under_untrusted() {
        let att = EpochTimingAttestation::new(
            10,
            vec![ClockClass::HlcCluster],
            DriftClass::UntrustedTime,
            Some(9),
            5,
            HlcValue::new(300, 1),
            2000,
        );
        assert!(!att.permits_transition());
    }

    // ------------------------------------------------------------------
    // HlcValue serde round-trip
    // ------------------------------------------------------------------

    #[test]
    fn hlc_value_serde_roundtrip() {
        let original = HlcValue::new(123456789, 42);
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: HlcValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, parsed);
    }

    #[test]
    fn hlc_value_serde_zero() {
        let original = HlcValue::zero();
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: HlcValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, parsed);
    }

    #[test]
    fn hlc_value_serde_max_values() {
        let original = HlcValue::new(u64::MAX, u64::MAX);
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: HlcValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, parsed);
    }

    // ------------------------------------------------------------------
    // DerivedDeadline edge cases
    // ------------------------------------------------------------------

    #[test]
    fn derived_deadline_zero_base() {
        let dd = DerivedDeadline::with_slack(ClockClass::BoottimeLocal, 0, 0);
        assert_eq!(dd.base_deadline_ns, 0);
        assert_eq!(dd.effective_deadline_ns, 0);
        assert!(dd.has_passed(0));
        assert!(dd.has_passed(1));
        assert_eq!(dd.remaining_ns(0), 0);
        assert_eq!(dd.remaining_ns(1), 0);
    }

    #[test]
    fn derived_deadline_max_base() {
        let dd = DerivedDeadline::with_slack(ClockClass::BoottimeLocal, u64::MAX, 0);
        assert_eq!(dd.base_deadline_ns, u64::MAX);
        assert_eq!(dd.effective_deadline_ns, u64::MAX);
        assert!(!dd.has_passed(u64::MAX - 1));
        assert!(dd.has_passed(u64::MAX));
    }

    #[test]
    fn derived_deadline_saturating_add() {
        let dd = DerivedDeadline::with_slack(ClockClass::BoottimeLocal, u64::MAX, 100);
        assert_eq!(dd.effective_deadline_ns, u64::MAX);
        assert_eq!(dd.drift_slack_ns, 100);
    }

    #[test]
    fn derived_deadline_equal_base_and_slack() {
        let dd = DerivedDeadline::with_slack(ClockClass::FenceDeadline, 1000, 1000);
        assert_eq!(dd.effective_deadline_ns, 2000);
        assert_eq!(dd.remaining_ns(1500), 500);
        assert_eq!(dd.remaining_ns(2500), 0);
    }

    #[test]
    fn derived_deadline_with_all_clock_classes() {
        for cc in &[
            ClockClass::MonoRawLocal,
            ClockClass::MonoServiceLocal,
            ClockClass::BoottimeLocal,
            ClockClass::RealtimeNarrative,
            ClockClass::HlcCluster,
            ClockClass::FenceDeadline,
            ClockClass::LeaseDeadline,
        ] {
            let dd = DerivedDeadline::with_slack(*cc, 500, 100);
            assert_eq!(dd.clock_class, *cc);
            assert_eq!(dd.effective_deadline_ns, 600);
        }
    }

    // ------------------------------------------------------------------
    // ClockSourceSample construction and equality
    // ------------------------------------------------------------------

    #[test]
    fn clock_source_sample_eq() {
        let a = ClockSourceSample {
            mono_raw_ns: 1,
            mono_service_ns: 2,
            boottime_ns: 3,
            realtime_ns: 4,
        };
        let b = ClockSourceSample {
            mono_raw_ns: 1,
            mono_service_ns: 2,
            boottime_ns: 3,
            realtime_ns: 4,
        };
        let c = ClockSourceSample {
            mono_raw_ns: 1,
            mono_service_ns: 2,
            boottime_ns: 3,
            realtime_ns: 5,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clock_source_sample_clone() {
        let a = ClockSourceSample {
            mono_raw_ns: 100,
            mono_service_ns: 101,
            boottime_ns: 102,
            realtime_ns: 103,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // FenceFrontier and FenceTiming construction
    // ------------------------------------------------------------------

    #[test]
    fn fence_frontier_new() {
        let ff = FenceFrontier::new(10, 5000);
        assert_eq!(ff.epoch, 10);
        assert_eq!(ff.wall_ns, 5000);
    }

    #[test]
    fn fence_frontier_const_new() {
        let ff = FenceFrontier {
            epoch: 5,
            wall_ns: 100,
        };
        assert_eq!(ff.epoch, 5);
        assert_eq!(ff.wall_ns, 100);
    }

    // ------------------------------------------------------------------
    // FreshnessFenceRecord is_expired edge cases
    // ------------------------------------------------------------------

    #[test]
    fn freshness_fence_is_expired_exactly_at_expiry() {
        let frontier = FenceFrontier::new(1, 100);
        let timing = FenceTiming {
            issue_time_ns: 0,
            max_drift_window_ns: 1000,
        };
        let fence = FreshnessFenceRecord::new(
            1,
            "d".into(),
            frontier,
            FenceClass::Strict,
            0,
            timing,
            DriftClass::TrustedLocal,
        );
        assert_eq!(fence.expiry_time_ns, 1000);
        assert!(!fence.is_expired(999));
        assert!(fence.is_expired(1000));
        assert!(fence.is_expired(1001));
    }

    #[test]
    fn freshness_fence_is_expired_saturating_expiry() {
        let frontier = FenceFrontier::new(1, 100);
        let timing = FenceTiming {
            issue_time_ns: u64::MAX,
            max_drift_window_ns: 1000,
        };
        let fence = FreshnessFenceRecord::new(
            1,
            "d".into(),
            frontier,
            FenceClass::Strict,
            0,
            timing,
            DriftClass::TrustedLocal,
        );
        assert_eq!(fence.expiry_time_ns, u64::MAX);
    }

    // ------------------------------------------------------------------
    // DeadlineEscalationReceipt construction
    // ------------------------------------------------------------------

    #[test]
    fn escalation_receipt_fields() {
        let receipt = DeadlineEscalationReceipt {
            receipt_id: 42,
            hlc_at_escalation: HlcValue::new(1000, 5),
            deadline_ns: 2000,
            detected_at_ns: 2500,
            drift_class: DriftClass::ElevatedCluster,
            action: EscalationAction::Failover,
            old_state: "grace".into(),
            new_state: "expired".into(),
        };
        assert_eq!(receipt.receipt_id, 42);
        assert_eq!(receipt.action, EscalationAction::Failover);
        assert_eq!(receipt.old_state, "grace");
        assert_eq!(receipt.new_state, "expired");
    }

    // ------------------------------------------------------------------
    // TimeHealthFinding construction
    // ------------------------------------------------------------------

    #[test]
    fn time_health_finding_fields() {
        let finding = TimeHealthFinding {
            finding_id: 1,
            clock_class: ClockClass::MonoRawLocal,
            severity: FindingSeverity::Critical,
            description: "backward jump".into(),
            hlc_at_finding: HlcValue::new(500, 0),
        };
        assert_eq!(finding.finding_id, 1);
        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert_eq!(finding.description, "backward jump");
    }

    // ------------------------------------------------------------------
    // Display trait tests
    // ------------------------------------------------------------------

    #[test]
    fn clock_class_display() {
        assert_eq!(
            format!("{}", ClockClass::MonoRawLocal),
            "time_clock_0.mono_raw_local"
        );
        assert_eq!(
            format!("{}", ClockClass::MonoServiceLocal),
            "time_clock_1.mono_service_local"
        );
        assert_eq!(
            format!("{}", ClockClass::BoottimeLocal),
            "time_clock_2.boottime_local"
        );
        assert_eq!(
            format!("{}", ClockClass::RealtimeNarrative),
            "time_clock_3.realtime_narrative"
        );
        assert_eq!(
            format!("{}", ClockClass::HlcCluster),
            "time_clock_4.hlc_cluster"
        );
        assert_eq!(
            format!("{}", ClockClass::FenceDeadline),
            "time_clock_5.fence_deadline"
        );
        assert_eq!(
            format!("{}", ClockClass::LeaseDeadline),
            "time_clock_6.lease_deadline"
        );
    }

    #[test]
    fn drift_class_display() {
        assert_eq!(
            format!("{}", DriftClass::TrustedLocal),
            "drift_time_0.trusted_local"
        );
        assert_eq!(
            format!("{}", DriftClass::NominalCluster),
            "drift_time_1.nominal_cluster"
        );
        assert_eq!(
            format!("{}", DriftClass::ElevatedCluster),
            "drift_time_2.elevated_cluster"
        );
        assert_eq!(
            format!("{}", DriftClass::SevereCluster),
            "drift_time_3.severe_cluster"
        );
        assert_eq!(
            format!("{}", DriftClass::UntrustedTime),
            "drift_time_4.untrusted_time"
        );
    }

    #[test]
    fn fence_class_display() {
        assert_eq!(format!("{}", FenceClass::Strict), "fence_class.0.strict");
        assert_eq!(format!("{}", FenceClass::Bounded), "fence_class.1.bounded");
        assert_eq!(format!("{}", FenceClass::Soft), "fence_class.2.soft");
    }

    // ------------------------------------------------------------------
    // FenceClass method tests
    // ------------------------------------------------------------------

    #[test]
    fn fence_class_blocks_stale_reads() {
        assert!(FenceClass::Strict.blocks_stale_reads());
        assert!(!FenceClass::Bounded.blocks_stale_reads());
        assert!(!FenceClass::Soft.blocks_stale_reads());
    }

    #[test]
    fn fence_class_permits_degraded() {
        assert!(!FenceClass::Strict.permits_degraded());
        assert!(FenceClass::Bounded.permits_degraded());
        assert!(FenceClass::Soft.permits_degraded());
    }

    // ------------------------------------------------------------------
    // FreshnessVerdict method tests
    // ------------------------------------------------------------------

    #[test]
    fn freshness_verdict_permits_operation() {
        assert!(FreshnessVerdict::WithinBound.permits_operation());
        assert!(FreshnessVerdict::DegradedAdmission.permits_operation());
        assert!(!FreshnessVerdict::StaleSource.permits_operation());
        assert!(!FreshnessVerdict::Expired.permits_operation());
    }

    // ------------------------------------------------------------------
    // FenceTiming construction
    // ------------------------------------------------------------------

    #[test]
    fn fence_timing_construction() {
        let ft = FenceTiming {
            issue_time_ns: 500,
            max_drift_window_ns: 10_000,
        };
        assert_eq!(ft.issue_time_ns, 500);
        assert_eq!(ft.max_drift_window_ns, 10_000);
    }

    #[test]
    fn fence_timing_clone_copy() {
        let ft = FenceTiming {
            issue_time_ns: 100,
            max_drift_window_ns: 200,
        };
        let ft2 = ft; // Copy
        assert_eq!(ft.issue_time_ns, ft2.issue_time_ns);
        assert_eq!(ft.max_drift_window_ns, ft2.max_drift_window_ns);
        let ft3 = ft2;
        assert_eq!(ft, ft3);
    }

    // ------------------------------------------------------------------
    // Enum variant exhaustive checks
    // ------------------------------------------------------------------

    #[test]
    fn hlc_state_all_variants_distinct() {
        use std::collections::HashSet;
        let variants: HashSet<_> = vec![
            HlcState::Idle,
            HlcState::LocalAdvanced,
            HlcState::RemoteMerged,
            HlcState::PersistedForReceipt,
        ]
        .into_iter()
        .collect();
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn fence_deadline_state_all_variants_distinct() {
        use std::collections::HashSet;
        let variants: HashSet<_> = vec![
            FenceDeadlineState::Issued,
            FenceDeadlineState::AcksInflight,
            FenceDeadlineState::PartialLag,
            FenceDeadlineState::GraceExtension,
            FenceDeadlineState::DegradedVisibility,
            FenceDeadlineState::Escalated,
        ]
        .into_iter()
        .collect();
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn drift_suspicion_state_all_variants_distinct() {
        use std::collections::HashSet;
        let variants: HashSet<_> = vec![
            DriftSuspicionState::Nominal,
            DriftSuspicionState::Elevated,
            DriftSuspicionState::Severe,
            DriftSuspicionState::HoldSensitiveActions,
            DriftSuspicionState::Recovered,
        ]
        .into_iter()
        .collect();
        assert_eq!(variants.len(), 5);
    }

    #[test]
    fn escalation_action_all_variants_distinct() {
        use std::collections::HashSet;
        let variants: HashSet<_> = vec![
            EscalationAction::None,
            EscalationAction::Hold,
            EscalationAction::Degrade,
            EscalationAction::Failover,
            EscalationAction::Stop,
        ]
        .into_iter()
        .collect();
        assert_eq!(variants.len(), 5);
    }

    #[test]
    fn finding_severity_ordering() {
        assert!(FindingSeverity::Info < FindingSeverity::Warning);
        assert!(FindingSeverity::Warning < FindingSeverity::Critical);
        assert!(FindingSeverity::Critical < FindingSeverity::Emergency);
    }

    #[test]
    fn finding_severity_all_variants_distinct() {
        use std::collections::HashSet;
        let variants: HashSet<_> = vec![
            FindingSeverity::Info,
            FindingSeverity::Warning,
            FindingSeverity::Critical,
            FindingSeverity::Emergency,
        ]
        .into_iter()
        .collect();
        assert_eq!(variants.len(), 4);
    }

    // ------------------------------------------------------------------
    // DriftClass::requires_hold
    // ------------------------------------------------------------------

    #[test]
    fn drift_requires_hold_only_severe_and_untrusted() {
        assert!(!DriftClass::TrustedLocal.requires_hold());
        assert!(!DriftClass::NominalCluster.requires_hold());
        assert!(!DriftClass::ElevatedCluster.requires_hold());
        assert!(DriftClass::SevereCluster.requires_hold());
        assert!(DriftClass::UntrustedTime.requires_hold());
    }

    // ------------------------------------------------------------------
    // LeaseDeadlineRecord and FenceDeadlineRecord construction
    // ------------------------------------------------------------------

    #[test]
    fn lease_deadline_record_fields_preserved() {
        let rec = LeaseDeadlineRecord {
            lease_deadline_id: 42,
            clock_class: ClockClass::BoottimeLocal,
            opened_at_ns: 1000,
            renew_deadline_ns: 2000,
            expiry_deadline_ns: 5000,
            grace_deadline_ns: 7000,
            drift_slack_class: DriftClass::NominalCluster,
            state: LeaseDeadlineState::Open,
        };
        assert_eq!(rec.lease_deadline_id, 42);
        assert_eq!(rec.clock_class, ClockClass::BoottimeLocal);
        assert_eq!(rec.opened_at_ns, 1000);
        assert_eq!(rec.renew_deadline_ns, 2000);
        assert_eq!(rec.expiry_deadline_ns, 5000);
        assert_eq!(rec.grace_deadline_ns, 7000);
        assert_eq!(rec.drift_slack_class, DriftClass::NominalCluster);
        assert_eq!(rec.state, LeaseDeadlineState::Open);
    }

    #[test]
    fn lease_deadline_record_clone_eq() {
        let a = LeaseDeadlineRecord {
            lease_deadline_id: 1,
            clock_class: ClockClass::MonoServiceLocal,
            opened_at_ns: 500,
            renew_deadline_ns: 1500,
            expiry_deadline_ns: 3000,
            grace_deadline_ns: 4000,
            drift_slack_class: DriftClass::TrustedLocal,
            state: LeaseDeadlineState::Renewing,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn fence_deadline_record_fields_preserved() {
        let rec = FenceDeadlineRecord {
            fence_deadline_id: 7,
            clock_class: ClockClass::FenceDeadline,
            issued_at_ns: 500,
            ack_deadline_ns: 1500,
            grace_deadline_ns: 3000,
            drift_slack_class: DriftClass::NominalCluster,
            state: FenceDeadlineState::Issued,
        };
        assert_eq!(rec.fence_deadline_id, 7);
        assert_eq!(rec.clock_class, ClockClass::FenceDeadline);
        assert_eq!(rec.issued_at_ns, 500);
        assert_eq!(rec.ack_deadline_ns, 1500);
        assert_eq!(rec.grace_deadline_ns, 3000);
        assert_eq!(rec.drift_slack_class, DriftClass::NominalCluster);
        assert_eq!(rec.state, FenceDeadlineState::Issued);
    }

    #[test]
    fn fence_deadline_record_clone_eq() {
        let a = FenceDeadlineRecord {
            fence_deadline_id: 3,
            clock_class: ClockClass::FenceDeadline,
            issued_at_ns: 0,
            ack_deadline_ns: 1000,
            grace_deadline_ns: 2000,
            drift_slack_class: DriftClass::TrustedLocal,
            state: FenceDeadlineState::AcksInflight,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // HlcValue edge cases
    // ------------------------------------------------------------------

    #[test]
    fn hlc_value_physical_ns_getter() {
        assert_eq!(HlcValue::new(0, 0).physical_ns(), 0);
        assert_eq!(HlcValue::new(42, 0).physical_ns(), 42);
        assert_eq!(HlcValue::new(u64::MAX, 0).physical_ns(), u64::MAX);
    }

    #[test]
    fn hlc_value_logical_getter() {
        assert_eq!(HlcValue::new(0, 0).logical(), 0);
        assert_eq!(HlcValue::new(0, 99).logical(), 99);
        assert_eq!(HlcValue::new(0, u64::MAX).logical(), u64::MAX);
    }

    #[test]
    fn hlc_value_ordering_same_physical_diff_logical() {
        let a = HlcValue::new(100, 1);
        let b = HlcValue::new(100, 5);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn hlc_value_ordering_physical_trumps_logical() {
        let a = HlcValue::new(200, 0);
        let b = HlcValue::new(100, u64::MAX);
        assert!(a > b);
        assert!(b < a);
    }

    // ------------------------------------------------------------------
    // FenceFrontier edge cases
    // ------------------------------------------------------------------

    #[test]
    fn fence_frontier_zero_epoch() {
        let ff = FenceFrontier::new(0, 1000);
        assert_eq!(ff.epoch, 0);
        assert_eq!(ff.wall_ns, 1000);
    }

    #[test]
    fn fence_frontier_max_values() {
        let ff = FenceFrontier::new(u64::MAX, u64::MAX);
        assert_eq!(ff.epoch, u64::MAX);
        assert_eq!(ff.wall_ns, u64::MAX);
    }

    // ------------------------------------------------------------------
    // DeadlineEscalationReceipt Clone + Eq
    // ------------------------------------------------------------------

    #[test]
    fn escalation_receipt_clone_and_inequality() {
        let a = DeadlineEscalationReceipt {
            receipt_id: 1,
            hlc_at_escalation: HlcValue::new(100, 0),
            deadline_ns: 5000,
            detected_at_ns: 6000,
            drift_class: DriftClass::ElevatedCluster,
            action: EscalationAction::Hold,
            old_state: "open".into(),
            new_state: "warning".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = DeadlineEscalationReceipt {
            receipt_id: 2,
            ..a.clone()
        };
        assert_ne!(a, c);
    }

    // ------------------------------------------------------------------
    // TimeHealthFinding across all severity levels
    // ------------------------------------------------------------------

    #[test]
    fn time_health_finding_all_severity_levels_non_empty_debug() {
        let variants = [
            (FindingSeverity::Info, ClockClass::MonoRawLocal),
            (FindingSeverity::Warning, ClockClass::MonoServiceLocal),
            (FindingSeverity::Critical, ClockClass::BoottimeLocal),
            (FindingSeverity::Emergency, ClockClass::RealtimeNarrative),
        ];
        for (severity, clock_class) in variants {
            let finding = TimeHealthFinding {
                finding_id: 1,
                clock_class,
                severity,
                description: "test finding".into(),
                hlc_at_finding: HlcValue::zero(),
            };
            assert!(!format!("{finding:?}").is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Freshness fence types (P8-04 Section 4)
// ---------------------------------------------------------------------------

/// Freshness fence classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FenceClass {
    /// No read behind fence; source must be at or ahead of the frontier.
    Strict,
    /// Reads permitted within a declared lag window.
    Bounded,
    /// Advisory only; degradation visible but not blocked.
    Soft,
}

impl FenceClass {
    /// Whether this fence class blocks reads that are behind the frontier.
    pub fn blocks_stale_reads(&self) -> bool {
        matches!(self, FenceClass::Strict)
    }

    /// Whether this fence class permits degraded reads.
    pub fn permits_degraded(&self) -> bool {
        matches!(self, FenceClass::Bounded | FenceClass::Soft)
    }
}

impl fmt::Display for FenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FenceClass::Strict => "fence_class.0.strict",
            FenceClass::Bounded => "fence_class.1.bounded",
            FenceClass::Soft => "fence_class.2.soft",
        };
        write!(f, "{s}")
    }
}

/// Verdict from evaluating freshness of a source against a fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FreshnessVerdict {
    /// Source is within the fence bound; proceed normally.
    WithinBound,
    /// Source is behind the fence; operation must abort.
    StaleSource,
    /// Source is within a degradation window; proceed with visible degradation.
    DegradedAdmission,
    /// The fence itself has expired; operation must abort.
    Expired,
}

impl FreshnessVerdict {
    /// Whether this verdict permits the operation to proceed.
    pub fn permits_operation(&self) -> bool {
        matches!(
            self,
            FreshnessVerdict::WithinBound | FreshnessVerdict::DegradedAdmission
        )
    }
}

/// A freshness fence frontier (logical epoch + wall-clock bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceFrontier {
    /// Logical epoch the source must be at or ahead of.
    pub epoch: u64,
    /// Wall-clock bound for the fence frontier (nanoseconds).
    pub wall_ns: u64,
}

impl FenceFrontier {
    pub const fn new(epoch: u64, wall_ns: u64) -> Self {
        Self { epoch, wall_ns }
    }
}

/// Timing parameters for a freshness fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceTiming {
    /// Fence issue time (nanoseconds from BoottimeLocal).
    pub issue_time_ns: u64,
    /// Maximum drift window applied to compute expiry (nanoseconds).
    pub max_drift_window_ns: u64,
}

/// A freshness fence record (P8-04 Sections 4, 9.2).
///
/// Freshness fences protect reads and writes from stale or lagged sources.
/// Every fence has a declared frontier (the minimum acceptable source position),
/// a fence class controlling strictness, and an expiry after which the fence
/// is no longer valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessFenceRecord {
    /// Monotonic fence identifier.
    pub fence_id: u64,
    /// The authority domain this fence protects.
    pub authority_domain_ref: String,
    /// The fence frontier: source must be at or ahead of this logical epoch.
    pub fence_frontier_epoch: u64,
    /// Wall-clock bound for the fence frontier (nanoseconds).
    pub fence_frontier_wall_ns: u64,
    /// Fence strictness class.
    pub fence_class: FenceClass,
    /// Allowed lag window for Bounded fences (nanoseconds).
    pub lag_window_ns: u64,
    /// Fence issue time (nanoseconds from BoottimeLocal).
    pub issue_time_ns: u64,
    /// Fence expiry time (issue_time + max_drift_window, nanoseconds).
    pub expiry_time_ns: u64,
    /// Drift class at the time the fence was issued.
    pub drift_class_at_issue: DriftClass,
}

impl FreshnessFenceRecord {
    /// Create a new freshness fence.
    pub fn new(
        fence_id: u64,
        authority_domain_ref: String,
        frontier: FenceFrontier,
        fence_class: FenceClass,
        lag_window_ns: u64,
        timing: FenceTiming,
        drift_class_at_issue: DriftClass,
    ) -> Self {
        FreshnessFenceRecord {
            fence_id,
            authority_domain_ref,
            fence_frontier_epoch: frontier.epoch,
            fence_frontier_wall_ns: frontier.wall_ns,
            fence_class,
            lag_window_ns,
            issue_time_ns: timing.issue_time_ns,
            expiry_time_ns: timing
                .issue_time_ns
                .saturating_add(timing.max_drift_window_ns),
            drift_class_at_issue,
        }
    }
    pub fn is_expired(&self, current_ns: u64) -> bool {
        current_ns >= self.expiry_time_ns
    }
}

/// An epoch timing attestation (P8-04 Section 5).
///
/// Binds a membership config epoch transition to a timing attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTimingAttestation {
    /// The epoch being attested.
    pub epoch_id: u64,
    /// References to clock sources used for the attestation.
    pub clock_source_refs: Vec<ClockClass>,
    /// Drift class at the time of epoch transition.
    pub drift_bound_at_transition: DriftClass,
    /// Previous epoch ID (None for initial epoch).
    pub previous_epoch_ref: Option<u64>,
    /// The freshness fence that was satisfied for this transition.
    pub transition_fence_ref: u64,
    /// HLC value at the time of attestation.
    pub hlc_at_attestation: HlcValue,
    /// Time of attestation (boottime nanoseconds).
    pub attested_at_ns: u64,
    /// Whether the attestation is valid (transition may proceed).
    pub is_valid: bool,
}

impl EpochTimingAttestation {
    /// Create a new epoch timing attestation.
    pub fn new(
        epoch_id: u64,
        clock_source_refs: Vec<ClockClass>,
        drift_bound_at_transition: DriftClass,
        previous_epoch_ref: Option<u64>,
        transition_fence_ref: u64,
        hlc_at_attestation: HlcValue,
        attested_at_ns: u64,
    ) -> Self {
        let is_valid = drift_bound_at_transition.allows_authority_movement();
        EpochTimingAttestation {
            epoch_id,
            clock_source_refs,
            drift_bound_at_transition,
            previous_epoch_ref,
            transition_fence_ref,
            hlc_at_attestation,
            attested_at_ns,
            is_valid,
        }
    }

    /// Whether this attestation permits the epoch transition to proceed.
    pub fn permits_transition(&self) -> bool {
        self.is_valid
    }
}

/// Clock source quorum for resynchronization receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceQuorum {
    /// Number of clock sources that confirmed recovery.
    pub confirmed: u32,
    /// Total number of clock sources considered.
    pub total: u32,
}

impl SourceQuorum {
    pub const fn new(confirmed: u32, total: u32) -> Self {
        Self { confirmed, total }
    }
}

/// A clock resynchronization receipt (P8-04 Section 7).
///
/// Produced when drift recovers after a period of exceeded drift.
/// Recovery requires a majority of clock sources to confirm health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockResynchronizationReceipt {
    /// Monotonic receipt identifier.
    pub receipt_id: u64,
    /// The node that produced this receipt.
    pub node_ref: String,
    /// Number of clock sources that confirmed recovery.
    pub confirmed_sources: u32,
    /// Total number of clock sources considered.
    pub total_sources: u32,
    /// Previous drift class before recovery.
    pub previous_drift_class: DriftClass,
    /// New drift class after recovery.
    pub new_drift_class: DriftClass,
    /// HLC value at time of resynchronization.
    pub hlc_at_resync: HlcValue,
    /// Time of resynchronization (boottime nanoseconds).
    pub resync_time_ns: u64,
}

impl ClockResynchronizationReceipt {
    /// Create a new resynchronization receipt.
    pub fn new(
        receipt_id: u64,

        node_ref: String,

        sources: SourceQuorum,

        previous_drift_class: DriftClass,

        new_drift_class: DriftClass,

        hlc_at_resync: HlcValue,

        resync_time_ns: u64,
    ) -> Self {
        ClockResynchronizationReceipt {
            receipt_id,

            node_ref,

            confirmed_sources: sources.confirmed,

            total_sources: sources.total,

            previous_drift_class,

            new_drift_class,

            hlc_at_resync,

            resync_time_ns,
        }
    }

    /// Whether this receipt represents a successful recovery (majority confirmed).
    pub fn is_majority_recovery(&self) -> bool {
        self.confirmed_sources * 2 > self.total_sources
    }
}
