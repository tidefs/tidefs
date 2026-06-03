#![cfg_attr(not(test), no_std)]
//! tidefs-clock-timing: HLC, clock health, drift estimation, lease/fence deadlines, freshness fences, epoch timing attestation, and timeout
//! escalation (P8-04).
//!
//! # Design rule
//!
//! Authority ordering is receipt/epoch/anchor-based; time only gates waiting,
//! liveness, escalation, and narrative rendering.
//!
//! # Clock classes (P8-04 Section 2)
//!
//! Seven canonical clock classes are defined:
//!
//! - `MonoRawLocal` (`time_clock_0`) — local elapsed-time, no wall-clock semantics
//! - `MonoServiceLocal` (`time_clock_1`) — local service deadlines
//! - `BoottimeLocal` (`time_clock_2`) — suspend-aware deadlines
//! - `RealtimeNarrative` (`time_clock_3`) — operator timestamps only (NOT authoritative)
//! - `HlcCluster` (`time_clock_4`) — hybrid logical time, cross-node causal ordering
//! - `FenceDeadline` (`time_clock_5`) — derived freshness-fence deadlines
//! - `LeaseDeadline` (`time_clock_6`) — derived lease-expiry deadlines
//!
//! # Drift classes (P8-04 Section 3)
//!
//! Five canonical drift/trust classes from `TrustedLocal` through `UntrustedTime`.
//! Drift classes control deadline slack, admission of sensitive actions, and
//! failover eligibility.
//!
//! # Freshness fences (P8-04 Section 4)
//!
//! `FreshnessFenceRecord` declares a freshness barrier: source data must be at
//! or ahead of the fence frontier. Fence classes (`Strict`, `Bounded`, `Soft`)
//! control what happens when a source is behind. Evaluation produces a
//! `FreshnessVerdict`.
//!
//! # Runtime components (P8-04 Section 4)
//!
//! - `ClockSampler` / `TimeHealthMonitor` — sample and classify local clock health
//! - `HybridLogicalClock` — maintain HLC for causal cross-node ordering
//! - `LeaseDeadline` / `FenceDeadline` — track lease and fence expirations
//! - `DriftEstimator` — estimate cluster drift from observations
//! - `TimeoutEscalator` — convert deadline misses into policy actions
//!
//! ```no_run
//! use tidefs_clock_timing::{
//!     HybridLogicalClock, TimeHealthMonitor, DriftEstimator, LeaseDeadline,
//!     DriftClass, ClockClass, FenceClass, FenceFrontier, FenceTiming,
//!     FreshnessFenceRecord, evaluate_freshness_against_fence,
//!     ClockSourceSample, DriftSample,
//! };
//!
//! // HLC: advance on local events
//! let mut hlc = HybridLogicalClock::new();
//! let ts = hlc.advance_local(100_000_000);
//!
//! // Freshness fence: gate reads on epoch/wall-clock frontier
//! let frontier = FenceFrontier::new(10, 1_000_000_000);
//! let timing = FenceTiming { issue_time_ns: 500_000_000, max_drift_window_ns: 10_000_000_000 };
//! let fence = FreshnessFenceRecord::new(
//!     1, "domain_a".into(), frontier, FenceClass::Strict, 0, timing,
//!     DriftClass::NominalCluster,
//! );
//! let verdict = evaluate_freshness_against_fence(
//!     15, 1_500_000_000, &fence, 1_000_000_000, DriftClass::TrustedLocal,
//! );
//! assert!(verdict.permits_operation());
//! ```

#![forbid(unsafe_code)]

extern crate alloc;

pub mod deadline;
pub mod drift;
pub mod escalation;
pub mod fence;
pub mod health;
pub mod hlc;
pub mod types;

// Re-exports for convenient access.
pub use types::{
    ClockClass, ClockResynchronizationReceipt, ClockSourceSample, DeadlineEscalationReceipt,
    DerivedDeadline, DriftClass, DriftSuspicionState, EpochTimingAttestation, EscalationAction,
    FenceClass, FenceDeadlineRecord, FenceDeadlineState, FenceFrontier, FenceTiming,
    FindingSeverity, FreshnessFenceRecord, FreshnessVerdict, HeartbeatEpochRecord, HlcState,
    HlcValue, LeaseDeadlineRecord, LeaseDeadlineState, SourceQuorum, TimeHealth, TimeHealthFinding,
};

pub use hlc::HybridLogicalClock;

pub use health::{ClockSampler, TimeHealthMonitor};

pub use drift::{DriftEstimator, DriftSample};

pub use deadline::{FenceDeadline, LeaseDeadline};

pub use escalation::TimeoutEscalator;

pub use fence::{
    attest_epoch_timing_and_bind_to_config_epoch, detect_drift_exceeded_and_trigger_safety_actions,
    evaluate_freshness_against_fence, evaluate_transfer_ticket_freshness, DriftSafetyResult,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexports_clock_class_variants() {
        assert!(ClockClass::HlcCluster.is_authoritative());
        assert!(!ClockClass::RealtimeNarrative.is_authoritative());
    }

    #[test]
    fn reexports_drift_class_methods() {
        assert!(DriftClass::NominalCluster.allows_authority_movement());
        assert!(!DriftClass::SevereCluster.allows_authority_movement());
    }

    #[test]
    fn reexports_fence_class_methods() {
        assert!(FenceClass::Strict.blocks_stale_reads());
        assert!(FenceClass::Bounded.permits_degraded());
    }

    #[test]
    fn reexports_hlc_value_construct_and_getters() {
        let v = HlcValue::new(100, 5);
        assert_eq!(v.physical_ns(), 100);
        assert_eq!(v.logical(), 5);
    }

    #[test]
    fn reexports_hybrid_logical_clock_basic() {
        let hlc = HybridLogicalClock::new();
        assert_eq!(hlc.current(), HlcValue::zero());
        assert_eq!(hlc.receipt_count(), 0);
    }

    #[test]
    fn reexports_clock_sampler_initial_state() {
        let sampler = ClockSampler::new();
        assert_eq!(sampler.sample_count(), 0);
        assert!(sampler.last_sample().is_none());
    }

    #[test]
    fn reexports_time_health_monitor_classify() {
        let mut monitor = TimeHealthMonitor::new();
        let sample = ClockSampler::new().sample(100, 100, 100, 100);
        assert_eq!(monitor.classify(&sample), TimeHealth::Healthy);
    }

    #[test]
    fn reexports_drift_estimator_initial_state() {
        let est = DriftEstimator::new();
        assert_eq!(est.drift_class(), DriftClass::TrustedLocal);
    }

    #[test]
    fn reexports_fence_deadline_issue_basic() {
        let fence = FenceDeadline::issue(1, 1000, 500, 200, DriftClass::TrustedLocal);
        let rec = fence.record();
        assert_eq!(rec.fence_deadline_id, 1);
        assert_eq!(rec.state, FenceDeadlineState::Issued);
    }

    #[test]
    fn reexports_lease_deadline_open_basic() {
        let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
        let rec = lease.record();
        assert_eq!(rec.lease_deadline_id, 1);
        assert_eq!(rec.state, LeaseDeadlineState::Open);
    }

    #[test]
    fn reexports_timeout_escalator_new() {
        let esc = TimeoutEscalator::new(DriftClass::TrustedLocal);
        assert_eq!(esc.receipt_count(), 0);
    }

    #[test]
    fn reexports_evaluate_freshness_smoke() {
        let frontier = FenceFrontier::new(10, 1000);
        let timing = FenceTiming {
            issue_time_ns: 500,
            max_drift_window_ns: 10_000,
        };
        let fence = FreshnessFenceRecord::new(
            1,
            "test".into(),
            frontier,
            FenceClass::Strict,
            0,
            timing,
            DriftClass::NominalCluster,
        );
        let verdict =
            evaluate_freshness_against_fence(15, 1500, &fence, 1000, DriftClass::TrustedLocal);
        assert!(verdict.permits_operation());
    }

    #[test]
    fn reexports_detect_drift_extreme() {
        let result = detect_drift_exceeded_and_trigger_safety_actions(
            DriftClass::UntrustedTime,
            DriftSuspicionState::Severe,
            "test-node",
            HlcValue::new(100, 0),
            5000,
        );
        assert!(result.hold_sensitive_actions);
        assert!(result.block_new_transfers && result.block_epoch_transitions);
    }

    #[test]
    fn reexports_attest_epoch_timing_smoke() {
        let frontier = FenceFrontier::new(5, 500);
        let timing = FenceTiming {
            issue_time_ns: 0,
            max_drift_window_ns: 10_000,
        };
        let fence = FreshnessFenceRecord::new(
            10,
            "epoch-test".into(),
            frontier,
            FenceClass::Strict,
            0,
            timing,
            DriftClass::NominalCluster,
        );
        let result = attest_epoch_timing_and_bind_to_config_epoch(
            5,
            Some(4),
            &fence,
            vec![ClockClass::HlcCluster],
            DriftClass::NominalCluster,
            HlcValue::new(200, 0),
            1000,
        );
        assert!(result.permits_transition());
    }
}
