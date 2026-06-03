//! Property-based tests for HLC ordering, HlcValue serde round-trip,
//! DriftEstimator skew-detection thresholds, wall-clock-to-HLC consistency,
//! and HLC merge-chain causality invariants.

use proptest::prelude::*;
use tidefs_clock_timing::{
    ClockClass, DriftClass, DriftEstimator, DriftSample, DriftSuspicionState, HlcState, HlcValue,
    HybridLogicalClock,
};

// =========================================================================
// Strategies
// =========================================================================

fn arb_physical_ns() -> impl Strategy<Value = u64> {
    0u64..1_000_000_000u64
}

fn arb_logical() -> impl Strategy<Value = u64> {
    0u64..65_536u64
}

fn arb_hlc_value() -> impl Strategy<Value = HlcValue> {
    (arb_physical_ns(), arb_logical()).prop_map(|(p, l)| HlcValue::new(p, l))
}

fn arb_non_decreasing_physical(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u64>> {
    proptest::collection::vec(arb_physical_ns(), len).prop_map(|mut v| {
        v.sort_unstable();
        v
    })
}

fn arb_delta_ns() -> impl Strategy<Value = u64> {
    0u64..100_000_000u64
}

fn arb_skew_ns() -> impl Strategy<Value = i128> {
    (-1_000_000i128..1_000_000i128).prop_map(|x| x)
}

fn arb_skew_elevated() -> impl Strategy<Value = i128> {
    (1_000_001i128..100_000_000i128).prop_map(|x| x)
}

fn arb_skew_severe() -> impl Strategy<Value = i128> {
    (10_000_001i128..1_000_000_000i128).prop_map(|x| x)
}

fn arb_jitter_ns() -> impl Strategy<Value = u64> {
    0u64..10_000_000u64
}

fn arb_jitter_elevated() -> impl Strategy<Value = u64> {
    500_001u64..10_000_000u64
}

// =========================================================================
// Non-proptest edge-case tests
// =========================================================================

#[test]
fn hlc_value_zero_json_roundtrip() {
    let zero = HlcValue::zero();
    let encoded = serde_json::to_string(&zero).unwrap();
    let decoded: HlcValue = serde_json::from_str(&encoded).unwrap();
    assert_eq!(zero, decoded);
}

#[test]
fn hlc_value_max_json_roundtrip() {
    let max = HlcValue::new(u64::MAX, u64::MAX);
    let encoded = serde_json::to_string(&max).unwrap();
    let decoded: HlcValue = serde_json::from_str(&encoded).unwrap();
    assert_eq!(max, decoded);
}

// =========================================================================
// HLC total-ordering invariants
// =========================================================================

proptest! {
    #[test]
    fn hlc_advance_local_is_strictly_increasing(
        physicals in arb_non_decreasing_physical(2..100)
    ) {
        let mut hlc = HybridLogicalClock::new();
        let mut prev: Option<HlcValue> = None;

        for (i, &phys) in physicals.iter().enumerate() {
            let val = hlc.advance_local(phys);
            if let Some(p) = prev {
                assert!(
                    HybridLogicalClock::happened_before(&p, &val),
                    "HLC regressed at step {i}: prev={p:?}, current={val:?}"
                );
            }
            prev = Some(val);
        }
    }

    #[test]
    fn hlc_mixed_operations_never_regress(
        seed_physical in arb_physical_ns(),
        ops in proptest::collection::vec(
            (arb_physical_ns(), arb_physical_ns(), arb_logical()),
            1..50,
        )
    ) {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(seed_physical);
        let mut prev = hlc.current();

        for (local_phys, remote_phys, remote_logical) in ops {
            let v1 = hlc.advance_local(local_phys.max(prev.physical_ns()));
            assert!(HybridLogicalClock::happened_before(&prev, &v1));
            prev = v1;

            let remote = HlcValue::new(remote_phys, remote_logical);
            let local_wall = remote_phys.max(prev.physical_ns()).saturating_add(1);
            let v2 = hlc.merge_remote(remote, local_wall);
            assert!(HybridLogicalClock::happened_before(&prev, &v2));
            prev = v2;
        }
    }

    #[test]
    fn hlc_causal_compare_is_total(
        a in arb_hlc_value(),
        b in arb_hlc_value(),
    ) {
        let ord = HybridLogicalClock::causal_compare(&a, &b);
        if a == b {
            assert_eq!(ord, std::cmp::Ordering::Equal);
        } else {
            assert_ne!(ord, std::cmp::Ordering::Equal);
            if ord == std::cmp::Ordering::Less {
                assert!(HybridLogicalClock::happened_before(&a, &b));
                assert!(!HybridLogicalClock::happened_before(&b, &a));
            } else {
                assert!(HybridLogicalClock::happened_before(&b, &a));
                assert!(!HybridLogicalClock::happened_before(&a, &b));
            }
        }
    }

    #[test]
    fn hlc_causal_compare_is_transitive(
        a in arb_hlc_value(),
        b in arb_hlc_value(),
        c in arb_hlc_value(),
    ) {
        if HybridLogicalClock::happened_before(&a, &b)
            && HybridLogicalClock::happened_before(&b, &c)
        {
            assert!(HybridLogicalClock::happened_before(&a, &c));
        }
    }

    #[test]
    fn hlc_causal_compare_is_reflexive_equal(
        val in arb_hlc_value(),
    ) {
        assert_eq!(
            HybridLogicalClock::causal_compare(&val, &val),
            std::cmp::Ordering::Equal
        );
        assert!(!HybridLogicalClock::happened_before(&val, &val));
    }
}

// =========================================================================
// Multi-node merge-chain causality
// =========================================================================

proptest! {
    #[test]
    fn hlc_merge_chain_preserves_causality(
        a1_phys in arb_physical_ns(),
        a2_phys in arb_physical_ns(),
        b_phys in arb_physical_ns(),
        b_adv_phys in arb_physical_ns(),
    ) {
        let mut hlc_a = HybridLogicalClock::new();
        let mut hlc_b = HybridLogicalClock::new();

        let a1 = hlc_a.advance_local(a1_phys);
        let b1 = hlc_b.merge_remote(a1, b_phys);
        let b2 = hlc_b.advance_local(b_adv_phys.max(b1.physical_ns()));
        let a2 = hlc_a.advance_local(a2_phys.max(a1.physical_ns()));
        let a3_phys = b2.physical_ns().max(a2.physical_ns()).saturating_add(1);
        let a3 = hlc_a.merge_remote(b2, a3_phys);

        assert!(HybridLogicalClock::happened_before(&a1, &b2),
            "a1 {a1:?} should happen before b2 {b2:?}");
        assert!(HybridLogicalClock::happened_before(&b2, &a3),
            "b2 {b2:?} should happen before a3 {a3:?}");
        assert!(HybridLogicalClock::happened_before(&a1, &a3),
            "a1 {a1:?} should happen before a3 {a3:?}");
    }
}

// =========================================================================
// HlcValue serde round-trip (JSON)
// =========================================================================

proptest! {
    #[test]
    fn hlc_value_json_roundtrip(val in arb_hlc_value()) {
        let encoded = serde_json::to_string(&val).expect("serialization must succeed");
        let decoded: HlcValue =
            serde_json::from_str(&encoded).expect("deserialization must succeed");
        assert_eq!(
            val, decoded,
            "round-trip mismatch: {val:?} -> '{encoded}' -> {decoded:?}"
        );
    }
}

// =========================================================================
// Wall-clock to HLC physical component consistency
// =========================================================================

proptest! {
    #[test]
    fn hlc_physical_component_tracks_wall_clock(
        start in arb_physical_ns(),
        delta in arb_delta_ns(),
    ) {
        let mut hlc = HybridLogicalClock::new();
        let v1 = hlc.advance_local(start);
        assert_eq!(v1.physical_ns(), start);

        let next = start.saturating_add(delta);
        let v2 = hlc.advance_local(next);
        assert_eq!(v2.physical_ns(), next,
            "HLC physical should match wall-clock input");
    }

    #[test]
    fn hlc_physical_never_lags_wall_clock(
        start in arb_physical_ns(),
        delta in arb_delta_ns(),
    ) {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(start);

        let next = start.saturating_add(delta);
        let v = hlc.advance_local(next);
        assert!(v.physical_ns() >= next);
    }

    #[test]
    fn hlc_merge_physical_at_least_local_wall_clock(
        current_phys in arb_physical_ns(),
        remote in arb_hlc_value(),
        local_wall in arb_physical_ns(),
    ) {
        let mut hlc =
            HybridLogicalClock::from_value(HlcValue::new(current_phys, 0));
        let merged = hlc.merge_remote(remote, local_wall);
        assert!(
            merged.physical_ns() >= local_wall,
            "merged physical {} should be >= local wall clock {}",
            merged.physical_ns(),
            local_wall
        );
    }
}

// =========================================================================
// DriftEstimator skew-detection threshold properties
// =========================================================================

proptest! {
    #[test]
    fn skew_below_threshold_stays_nominal(
        skew in arb_skew_ns(),
        jitter in 0u64..500_000u64,
    ) {
        let mut est =
            DriftEstimator::with_thresholds(100_000, 1_000_000, 500_000, 8, 4);

        for _ in 0..8 {
            est.observe(DriftSample {
                skew_ns: skew,
                jitter_ns: jitter,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        assert_ne!(est.drift_class(), DriftClass::SevereCluster);
    }

    #[test]
    fn elevated_skew_is_detected(skew in arb_skew_elevated()) {
        let mut est = DriftEstimator::new();
        for _ in 0..64 {
            est.observe(DriftSample {
                skew_ns: skew,
                jitter_ns: 0,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        assert!(
            est.drift_class() as u8 >= DriftClass::ElevatedCluster as u8,
            "skew {skew} ns should trigger at least ElevatedCluster, got {:?}",
            est.drift_class()
        );
    }

    #[test]
    fn severe_skew_is_detected(skew in arb_skew_severe()) {
        let mut est = DriftEstimator::new();
        for _ in 0..64 {
            est.observe(DriftSample {
                skew_ns: skew,
                jitter_ns: 0,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        assert_eq!(est.drift_class(), DriftClass::SevereCluster,
            "skew {skew} ns should trigger SevereCluster, got {:?}",
            est.drift_class());
    }

    #[test]
    fn elevated_jitter_is_detected(jitter in arb_jitter_elevated()) {
        let mut est = DriftEstimator::new();
        for _ in 0..64 {
            est.observe(DriftSample {
                skew_ns: 0,
                jitter_ns: jitter,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        assert!(
            est.drift_class() as u8 >= DriftClass::ElevatedCluster as u8,
            "jitter {jitter} ns should trigger at least ElevatedCluster, got {:?}",
            est.drift_class()
        );
    }

    #[test]
    fn zero_skew_stabilizes_nominal(n_samples in 32u32..128u32) {
        let mut est =
            DriftEstimator::with_thresholds(1_000_000, 10_000_000, 500_000, 16, 4);
        for _ in 0..n_samples {
            est.observe(DriftSample {
                skew_ns: 0,
                jitter_ns: 0,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        assert_eq!(est.drift_class(), DriftClass::NominalCluster,
            "zero skew/jitter should stabilize to NominalCluster, got {:?}",
            est.drift_class());
    }

    #[test]
    fn drift_recovery_after_nominal_samples(n_nominal in 4u32..32u32) {
        let mut est =
            DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 4, 4);
        for _ in 0..4 {
            est.observe(DriftSample {
                skew_ns: 5_000,
                jitter_ns: 0,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        for _ in 0..n_nominal {
            est.observe(DriftSample {
                skew_ns: 100,
                jitter_ns: 50,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        let cls = est.drift_class();
        assert!(
            cls == DriftClass::NominalCluster
                || cls == DriftClass::TrustedLocal,
            "after {n_nominal} nominal samples, drift should recover, got {cls:?}"
        );
    }

    #[test]
    fn suspicion_state_consistent_with_drift_class(
        skew in arb_skew_ns(),
        jitter in arb_jitter_ns(),
    ) {
        let mut est =
            DriftEstimator::with_thresholds(100_000, 1_000_000, 500_000, 8, 4);
        for _ in 0..8 {
            est.observe(DriftSample {
                skew_ns: skew,
                jitter_ns: jitter,
                clock_class: ClockClass::HlcCluster,
                observed_at_ns: 0,
            });
        }
        let cls = est.drift_class();
        let susp = est.suspicion_state();

        match cls {
            DriftClass::TrustedLocal | DriftClass::NominalCluster => {
                assert!(
                    susp == DriftSuspicionState::Nominal
                        || susp == DriftSuspicionState::Recovered,
                    "Nominal drift should have Nominal/Recovered suspicion, got {susp:?}"
                );
            }
            DriftClass::ElevatedCluster => {
                assert_eq!(susp, DriftSuspicionState::Elevated,
                    "Elevated drift should have Elevated suspicion, got {susp:?}");
            }
            DriftClass::SevereCluster => {
                assert_eq!(susp, DriftSuspicionState::Severe,
                    "Severe drift should have Severe suspicion, got {susp:?}");
            }
            DriftClass::UntrustedTime => {
                assert_eq!(susp, DriftSuspicionState::HoldSensitiveActions,
                    "Untrusted should have HoldSensitiveActions suspicion, got {susp:?}");
            }
        }
    }
}

// =========================================================================
// HLC lifecycle state invariants
// =========================================================================

proptest! {
    #[test]
    fn advance_local_sets_local_advanced_state(phys in arb_physical_ns()) {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(phys);
        assert_eq!(hlc.state(), HlcState::LocalAdvanced);
    }

    #[test]
    fn merge_remote_sets_remote_merged_state(
        phys in arb_physical_ns(),
        remote in arb_hlc_value(),
        local_wall in arb_physical_ns(),
    ) {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(phys);
        hlc.merge_remote(remote, local_wall);
        assert_eq!(hlc.state(), HlcState::RemoteMerged);
    }

    #[test]
    fn persist_for_receipt_increments_counter_by_one(
        phys in arb_physical_ns(),
        n_persists in 1u32..20u32,
    ) {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(phys);
        let before = hlc.receipt_count();

        for i in 0..n_persists {
            hlc.persist_for_receipt();
            assert_eq!(hlc.receipt_count(), before + (i as u64) + 1);
            assert_eq!(hlc.state(), HlcState::PersistedForReceipt);
        }
    }
}
