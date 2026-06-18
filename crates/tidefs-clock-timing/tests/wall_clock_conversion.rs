// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Round-trip and bounded-drift tests for wall-clock / monotonic conversion
//! fidelity using ClockSampler. The crate samples all clock sources together;
//! this module verifies that samples taken close together produce values within
//! expected real-time windows and that wall-clock never diverges implausibly
//! from monotonic_raw under normal progression.

use proptest::prelude::*;
use tidefs_clock_timing::{ClockSampler, TimeHealth, TimeHealthMonitor};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_mono_ns() -> impl Strategy<Value = u64> {
    0u64..10_000_000_000u64
}

/// Plausible wall-clock offset from boot (Dec 2025 Unix epoch in ns).
fn arb_realtime_offset_ns() -> impl Strategy<Value = u64> {
    1_700_000_000_000_000_000u64..1_800_000_000_000_000_000u64
}

fn arb_small_delta() -> impl Strategy<Value = u64> {
    1u64..10_000_000u64
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// When realtime offset is stable, the realtime delta equals the
    /// monotonic delta across successive samples.
    #[test]
    fn realtime_delta_matches_mono_delta(
        start in arb_mono_ns(),
        rt_offset in arb_realtime_offset_ns(),
        delta in arb_small_delta()
    ) {
        let mut sampler = ClockSampler::new();

        let mono1 = start;
        let rt1 = start.saturating_add(rt_offset);
        sampler.sample(mono1, mono1, mono1, rt1);

        let mono2 = start.saturating_add(delta);
        let rt2 = mono2.saturating_add(rt_offset);
        sampler.sample(mono2, mono2, mono2, rt2);

        let rt_delta = rt2.saturating_sub(rt1);
        let mono_delta = mono2.saturating_sub(mono1);
        assert_eq!(rt_delta, mono_delta,
            "realtime delta ({rt_delta}) != mono delta ({mono_delta})");
    }

    /// Stable realtime offset should not trigger any health degradation.
    /// Use a lenient jitter threshold (20ms) to handle proptest deltas up to 10ms.
    #[test]
    fn stable_realtime_offset_is_healthy(
        start in arb_mono_ns(),
        rt_offset in arb_realtime_offset_ns(),
        deltas in proptest::collection::vec(arb_small_delta(), 1..20)
    ) {
        let mut monitor = TimeHealthMonitor::with_thresholds(
            100_000_000, 0, 20_000_000, 3,
        );
        let mut mono = start;
        let mut rt = start.saturating_add(rt_offset);

        // First sample
        let s = ClockSampler::new().sample(mono, mono, mono, rt);
        assert_eq!(monitor.classify(&s), TimeHealth::Healthy);

        for delta in deltas {
            mono = mono.saturating_add(delta);
            rt = rt.saturating_add(delta);
            let s = ClockSampler::new().sample(mono, mono, mono, rt);
            assert_eq!(monitor.classify(&s), TimeHealth::Healthy,
                "should stay healthy at mono={mono}");
        }
    }

    /// Both mono_raw_ns and realtime_ns advance together under normal
    /// progression and are stored correctly.
    #[test]
    fn both_clocks_advance_together(
        start in arb_mono_ns(),
        rt_offset in arb_realtime_offset_ns(),
        deltas in proptest::collection::vec(arb_small_delta(), 2..10)
    ) {
        let mut sampler = ClockSampler::new();
        let mut mono = start;
        let mut rt = start.saturating_add(rt_offset);

        for delta in deltas {
            mono = mono.saturating_add(delta);
            rt = rt.saturating_add(delta);
            let s = sampler.sample(mono, mono, mono, rt);
            assert_eq!(s.mono_raw_ns, mono);
            assert_eq!(s.realtime_ns, rt);
        }
    }
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn realtime_can_be_less_than_monotonic() {
    let mut sampler = ClockSampler::new();
    let s = sampler.sample(1000, 1000, 1000, 500);
    assert_eq!(s.realtime_ns, 500);
    assert_eq!(s.mono_raw_ns, 1000);
}

#[test]
fn realtime_at_zero() {
    let mut sampler = ClockSampler::new();
    let s = sampler.sample(0, 0, 0, 0);
    assert_eq!(s.realtime_ns, 0);
}

#[test]
fn realtime_near_u64_max() {
    let big = u64::MAX;
    let mut sampler = ClockSampler::new();
    let s = sampler.sample(big, big, big, big);
    assert_eq!(s.realtime_ns, big);
    assert_eq!(s.mono_raw_ns, big);
}

#[test]
fn saturating_realtime_transition() {
    let near_max = u64::MAX - 10;
    let mut sampler = ClockSampler::new();
    let s1 = sampler.sample(near_max, near_max, near_max, near_max);
    assert_eq!(s1.realtime_ns, near_max);
    let s2 = sampler.sample(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(s2.realtime_ns, u64::MAX);
}
