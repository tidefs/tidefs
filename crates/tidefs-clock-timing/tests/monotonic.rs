// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Property-based tests for monotonic clock advancement (ClockSampler +
//! TimeHealthMonitor). Verifies the monotonic clock never goes backward, advances
//! by reasonable deltas under normal conditions, and detects step regressions.
//!
//! These are external integration tests — they exercise only the public API.

use proptest::prelude::*;
use tidefs_clock_timing::{ClockSampler, TimeHealth, TimeHealthMonitor};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// A plausible monotonic_raw timestamp (nanoseconds since boot).
/// 0..~10 seconds is a reasonable window for a typical test process.
fn arb_mono_ns() -> impl Strategy<Value = u64> {
    0u64..10_000_000_000u64
}

/// A vector of strictly increasing timestamps (sorted).
fn arb_increasing_values(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u64>> {
    proptest::collection::vec(arb_mono_ns(), len).prop_map(|mut v| {
        v.sort_unstable();
        v
    })
}

/// A normal forward delta: 1 ns to 10 ms (10,000,000 ns).
fn arb_small_delta() -> impl Strategy<Value = u64> {
    1u64..10_000_000u64
}

/// A backward jump: 1 ns to 1 s.
fn arb_backward_by() -> impl Strategy<Value = u64> {
    1u64..1_000_000_000u64
}

/// A forward jump large enough to trigger suspend/pause suspicion (above 100ms).
fn arb_suspend_jump() -> impl Strategy<Value = u64> {
    100_000_001u64..2_000_000_000u64
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Successive samples with strictly increasing mono_raw_ns never regress:
    /// each sample stores the input, sample count increments, and the last
    /// sample is always the most recent.
    #[test]
    fn sampler_always_returns_input_value(
        values in arb_increasing_values(2..10)
    ) {
        let mut sampler = ClockSampler::new();
        let mut prev: Option<u64> = None;

        for (i, &ns) in values.iter().enumerate() {
            let sample = sampler.sample(ns, ns, ns, ns);
            assert_eq!(sample.mono_raw_ns, ns,
                "sample[{i}]: expected input {ns}, got {}", sample.mono_raw_ns);
            assert_eq!(sampler.sample_count(), (i + 1) as u64);
            if let Some(p) = prev {
                assert!(ns >= p,
                    "mono_raw_ns regressed: {p} -> {ns}");
            }
            prev = Some(ns);
        }
    }

    /// Normal progression (small forward deltas) must never be flagged
    /// as unhealthy. Use a lenient jitter threshold to avoid false positives
    /// from proptest-generated deltas up to 10ms.
    #[test]
    fn normal_progression_stays_healthy(
        start in arb_mono_ns(),
        deltas in proptest::collection::vec(arb_small_delta(), 1..30)
    ) {
        let mut monitor = TimeHealthMonitor::with_thresholds(
            100_000_000, // 100ms max forward jump
            0,           // any backward jump
            20_000_000,  // 20ms jitter threshold (above max delta)
            3,           // recovery samples
        );
        let mut current = start;

        // First sample is always healthy.
        let s = ClockSampler::new().sample(current, current, current, current);
        assert_eq!(monitor.classify(&s), TimeHealth::Healthy);

        for delta in deltas {
            current = current.saturating_add(delta);
            let s = ClockSampler::new().sample(current, current, current, current);
            let health = monitor.classify(&s);
            assert!(health == TimeHealth::Healthy,
                "unexpected health {health:?} at mono_raw={current} (delta={delta})");
        }
    }

    /// Any backward jump (even 1 ns) must be classified as StepRegressed.
    #[test]
    fn backward_jump_is_step_regressed(
        start in arb_mono_ns(),
        backward_by in arb_backward_by()
    ) {
        let mut monitor = TimeHealthMonitor::new();
        let s1 = ClockSampler::new().sample(start, start, start, start);
        monitor.classify(&s1);

        let back = start.saturating_sub(backward_by);
        let s2 = ClockSampler::new().sample(back, back, back, back);
        assert_eq!(monitor.classify(&s2), TimeHealth::StepRegressed);
    }

    /// Forward jumps above the default 100ms threshold must be classified
    /// as SuspendOrPauseSuspect.
    #[test]
    fn large_forward_jump_is_suspend_suspect(
        start in arb_mono_ns(),
        jump_by in arb_suspend_jump()
    ) {
        let mut monitor = TimeHealthMonitor::new();
        let s1 = ClockSampler::new().sample(start, start, start, start);
        monitor.classify(&s1);

        let after = start.saturating_add(jump_by);
        let s2 = ClockSampler::new().sample(after, after, after, after);
        assert_eq!(monitor.classify(&s2), TimeHealth::SuspendOrPauseSuspect);
    }
}

// ---------------------------------------------------------------------------
// Edge-case tests (non-proptest)
// ---------------------------------------------------------------------------

#[test]
fn sampler_empty_before_first_sample() {
    let sampler = ClockSampler::new();
    assert!(
        sampler.last_sample().is_none(),
        "no sample should exist before first call"
    );
    assert_eq!(sampler.sample_count(), 0);
}

#[test]
fn sampler_stores_fields_independently() {
    let mut sampler = ClockSampler::new();
    let s = sampler.sample(100, 200, 300, 400);
    assert_eq!(s.mono_raw_ns, 100);
    assert_eq!(s.mono_service_ns, 200);
    assert_eq!(s.boottime_ns, 300);
    assert_eq!(s.realtime_ns, 400);
}

#[test]
fn zero_delta_is_healthy() {
    let mut monitor = TimeHealthMonitor::with_thresholds(100_000_000, 0, 1_000_000, 3);
    let s = ClockSampler::new().sample(5000, 5000, 5000, 5000);
    monitor.classify(&s);
    assert_eq!(
        monitor.classify(&s),
        TimeHealth::Healthy,
        "identical timestamps (delta=0) should stay healthy"
    );
}
