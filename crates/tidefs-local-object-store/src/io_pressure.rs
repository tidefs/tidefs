//! Foreground I/O pressure probe for background operation throttling.
//!
//! [`IoPressureProbe`] provides a simple, Send+Sync callable that
//! returns a normalized foreground pressure value (0.0 = no pressure,
//! 1.0 = maximum pressure). Background operations such as rebuild,
//! scrub, and backfill query the probe and yield proportionally so
//! foreground latency budgets are not violated.
//!
//! # Integration
//!
//! Transport-layer backpressure (e.g. [`SendCapacity`] for the Data
//! lane) can be wrapped as an `IoPressureProbe` so that rebuild
//! throughput backs off when foreground client I/O is congested.
//!
//! # Design
//!
//! The probe is intentionally minimal: a single `f64` in [0, 1]
//! with no back-channel, no histogram, and no async dependency.
//! Higher-level crates own the signal source (transport lane depth,
//! I/O scheduler queue length, CPU pressure, etc.) and feed it
//! into the probe.

use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// IoPressureProbe
// ---------------------------------------------------------------------------

/// A queryable source of foreground I/O pressure.
///
/// Background operations (rebuild, scrub, backfill) call
/// [`pressure`](Self::pressure) to decide whether to yield or slow
/// down. A value of 0.0 means no pressure; 1.0 means the foreground
/// is saturated and background operations should back off maximally.
#[derive(Clone)]
pub struct IoPressureProbe {
    inner: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl IoPressureProbe {
    /// Create a probe from a closure.
    ///
    /// The closure must be `Send + Sync + 'static` so the probe can
    /// be shared across threads and held for the lifetime of a
    /// background operation.
    pub fn new(f: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        Self { inner: Arc::new(f) }
    }

    /// A probe that always reports zero pressure (no throttling).
    #[must_use]
    pub fn none() -> Self {
        Self::new(|| 0.0)
    }

    /// A probe that always reports maximum pressure (background always
    /// yields). Useful for testing and for emergency operator-controlled
    /// rebuild suspension.
    #[must_use]
    pub fn max() -> Self {
        Self::new(|| 1.0)
    }

    /// Query the current foreground pressure (0.0–1.0).
    ///
    /// The returned value is clamped to [0.0, 1.0] by the probe
    /// implementation; callers may assume the range.
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let raw = (self.inner)();
        raw.clamp(0.0, 1.0)
    }

    /// Convenience: compute a yield duration proportional to the
    /// current pressure.
    ///
    /// Returns `Some(duration)` when pressure > 0, with longer
    /// durations for higher pressure. Returns `None` when pressure
    /// is at 0 (no yield needed).
    ///
    /// `max_yield` is the longest yield to use at pressure = 1.0.
    #[must_use]
    pub fn yield_duration(&self, max_yield: Duration) -> Option<Duration> {
        let p = self.pressure();
        if p <= 0.0 {
            None
        } else {
            let ms = (max_yield.as_millis() as f64 * p) as u64;
            Some(Duration::from_millis(ms.max(1)))
        }
    }

    /// Check whether the rebuild should yield right now, and if so
    /// for how long.
    ///
    /// Internally calls [`yield_duration`] with a default max yield
    /// of 100 ms (tunable through the `max_yield` parameter on
    /// [`yield_duration`]).
    #[must_use]
    pub fn should_yield(&self, max_yield: Duration) -> Option<Duration> {
        self.yield_duration(max_yield)
    }
}

impl std::fmt::Debug for IoPressureProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoPressureProbe")
            .field("pressure", &self.pressure())
            .finish()
    }
}

impl Default for IoPressureProbe {
    fn default() -> Self {
        Self::none()
    }
}

// ---------------------------------------------------------------------------
// RebuildThrottleConfig
// ---------------------------------------------------------------------------

/// Configuration controlling how aggressively background rebuild
/// yields to foreground I/O.
#[derive(Clone, Debug)]
pub struct RebuildThrottleConfig {
    /// Maximum time the rebuild will yield per object when foreground
    /// pressure is at 1.0 (maximum).
    pub max_yield_per_object: Duration,
    /// Number of objects to copy between pressure probes.
    ///
    /// Checking every object can add overhead; batching reduces it
    /// at the cost of slightly coarser backpressure response.
    pub probe_interval_objects: usize,
}

impl Default for RebuildThrottleConfig {
    fn default() -> Self {
        Self {
            max_yield_per_object: Duration::from_millis(100),
            probe_interval_objects: 16,
        }
    }
}

impl RebuildThrottleConfig {
    /// A configuration that disables all throttling.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_yield_per_object: Duration::from_millis(0),
            probe_interval_objects: usize::MAX,
        }
    }

    /// Whether throttling is effectively disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.max_yield_per_object.is_zero() || self.probe_interval_objects == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn none_probe_always_zero() {
        let probe = IoPressureProbe::none();
        assert_eq!(probe.pressure(), 0.0);
        assert!(probe.yield_duration(Duration::from_millis(100)).is_none());
        assert!(probe.should_yield(Duration::from_millis(100)).is_none());
    }

    #[test]
    fn max_probe_always_one() {
        let probe = IoPressureProbe::max();
        assert_eq!(probe.pressure(), 1.0);
        let yd = probe.yield_duration(Duration::from_millis(100)).unwrap();
        assert_eq!(yd, Duration::from_millis(100));
    }

    #[test]
    fn dynamic_probe_returns_correct_value() {
        let counter = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&counter);
        let probe = IoPressureProbe::new(move || c.fetch_add(1, Ordering::SeqCst) as f64 / 10.0);

        assert!((probe.pressure() - 0.1).abs() < 0.001);
        assert!((probe.pressure() - 0.2).abs() < 0.001);
    }

    #[test]
    fn probe_clamps_out_of_range() {
        let probe = IoPressureProbe::new(|| 2.5);
        assert_eq!(probe.pressure(), 1.0);

        let probe2 = IoPressureProbe::new(|| -0.5);
        assert_eq!(probe2.pressure(), 0.0);
    }

    #[test]
    fn yield_duration_scales_linearly() {
        let probe = IoPressureProbe::new(|| 0.5);
        let yd = probe.yield_duration(Duration::from_millis(200)).unwrap();
        assert_eq!(yd, Duration::from_millis(100));
    }

    #[test]
    fn yield_duration_minimum_one_ms() {
        let probe = IoPressureProbe::new(|| 0.001);
        let yd = probe.yield_duration(Duration::from_millis(1000)).unwrap();
        assert_eq!(yd, Duration::from_millis(1));
    }

    #[test]
    fn throttle_config_default_is_enabled() {
        let cfg = RebuildThrottleConfig::default();
        assert!(!cfg.is_disabled());
        assert_eq!(cfg.max_yield_per_object, Duration::from_millis(100));
        assert_eq!(cfg.probe_interval_objects, 16);
    }

    #[test]
    fn throttle_config_disabled_is_disabled() {
        assert!(RebuildThrottleConfig::disabled().is_disabled());

        let cfg = RebuildThrottleConfig {
            max_yield_per_object: Duration::from_millis(0),
            probe_interval_objects: 16,
        };
        assert!(cfg.is_disabled());

        let cfg = RebuildThrottleConfig {
            max_yield_per_object: Duration::from_millis(100),
            probe_interval_objects: 0,
        };
        assert!(cfg.is_disabled());
    }

    #[test]
    fn probe_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IoPressureProbe>();
        assert_send_sync::<RebuildThrottleConfig>();
    }

    #[test]
    fn probe_debug_includes_pressure() {
        let probe = IoPressureProbe::new(|| 0.75);
        let dbg = format!("{probe:?}");
        assert!(dbg.contains("0.75"));
    }
}
