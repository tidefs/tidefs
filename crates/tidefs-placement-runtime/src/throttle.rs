// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bandwidth throttling for recovery and rebalance traffic.
//!
//! Recovery and rebalance transfers can saturate network links and degrade
//! client IO.  [`BandwidthThrottle`] uses a token-bucket algorithm to cap
//! aggregate transfer throughput.  It supports a dynamic mode that backs
//! off when client-IO latency rises, keeping headroom for foreground
//! operations.
//!
//! When `max_recovery_bandwidth_mbps` is 0 the throttle is unlimited:
//! every `consume` / `acquire` returns immediately with zero delay.

use std::time::{Duration, Instant};

// ── Bandwidth throttle configuration ──────────────────────────────────

/// Configuration for the recovery / rebalance bandwidth throttle.
#[derive(Debug, Clone, PartialEq)]
pub struct BandwidthThrottleConfig {
    /// Maximum recovery bandwidth in megabits per second.
    ///
    /// 0 disables throttling entirely (unlimited mode).
    pub max_recovery_bandwidth_mbps: u64,
    /// Maximum burst size the token bucket can accumulate (bytes).
    ///
    /// Defaults to 2 × per-second token capacity so short bursts are not
    /// suppressed unnecessarily.
    pub token_bucket_capacity_bytes: u64,
    /// Enable dynamic throttling that reduces recovery bandwidth when
    /// client-IO latency increases.
    pub dynamic_throttle_enabled: bool,
    /// Floor ratio applied when IO pressure is at maximum (1.0).
    ///
    /// E.g. 0.1 means recovery bandwidth never drops below 10% of
    /// `max_recovery_bandwidth_mbps`.
    pub min_throttle_ratio: f64,
}

impl Default for BandwidthThrottleConfig {
    fn default() -> Self {
        Self {
            max_recovery_bandwidth_mbps: 0, // unlimited
            token_bucket_capacity_bytes: 0, // computed at construction
            dynamic_throttle_enabled: false,
            min_throttle_ratio: 0.1,
        }
    }
}

impl BandwidthThrottleConfig {
    /// Create a config targeting a specific bandwidth limit.
    #[must_use]
    pub fn with_max_mbps(max_recovery_bandwidth_mbps: u64) -> Self {
        Self {
            max_recovery_bandwidth_mbps,
            ..Self::default()
        }
    }

    /// Enable dynamic throttling with the given floor ratio.
    #[must_use]
    pub fn with_dynamic(mut self, min_ratio: f64) -> Self {
        self.dynamic_throttle_enabled = true;
        self.min_throttle_ratio = min_ratio.clamp(0.0, 1.0);
        self
    }

    /// Bytes-per-second equivalent of `max_recovery_bandwidth_mbps`.
    #[must_use]
    pub fn max_bytes_per_sec(&self) -> u64 {
        if self.max_recovery_bandwidth_mbps == 0 {
            return u64::MAX;
        }
        // mbps to bytes/sec: multiply by 1_000_000 / 8 = 125_000
        self.max_recovery_bandwidth_mbps.saturating_mul(125_000)
    }
}

// ── IO pressure signal ────────────────────────────────────────────────

/// A normalised measurement of foreground client-IO pressure.
///
/// 0.0 = no pressure (recovery may use full bandwidth).
/// 1.0 = maximum pressure (recovery backs off to min_throttle_ratio).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IoPressure(pub f64);

impl IoPressure {
    pub const NONE: Self = Self(0.0);
    pub const MAX: Self = Self(1.0);

    /// Create from a raw value, clamping into [0.0, 1.0].
    #[must_use]
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.0
    }
}

impl Default for IoPressure {
    fn default() -> Self {
        Self::NONE
    }
}

// ── Throttle statistics ───────────────────────────────────────────────

/// Running statistics collected by the bandwidth throttle.
#[derive(Debug, Clone, Default)]
pub struct ThrottleStats {
    /// Current effective bandwidth in megabits per second.
    pub current_bandwidth_mbps: u64,
    /// Tokens currently available in the bucket.
    pub tokens_available: u64,
    /// Cumulative number of transfers that were throttled (delayed).
    pub throttled_transfers: u64,
    /// Cumulative delay in milliseconds imposed by the throttle.
    pub total_throttle_delay_ms: u64,
    /// Cumulative bytes consumed through the throttle.
    pub bytes_consumed: u64,
    /// Cumulative bytes that triggered a delay.
    pub bytes_throttled: u64,
    /// Total consume / try_consume calls.
    pub transfer_count: u64,
    /// Number of times the throttle was in unlimited mode (no-op).
    pub unlimited_count: u64,
}

impl ThrottleStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Average delay per throttled transfer, in milliseconds.
    #[must_use]
    pub fn avg_throttle_delay_ms(&self) -> f64 {
        if self.throttled_transfers == 0 {
            0.0
        } else {
            self.total_throttle_delay_ms as f64 / self.throttled_transfers as f64
        }
    }

    /// Fraction of transfers that were throttled.
    #[must_use]
    pub fn throttle_ratio(&self) -> f64 {
        if self.transfer_count == 0 {
            0.0
        } else {
            self.throttled_transfers as f64 / self.transfer_count as f64
        }
    }
}

// ── Bandwidth throttle ────────────────────────────────────────────────

/// Token-bucket bandwidth throttle for recovery and rebalance transfers.
///
/// On each try_consume(bytes), the bucket is refilled: tokens +=
/// elapsed * effective_rate. If tokens >= bytes, consume and return
/// Ok(0) (no delay). If tokens < bytes, compute the wait time needed
/// for enough tokens to accumulate and return Ok(wait). The caller
/// should sleep for that duration before retrying.
///
/// When max_recovery_bandwidth_mbps == 0, the throttle is unlimited
/// and always returns Ok(0).
///
/// When dynamic_throttle_enabled is true, the effective rate is reduced
/// linearly from max_bytes_per_sec down to min_throttle_ratio *
/// max_bytes_per_sec as io_pressure rises from 0.0 to 1.0.
#[derive(Debug)]
pub struct BandwidthThrottle {
    config: BandwidthThrottleConfig,
    /// Fractional tokens (bytes) - f64 avoids discretisation jitter.
    tokens: f64,
    /// Last instant at which tokens were refilled.
    last_refill: Instant,
    /// Current effective bandwidth in bytes per second, accounting
    /// for dynamic throttle reduction.
    effective_bytes_per_sec: f64,
    /// Current IO pressure level (0.0 = none, 1.0 = max).
    io_pressure: IoPressure,
    /// Accumulated statistics.
    stats: ThrottleStats,
}

impl BandwidthThrottle {
    /// Create a new throttle from the given config.
    #[must_use]
    pub fn new(config: BandwidthThrottleConfig) -> Self {
        let mut config = config;
        if config.token_bucket_capacity_bytes == 0 && config.max_recovery_bandwidth_mbps > 0 {
            config.token_bucket_capacity_bytes = config.max_bytes_per_sec().saturating_mul(2);
        }
        let effective = config.max_bytes_per_sec() as f64;
        let mut slf = Self {
            tokens: config.token_bucket_capacity_bytes as f64,
            last_refill: Instant::now(),
            effective_bytes_per_sec: effective,
            io_pressure: IoPressure::NONE,
            config,
            stats: ThrottleStats::new(),
        };
        slf.recalc_effective_rate();
        slf
    }

    // ── Public API ───────────────────────────────────────────────────

    /// Whether the throttle is in unlimited mode (no bandwidth cap).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.config.max_recovery_bandwidth_mbps == 0
    }

    /// Attempt to consume `bytes` from the token bucket.
    ///
    /// Returns Ok(0) if tokens are sufficient (transfer may proceed
    /// immediately) or Ok(wait_ms) with the number of milliseconds
    /// the caller should wait before retrying.
    pub fn try_consume(&mut self, bytes: u64) -> Result<u64, &'static str> {
        self.stats.transfer_count += 1;

        if self.is_unlimited() {
            self.stats.unlimited_count += 1;
            self.stats.bytes_consumed = self.stats.bytes_consumed.saturating_add(bytes);
            return Ok(0);
        }

        self.refill();

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            self.stats.bytes_consumed = self.stats.bytes_consumed.saturating_add(bytes);
            Ok(0)
        } else {
            let deficit = bytes as f64 - self.tokens;
            let wait_secs = deficit / self.effective_bytes_per_sec;
            let wait_ms = (wait_secs * 1000.0).ceil() as u64;
            let wait_ms = wait_ms.max(1);

            self.stats.throttled_transfers += 1;
            self.stats.bytes_throttled = self.stats.bytes_throttled.saturating_add(bytes);
            self.stats.total_throttle_delay_ms =
                self.stats.total_throttle_delay_ms.saturating_add(wait_ms);

            Ok(wait_ms)
        }
    }

    /// Consume tokens (blocking helper for convenience).
    ///
    /// Sleeps in a loop until tokens are available. For async code prefer
    /// try_consume + manual sleep / tokio::time::sleep.
    pub fn consume(&mut self, bytes: u64) {
        loop {
            match self.try_consume(bytes) {
                Ok(0) => return,
                Ok(wait_ms) => {
                    std::thread::sleep(Duration::from_millis(wait_ms));
                }
                Err(_) => unreachable!(),
            }
        }
    }

    /// Peek at whether a transfer of `bytes` would be delayed, without
    /// consuming tokens. Returns true if it would proceed immediately.
    #[must_use]
    pub fn would_proceed(&self, bytes: u64) -> bool {
        if self.is_unlimited() {
            return true;
        }
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let tokens = (self.tokens + elapsed * self.effective_bytes_per_sec)
            .min(self.config.token_bucket_capacity_bytes as f64);
        tokens >= bytes as f64
    }

    /// Update the IO pressure signal for dynamic throttling.
    pub fn update_io_pressure(&mut self, pressure: impl Into<IoPressure>) {
        self.io_pressure = pressure.into();
        self.recalc_effective_rate();
    }

    /// Current IO pressure level.
    #[must_use]
    pub fn io_pressure(&self) -> IoPressure {
        self.io_pressure
    }

    /// Current effective bandwidth in megabits per second.
    #[must_use]
    pub fn current_bandwidth_mbps(&self) -> u64 {
        self.stats.current_bandwidth_mbps
    }

    /// Tokens currently available (approximate, before refill).
    #[must_use]
    pub fn tokens_available(&self) -> u64 {
        self.tokens as u64
    }

    /// Read-only access to accumulated statistics.
    #[must_use]
    pub fn stats(&self) -> &ThrottleStats {
        &self.stats
    }

    /// Reset all statistics counters (but not tokens or config).
    pub fn reset_stats(&mut self) {
        self.stats = ThrottleStats::new();
    }

    /// Reset the token bucket to full capacity.
    pub fn reset_tokens(&mut self) {
        self.tokens = self.config.token_bucket_capacity_bytes as f64;
        self.last_refill = Instant::now();
    }

    /// Set a new max bandwidth at runtime.
    pub fn set_max_mbps(&mut self, mbps: u64) {
        self.config.max_recovery_bandwidth_mbps = mbps;
        if mbps == 0 {
            self.effective_bytes_per_sec = f64::MAX;
            self.stats.current_bandwidth_mbps = 0;
            self.stats.current_bandwidth_mbps = 0;
        } else {
            self.config.token_bucket_capacity_bytes =
                self.config.max_bytes_per_sec().saturating_mul(2);
            self.recalc_effective_rate();
        }
        self.reset_tokens();
    }

    // ── Internals ─────────────────────────────────────────────────────

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let added = elapsed * self.effective_bytes_per_sec;
        self.tokens = (self.tokens + added).min(self.config.token_bucket_capacity_bytes as f64);
        self.last_refill = Instant::now();
        self.stats.tokens_available = self.tokens as u64;
    }

    fn recalc_effective_rate(&mut self) {
        if self.config.max_recovery_bandwidth_mbps == 0 {
            self.effective_bytes_per_sec = f64::MAX;
            self.stats.current_bandwidth_mbps = 0;
            self.stats.current_bandwidth_mbps = 0;
            self.stats.current_bandwidth_mbps = 0;
            return;
        }

        let max_bps = self.config.max_bytes_per_sec() as f64;

        if self.config.dynamic_throttle_enabled {
            let pressure = self.io_pressure.as_f64();
            let ratio = 1.0 - pressure * (1.0 - self.config.min_throttle_ratio);
            self.effective_bytes_per_sec = max_bps * ratio;
        } else {
            self.effective_bytes_per_sec = max_bps;
        }

        self.stats.current_bandwidth_mbps =
            (self.effective_bytes_per_sec / 125_000.0).round() as u64;
    }
}

impl Default for BandwidthThrottle {
    fn default() -> Self {
        Self::new(BandwidthThrottleConfig::default())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Token bucket refill + consume ---------------------------------

    #[test]
    fn unlimited_mode_always_proceeds() {
        let mut throttle = BandwidthThrottle::new(BandwidthThrottleConfig {
            max_recovery_bandwidth_mbps: 0,
            ..Default::default()
        });
        assert!(throttle.is_unlimited());
        assert_eq!(throttle.try_consume(1_000_000_000).unwrap(), 0);
        assert_eq!(throttle.try_consume(1).unwrap(), 0);
        assert_eq!(throttle.stats().unlimited_count, 2);
    }

    #[test]
    fn unlimited_would_proceed_always_true() {
        let throttle = BandwidthThrottle::new(BandwidthThrottleConfig {
            max_recovery_bandwidth_mbps: 0,
            ..Default::default()
        });
        assert!(throttle.would_proceed(u64::MAX));
        assert!(throttle.would_proceed(1));
    }

    #[test]
    fn initial_tokens_allow_burst_up_to_capacity() {
        let config = BandwidthThrottleConfig::with_max_mbps(800);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        assert_eq!(throttle.try_consume(cap).unwrap(), 0);
        assert!(throttle.tokens_available() < cap);
    }

    #[test]
    fn bucket_refills_over_time() {
        let config = BandwidthThrottleConfig::with_max_mbps(800);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        assert_eq!(throttle.try_consume(cap).unwrap(), 0);
        // Consuming cap again immediately should be delayed.
        let wait = throttle.try_consume(cap).unwrap();
        assert!(wait > 0);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(throttle.try_consume(9_000_000).unwrap(), 0);
        assert!(throttle.tokens_available() < 2_000_000);
    }

    #[test]
    fn consume_blocks_until_tokens_available() {
        let config = BandwidthThrottleConfig::with_max_mbps(800);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        assert_eq!(throttle.try_consume(cap).unwrap(), 0);
        let start = Instant::now();
        throttle.consume(50_000_000);
        let elapsed_ms = start.elapsed().as_millis();
        assert!(
            elapsed_ms >= 400,
            "expected >=400ms wait, got {elapsed_ms}ms"
        );
        assert!(
            elapsed_ms <= 1000,
            "expected <=1000ms wait, got {elapsed_ms}ms"
        );
    }

    // -- Throttle at max_bandwidth -------------------------------------

    #[test]
    fn sustained_throughput_matches_max_bandwidth() {
        let config = BandwidthThrottleConfig::with_max_mbps(80);
        let mut throttle = BandwidthThrottle::new(config);
        let chunk = 1_000_000;
        let count = 50;
        let mut total_wait_ms: u64 = 0;
        for _ in 0..count {
            total_wait_ms += throttle.try_consume(chunk).unwrap();
        }
        assert!(
            total_wait_ms >= 2500,
            "expected >=2500ms, got {total_wait_ms}ms"
        );
        assert!(
            total_wait_ms <= 6000,
            "expected <=6000ms, got {total_wait_ms}ms"
        );
    }

    #[test]
    fn zero_byte_transfer_always_proceeds() {
        let config = BandwidthThrottleConfig::with_max_mbps(1);
        let mut throttle = BandwidthThrottle::new(config);
        assert_eq!(throttle.try_consume(0).unwrap(), 0);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        assert_eq!(throttle.try_consume(0).unwrap(), 0);
    }

    #[test]
    fn tokens_never_exceed_capacity() {
        let config = BandwidthThrottleConfig::with_max_mbps(800);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        assert_eq!(throttle.tokens_available(), 0);
        std::thread::sleep(Duration::from_secs(3));
        let wait = throttle.try_consume(cap).unwrap();
        assert_eq!(wait, 0);
        let wait2 = throttle.try_consume(cap).unwrap();
        assert!(wait2 > 0, "second cap-sized consume should be delayed");
    }

    // -- Dynamic reduction on IO pressure -------------------------------

    #[test]
    fn dynamic_throttle_reduces_bandwidth_under_pressure() {
        let config = BandwidthThrottleConfig::with_max_mbps(800).with_dynamic(0.1);
        let mut throttle = BandwidthThrottle::new(config);
        assert_eq!(throttle.current_bandwidth_mbps(), 800);
        throttle.update_io_pressure(IoPressure::new(0.5));
        let expected_mid = (800.0 * 0.55) as u64;
        assert!(
            (throttle.current_bandwidth_mbps() as i64 - expected_mid as i64).abs() <= 2,
            "expected ~{expected_mid} mbps, got {}",
            throttle.current_bandwidth_mbps()
        );
        throttle.update_io_pressure(IoPressure::MAX);
        assert!(
            (throttle.current_bandwidth_mbps() as i64 - 80i64).abs() <= 1,
            "expected ~80 mbps, got {}",
            throttle.current_bandwidth_mbps()
        );
        throttle.update_io_pressure(IoPressure::NONE);
        assert_eq!(throttle.current_bandwidth_mbps(), 800);
    }

    #[test]
    fn dynamic_throttle_changes_effective_drain_rate() {
        let config = BandwidthThrottleConfig::with_max_mbps(100).with_dynamic(0.2);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        throttle.update_io_pressure(IoPressure::MAX);
        let wait_ms = throttle.try_consume(1_000_000).unwrap();
        assert!(
            wait_ms > 100,
            "under full pressure 1MB should need >100ms, got {wait_ms}ms"
        );
    }

    #[test]
    fn dynamic_throttle_disabled_ignores_pressure() {
        let config = BandwidthThrottleConfig::with_max_mbps(800);
        let mut throttle = BandwidthThrottle::new(config);
        throttle.update_io_pressure(IoPressure::MAX);
        assert_eq!(throttle.current_bandwidth_mbps(), 800);
        assert_eq!(throttle.io_pressure(), IoPressure::MAX);
    }

    // -- Stats ---------------------------------------------------------

    #[test]
    fn stats_track_throttled_and_unthrottled() {
        let config = BandwidthThrottleConfig::with_max_mbps(100);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap / 2).unwrap();
        assert_eq!(throttle.stats().transfer_count, 1);
        assert_eq!(throttle.stats().throttled_transfers, 0);
        throttle.try_consume(cap).unwrap();
        assert_eq!(throttle.stats().transfer_count, 2);
        assert!(throttle.stats().throttled_transfers >= 1);
        assert!(throttle.stats().total_throttle_delay_ms > 0);
    }

    #[test]
    fn stats_avg_throttle_delay() {
        let config = BandwidthThrottleConfig::with_max_mbps(10);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        throttle.try_consume(1_000_000).unwrap();
        assert!(throttle.stats().throttled_transfers >= 1);
        assert!(throttle.stats().avg_throttle_delay_ms() > 0.0);
    }

    #[test]
    fn stats_avg_delay_zero_when_no_throttling() {
        let throttle = BandwidthThrottle::default();
        assert_eq!(throttle.stats().avg_throttle_delay_ms(), 0.0);
    }

    #[test]
    fn stats_throttle_ratio() {
        let config = BandwidthThrottleConfig::with_max_mbps(10);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        throttle.try_consume(cap).unwrap();
        let ratio = throttle.stats().throttle_ratio();
        assert!(ratio > 0.0);
        assert!(ratio < 1.0);
    }

    // -- would_proceed -------------------------------------------------

    #[test]
    fn would_proceed_does_not_consume_tokens() {
        let config = BandwidthThrottleConfig::with_max_mbps(10);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        assert!(throttle.would_proceed(cap));
        assert_eq!(throttle.try_consume(cap).unwrap(), 0);
    }

    #[test]
    fn would_proceed_false_when_insufficient() {
        let config = BandwidthThrottleConfig::with_max_mbps(1);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        assert!(!throttle.would_proceed(cap));
    }

    // -- set_max_mbps at runtime ---------------------------------------

    #[test]
    fn set_max_mbps_updates_rate() {
        let config = BandwidthThrottleConfig::with_max_mbps(100);
        let mut throttle = BandwidthThrottle::new(config);
        assert_eq!(throttle.current_bandwidth_mbps(), 100);
        throttle.set_max_mbps(50);
        assert_eq!(throttle.current_bandwidth_mbps(), 50);
        throttle.set_max_mbps(0);
        assert!(throttle.is_unlimited());
        assert_eq!(throttle.current_bandwidth_mbps(), 0);
        assert_eq!(throttle.try_consume(1_000_000_000).unwrap(), 0);
    }

    // -- reset_stats / reset_tokens ------------------------------------

    #[test]
    fn reset_stats_clears_counters() {
        let config = BandwidthThrottleConfig::with_max_mbps(10);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        throttle.try_consume(cap).unwrap();
        assert!(throttle.stats().transfer_count > 0);
        throttle.reset_stats();
        assert_eq!(throttle.stats().transfer_count, 0);
        assert_eq!(throttle.stats().throttled_transfers, 0);
    }

    #[test]
    fn reset_tokens_refills_to_capacity() {
        let config = BandwidthThrottleConfig::with_max_mbps(10);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.try_consume(cap).unwrap();
        assert!(throttle.tokens_available() < cap);
        throttle.reset_tokens();
        assert_eq!(throttle.tokens_available(), cap);
    }

    // -- IoPressure helpers --------------------------------------------

    #[test]
    fn io_pressure_clamps_to_range() {
        assert_eq!(IoPressure::new(-1.0).as_f64(), 0.0);
        assert_eq!(IoPressure::new(0.5).as_f64(), 0.5);
        assert_eq!(IoPressure::new(2.0).as_f64(), 1.0);
        assert_eq!(IoPressure::NONE.as_f64(), 0.0);
        assert_eq!(IoPressure::MAX.as_f64(), 1.0);
    }

    // -- Config helpers ------------------------------------------------

    #[test]
    fn config_max_bytes_per_sec_zero_mbps_is_max() {
        let cfg = BandwidthThrottleConfig::default();
        assert_eq!(cfg.max_bytes_per_sec(), u64::MAX);
    }

    #[test]
    fn config_max_bytes_per_sec_converts_correctly() {
        let cfg = BandwidthThrottleConfig::with_max_mbps(8);
        assert_eq!(cfg.max_bytes_per_sec(), 1_000_000);
    }

    #[test]
    fn default_config_is_unlimited() {
        let cfg = BandwidthThrottleConfig::default();
        assert_eq!(cfg.max_recovery_bandwidth_mbps, 0);
        assert!(!cfg.dynamic_throttle_enabled);
    }

    // -- Integration: token bucket + IO pressure refill rate ------------

    #[test]
    fn low_pressure_allows_near_full_bandwidth_consumption() {
        let config = BandwidthThrottleConfig::with_max_mbps(80).with_dynamic(0.1);
        let mut throttle = BandwidthThrottle::new(config);
        let cap = throttle.config.token_bucket_capacity_bytes;
        throttle.update_io_pressure(IoPressure::new(0.05));
        throttle.try_consume(cap).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let result = throttle.try_consume(4_000_000).unwrap();
        assert_eq!(result, 0, "should proceed at low pressure after 500ms");
    }
}
