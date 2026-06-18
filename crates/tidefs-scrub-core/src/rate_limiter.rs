// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! I/O rate limiter for background scrub.
//!
//! [`RateLimiter`] uses a dual token-bucket algorithm to cap both bytes/sec
//! and IOPS so that background scrub never starves foreground FUSE/ublk I/O.
//!
//! # Token-bucket design
//!
//! Two independent token buckets (bytes and ops) refill at their configured
//! rates.  Each bucket has a maximum capacity (burst) equal to its per-second
//! rate, allowing short bursts without exceeding the long-term average.
//!
//! When a scrub worker wants to consume resources it calls
//! [`RateLimiter::try_consume`], which:
//!
//! 1. Refills both buckets based on elapsed wall-clock time since the last
//!    refill.
//! 2. Checks whether both buckets have enough tokens.
//! 3. If yes, deducts tokens and returns `true`.
//! 4. If no, returns `false` (the caller should back off and retry later).
//!
//! An unbounded limiter (bytes_per_sec=0, iops=0) always returns `true`
//! and never throttles.  This is the production default when rate limiting
//! is disabled.

use std::sync::Mutex;
use std::time::Instant;

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Dual token-bucket I/O rate limiter.
///
/// Thread-safe: the inner state is behind a [`Mutex`].
///
/// # Examples
///
/// ```
/// use tidefs_scrub::rate_limiter::RateLimiter;
/// use std::time::Duration;
///
/// // 1 MiB/s, 100 IOPS
/// let limiter = RateLimiter::new(1_048_576, 100);
///
/// // Consume a 4 KiB read (1 op, 4096 bytes).
/// assert!(limiter.try_consume(4096, 1));
///
/// // Consuming more than the burst capacity is rejected.
/// let huge = RateLimiter::new(1024, 1);
/// assert!(!huge.try_consume(999_999_999, 1));
/// ```
pub struct RateLimiter {
    inner: Mutex<Inner>,
    /// Bytes per second budget.  0 means unlimited.
    bytes_per_sec: u64,
    /// IOPS budget.  0 means unlimited.
    iops_limit: u64,
}

struct Inner {
    /// Tokens available in the byte bucket (fractional, stored as μ-tokens).
    /// 1 token = 1 byte.  Stored as f64 for sub-byte refill precision.
    byte_tokens: f64,
    /// Tokens available in the ops bucket (fractional).
    ops_tokens: f64,
    /// Last refill timestamp.
    last_refill: Instant,
    /// Cumulative bytes consumed (for observability).
    total_bytes: u64,
    /// Cumulative ops consumed (for observability).
    total_ops: u64,
    /// Number of times `try_consume` returned false.
    throttled: u64,
}

impl RateLimiter {
    /// Create a rate limiter with the given byte and IOPS budgets.
    ///
    /// Set either limit to `0` to disable that dimension (unlimited).
    /// Both set to `0` creates a no-op limiter that never throttles.
    #[must_use]
    pub fn new(bytes_per_sec: u64, iops_limit: u64) -> Self {
        let burst_bytes = if bytes_per_sec > 0 {
            bytes_per_sec as f64
        } else {
            f64::MAX
        };
        let burst_ops = if iops_limit > 0 {
            iops_limit as f64
        } else {
            f64::MAX
        };
        Self {
            inner: Mutex::new(Inner {
                byte_tokens: burst_bytes,
                ops_tokens: burst_ops,
                last_refill: Instant::now(),
                total_bytes: 0,
                total_ops: 0,
                throttled: 0,
            }),
            bytes_per_sec,
            iops_limit,
        }
    }

    /// Create a rate limiter that never throttles (both limits zero).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0, 0)
    }

    /// Attempt to consume `bytes` bytes and `ops` operations.
    ///
    /// Returns `true` if both tokens are available and were deducted.
    /// Returns `false` if either bucket has insufficient tokens; no
    /// tokens are consumed on failure.  The caller should back off and
    /// retry after a short sleep.
    ///
    /// Call this before performing a batch of scrub reads.  For best
    /// results, batch several objects per call rather than calling once
    /// per object.
    pub fn try_consume(&self, bytes: u64, ops: u64) -> bool {
        let mut inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        inner.refill(self.bytes_per_sec, self.iops_limit);

        let need_bytes = bytes as f64;
        let need_ops = ops as f64;

        let byte_ok = self.bytes_per_sec == 0 || inner.byte_tokens >= need_bytes;
        let ops_ok = self.iops_limit == 0 || inner.ops_tokens >= need_ops;

        if byte_ok && ops_ok {
            if self.bytes_per_sec > 0 {
                inner.byte_tokens -= need_bytes;
            }
            if self.iops_limit > 0 {
                inner.ops_tokens -= need_ops;
            }
            inner.total_bytes = inner.total_bytes.saturating_add(bytes);
            inner.total_ops = inner.total_ops.saturating_add(ops);
            true
        } else {
            inner.throttled = inner.throttled.saturating_add(1);
            false
        }
    }

    /// Return the effective bytes/sec rate observed since creation.
    ///
    /// Computed as `total_bytes / elapsed_secs`.  Returns `0.0` when no
    /// time has elapsed.
    #[must_use]
    pub fn effective_bytes_per_sec(&self) -> f64 {
        let inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        let elapsed = inner.last_refill.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            inner.total_bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Return the effective IOPS observed since creation.
    #[must_use]
    pub fn effective_iops(&self) -> f64 {
        let inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        let elapsed = inner.last_refill.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            inner.total_ops as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Total bytes consumed through this limiter.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.inner
            .lock()
            .expect("RateLimiter: mutex poisoned")
            .total_bytes
    }

    /// Total ops consumed through this limiter.
    #[must_use]
    pub fn total_ops(&self) -> u64 {
        self.inner
            .lock()
            .expect("RateLimiter: mutex poisoned")
            .total_ops
    }

    /// Number of times `try_consume` returned false.
    #[must_use]
    pub fn throttled_count(&self) -> u64 {
        self.inner
            .lock()
            .expect("RateLimiter: mutex poisoned")
            .throttled
    }

    /// Available byte tokens (for diagnostic use).
    #[must_use]
    pub fn available_byte_tokens(&self) -> f64 {
        let mut inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        inner.refill(self.bytes_per_sec, self.iops_limit);
        inner.byte_tokens
    }

    /// Available ops tokens (for diagnostic use).
    #[must_use]
    pub fn available_ops_tokens(&self) -> f64 {
        let mut inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        inner.refill(self.bytes_per_sec, self.iops_limit);
        inner.ops_tokens
    }

    /// Whether this limiter is configured to restrict any dimension.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.bytes_per_sec > 0 || self.iops_limit > 0
    }

    /// Reset statistics counters.  Token buckets are not reset.
    pub fn reset_stats(&self) {
        let mut inner = self.inner.lock().expect("RateLimiter: mutex poisoned");
        inner.total_bytes = 0;
        inner.total_ops = 0;
        inner.throttled = 0;
    }
}

impl Inner {
    /// Refill tokens based on elapsed wall-clock time.
    fn refill(&mut self, bytes_per_sec: u64, iops_limit: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        if bytes_per_sec > 0 {
            self.byte_tokens =
                (self.byte_tokens + elapsed * bytes_per_sec as f64).min(bytes_per_sec as f64);
            // cap at 1-second burst
        }
        if iops_limit > 0 {
            self.ops_tokens =
                (self.ops_tokens + elapsed * iops_limit as f64).min(iops_limit as f64);
            // cap at 1-second burst
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::unlimited()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // ── Construction ─────────────────────────────────────────────

    #[test]
    fn unlimited_never_throttles() {
        let limiter = RateLimiter::unlimited();
        assert!(!limiter.is_active());
        for _ in 0..1000 {
            assert!(limiter.try_consume(1_000_000, 100));
        }
        assert_eq!(limiter.throttled_count(), 0);
    }

    #[test]
    fn default_is_unlimited() {
        let limiter = RateLimiter::default();
        assert!(!limiter.is_active());
    }

    #[test]
    fn bytes_only_limit_is_active() {
        let limiter = RateLimiter::new(1024, 0);
        assert!(limiter.is_active());
    }

    #[test]
    fn iops_only_limit_is_active() {
        let limiter = RateLimiter::new(0, 10);
        assert!(limiter.is_active());
    }

    // ── Byte rate limiting ───────────────────────────────────────

    #[test]
    fn byte_limit_allows_up_to_burst() {
        // 1 KiB/s, burst = 1 KiB
        let limiter = RateLimiter::new(1024, 0);
        // Consume the full burst.
        assert!(limiter.try_consume(1024, 1));
        // Burst exhausted; next consume should fail.
        assert!(!limiter.try_consume(1, 1));
    }

    #[test]
    fn byte_limit_refills_over_time() {
        let limiter = RateLimiter::new(10_000, 0); // 10 KB/s
                                                   // Exhaust the burst.
        assert!(limiter.try_consume(10_000, 1));
        assert!(!limiter.try_consume(1, 1));

        // Wait for 100ms: should get ~1000 bytes back.
        thread::sleep(Duration::from_millis(100));
        assert!(limiter.try_consume(500, 1));
        // Remaining tokens (~500) not enough for 1000.
        assert!(!limiter.try_consume(1000, 1));
    }

    #[test]
    fn byte_limit_zero_uses_no_tokens() {
        let limiter = RateLimiter::new(1024, 0);
        // Consume 0 bytes but 1 op (ops unlimited, so passes).
        assert!(limiter.try_consume(0, 1));
        // Byte bucket should still be full.
        assert!(limiter.try_consume(1024, 1));
    }

    // ── IOPS limiting ────────────────────────────────────────────

    #[test]
    fn iops_limit_allows_up_to_burst() {
        let limiter = RateLimiter::new(0, 5); // 5 IOPS, burst = 5
        for _ in 0..5 {
            assert!(limiter.try_consume(0, 1));
        }
        // 6th op should be throttled.
        assert!(!limiter.try_consume(0, 1));
    }

    #[test]
    fn iops_limit_refills_over_time() {
        let limiter = RateLimiter::new(0, 100); // 100 IOPS
                                                // Exhaust.
        for _ in 0..100 {
            assert!(limiter.try_consume(0, 1));
        }
        assert!(!limiter.try_consume(0, 1));

        // Wait 50ms: 5 ops refilled (100 * 0.05).
        thread::sleep(Duration::from_millis(50));
        for _ in 0..5 {
            assert!(limiter.try_consume(0, 1));
        }
        assert!(!limiter.try_consume(0, 1));
    }

    // ── Dual limiting ────────────────────────────────────────────

    #[test]
    fn dual_limit_must_satisfy_both() {
        // 1 KiB/s, 2 IOPS
        let limiter = RateLimiter::new(1024, 2);

        // Two small ops fit in both buckets.
        assert!(limiter.try_consume(100, 1));
        assert!(limiter.try_consume(100, 1));

        // Ops exhausted; bytes still available but ops not → throttled.
        assert!(!limiter.try_consume(100, 1));
    }

    #[test]
    fn dual_limit_bytes_exhausted_blocks_despite_ops_available() {
        let limiter = RateLimiter::new(100, 10); // 100 B/s, 10 IOPS
                                                 // Consume all bytes with one op.
        assert!(limiter.try_consume(100, 1));
        // Bytes exhausted, ops still available → throttled.
        assert!(!limiter.try_consume(1, 1));
    }

    // ── Statistics ───────────────────────────────────────────────

    #[test]
    fn total_bytes_accumulates() {
        let limiter = RateLimiter::new(10_000, 100);
        limiter.try_consume(1024, 1);
        limiter.try_consume(512, 1);
        assert_eq!(limiter.total_bytes(), 1536);
    }

    #[test]
    fn total_ops_accumulates() {
        let limiter = RateLimiter::new(10_000, 100);
        limiter.try_consume(0, 3);
        limiter.try_consume(0, 7);
        assert_eq!(limiter.total_ops(), 10);
    }

    #[test]
    fn throttled_count_increments_on_rejection() {
        let limiter = RateLimiter::new(10, 1); // tiny
        limiter.try_consume(10, 1); // exhaust
        assert!(!limiter.try_consume(1, 1));
        assert!(!limiter.try_consume(1, 1));
        assert_eq!(limiter.throttled_count(), 2);
    }

    #[test]
    fn throttled_count_zero_when_unlimited() {
        let limiter = RateLimiter::unlimited();
        for _ in 0..100 {
            limiter.try_consume(1_000_000, 1000);
        }
        assert_eq!(limiter.throttled_count(), 0);
    }

    #[test]
    fn effective_bytes_per_sec_is_positive_after_consumption() {
        let limiter = RateLimiter::new(1_000_000, 0);
        limiter.try_consume(500_000, 1);
        let rate = limiter.effective_bytes_per_sec();
        assert!(rate > 0.0);
    }

    #[test]
    fn effective_iops_is_positive_after_consumption() {
        let limiter = RateLimiter::new(0, 1000);
        for _ in 0..10 {
            limiter.try_consume(0, 1);
        }
        let rate = limiter.effective_iops();
        assert!(rate > 0.0);
    }

    #[test]
    fn reset_stats_zeroes_counters() {
        let limiter = RateLimiter::new(10_000, 100);
        limiter.try_consume(1000, 10);
        assert!(limiter.total_bytes() > 0);
        assert!(limiter.total_ops() > 0);

        limiter.reset_stats();
        assert_eq!(limiter.total_bytes(), 0);
        assert_eq!(limiter.total_ops(), 0);
        assert_eq!(limiter.throttled_count(), 0);
    }

    // ── Token availability ───────────────────────────────────────

    #[test]
    fn available_tokens_reflects_state() {
        let limiter = RateLimiter::new(1000, 10);
        let initial = limiter.available_byte_tokens();
        assert!(initial > 0.0);

        limiter.try_consume(500, 1);
        let after = limiter.available_byte_tokens();
        assert!(after < initial);
    }

    #[test]
    fn available_ops_tokens_reflects_state() {
        let limiter = RateLimiter::new(0, 10);
        let initial = limiter.available_ops_tokens();
        assert!(initial > 0.0);

        limiter.try_consume(0, 5);
        let after = limiter.available_ops_tokens();
        assert!(after < initial);
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn zero_byte_consume_with_ops_only_limit() {
        let limiter = RateLimiter::new(0, 5);
        // Ops should be consumed even when bytes is 0.
        for _ in 0..5 {
            assert!(limiter.try_consume(0, 1));
        }
        assert!(!limiter.try_consume(0, 1));
        // Bytes should not have been counted.
        assert_eq!(limiter.total_bytes(), 0);
    }

    #[test]
    fn zero_op_consume_with_bytes_only_limit() {
        let limiter = RateLimiter::new(1024, 0);
        assert!(limiter.try_consume(512, 0));
        assert!(limiter.try_consume(512, 0));
        assert!(!limiter.try_consume(1, 0));
        assert_eq!(limiter.total_ops(), 0);
    }

    #[test]
    fn burst_does_not_exceed_one_second_worth() {
        let limiter = RateLimiter::new(100, 0);
        // Can consume 100 bytes (the burst).
        assert!(limiter.try_consume(100, 1));
        // But not 101.
        assert!(!limiter.try_consume(1, 1));
    }

    #[test]
    fn refill_never_exceeds_burst_cap() {
        let limiter = RateLimiter::new(100, 100);
        // Exhaust.
        limiter.try_consume(100, 100);
        // Wait plenty of time for more than a second's worth of refill.
        thread::sleep(Duration::from_millis(1500));
        // Should only have 100 tokens available (1s burst cap), not 150.
        let tokens = limiter.available_byte_tokens();
        assert!(tokens <= 100.0 + 1.0, "tokens={tokens} exceeded burst cap");
    }

    // ── Concurrency smoke ────────────────────────────────────────

    #[test]
    fn concurrent_try_consume_is_sound() {
        use std::sync::Arc;
        let limiter = Arc::new(RateLimiter::new(1_000_000, 10_000));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let l = limiter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    l.try_consume(100, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All ops should have been consumed (plenty of budget).
        assert_eq!(limiter.total_ops(), 400);
    }
}
