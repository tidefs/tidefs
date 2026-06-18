// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Push retry policy with exponential backoff, jitter, and dead-target marking.
//!
//! `PushRetryPolicy` drives retry decisions for `ReplicaPush` fanout
//! operations. It tracks per-target failure counts, marks persistently
//! unreachable targets as dead, and computes backoff intervals with
//! bounded jitter to avoid thundering-herd effects.

use std::collections::HashMap;
use std::time::Duration;

// ── PushRetryPolicy ─────────────────────────────────────────────────

/// Configurable retry policy for replica chunk push operations.
///
/// Tracks per-target consecutive failure counts and marks a target as
/// *dead* once its failure streak exceeds the configured threshold.
/// Dead targets are excluded from subsequent push attempts until
/// explicitly revived.
#[derive(Clone, Debug)]
pub struct PushRetryPolicy {
    /// Maximum number of retry attempts per push operation.
    pub max_retries: u32,
    /// Base backoff duration for the first retry.
    pub base_backoff: Duration,
    /// Maximum backoff duration to clamp exponential growth.
    pub max_backoff: Duration,
    /// Maximum jitter added to backoff (± half this value).
    pub jitter: Duration,
    /// Number of consecutive failures before a target is marked dead.
    pub dead_threshold: u32,
    /// Per-target consecutive failure counter.
    failure_counts: HashMap<u64, u32>,
    /// Set of targets currently marked dead.
    dead_targets: HashMap<u64, u32>,
}

impl PushRetryPolicy {
    /// Create a new retry policy with the given parameters.
    #[must_use]
    pub fn new(
        max_retries: u32,
        base_backoff: Duration,
        max_backoff: Duration,
        jitter: Duration,
        dead_threshold: u32,
    ) -> Self {
        Self {
            max_retries,
            base_backoff,
            max_backoff,
            jitter,
            dead_threshold,
            failure_counts: HashMap::new(),
            dead_targets: HashMap::new(),
        }
    }

    /// Default policy suitable for LAN replication.
    #[must_use]
    pub fn default_lan() -> Self {
        Self::new(
            3,
            Duration::from_millis(50),
            Duration::from_secs(5),
            Duration::from_millis(25),
            5,
        )
    }

    /// Default policy suitable for WAN / cross-region replication.
    #[must_use]
    pub fn default_wan() -> Self {
        Self::new(
            5,
            Duration::from_millis(200),
            Duration::from_secs(30),
            Duration::from_millis(100),
            3,
        )
    }

    /// Compute the backoff duration for a given retry attempt (1-indexed).
    ///
    /// The backoff grows exponentially from `base_backoff` and is clamped
    /// to `max_backoff`. Jitter is applied as a pseudorandom offset derived
    /// from the attempt number (deterministic, no external RNG needed).
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base_ms = self.base_backoff.as_millis() as u64;
        let max_ms = self.max_backoff.as_millis() as u64;
        let jitter_ms = self.jitter.as_millis() as u64;

        // Exponential: base * 2^(attempt-1)
        let exp = 2u64.saturating_pow(attempt.saturating_sub(1));
        let mut ms = base_ms.saturating_mul(exp);

        if ms > max_ms {
            ms = max_ms;
        }

        // Deterministic jitter via multiplicative hash of attempt number.
        // Uses the same seed-derived offset each time for a given attempt
        // value, so callers see consistent behavior for the same attempt.
        if jitter_ms > 0 {
            let hash = hash_u64(u64::from(attempt));
            let jitter_offset = hash % jitter_ms;
            // Alternate between adding and subtracting jitter based on attempt parity.
            if attempt % 2 == 0 {
                ms = ms.saturating_add(jitter_offset);
            } else {
                ms = ms.saturating_sub(jitter_offset);
            }
        }

        if ms > max_ms {
            ms = max_ms;
        }

        Duration::from_millis(ms)
    }

    /// Record a successful push to a target, resetting its failure count.
    pub fn record_success(&mut self, target_id: u64) {
        self.failure_counts.remove(&target_id);
        self.dead_targets.remove(&target_id);
    }

    /// Record a failed push to a target. Returns `true` if the target
    /// has now exceeded the dead threshold.
    pub fn record_failure(&mut self, target_id: u64) -> bool {
        let count = self.failure_counts.entry(target_id).or_insert(0);
        *count += 1;
        if *count >= self.dead_threshold {
            self.dead_targets.insert(target_id, *count);
            true
        } else {
            false
        }
    }

    /// Check whether a target is currently marked dead.
    #[must_use]
    pub fn is_dead(&self, target_id: u64) -> bool {
        self.dead_targets.contains_key(&target_id)
    }

    /// Revive a dead target, resetting its failure count to zero.
    /// Returns `true` if the target was previously dead.
    pub fn revive(&mut self, target_id: u64) -> bool {
        self.failure_counts.remove(&target_id);
        self.dead_targets.remove(&target_id).is_some()
    }

    /// Returns the current failure count for a target (0 if never failed).
    #[must_use]
    pub fn failure_count(&self, target_id: u64) -> u32 {
        self.failure_counts.get(&target_id).copied().unwrap_or(0)
    }

    /// Returns the current set of dead target IDs.
    #[must_use]
    pub fn dead_target_ids(&self) -> Vec<u64> {
        self.dead_targets.keys().copied().collect()
    }

    /// Returns the number of dead targets.
    #[must_use]
    pub fn dead_count(&self) -> usize {
        self.dead_targets.len()
    }

    /// Reset all failure tracking state.
    pub fn reset(&mut self) {
        self.failure_counts.clear();
        self.dead_targets.clear();
    }

    /// Whether a push operation should be retried given the current
    /// attempt count and whether quorum was reached.
    #[must_use]
    pub fn should_retry(&self, attempt: u32, quorum_reached: bool) -> bool {
        !quorum_reached && attempt < self.max_retries
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Simple multiplicative hash for deterministic jitter.
fn hash_u64(n: u64) -> u64 {
    // Knuth multiplicative hash
    n.wrapping_mul(0x9E3779B97F4A7C15)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> PushRetryPolicy {
        PushRetryPolicy::new(
            3,
            Duration::from_millis(100),
            Duration::from_secs(10),
            Duration::from_millis(50),
            3,
        )
    }

    // ── Backoff timing ───────────────────────────────────────────

    #[test]
    fn backoff_grows_exponentially() {
        let policy = test_policy();
        let b1 = policy.backoff_for_attempt(1).as_millis() as u64;
        let b2 = policy.backoff_for_attempt(2).as_millis() as u64;
        let b3 = policy.backoff_for_attempt(3).as_millis() as u64;
        // Exponential growth: b2 should be approx 2x b1, b3 approx 2x b2
        // (jitter may skew slightly, so use broad bounds)
        assert!(b2 >= b1, "b2 ({b2}) should be >= b1 ({b1})");
        assert!(b3 >= b2, "b3 ({b3}) should be >= b2 ({b2})");
    }

    #[test]
    fn backoff_respects_max() {
        let policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(100),
            Duration::from_millis(500),
            Duration::from_millis(50),
            3,
        );
        for attempt in 1..=10 {
            let ms = policy.backoff_for_attempt(attempt).as_millis() as u64;
            assert!(ms <= 500, "attempt {attempt}: {ms}ms exceeds max 500ms");
        }
    }

    #[test]
    fn backoff_with_attempt_1_is_base() {
        let policy = test_policy();
        let b1 = policy.backoff_for_attempt(1).as_millis() as u64;
        let base = policy.base_backoff.as_millis() as u64;
        let jitter = policy.jitter.as_millis() as u64;
        // With jitter subtracted for odd attempts: base - jitter <= b1 <= base + jitter
        let lower = base.saturating_sub(jitter);
        let upper = base.saturating_add(jitter);
        assert!(b1 >= lower, "b1 ({b1}) < lower ({lower})");
        assert!(b1 <= upper, "b1 ({b1}) > upper ({upper})");
    }

    #[test]
    fn backoff_deterministic() {
        let policy = test_policy();
        let b1 = policy.backoff_for_attempt(3);
        let b2 = policy.backoff_for_attempt(3);
        assert_eq!(b1, b2, "backoff should be deterministic");
    }

    #[test]
    fn backoff_zero_with_zero_base() {
        let policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(0),
            Duration::from_millis(100),
            Duration::from_millis(10),
            3,
        );
        let b = policy.backoff_for_attempt(1);
        assert_eq!(b.as_millis(), 0);
    }

    // ── Dead-target marking ──────────────────────────────────────

    #[test]
    fn target_becomes_dead_after_threshold_failures() {
        let mut policy = test_policy();
        assert!(!policy.is_dead(100));
        policy.record_failure(100);
        assert!(!policy.is_dead(100));
        policy.record_failure(100);
        assert!(!policy.is_dead(100));
        let became_dead = policy.record_failure(100);
        assert!(became_dead);
        assert!(policy.is_dead(100));
    }

    #[test]
    fn success_resets_dead_target() {
        let mut policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            2,
        );
        policy.record_failure(200);
        let became_dead = policy.record_failure(200);
        assert!(became_dead);
        assert!(policy.is_dead(200));
        policy.record_success(200);
        assert!(!policy.is_dead(200));
        assert_eq!(policy.failure_count(200), 0);
    }

    #[test]
    fn revive_dead_target() {
        let mut policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            2,
        );
        policy.record_failure(7);
        policy.record_failure(7);
        assert!(policy.is_dead(7));
        let revived = policy.revive(7);
        assert!(revived);
        assert!(!policy.is_dead(7));
    }

    #[test]
    fn revive_not_dead_returns_false() {
        let mut policy = test_policy();
        let revived = policy.revive(99);
        assert!(!revived);
    }

    #[test]
    fn failure_count_tracks_correctly() {
        let mut policy = test_policy();
        assert_eq!(policy.failure_count(1), 0);
        policy.record_failure(1);
        assert_eq!(policy.failure_count(1), 1);
        policy.record_failure(1);
        assert_eq!(policy.failure_count(1), 2);
        policy.record_success(1);
        assert_eq!(policy.failure_count(1), 0);
    }

    #[test]
    fn multiple_independent_targets() {
        let mut policy = test_policy();
        policy.record_failure(1);
        policy.record_failure(1);
        policy.record_failure(2);
        assert!(!policy.is_dead(1));
        assert!(!policy.is_dead(2));
        policy.record_failure(1);
        assert!(policy.is_dead(1));
        assert!(!policy.is_dead(2));
    }

    #[test]
    fn dead_target_ids_returns_correct_set() {
        let mut policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            1,
        );
        policy.record_failure(10);
        policy.record_failure(20);
        let dead = policy.dead_target_ids();
        assert!(dead.contains(&10));
        assert!(dead.contains(&20));
        assert_eq!(dead.len(), 2);
    }

    #[test]
    fn reset_clears_all_state() {
        let mut policy = test_policy();
        policy.record_failure(5);
        policy.record_failure(5);
        policy.record_failure(5);
        assert!(policy.is_dead(5));
        policy.reset();
        assert!(!policy.is_dead(5));
        assert_eq!(policy.failure_count(5), 0);
        assert!(policy.dead_target_ids().is_empty());
    }

    // ── should_retry ────────────────────────────────────────────

    #[test]
    fn should_retry_when_quorum_not_reached_and_attempts_remain() {
        let policy = test_policy();
        assert!(policy.should_retry(1, false));
        assert!(policy.should_retry(2, false));
    }

    #[test]
    fn should_not_retry_when_quorum_reached() {
        let policy = test_policy();
        assert!(!policy.should_retry(1, true));
    }

    #[test]
    fn should_not_retry_when_max_retries_exceeded() {
        let policy = test_policy();
        assert!(!policy.should_retry(3, false));
        assert!(!policy.should_retry(5, false));
    }

    #[test]
    fn should_retry_boundary() {
        let policy = PushRetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            2,
        );
        assert!(policy.should_retry(2, false)); // attempt 2 < max 3
        assert!(!policy.should_retry(3, false)); // attempt 3 == max 3
    }

    // ── Default constructors ────────────────────────────────────

    #[test]
    fn default_lan_reasonable() {
        let policy = PushRetryPolicy::default_lan();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_backoff, Duration::from_millis(50));
        assert_eq!(policy.max_backoff, Duration::from_secs(5));
        assert_eq!(policy.dead_threshold, 5);
    }

    #[test]
    fn default_wan_reasonable() {
        let policy = PushRetryPolicy::default_wan();
        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.base_backoff, Duration::from_millis(200));
        assert_eq!(policy.max_backoff, Duration::from_secs(30));
        assert_eq!(policy.dead_threshold, 3);
    }
}
