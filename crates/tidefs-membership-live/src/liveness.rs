// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Protocol-level liveness tracking for membership peers.
//!
//! The [`LivenessTracker`] maintains per-member heartbeat expectations
//! independently of transport-layer TCP keepalive. A peer with an active
//! transport connection may still be stuck at the application layer.
//! Liveness tracking records the most recent authenticated protocol
//! message timestamp for each member and detects failures when the grace
//! period (`heartbeat_interval * failure_threshold`) expires without
//! activity.
//!
//! Failed-member signals are consumed by the epoch state machine to
//! trigger reconfiguration (member removal / failover).

use std::collections::BTreeMap;
use std::time::Duration;
use tidefs_membership_epoch::MemberId;

use crate::types::now_millis;

// ---------------------------------------------------------------------------
// LivenessConfig
// ---------------------------------------------------------------------------

/// Configuration for the liveness tracker.
///
/// The failure grace period is `heartbeat_interval * failure_threshold`:
/// a member is declared unresponsive when that duration elapses since
/// the last recorded activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Expected interval between protocol messages from a peer.
    pub heartbeat_interval: Duration,
    /// Number of missed heartbeat intervals before declaring failure.
    /// Must be >= 1.
    pub failure_threshold: u32,
    /// Minimum number of active peers required for liveness tracking to
    /// produce failure signals. Below this count, failures are recorded
    /// but not emitted (avoids false positives in very small clusters).
    pub min_peers_for_liveness: usize,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_millis(500),
            failure_threshold: 5,
            min_peers_for_liveness: 2,
        }
    }
}

impl LivenessConfig {
    /// Validate the configuration. Returns `Err` with a description if
    /// any field is invalid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.heartbeat_interval.as_millis() == 0 {
            return Err("heartbeat_interval must be non-zero");
        }
        if self.failure_threshold == 0 {
            return Err("failure_threshold must be >= 1");
        }
        Ok(())
    }

    /// The failure grace period in milliseconds.
    pub fn grace_period_ms(&self) -> u64 {
        self.heartbeat_interval.as_millis() as u64 * self.failure_threshold as u64
    }
}

// ---------------------------------------------------------------------------
// LivenessRecord
// ---------------------------------------------------------------------------

/// Per-member liveness state tracked by the [`LivenessTracker`].
#[derive(Clone, Debug)]
struct LivenessRecord {
    /// Most recent activity timestamp (milliseconds since epoch).
    last_seen_millis: u64,
    /// Whether this member is currently considered failed.
    failed: bool,
}

impl LivenessRecord {
    fn new(now_millis: u64) -> Self {
        Self {
            last_seen_millis: now_millis,
            failed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// LivenessTracker
// ---------------------------------------------------------------------------

/// Protocol-level liveness tracker for membership peers.
///
/// # Usage
///
/// 1. Call [`register_member`] for each known peer.
/// 2. On receipt of any authenticated membership protocol message
///    (ping/ack/gossip/epoch-proposal/etc.), call [`record_activity`].
/// 3. Periodically call [`poll_failures`] to detect unresponsive peers
///    and feed the result into the epoch state machine.
/// 4. Call [`remove_member`] when a peer leaves the member set.
pub struct LivenessTracker {
    config: LivenessConfig,
    records: BTreeMap<MemberId, LivenessRecord>,
}

impl LivenessTracker {
    /// Create a new tracker with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid (zero interval or threshold).
    pub fn new(config: LivenessConfig) -> Self {
        config
            .validate()
            .expect("LivenessConfig must be valid: non-zero interval and threshold >= 1");
        Self {
            config,
            records: BTreeMap::new(),
        }
    }

    /// Register a peer for liveness tracking.
    ///
    /// The initial `last_seen` timestamp is set to the current time so
    /// the member is not immediately flagged as failed.
    pub fn register_member(&mut self, member_id: MemberId) {
        let now = now_millis();
        self.records
            .entry(member_id)
            .or_insert_with(|| LivenessRecord::new(now));
    }

    /// Remove a peer from liveness tracking.
    pub fn remove_member(&mut self, member_id: MemberId) {
        self.records.remove(&member_id);
    }

    /// Record protocol activity from a member, resetting its failure
    /// timer. If the member was previously marked as failed, this
    /// clears the failure flag (recovery).
    pub fn record_activity(&mut self, member_id: MemberId) {
        let now = now_millis();
        if let Some(record) = self.records.get_mut(&member_id) {
            record.last_seen_millis = now;
            record.failed = false;
        }
    }

    /// Return the count of tracked members.
    pub fn member_count(&self) -> usize {
        self.records.len()
    }

    /// Check whether a specific member is currently considered failed.
    pub fn is_failed(&self, member_id: MemberId) -> bool {
        self.records.get(&member_id).is_some_and(|r| r.failed)
    }

    /// Get the last-seen timestamp for a member, if tracked.
    pub fn last_seen(&self, member_id: MemberId) -> Option<u64> {
        self.records.get(&member_id).map(|r| r.last_seen_millis)
    }

    /// Poll for failed members.
    ///
    /// Returns an iterator of [`MemberId`]s that have exceeded the
    /// failure grace period. Each failed member is returned at most
    /// once; subsequent polls will not re-emit the same member unless
    /// [`record_activity`] clears the failure and it fails again.
    ///
    /// Failures are only emitted when the tracked member count meets or
    /// exceeds [`LivenessConfig::min_peers_for_liveness`].
    pub fn poll_failures(&mut self) -> impl Iterator<Item = MemberId> + '_ {
        let now = now_millis();
        let grace = self.config.grace_period_ms();
        let emit = self.records.len() >= self.config.min_peers_for_liveness;

        self.records.iter_mut().filter_map(move |(id, record)| {
            if !emit {
                return None;
            }
            if record.failed {
                return None;
            }
            let elapsed = now.saturating_sub(record.last_seen_millis);
            if elapsed >= grace {
                record.failed = true;
                Some(*id)
            } else {
                None
            }
        })
    }

    /// Reset failure state for all tracked members.
    ///
    /// Useful after an epoch transition when the member set has changed.
    pub fn reset_failures(&mut self) {
        for record in self.records.values_mut() {
            record.failed = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn config_default_is_valid() {
        let cfg = LivenessConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_heartbeat_interval() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_failure_threshold() {
        let cfg = LivenessConfig {
            failure_threshold: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_grace_period_computation() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(200),
            failure_threshold: 3,
            min_peers_for_liveness: 2,
        };
        assert_eq!(cfg.grace_period_ms(), 600);
    }

    #[test]
    fn register_and_count() {
        let mut tracker = LivenessTracker::new(LivenessConfig::default());
        assert_eq!(tracker.member_count(), 0);

        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));
        assert_eq!(tracker.member_count(), 2);

        // Re-register is a no-op
        tracker.register_member(MemberId::new(1));
        assert_eq!(tracker.member_count(), 2);
    }

    #[test]
    fn record_activity_updates_last_seen() {
        let mut tracker = LivenessTracker::new(LivenessConfig::default());
        tracker.register_member(MemberId::new(1));

        let before = tracker.last_seen(MemberId::new(1)).unwrap();
        // Sleep a tiny amount to ensure timestamps differ
        thread::sleep(Duration::from_millis(2));
        tracker.record_activity(MemberId::new(1));
        let after = tracker.last_seen(MemberId::new(1)).unwrap();

        assert!(after > before);
    }

    #[test]
    fn record_activity_clears_failure() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(1),
            failure_threshold: 1,
            min_peers_for_liveness: 2,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));

        // Wait past grace period
        thread::sleep(Duration::from_millis(10));

        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.contains(&MemberId::new(1)));
        assert!(failures.contains(&MemberId::new(2)));

        // Record activity clears failure for member 1
        tracker.record_activity(MemberId::new(1));
        assert!(!tracker.is_failed(MemberId::new(1)));
        // Member 2 is still failed
        assert!(tracker.is_failed(MemberId::new(2)));

        // Second poll does not re-emit member 2
        let failures2: Vec<_> = tracker.poll_failures().collect();
        assert!(!failures2.contains(&MemberId::new(2)));
    }

    #[test]
    fn failure_detection_after_grace_period() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(10),
            failure_threshold: 2,
            min_peers_for_liveness: 2,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));

        // Not enough time passed (< 20ms grace)
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.is_empty());

        // Wait past grace period (20ms)
        thread::sleep(Duration::from_millis(30));

        // Record activity for member 1 just before polling, so it survives
        tracker.record_activity(MemberId::new(1));

        let failures: Vec<_> = tracker.poll_failures().collect();
        // Member 2 should have failed
        assert!(failures.contains(&MemberId::new(2)));
        // Member 1 should not have failed (fresh timestamp)
        assert!(!failures.contains(&MemberId::new(1)));
    }

    #[test]
    fn no_failures_below_min_peers() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(1),
            failure_threshold: 1,
            min_peers_for_liveness: 3,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));

        thread::sleep(Duration::from_millis(10));

        // Only 2 peers, min_peers_for_liveness is 3: no failures emitted
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.is_empty());
    }

    #[test]
    fn single_peer_cluster_no_failures() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(1),
            failure_threshold: 1,
            min_peers_for_liveness: 2,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));

        thread::sleep(Duration::from_millis(10));

        // Single peer, min_peers_for_liveness is 2: no failures emitted
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.is_empty());
    }

    #[test]
    fn rapid_toggling_recovery() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(1),
            failure_threshold: 1,
            min_peers_for_liveness: 2,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));

        // Fail both
        thread::sleep(Duration::from_millis(10));
        let _: Vec<_> = tracker.poll_failures().collect();
        assert!(tracker.is_failed(MemberId::new(1)));
        assert!(tracker.is_failed(MemberId::new(2)));

        // Recover member 1
        tracker.record_activity(MemberId::new(1));
        assert!(!tracker.is_failed(MemberId::new(1)));

        // Fail member 1 again
        thread::sleep(Duration::from_millis(10));
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.contains(&MemberId::new(1)));
        // Member 2 already failed, not re-emitted
        assert!(!failures.contains(&MemberId::new(2)));
        assert!(tracker.is_failed(MemberId::new(1)));
    }

    #[test]
    fn remove_member_cleans_up() {
        let mut tracker = LivenessTracker::new(LivenessConfig::default());
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));
        assert_eq!(tracker.member_count(), 2);

        tracker.remove_member(MemberId::new(1));
        assert_eq!(tracker.member_count(), 1);
        assert!(tracker.last_seen(MemberId::new(1)).is_none());
    }

    #[test]
    fn reset_failures_clears_all() {
        let cfg = LivenessConfig {
            heartbeat_interval: Duration::from_millis(1),
            failure_threshold: 1,
            min_peers_for_liveness: 2,
        };
        let mut tracker = LivenessTracker::new(cfg);
        tracker.register_member(MemberId::new(1));
        tracker.register_member(MemberId::new(2));

        thread::sleep(Duration::from_millis(10));
        let _: Vec<_> = tracker.poll_failures().collect();
        assert!(tracker.is_failed(MemberId::new(1)));
        assert!(tracker.is_failed(MemberId::new(2)));

        tracker.reset_failures();
        assert!(!tracker.is_failed(MemberId::new(1)));
        assert!(!tracker.is_failed(MemberId::new(2)));

        // After reset, a new poll can re-emit them
        thread::sleep(Duration::from_millis(10));
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.contains(&MemberId::new(1)));
        assert!(failures.contains(&MemberId::new(2)));
    }

    #[test]
    fn unknown_member_queries_return_none_or_false() {
        let tracker = LivenessTracker::new(LivenessConfig::default());
        assert!(!tracker.is_failed(MemberId::new(99)));
        assert!(tracker.last_seen(MemberId::new(99)).is_none());
    }

    #[test]
    fn zero_peers_no_panic() {
        let mut tracker = LivenessTracker::new(LivenessConfig::default());
        let failures: Vec<_> = tracker.poll_failures().collect();
        assert!(failures.is_empty());
    }
}
