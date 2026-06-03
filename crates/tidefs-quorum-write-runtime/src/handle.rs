#![forbid(unsafe_code)]

//! Per-write quorum handle: tracks ack arrival, timeout, retry eligibility,
//! and partial-ack progress for a single quorum write operation.
//!
//! Each `QuorumWriteHandle` is a self-contained state machine for one write.
//! The leader creates a handle at dispatch; replicas feed acks into it; the
//! handle resolves when quorum is met or becomes impossible.
//!
//! Duplicate acks are idempotent — recording the same replica twice is a
//! no-op for the ack count.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use tidefs_quorum_write::NodeId;

use crate::config::WriteQuorumConfig;

/// Per-write state machine tracking acknowledgement progress toward quorum.
///
/// # Lifecycle
///
/// 1. Created at write dispatch with a `WriteQuorumConfig` and timeout
///    parameters.
/// 2. `record_ack(replica)` called for each replica acknowledgement.
/// 3. `record_failure(replica)` called for each replica failure.
/// 4. Resolves to `QuorumMet` when ack count >= W, or `QuorumFailed` when
///    quorum becomes impossible or the total timeout expires.
/// 5. `can_retry()` returns true if the handle may be retried (within
///    `max_retries` and if the phase timeout elapsed without resolution).
#[derive(Debug)]
pub struct QuorumWriteHandle {
    config: WriteQuorumConfig,
    /// Replicas that have acknowledged (idempotent via BTreeSet).
    acked_replicas: BTreeSet<NodeId>,
    /// Replicas that have explicitly failed.
    failed_replicas: BTreeSet<NodeId>,
    /// Current retry attempt (0 = first dispatch).
    attempt: u32,
    /// Maximum retry attempts before giving up.
    max_retries: u32,
    /// Per-phase (retry) timeout.
    phase_timeout: Duration,
    /// Hard deadline for the entire write lifecycle.
    total_timeout: Duration,
    /// Wall-clock instant when the handle was created.
    created_at: Instant,
    /// Instant of the most recent ack (None if no acks yet).
    last_ack_at: Option<Instant>,
    /// Whether the handle has reached a terminal resolution.
    resolved: bool,
    /// Terminal resolution, if any.
    resolution: Option<QuorumWriteResolution>,
}

/// Outcome returned by `record_ack` to inform the leader what to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumAckOutcome {
    /// Ack recorded; quorum not yet met.
    AckReceived,
    /// Ack recorded and quorum is now satisfied — commit may proceed.
    QuorumReached,
    /// Duplicate ack from an already-acked replica (idempotent).
    DuplicateAck,
    /// Handle is already resolved; ack ignored.
    AlreadyResolved,
}

/// Terminal resolution of a quorum write handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumWriteResolution {
    /// Quorum was met with `acks` acknowledgements from `targets`.
    QuorumMet { acks: usize, targets: Vec<NodeId> },
    /// Quorum failed: `acks` collected out of `required`, with a
    /// human-readable `reason`.
    QuorumFailed {
        acks: usize,
        required: usize,
        reason: String,
    },
}

impl QuorumWriteHandle {
    /// Create a new handle for a single quorum write.
    #[must_use]
    pub fn new(
        config: WriteQuorumConfig,
        max_retries: u32,
        phase_timeout: Duration,
        total_timeout: Duration,
    ) -> Self {
        Self {
            config,
            acked_replicas: BTreeSet::new(),
            failed_replicas: BTreeSet::new(),
            attempt: 0,
            max_retries,
            phase_timeout,
            total_timeout,
            created_at: Instant::now(),
            last_ack_at: None,
            resolved: false,
            resolution: None,
        }
    }

    /// Record an acknowledgement from `replica`.
    ///
    /// Returns `QuorumReached` when the ack count first meets the write-quorum
    /// threshold W, `AckReceived` otherwise, `DuplicateAck` if this replica
    /// already acked, and `AlreadyResolved` if the handle is already terminal.
    pub fn record_ack(&mut self, replica: NodeId) -> QuorumAckOutcome {
        if self.resolved {
            return QuorumAckOutcome::AlreadyResolved;
        }

        if self.acked_replicas.contains(&replica) {
            return QuorumAckOutcome::DuplicateAck;
        }

        self.acked_replicas.insert(replica);
        self.last_ack_at = Some(Instant::now());

        if self.config.is_quorum_met(self.acked_replicas.len()) {
            self.resolve_quorum_met();
            QuorumAckOutcome::QuorumReached
        } else {
            QuorumAckOutcome::AckReceived
        }
    }

    /// Record an explicit failure from `replica`.
    ///
    /// This reduces the pool of alive replicas and may make quorum impossible.
    /// If the replica already acked, the failure is ignored (the ack stands).
    pub fn record_failure(&mut self, replica: NodeId) {
        if self.resolved {
            return;
        }
        // If this replica already acked, the ack still counts.
        if self.acked_replicas.contains(&replica) {
            return;
        }
        self.failed_replicas.insert(replica);

        let alive = self.alive_count();
        if self.config.quorum_impossible(alive) {
            self.resolve_quorum_failed("quorum impossible: insufficient alive replicas");
        }
    }

    /// Begin a retry attempt. Increments the attempt counter and clears
    /// transient ack/failure state so the leader can re-dispatch to replicas.
    ///
    /// Returns `true` if the retry was started, `false` if `max_retries`
    /// is exhausted or the handle is already resolved.
    pub fn begin_retry(&mut self) -> bool {
        if self.resolved {
            return false;
        }
        if self.attempt >= self.max_retries {
            self.resolve_quorum_failed("max retries exhausted");
            return false;
        }
        self.attempt += 1;
        self.acked_replicas.clear();
        self.failed_replicas.clear();
        self.last_ack_at = None;
        true
    }

    // ── Query methods ───────────────────────────────────────────────

    /// Number of unique replicas that have acknowledged.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        self.acked_replicas.len()
    }

    /// Number of replicas that have explicitly failed.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.failed_replicas.len()
    }

    /// Number of replicas still alive (not explicitly failed).
    #[must_use]
    pub fn alive_count(&self) -> usize {
        self.config.n().saturating_sub(self.failed_replicas.len())
    }

    /// Whether the write-quorum threshold W has been met.
    #[must_use]
    pub fn quorum_met(&self) -> bool {
        self.config.is_quorum_met(self.acked_replicas.len())
    }

    /// Whether quorum is impossible given current failure count.
    #[must_use]
    pub fn quorum_impossible(&self) -> bool {
        self.config.quorum_impossible(self.alive_count())
    }

    /// Wall-clock duration since the handle was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Whether the current retry phase has exceeded `phase_timeout`.
    ///
    /// Uses time since last ack if any acks have been received; otherwise
    /// uses time since handle creation.
    #[must_use]
    pub fn is_phase_timed_out(&self) -> bool {
        match self.last_ack_at {
            Some(t) => t.elapsed() >= self.phase_timeout,
            None => self.elapsed() >= self.phase_timeout,
        }
    }

    /// Whether the total write timeout has been exceeded.
    #[must_use]
    pub fn is_total_timed_out(&self) -> bool {
        self.elapsed() >= self.total_timeout
    }

    /// Whether the handle can still be retried.
    #[must_use]
    pub fn can_retry(&self) -> bool {
        !self.resolved && self.attempt < self.max_retries && !self.is_total_timed_out()
    }

    /// Whether the handle has reached a terminal resolution.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.resolved
    }

    /// The terminal resolution, if any.
    #[must_use]
    pub fn resolution(&self) -> Option<&QuorumWriteResolution> {
        self.resolution.as_ref()
    }

    /// Current retry attempt number (0-based: 0 = first dispatch).
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Sorted list of replica ids that have acknowledged.
    #[must_use]
    pub fn acked_replicas_sorted(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self.acked_replicas.iter().copied().collect();
        v.sort_by_key(|n| n.0);
        v
    }

    /// Reference to the quorum config.
    #[must_use]
    pub fn config(&self) -> &WriteQuorumConfig {
        &self.config
    }

    // ── Internal resolution helpers ──────────────────────────────────

    fn resolve_quorum_met(&mut self) {
        self.resolved = true;
        self.resolution = Some(QuorumWriteResolution::QuorumMet {
            acks: self.acked_replicas.len(),
            targets: self.acked_replicas_sorted(),
        });
    }

    fn resolve_quorum_failed(&mut self, reason: &str) {
        self.resolved = true;
        self.resolution = Some(QuorumWriteResolution::QuorumFailed {
            acks: self.acked_replicas.len(),
            required: self.config.w(),
            reason: reason.to_string(),
        });
    }
}

// ── QuorumAckOutcome helpers ─────────────────────────────────────────

impl QuorumAckOutcome {
    /// Whether this outcome terminates the ack-collection phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::QuorumReached | Self::AlreadyResolved)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg_3_2() -> WriteQuorumConfig {
        WriteQuorumConfig::new(3, 2).unwrap()
    }

    fn node(id: u64) -> NodeId {
        NodeId::new(id)
    }

    fn short_timeouts() -> (Duration, Duration) {
        (Duration::from_millis(500), Duration::from_secs(5))
    }

    // ── Basic ack flow ───────────────────────────────────────────────

    #[test]
    fn single_ack_not_quorum() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let outcome = h.record_ack(node(1));
        assert_eq!(outcome, QuorumAckOutcome::AckReceived);
        assert!(!h.quorum_met());
        assert!(!h.is_resolved());
        assert_eq!(h.ack_count(), 1);
    }

    #[test]
    fn quorum_reached_on_second_ack() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        let outcome = h.record_ack(node(2));
        assert_eq!(outcome, QuorumAckOutcome::QuorumReached);
        assert!(h.quorum_met());
        assert!(h.is_resolved());
        assert_eq!(h.ack_count(), 2);

        let r = h.resolution().unwrap();
        match r {
            QuorumWriteResolution::QuorumMet { acks, targets } => {
                assert_eq!(*acks, 2);
                assert_eq!(targets, &[node(1), node(2)]);
            }
            _ => panic!("expected QuorumMet"),
        }
    }

    #[test]
    fn third_ack_after_quorum_is_idempotent() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        h.record_ack(node(2)); // quorum reached
        let outcome = h.record_ack(node(3));
        assert_eq!(outcome, QuorumAckOutcome::AlreadyResolved);
        assert_eq!(h.ack_count(), 2); // third ack not recorded
    }

    // ── Duplicate ack ────────────────────────────────────────────────

    #[test]
    fn duplicate_ack_is_idempotent() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        let outcome = h.record_ack(node(1));
        assert_eq!(outcome, QuorumAckOutcome::DuplicateAck);
        assert_eq!(h.ack_count(), 1);
    }

    // ── Failure handling ─────────────────────────────────────────────

    #[test]
    fn one_failure_still_possible() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_failure(node(3));
        assert_eq!(h.failure_count(), 1);
        assert_eq!(h.alive_count(), 2);
        assert!(!h.quorum_impossible());
        // N=3, W=2: one failure still allows quorum
        assert!(!h.is_resolved());
    }

    #[test]
    fn two_failures_make_quorum_impossible() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_failure(node(2));
        h.record_failure(node(3));
        assert!(h.quorum_impossible());
        assert!(h.is_resolved());

        let r = h.resolution().unwrap();
        match r {
            QuorumWriteResolution::QuorumFailed {
                acks,
                required,
                reason,
            } => {
                assert_eq!(*acks, 0);
                assert_eq!(*required, 2);
                assert!(reason.contains("impossible"));
            }
            _ => panic!("expected QuorumFailed"),
        }
    }

    #[test]
    fn failure_after_ack_is_ignored() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        assert_eq!(h.ack_count(), 1);
        // Node 1 fails after acking — the ack still counts
        h.record_failure(node(1));
        assert_eq!(h.ack_count(), 1);
        assert_eq!(h.failure_count(), 0); // not counted as failed
        assert_eq!(h.alive_count(), 3); // node 1 still "alive" for quorum math
    }

    // ── Retry logic ──────────────────────────────────────────────────

    #[test]
    fn begin_retry_clears_state_and_increments_attempt() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            3,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        h.record_failure(node(2));
        assert_eq!(h.attempt(), 0);

        assert!(h.begin_retry());
        assert_eq!(h.attempt(), 1);
        assert_eq!(h.ack_count(), 0);
        assert_eq!(h.failure_count(), 0);
        assert!(!h.is_resolved());
    }

    #[test]
    fn retry_exhausts_max_retries() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        assert!(h.begin_retry()); // attempt 1
        assert!(h.begin_retry()); // attempt 2
        assert!(!h.begin_retry()); // max exhausted -> false, resolved to failed
        assert!(h.is_resolved());
        match h.resolution().unwrap() {
            QuorumWriteResolution::QuorumFailed { reason, .. } => {
                assert!(reason.contains("max retries"));
            }
            _ => panic!("expected QuorumFailed"),
        }
    }

    #[test]
    fn cannot_retry_after_resolution() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            3,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        h.record_ack(node(2)); // resolved
        assert!(h.is_resolved());
        assert!(!h.begin_retry());
        assert!(!h.can_retry());
    }

    // ── Timeout checks ───────────────────────────────────────────────

    #[test]
    fn fresh_handle_not_timed_out() {
        let (phase, total) = short_timeouts();
        let h = QuorumWriteHandle::new(cfg_3_2(), 2, phase, total);
        assert!(!h.is_phase_timed_out());
        assert!(!h.is_total_timed_out());
        assert!(h.can_retry());
    }

    #[test]
    fn zero_phase_timeout_is_immediately_phase_timed_out() {
        let h = QuorumWriteHandle::new(cfg_3_2(), 2, Duration::ZERO, Duration::from_secs(10));
        assert!(h.is_phase_timed_out());
        assert!(!h.is_total_timed_out());
    }

    #[test]
    fn zero_total_timeout_is_immediately_total_timed_out() {
        let h = QuorumWriteHandle::new(cfg_3_2(), 2, Duration::from_secs(1), Duration::ZERO);
        assert!(h.is_total_timed_out());
        assert!(!h.can_retry());
    }

    #[test]
    fn elapsed_increases() {
        let h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let e1 = h.elapsed();
        std::thread::sleep(Duration::from_millis(1));
        let e2 = h.elapsed();
        assert!(e2 >= e1);
    }

    // ── Config edge cases ────────────────────────────────────────────

    #[test]
    fn single_replica_quorum() {
        let mut h = QuorumWriteHandle::new(
            WriteQuorumConfig::single_replica(),
            0,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let outcome = h.record_ack(node(1));
        assert_eq!(outcome, QuorumAckOutcome::QuorumReached);
        assert!(h.quorum_met());
    }

    #[test]
    fn majority_5_3_reaches_at_3() {
        let mut h = QuorumWriteHandle::new(
            WriteQuorumConfig::majority_of(5),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        assert_eq!(h.record_ack(node(1)), QuorumAckOutcome::AckReceived);
        assert_eq!(h.record_ack(node(2)), QuorumAckOutcome::AckReceived);
        assert!(!h.quorum_met());
        assert_eq!(h.record_ack(node(3)), QuorumAckOutcome::QuorumReached);
    }

    // ── Acked replicas ordering ──────────────────────────────────────

    #[test]
    fn acked_replicas_sorted_by_id() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        // Acks arrive: node(3), then node(1) -> quorum met at 2.
        h.record_ack(node(3));
        h.record_ack(node(1)); // quorum reached here
        assert!(h.is_resolved());
        let r = h.resolution().unwrap();
        match r {
            QuorumWriteResolution::QuorumMet { targets, .. } => {
                // Only the two acks recorded before quorum was met.
                assert_eq!(targets, &[node(1), node(3)]);
            }
            _ => panic!("expected QuorumMet"),
        }
    }

    // ── QuorumAckOutcome helpers ─────────────────────────────────────

    #[test]
    fn ack_outcome_is_terminal() {
        assert!(!QuorumAckOutcome::AckReceived.is_terminal());
        assert!(!QuorumAckOutcome::DuplicateAck.is_terminal());
        assert!(QuorumAckOutcome::QuorumReached.is_terminal());
        assert!(QuorumAckOutcome::AlreadyResolved.is_terminal());
    }

    // ── Resolution display ───────────────────────────────────────────

    #[test]
    fn resolution_quorum_met_has_acks_geq_w() {
        let mut h = QuorumWriteHandle::new(
            cfg_3_2(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_ack(node(1));
        h.record_ack(node(2));
        match h.resolution().unwrap() {
            QuorumWriteResolution::QuorumMet { acks, .. } => {
                assert!(*acks >= 2);
            }
            _ => panic!("expected QuorumMet"),
        }
    }

    #[test]
    fn resolution_quorum_failed_has_reason() {
        let mut h = QuorumWriteHandle::new(
            WriteQuorumConfig::new(2, 2).unwrap(),
            0,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        h.record_failure(node(1));
        h.record_failure(node(2));
        match h.resolution().unwrap() {
            QuorumWriteResolution::QuorumFailed { reason, .. } => {
                assert!(!reason.is_empty());
            }
            _ => panic!("expected QuorumFailed"),
        }
    }
}
