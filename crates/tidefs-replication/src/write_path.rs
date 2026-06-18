// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replication write-path: fanout writes to replica peers, collect
//! per-replica acknowledgments, and signal quorum satisfaction or
//! shortfall to the caller.
//!
//! # Architecture
//!
//! ```text
//! submit_write(payload, replicas, quorum) --> ReplicationWriteHandle
//!                                                 |
//!                               ReplicaSendDispatch  (fan-out)
//!                                                 |
//!                           +---------------------+---------------------+
//!                           v                     v                     v
//!                       target_0              target_1              target_N
//!                           |                     |                     |
//!                           v                     v                     v
//!                         ack/nack             ack/nack             ack/nack
//!                           |                     |                     |
//!                           +---------------------+---------------------+
//!                                                 |
//!                                                 v
//!                              QuorumAcknowledgmentAggregator
//!                                                 |
//!                                                 v
//!                                         ReplicationWriteOutcome
//! ```

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tidefs_membership_epoch::MemberId;

// ============================================================================
// QuorumMode
// ============================================================================

/// Quorum semantics for replication write dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumMode {
    /// Every target must acknowledge.
    All,
    /// Strict majority (N/2 + 1) must acknowledge.
    Majority,
    /// At least one target must acknowledge.
    Single,
}

impl QuorumMode {
    /// Minimum acknowledgments required to achieve quorum for
    /// `target_count` replicas.
    #[must_use]
    pub const fn min_quorum(self, target_count: usize) -> usize {
        match self {
            Self::All => target_count,
            Self::Majority => {
                if target_count == 0 {
                    0
                } else {
                    target_count / 2 + 1
                }
            }
            Self::Single => {
                if target_count == 0 {
                    0
                } else {
                    1
                }
            }
        }
    }
}

// ============================================================================
// ReplicationWriteOutcome
// ============================================================================

/// Result of a replication write submitted through
/// [`ReplicationWriteHandle`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicationWriteOutcome {
    /// Quorum was reached.
    QuorumReached {
        /// How many targets acknowledged.
        ack_count: usize,
        /// Total targets attempted.
        target_count: usize,
        /// Set of targets that acknowledged.
        acked: Vec<MemberId>,
        /// Set of targets that failed to ack (within timeout).
        failed: Vec<MemberId>,
    },
    /// Quorum was not reached.
    QuorumShortfall {
        /// How many targets acknowledged.
        ack_count: usize,
        /// Required quorum count.
        quorum_required: usize,
        /// Reason for the shortfall.
        reason: QuorumShortfallReason,
    },
    /// No replicas were configured.
    NoReplicas,
}

impl ReplicationWriteOutcome {
    /// Returns `true` if quorum was reached (the write is durable).
    #[must_use]
    pub fn is_quorum_reached(&self) -> bool {
        matches!(self, Self::QuorumReached { .. })
    }

    /// Number of replicas that acknowledged.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        match self {
            Self::QuorumReached { ack_count, .. } | Self::QuorumShortfall { ack_count, .. } => {
                *ack_count
            }
            Self::NoReplicas => 0,
        }
    }
}

// ============================================================================
// QuorumShortfallReason
// ============================================================================

/// Why quorum was not reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumShortfallReason {
    /// The per-target timeout expired before enough acks arrived.
    Timeout {
        acks_collected: usize,
        quorum_required: usize,
    },
    /// Quorum became impossible -- the remaining viable targets cannot
    /// meet the threshold.
    QuorumImpossible {
        acks_collected: usize,
        quorum_required: usize,
        /// Targets that neither acked nor failed yet.
        remaining_possible: usize,
    },
}

// ============================================================================
// ReplicationWriteTransport
// ============================================================================

/// Transport abstraction for the replication write path.
///
/// Decouples the write-path state machine from concrete transport
/// implementations. Production users implement this against
/// [`tidefs_transport::Transport`]; tests use mocks.
pub trait ReplicationWriteTransport: Send + Sync {
    /// Send a write payload to a single target and wait for its
    /// acknowledgment.
    ///
    /// Returns `Ok(true)` if the target acknowledged the write,
    /// `Ok(false)` if the target explicitly rejected it, or `Err`
    /// on transport-level failure.
    fn write_to_target(
        &self,
        target: MemberId,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<bool, String>;
}

// ============================================================================
// Internal per-target result
// ============================================================================

#[derive(Clone, Debug, Eq, PartialEq)]
enum TargetResult {
    Acked { target: MemberId },
    Failed { target: MemberId, error: String },
}

// ============================================================================
// ReplicaSendDispatch
// ============================================================================

/// Fan-out engine: dispatches a write payload to every replica target
/// concurrently, collecting results through channels.
struct ReplicaSendDispatch;

impl ReplicaSendDispatch {
    fn new() -> Self {
        Self
    }

    /// Concurrently fan out a write to all replicas via `transport`.
    /// Returns join handles and per-target result receivers.
    fn fanout<T: ReplicationWriteTransport + 'static>(
        &self,
        transport: std::sync::Arc<T>,
        payload: Vec<u8>,
        replicas: Vec<MemberId>,
        timeout: Duration,
    ) -> (Vec<JoinHandle<()>>, Vec<Receiver<TargetResult>>) {
        let mut handles = Vec::with_capacity(replicas.len());
        let mut receivers = Vec::with_capacity(replicas.len());

        for replica in replicas {
            let t = std::sync::Arc::clone(&transport);
            let p = payload.clone();
            let (tx, rx) = mpsc::channel();

            let handle = thread::spawn(move || {
                let result = match t.write_to_target(replica, &p, timeout) {
                    Ok(true) => TargetResult::Acked { target: replica },
                    Ok(false) => TargetResult::Failed {
                        target: replica,
                        error: "target rejected write".into(),
                    },
                    Err(e) => TargetResult::Failed {
                        target: replica,
                        error: e,
                    },
                };
                let _ = tx.send(result);
            });

            handles.push(handle);
            receivers.push(rx);
        }

        (handles, receivers)
    }
}

// ============================================================================
// QuorumAcknowledgmentAggregator
// ============================================================================

/// Collects per-target acknowledgments and decides quorum.
struct QuorumAcknowledgmentAggregator;

impl QuorumAcknowledgmentAggregator {
    /// Wait for results from the concurrent fanout and determine the
    /// replication outcome.
    fn aggregate(
        handles: Vec<JoinHandle<()>>,
        receivers: Vec<Receiver<TargetResult>>,
        replicas: Vec<MemberId>,
        quorum_mode: QuorumMode,
        aggregate_timeout: Duration,
    ) -> ReplicationWriteOutcome {
        let target_count = replicas.len();

        if target_count == 0 {
            for h in handles {
                let _ = h.join();
            }
            return ReplicationWriteOutcome::NoReplicas;
        }

        let quorum_required = quorum_mode.min_quorum(target_count);
        let mut acked: Vec<MemberId> = Vec::new();
        let mut failed: Vec<MemberId> = Vec::new();

        let deadline = std::time::Instant::now() + aggregate_timeout;
        let mut rxs: Vec<(MemberId, Receiver<TargetResult>)> =
            replicas.into_iter().zip(receivers).collect();

        loop {
            // Quorum already satisfied -- drain residual results and return.
            if acked.len() >= quorum_required {
                for (_replica, rx) in &rxs {
                    if let Ok(result) = rx.recv_timeout(Duration::from_millis(1)) {
                        match result {
                            TargetResult::Acked { target } => {
                                if !acked.contains(&target) {
                                    acked.push(target);
                                }
                            }
                            TargetResult::Failed { target, .. } => {
                                if !failed.contains(&target) && !acked.contains(&target) {
                                    failed.push(target);
                                }
                            }
                        }
                    }
                }
                for h in handles {
                    let _ = h.join();
                }
                return ReplicationWriteOutcome::QuorumReached {
                    ack_count: acked.len(),
                    target_count,
                    acked,
                    failed,
                };
            }

            // Quorum impossible: max possible acks < required.
            let max_possible = acked.len() + rxs.len();
            if max_possible < quorum_required {
                for h in handles {
                    let _ = h.join();
                }
                return ReplicationWriteOutcome::QuorumShortfall {
                    ack_count: acked.len(),
                    quorum_required,
                    reason: QuorumShortfallReason::QuorumImpossible {
                        acks_collected: acked.len(),
                        quorum_required,
                        remaining_possible: rxs.len(),
                    },
                };
            }

            // Aggregate deadline expired.
            let now = std::time::Instant::now();
            if now >= deadline {
                for h in handles {
                    let _ = h.join();
                }
                return ReplicationWriteOutcome::QuorumShortfall {
                    ack_count: acked.len(),
                    quorum_required,
                    reason: QuorumShortfallReason::Timeout {
                        acks_collected: acked.len(),
                        quorum_required,
                    },
                };
            }

            let remain = deadline - now;

            // Non-blocking poll of all pending receivers.
            let mut any_received = false;
            let mut i: isize = 0;
            while (i as usize) < rxs.len() {
                let idx = i as usize;
                match rxs[idx].1.recv_timeout(Duration::from_millis(1)) {
                    Ok(TargetResult::Acked { target }) => {
                        if !acked.contains(&target) {
                            acked.push(target);
                        }
                        rxs.remove(idx);
                        any_received = true;
                        continue;
                    }
                    Ok(TargetResult::Failed { target, .. }) => {
                        if !failed.contains(&target) {
                            failed.push(target);
                        }
                        rxs.remove(idx);
                        any_received = true;
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        rxs.remove(idx);
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Not ready yet.
                    }
                }
                i += 1;
            }

            // If nothing arrived, do a blocking wait on the first pending
            // receiver for the remaining time. Process the result immediately
            // so we do not discard it and then time out on the next poll.
            if !any_received && !rxs.is_empty() {
                match rxs[0].1.recv_timeout(remain) {
                    Ok(TargetResult::Acked { target }) => {
                        if !acked.contains(&target) {
                            acked.push(target);
                        }
                        rxs.remove(0);
                    }
                    Ok(TargetResult::Failed { target, .. }) => {
                        if !failed.contains(&target) {
                            failed.push(target);
                        }
                        rxs.remove(0);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        rxs.remove(0);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Still nothing; loop will handle timeout check.
                    }
                }
            }
        }
    }
}

// ============================================================================
// ReplicationWriteHandle
// ============================================================================

/// Public handle for submitting replication writes.
///
/// Accepts a write payload, fans it out to every configured replica,
/// collects acknowledgments, and signals quorum satisfaction or
/// shortfall.
///
/// # Example
///
/// ```ignore
/// use tidefs_replication::write_path::{
///     ReplicationWriteHandle, ReplicationWriteOutcome, QuorumMode,
/// };
/// use tidefs_membership_epoch::MemberId;
///
/// let transport = MyTransport::new();
/// let mut handle = ReplicationWriteHandle::new(transport);
/// let outcome = handle.submit_write(
///     b"my payload",
///     &[MemberId::new(1), MemberId::new(2), MemberId::new(3)],
///     QuorumMode::Majority,
/// );
/// assert!(outcome.is_quorum_reached());
/// ```
pub struct ReplicationWriteHandle<T: ReplicationWriteTransport + 'static> {
    transport: std::sync::Arc<T>,
    default_timeout: Duration,
    dispatcher: ReplicaSendDispatch,
}

impl<T: ReplicationWriteTransport + 'static> ReplicationWriteHandle<T> {
    /// Create a new handle with the given transport backend.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport: std::sync::Arc::new(transport),
            default_timeout: Duration::from_secs(30),
            dispatcher: ReplicaSendDispatch::new(),
        }
    }

    /// Set the default per-target timeout for write operations.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.default_timeout = timeout;
        self.dispatcher = ReplicaSendDispatch::new();
    }

    /// Submit a write to replicas and block until quorum is reached,
    /// quorum becomes impossible, or the deadline expires.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to replicate.
    /// * `replicas` - The set of target members to write to.
    /// * `quorum_mode` - The quorum threshold to enforce.
    #[must_use]
    pub fn submit_write(
        &mut self,
        payload: &[u8],
        replicas: &[MemberId],
        quorum_mode: QuorumMode,
    ) -> ReplicationWriteOutcome {
        if replicas.is_empty() {
            return ReplicationWriteOutcome::NoReplicas;
        }

        let replicas_vec = replicas.to_vec();
        let (handles, receivers) = self.dispatcher.fanout(
            std::sync::Arc::clone(&self.transport),
            payload.to_vec(),
            replicas_vec.clone(),
            self.default_timeout,
        );

        // Use twice the per-target timeout as the aggregate deadline.
        let aggregate_timeout = self.default_timeout * 2;

        QuorumAcknowledgmentAggregator::aggregate(
            handles,
            receivers,
            replicas_vec,
            quorum_mode,
            aggregate_timeout,
        )
    }
}

// ============================================================================
// ReplicationWriteRequest (oneshot-based async variant)
// ============================================================================

/// A pending replication write request with a oneshot reply channel.
///
/// This variant is useful when the caller wants to enqueue a write
/// and await its outcome asynchronously (e.g., from a worker task).
pub struct ReplicationWriteRequest {
    /// The payload to replicate.
    pub payload: Vec<u8>,
    /// The target replicas.
    pub replicas: Vec<MemberId>,
    /// The quorum threshold.
    pub quorum_mode: QuorumMode,
    /// Per-target timeout for this request.
    pub timeout: Duration,
    /// Reply channel for the outcome.
    pub reply: Sender<ReplicationWriteOutcome>,
}

impl ReplicationWriteRequest {
    /// Create a new request. The caller retains the receiver side of
    /// the channel to await the outcome.
    #[must_use]
    pub fn new(
        payload: Vec<u8>,
        replicas: Vec<MemberId>,
        quorum_mode: QuorumMode,
        timeout: Duration,
    ) -> (Self, Receiver<ReplicationWriteOutcome>) {
        let (tx, rx) = mpsc::channel();
        (
            Self {
                payload,
                replicas,
                quorum_mode,
                timeout,
                reply: tx,
            },
            rx,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -- Mock transport ----------------------------------------------------

    struct MockTransport {
        behaviors: Mutex<HashMap<u64, Result<bool, String>>>,
        latency: Duration,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                behaviors: Mutex::new(HashMap::new()),
                latency: Duration::from_millis(1),
            }
        }

        fn set_ack(&self, target: u64) {
            self.behaviors.lock().unwrap().insert(target, Ok(true));
        }

        fn set_reject(&self, target: u64) {
            self.behaviors.lock().unwrap().insert(target, Ok(false));
        }

        fn set_error(&self, target: u64, msg: &str) {
            self.behaviors
                .lock()
                .unwrap()
                .insert(target, Err(msg.into()));
        }

        #[allow(dead_code)]
        fn set_latency(&mut self, d: Duration) {
            self.latency = d;
        }
    }

    impl ReplicationWriteTransport for MockTransport {
        fn write_to_target(
            &self,
            target: MemberId,
            _payload: &[u8],
            _timeout: Duration,
        ) -> Result<bool, String> {
            thread::sleep(self.latency);
            match self.behaviors.lock().unwrap().get(&target.0) {
                Some(result) => result.clone(),
                None => Err("no behavior configured".into()),
            }
        }
    }

    fn member_ids(ids: &[u64]) -> Vec<MemberId> {
        ids.iter().map(|&i| MemberId::new(i)).collect()
    }

    // -- QuorumMode tests --------------------------------------------------

    #[test]
    fn quorum_mode_all() {
        assert_eq!(QuorumMode::All.min_quorum(3), 3);
        assert_eq!(QuorumMode::All.min_quorum(1), 1);
        assert_eq!(QuorumMode::All.min_quorum(0), 0);
    }

    #[test]
    fn quorum_mode_majority() {
        assert_eq!(QuorumMode::Majority.min_quorum(3), 2);
        assert_eq!(QuorumMode::Majority.min_quorum(5), 3);
        assert_eq!(QuorumMode::Majority.min_quorum(4), 3);
        assert_eq!(QuorumMode::Majority.min_quorum(2), 2);
        assert_eq!(QuorumMode::Majority.min_quorum(1), 1);
        assert_eq!(QuorumMode::Majority.min_quorum(0), 0);
    }

    #[test]
    fn quorum_mode_single() {
        assert_eq!(QuorumMode::Single.min_quorum(5), 1);
        assert_eq!(QuorumMode::Single.min_quorum(1), 1);
        assert_eq!(QuorumMode::Single.min_quorum(0), 0);
    }

    // -- Single replica tests ----------------------------------------------

    #[test]
    fn single_replica_ack_succeeds() {
        let t = MockTransport::new();
        t.set_ack(1);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1]), QuorumMode::All);
        assert!(outcome.is_quorum_reached());
        assert_eq!(outcome.ack_count(), 1);
    }

    #[test]
    fn single_replica_reject_fails() {
        let t = MockTransport::new();
        t.set_reject(1);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1]), QuorumMode::All);
        assert!(!outcome.is_quorum_reached());
        match outcome {
            ReplicationWriteOutcome::QuorumShortfall { ack_count, .. } => {
                assert_eq!(ack_count, 0);
            }
            other => panic!("expected QuorumShortfall, got {other:?}"),
        }
    }

    #[test]
    fn single_replica_error_fails() {
        let t = MockTransport::new();
        t.set_error(1, "connection refused");
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1]), QuorumMode::All);
        assert!(!outcome.is_quorum_reached());
    }

    // -- Multi-replica majority tests --------------------------------------

    #[test]
    fn three_replicas_majority_all_ack() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        t.set_ack(3);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::Majority);
        assert!(outcome.is_quorum_reached());
        match outcome {
            ReplicationWriteOutcome::QuorumReached {
                ack_count,
                target_count,
                ..
            } => {
                assert_eq!(ack_count, 3);
                assert_eq!(target_count, 3);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn three_replicas_majority_two_ack_succeeds() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        t.set_reject(3);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::Majority);
        assert!(outcome.is_quorum_reached());
        match outcome {
            ReplicationWriteOutcome::QuorumReached {
                ack_count, failed, ..
            } => {
                assert_eq!(ack_count, 2);
                assert_eq!(failed.len(), 1);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn three_replicas_majority_one_ack_shortfall() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_reject(2);
        t.set_reject(3);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::Majority);
        assert!(!outcome.is_quorum_reached());
        match outcome {
            ReplicationWriteOutcome::QuorumShortfall { ack_count, .. } => {
                assert_eq!(ack_count, 1);
            }
            other => panic!("expected QuorumShortfall, got {other:?}"),
        }
    }

    // -- Multi-replica all tests -------------------------------------------

    #[test]
    fn three_replicas_all_ack_succeeds() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        t.set_ack(3);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::All);
        assert!(outcome.is_quorum_reached());
    }

    #[test]
    fn three_replicas_all_with_one_failure_shortfall() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        t.set_reject(3);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::All);
        assert!(!outcome.is_quorum_reached());
    }

    // -- Single quorum tests -----------------------------------------------

    #[test]
    fn five_replicas_single_quorum_one_ack() {
        let t = MockTransport::new();
        t.set_ack(3);
        t.set_reject(1);
        t.set_reject(2);
        t.set_reject(4);
        t.set_reject(5);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome =
            handle.submit_write(b"data", &member_ids(&[1, 2, 3, 4, 5]), QuorumMode::Single);
        assert!(outcome.is_quorum_reached());
        assert_eq!(outcome.ack_count(), 1);
    }

    // -- Zero replica tests ------------------------------------------------

    #[test]
    fn zero_replicas_returns_no_replicas() {
        let t = MockTransport::new();
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &[], QuorumMode::Majority);
        assert!(matches!(outcome, ReplicationWriteOutcome::NoReplicas));
    }

    // -- ReplicationWriteRequest (oneshot) tests ---------------------------

    #[test]
    fn oneshot_request_channel_roundtrip() {
        let (request, rx) = ReplicationWriteRequest::new(
            b"payload".to_vec(),
            member_ids(&[1, 2]),
            QuorumMode::Majority,
            Duration::from_secs(5),
        );
        assert_eq!(request.replicas.len(), 2);
        assert_eq!(request.quorum_mode, QuorumMode::Majority);

        let outcome = ReplicationWriteOutcome::QuorumReached {
            ack_count: 2,
            target_count: 2,
            acked: member_ids(&[1, 2]),
            failed: vec![],
        };
        request.reply.send(outcome.clone()).unwrap();
        assert_eq!(rx.recv().unwrap(), outcome);
    }

    #[test]
    fn oneshot_request_dropped_sender_disconnects_receiver() {
        let (request, rx) = ReplicationWriteRequest::new(
            b"data".to_vec(),
            member_ids(&[1]),
            QuorumMode::Single,
            Duration::from_secs(1),
        );
        drop(request);
        assert!(rx.recv().is_err());
    }

    // -- Outcome accessor tests --------------------------------------------

    #[test]
    fn outcome_is_quorum_reached() {
        let reached = ReplicationWriteOutcome::QuorumReached {
            ack_count: 2,
            target_count: 3,
            acked: member_ids(&[1, 2]),
            failed: member_ids(&[3]),
        };
        assert!(reached.is_quorum_reached());

        let shortfall = ReplicationWriteOutcome::QuorumShortfall {
            ack_count: 1,
            quorum_required: 2,
            reason: QuorumShortfallReason::Timeout {
                acks_collected: 1,
                quorum_required: 2,
            },
        };
        assert!(!shortfall.is_quorum_reached());

        let none = ReplicationWriteOutcome::NoReplicas;
        assert!(!none.is_quorum_reached());
    }

    #[test]
    fn outcome_ack_count() {
        assert_eq!(
            ReplicationWriteOutcome::QuorumReached {
                ack_count: 3,
                target_count: 3,
                acked: vec![],
                failed: vec![],
            }
            .ack_count(),
            3
        );
        assert_eq!(
            ReplicationWriteOutcome::QuorumShortfall {
                ack_count: 1,
                quorum_required: 2,
                reason: QuorumShortfallReason::Timeout {
                    acks_collected: 1,
                    quorum_required: 2,
                },
            }
            .ack_count(),
            1
        );
        assert_eq!(ReplicationWriteOutcome::NoReplicas.ack_count(), 0);
    }

    // -- Concurrent handle usage -------------------------------------------

    #[test]
    fn handle_can_be_reused_for_multiple_writes() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        let mut handle = ReplicationWriteHandle::new(t);

        let o1 = handle.submit_write(b"first", &member_ids(&[1, 2]), QuorumMode::All);
        assert!(o1.is_quorum_reached());

        let o2 = handle.submit_write(b"second", &member_ids(&[1, 2]), QuorumMode::All);
        assert!(o2.is_quorum_reached());
    }

    // -- Five-replica diverse scenarios ------------------------------------

    #[test]
    fn five_replicas_three_ack_majority_succeeds() {
        let t = MockTransport::new();
        for i in 1..=3 {
            t.set_ack(i);
        }
        for i in 4..=5 {
            t.set_reject(i);
        }
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome =
            handle.submit_write(b"data", &member_ids(&[1, 2, 3, 4, 5]), QuorumMode::Majority);
        assert!(outcome.is_quorum_reached());
    }

    #[test]
    fn five_replicas_two_ack_majority_shortfall() {
        let t = MockTransport::new();
        t.set_ack(1);
        t.set_ack(2);
        t.set_reject(3);
        t.set_reject(4);
        t.set_reject(5);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome =
            handle.submit_write(b"data", &member_ids(&[1, 2, 3, 4, 5]), QuorumMode::Majority);
        // Majority of 5 = 3 needed, only 2 acked --> shortfall.
        assert!(!outcome.is_quorum_reached());
    }

    // -- Deduplication: single channel per target --------------------------

    #[test]
    fn single_target_one_channel_no_double_count() {
        let t = MockTransport::new();
        t.set_ack(1);
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1]), QuorumMode::Single);
        assert_eq!(outcome.ack_count(), 1);
    }

    // -- Timeout via QuorumImpossible path ---------------------------------

    #[test]
    fn all_targets_error_yields_quorum_impossible() {
        let t = MockTransport::new();
        t.set_error(1, "offline");
        t.set_error(2, "offline");
        t.set_error(3, "offline");
        let mut handle = ReplicationWriteHandle::new(t);
        let outcome = handle.submit_write(b"data", &member_ids(&[1, 2, 3]), QuorumMode::Majority);
        assert!(!outcome.is_quorum_reached());
        match outcome {
            ReplicationWriteOutcome::QuorumShortfall { reason, .. } => {
                assert!(matches!(
                    reason,
                    QuorumShortfallReason::QuorumImpossible { .. }
                ));
            }
            other => panic!("expected QuorumShortfall, got {other:?}"),
        }
    }
}
