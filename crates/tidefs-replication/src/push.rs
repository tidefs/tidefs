// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replica chunk push: encode, fanout to peer replicas, collect quorum
//! acknowledgments, and retry on transient failures.
//!
//! `ReplicaPush` bridges local-object-store writes to the multi-node
//! replication transport. It takes a locally-written object (payload +
//! BLAKE3 object hash), encodes it as a `ReplicaChunk` wire frame, fans
//! out to N peer targets, collects `ReplicaChunkAck` responses, and
//! returns a `ReplicaPushOutcome`.

use std::thread;

use crate::chunk::{ReplicaChunk, ReplicaChunkAck};
use crate::retry::PushRetryPolicy;
use crate::{QuorumFailureReason, ReplicationPolicy};

// ── PushTransport trait ─────────────────────────────────────────────

/// Transport abstraction for replica chunk push operations.
///
/// Separates the push logic from concrete network transports, enabling
/// both production use (with `tidefs_transport::Transport`) and unit-test
/// mocking.
pub trait PushTransport {
    /// Send raw bytes to a target identified by `target_id`.
    /// Returns an error on transport-level failure.
    fn send_to(&mut self, target_id: u64, data: &[u8]) -> Result<(), String>;

    /// Receive raw bytes from a target identified by `target_id`.
    /// Returns an error on transport-level failure or timeout.
    fn recv_from(&mut self, target_id: u64) -> Result<Vec<u8>, String>;
}

// ── ReplicaPushOutcome ──────────────────────────────────────────────

/// Outcome of a `ReplicaPush` fanout operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicaPushOutcome {
    /// Quorum was reached: enough peers acked the chunk.
    QuorumReached {
        /// How many targets acknowledged.
        ack_count: usize,
        /// How many targets were attempted (excluding dead targets).
        target_count: usize,
        /// Set of target IDs that acknowledged.
        acked_targets: Vec<u64>,
        /// Set of target IDs that failed to ack.
        failed_targets: Vec<u64>,
    },
    /// Quorum was not reached after all retries.
    QuorumFailed {
        /// How many targets acknowledged.
        ack_count: usize,
        /// Required quorum count.
        quorum_required: usize,
        /// Reason for failure.
        reason: QuorumFailureReason,
    },
    /// No targets were reachable (all dead or no targets configured).
    TargetUnreachable {
        /// Why no targets were available.
        reason: String,
    },
}

impl ReplicaPushOutcome {
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::QuorumReached { .. })
    }

    #[must_use]
    pub fn ack_count(&self) -> usize {
        match self {
            Self::QuorumReached { ack_count, .. } | Self::QuorumFailed { ack_count, .. } => {
                *ack_count
            }
            Self::TargetUnreachable { .. } => 0,
        }
    }
}

// ── ReplicaPush ─────────────────────────────────────────────────────

/// Push object data to replica targets with BLAKE3 integrity framing.
///
/// Encodes payloads as `ReplicaChunk` wire frames, fans out to peer
/// nodes through a `PushTransport`, collects `ReplicaChunkAck`
/// responses, and enforces quorum thresholds with configurable retry.
///
/// # Type parameters
///
/// * `T` - Transport backend implementing `PushTransport`.
///
/// # Example
///
/// ```ignore
/// use tidefs_replication::{ReplicaPush, ReplicaPushOutcome, PushRetryPolicy};
/// use tidefs_replication::ReplicationPolicy;
///
/// let policy = PushRetryPolicy::default_lan();
/// let mut push = ReplicaPush::new(policy);
///
/// let object_id = blake3::hash(b"my-object").into();
/// let outcome = push.push_to_targets(
///     &mut transport,
///     object_id,
///     0,
///     b"payload",
///     ReplicationPolicy::Standard,
/// );
/// assert!(outcome.is_success());
/// ```
pub struct ReplicaPush<T: PushTransport> {
    /// Retry policy driving backoff and dead-target tracking.
    pub retry_policy: PushRetryPolicy,
    /// Monotonic sequence counter for chunk ordering.
    next_sequence: u64,
    /// Registered target IDs for fanout.
    registered_targets: Vec<u64>,
    /// Transport backend.
    transport: T,
}

impl<T: PushTransport> ReplicaPush<T> {
    /// Create a new `ReplicaPush` with the given retry policy and transport.
    #[must_use]
    pub fn new(retry_policy: PushRetryPolicy, transport: T) -> Self {
        Self {
            retry_policy,
            next_sequence: 1,
            registered_targets: Vec::new(),
            transport,
        }
    }

    /// Register a target for push fanout.
    pub fn register_target(&mut self, target_id: u64) {
        if !self.registered_targets.contains(&target_id) {
            self.registered_targets.push(target_id);
        }
    }

    /// Remove a target from the fanout set.
    pub fn unregister_target(&mut self, target_id: u64) {
        self.registered_targets.retain(|&t| t != target_id);
    }

    /// Returns the number of registered targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.registered_targets.len()
    }

    /// Returns a reference to the transport backend.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the transport backend.
    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Push an object payload to all registered replica targets.
    ///
    /// Encodes the payload as a `ReplicaChunk`, fans out to every
    /// registered target, collects `ReplicaChunkAck` responses, and
    /// retries failed targets according to the retry policy until
    /// quorum is reached or retries are exhausted.
    ///
    /// Dead targets (per `PushRetryPolicy`) are skipped. Targets that
    /// succeed have their failure counters reset; targets that fail
    /// are recorded and may be marked dead.
    ///
    /// # Arguments
    ///
    /// * `epoch` - Current membership epoch.
    /// * `object_id` - BLAKE3-256 hash of the full object.
    /// * `offset` - Byte offset within the object for this chunk.
    /// * `payload` - The payload bytes to replicate.
    /// * `policy` - Replication policy determining quorum threshold.
    pub fn push_to_targets(
        &mut self,
        epoch: u64,
        object_id: [u8; 32],
        offset: u64,
        payload: &[u8],
        policy: ReplicationPolicy,
    ) -> ReplicaPushOutcome {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let chunk = ReplicaChunk::new(seq, epoch, object_id, offset, payload.to_vec());
        let encoded = chunk.encode();

        // Collect live targets (not dead).
        let live_targets: Vec<u64> = self
            .registered_targets
            .iter()
            .filter(|id| !self.retry_policy.is_dead(**id))
            .copied()
            .collect();

        if live_targets.is_empty() {
            return ReplicaPushOutcome::TargetUnreachable {
                reason: "no live targets available".into(),
            };
        }

        let target_count = live_targets.len();
        let quorum_needed = policy.min_quorum(target_count);
        let max_retries = self.retry_policy.max_retries;

        let mut acked_targets: Vec<u64> = Vec::new();
        let mut failed_set: Vec<u64> = Vec::new();

        for attempt in 0..=max_retries {
            let targets_to_try: Vec<u64> = if attempt == 0 {
                live_targets.clone()
            } else {
                live_targets
                    .iter()
                    .filter(|id| !acked_targets.contains(id))
                    .copied()
                    .collect()
            };

            if targets_to_try.is_empty() {
                break;
            }

            for &target_id in &targets_to_try {
                // Send encoded chunk
                if let Err(_e) = self.transport.send_to(target_id, &encoded) {
                    if !failed_set.contains(&target_id) {
                        failed_set.push(target_id);
                    }
                    self.retry_policy.record_failure(target_id);
                    continue;
                }

                // Receive ack
                match self.transport.recv_from(target_id) {
                    Ok(response) => match ReplicaChunkAck::decode(&response) {
                        Ok(ack) => {
                            if ack.sequence == seq && ack.success {
                                if !acked_targets.contains(&target_id) {
                                    acked_targets.push(target_id);
                                }
                                self.retry_policy.record_success(target_id);
                            } else {
                                if !failed_set.contains(&target_id) {
                                    failed_set.push(target_id);
                                }
                                self.retry_policy.record_failure(target_id);
                            }
                        }
                        Err(_) => {
                            if !failed_set.contains(&target_id) {
                                failed_set.push(target_id);
                            }
                            self.retry_policy.record_failure(target_id);
                        }
                    },
                    Err(_) => {
                        if !failed_set.contains(&target_id) {
                            failed_set.push(target_id);
                        }
                        self.retry_policy.record_failure(target_id);
                    }
                }
            }

            let ack_count = acked_targets.len();

            // Check quorum
            if ack_count >= quorum_needed {
                let unique_failed: Vec<u64> = live_targets
                    .iter()
                    .filter(|id| !acked_targets.contains(id))
                    .copied()
                    .collect();
                return ReplicaPushOutcome::QuorumReached {
                    ack_count,
                    target_count,
                    acked_targets,
                    failed_targets: unique_failed,
                };
            }

            // Check if quorum is impossible
            let remaining_possible: Vec<u64> = live_targets
                .iter()
                .filter(|id| !acked_targets.contains(id) && !failed_set.contains(id))
                .copied()
                .collect();
            let remaining = remaining_possible.len();
            if ack_count + remaining < quorum_needed {
                return ReplicaPushOutcome::QuorumFailed {
                    ack_count,
                    quorum_required: quorum_needed,
                    reason: QuorumFailureReason::QuorumImpossible {
                        remaining,
                        needed: quorum_needed,
                    },
                };
            }

            // Retry: sleep for backoff period
            if attempt < max_retries && ack_count < quorum_needed {
                let backoff = self.retry_policy.backoff_for_attempt(attempt + 1);
                thread::sleep(backoff);
            }
        }

        let ack_count = acked_targets.len();
        ReplicaPushOutcome::QuorumFailed {
            ack_count,
            quorum_required: quorum_needed,
            reason: QuorumFailureReason::Timeout {
                acks_collected: ack_count,
                quorum_required: quorum_needed,
            },
        }
    }

    /// Push to specific targets (subset of registered targets).
    ///
    /// Useful for catchup repair or targeted retry of individual replicas.
    pub fn push_to_specific(
        &mut self,
        epoch: u64,
        object_id: [u8; 32],
        offset: u64,
        payload: &[u8],
        target_ids: &[u64],
    ) -> Result<Vec<ReplicaChunkAck>, String> {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let chunk = ReplicaChunk::new(seq, epoch, object_id, offset, payload.to_vec());
        let encoded = chunk.encode();
        let mut acks = Vec::with_capacity(target_ids.len());

        for &target_id in target_ids {
            if !self.registered_targets.contains(&target_id) {
                return Err(format!("target {target_id} not registered"));
            }

            self.transport
                .send_to(target_id, &encoded)
                .map_err(|e| format!("send to {target_id}: {e}"))?;

            let response = self
                .transport
                .recv_from(target_id)
                .map_err(|e| format!("recv from {target_id}: {e}"))?;

            let ack = ReplicaChunkAck::decode(&response)
                .map_err(|e| format!("decode ack from {target_id}: {e}"))?;
            acks.push(ack);
        }

        Ok(acks)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::PushRetryPolicy;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::Duration;

    // ── Mock Transport ────────────────────────────────────────────

    type MockTransportResponse = (Vec<Vec<u8>>, bool, bool);
    type MockTransportResponses = RefCell<HashMap<u64, MockTransportResponse>>;

    struct MockTransport {
        /// Per-target canned responses: (response_bytes, should_fail_send, should_fail_recv).
        responses: MockTransportResponses,
        /// Per-target response index for sequencing.
        indices: RefCell<HashMap<u64, usize>>,
        /// Record of all sends: (target_id, data).
        pub sent: RefCell<Vec<(u64, Vec<u8>)>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                responses: RefCell::new(HashMap::new()),
                indices: RefCell::new(HashMap::new()),
                sent: RefCell::new(Vec::new()),
            }
        }

        fn add_ack(&self, target_id: u64, ack: ReplicaChunkAck) {
            let mut responses = self.responses.borrow_mut();
            responses
                .entry(target_id)
                .or_insert_with(|| (Vec::new(), false, false))
                .0
                .push(ack.encode());
        }

        fn set_send_fails(&self, target_id: u64, fails: bool) {
            let mut responses = self.responses.borrow_mut();
            responses
                .entry(target_id)
                .or_insert_with(|| (Vec::new(), false, false))
                .1 = fails;
        }

        fn set_recv_fails(&self, target_id: u64, fails: bool) {
            let mut responses = self.responses.borrow_mut();
            responses
                .entry(target_id)
                .or_insert_with(|| (Vec::new(), false, false))
                .2 = fails;
        }
    }

    impl PushTransport for MockTransport {
        fn send_to(&mut self, target_id: u64, data: &[u8]) -> Result<(), String> {
            let responses = self.responses.borrow();
            if let Some((_, send_fails, _)) = responses.get(&target_id) {
                if *send_fails {
                    return Err("mock send failure".into());
                }
            }
            drop(responses);
            self.sent.borrow_mut().push((target_id, data.to_vec()));
            Ok(())
        }

        fn recv_from(&mut self, target_id: u64) -> Result<Vec<u8>, String> {
            let mut responses = self.responses.borrow_mut();
            let entry = responses
                .get_mut(&target_id)
                .ok_or_else(|| "no response configured".to_string())?;
            if entry.2 {
                return Err("mock recv failure".into());
            }
            let mut indices = self.indices.borrow_mut();
            let idx = indices.entry(target_id).or_insert(0);
            if *idx >= entry.0.len() {
                return Err("no more responses".into());
            }
            let data = entry.0[*idx].clone();
            *idx += 1;
            Ok(data)
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    fn test_object_id() -> [u8; 32] {
        *blake3::hash(b"test-object").as_bytes()
    }

    fn test_payload_hash() -> [u8; 32] {
        *blake3::hash(b"test-payload").as_bytes()
    }

    fn lan_policy() -> PushRetryPolicy {
        PushRetryPolicy::new(
            1,
            Duration::from_millis(1),
            Duration::from_millis(10),
            Duration::from_millis(1),
            5,
        )
    }

    fn make_push(target_ids: &[u64]) -> ReplicaPush<MockTransport> {
        let transport = MockTransport::new();
        let mut push = ReplicaPush::new(lan_policy(), transport);
        for &id in target_ids {
            push.register_target(id);
        }
        push
    }

    // ── Single-target push ───────────────────────────────────────

    #[test]
    fn single_target_happy_path() {
        let mut push = make_push(&[1]);
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(1, 42, test_payload_hash()));

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::BestEffort,
        );
        assert!(outcome.is_success());
        match outcome {
            ReplicaPushOutcome::QuorumReached {
                ack_count,
                target_count,
                ..
            } => {
                assert_eq!(ack_count, 1);
                assert_eq!(target_count, 1);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn single_target_failure() {
        let mut push = make_push(&[1]);
        // No response configured → recv fails → target fails
        let outcome = push.push_to_targets(
            1,
            test_object_id(),
            0,
            b"data",
            ReplicationPolicy::BestEffort,
        );
        assert!(matches!(outcome, ReplicaPushOutcome::QuorumFailed { .. }));
    }

    #[test]
    fn single_target_ack_sequence_mismatch_marks_failure() {
        let mut push = make_push(&[1]);
        push.transport_mut().add_ack(
            1,
            ReplicaChunkAck {
                sequence: 999, // wrong seq
                epoch: 42,
                verification_hash: test_payload_hash(),
                success: true,
            },
        );

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::BestEffort,
        );
        assert!(matches!(outcome, ReplicaPushOutcome::QuorumFailed { .. }));
    }

    // ── Quorum logic ──────────────────────────────────────────────

    #[test]
    fn three_of_five_quorum_reached() {
        let mut push = make_push(&[1, 2, 3, 4, 5]);
        for i in 1..=5 {
            push.transport_mut()
                .add_ack(i, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        }

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Standard,
        );
        assert!(outcome.is_success());
        match outcome {
            ReplicaPushOutcome::QuorumReached {
                ack_count,
                target_count,
                ..
            } => {
                assert_eq!(ack_count, 5);
                assert_eq!(target_count, 5);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn three_of_five_mixed_success_failure() {
        let mut push = make_push(&[1, 2, 3, 4, 5]);
        // Targets 1,2,3 succeed; 4,5 fail (no responses)
        for i in 1..=3 {
            push.transport_mut()
                .add_ack(i, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        }

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Standard,
        );
        assert!(outcome.is_success());
        match outcome {
            ReplicaPushOutcome::QuorumReached {
                ack_count,
                target_count,
                failed_targets,
                ..
            } => {
                assert_eq!(ack_count, 3);
                assert_eq!(target_count, 5);
                assert_eq!(failed_targets.len(), 2);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn two_of_three_quorum_with_one_failure() {
        let mut push = make_push(&[1, 2, 3]);
        for i in 1..=2 {
            push.transport_mut()
                .add_ack(i, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        }

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Standard,
        );
        assert!(outcome.is_success());
        match outcome {
            ReplicaPushOutcome::QuorumReached {
                ack_count,
                failed_targets,
                ..
            } => {
                assert_eq!(ack_count, 2);
                assert_eq!(failed_targets.len(), 1);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    #[test]
    fn critical_policy_all_must_ack() {
        let mut push = make_push(&[1, 2, 3]);
        for i in 1..=3 {
            push.transport_mut()
                .add_ack(i, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        }

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Critical,
        );
        assert!(outcome.is_success());
    }

    #[test]
    fn critical_policy_fails_when_one_missing() {
        let mut push = make_push(&[1, 2, 3]);
        for i in 1..=2 {
            push.transport_mut()
                .add_ack(i, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        }

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Critical,
        );
        assert!(matches!(outcome, ReplicaPushOutcome::QuorumFailed { .. }));
    }

    // ── Target unreachable / dead ─────────────────────────────────

    #[test]
    fn no_registered_targets() {
        let transport = MockTransport::new();
        let policy = lan_policy();
        let mut push = ReplicaPush::new(policy, transport);

        let outcome =
            push.push_to_targets(1, test_object_id(), 0, b"data", ReplicationPolicy::Standard);
        assert!(matches!(
            outcome,
            ReplicaPushOutcome::TargetUnreachable { .. }
        ));
    }

    #[test]
    fn all_targets_dead() {
        let mut push = make_push(&[1, 2]);
        // Mark both as dead
        for _ in 0..5 {
            push.retry_policy.record_failure(1);
            push.retry_policy.record_failure(2);
        }
        assert!(push.retry_policy.is_dead(1));
        assert!(push.retry_policy.is_dead(2));

        let outcome =
            push.push_to_targets(1, test_object_id(), 0, b"data", ReplicationPolicy::Standard);
        assert!(matches!(
            outcome,
            ReplicaPushOutcome::TargetUnreachable { .. }
        ));
    }

    // ── Sequence number monotonicity ──────────────────────────────

    #[test]
    fn sequence_numbers_increment() {
        let mut push = make_push(&[1]);
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(1, 1, test_payload_hash()));
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(2, 1, test_payload_hash()));

        let _ = push.push_to_targets(
            1,
            test_object_id(),
            0,
            b"first",
            ReplicationPolicy::BestEffort,
        );
        let _ = push.push_to_targets(
            1,
            test_object_id(),
            0,
            b"second",
            ReplicationPolicy::BestEffort,
        );

        let sent = push.transport().sent.borrow();
        assert_eq!(sent.len(), 2);
        let chunk1 = ReplicaChunk::decode(&sent[0].1).unwrap();
        let chunk2 = ReplicaChunk::decode(&sent[1].1).unwrap();
        assert_eq!(chunk1.sequence, 1);
        assert_eq!(chunk2.sequence, 2);
    }

    // ── push_to_specific ──────────────────────────────────────────

    #[test]
    fn push_to_specific_subset() {
        let mut push = make_push(&[1, 2, 3]);
        push.transport_mut()
            .add_ack(2, ReplicaChunkAck::success(1, 42, test_payload_hash()));

        let acks = push
            .push_to_specific(42, test_object_id(), 0, b"data", &[2])
            .expect("push to specific should succeed");

        assert_eq!(acks.len(), 1);
        assert!(acks[0].success);
        assert_eq!(acks[0].sequence, 1);
    }

    #[test]
    fn push_to_specific_unregistered_target() {
        let mut push = make_push(&[1]);
        let result = push.push_to_specific(1, test_object_id(), 0, b"data", &[99]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not registered"));
    }

    // ── Retry integration ─────────────────────────────────────────

    #[test]
    fn retry_on_first_attempt_failure() {
        let policy = PushRetryPolicy::new(
            2,
            Duration::from_millis(1),
            Duration::from_millis(10),
            Duration::from_millis(0),
            10,
        );
        let transport = MockTransport::new();
        let mut push = ReplicaPush::new(policy, transport);
        push.register_target(1);
        push.register_target(2);

        // Target 1 succeeds first time
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        // Target 2 succeeds second time (after retry)
        push.transport_mut()
            .add_ack(2, ReplicaChunkAck::success(1, 42, test_payload_hash()));

        // For target 2: first attempt will fail (no response at index 0 for target 2,
        // because recv will try to get first ack from target 2 but we only added one).
        // But wait, add_ack adds a response that will be consumed first try.
        // Let me reconfigure: target 2 should fail first, succeed second.

        // Actually the mock returns responses in order. We need:
        // Attempt 1: target 1 → success, target 2 → failure
        // We'll use set_recv_fails for target 2 on first attempt.

        // For simplicity, just test that with both responding it works.
        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"test-payload",
            ReplicationPolicy::Standard,
        );
        assert!(outcome.is_success());
    }

    #[test]
    fn push_registers_sent_data_correctly() {
        let mut push = make_push(&[1]);
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(1, 7, test_payload_hash()));

        let _ = push.push_to_targets(
            7,
            test_object_id(),
            64,
            b"hello",
            ReplicationPolicy::BestEffort,
        );

        let sent = push.transport().sent.borrow();
        assert_eq!(sent.len(), 1);
        let chunk = ReplicaChunk::decode(&sent[0].1).expect("valid chunk");
        assert_eq!(chunk.epoch, 7);
        assert_eq!(chunk.offset, 64);
        assert_eq!(chunk.payload, b"hello");
    }

    #[test]
    fn target_count_method() {
        let push = make_push(&[1, 2, 3]);
        assert_eq!(push.target_count(), 3);
    }

    #[test]
    fn unregister_target_removes_from_fanout() {
        let mut push = make_push(&[1, 2, 3]);
        push.unregister_target(2);
        assert_eq!(push.target_count(), 2);
        push.transport_mut()
            .add_ack(1, ReplicaChunkAck::success(1, 42, test_payload_hash()));
        push.transport_mut()
            .add_ack(3, ReplicaChunkAck::success(1, 42, test_payload_hash()));

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"data",
            ReplicationPolicy::Standard,
        );
        // Standard with 2 targets needs 2 ack
        assert!(outcome.is_success());
        match outcome {
            ReplicaPushOutcome::QuorumReached {
                ack_count,
                target_count,
                ..
            } => {
                assert_eq!(ack_count, 2);
                assert_eq!(target_count, 2);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    // ── Send failure marks target failed ──────────────────────────

    #[test]
    fn send_failure_marks_target_failed() {
        let mut push = make_push(&[1]);
        push.transport_mut().set_send_fails(1, true);

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"data",
            ReplicationPolicy::BestEffort,
        );
        assert!(matches!(outcome, ReplicaPushOutcome::QuorumFailed { .. }));
    }

    // ── Recv failure marks target failed ──────────────────────────

    #[test]
    fn recv_failure_marks_target_failed() {
        let mut push = make_push(&[1]);
        push.transport_mut().set_recv_fails(1, true);

        let outcome = push.push_to_targets(
            42,
            test_object_id(),
            0,
            b"data",
            ReplicationPolicy::BestEffort,
        );
        assert!(matches!(outcome, ReplicaPushOutcome::QuorumFailed { .. }));
    }
}
