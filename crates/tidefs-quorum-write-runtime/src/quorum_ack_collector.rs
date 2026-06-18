// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! QuorumAckCollector: spawns per-replica writes (simulated via threads),
//! collects acknowledgements on an mpsc channel, verifies BLAKE3 hashes,
//! and fires the quorum-satisfied signal once the threshold is met.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tidefs_quorum_write::NodeId;

use crate::quorum_decision::QuorumDecision;
use crate::quorum_write_request::{compute_blake3, QuorumWriteRequest};
use crate::replica_write_handle::ReplicaWriteHandle;

/// Per-replica acknowledgement message sent from the simulated transport
/// thread back to the collector.
#[derive(Clone, Debug)]
struct ReplicaAck {
    replica_id: NodeId,
    checksum_match: bool,
    latency: Duration,
}

/// Behaviour knob for a single replica in `QuorumAckCollector` tests.
/// Production collectors use real transport sessions; this struct
/// lets callers inject controlled replica responses.
#[derive(Clone, Debug)]
pub struct ReplicaBehavior {
    /// The replica node id.
    pub replica_id: NodeId,
    /// If true, the replica acknowledges with a matching checksum.
    pub ack: bool,
    /// If true, the replica sends a mismatched checksum (simulates corruption).
    pub mismatch: bool,
    /// If true, the replica never responds (simulates crash/timeout).
    pub silent: bool,
    /// Artificial delay in milliseconds before the replica responds.
    pub delay_ms: u64,
}

impl ReplicaBehavior {
    /// A healthy replica that acknowledges with a matching checksum.
    #[must_use]
    pub fn healthy(replica_id: NodeId) -> Self {
        Self {
            replica_id,
            ack: true,
            mismatch: false,
            silent: false,
            delay_ms: 0,
        }
    }

    /// A replica that acknowledges but with a mismatched checksum.
    #[must_use]
    pub fn mismatched(replica_id: NodeId) -> Self {
        Self {
            replica_id,
            ack: false,
            mismatch: true,
            silent: false,
            delay_ms: 0,
        }
    }

    /// A silent replica that never responds (simulates failure/timeout).
    #[must_use]
    pub fn silent(replica_id: NodeId) -> Self {
        Self {
            replica_id,
            ack: false,
            mismatch: false,
            silent: true,
            delay_ms: 0,
        }
    }

    /// Add artificial latency to this replica.
    #[must_use]
    pub fn with_delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
}

/// Collects per-replica acknowledgements and decides the quorum outcome.
///
/// # Lifecycle
///
/// 1. Construct with `QuorumAckCollector::new(request, timeout)`.
/// 2. Call `collect(behaviors)` with controlled replica behaviours
///    (production path uses real transport sessions).
/// 3. The collector spawns one thread per replica that computes its
///    local BLAKE3 hash, compares against the expected hash, and
///    sends a `ReplicaAck` through the channel.
/// 4. Once `quorum_threshold` matching acks arrive, the collector
///    returns `QuorumDecision::QuorumSatisfied`.
/// 5. If too many replicas fail/refuse, returns `QuorumFailed`.
/// 6. If the total timeout expires, returns `QuorumTimedOut`.
pub struct QuorumAckCollector {
    request: QuorumWriteRequest,
    total_timeout: Duration,
}

impl QuorumAckCollector {
    /// Create a new collector for the given request with a total deadline.
    #[must_use]
    pub fn new(request: QuorumWriteRequest, total_timeout: Duration) -> Self {
        Self {
            request,
            total_timeout,
        }
    }

    /// Collect acknowledgements from replicas using controlled behaviours.
    ///
    /// Spawns one OS thread per replica (simulating transport dispatch).
    /// Each thread computes a local BLAKE3 hash and sends the result via
    /// an mpsc channel. The collector waits for `quorum_threshold` acks
    /// with matching checksums, or fails/times out.
    ///
    /// # Panics
    ///
    /// Panics if any spawned thread panics.
    #[must_use]
    pub fn collect(&self, behaviors: &[ReplicaBehavior]) -> QuorumDecision {
        let (tx, rx): (Sender<ReplicaAck>, Receiver<ReplicaAck>) = mpsc::channel();
        let expected_hash = self.request.blake3_hash;
        let payload = self.request.payload.clone();
        let quorum_threshold = self.request.quorum_threshold;
        let target_count = behaviors.len();

        // Track per-replica handles for latency reporting
        let mut handles: Vec<ReplicaWriteHandle> = behaviors
            .iter()
            .map(|b| ReplicaWriteHandle::new(b.replica_id))
            .collect();
        let mut join_handles: Vec<JoinHandle<()>> = Vec::with_capacity(target_count);

        // Spawn one thread per replica
        for behavior in behaviors.iter() {
            let thread_tx = tx.clone();
            let payload = payload.clone();
            let delay = Duration::from_millis(behavior.delay_ms);
            let replica_id = behavior.replica_id;
            let silent = behavior.silent;
            let mismatch = behavior.mismatch;
            let ack = behavior.ack;
            let total_timeout = self.total_timeout;

            let jh = thread::spawn(move || {
                if silent {
                    // Sleep past the total timeout to simulate a hung replica
                    thread::sleep(total_timeout + Duration::from_secs(1));
                    return;
                }
                if delay > Duration::ZERO {
                    thread::sleep(delay);
                }
                let local_hash = compute_blake3(&payload);
                let checksum_match = if mismatch {
                    false
                } else if ack {
                    local_hash == expected_hash
                } else {
                    false
                };
                let send_time = if delay > Duration::ZERO {
                    delay
                } else {
                    Duration::ZERO
                };
                let _ = thread_tx.send(ReplicaAck {
                    replica_id,
                    checksum_match,
                    latency: send_time,
                });
            });
            join_handles.push(jh);
        }

        // Re-create a sender since we dropped all clones above.
        // Actually, we already dropped `tx` after the last clone. We need to
        // keep the original sender alive so we receive.
        // But the original `tx` is still in scope; we only dropped clones.
        // Wait - we dropped `tx` inside the loop. Let me fix this.
        // Actually, the code above creates `tx` before the loop, then on each
        // iteration clones it, sends the clone to the thread, then drops the
        // clone. The original `tx` is still alive in this scope. But wait,
        // we dropped `tx` (the clone created by tx.clone()) not the original.
        // Let me re-read... we do `let tx = tx.clone();` which shadows the
        // outer binding each iteration. Then `drop(tx)` drops the shadow.
        // The original `tx` (from the let binding before the loop) is still
        // alive. This is fine but confusing. Let me restructure.
        drop(tx); // Drop the original sender so rx.iter() terminates when all threads are done

        let start = std::time::Instant::now();
        let mut _ack_count: usize = 0;
        let mut matched_acks: usize = 0;
        let mut failures: Vec<NodeId> = Vec::new();

        // Collect acks until quorum met, impossible, or timeout
        loop {
            let elapsed = start.elapsed();
            if elapsed >= self.total_timeout {
                // Join all threads before returning
                for jh in join_handles {
                    let _ = jh.join();
                }
                return QuorumDecision::QuorumTimedOut {
                    acks: matched_acks,
                    required: quorum_threshold,
                };
            }

            // Check if quorum is still possible: max possible acks = matched + (target_count - matched - failures) = target_count - failures
            // If max_possible < quorum_threshold, quorum is impossible
            let remaining_targets = target_count.saturating_sub(failures.len());
            // quorum impossible when remaining_targets < quorum_threshold

            if remaining_targets < quorum_threshold {
                for jh in join_handles {
                    let _ = jh.join();
                }
                return QuorumDecision::QuorumFailed {
                    acks: matched_acks,
                    required: quorum_threshold,
                    failures,
                };
            }

            // Try to receive an ack with a short timeout to allow polling
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(ack) => {
                    _ack_count += 1;
                    // Update the corresponding replica handle
                    for h in &mut handles {
                        if h.replica_id == ack.replica_id && !h.has_responded() {
                            h.record_ack(ack.checksum_match);
                            break;
                        }
                    }
                    if ack.checksum_match {
                        matched_acks += 1;
                        if matched_acks >= quorum_threshold {
                            for jh in join_handles {
                                let _ = jh.join();
                            }
                            return QuorumDecision::QuorumSatisfied {
                                ack_count: matched_acks,
                                quorum_threshold,
                            };
                        }
                    } else {
                        // Checksum mismatch counts as a failure for quorum math
                        failures.push(ack.replica_id);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // No ack yet; loop back and check timeout/impossible conditions
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // All senders dropped (all threads finished)
                    break;
                }
            }
        }

        // Channel disconnected: all threads finished without reaching quorum
        for jh in join_handles {
            let _ = jh.join();
        }
        if matched_acks >= quorum_threshold {
            QuorumDecision::QuorumSatisfied {
                ack_count: matched_acks,
                quorum_threshold,
            }
        } else {
            QuorumDecision::QuorumFailed {
                acks: matched_acks,
                required: quorum_threshold,
                failures,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(n: u64) -> Vec<NodeId> {
        (1..=n).map(NodeId::new).collect()
    }

    fn make_request(targets: &[NodeId], threshold: usize) -> QuorumWriteRequest {
        let payload = b"test quorum payload".to_vec();
        QuorumWriteRequest::new(
            payload,
            targets.to_vec(),
            threshold,
            compute_blake3(b"test quorum payload"),
        )
    }

    #[test]
    fn all_healthy_quorum_satisfied() {
        let targets = nodes(3);
        let req = make_request(&targets, 2);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors: Vec<ReplicaBehavior> = targets
            .iter()
            .map(|n| ReplicaBehavior::healthy(*n))
            .collect();
        let decision = collector.collect(&behaviors);
        assert!(decision.is_success());
        // Quorum met at threshold (2); collector returns as soon as enough
        // matching acks arrive, which may be before all replicas respond.
        match decision {
            QuorumDecision::QuorumSatisfied {
                ack_count,
                quorum_threshold,
            } => {
                assert!(ack_count >= quorum_threshold);
                assert_eq!(quorum_threshold, 2);
            }
            _ => panic!("expected QuorumSatisfied"),
        }
    }

    #[test]
    fn single_replica_quorum() {
        let targets = vec![NodeId::new(1)];
        let req = make_request(&targets, 1);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![ReplicaBehavior::healthy(NodeId::new(1))];
        let decision = collector.collect(&behaviors);
        assert!(decision.is_success());
        assert_eq!(decision.ack_count(), 1);
    }

    #[test]
    fn checksum_mismatch_rejected() {
        let targets = nodes(3);
        let req = make_request(&targets, 2);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![
            ReplicaBehavior::healthy(NodeId::new(1)),
            ReplicaBehavior::mismatched(NodeId::new(2)),
            ReplicaBehavior::mismatched(NodeId::new(3)),
        ];
        let decision = collector.collect(&behaviors);
        match decision {
            QuorumDecision::QuorumFailed {
                acks,
                required,
                failures,
            } => {
                assert_eq!(acks, 1);
                assert_eq!(required, 2);
                assert_eq!(failures.len(), 2);
            }
            _ => panic!("expected QuorumFailed, got {decision:?}"),
        }
    }

    #[test]
    fn silent_replicas_cause_timeout() {
        // 5 replicas, need 3. 2 are silent but 2 are healthy.
        // Quorum is still possible (3 alive needed, 2+1 alive).
        // With very short timeout, collector times out before silents respond.
        let targets = nodes(5);
        let req = make_request(&targets, 3);
        let collector = QuorumAckCollector::new(req, Duration::from_millis(100));
        let behaviors = vec![
            ReplicaBehavior::healthy(NodeId::new(1)),
            ReplicaBehavior::healthy(NodeId::new(2)),
            ReplicaBehavior::silent(NodeId::new(3)),
            ReplicaBehavior::silent(NodeId::new(4)),
            ReplicaBehavior::silent(NodeId::new(5)),
        ];
        let decision = collector.collect(&behaviors);
        match decision {
            QuorumDecision::QuorumTimedOut { acks, required } => {
                assert_eq!(acks, 2); // two healthy responded
                assert_eq!(required, 3);
            }
            _ => panic!("expected QuorumTimedOut, got {decision:?}"),
        }
    }

    #[test]
    fn all_fail_path() {
        let targets = nodes(3);
        let req = make_request(&targets, 2);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![
            ReplicaBehavior::mismatched(NodeId::new(1)),
            ReplicaBehavior::mismatched(NodeId::new(2)),
            ReplicaBehavior::silent(NodeId::new(3)),
        ];
        let decision = collector.collect(&behaviors);
        match decision {
            QuorumDecision::QuorumFailed { acks, .. } => {
                assert_eq!(acks, 0);
            }
            _ => panic!("expected QuorumFailed, got {decision:?}"),
        }
    }

    #[test]
    fn three_of_five_majority() {
        let targets = nodes(5);
        let req = make_request(&targets, 3); // 5/2+1 = 3
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![
            ReplicaBehavior::healthy(NodeId::new(1)),
            ReplicaBehavior::healthy(NodeId::new(2)),
            ReplicaBehavior::healthy(NodeId::new(3)),
            ReplicaBehavior::silent(NodeId::new(4)),
            ReplicaBehavior::silent(NodeId::new(5)),
        ];
        let decision = collector.collect(&behaviors);
        assert!(decision.is_success());
        match decision {
            QuorumDecision::QuorumSatisfied {
                ack_count,
                quorum_threshold,
            } => {
                assert_eq!(ack_count, 3);
                assert_eq!(quorum_threshold, 3);
            }
            _ => panic!("expected QuorumSatisfied"),
        }
    }

    #[test]
    fn delayed_replica_still_counts() {
        let targets = nodes(3);
        let req = make_request(&targets, 2);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![
            ReplicaBehavior::healthy(NodeId::new(1)),
            ReplicaBehavior::healthy(NodeId::new(2)),
            ReplicaBehavior::healthy(NodeId::new(3)).with_delay(50),
        ];
        let decision = collector.collect(&behaviors);
        assert!(decision.is_success());
        // At least quorum_threshold (2) matching acks; delayed replica
        // may or may not arrive before collector returns at quorum.
        assert!(decision.ack_count() >= 2);
    }

    #[test]
    fn quorum_impossible_due_to_failures() {
        // 5 replicas, need 3. 4 fail (mismatched) immediately, 1 silent.
        // After 3 mismatches arrive, remaining=2 < quorum=3 => impossible.
        // This is deterministic because all non-silent replicas fail,
        // so no matching ack can ever arrive regardless of ordering.
        let targets = nodes(5);
        let req = make_request(&targets, 3);
        let collector = QuorumAckCollector::new(req, Duration::from_secs(5));
        let behaviors = vec![
            ReplicaBehavior::mismatched(NodeId::new(1)),
            ReplicaBehavior::mismatched(NodeId::new(2)),
            ReplicaBehavior::mismatched(NodeId::new(3)),
            ReplicaBehavior::mismatched(NodeId::new(4)),
            ReplicaBehavior::silent(NodeId::new(5)),
        ];
        let decision = collector.collect(&behaviors);
        match decision {
            QuorumDecision::QuorumFailed { acks, required, .. } => {
                assert_eq!(acks, 0);
                assert_eq!(required, 3);
            }
            _ => panic!("expected QuorumFailed"),
        }
    }
}
