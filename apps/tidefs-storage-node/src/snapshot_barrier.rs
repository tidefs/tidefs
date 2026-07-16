// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Multi-node snapshot barrier protocol for cross-node consistency.
//!
//! ## Problem
//!
//! When a coordinator cuts a snapshot in a multi-node TideFS cluster,
//! concurrent writers on different storage nodes must be quiesced so
//! the snapshot's committed root references data that is durable and
//! consistent across every node. Without a barrier, a snapshot may
//! reference object data that has not yet been committed on a remote
//! node, breaking the "import on a different node" close standard.
//!
//! ## Protocol
//!
//! 1. **Coordinator** assigns a monotonic `barrier_id` and sends
//!    `Frame::SnapshotBarrier { barrier_id, ref snapshot_name }` to every
//!    peer in the current membership roster.
//! 2. **Peer** receives the barrier, drains pending writes to its
//!    local object store (sync/flush), captures its committed-root
//!    transaction-group id and generation, and responds with
//!    `Frame::SnapshotBarrierResponse { barrier_id, committed_root_txg,
//!    committed_root_generation, object_count }`.
//! 3. **Coordinator** collects responses from all peers. If all peers
//!    respond and report committed roots consistent with the
//!    coordinator's own state, the snapshot is safe to cut. If any
//!    peer times out or reports an inconsistent state, the barrier
//!    fails and the snapshot is refused.
//!
//! ## Integration
//!
//! This module defines the protocol types, a coordinator-side
//! `BarrierCollector`, and a peer-side `BarrierHandler` trait.
//! The actual dispatch is wired in `server.rs` through the existing
//! `handle_frame_ctx` function.
//!
//! ## Validation tier
//!
//! Tier 1 (cargo/unit): module compiles, roundtrip tests pass.
//! Tier 7 (multi-node runtime): requires a live cluster with
//! concurrent writers, real barrier dispatch, and retained
//! cross-node snapshot import validation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::protocol::{encode, Frame};

// ---------------------------------------------------------------------------
// BarrierId
// ---------------------------------------------------------------------------

/// Monotonic barrier identifier assigned by the coordinator.
pub type BarrierId = u64;

static NEXT_BARRIER_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a process-local monotonic barrier id for coordinator-initiated rounds.
pub fn allocate_barrier_id() -> BarrierId {
    NEXT_BARRIER_ID.fetch_add(1, Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// SnapshotBarrierConfig
// ---------------------------------------------------------------------------

/// Configuration for the snapshot barrier protocol.
#[derive(Clone, Debug)]
pub struct SnapshotBarrierConfig {
    /// Maximum time to wait for a single peer's response.
    pub peer_timeout: Duration,
    /// Maximum number of peers the barrier will wait for.
    pub max_peers: usize,
}

impl Default for SnapshotBarrierConfig {
    fn default() -> Self {
        Self {
            peer_timeout: Duration::from_secs(30),
            max_peers: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// BarrierResponse — collected peer response
// ---------------------------------------------------------------------------

/// A peer's response to a snapshot barrier request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierResponse {
    /// Peer's node id (from membership roster).
    pub peer_id: u64,
    /// Matching barrier id from the request.
    pub barrier_id: BarrierId,
    /// The peer's committed-root transaction-group id.
    pub committed_root_txg: u64,
    /// The peer's committed-root generation.
    pub committed_root_generation: u64,
    /// Objects in the peer's store at the barrier point.
    pub object_count: u64,
    /// Wall-clock time when the response was received.
    pub received_at: Instant,
}

impl BarrierResponse {
    /// Build a response from a decoded `Frame::SnapshotBarrierResponse`.
    pub fn from_frame(peer_id: u64, frame: &Frame) -> Option<Self> {
        match frame {
            Frame::SnapshotBarrierResponse {
                barrier_id,
                committed_root_txg,
                committed_root_generation,
                object_count,
            } => Some(Self {
                peer_id,
                barrier_id: *barrier_id,
                committed_root_txg: *committed_root_txg,
                committed_root_generation: *committed_root_generation,
                object_count: *object_count,
                received_at: Instant::now(),
            }),
            _ => None,
        }
    }

    /// Encode this response as a transport-ready frame.
    pub fn to_frame(&self) -> Frame {
        Frame::SnapshotBarrierResponse {
            barrier_id: self.barrier_id,
            committed_root_txg: self.committed_root_txg,
            committed_root_generation: self.committed_root_generation,
            object_count: self.object_count,
        }
    }
}

// ---------------------------------------------------------------------------
// BarrierCollector — coordinator-side response collector
// ---------------------------------------------------------------------------

/// Collects snapshot barrier responses from peers.
///
/// The coordinator creates one `BarrierCollector` per snapshot barrier
/// round. It records responses or explicit failures as they arrive and
/// provides an `is_complete()` check plus an `outcome()` that summarises the
/// result.
#[derive(Debug)]
pub struct BarrierCollector {
    /// Barrier id for this round.
    pub barrier_id: BarrierId,
    /// Snapshot name being created.
    pub snapshot_name: String,
    /// Expected peer ids (from membership roster).
    expected_peers: Vec<u64>,
    /// Responses received so far, keyed by peer_id.
    responses: BTreeMap<u64, BarrierResponse>,
    /// Peer-side failures received during the barrier, keyed by peer_id.
    failures: BTreeMap<u64, String>,
    /// Wall-clock time when the collector was created.
    started_at: Instant,
    /// Configuration for this barrier.
    config: SnapshotBarrierConfig,
}

/// Outcome of a snapshot barrier round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BarrierOutcome {
    /// All peers responded and committed roots are consistent.
    Consistent {
        /// The minimum committed-root txg across all peers.
        min_txg: u64,
        /// The maximum committed-root txg across all peers.
        max_txg: u64,
        /// Total object count across all peers.
        total_objects: u64,
        /// Per-peer responses.
        responses: BTreeMap<u64, BarrierResponse>,
    },
    /// One or more peers timed out.
    Timeout {
        /// Peers that responded before timeout.
        responded: Vec<u64>,
        /// Peers that did not respond.
        missing: Vec<u64>,
    },
    /// Committed roots are inconsistent (txg or generation mismatch).
    Inconsistent {
        min_txg: u64,
        max_txg: u64,
        min_generation: u64,
        max_generation: u64,
        responses: BTreeMap<u64, BarrierResponse>,
    },
    /// A peer reported an explicit barrier failure.
    Failed { peer_id: u64, reason: String },
}

/// Successful pre-send snapshot barrier summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotBarrierSendReport {
    pub barrier_id: BarrierId,
    /// Remote peers that participated; this count excludes the coordinator.
    pub peer_count: usize,
    pub min_txg: u64,
    pub max_txg: u64,
    /// Objects reported across the coordinator and all remote peers.
    pub total_objects: u64,
}

/// Pre-send barrier failure that must abort VFSSEND2 transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotBarrierSendError {
    AlreadyActive {
        barrier_id: BarrierId,
    },
    LocalSyncFailed {
        barrier_id: BarrierId,
        reason: String,
    },
    PeerLimitExceeded {
        barrier_id: BarrierId,
        peer_count: usize,
        max_peers: usize,
    },
    MembershipPeerUnavailable {
        barrier_id: BarrierId,
        peer_ids: Vec<u64>,
    },
    SendFailed {
        barrier_id: BarrierId,
        peer_id: u64,
        reason: String,
    },
    Interrupted {
        barrier_id: BarrierId,
    },
    PeerFailed {
        barrier_id: BarrierId,
        peer_id: u64,
        reason: String,
    },
    Timeout {
        barrier_id: BarrierId,
        responded: Vec<u64>,
        missing: Vec<u64>,
    },
    Inconsistent {
        barrier_id: BarrierId,
        min_txg: u64,
        max_txg: u64,
        min_generation: u64,
        max_generation: u64,
    },
}

impl fmt::Display for SnapshotBarrierSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive { barrier_id } => write!(
                f,
                "barrier {barrier_id} refused because another barrier is already active"
            ),
            Self::LocalSyncFailed { barrier_id, reason } => {
                write!(f, "barrier {barrier_id} local store sync failed: {reason}")
            }
            Self::PeerLimitExceeded {
                barrier_id,
                peer_count,
                max_peers,
            } => write!(
                f,
                "barrier {barrier_id} refused because peer count {peer_count} exceeds configured maximum {max_peers}"
            ),
            Self::MembershipPeerUnavailable {
                barrier_id,
                peer_ids,
            } => write!(
                f,
                "barrier {barrier_id} membership_peer_unavailable: no eligible storage session for active roster peers {peer_ids:?}"
            ),
            Self::SendFailed {
                barrier_id,
                peer_id,
                reason,
            } => write!(
                f,
                "barrier {barrier_id} send to peer {peer_id} failed: {reason}"
            ),
            Self::Interrupted { barrier_id } => {
                write!(f, "barrier {barrier_id} interrupted before completion")
            }
            Self::PeerFailed {
                barrier_id,
                peer_id,
                reason,
            } => write!(
                f,
                "barrier {barrier_id} peer {peer_id} failed before responding: {reason}"
            ),
            Self::Timeout {
                barrier_id,
                responded,
                missing,
            } => write!(
                f,
                "barrier {barrier_id} timed out; responded={responded:?} missing={missing:?}"
            ),
            Self::Inconsistent {
                barrier_id,
                min_txg,
                max_txg,
                min_generation,
                max_generation,
            } => write!(
                f,
                "barrier {barrier_id} inconsistent committed-root txg range {min_txg}..{max_txg}, generation range {min_generation}..{max_generation}"
            ),
        }
    }
}

/// Convert a completed barrier outcome into the mandatory pre-send gate result.
pub fn snapshot_barrier_send_report(
    barrier_id: BarrierId,
    outcome: BarrierOutcome,
) -> Result<SnapshotBarrierSendReport, SnapshotBarrierSendError> {
    match outcome {
        BarrierOutcome::Consistent {
            min_txg,
            max_txg,
            total_objects,
            responses,
        } => Ok(SnapshotBarrierSendReport {
            barrier_id,
            peer_count: responses.len(),
            min_txg,
            max_txg,
            total_objects,
        }),
        BarrierOutcome::Timeout { responded, missing } => Err(SnapshotBarrierSendError::Timeout {
            barrier_id,
            responded,
            missing,
        }),
        BarrierOutcome::Inconsistent {
            min_txg,
            max_txg,
            min_generation,
            max_generation,
            ..
        } => Err(SnapshotBarrierSendError::Inconsistent {
            barrier_id,
            min_txg,
            max_txg,
            min_generation,
            max_generation,
        }),
        BarrierOutcome::Failed { peer_id, reason } => Err(SnapshotBarrierSendError::PeerFailed {
            barrier_id,
            peer_id,
            reason,
        }),
    }
}

impl BarrierCollector {
    /// Create a new barrier collector for the given peer set.
    pub fn new(
        barrier_id: BarrierId,
        snapshot_name: String,
        mut expected_peers: Vec<u64>,
        config: SnapshotBarrierConfig,
    ) -> Self {
        expected_peers.sort_unstable();
        expected_peers.dedup();

        Self {
            barrier_id,
            snapshot_name,
            expected_peers,
            responses: BTreeMap::new(),
            failures: BTreeMap::new(),
            started_at: Instant::now(),
            config,
        }
    }

    /// Encode the barrier request frame for a peer.
    pub fn make_request_frame(&self) -> Frame {
        Frame::SnapshotBarrier {
            barrier_id: self.barrier_id,
            snapshot_name: self.snapshot_name.clone(),
        }
    }

    /// Encode the barrier request as raw bytes (for transport send).
    pub fn encode_request(&self) -> Vec<u8> {
        encode(&self.make_request_frame())
    }

    /// Record a peer's response. Returns `true` if the response was
    /// accepted (correct barrier_id, expected peer, not already recorded).
    pub fn record_response(&mut self, response: BarrierResponse) -> bool {
        if response.barrier_id != self.barrier_id {
            return false;
        }
        if self.is_timed_out() {
            return false;
        }
        if !self.expected_peers.contains(&response.peer_id) {
            return false;
        }
        if self.responses.contains_key(&response.peer_id) {
            return false;
        }
        if self.failures.contains_key(&response.peer_id) {
            return false;
        }
        self.responses.insert(response.peer_id, response);
        true
    }

    /// Record a peer-side barrier failure. Returns `true` if accepted.
    pub fn record_failure(&mut self, peer_id: u64, reason: String) -> bool {
        if self.is_timed_out() {
            return false;
        }
        if !self.expected_peers.contains(&peer_id) {
            return false;
        }
        if self.responses.contains_key(&peer_id) {
            return false;
        }
        if self.failures.contains_key(&peer_id) {
            return false;
        }
        self.failures.insert(peer_id, reason);
        true
    }

    /// Number of responses received so far.
    pub fn responded_count(&self) -> usize {
        self.responses.len()
    }

    /// Number of peers still outstanding.
    pub fn missing_count(&self) -> usize {
        self.expected_peers
            .len()
            .saturating_sub(self.responses.len() + self.failures.len())
    }

    /// Whether all expected peers have responded or failed.
    pub fn is_complete(&self) -> bool {
        self.responses.len() + self.failures.len() == self.expected_peers.len()
    }

    /// Whether the barrier has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.started_at.elapsed() >= self.config.peer_timeout
    }

    /// Evaluate the barrier outcome.
    ///
    /// Returns `None` if the barrier is still in progress (not
    /// complete and not timed out).
    pub fn outcome(&self) -> Option<BarrierOutcome> {
        if let Some((&peer_id, reason)) = self.failures.iter().next() {
            Some(BarrierOutcome::Failed {
                peer_id,
                reason: reason.clone(),
            })
        } else if self.is_complete() {
            let min_txg = self
                .responses
                .values()
                .map(|r| r.committed_root_txg)
                .min()
                .unwrap_or(0);
            let max_txg = self
                .responses
                .values()
                .map(|r| r.committed_root_txg)
                .max()
                .unwrap_or(0);
            let min_generation = self
                .responses
                .values()
                .map(|r| r.committed_root_generation)
                .min()
                .unwrap_or(0);
            let max_generation = self
                .responses
                .values()
                .map(|r| r.committed_root_generation)
                .max()
                .unwrap_or(0);
            let total_objects: u64 = self.responses.values().map(|r| r.object_count).sum();

            // Consistency check: all peers must report the same
            // committed-root txg and generation. Any spread indicates a
            // peer advanced while the barrier was in flight.
            if max_txg == min_txg && max_generation == min_generation {
                Some(BarrierOutcome::Consistent {
                    min_txg,
                    max_txg,
                    total_objects,
                    responses: self.responses.clone(),
                })
            } else {
                Some(BarrierOutcome::Inconsistent {
                    min_txg,
                    max_txg,
                    min_generation,
                    max_generation,
                    responses: self.responses.clone(),
                })
            }
        } else if self.is_timed_out() {
            let responded: Vec<u64> = self.responses.keys().copied().collect();
            let missing: Vec<u64> = self
                .expected_peers
                .iter()
                .filter(|id| !self.responses.contains_key(id) && !self.failures.contains_key(id))
                .copied()
                .collect();
            Some(BarrierOutcome::Timeout { responded, missing })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// BarrierHandler — trait for peer-side barrier processing
// ---------------------------------------------------------------------------

/// Trait that storage-node servers implement to handle incoming
/// snapshot barrier requests.
///
/// The server calls `handle_barrier` when it receives a
/// `Frame::SnapshotBarrier`, and responds with the encoded
/// `Frame::SnapshotBarrierResponse`.
pub trait BarrierHandler {
    /// Process a snapshot barrier request.
    ///
    /// The implementation should:
    /// 1. Sync/flush the local object store to drain pending writes.
    /// 2. Capture the current committed-root txg and generation.
    /// 3. Return the barrier response.
    fn handle_barrier(&mut self, barrier_id: BarrierId, snapshot_name: &str) -> BarrierResponse;
}

// ---------------------------------------------------------------------------
// SnapshotCoordinator — coordinator-side barrier execution
// ---------------------------------------------------------------------------

/// Executes a snapshot barrier across a set of peers.
///
/// The coordinator:
/// 1. Creates a `BarrierCollector` for the peer set.
/// 2. Encodes the barrier request frame.
/// 3. Fans out the request to every peer via a caller-supplied send
///    function.
/// 4. Collects responses with a deadline.
/// 5. Evaluates the `BarrierOutcome`.
///
/// Sending and receiving are abstracted behind closures so the
/// coordinator can work with any transport backend (TCP, RDMA,
/// deterministic harness, loopback).
pub struct SnapshotCoordinator {
    collector: BarrierCollector,
}

/// Error conditions for coordinator operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    /// The barrier round has already completed or timed out.
    RoundClosed,
    /// A send to a peer failed.
    SendFailed { peer_id: u64, reason: String },
    /// The barrier timed out before all peers responded.
    Timeout,
    /// Committed roots are inconsistent across peers.
    Inconsistent,
}

impl SnapshotCoordinator {
    /// Create a new coordinator for a single barrier round.
    pub fn new(
        barrier_id: BarrierId,
        snapshot_name: String,
        expected_peers: Vec<u64>,
        config: SnapshotBarrierConfig,
    ) -> Self {
        Self {
            collector: BarrierCollector::new(barrier_id, snapshot_name, expected_peers, config),
        }
    }

    /// Return the active barrier id for diagnostics and refusal paths.
    pub fn barrier_id(&self) -> BarrierId {
        self.collector.barrier_id
    }

    /// Return the encoded barrier request frame bytes (for fanout).
    pub fn request_bytes(&self) -> Vec<u8> {
        self.collector.encode_request()
    }

    /// Return the barrier request frame.
    pub fn request_frame(&self) -> Frame {
        self.collector.make_request_frame()
    }

    /// Fan out the barrier request to all peers.
    ///
    /// Calls `send_fn(peer_id, request_bytes)` for every peer in the
    /// expected set. Returns the number of successful sends. The first
    /// send failure aborts the round so callers do not continue a
    /// barrier that never reached an expected peer.
    pub fn fanout<E: std::fmt::Display>(
        &self,
        mut send_fn: impl FnMut(u64, Vec<u8>) -> Result<(), E>,
    ) -> Result<usize, CoordinatorError> {
        let request_bytes = self.collector.encode_request();
        let mut sent = 0;
        for &peer_id in &self.collector.expected_peers {
            match send_fn(peer_id, request_bytes.clone()) {
                Ok(()) => sent += 1,
                Err(e) => {
                    return Err(CoordinatorError::SendFailed {
                        peer_id,
                        reason: e.to_string(),
                    });
                }
            }
        }
        Ok(sent)
    }

    /// Record a peer's decoded barrier response.
    ///
    /// Returns `true` if the response was accepted (correct barrier_id
    /// and peer in the expected set).
    pub fn record_response(&mut self, peer_id: u64, response_frame: &Frame) -> bool {
        if let Some(resp) = BarrierResponse::from_frame(peer_id, response_frame) {
            self.collector.record_response(resp)
        } else {
            false
        }
    }

    /// Record a peer-side barrier failure.
    ///
    /// Returns `true` if the failure was accepted (peer in the expected
    /// set and not already recorded).
    pub fn record_failure(&mut self, peer_id: u64, reason: String) -> bool {
        self.collector.record_failure(peer_id, reason)
    }

    /// Number of responses received so far.
    pub fn responded_count(&self) -> usize {
        self.collector.responded_count()
    }

    /// Number of peers still outstanding.
    pub fn missing_count(&self) -> usize {
        self.collector.missing_count()
    }

    /// Whether all expected peers have responded or failed.
    pub fn is_complete(&self) -> bool {
        self.collector.is_complete()
    }

    /// Whether the barrier has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.collector.is_timed_out()
    }

    /// Evaluate the barrier outcome.
    ///
    /// Returns `None` if the round is still in progress.
    pub fn outcome(&self) -> Option<BarrierOutcome> {
        self.collector.outcome()
    }

    /// Wait for all peers to respond or the barrier to time out.
    ///
    /// This is a polling-based wait. Callers should invoke this in a
    /// loop or use it with an async runtime.
    ///
    /// Returns the outcome once the round is complete or timed out.
    pub fn wait_for_outcome(&mut self) -> BarrierOutcome {
        loop {
            if let Some(outcome) = self.collector.outcome() {
                return outcome;
            }
            std::thread::yield_now();
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// BarrierStore — abstraction for peer-side store sync and stats
// ---------------------------------------------------------------------------

/// Trait that abstracts the store backend for snapshot barrier handling.
///
/// The storage-node server implements this for its `StoreBackend` enum
/// so the barrier handler can sync the store, capture stats, and return
/// a `Frame::SnapshotBarrierResponse` without coupling to specific store
/// types.
pub trait BarrierStore {
    /// Sync all pending writes to durable storage.
    fn sync_all(&mut self) -> Result<(), String>;

    /// Number of live objects in the store at this moment.
    fn object_count(&self) -> u64;

    /// Transaction-group id of the most recently committed root.
    /// Returns 0 if no root has been committed yet.
    fn committed_root_txg(&self) -> u64;

    /// Monotonic generation counter incremented on each txg commit.
    fn committed_root_generation(&self) -> u64;
}

// ---------------------------------------------------------------------------
// BarrierState — peer-side barrier round tracking
// ---------------------------------------------------------------------------

/// Per-server state for snapshot barrier rounds.
///
/// Tracks a monotonic generation counter and the last barrier id
/// processed. The generation counter serves as the `committed_root_generation`
/// in barrier responses until the store backend exposes real txg/generation
/// values.
///
/// Thread-safe: uses atomic operations for the counter.
pub struct BarrierState {
    /// Monotonic counter incremented on each barrier round.
    generation: AtomicU64,
    /// Last barrier id processed (for idempotency).
    last_barrier_id: AtomicU64,
}

impl BarrierState {
    /// Create a new barrier state starting at generation 0.
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            last_barrier_id: AtomicU64::new(0),
        }
    }

    /// Allocate the next generation number for a barrier round.
    ///
    /// Returns the new generation value. Thread-safe.
    pub fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Return the current generation without advancing.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Record the last barrier id processed.
    pub fn set_last_barrier_id(&self, barrier_id: u64) {
        self.last_barrier_id.store(barrier_id, Ordering::SeqCst);
    }

    /// Return the last barrier id processed.
    pub fn last_barrier_id(&self) -> u64 {
        self.last_barrier_id.load(Ordering::SeqCst)
    }
}

impl Default for BarrierState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// process_barrier_request — peer-side handler helper
// ---------------------------------------------------------------------------

/// Process a snapshot barrier request against a store backend.
///
/// Syncs the store, captures stats, and returns a
/// `Frame::SnapshotBarrierResponse` with real committed-root values.
///
/// The `barrier_state` provides the generation counter; `store` provides
/// the object count and committed-root txg.
pub fn process_barrier_request(
    barrier_id: u64,
    store: &mut dyn BarrierStore,
    barrier_state: &BarrierState,
) -> Result<Frame, String> {
    // Sync before capturing stats so the response reflects durable state.
    store.sync_all()?;
    let generation = barrier_state.next_generation();
    barrier_state.set_last_barrier_id(barrier_id);
    let txg = store.committed_root_txg();

    Ok(Frame::SnapshotBarrierResponse {
        barrier_id,
        committed_root_txg: txg,
        committed_root_generation: generation,
        object_count: store.object_count(),
    })
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode, encode};

    // ── Frame roundtrip tests ────────────────────────────────────────

    #[test]
    fn roundtrip_snapshot_barrier_request() {
        let f = Frame::SnapshotBarrier {
            barrier_id: 42,
            snapshot_name: "pre-upgrade-snap".into(),
        };
        let decoded = decode(&encode(&f));
        assert_eq!(decoded, Some(f));
    }

    #[test]
    fn roundtrip_snapshot_barrier_request_empty_name() {
        let f = Frame::SnapshotBarrier {
            barrier_id: 1,
            snapshot_name: String::new(),
        };
        let decoded = decode(&encode(&f));
        assert_eq!(decoded, Some(f));
    }

    #[test]
    fn roundtrip_snapshot_barrier_response() {
        let f = Frame::SnapshotBarrierResponse {
            barrier_id: 42,
            committed_root_txg: 100,
            committed_root_generation: 7,
            object_count: 1234,
        };
        let decoded = decode(&encode(&f));
        assert_eq!(decoded, Some(f));
    }

    #[test]
    fn roundtrip_snapshot_barrier_response_zeroes() {
        let f = Frame::SnapshotBarrierResponse {
            barrier_id: 0,
            committed_root_txg: 0,
            committed_root_generation: 0,
            object_count: 0,
        };
        let decoded = decode(&encode(&f));
        assert_eq!(decoded, Some(f));
    }

    // ── BarrierCollector tests ───────────────────────────────────────

    fn make_config() -> SnapshotBarrierConfig {
        SnapshotBarrierConfig {
            peer_timeout: Duration::from_secs(60),
            max_peers: 8,
        }
    }

    fn make_response(
        peer_id: u64,
        barrier_id: u64,
        txg: u64,
        gen: u64,
        count: u64,
    ) -> BarrierResponse {
        BarrierResponse {
            peer_id,
            barrier_id,
            committed_root_txg: txg,
            committed_root_generation: gen,
            object_count: count,
            received_at: Instant::now(),
        }
    }

    #[test]
    fn collector_starts_incomplete() {
        let c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(!c.is_complete());
        assert_eq!(c.responded_count(), 0);
        assert_eq!(c.missing_count(), 2);
        assert!(c.outcome().is_none());
    }

    #[test]
    fn collector_deduplicates_expected_peers() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![20, 10, 10, 20], make_config());
        assert!(!c.is_complete());
        assert_eq!(c.missing_count(), 2);

        assert!(c.record_response(make_response(10, 1, 100, 5, 10)));
        assert!(!c.is_complete());
        assert_eq!(c.missing_count(), 1);

        assert!(c.record_response(make_response(20, 1, 100, 5, 20)));
        assert!(c.is_complete());
        assert_eq!(c.missing_count(), 0);

        match c.outcome() {
            Some(BarrierOutcome::Consistent { responses, .. }) => {
                assert_eq!(responses.len(), 2);
            }
            other => panic!("expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn collector_rejects_wrong_barrier_id() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10], make_config());
        let r = make_response(10, 99, 100, 5, 0); // wrong barrier_id
        assert!(!c.record_response(r));
        assert_eq!(c.responded_count(), 0);
    }

    #[test]
    fn collector_rejects_unknown_peer() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10], make_config());
        let r = make_response(99, 1, 100, 5, 0); // peer 99 not expected
        assert!(!c.record_response(r));
        assert_eq!(c.responded_count(), 0);
    }

    #[test]
    fn collector_rejects_duplicate_peer_response() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(c.record_response(make_response(10, 1, 100, 5, 10)));
        assert!(!c.record_response(make_response(10, 1, 200, 5, 99)));
        assert_eq!(c.responded_count(), 1);

        match c.responses.get(&10) {
            Some(response) => {
                assert_eq!(response.committed_root_txg, 100);
                assert_eq!(response.object_count, 10);
            }
            None => panic!("expected response from peer 10"),
        }
    }

    #[test]
    fn collector_records_peer_failure() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10], make_config());

        assert!(c.record_failure(10, "sync failed".into()));
        assert_eq!(c.responded_count(), 0);
        assert_eq!(c.missing_count(), 0);
        assert!(c.is_complete());
        assert!(!c.record_response(make_response(10, 1, 100, 5, 10)));

        match c.outcome() {
            Some(BarrierOutcome::Failed { peer_id, reason }) => {
                assert_eq!(peer_id, 10);
                assert_eq!(reason, "sync failed");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn collector_rejects_late_response_after_timeout() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(c.record_response(make_response(10, 1, 100, 5, 10)));
        c.started_at = Instant::now() - c.config.peer_timeout - Duration::from_secs(1);

        assert!(!c.record_response(make_response(20, 1, 100, 5, 20)));
        assert_eq!(c.responded_count(), 1);
        assert_eq!(
            c.outcome(),
            Some(BarrierOutcome::Timeout {
                responded: vec![10],
                missing: vec![20],
            })
        );
    }

    #[test]
    fn collector_rejects_late_failure_after_timeout() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(c.record_response(make_response(10, 1, 100, 5, 10)));
        c.started_at = Instant::now() - c.config.peer_timeout - Duration::from_secs(1);

        assert!(!c.record_failure(20, "late failure".into()));
        assert_eq!(c.missing_count(), 1);
        assert_eq!(
            c.outcome(),
            Some(BarrierOutcome::Timeout {
                responded: vec![10],
                missing: vec![20],
            })
        );
    }

    #[test]
    fn collector_completes_with_all_responses() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20, 30], make_config());
        assert!(c.record_response(make_response(10, 1, 100, 5, 10)));
        assert!(!c.is_complete());
        assert!(c.record_response(make_response(20, 1, 100, 5, 20)));
        assert!(c.record_response(make_response(30, 1, 100, 5, 30)));
        assert!(c.is_complete());
        assert_eq!(c.missing_count(), 0);
    }

    #[test]
    fn collector_outcome_consistent() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        c.record_response(make_response(10, 1, 100, 5, 10));
        c.record_response(make_response(20, 1, 100, 5, 20));
        match c.outcome() {
            Some(BarrierOutcome::Consistent {
                min_txg,
                max_txg,
                total_objects,
                ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 100);
                assert_eq!(total_objects, 30);
            }
            other => panic!("expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn collector_outcome_inconsistent_with_one_txg_difference() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        c.record_response(make_response(10, 1, 100, 5, 10));
        c.record_response(make_response(20, 1, 101, 5, 20));
        match c.outcome() {
            Some(BarrierOutcome::Inconsistent {
                min_txg, max_txg, ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 101);
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    #[test]
    fn collector_outcome_inconsistent_with_generation_difference() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        c.record_response(make_response(10, 1, 100, 5, 10));
        c.record_response(make_response(20, 1, 100, 6, 20));
        match c.outcome() {
            Some(BarrierOutcome::Inconsistent {
                min_txg,
                max_txg,
                min_generation,
                max_generation,
                ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 100);
                assert_eq!(min_generation, 5);
                assert_eq!(max_generation, 6);
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    #[test]
    fn collector_outcome_inconsistent_wide_txg_spread() {
        let mut c = BarrierCollector::new(1, "snap".into(), vec![10, 20], make_config());
        c.record_response(make_response(10, 1, 100, 5, 10));
        c.record_response(make_response(20, 1, 200, 5, 20));
        match c.outcome() {
            Some(BarrierOutcome::Inconsistent {
                min_txg, max_txg, ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 200);
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    #[test]
    fn barrier_response_from_frame() {
        let frame = Frame::SnapshotBarrierResponse {
            barrier_id: 7,
            committed_root_txg: 42,
            committed_root_generation: 3,
            object_count: 99,
        };
        let resp = BarrierResponse::from_frame(10, &frame).unwrap();
        assert_eq!(resp.peer_id, 10);
        assert_eq!(resp.barrier_id, 7);
        assert_eq!(resp.committed_root_txg, 42);
        assert_eq!(resp.committed_root_generation, 3);
        assert_eq!(resp.object_count, 99);
    }

    #[test]
    fn barrier_response_from_wrong_frame() {
        let frame = Frame::Ok;
        assert!(BarrierResponse::from_frame(10, &frame).is_none());
    }

    #[test]
    fn barrier_response_to_frame_roundtrip() {
        let resp = BarrierResponse {
            peer_id: 5,
            barrier_id: 3,
            committed_root_txg: 77,
            committed_root_generation: 2,
            object_count: 500,
            received_at: Instant::now(),
        };
        let frame = resp.to_frame();
        let back = BarrierResponse::from_frame(5, &frame).unwrap();
        assert_eq!(back.barrier_id, 3);
        assert_eq!(back.committed_root_txg, 77);
        assert_eq!(back.committed_root_generation, 2);
        assert_eq!(back.object_count, 500);
    }

    #[test]
    fn collector_encoding_roundtrip() {
        let c = BarrierCollector::new(42, "test-snap".into(), vec![1, 2], make_config());
        let req_frame = c.make_request_frame();
        match req_frame {
            Frame::SnapshotBarrier {
                barrier_id,
                ref snapshot_name,
            } => {
                assert_eq!(barrier_id, 42);
                assert_eq!(snapshot_name, "test-snap");
            }
            other => panic!("expected SnapshotBarrier, got {other:?}"),
        }
        let encoded = c.encode_request();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, req_frame);
    }

    // ── SnapshotCoordinator tests ────────────────────────────────────

    #[test]
    fn coordinator_fanout_sends_to_all_peers() {
        let coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20, 30], make_config());
        let mut sent_to = Vec::new();
        let count = coord.fanout(|peer_id, _bytes| {
            sent_to.push(peer_id);
            Ok::<(), &str>(())
        });
        assert_eq!(count, Ok(3));
        assert_eq!(sent_to, vec![10, 20, 30]);
    }

    #[test]
    fn coordinator_fanout_fails_closed_on_send_failure() {
        let coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20, 30], make_config());
        let mut attempted = Vec::new();
        let err = coord.fanout(|peer_id, _bytes| {
            attempted.push(peer_id);
            if peer_id == 20 {
                Err("send failed")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            err,
            Err(CoordinatorError::SendFailed {
                peer_id: 20,
                reason: "send failed".into(),
            })
        );
        assert_eq!(attempted, vec![10, 20]);
    }

    #[test]
    fn coordinator_records_and_evaluates() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(!coord.is_complete());
        assert_eq!(coord.responded_count(), 0);

        let resp_frame = Frame::SnapshotBarrierResponse {
            barrier_id: 1,
            committed_root_txg: 100,
            committed_root_generation: 5,
            object_count: 10,
        };
        assert!(coord.record_response(10, &resp_frame));
        assert_eq!(coord.responded_count(), 1);
        assert!(!coord.is_complete());

        assert!(coord.record_response(20, &resp_frame));
        assert!(coord.is_complete());

        match coord.outcome() {
            Some(BarrierOutcome::Consistent {
                min_txg, max_txg, ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 100);
            }
            other => panic!("expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn coordinator_rejects_wrong_barrier_id_response() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10], make_config());
        let resp_frame = Frame::SnapshotBarrierResponse {
            barrier_id: 999, // wrong
            committed_root_txg: 100,
            committed_root_generation: 5,
            object_count: 10,
        };
        assert!(!coord.record_response(10, &resp_frame));
        assert_eq!(coord.responded_count(), 0);
    }

    #[test]
    fn coordinator_rejects_unexpected_peer_response() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10], make_config());
        let resp_frame = Frame::SnapshotBarrierResponse {
            barrier_id: 1,
            committed_root_txg: 100,
            committed_root_generation: 5,
            object_count: 10,
        };
        assert!(!coord.record_response(99, &resp_frame));
        assert_eq!(coord.responded_count(), 0);

        assert!(coord.record_response(10, &resp_frame));
        assert_eq!(coord.responded_count(), 1);
    }

    #[test]
    fn coordinator_rejects_duplicate_peer_response() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20], make_config());
        assert!(coord.record_response(
            10,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 100,
                committed_root_generation: 5,
                object_count: 10,
            },
        ));
        assert!(!coord.record_response(
            10,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 200,
                committed_root_generation: 5,
                object_count: 99,
            },
        ));
        assert_eq!(coord.responded_count(), 1);

        assert!(coord.record_response(
            20,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 100,
                committed_root_generation: 5,
                object_count: 20,
            },
        ));

        match coord.outcome() {
            Some(BarrierOutcome::Consistent {
                min_txg,
                max_txg,
                total_objects,
                ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 100);
                assert_eq!(total_objects, 30);
            }
            other => panic!("expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn coordinator_records_peer_failure() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10], make_config());

        assert!(coord.record_failure(10, "barrier failed".into()));
        assert_eq!(coord.responded_count(), 0);
        assert_eq!(coord.missing_count(), 0);
        assert!(coord.is_complete());
        assert!(!coord.record_response(
            10,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 100,
                committed_root_generation: 5,
                object_count: 10,
            },
        ));

        match coord.outcome() {
            Some(BarrierOutcome::Failed { peer_id, reason }) => {
                assert_eq!(peer_id, 10);
                assert_eq!(reason, "barrier failed");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn coordinator_fanout_uses_correct_request() {
        let coord = SnapshotCoordinator::new(42, "pre-upgrade".into(), vec![1], make_config());
        let frame = coord.request_frame();
        match frame {
            Frame::SnapshotBarrier {
                barrier_id,
                ref snapshot_name,
            } => {
                assert_eq!(barrier_id, 42);
                assert_eq!(snapshot_name, "pre-upgrade");
            }
            other => panic!("expected SnapshotBarrier, got {other:?}"),
        }

        let bytes = coord.request_bytes();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn coordinator_inconsistent_outcome() {
        let mut coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20], make_config());
        coord.record_response(
            10,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 100,
                committed_root_generation: 5,
                object_count: 10,
            },
        );
        coord.record_response(
            20,
            &Frame::SnapshotBarrierResponse {
                barrier_id: 1,
                committed_root_txg: 200,
                committed_root_generation: 5,
                object_count: 20,
            },
        );
        match coord.outcome() {
            Some(BarrierOutcome::Inconsistent {
                min_txg, max_txg, ..
            }) => {
                assert_eq!(min_txg, 100);
                assert_eq!(max_txg, 200);
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    #[test]
    fn coordinator_missing_count() {
        let coord = SnapshotCoordinator::new(1, "snap".into(), vec![10, 20, 30], make_config());
        assert_eq!(coord.missing_count(), 3);
        assert_eq!(coord.responded_count(), 0);
    }

    // ── BarrierStore mock for testing ────────────────────────────────

    struct MockStore {
        object_count: u64,
        committed_root_txg: u64,
        committed_root_generation: u64,
        sync_called: bool,
        sync_error: Option<String>,
    }

    impl MockStore {
        fn new(count: u64, txg: u64, gen: u64) -> Self {
            Self {
                object_count: count,
                committed_root_txg: txg,
                committed_root_generation: gen,
                sync_called: false,
                sync_error: None,
            }
        }

        fn with_sync_error(mut self, message: &str) -> Self {
            self.sync_error = Some(message.to_string());
            self
        }
    }

    impl BarrierStore for MockStore {
        fn sync_all(&mut self) -> Result<(), String> {
            self.sync_called = true;
            if let Some(message) = &self.sync_error {
                return Err(message.clone());
            }
            Ok(())
        }
        fn object_count(&self) -> u64 {
            self.object_count
        }
        fn committed_root_txg(&self) -> u64 {
            self.committed_root_txg
        }
        fn committed_root_generation(&self) -> u64 {
            self.committed_root_generation
        }
    }

    // ── BarrierState tests ───────────────────────────────────────────

    #[test]
    fn barrier_state_generation_is_monotonic() {
        let state = BarrierState::new();
        assert_eq!(state.current_generation(), 0);
        let g1 = state.next_generation();
        let g2 = state.next_generation();
        let g3 = state.next_generation();
        assert_eq!(g1, 1);
        assert_eq!(g2, 2);
        assert_eq!(g3, 3);
        assert_eq!(state.current_generation(), 3);
    }

    #[test]
    fn barrier_state_tracks_last_barrier_id() {
        let state = BarrierState::new();
        assert_eq!(state.last_barrier_id(), 0);
        state.set_last_barrier_id(42);
        assert_eq!(state.last_barrier_id(), 42);
        state.set_last_barrier_id(99);
        assert_eq!(state.last_barrier_id(), 99);
    }

    #[test]
    fn barrier_state_default_is_zero() {
        let state = BarrierState::default();
        assert_eq!(state.current_generation(), 0);
        assert_eq!(state.last_barrier_id(), 0);
    }

    // ── process_barrier_request tests ────────────────────────────────

    #[test]
    fn process_barrier_request_syncs_and_returns_response() {
        let mut store = MockStore::new(100, 42, 5);
        let state = BarrierState::new();
        let response = process_barrier_request(7, &mut store, &state).expect("barrier response");
        assert!(store.sync_called);
        match response {
            Frame::SnapshotBarrierResponse {
                barrier_id,
                committed_root_txg,
                committed_root_generation,
                object_count,
            } => {
                assert_eq!(barrier_id, 7);
                assert_eq!(committed_root_txg, 42);
                assert_eq!(committed_root_generation, 1);
                assert_eq!(object_count, 100);
            }
            other => panic!("expected SnapshotBarrierResponse, got {other:?}"),
        }
    }

    #[test]
    fn process_barrier_request_increments_generation() {
        let mut store = MockStore::new(0, 0, 0);
        let state = BarrierState::new();
        process_barrier_request(1, &mut store, &state).expect("barrier response");
        assert_eq!(state.current_generation(), 1);
        process_barrier_request(2, &mut store, &state).expect("barrier response");
        assert_eq!(state.current_generation(), 2);
        process_barrier_request(3, &mut store, &state).expect("barrier response");
        assert_eq!(state.current_generation(), 3);
    }

    #[test]
    fn process_barrier_request_uses_store_txg() {
        let mut store = MockStore::new(50, 999, 0);
        let state = BarrierState::new();
        let response = process_barrier_request(1, &mut store, &state).expect("barrier response");
        match response {
            Frame::SnapshotBarrierResponse {
                committed_root_txg, ..
            } => {
                assert_eq!(committed_root_txg, 999);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn process_barrier_request_zero_txg_ok() {
        let mut store = MockStore::new(10, 0, 0);
        let state = BarrierState::new();
        let response = process_barrier_request(0, &mut store, &state).expect("barrier response");
        match response {
            Frame::SnapshotBarrierResponse {
                barrier_id,
                committed_root_txg,
                committed_root_generation,
                object_count,
            } => {
                assert_eq!(barrier_id, 0);
                assert_eq!(committed_root_txg, 0);
                assert_eq!(committed_root_generation, 1);
                assert_eq!(object_count, 10);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn process_barrier_request_does_not_advance_state_on_sync_error() {
        let mut store = MockStore::new(10, 42, 5).with_sync_error("sync failed");
        let state = BarrierState::new();

        let err = process_barrier_request(9, &mut store, &state).expect_err("sync error");

        assert_eq!(err, "sync failed");
        assert!(store.sync_called);
        assert_eq!(state.current_generation(), 0);
        assert_eq!(state.last_barrier_id(), 0);
    }

    #[test]
    fn snapshot_barrier_send_report_accepts_consistent_outcome() {
        let responses = BTreeMap::from([
            (
                2,
                BarrierResponse {
                    peer_id: 2,
                    barrier_id: 7,
                    committed_root_txg: 41,
                    committed_root_generation: 5,
                    object_count: 10,
                    received_at: Instant::now(),
                },
            ),
            (
                3,
                BarrierResponse {
                    peer_id: 3,
                    barrier_id: 7,
                    committed_root_txg: 41,
                    committed_root_generation: 5,
                    object_count: 12,
                    received_at: Instant::now(),
                },
            ),
        ]);

        let report = snapshot_barrier_send_report(
            7,
            BarrierOutcome::Consistent {
                min_txg: 41,
                max_txg: 41,
                total_objects: 22,
                responses,
            },
        )
        .expect("consistent barrier admits send");

        assert_eq!(report.barrier_id, 7);
        assert_eq!(report.peer_count, 2);
        assert_eq!(report.min_txg, 41);
        assert_eq!(report.max_txg, 41);
        assert_eq!(report.total_objects, 22);
    }

    #[test]
    fn snapshot_barrier_send_report_rejects_timeout() {
        let err = snapshot_barrier_send_report(
            8,
            BarrierOutcome::Timeout {
                responded: vec![2],
                missing: vec![3],
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            SnapshotBarrierSendError::Timeout {
                barrier_id: 8,
                responded: vec![2],
                missing: vec![3],
            }
        );
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn snapshot_barrier_send_report_rejects_inconsistent() {
        let responses = BTreeMap::from([
            (
                2,
                BarrierResponse {
                    peer_id: 2,
                    barrier_id: 9,
                    committed_root_txg: 41,
                    committed_root_generation: 5,
                    object_count: 10,
                    received_at: Instant::now(),
                },
            ),
            (
                3,
                BarrierResponse {
                    peer_id: 3,
                    barrier_id: 9,
                    committed_root_txg: 41,
                    committed_root_generation: 6,
                    object_count: 12,
                    received_at: Instant::now(),
                },
            ),
        ]);

        let err = snapshot_barrier_send_report(
            9,
            BarrierOutcome::Inconsistent {
                min_txg: 41,
                max_txg: 41,
                min_generation: 5,
                max_generation: 6,
                responses,
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            SnapshotBarrierSendError::Inconsistent {
                barrier_id: 9,
                min_txg: 41,
                max_txg: 41,
                min_generation: 5,
                max_generation: 6,
            }
        );
        assert!(err.to_string().contains("inconsistent"));
        assert!(err.to_string().contains("txg range 41..41"));
        assert!(err.to_string().contains("generation range 5..6"));
    }

    #[test]
    fn snapshot_barrier_send_report_rejects_peer_failure() {
        let err = snapshot_barrier_send_report(
            10,
            BarrierOutcome::Failed {
                peer_id: 2,
                reason: "sync failed".into(),
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            SnapshotBarrierSendError::PeerFailed {
                barrier_id: 10,
                peer_id: 2,
                reason: "sync failed".into(),
            }
        );
        assert!(err.to_string().contains("peer 2 failed"));
    }
}
