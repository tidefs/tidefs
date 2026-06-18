// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Commit coordinator transport bridge: distributes epoch proposals to
//! peer members over transport and collects quorum acknowledgments.
//!
//! [`CommitCoordinatorTransportBridge`] implements
//! [`tidefs_membership_epoch::EpochTransitionOps`] so it plugs directly
//! into the [`tidefs_membership_epoch::MembershipEpochDriver`] without
//! coupling epoch logic to transport internals.
//!
//! ## Architecture
//!
//! ```text
//! MembershipEpochDriver
//!   |
//!   +-- EpochTransitionOps::broadcast_proposal()
//!         |
//!         +-- CommitCoordinatorTransportBridge
//!               |
//!               +-- MembershipOutboundDispatch::broadcast(ProposalSubmission)
//!                     |
//!                     +-- Transport send pipeline per peer
//!
//! Peer receives ProposalSubmission (via MembershipInboundDispatch)
//!   |
//!   +-- validate proposal against local epoch chain
//!   +-- send ProposalAck back to proposer
//!
//! Proposer receives ProposalAck (via MembershipInboundDispatch)
//!   |
//!   +-- CommitCoordinatorTransportBridge::on_ack()
//!         |
//!         +-- MembershipEpochDriver::receive_ack()
//!               |
//!               +-- quorum reached → commit → EpochTransitionOps::on_epoch_committed()
//! ```
//!
//! ## Quorum semantics
//!
//! The bridge collects acks with a configurable timeout. Quorum is
//! satisfied when a simple majority of peers have acknowledged the
//! current proposal. Duplicate acks from the same peer are idempotent
//! (counted once). Out-of-order acks for past proposals are dropped.
//!
//! ## Integration
//!
//! ```ignore
//! use tidefs_membership_live::commit_coordinator_bridge::CommitCoordinatorTransportBridge;
//! use tidefs_membership_live::membership_outbound_dispatch::MembershipOutboundDispatch;
//! use tidefs_membership_epoch::MembershipEpochDriver;
//!
//! let bridge = CommitCoordinatorTransportBridge::new(
//!     proposer_id,
//!     Box::new(my_ack_handler),
//!     outbound_dispatch,
//! );
//! let mut driver = MembershipEpochDriver::new(config, peer_count, bridge, ...);
//! ```

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::epoch_proposal::EpochProposalMessage;
use tidefs_membership_epoch::epoch_transition::EpochTransitionResult;
use tidefs_membership_epoch::MemberId;

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};

// ---------------------------------------------------------------------------
// AckCollector — quorum vote tally with duplicate suppression
// ---------------------------------------------------------------------------

/// Collects peer acknowledgments for a single proposal and determines
/// when quorum is reached.
///
/// Thread-safe: shared between the inbound dispatch handler and the
/// bridge's epoch transition callbacks.
#[derive(Debug)]
#[allow(dead_code)]
struct AckCollector {
    /// The BLAKE3-256 hash of the proposal this collector is tracking.
    proposal_hash: [u8; 32],
    /// Set of peer member IDs that have acknowledged this proposal.
    /// BTreeSet ensures idempotency (duplicate acks are no-ops).
    acked_peers: Mutex<BTreeSet<MemberId>>,
    /// Number of peers expected to ack (excludes the proposer).
    peer_count: usize,
    /// Number of acks needed for quorum (simple majority).
    quorum_threshold: usize,
    /// Millisecond timestamp when ack collection started.
    started_at_millis: u64,
}

impl AckCollector {
    /// Create a new ack collector for the given proposal.
    ///
    /// `peer_count` is the number of peers who received the proposal
    /// (excludes the proposer).  Quorum requires `floor(peer_count / 2) + 1`
    /// acks, i.e. a simple majority of the voting body.
    #[allow(dead_code)]
    fn new(proposal_hash: [u8; 32], peer_count: usize, now_millis: u64) -> Self {
        let quorum_threshold = if peer_count == 0 {
            0 // single-node: no external acks needed
        } else {
            (peer_count / 2) + 1
        };
        Self {
            proposal_hash,
            acked_peers: Mutex::new(BTreeSet::new()),
            peer_count,
            quorum_threshold,
            started_at_millis: now_millis,
        }
    }

    /// Record an ack from a peer.
    ///
    /// Returns `true` if this is a new (non-duplicate) ack. Returns
    /// `false` if the peer already acked or the ack is for a different
    /// proposal.
    fn record_ack(&self, peer: MemberId, ack_hash: &[u8; 32]) -> bool {
        if *ack_hash != self.proposal_hash {
            return false; // stale ack for a different proposal
        }
        let mut peers = self.acked_peers.lock().unwrap();
        peers.insert(peer) // true if newly inserted, false if duplicate
    }

    /// Whether quorum has been reached.
    fn quorum_reached(&self) -> bool {
        let peers = self.acked_peers.lock().unwrap();
        peers.len() >= self.quorum_threshold
    }

    /// Number of unique peers that have acked so far.
    fn ack_count(&self) -> usize {
        self.acked_peers.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// AckDispatchHandler — routes inbound ProposalAck to the bridge
// ---------------------------------------------------------------------------

/// A `MembershipMessageHandler` that delivers `ProposalAck` messages
/// to a shared [`AckCollector`] and an optional ack callback.
///
/// Registered with [`crate::membership_inbound_dispatch::MembershipInboundDispatch`]
/// under discriminant 22 so incoming transport messages are routed here.
///
/// The callback receives a fully-constructed
/// [`tidefs_membership_epoch::epoch_proposal::EpochAckMessage`] ready to
/// pass to [`tidefs_membership_epoch::MembershipEpochDriver::receive_ack`].
struct AckDispatchHandler {
    /// The active ack collector (None when no proposal is in flight).
    collector: Arc<Mutex<Option<Arc<AckCollector>>>>,
    /// Callback invoked on each new (non-duplicate, accepted) ack.
    /// Receives the epoch-layer ack message ready for the driver.
    on_ack: Mutex<Box<dyn FnMut(tidefs_membership_epoch::epoch_proposal::EpochAckMessage) + Send>>,
}

impl AckDispatchHandler {
    fn new(
        collector: Arc<Mutex<Option<Arc<AckCollector>>>>,
        on_ack: Box<dyn FnMut(tidefs_membership_epoch::epoch_proposal::EpochAckMessage) + Send>,
    ) -> Self {
        Self {
            collector,
            on_ack: Mutex::new(on_ack),
        }
    }
}

impl MembershipMessageHandler for AckDispatchHandler {
    fn handle_proposal_ack(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        if let MembershipMessage::ProposalAck {
            responder,
            proposal_hash,
            accepted,
            reject_reason: _,
            acked_at_millis: _,
        } = msg
        {
            if !accepted {
                // Rejected proposals are dropped; they do not count toward quorum.
                return Ok(());
            }

            let collector_guard = self.collector.lock().unwrap();
            if let Some(ref collector) = *collector_guard {
                if collector.record_ack(*responder, proposal_hash) {
                    // New ack: build epoch-layer ack via canonical constructor
                    let epoch_ack =
                        tidefs_membership_epoch::epoch_proposal::EpochAckMessage::approve(
                            responder.0,
                            proposal_hash,
                        );
                    let mut cb = self.on_ack.lock().unwrap();
                    (cb)(epoch_ack);
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitCoordinatorTransportBridge
// ---------------------------------------------------------------------------

/// Implements [`tidefs_membership_epoch::EpochTransitionOps`] using
/// transport for proposal distribution and ack collection.
///
/// # Lifecycle
///
/// 1. [`broadcast_proposal`] — serializes the proposal as a
///    `MembershipOutboundMessage::ProposalSubmission` and sends it
///    to all active roster peers via
///    [`MembershipOutboundDispatch::broadcast`].
/// 2. [`start_ack_collection`] — installs a new [`AckCollector`]
///    tracking the current proposal hash.
/// 3. Inbound `ProposalAck` messages are routed by the transport
///    receive path → [`MembershipInboundDispatch`] → this bridge's
///    [`AckDispatchHandler`], which records the ack in the collector.
/// 4. The caller (typically [`MembershipEpochDriver`]) polls for
///    quorum and calls `receive_ack` / `try_commit`.
/// 5. [`on_epoch_committed`] — clears the collector; the committed
///    epoch result is available for downstream consumers.
/// 6. [`on_timeout`] — clears the collector, allowing a new proposal.
pub struct CommitCoordinatorTransportBridge<'a> {
    /// The proposer's own member identity (reserved for future use).
    #[allow(dead_code)]
    proposer_id: u64,
    /// Transport outbound dispatch for broadcasting proposals.
    outbound: Option<&'a MembershipOutboundDispatch<'a>>,
    /// Shared ack collector for the currently in-flight proposal.
    /// None when no proposal is active.
    collector: Arc<Mutex<Option<Arc<AckCollector>>>>,
    /// Milliseconds-since-epoch clock for timestamping.
    clock_ms: Box<dyn Fn() -> u64 + Send>,
    /// Optional handler for committed catalog deltas.
    /// Called during [`on_epoch_committed`] with raw catalog_delta_bytes.
    catalog_delta_handler: Option<CatalogDeltaHandler>,
}

type CatalogDeltaHandler = Box<dyn FnMut(&[u8]) + Send>;

impl<'a> CommitCoordinatorTransportBridge<'a> {
    /// Create a new bridge.
    ///
    /// `proposer_id` is the local member's node ID.
    /// `outbound` provides the transport send path for proposal broadcast.
    pub fn new(proposer_id: u64, outbound: Option<&'a MembershipOutboundDispatch<'a>>) -> Self {
        Self {
            proposer_id,
            outbound,
            collector: Arc::new(Mutex::new(None)),
            clock_ms: Box::new(|| {
                // Simple monotonic millisecond counter for testing;
                // production replaces this with a real clock.
                0
            }),
            catalog_delta_handler: None,
        }
    }

    /// Replace the clock function (useful for tests).
    pub fn with_clock(mut self, clock_ms: Box<dyn Fn() -> u64 + Send>) -> Self {
        self.clock_ms = clock_ms;
        self
    }

    /// Set a handler for committed catalog deltas.
    ///
    /// When a proposal carrying a catalog delta is committed, this handler
    /// is called with the raw `catalog_delta_bytes` so the application can
    /// deserialize and apply the delta through the pool-scoped catalog.
    /// The handler is called during [`on_epoch_committed`].
    pub fn with_catalog_delta_handler(mut self, handler: CatalogDeltaHandler) -> Self {
        self.catalog_delta_handler = Some(handler);
        self
    }

    /// Create a `MembershipMessageHandler` to register with
    /// [`crate::membership_inbound_dispatch::MembershipInboundDispatch`]
    /// under discriminant 22.
    ///
    /// The handler routes incoming `ProposalAck` messages to the
    /// bridge's internal ack collector, filters duplicates, and
    /// invokes `on_ack` with a fully-constructed
    /// [`tidefs_membership_epoch::epoch_proposal::EpochAckMessage`]
    /// for each new, non-duplicate, accepted ack.
    ///
    /// The callback is typically wired to
    /// [`tidefs_membership_epoch::MembershipEpochDriver::receive_ack`].
    pub fn make_ack_handler(
        &self,
        on_ack: Box<dyn FnMut(tidefs_membership_epoch::epoch_proposal::EpochAckMessage) + Send>,
    ) -> Box<dyn MembershipMessageHandler> {
        Box::new(AckDispatchHandler::new(Arc::clone(&self.collector), on_ack))
    }

    /// Check whether quorum has been reached for the current proposal.
    ///
    /// Returns `false` when no proposal is in flight.
    pub fn quorum_reached(&self) -> bool {
        let guard = self.collector.lock().unwrap();
        guard.as_ref().is_some_and(|c| c.quorum_reached())
    }

    /// Return the number of unique peers that have acked the current
    /// proposal.  Returns 0 when no proposal is in flight.
    pub fn ack_count(&self) -> usize {
        let guard = self.collector.lock().unwrap();
        guard.as_ref().map_or(0, |c| c.ack_count())
    }

    /// Process an inbound `ProposalAck` received via transport.
    ///
    /// Converts the wire-format ack to an [`EpochAckMessage`] that can be
    /// fed to [`MembershipEpochDriver::receive_ack`].  Records the ack in
    /// the internal collector for observability.
    ///
    /// Returns `Some(EpochAckMessage)` if the ack is valid and non-duplicate,
    /// or `None` if it should be dropped (wrong proposal, duplicate, rejected).
    pub fn handle_inbound_ack(
        &self,
        responder: MemberId,
        proposal_hash: &[u8; 32],
        accepted: bool,
        _reject_reason: &Option<String>,
        _acked_at_millis: u64,
    ) -> Option<tidefs_membership_epoch::epoch_proposal::EpochAckMessage> {
        let guard = self.collector.lock().unwrap();
        let collector = guard.as_ref()?;

        if !accepted {
            return None; // rejected acks don't count toward quorum
        }

        if !collector.record_ack(responder, proposal_hash) {
            return None; // duplicate or wrong proposal
        }

        // Build the epoch-layer ack message for the driver
        // Use the canonical constructor which computes the correct BLAKE3 hash.
        Some(
            tidefs_membership_epoch::epoch_proposal::EpochAckMessage::approve(
                responder.0,
                proposal_hash,
            ),
        )
    }

    // -- private helpers --

    fn now_ms(&self) -> u64 {
        (self.clock_ms)()
    }
}

impl<'a> tidefs_membership_epoch::EpochTransitionOps for CommitCoordinatorTransportBridge<'a> {
    fn broadcast_proposal(&mut self, proposal: &EpochProposalMessage) {
        let submitting_msg = MembershipOutboundMessage::ProposalSubmission {
            proposer: MemberId::new(proposal.proposer_id),
            current_epoch: proposal.current_epoch,
            proposed_epoch: proposal.proposed_epoch,
            delta: proposal.delta,
            resulting_members: proposal.resulting_members.clone(),
            proposal_hash: proposal.blake3_hash,
            submitted_at_millis: self.now_ms(),
            catalog_delta_bytes: proposal.catalog_delta_bytes.clone(),
        };

        // Broadcast to all active roster peers via transport.
        if let Some(outbound) = self.outbound {
            let _result = outbound.broadcast(submitting_msg);
            // Partial failures are recorded by the outbound dispatch;
            // the caller can inspect BroadcastResult if needed.
        }

        // Store the proposal hash so start_ack_collection can create
        // a collector keyed to this proposal.
        let collector = AckCollector::new(
            proposal.blake3_hash,
            proposal.resulting_members.len().saturating_sub(1), // exclude proposer
            self.now_ms(),
        );
        let mut guard = self.collector.lock().unwrap();
        *guard = Some(Arc::new(collector));
    }

    fn start_ack_collection(&mut self) {
        // The collector was already created in broadcast_proposal.
        // start_ack_collection signals the beginning of the ack-gathering
        // window; a production implementation starts a timeout timer here
        // to abort the proposal if quorum is not reached in time.
        //
        // The MembershipEpochDriver's internal state machine handles
        // the actual timeout logic, so this is intentionally minimal.
    }

    fn on_epoch_committed(&mut self, result: &EpochTransitionResult) {
        // Clear the current proposal's ack collector.
        let mut guard = self.collector.lock().unwrap();
        *guard = None;

        // Apply any catalog delta carried by the committed proposal.
        if let Some(ref bytes) = result.proposal.catalog_delta_bytes {
            if let Some(ref mut handler) = self.catalog_delta_handler {
                handler(bytes);
            }
            // No handler configured: delta is silently skipped here;
            // it will be applied via the EpochCommitBus subscriber path.
        }
    }

    fn on_timeout(&mut self) {
        // Clear the current proposal's ack collector.
        let mut guard = self.collector.lock().unwrap();
        *guard = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::epoch_proposal::MembershipDelta;
    use tidefs_membership_epoch::EpochTransitionOps;

    // ------------------------------------------------------------------
    // AckCollector tests
    // ------------------------------------------------------------------

    fn make_collector(peer_count: usize) -> AckCollector {
        AckCollector::new([0xABu8; 32], peer_count, 1000)
    }

    #[test]
    fn ack_collector_single_node_no_quorum_needed() {
        let c = make_collector(0);
        assert!(c.quorum_reached());
        assert_eq!(c.ack_count(), 0);
    }

    #[test]
    fn ack_collector_majority_quorum() {
        // 3 peers → quorum = floor(3/2) + 1 = 2
        let c = make_collector(3);
        assert!(!c.quorum_reached());

        assert!(c.record_ack(MemberId::new(1), &[0xABu8; 32]));
        assert!(!c.quorum_reached());
        assert_eq!(c.ack_count(), 1);

        assert!(c.record_ack(MemberId::new(2), &[0xABu8; 32]));
        assert!(c.quorum_reached());
        assert_eq!(c.ack_count(), 2);
    }

    #[test]
    fn ack_collector_minority_no_quorum() {
        // 4 peers → quorum = floor(4/2) + 1 = 3
        let c = make_collector(4);
        assert!(!c.quorum_reached());

        assert!(c.record_ack(MemberId::new(1), &[0xABu8; 32]));
        assert!(c.record_ack(MemberId::new(2), &[0xABu8; 32]));
        assert!(!c.quorum_reached());
        assert_eq!(c.ack_count(), 2);
    }

    #[test]
    fn ack_collector_duplicate_ack_idempotent() {
        let c = make_collector(3);

        assert!(c.record_ack(MemberId::new(1), &[0xABu8; 32]));
        assert_eq!(c.ack_count(), 1);

        // Duplicate from same peer
        assert!(!c.record_ack(MemberId::new(1), &[0xABu8; 32]));
        assert_eq!(c.ack_count(), 1); // unchanged

        // Still need one more for quorum
        assert!(!c.quorum_reached());
        assert!(c.record_ack(MemberId::new(2), &[0xABu8; 32]));
        assert!(c.quorum_reached());
    }

    #[test]
    fn ack_collector_wrong_proposal_hash_rejected() {
        let c = make_collector(3);

        // Ack for a different proposal hash is silently dropped
        assert!(!c.record_ack(MemberId::new(1), &[0xCDu8; 32]));
        assert_eq!(c.ack_count(), 0);
    }

    #[test]
    fn ack_collector_out_of_order_ack_ok() {
        // Acks can arrive in any order — all count toward quorum
        let c = make_collector(3);

        assert!(c.record_ack(MemberId::new(3), &[0xABu8; 32]));
        assert!(c.record_ack(MemberId::new(1), &[0xABu8; 32]));
        assert!(c.quorum_reached());
        assert_eq!(c.ack_count(), 2);
    }

    #[test]
    fn ack_collector_empty_roster_quorum_zero() {
        let c = make_collector(0);
        assert!(c.quorum_reached());
        assert_eq!(c.quorum_threshold, 0);
    }

    #[test]
    fn ack_collector_quorum_threshold_calculation() {
        assert_eq!(make_collector(0).quorum_threshold, 0);
        assert_eq!(make_collector(1).quorum_threshold, 1); // floor(1/2)+1 = 1
        assert_eq!(make_collector(2).quorum_threshold, 2); // floor(2/2)+1 = 2
        assert_eq!(make_collector(3).quorum_threshold, 2); // floor(3/2)+1 = 2
        assert_eq!(make_collector(4).quorum_threshold, 3); // floor(4/2)+1 = 3
        assert_eq!(make_collector(5).quorum_threshold, 3); // floor(5/2)+1 = 3
    }

    // ------------------------------------------------------------------
    // CommitCoordinatorTransportBridge tests
    // ------------------------------------------------------------------

    fn make_bridge<'a>() -> CommitCoordinatorTransportBridge<'a> {
        let mut bridge = CommitCoordinatorTransportBridge::new(1, None);
        let counter = std::cell::Cell::new(0u64);
        bridge = bridge.with_clock(Box::new(move || {
            let v = counter.get();
            counter.set(v + 1);
            v
        }));
        bridge
    }

    #[test]
    fn bridge_quorum_reached_false_when_no_collector() {
        let bridge = make_bridge();
        assert!(!bridge.quorum_reached());
        assert_eq!(bridge.ack_count(), 0);
    }

    #[test]
    fn bridge_ack_count_zero_when_no_collector() {
        let bridge = make_bridge();
        assert_eq!(bridge.ack_count(), 0);
    }

    #[test]
    fn bridge_make_ack_handler_returns_valid_handler() {
        let bridge = make_bridge();
        let handler = bridge.make_ack_handler(Box::new(|_epoch_ack| {}));
        // Just verify it compiles and is a valid boxed trait object
        let _: Box<dyn MembershipMessageHandler> = handler;
    }

    #[test]
    fn bridge_on_timeout_clears_collector() {
        let mut bridge = make_bridge();
        // Simulate having an active collector
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 3, 0)));
        }
        bridge.on_timeout();
        // Collector should be cleared
        let guard = bridge.collector.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn bridge_on_epoch_committed_clears_collector() {
        let mut bridge = make_bridge();
        // Simulate having an active collector
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 3, 0)));
        }
        // Minimal EpochTransitionResult for the callback
        let result = tidefs_membership_epoch::epoch_transition::EpochTransitionResult {
            proposal: EpochProposalMessage {
                proposer_id: 1,
                current_epoch: 0,
                proposed_epoch: 1,
                delta: MembershipDelta::NodeJoined(2),
                resulting_members: vec![1, 2],
                blake3_hash: [0xABu8; 32],
                catalog_delta_bytes: None,
            },
            approvals: 1,
            responses: 1,
        };
        bridge.on_epoch_committed(&result);
        // Collector should be cleared
        let guard = bridge.collector.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn bridge_start_ack_collection_does_not_panic() {
        // start_ack_collection is called after broadcast_proposal;
        // the collector is already created. Verify it doesn't panic
        // when called without a prior broadcast (collector is None).
        let mut bridge = make_bridge();
        bridge.start_ack_collection();
        let guard = bridge.collector.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn bridge_broadcast_creates_collector() {
        let mut bridge = make_bridge();
        let proposal = EpochProposalMessage {
            proposer_id: 1,
            current_epoch: 0,
            proposed_epoch: 1,
            delta: MembershipDelta::NodeJoined(2),
            resulting_members: vec![1, 2],
            blake3_hash: [0xABu8; 32],
            catalog_delta_bytes: None,
        };
        bridge.broadcast_proposal(&proposal);
        // Collector should exist after broadcast
        let guard = bridge.collector.lock().unwrap();
        assert!(guard.is_some());
        let c = guard.as_ref().unwrap();
        assert!(!c.quorum_reached()); // 1 peer, quorum threshold = 1
    }

    // ------------------------------------------------------------------
    // AckDispatchHandler tests
    // ------------------------------------------------------------------

    type AckCalls = Arc<Mutex<Vec<(MemberId, [u8; 32])>>>;

    #[test]
    fn ack_dispatch_handler_records_valid_ack() {
        let collector = Arc::new(Mutex::new(Some(Arc::new(AckCollector::new(
            [0xABu8; 32],
            3,
            0,
        )))));
        let ack_calls: AckCalls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&ack_calls);

        let handler = AckDispatchHandler::new(
            Arc::clone(&collector),
            Box::new(move |epoch_ack| {
                calls_clone
                    .lock()
                    .unwrap()
                    .push((MemberId::new(epoch_ack.acker_id), epoch_ack.proposal_hash));
            }),
        );

        let msg = MembershipMessage::ProposalAck {
            responder: MemberId::new(2),
            proposal_hash: [0xABu8; 32],
            accepted: true,
            reject_reason: None,
            acked_at_millis: 100,
        };

        handler.handle_proposal_ack(&msg).unwrap();

        // Collector should have one ack
        let guard = collector.lock().unwrap();
        let c = guard.as_ref().unwrap();
        assert_eq!(c.ack_count(), 1);

        // Callback should have been invoked
        let calls = ack_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, MemberId::new(2));
        assert_eq!(calls[0].1, [0xABu8; 32]);
    }

    #[test]
    fn ack_dispatch_handler_ignores_rejected_ack() {
        let collector = Arc::new(Mutex::new(Some(Arc::new(AckCollector::new(
            [0xABu8; 32],
            3,
            0,
        )))));
        let ack_calls: AckCalls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&ack_calls);

        let handler = AckDispatchHandler::new(
            Arc::clone(&collector),
            Box::new(move |epoch_ack| {
                calls_clone
                    .lock()
                    .unwrap()
                    .push((MemberId::new(epoch_ack.acker_id), epoch_ack.proposal_hash));
            }),
        );

        let msg = MembershipMessage::ProposalAck {
            responder: MemberId::new(2),
            proposal_hash: [0xABu8; 32],
            accepted: false, // REJECTED
            reject_reason: Some("stale epoch".into()),
            acked_at_millis: 100,
        };

        handler.handle_proposal_ack(&msg).unwrap();

        // Rejected acks do not count toward quorum
        let guard = collector.lock().unwrap();
        let c = guard.as_ref().unwrap();
        assert_eq!(c.ack_count(), 0);

        // Callback not invoked for rejections
        let calls = ack_calls.lock().unwrap();
        assert!(calls.is_empty());
    }

    #[test]
    fn ack_dispatch_handler_no_collector_does_not_panic() {
        let collector = Arc::new(Mutex::new(None)); // no active collector
        let handler = AckDispatchHandler::new(
            Arc::clone(&collector),
            Box::new(|_epoch_ack| {
                panic!("should not be called");
            }),
        );

        let msg = MembershipMessage::ProposalAck {
            responder: MemberId::new(2),
            proposal_hash: [0xABu8; 32],
            accepted: true,
            reject_reason: None,
            acked_at_millis: 100,
        };

        // Should not panic
        handler.handle_proposal_ack(&msg).unwrap();
    }

    #[test]
    fn ack_dispatch_handler_duplicate_ack_no_double_count() {
        let collector = Arc::new(Mutex::new(Some(Arc::new(AckCollector::new(
            [0xABu8; 32],
            3,
            0,
        )))));
        let call_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let cc = Arc::clone(&call_count);

        let handler = AckDispatchHandler::new(
            Arc::clone(&collector),
            Box::new(move |_epoch_ack| {
                *cc.lock().unwrap() += 1;
            }),
        );

        let msg = MembershipMessage::ProposalAck {
            responder: MemberId::new(2),
            proposal_hash: [0xABu8; 32],
            accepted: true,
            reject_reason: None,
            acked_at_millis: 100,
        };

        // First ack
        handler.handle_proposal_ack(&msg).unwrap();
        assert_eq!(*call_count.lock().unwrap(), 1);

        // Duplicate ack (same peer, same hash)
        handler.handle_proposal_ack(&msg).unwrap();
        // Callback should NOT fire for duplicate
        assert_eq!(*call_count.lock().unwrap(), 1);

        // Collector count stays at 1
        let guard = collector.lock().unwrap();
        let c = guard.as_ref().unwrap();
        assert_eq!(c.ack_count(), 1);
    }

    // ------------------------------------------------------------------
    // Bridge handle_inbound_ack tests
    // ------------------------------------------------------------------

    #[test]
    fn bridge_handle_inbound_ack_converts_to_epoch_ack() {
        let bridge = make_bridge();
        // Simulate broadcast creating a collector
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 2, 0)));
        }

        let result = bridge.handle_inbound_ack(MemberId::new(2), &[0xABu8; 32], true, &None, 100);
        assert!(result.is_some());
        let ack = result.unwrap();
        assert_eq!(ack.acker_id, 2);
        assert_eq!(ack.proposal_hash, [0xABu8; 32]);
        assert!(ack.approved);
    }

    #[test]
    fn bridge_handle_inbound_ack_rejected_returns_none() {
        let bridge = make_bridge();
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 2, 0)));
        }

        let result = bridge.handle_inbound_ack(
            MemberId::new(2),
            &[0xABu8; 32],
            false, // rejected
            &Some("stale epoch".into()),
            100,
        );
        assert!(result.is_none());
    }

    #[test]
    fn bridge_handle_inbound_ack_wrong_hash_returns_none() {
        let bridge = make_bridge();
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 2, 0)));
        }

        let result = bridge.handle_inbound_ack(
            MemberId::new(2),
            &[0xCDu8; 32], // wrong hash
            true,
            &None,
            100,
        );
        assert!(result.is_none());
    }

    #[test]
    fn bridge_handle_inbound_ack_duplicate_returns_none() {
        let bridge = make_bridge();
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 2, 0)));
        }

        // First ack — accepted
        let r1 = bridge.handle_inbound_ack(MemberId::new(2), &[0xABu8; 32], true, &None, 100);
        assert!(r1.is_some());

        // Duplicate — dropped
        let r2 = bridge.handle_inbound_ack(MemberId::new(2), &[0xABu8; 32], true, &None, 200);
        assert!(r2.is_none());
    }

    #[test]
    fn bridge_handle_inbound_ack_no_collector_returns_none() {
        let bridge = make_bridge();
        // No collector set up (no broadcast happened)
        let result = bridge.handle_inbound_ack(MemberId::new(2), &[0xABu8; 32], true, &None, 100);
        assert!(result.is_none());
    }

    #[test]
    fn bridge_full_ack_flow_quorum() {
        let bridge = make_bridge();
        // Simulate 3-member roster (proposer + 2 peers)
        {
            let mut guard = bridge.collector.lock().unwrap();
            *guard = Some(Arc::new(AckCollector::new([0xABu8; 32], 2, 0)));
        }

        // Peer 1 acks
        let r1 = bridge.handle_inbound_ack(MemberId::new(2), &[0xABu8; 32], true, &None, 100);
        assert!(r1.is_some());
        assert!(!bridge.quorum_reached()); // need 2, only have 1

        // Peer 2 acks
        let r2 = bridge.handle_inbound_ack(MemberId::new(3), &[0xABu8; 32], true, &None, 200);
        assert!(r2.is_some());
        assert!(bridge.quorum_reached()); // 2 of 2 = quorum
        assert_eq!(bridge.ack_count(), 2);
    }

    #[test]
    fn ack_dispatch_handler_wrong_hash_not_counted() {
        let collector = Arc::new(Mutex::new(Some(Arc::new(AckCollector::new(
            [0xABu8; 32],
            3,
            0,
        )))));
        let call_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let cc = Arc::clone(&call_count);

        let handler = AckDispatchHandler::new(
            Arc::clone(&collector),
            Box::new(move |_epoch_ack| {
                *cc.lock().unwrap() += 1;
            }),
        );

        let msg = MembershipMessage::ProposalAck {
            responder: MemberId::new(2),
            proposal_hash: [0xCDu8; 32], // wrong proposal hash
            accepted: true,
            reject_reason: None,
            acked_at_millis: 100,
        };

        handler.handle_proposal_ack(&msg).unwrap();

        // Callback not invoked for wrong hash
        assert_eq!(*call_count.lock().unwrap(), 0);

        // Collector count stays at 0
        let guard = collector.lock().unwrap();
        let c = guard.as_ref().unwrap();
        assert_eq!(c.ack_count(), 0);
    }
}
