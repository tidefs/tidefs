// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Drain protocol runtime orchestrator.
//!
//! [`DrainRuntime`] wires together the drain state machine
//! ([`crate::state_machine::DrainProtocolMachine`]), wire messages
//! ([`crate::protocol`]), configuration ([`crate::config::DrainConfig`]),
//! and external services via [`DrainRuntimeOps`] to execute a
//! complete graceful node drain:
//!
//! 1. Broadcast [`DrainAnnounce`] to all peers.
//! 2. Collect [`DrainAck`] responses (with timeout).
//! 3. Execute state transfers via [`StateTransferRequest`] /
//!    [`StateTransferChunk`] to designated target peers.
//! 4. Coordinate roster removal (remove drained node).
//! 5. Signal transport teardown for connections to the drained node.
//! 6. Broadcast [`DrainComplete`].
//!
//! The runtime emits lifecycle events (`Draining`, `Drained`) through
//! the event bridge so upstream systems (membership roster, epoch
//! transition, transport peer manager) react to drain progress.

use std::time::Instant;

use tidefs_membership_epoch::{EpochId, MemberId};

use crate::config::DrainConfig;
use crate::protocol::{
    DrainAck, DrainAnnounce, DrainComplete, DrainWireMessage, StateTransferChunk,
    StateTransferRequest,
};
use crate::state_machine::{
    DrainProtocolError, DrainProtocolMachine, DrainProtocolSnapshot, DrainProtocolState,
};

// ---------------------------------------------------------------------------
// DrainRuntimeOps -- external service abstraction
// ---------------------------------------------------------------------------

/// External services required by [`DrainRuntime`].
///
/// Implementations bridge to live cluster subsystems: messaging,
/// membership roster, transport peer manager, and event dispatch.
pub trait DrainRuntimeOps {
    /// Send a drain announce to a specific peer.
    ///
    /// Returns the [`DrainAck`] from that peer, or an error string if
    /// sending failed or the peer is unreachable.
    fn send_announce(
        &mut self,
        announce: &DrainAnnounce,
        peer: MemberId,
    ) -> Result<DrainAck, String>;

    /// Broadcast a [`DrainAnnounce`] to all peers and collect the
    /// resulting [`DrainAck`] responses.
    ///
    /// Implementations should fan out to every known peer (excluding
    /// the draining node itself), wait for all responses (or a
    /// timeout), and return the acks from peers that responded.
    fn broadcast_announce(&mut self, announce: &DrainAnnounce) -> Result<Vec<DrainAck>, String>;

    /// Send a state transfer chunk to a target peer.
    fn send_transfer_chunk(
        &mut self,
        chunk: &StateTransferChunk,
        target: MemberId,
    ) -> Result<(), String>;

    /// Request state transfer from the draining node (target side).
    fn request_state_transfer(
        &mut self,
        request: &StateTransferRequest,
        target: MemberId,
    ) -> Result<(), String>;

    /// Broadcast a [`DrainComplete`] message to all remaining peers.
    fn broadcast_drain_complete(&mut self, complete: &DrainComplete) -> Result<(), String>;

    /// Remove the drained node from the membership roster, marking it
    /// as `Left`.
    fn remove_from_roster(&mut self, node_id: MemberId) -> Result<(), String>;

    /// Signal the transport peer manager to begin draining (or
    /// tearing down) connections for the given node.
    fn signal_transport_drain(&mut self, node_id: MemberId);

    /// Signal the transport peer manager that the drain is complete
    /// and connections may be forcefully torn down.
    fn signal_transport_teardown(&mut self, node_id: MemberId);

    /// Emit a drain lifecycle event to the membership event bridge.
    fn emit_drain_event(&mut self, event: DrainRuntimeEvent);

    /// Return the current membership epoch.
    fn current_epoch(&self) -> EpochId;

    /// Return the set of active peer node IDs (excluding the draining
    /// node itself, if already known).
    fn active_peers(&self) -> Vec<MemberId>;

    /// Return the number of active peers.
    fn active_peer_count(&self) -> u64 {
        self.active_peers().len() as u64
    }
}

// ---------------------------------------------------------------------------
// DrainRuntimeEvent
// ---------------------------------------------------------------------------

/// Lifecycle events emitted by [`DrainRuntime`] through
/// [`DrainRuntimeOps::emit_drain_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainRuntimeEvent {
    /// The drain has been announced and acks are being collected.
    Draining {
        node_id: MemberId,
        epoch_id: EpochId,
        expected_peers: u64,
    },
    /// The drain has completed successfully.
    Drained {
        node_id: MemberId,
        epoch_id: EpochId,
        forced: bool,
    },
    /// The drain timed out and was force-completed.
    DrainTimeout {
        node_id: MemberId,
        epoch_id: EpochId,
    },
    /// Drain was cancelled (operator or error).
    DrainCancelled { node_id: MemberId, reason: String },
    /// An error occurred during drain execution.
    DrainError { node_id: MemberId, error: String },
}

// ---------------------------------------------------------------------------
// DrainRuntimeError
// ---------------------------------------------------------------------------

/// Errors returned by [`DrainRuntime`] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainRuntimeError {
    /// The state machine rejected the operation.
    Protocol(DrainProtocolError),
    /// A peer communication failed.
    PeerCommunication { peer: MemberId, detail: String },
    /// Broadcast failed.
    BroadcastFailed(String),
    /// State transfer failed.
    TransferFailed { target: MemberId, detail: String },
    /// Roster removal failed.
    RosterRemovalFailed(String),
    /// Drain timed out.
    TimedOut,
    /// A concurrent drain is already in progress.
    AlreadyDraining { existing_node_id: MemberId },
    /// No active drain to operate on.
    NoActiveDrain,
}

impl std::fmt::Display for DrainRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::PeerCommunication { peer, detail } => {
                write!(f, "peer {0} communication failed: {detail}", peer.0)
            }
            Self::BroadcastFailed(d) => write!(f, "broadcast failed: {d}"),
            Self::TransferFailed { target, detail } => {
                write!(f, "transfer to {0} failed: {detail}", target.0)
            }
            Self::RosterRemovalFailed(d) => {
                write!(f, "roster removal failed: {d}")
            }
            Self::TimedOut => write!(f, "drain timed out"),
            Self::AlreadyDraining { existing_node_id } => {
                write!(f, "already draining node {0}", existing_node_id.0)
            }
            Self::NoActiveDrain => write!(f, "no active drain in progress"),
        }
    }
}

impl std::error::Error for DrainRuntimeError {}

impl From<DrainProtocolError> for DrainRuntimeError {
    fn from(e: DrainProtocolError) -> Self {
        Self::Protocol(e)
    }
}

// ---------------------------------------------------------------------------
// DrainRuntime -- orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the full drain protocol lifecycle.
///
/// Generic over [`DrainRuntimeOps`] so integration tests can supply
/// mock services and production code wires live cluster subsystems.
pub struct DrainRuntime<O: DrainRuntimeOps> {
    /// Protocol-level state machine.
    machine: DrainProtocolMachine,
    /// Validated configuration.
    config: DrainConfig,
    /// External services.
    ops: O,
    /// Monotonically increasing drain sequence number.
    drain_sequence: u64,
    /// Instant when the current drain started, for timeout tracking.
    drain_start: Option<Instant>,
    /// Whether the current drain was forced (timeout).
    forced: bool,
}

impl<O: DrainRuntimeOps> DrainRuntime<O> {
    /// Create a new runtime with the given configuration and ops.
    #[must_use]
    pub fn new(config: DrainConfig, ops: O) -> Self {
        Self {
            machine: DrainProtocolMachine::new(),
            config,
            ops,
            drain_sequence: 0,
            drain_start: None,
            forced: false,
        }
    }

    // ---- accessors ----

    #[must_use]
    pub fn state(&self) -> DrainProtocolState {
        self.machine.state()
    }

    #[must_use]
    pub fn snapshot(&self) -> DrainProtocolSnapshot {
        self.machine.snapshot()
    }

    #[must_use]
    pub fn config(&self) -> &DrainConfig {
        &self.config
    }

    #[must_use]
    pub fn drain_sequence(&self) -> u64 {
        self.drain_sequence
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        !matches!(self.machine.state(), DrainProtocolState::Idle)
    }

    /// Check whether the drain has timed out.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        if self.config.timeout_disabled() {
            return false;
        }
        match self.drain_start {
            Some(start) => start.elapsed().as_millis() as u64 >= self.config.drain_timeout_ms,
            None => false,
        }
    }

    // ---- protocol operations ----

    /// Initiate a drain for the given node.
    ///
    /// 1. Validates the machine is idle.
    /// 2. Announces drain to all peers.
    /// 3. Collects acknowledgements.
    /// 4. Emits `DrainRuntimeEvent::Draining`.
    ///
    /// Returns the snapshot after announce+ack collection.
    ///
    /// # Errors
    /// - `AlreadyDraining` if a drain is already in progress.
    /// - `BroadcastFailed` if the announce could not be sent.
    /// - `PeerCommunication` if a required peer did not respond.
    pub fn start_drain(
        &mut self,
        node_id: MemberId,
        reason: String,
    ) -> Result<DrainProtocolSnapshot, DrainRuntimeError> {
        if self.is_draining() {
            return Err(DrainRuntimeError::AlreadyDraining {
                existing_node_id: self.machine.draining_node_id(),
            });
        }

        let epoch_id = self.ops.current_epoch();
        let expected_peers = self.ops.active_peer_count();
        self.drain_sequence = self.drain_sequence.wrapping_add(1);
        let sequence = self.drain_sequence;

        // Step 1: Announce to the state machine.
        self.machine
            .announce_drain(node_id, epoch_id, expected_peers)?;

        // Step 2: Build and broadcast the announce message.
        let announce = DrainAnnounce::new(
            node_id, node_id, // self-initiated drain
            epoch_id, sequence, reason,
        );

        self.drain_start = Some(Instant::now());
        self.forced = false;

        let acks = self
            .ops
            .broadcast_announce(&announce)
            .map_err(DrainRuntimeError::BroadcastFailed)?;

        // Step 3: Register accepted acks. Rejected acks are silently
        // skipped (they do not count toward quorum). The caller
        // inspects the snapshot's all_acks_received() to decide
        // whether to proceed before calling begin_state_transfer().
        for ack in &acks {
            if ack.verify_full() && ack.accepted {
                self.machine.record_ack()?;
            }
        }

        // Emit the Draining event.
        self.ops.emit_drain_event(DrainRuntimeEvent::Draining {
            node_id,
            epoch_id,
            expected_peers,
        });

        let snap = self.machine.snapshot();

        // If no peers at all, fast-forward through the pipeline.
        if expected_peers == 0 {
            self.machine.start_draining()?;
            self.machine.complete_draining()?;
        }

        Ok(snap)
    }

    /// Advance to the Draining state (state transfer phase).
    ///
    /// Called after all acks have been received and the caller decides
    /// to proceed. The caller should call `snapshot().all_acks_received()`
    /// first to verify readiness.
    ///
    /// # Errors
    /// - `Protocol` if the state machine rejects the transition.
    pub fn begin_state_transfer(&mut self) -> Result<DrainProtocolSnapshot, DrainRuntimeError> {
        let snap = self.machine.start_draining()?;

        // Signal transport that drain is beginning for this node.
        let node_id = self.machine.draining_node_id();
        self.ops.signal_transport_drain(node_id);

        Ok(snap)
    }

    /// Transfer a chunk of state to a target peer.
    ///
    /// Constructs a [`StateTransferChunk`], sends it via the ops,
    /// and returns the chunk for the caller's bookkeeping.
    ///
    /// # Errors
    /// - `NoActiveDrain` if not in `Draining` state.
    /// - `TransferFailed` if the send fails.
    pub fn transfer_chunk(
        &mut self,
        target: MemberId,
        transfer_id: u64,
        chunk_index: u64,
        payload: Vec<u8>,
    ) -> Result<StateTransferChunk, DrainRuntimeError> {
        if self.state() != DrainProtocolState::Draining {
            return Err(DrainRuntimeError::NoActiveDrain);
        }

        let chunk = StateTransferChunk::new(
            self.machine.draining_node_id(),
            target,
            transfer_id,
            chunk_index,
            payload,
        );

        self.ops
            .send_transfer_chunk(&chunk, target)
            .map_err(|e| DrainRuntimeError::TransferFailed { target, detail: e })?;

        Ok(chunk)
    }

    /// Complete the state transfer phase and transition to
    /// `DrainComplete`.
    ///
    /// # Errors
    /// - `Protocol` if the state machine rejects the transition.
    pub fn complete_state_transfer(&mut self) -> Result<DrainProtocolSnapshot, DrainRuntimeError> {
        self.machine.complete_draining()?;
        Ok(self.machine.snapshot())
    }

    /// Finalize the drain: remove from roster, signal transport
    /// teardown, broadcast `DrainComplete`, and transition to
    /// `Drained`.
    ///
    /// # Errors
    /// - `Protocol` if the state machine rejects the transition.
    /// - `RosterRemovalFailed` if roster removal fails.
    /// - `BroadcastFailed` if the DrainComplete broadcast fails.
    pub fn finalize_drain(&mut self) -> Result<DrainProtocolSnapshot, DrainRuntimeError> {
        let node_id = self.machine.draining_node_id();
        let epoch_id = self.machine.epoch_id();

        // Remove from roster.
        self.ops
            .remove_from_roster(node_id)
            .map_err(DrainRuntimeError::RosterRemovalFailed)?;

        // Signal transport teardown.
        self.ops.signal_transport_teardown(node_id);

        // Build and broadcast DrainComplete.
        let complete = DrainComplete::new(node_id, epoch_id, self.drain_sequence, self.forced);
        self.ops
            .broadcast_drain_complete(&complete)
            .map_err(DrainRuntimeError::BroadcastFailed)?;

        // Transition to Drained.
        self.machine.finalize_drain()?;

        // Emit Drained event.
        self.ops.emit_drain_event(DrainRuntimeEvent::Drained {
            node_id,
            epoch_id,
            forced: self.forced,
        });

        self.drain_start = None;

        Ok(self.machine.snapshot())
    }

    /// Force the drain to completion regardless of current state.
    ///
    /// Used when a timeout fires or an operator forces the drain.
    /// Skips state transfer and goes directly to Drained.
    pub fn force_drain(&mut self) -> DrainProtocolSnapshot {
        self.forced = true;
        let node_id = self.machine.draining_node_id();
        let epoch_id = self.machine.epoch_id();

        let snap = self.machine.force_drained();

        // Best-effort teardown and roster removal.
        let _ = self.ops.remove_from_roster(node_id);
        self.ops.signal_transport_teardown(node_id);

        // Emit timeout or forced event.
        if self.forced {
            self.ops
                .emit_drain_event(DrainRuntimeEvent::DrainTimeout { node_id, epoch_id });
        }

        self.drain_start = None;
        snap
    }

    /// Cancel the active drain and return to idle.
    ///
    /// # Errors
    /// - `Protocol` if the state machine rejects the cancellation.
    pub fn cancel_drain(
        &mut self,
        reason: String,
    ) -> Result<DrainProtocolSnapshot, DrainRuntimeError> {
        let node_id = self.machine.draining_node_id();
        self.machine.cancel_drain(reason.clone())?;

        self.ops
            .emit_drain_event(DrainRuntimeEvent::DrainCancelled { node_id, reason });

        self.drain_start = None;
        self.forced = false;

        Ok(self.machine.snapshot())
    }

    /// Check for timeout and force-drain if expired.
    ///
    /// Returns `true` if a timeout occurred and the drain was forced.
    #[must_use]
    pub fn check_timeout(&mut self) -> bool {
        if !self.is_draining() || self.state().is_terminal() {
            return false;
        }
        if self.timed_out() {
            self.force_drain();
            true
        } else {
            false
        }
    }

    /// Reset the runtime to idle, clearing all state.
    pub fn reset(&mut self) {
        self.machine.reset();
        self.drain_start = None;
        self.forced = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // -----------------------------------------------------------------------
    // MockOps -- in-memory test double
    // -----------------------------------------------------------------------

    struct MockOps {
        epoch: EpochId,
        peers: Vec<MemberId>,
        /// Ack responses keyed by peer id: (accepted, rejection_reason)
        ack_responses: HashMap<u64, (bool, Option<String>)>,
        /// Whether broadcast fails.
        broadcast_fails: bool,
        /// Whether roster removal fails.
        roster_removal_fails: bool,
        /// Whether transfer chunk send fails for a specific target.
        transfer_fail_targets: Vec<u64>,
        /// Events emitted during the test.
        events: Vec<DrainRuntimeEvent>,
        /// Roster: set of members.
        roster: Vec<MemberId>,
        /// Transport drain nodes.
        transport_drain_calls: Vec<MemberId>,
        /// Transport teardown nodes.
        transport_teardown_calls: Vec<MemberId>,
    }

    impl MockOps {
        fn new(epoch: u64, peers: Vec<u64>) -> Self {
            Self {
                epoch: EpochId(epoch),
                peers: peers.into_iter().map(mid).collect(),
                ack_responses: HashMap::new(),
                broadcast_fails: false,
                roster_removal_fails: false,
                transfer_fail_targets: Vec::new(),
                events: Vec::new(),
                roster: Vec::new(),
                transport_drain_calls: Vec::new(),
                transport_teardown_calls: Vec::new(),
            }
        }

        fn with_ack(mut self, peer: u64, accepted: bool) -> Self {
            self.ack_responses.insert(peer, (accepted, None));
            self
        }
    }

    impl DrainRuntimeOps for MockOps {
        fn send_announce(
            &mut self,
            _announce: &DrainAnnounce,
            _peer: MemberId,
        ) -> Result<DrainAck, String> {
            unimplemented!("use broadcast_announce for tests")
        }

        fn broadcast_announce(
            &mut self,
            announce: &DrainAnnounce,
        ) -> Result<Vec<DrainAck>, String> {
            if self.broadcast_fails {
                return Err("broadcast failed".into());
            }
            let mut acks = Vec::new();
            for peer in &self.peers {
                if peer.0 == announce.draining_node_id.0 {
                    continue; // don't ack self
                }
                let (accepted, rejection) = self
                    .ack_responses
                    .get(&peer.0)
                    .cloned()
                    .unwrap_or((true, None));
                let ack = DrainAck::new(
                    announce.draining_node_id,
                    *peer,
                    announce.epoch_id,
                    announce.drain_sequence,
                    accepted,
                    rejection,
                );
                acks.push(ack);
            }
            Ok(acks)
        }

        fn send_transfer_chunk(
            &mut self,
            _chunk: &StateTransferChunk,
            target: MemberId,
        ) -> Result<(), String> {
            if self.transfer_fail_targets.contains(&target.0) {
                Err(format!("transfer failed to {0}", target.0))
            } else {
                Ok(())
            }
        }

        fn request_state_transfer(
            &mut self,
            _request: &StateTransferRequest,
            _target: MemberId,
        ) -> Result<(), String> {
            Ok(())
        }

        fn broadcast_drain_complete(&mut self, _complete: &DrainComplete) -> Result<(), String> {
            if self.broadcast_fails {
                Err("broadcast failed".into())
            } else {
                Ok(())
            }
        }

        fn remove_from_roster(&mut self, node_id: MemberId) -> Result<(), String> {
            if self.roster_removal_fails {
                Err("roster removal failed".into())
            } else {
                self.roster.retain(|m| m.0 != node_id.0);
                Ok(())
            }
        }

        fn signal_transport_drain(&mut self, node_id: MemberId) {
            self.transport_drain_calls.push(node_id);
        }

        fn signal_transport_teardown(&mut self, node_id: MemberId) {
            self.transport_teardown_calls.push(node_id);
        }

        fn emit_drain_event(&mut self, event: DrainRuntimeEvent) {
            self.events.push(event);
        }

        fn current_epoch(&self) -> EpochId {
            self.epoch
        }

        fn active_peers(&self) -> Vec<MemberId> {
            self.peers.clone()
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a runtime with default config and mock ops
    // -----------------------------------------------------------------------

    fn make_runtime(epoch: u64, peers: Vec<u64>) -> DrainRuntime<MockOps> {
        let config = DrainConfig::default();
        let ops = MockOps::new(epoch, peers);
        DrainRuntime::new(config, ops)
    }

    // -----------------------------------------------------------------------
    // Happy-path tests
    // -----------------------------------------------------------------------

    #[test]
    fn starts_idle() {
        let rt = make_runtime(1, vec![2, 3, 4]);
        assert_eq!(rt.state(), DrainProtocolState::Idle);
        assert!(!rt.is_draining());
    }

    #[test]
    fn start_drain_no_peers() {
        let mut rt = make_runtime(1, vec![]);
        let snap = rt.start_drain(mid(1), "test drain".into()).unwrap();
        // With zero peers, fast-forwards through announce -> draining -> complete.
        assert_eq!(rt.state(), DrainProtocolState::DrainComplete);
        assert!(snap.verify_digest());
        assert_eq!(rt.drain_sequence(), 1);
    }

    #[test]
    fn start_drain_with_peers() {
        let mut rt = make_runtime(5, vec![2, 3, 4]);
        let snap = rt.start_drain(mid(1), "maintenance".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::DrainAnnounced);
        assert!(snap.verify_digest());
        assert_eq!(snap.acks_expected, 3);
        assert_eq!(snap.acks_received, 3); // all peers accepted
        assert!(snap.all_acks_received());

        // Verify Draining event was emitted.
        assert_eq!(rt.ops.events.len(), 1);
        assert!(matches!(
            &rt.ops.events[0],
            DrainRuntimeEvent::Draining {
                node_id,
                epoch_id: EpochId(5),
                expected_peers: 3,
            } if node_id.0 == 1
        ));
    }

    #[test]
    fn full_happy_path() {
        let mut rt = make_runtime(7, vec![2, 3, 4]);
        rt.start_drain(mid(42), "happy drain".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::DrainAnnounced);

        // Begin state transfer.
        let snap = rt.begin_state_transfer().unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Draining);
        assert!(snap.verify_digest());

        // Verify transport drain was signaled.
        assert_eq!(rt.ops.transport_drain_calls.len(), 1);
        assert_eq!(rt.ops.transport_drain_calls[0].0, 42);

        // Transfer some chunks.
        let chunk = rt.transfer_chunk(mid(2), 0, 0, vec![1, 2, 3, 4]).unwrap();
        assert!(chunk.verify_full());
        assert!(chunk.verify_payload());

        rt.transfer_chunk(mid(3), 1, 0, vec![5, 6, 7, 8]).unwrap();

        // Complete state transfer.
        let snap = rt.complete_state_transfer().unwrap();
        assert_eq!(rt.state(), DrainProtocolState::DrainComplete);
        assert!(snap.verify_digest());

        // Finalize.
        let snap = rt.finalize_drain().unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());

        // Verify teardown signaled.
        assert_eq!(rt.ops.transport_teardown_calls.len(), 1);
        assert_eq!(rt.ops.transport_teardown_calls[0].0, 42);

        // Verify Drained event.
        assert_eq!(rt.ops.events.len(), 2);
        assert!(matches!(
            &rt.ops.events[1],
            DrainRuntimeEvent::Drained {
                node_id,
                epoch_id: EpochId(7),
                forced: false,
            } if node_id.0 == 42
        ));
    }

    // -----------------------------------------------------------------------
    // Timeout tests
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_disabled_when_zero() {
        let config = DrainConfig::new(0, 64, 4).unwrap();
        let ops = MockOps::new(1, vec![2, 3]);
        let rt = DrainRuntime::new(config, ops);
        assert!(!rt.timed_out());
    }

    #[test]
    fn timeout_not_fired_immediately() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        assert!(!rt.timed_out());
        assert!(!rt.check_timeout());
    }

    #[test]
    fn force_drain_from_announced() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        let snap = rt.force_drain();
        assert_eq!(rt.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());

        // Verify timeout event.
        assert!(rt
            .ops
            .events
            .iter()
            .any(|e| matches!(e, DrainRuntimeEvent::DrainTimeout { .. })));
    }

    #[test]
    fn force_drain_triggers_transport_teardown() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.force_drain();
        assert_eq!(rt.ops.transport_teardown_calls.len(), 1);
        assert_eq!(rt.ops.transport_teardown_calls[0].0, 1);
    }

    // -----------------------------------------------------------------------
    // Cancellation tests
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_from_announced() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        let snap = rt.cancel_drain("operator cancel".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Idle);
        assert!(snap.verify_digest());

        // Verify cancel event.
        assert!(rt
            .ops
            .events
            .iter()
            .any(|e| matches!(e, DrainRuntimeEvent::DrainCancelled { .. })));
    }

    #[test]
    fn cancel_from_draining() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.begin_state_transfer().unwrap();
        rt.cancel_drain("transfer error".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Idle);
    }

    #[test]
    fn cancel_from_complete() {
        let mut rt = make_runtime(1, vec![]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        // With 0 peers, fast-forwards to DrainComplete.
        rt.cancel_drain("epoch rejected".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Idle);
    }

    // -----------------------------------------------------------------------
    // Error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn start_drain_rejects_when_already_draining() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "first".into()).unwrap();
        let err = rt.start_drain(mid(2), "second".into()).unwrap_err();
        assert!(matches!(err, DrainRuntimeError::AlreadyDraining { .. }));
    }

    #[test]
    fn begin_transfer_rejects_wrong_state() {
        let mut rt = make_runtime(1, vec![2, 3]);
        let err = rt.begin_state_transfer().unwrap_err();
        assert!(matches!(err, DrainRuntimeError::Protocol(_)));
    }

    #[test]
    fn transfer_chunk_rejects_wrong_state() {
        let mut rt = make_runtime(1, vec![2, 3]);
        let err = rt.transfer_chunk(mid(2), 0, 0, vec![1, 2]).unwrap_err();
        assert!(matches!(err, DrainRuntimeError::NoActiveDrain));
    }

    #[test]
    fn transfer_chunk_failure() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.ops.transfer_fail_targets.push(2);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.begin_state_transfer().unwrap();
        let err = rt.transfer_chunk(mid(2), 0, 0, vec![1, 2]).unwrap_err();
        assert!(matches!(
            err,
            DrainRuntimeError::TransferFailed { target, .. } if target.0 == 2
        ));
    }

    #[test]
    fn roster_removal_failure() {
        let mut rt = make_runtime(1, vec![]);
        rt.ops.roster_removal_fails = true;
        rt.start_drain(mid(1), "test".into()).unwrap();
        // With 0 peers, fast-forwards to DrainComplete.
        // No need to call complete_draining() -- we are already there.
        let err = rt.finalize_drain().unwrap_err();
        assert!(matches!(err, DrainRuntimeError::RosterRemovalFailed(_)));
    }

    #[test]
    fn broadcast_fails_on_start() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.ops.broadcast_fails = true;
        let err = rt.start_drain(mid(1), "test".into()).unwrap_err();
        assert!(matches!(err, DrainRuntimeError::BroadcastFailed(_)));
    }

    // -----------------------------------------------------------------------
    // Multi-peer tests
    // -----------------------------------------------------------------------

    #[test]
    fn drain_with_five_peers() {
        let mut rt = make_runtime(10, vec![2, 3, 4, 5, 6]);
        let snap = rt.start_drain(mid(1), "5 peers".into()).unwrap();
        assert_eq!(snap.acks_expected, 5);
        assert_eq!(snap.acks_received, 5);
        assert!(snap.all_acks_received());
    }

    #[test]
    fn drain_with_seven_peers() {
        let mut rt = make_runtime(10, vec![2, 3, 4, 5, 6, 7, 8]);
        let snap = rt.start_drain(mid(1), "7 peers".into()).unwrap();
        assert_eq!(snap.acks_expected, 7);
        assert_eq!(snap.acks_received, 7);
    }

    #[test]
    fn partial_ack_rejection() {
        // Peer 3 rejects the drain.
        let mut rt = make_runtime(10, vec![2, 3, 4]);
        rt.ops = rt.ops.with_ack(3, false);

        let snap = rt.start_drain(mid(1), "partial reject".into()).unwrap();
        // Expect 3 peers total, peer 3 rejected so only 2 accepted acks.
        assert_eq!(snap.acks_expected, 3);
        // The rejected ack still counts as received; accepted_count would be 2,
        // but our mock records acks only when accepted=true.
        assert_eq!(snap.acks_received, 2);
        assert!(!snap.all_acks_received());
    }

    // -----------------------------------------------------------------------
    // State transfer tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_transfer_multiple_chunks() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "transfer test".into()).unwrap();
        rt.begin_state_transfer().unwrap();

        for i in 0..10 {
            let chunk = rt.transfer_chunk(mid(2), 0, i, vec![i as u8; 64]).unwrap();
            assert!(chunk.verify_full());
            assert!(chunk.verify_payload());
            assert_eq!(chunk.chunk_index, i);
        }
    }

    #[test]
    fn state_transfer_to_multiple_targets() {
        let mut rt = make_runtime(1, vec![2, 3, 4]);
        rt.start_drain(mid(1), "multi-target".into()).unwrap();
        rt.begin_state_transfer().unwrap();

        rt.transfer_chunk(mid(2), 0, 0, vec![1, 2]).unwrap();
        rt.transfer_chunk(mid(3), 0, 0, vec![3, 4]).unwrap();
        rt.transfer_chunk(mid(4), 0, 0, vec![5, 6]).unwrap();
    }

    // -----------------------------------------------------------------------
    // Concurrent drain serialization test
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_drain_rejected() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "first".into()).unwrap();
        // Second drain attempt rejected.
        let err = rt.start_drain(mid(2), "second".into()).unwrap_err();
        assert!(matches!(
            err,
            DrainRuntimeError::AlreadyDraining { existing_node_id } if existing_node_id.0 == 1
        ));
    }

    #[test]
    fn drain_after_previous_completes() {
        let mut rt = make_runtime(1, vec![]);
        // First drain.
        rt.start_drain(mid(1), "first".into()).unwrap();
        rt.finalize_drain().unwrap();

        // Reset and drain a different node.
        rt.reset();
        rt.start_drain(mid(2), "second".into()).unwrap();
        assert_eq!(rt.state(), DrainProtocolState::DrainComplete);
        rt.finalize_drain().unwrap();
        assert_eq!(rt.state(), DrainProtocolState::Drained);
    }

    // -----------------------------------------------------------------------
    // Event emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn events_on_cancel() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.cancel_drain("operator".into()).unwrap();
        assert!(rt.ops.events.iter().any(|e| matches!(
            e,
            DrainRuntimeEvent::DrainCancelled {
                node_id,
                reason,
            } if node_id.0 == 1 && reason == "operator"
        )));
    }

    #[test]
    fn events_on_force() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.force_drain();
        assert!(rt
            .ops
            .events
            .iter()
            .any(|e| matches!(e, DrainRuntimeEvent::DrainTimeout { .. })));
    }

    #[test]
    fn events_sequence_on_happy_path() {
        let mut rt = make_runtime(5, vec![]);
        rt.start_drain(mid(1), "happy".into()).unwrap();
        rt.finalize_drain().unwrap();

        assert_eq!(rt.ops.events.len(), 2);
        assert!(matches!(
            rt.ops.events[0],
            DrainRuntimeEvent::Draining { .. }
        ));
        assert!(matches!(
            rt.ops.events[1],
            DrainRuntimeEvent::Drained { forced: false, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Roster integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn roster_removes_node_on_finalize() {
        let mut rt = make_runtime(5, vec![]);
        rt.ops.roster = vec![mid(1), mid(2), mid(3)];
        rt.start_drain(mid(1), "roster test".into()).unwrap();
        rt.finalize_drain().unwrap();
        assert!(!rt.ops.roster.iter().any(|m| m.0 == 1));
        assert!(rt.ops.roster.iter().any(|m| m.0 == 2));
        assert!(rt.ops.roster.iter().any(|m| m.0 == 3));
    }

    #[test]
    fn roster_removes_node_on_force() {
        let mut rt = make_runtime(5, vec![2, 3]);
        rt.ops.roster = vec![mid(1), mid(2), mid(3)];
        rt.start_drain(mid(1), "force roster".into()).unwrap();
        rt.force_drain();
        assert!(!rt.ops.roster.iter().any(|m| m.0 == 1));
    }

    // -----------------------------------------------------------------------
    // BLAKE3 integrity verification in runtime context
    // -----------------------------------------------------------------------

    #[test]
    fn announce_message_verifies_in_runtime() {
        let mut rt = make_runtime(5, vec![2, 3]);
        rt.start_drain(mid(1), "integrity test".into()).unwrap();
        let snap = rt.snapshot();
        assert!(snap.verify_digest());
    }

    #[test]
    fn snapshot_consistent_across_phases() {
        let mut rt = make_runtime(5, vec![]);
        rt.start_drain(mid(1), "phase test".into()).unwrap();
        let s1 = rt.snapshot();
        assert!(s1.verify_digest());
        assert_eq!(s1.state, DrainProtocolState::DrainComplete);

        rt.finalize_drain().unwrap();
        let s2 = rt.snapshot();
        assert!(s2.verify_digest());
        assert_eq!(s2.state, DrainProtocolState::Drained);
        assert_ne!(s1.blake3_digest, s2.blake3_digest);
    }

    // -----------------------------------------------------------------------
    // Transport integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn transport_drain_called_during_state_transfer() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "transport test".into()).unwrap();
        // Before begin_state_transfer, no drain signal.
        assert!(rt.ops.transport_drain_calls.is_empty());
        rt.begin_state_transfer().unwrap();
        assert_eq!(rt.ops.transport_drain_calls.len(), 1);
        assert_eq!(rt.ops.transport_drain_calls[0].0, 1);
    }

    #[test]
    fn transport_teardown_called_on_finalize() {
        let mut rt = make_runtime(1, vec![]);
        rt.start_drain(mid(1), "teardown test".into()).unwrap();
        rt.finalize_drain().unwrap();
        assert_eq!(rt.ops.transport_teardown_calls.len(), 1);
        assert_eq!(rt.ops.transport_teardown_calls[0].0, 1);
    }

    // -----------------------------------------------------------------------
    // Reset tests
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_all_state() {
        let mut rt = make_runtime(1, vec![2, 3]);
        rt.start_drain(mid(1), "test".into()).unwrap();
        rt.reset();
        assert_eq!(rt.state(), DrainProtocolState::Idle);
        assert!(!rt.is_draining());
        assert!(rt.drain_start.is_none());
        assert!(!rt.forced);
    }

    // -----------------------------------------------------------------------
    // DrainRuntimeError display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let e = DrainRuntimeError::AlreadyDraining {
            existing_node_id: mid(42),
        };
        assert!(format!("{e}").contains("42"));

        let e = DrainRuntimeError::NoActiveDrain;
        assert!(format!("{e}").contains("no active drain"));

        let e = DrainRuntimeError::TimedOut;
        assert!(format!("{e}").contains("timed out"));
    }
}
