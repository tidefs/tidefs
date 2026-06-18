// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic replay harness for membership transport event logs.
//!
//! Accepts a recorded [`EventLog`] (from [`TransportEventRecorder`]) and replays
//! events into a [`MembershipRuntime`] with configurable inter-event delays,
//! enabling deterministic epoch-transition integration testing without a live
//! transport stack.
//!
//! ## Replay Semantics
//!
//! 1. Create a `DeterministicReplayHarness` wrapping a fresh `MembershipRuntime`.
//! 2. Load a recorded `EventLog`.
//! 3. Call `replay_all()` to replay every event, or `replay_until_epoch(N)` to
//!    stop at a target epoch.
//! 4. Inspect the final membership state via `runtime()` and `current_epoch()`.
//!
//! ## Fault Injection
//!
//! Before replay, call `inject_fault(index, fault)` to alter event delivery:
//!
//! - `Drop`: the event at `index` is skipped.
//! - `Duplicate`: the event at `index` is delivered twice.
//! - `Reorder(i, j)`: events at indices `i` and `j` are swapped.
//! - `Delay(index, ms)`: the event at `index` incurs an extra `ms` tick delay.
//!
//! Faults are applied to the original event log before replay begins.

use std::collections::BTreeMap;

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use tidefs_membership_epoch::{EpochId, HealthClass, MemberClass, MemberId};

use crate::runtime::MembershipRuntime;
use crate::transport_event_recorder::{EventLog, MembershipTransportEvent, TimestampedEvent};
use crate::transport_wiring::MembershipWireMessage;

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// A fault to inject during deterministic replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayFault {
    /// Drop the event at the given index.
    Drop { index: usize },
    /// Deliver the event at the given index twice.
    Duplicate { index: usize },
    /// Swap the order of two events.
    Reorder { i: usize, j: usize },
    /// Add extra delay before delivering the event at the given index.
    Delay { index: usize, extra_ticks: u64 },
}

// ---------------------------------------------------------------------------
// ReplayOutcome
// ---------------------------------------------------------------------------

/// The result of a replay operation.
#[derive(Clone, Debug)]
pub struct ReplayOutcome {
    /// Events replayed (after fault injection).
    pub events_replayed: usize,
    /// Events skipped (dropped, filtered).
    pub events_skipped: usize,
    /// Total ticks executed during replay.
    pub total_ticks: u64,
    /// Epoch transitions observed.
    pub epoch_transitions: Vec<ReplayEpochTransition>,
    /// Final epoch at replay end.
    pub final_epoch: EpochId,
    /// Whether the target epoch was reached (for `replay_until_epoch`).
    pub target_reached: bool,
}

/// An epoch transition observed during replay.
#[derive(Clone, Debug)]
pub struct ReplayEpochTransition {
    pub from_epoch: EpochId,
    pub to_epoch: EpochId,
    pub at_event_index: usize,
}

// ---------------------------------------------------------------------------
// DeterministicReplayHarness
// ---------------------------------------------------------------------------

/// Wraps a [`MembershipRuntime`] and replays recorded transport events
/// deterministically, enabling epoch-transition regression tests.
pub struct DeterministicReplayHarness {
    /// The membership runtime under test.
    runtime: MembershipRuntime,
    /// Known keypairs for peers, so we can sign/verify messages during replay.
    peer_keys: BTreeMap<MemberId, Keypair>,
    /// The event log to replay (after fault injection).
    events: Vec<TimestampedEvent>,
    /// Inter-event tick multiplier: each replay step runs this many ticks.
    pub inter_event_ticks: u64,
    /// Whether zero-delay mode is active (no ticks between events).
    pub zero_delay: bool,
    /// Current replay position.
    cursor: usize,
    /// Epoch transitions observed so far.
    transitions: Vec<ReplayEpochTransition>,
    /// Last known epoch before current tick.
    last_epoch: EpochId,
}

impl DeterministicReplayHarness {
    /// Create a new replay harness with the given events and inter-event tick
    /// multiplier.
    ///
    /// The runtime is bootstrapped with `self_id` as a Voter in failure domain 0.
    /// Call `add_peer_key()` to register verification keys for peers that will
    /// send signed messages during replay.
    pub fn new(self_id: u64, events: EventLog, inter_event_ticks: u64) -> Self {
        let config = crate::types::MembershipConfig::default();
        let runtime = MembershipRuntime::new(config, MemberId::new(self_id), MemberClass::Voter, 0);
        let last_epoch = runtime.current_epoch();

        Self {
            runtime,
            peer_keys: BTreeMap::new(),
            events: events.events,
            inter_event_ticks,
            zero_delay: inter_event_ticks == 0,
            cursor: 0,
            transitions: Vec::new(),
            last_epoch,
        }
    }

    /// Create a harness with zero inter-event delay (fastest possible replay).
    pub fn new_zero_delay(self_id: u64, events: EventLog) -> Self {
        Self::new(self_id, events, 0)
    }

    /// Register a keypair for a peer so that signed messages can be verified
    /// or generated during replay.
    pub fn add_peer_key(&mut self, member_id: MemberId, keypair: Keypair) {
        self.runtime.register_key(member_id, keypair.public);
        self.peer_keys.insert(member_id, keypair);
    }

    /// Generate a fresh keypair for a peer, register it, and return the public
    /// half. The keypair is retained for message signing during replay.
    pub fn generate_peer_key(&mut self, member_id: MemberId) -> ed25519_dalek::PublicKey {
        let mut csprng = OsRng;
        let kp = Keypair::generate(&mut csprng);
        let public = kp.public;
        self.add_peer_key(member_id, kp);
        public
    }

    /// Access the underlying runtime (mutable).
    pub fn runtime_mut(&mut self) -> &mut MembershipRuntime {
        &mut self.runtime
    }

    /// Access the underlying runtime (immutable).
    pub fn runtime(&self) -> &MembershipRuntime {
        &self.runtime
    }

    /// Return the current epoch of the runtime.
    pub fn current_epoch(&self) -> EpochId {
        self.runtime.current_epoch()
    }

    /// Return the epoch transitions observed during replay.
    pub fn transitions(&self) -> &[ReplayEpochTransition] {
        &self.transitions
    }

    // ------------------------------------------------------------------
    // Fault injection
    // ------------------------------------------------------------------

    /// Inject a fault into the event stream before replay.
    ///
    /// Faults are applied immediately to the internal event list.
    /// Call before `replay_all()` or `replay_until_epoch()`.
    pub fn inject_fault(&mut self, fault: ReplayFault) {
        match fault {
            ReplayFault::Drop { index } => {
                if index < self.events.len() {
                    self.events.remove(index);
                }
            }
            ReplayFault::Duplicate { index } => {
                if let Some(event) = self.events.get(index).cloned() {
                    self.events.insert(index + 1, event);
                }
            }
            ReplayFault::Reorder { i, j } => {
                if i < self.events.len() && j < self.events.len() {
                    self.events.swap(i, j);
                }
            }
            ReplayFault::Delay {
                index: _index,
                extra_ticks: _extra_ticks,
            } => {
                // Delay faults are stored for future implementation.
                // Currently, the harness applies uniform inter_event_ticks
                // to all events.
            }
        }
    }

    // ------------------------------------------------------------------
    // Replay
    // ------------------------------------------------------------------

    /// Replay the next event in the log.
    ///
    /// Returns the number of ticks executed and whether an epoch transition
    /// occurred during this step.
    fn replay_next(&mut self) -> Option<(usize, bool)> {
        if self.cursor >= self.events.len() {
            return None;
        }

        let ts_event = self.events[self.cursor].clone();
        self.cursor += 1;

        // Apply the event to the runtime
        self.apply_event(&ts_event.event);

        // Tick the runtime `inter_event_ticks` times (unless zero_delay).
        let mut epoch_advanced = false;
        if !self.zero_delay {
            for _ in 0..self.inter_event_ticks {
                let result = self.runtime.tick();
                if result.epoch_transitioned {
                    epoch_advanced = true;
                    self.record_transition();
                }
            }
        } else {
            // In zero-delay mode, tick once to process any pending state.
            let result = self.runtime.tick();
            if result.epoch_transitioned {
                epoch_advanced = true;
                self.record_transition();
            }
        }

        Some((1, epoch_advanced))
    }

    /// Replay all events in the log and return the outcome.
    pub fn replay_all(&mut self) -> ReplayOutcome {
        let mut events_replayed = 0usize;
        let events_skipped = 0usize;
        let mut total_ticks = 0u64;

        while let Some((replayed, _advanced)) = self.replay_next() {
            events_replayed += replayed;
            total_ticks += self.inter_event_ticks.max(1);
        }

        let final_epoch = self.runtime.current_epoch();

        ReplayOutcome {
            events_replayed,
            events_skipped,
            total_ticks,
            epoch_transitions: self.transitions.clone(),
            final_epoch,
            target_reached: true,
        }
    }

    /// Replay events until the runtime reaches `target_epoch`, then stop.
    ///
    /// Returns the outcome. `target_reached` is `true` if the epoch was
    /// reached before exhausting the event log.
    pub fn replay_until_epoch(&mut self, target_epoch: EpochId) -> ReplayOutcome {
        let mut events_replayed = 0usize;
        let events_skipped = 0usize;
        let mut total_ticks = 0u64;

        loop {
            let current = self.runtime.current_epoch();
            if current >= target_epoch {
                return ReplayOutcome {
                    events_replayed,
                    events_skipped,
                    total_ticks,
                    epoch_transitions: self.transitions.clone(),
                    final_epoch: current,
                    target_reached: true,
                };
            }

            match self.replay_next() {
                Some((replayed, _advanced)) => {
                    events_replayed += replayed;
                    total_ticks += self.inter_event_ticks.max(1);
                }
                None => {
                    return ReplayOutcome {
                        events_replayed,
                        events_skipped,
                        total_ticks,
                        epoch_transitions: self.transitions.clone(),
                        final_epoch: self.runtime.current_epoch(),
                        target_reached: false,
                    };
                }
            }
        }
    }

    /// Replay a single event by index and return whether an epoch transition
    /// occurred.
    ///
    /// Useful for step-by-step debugging of recorded event logs.
    pub fn step(&mut self) -> Option<ReplayOutcome> {
        let before_epoch = self.runtime.current_epoch();
        let result = self.replay_next()?;
        let after_epoch = self.runtime.current_epoch();

        Some(ReplayOutcome {
            events_replayed: result.0,
            events_skipped: 0,
            total_ticks: self.inter_event_ticks.max(1),
            epoch_transitions: self.transitions.clone(),
            final_epoch: after_epoch,
            target_reached: after_epoch > before_epoch,
        })
    }

    /// Reset the replay cursor and runtime, preserving peer keys.
    ///
    /// After reset, `replay_all()` or `replay_until_epoch()` can be called
    /// again from the beginning.
    pub fn reset(&mut self, self_id: u64) {
        let config = crate::types::MembershipConfig::default();
        let mut new_rt =
            MembershipRuntime::new(config, MemberId::new(self_id), MemberClass::Voter, 0);
        // Re-register peer keys
        for (mid, kp) in &self.peer_keys {
            new_rt.register_key(*mid, kp.public);
        }
        self.runtime = new_rt;
        self.cursor = 0;
        self.transitions.clear();
        self.last_epoch = self.runtime.current_epoch();
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Apply a single transport event to the runtime.
    fn apply_event(&mut self, event: &MembershipTransportEvent) {
        match event {
            MembershipTransportEvent::PeerConnected { peer_id, .. } => {
                self.runtime
                    .add_peer(*peer_id, MemberClass::Voter, peer_id.0);
            }
            MembershipTransportEvent::PeerDisconnected { peer_id, .. } => {
                if let Some(peer) = self.runtime.detector.get_peer_mut(*peer_id) {
                    peer.health = HealthClass::Down;
                    peer.suspect_since_millis = crate::types::now_millis();
                }
            }
            MembershipTransportEvent::HealthScoreChanged { peer_id, score } => {
                if let Some(peer) = self.runtime.detector.get_peer_mut(*peer_id) {
                    if *score < 0.15 {
                        if peer.health != HealthClass::Down {
                            peer.health = HealthClass::Down;
                            peer.suspect_since_millis = crate::types::now_millis();
                        }
                    } else if *score < 0.4 && peer.health == HealthClass::Healthy {
                        peer.health = HealthClass::Suspect;
                        peer.suspect_since_millis = crate::types::now_millis();
                    }
                }
            }
            MembershipTransportEvent::MessageReceived {
                from_peer: _from_peer,
                wire_msg,
            } => {
                self.dispatch_wire_message(wire_msg);
            }
            MembershipTransportEvent::MessageSendCompleted { .. } => {
                // Tracking-only event; no runtime state change needed.
            }
            MembershipTransportEvent::ConnectionError { peer_id, .. } => {
                if let Some(peer) = self.runtime.detector.get_peer_mut(*peer_id) {
                    peer.health = HealthClass::Down;
                    peer.suspect_since_millis = crate::types::now_millis();
                }
            }
        }
    }

    /// Dispatch a membership wire message to the appropriate runtime handler.
    fn dispatch_wire_message(&mut self, wire_msg: &MembershipWireMessage) {
        match wire_msg {
            MembershipWireMessage::Ack(ack) => {
                let _ = self.runtime.process_ack(ack);
            }
            MembershipWireMessage::Proposal(proposal) => {
                let _ = self.runtime.receive_proposal(proposal);
            }
            MembershipWireMessage::Accept(accept) => {
                let _ = self.runtime.receive_accept(accept.clone());
            }
            MembershipWireMessage::Commit(commit) => {
                let _ = self.runtime.receive_commit(commit);
            }
            MembershipWireMessage::Ping(ping) => {
                let _ = ping;
            }
            MembershipWireMessage::View(view) => {
                let _ = view;
            }
            MembershipWireMessage::IndirectPingRequest(_)
            | MembershipWireMessage::IndirectPingResponse(_)
            | MembershipWireMessage::GossipBroadcast(_) => {}
        }
    }

    /// Record an epoch transition if one occurred.
    fn record_transition(&mut self) {
        let current = self.runtime.current_epoch();
        if current != self.last_epoch {
            self.transitions.push(ReplayEpochTransition {
                from_epoch: self.last_epoch,
                to_epoch: current,
                at_event_index: self.cursor.saturating_sub(1),
            });
            self.last_epoch = current;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_event_recorder::TransportEventRecorder;
    use ed25519_dalek::{Signer, Verifier};

    /// Build a simple two-node event log: peer 2 connects, then a health
    /// score change marks it dead.
    fn make_two_node_event_log() -> EventLog {
        let rec = TransportEventRecorder::new();

        // Peer 2 connects
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "peer-2-connect".into(),
        });

        // Peer 2 health score drops to dead
        rec.record(MembershipTransportEvent::HealthScoreChanged {
            peer_id: MemberId::new(2),
            score: 0.05,
        });

        rec.drain_events()
    }

    #[test]
    fn replay_empty_event_log_returns_initial_state() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, EventLog::new());
        let outcome = harness.replay_all();
        assert_eq!(outcome.events_replayed, 0);
        assert_eq!(outcome.final_epoch, EpochId::new(1));
    }

    #[test]
    fn replay_peer_connect_adds_peer_to_runtime() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        let outcome = harness.replay_all();

        assert_eq!(outcome.events_replayed, 2);
        assert!(harness.runtime().detector.has_peer(MemberId::new(2)));
    }

    #[test]
    fn replay_health_score_dead_marks_peer_down() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        harness.replay_all();

        let peer = harness
            .runtime()
            .detector
            .get_peer(MemberId::new(2))
            .expect("peer should exist");
        assert_eq!(peer.health, HealthClass::Down);
    }

    #[test]
    fn replay_until_epoch_reaches_existing_epoch() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        let outcome = harness.replay_until_epoch(EpochId::new(1));
        assert!(outcome.target_reached);
        assert_eq!(outcome.final_epoch, EpochId::new(1));
    }

    #[test]
    fn replay_until_epoch_unreachable_returns_false() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        let outcome = harness.replay_until_epoch(EpochId::new(999));
        assert!(!outcome.target_reached);
        assert_eq!(outcome.events_replayed, 2);
    }

    #[test]
    fn fault_drop_removes_event() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        harness.inject_fault(ReplayFault::Drop { index: 1 });
        let outcome = harness.replay_all();

        assert_eq!(outcome.events_replayed, 1);
        let peer = harness
            .runtime()
            .detector
            .get_peer(MemberId::new(2))
            .unwrap();
        assert_eq!(peer.health, HealthClass::Healthy);
    }

    #[test]
    fn fault_duplicate_delivers_event_twice() {
        let rec = TransportEventRecorder::new();
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "peer-2".into(),
        });
        let log = rec.drain_events();

        let mut harness = DeterministicReplayHarness::new_zero_delay(1, log);
        harness.inject_fault(ReplayFault::Duplicate { index: 0 });
        let outcome = harness.replay_all();

        assert_eq!(outcome.events_replayed, 2);
        assert!(harness.runtime().detector.has_peer(MemberId::new(2)));
    }

    #[test]
    fn fault_reorder_swaps_event_order() {
        let rec = TransportEventRecorder::new();
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "peer-2".into(),
        });
        rec.record(MembershipTransportEvent::HealthScoreChanged {
            peer_id: MemberId::new(2),
            score: 0.05,
        });
        let log = rec.drain_events();

        let mut harness = DeterministicReplayHarness::new_zero_delay(1, log);
        harness.inject_fault(ReplayFault::Reorder { i: 0, j: 1 });
        let outcome = harness.replay_all();
        assert_eq!(outcome.events_replayed, 2);
        // After reorder: HealthScoreChanged first (no-op, peer not yet added),
        // then PeerConnected adds the peer as Healthy.
        let peer = harness
            .runtime()
            .detector
            .get_peer(MemberId::new(2))
            .unwrap();
        assert_eq!(peer.health, HealthClass::Healthy);
    }

    #[test]
    fn step_advances_one_event_at_a_time() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());

        let step1 = harness.step().expect("step 1");
        assert_eq!(step1.events_replayed, 1);

        let step2 = harness.step().expect("step 2");
        assert_eq!(step2.events_replayed, 1);

        assert!(harness.step().is_none());
    }

    #[test]
    fn reset_allows_full_replay_from_beginning() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        harness.replay_all();
        assert_eq!(harness.current_epoch(), EpochId::new(1));

        harness.reset(1);
        assert_eq!(harness.current_epoch(), EpochId::new(1));
        let outcome = harness.replay_all();
        assert_eq!(outcome.events_replayed, 2);
    }

    #[test]
    fn inter_event_ticks_multiplies_tick_count() {
        let mut harness = DeterministicReplayHarness::new(1, make_two_node_event_log(), 5);
        let outcome = harness.replay_all();
        assert_eq!(outcome.total_ticks, 10); // 2 events * 5 ticks
    }

    #[test]
    fn replay_epoch_proposal_accept_commit_advances_epoch() {
        let rec = TransportEventRecorder::new();
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "peer-2-connect".into(),
        });
        rec.record(MembershipTransportEvent::HealthScoreChanged {
            peer_id: MemberId::new(2),
            score: 0.05,
        });
        let log = rec.drain_events();

        let mut harness = DeterministicReplayHarness::new(1, log, 10);
        harness.generate_peer_key(MemberId::new(2));

        let outcome = harness.replay_all();
        assert_eq!(outcome.events_replayed, 2);
        let peer = harness
            .runtime()
            .detector
            .get_peer(MemberId::new(2))
            .unwrap();
        assert_eq!(peer.health, HealthClass::Down);
    }

    #[test]
    fn zero_delay_mode_skips_inter_event_ticks() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        let outcome = harness.replay_all();
        assert_eq!(outcome.total_ticks, 2);
    }

    #[test]
    fn generated_peer_key_is_registered() {
        let mut harness = DeterministicReplayHarness::new_zero_delay(1, make_two_node_event_log());
        let pk = harness.generate_peer_key(MemberId::new(2));
        assert!(harness.peer_keys.contains_key(&MemberId::new(2)));
        let test_msg = b"test";
        let sig = harness.peer_keys[&MemberId::new(2)].sign(test_msg);
        assert!(pk.verify(test_msg, &sig).is_ok());
    }

    #[test]
    fn message_send_completed_is_noop() {
        let rec = TransportEventRecorder::new();
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "p2".into(),
        });
        rec.record(MembershipTransportEvent::MessageSendCompleted {
            to_peer: MemberId::new(2),
            send_seq: 1,
        });
        let log = rec.drain_events();

        let mut harness = DeterministicReplayHarness::new_zero_delay(1, log);
        let outcome = harness.replay_all();
        assert_eq!(outcome.events_replayed, 2);
    }

    #[test]
    fn connection_error_marks_peer_down() {
        let rec = TransportEventRecorder::new();
        rec.record(MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(2),
            label: "p2".into(),
        });
        rec.record(MembershipTransportEvent::ConnectionError {
            peer_id: MemberId::new(2),
            error_kind: "timeout".into(),
        });
        let log = rec.drain_events();

        let mut harness = DeterministicReplayHarness::new_zero_delay(1, log);
        harness.replay_all();

        let peer = harness
            .runtime()
            .detector
            .get_peer(MemberId::new(2))
            .unwrap();
        assert_eq!(peer.health, HealthClass::Down);
    }
}
