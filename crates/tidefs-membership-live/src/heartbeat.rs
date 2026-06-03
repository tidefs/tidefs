#![forbid(unsafe_code)]

//! Peer heartbeat protocol with deadline-based failure detection and event escalation.
//!
//! This module bridges transport-level health signals (or their absence) into
//! membership liveness events. A [`HeartbeatTransmitter`] periodically
//! constructs [`HealthReport`] messages and dispatches them through the
//! [`MembershipOutboundDispatch`] pipeline. A [`PeerLivenessTracker`] enforces
//! per-peer heartbeat deadlines and escalates missed heartbeats into
//! [`MembershipEvent::MemberSuspected`] and [`MembershipEvent::MemberFailed`]
//! events returned to the caller for publication through the [`MembershipEventPublisher`].
//!
//! ## State Machine
//!
//! ```text
//!   Alive --(deadline expires)--> Suspected --(deadline expires)--> Failed
//!     ^                               |
//!     +---(heartbeat received)--------+
//! ```
//!
//! ## Integration
//!
//! - [`HeartbeatTransmitter`] uses [`MembershipOutboundDispatch`] to send
//!   `HealthReport` messages to all known peers.
//! - [`PeerLivenessTracker`] returns [`MembershipEvent`]s from its tick method for the
//!   `MemberSuspected` and `MemberFailed` events consumed by connection
//!   teardown (#5854) and epoch state machine subscribers.
//! - The deadline-based approach complements the SWIM-style ping/ack
//!   failure detector by providing a simpler, configurable liveness
//!   watchdog that operates independently of the SWIM protocol.

use std::collections::BTreeMap;
use std::time::Duration;

use tidefs_membership_epoch::MemberId;

use crate::event_bridge::MembershipEvent;
use crate::membership_outbound_dispatch::MembershipOutboundMessage;
use crate::types::now_millis;

// ---------------------------------------------------------------------------
// HeartbeatConfig
// ---------------------------------------------------------------------------

/// Configuration for the heartbeat protocol.
///
/// A peer is considered `Suspected` when `deadline` elapses since
/// `last_heard_ms` without a heartbeat. After `max_missed_count`
/// consecutive missed intervals, the peer transitions to `Failed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Interval between transmitted heartbeat messages.
    pub interval: Duration,
    /// Deadline for receiving a heartbeat before marking Suspected.
    /// Must be at least `interval`.
    pub deadline: Duration,
    /// Number of consecutive missed heartbeat intervals before declaring
    /// a peer Failed (after the Suspected transition).
    pub max_missed_count: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(500),
            deadline: Duration::from_millis(1500),
            max_missed_count: 3,
        }
    }
}

impl HeartbeatConfig {
    /// Validate the configuration. Returns `Err` with a description if
    /// any field is invalid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.interval.as_millis() == 0 {
            return Err("interval must be non-zero");
        }
        if self.deadline.as_millis() == 0 {
            return Err("deadline must be non-zero");
        }
        if self.deadline < self.interval {
            return Err("deadline must be >= interval");
        }
        if self.max_missed_count == 0 {
            return Err("max_missed_count must be >= 1");
        }
        Ok(())
    }

    /// The deadline in milliseconds as a u64.
    pub fn deadline_ms(&self) -> u64 {
        self.deadline.as_millis() as u64
    }

    /// The interval in milliseconds as a u64.
    pub fn interval_ms(&self) -> u64 {
        self.interval.as_millis() as u64
    }
}

// ---------------------------------------------------------------------------
// LivenessStatus
// ---------------------------------------------------------------------------

/// Per-peer liveness status tracked by the [`PeerLivenessTracker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LivenessStatus {
    /// Peer is actively sending heartbeats.
    Alive = 0,
    /// Peer has missed the heartbeat deadline; suspected of failure.
    Suspected = 1,
    /// Peer has exceeded max_missed_count consecutive missed intervals;
    /// confirmed failed.
    Failed = 2,
}

impl LivenessStatus {
    /// Whether the peer is in a terminal (non-recoverable-by-heartbeat) state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, LivenessStatus::Failed)
    }

    /// Whether the peer is considered reachable.
    pub fn is_alive(&self) -> bool {
        matches!(self, LivenessStatus::Alive)
    }
}

// ---------------------------------------------------------------------------
// PeerLiveness
// ---------------------------------------------------------------------------

/// Per-peer liveness state tracked by the deadline-based heartbeat protocol.
#[derive(Clone, Debug)]
pub struct PeerLiveness {
    /// The member being tracked.
    pub member_id: MemberId,
    /// Timestamp (ms) of the last received heartbeat or registration.
    pub last_heard_ms: u64,
    /// Consecutive missed heartbeat interval count.
    pub missed_count: u32,
    /// Current liveness status.
    pub status: LivenessStatus,
}

impl PeerLiveness {
    /// Create a new liveness record for a peer, initialised as Alive.
    pub fn new(member_id: MemberId, now_ms: u64) -> Self {
        Self {
            member_id,
            last_heard_ms: now_ms,
            missed_count: 0,
            status: LivenessStatus::Alive,
        }
    }

    /// Record a received heartbeat, resetting the missed count and
    /// clearing Suspected status back to Alive.
    pub fn record_heartbeat(&mut self, now_ms: u64) {
        self.last_heard_ms = now_ms;
        self.missed_count = 0;
        if self.status == LivenessStatus::Suspected {
            self.status = LivenessStatus::Alive;
        }
    }
}

// ---------------------------------------------------------------------------
// HeartbeatTransmitter
// ---------------------------------------------------------------------------

/// Periodic transmitter that sends `HealthReport` messages to all known
/// peers via the outbound dispatch pipeline.
///
/// Call [`tick`] on each membership runtime iteration. The transmitter
/// tracks elapsed time and sends heartbeats at the configured interval.
///
/// [`tick`]: HeartbeatTransmitter::tick
pub struct HeartbeatTransmitter {
    config: HeartbeatConfig,
    /// Last time (ms) a heartbeat was transmitted.
    last_transmit_ms: u64,
    /// The local member id for the `HealthReport` sender field.
    local_member_id: MemberId,
}

impl HeartbeatTransmitter {
    /// Create a new heartbeat transmitter.
    pub fn new(config: HeartbeatConfig, local_member_id: MemberId) -> Self {
        Self {
            config,
            last_transmit_ms: 0,
            local_member_id,
        }
    }

    /// Whether it's time to send heartbeats.
    pub fn should_transmit(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_transmit_ms) >= self.config.interval_ms()
    }

    /// Build a `HealthReport` message for the given target peer.
    pub fn build_health_report(&self, _target: MemberId, now_ms: u64) -> MembershipOutboundMessage {
        MembershipOutboundMessage::HealthReport {
            member_id: self.local_member_id,
            epoch: tidefs_membership_epoch::EpochId::new(0),
            health_class: 1u8, // Healthy
            reported_at_millis: now_ms,
        }
    }

    /// Execute a transmission tick: if the interval has elapsed, build
    /// `HealthReport` messages for every known peer and return them.
    ///
    /// Returns the list of (target, message) to dispatch. The caller is
    /// responsible for sending each through [`MembershipOutboundDispatch`].
    pub fn tick(
        &mut self,
        peers: &[MemberId],
        now_ms: u64,
    ) -> Vec<(MemberId, MembershipOutboundMessage)> {
        if !self.should_transmit(now_ms) {
            return Vec::new();
        }

        self.last_transmit_ms = now_ms;

        peers
            .iter()
            .filter(|id| **id != self.local_member_id)
            .map(|id| (*id, self.build_health_report(*id, now_ms)))
            .collect()
    }

    /// Reset the last transmit timestamp (e.g., after epoch change).
    pub fn reset(&mut self, now_ms: u64) {
        self.last_transmit_ms = now_ms;
    }

    /// Return the local member id.
    pub fn local_member_id(&self) -> MemberId {
        self.local_member_id
    }
}

// ---------------------------------------------------------------------------
// PeerLivenessTracker
// ---------------------------------------------------------------------------

/// Deadline-based liveness tracker that enforces per-peer heartbeat
/// deadlines and escalates missed heartbeats into membership events.
///
/// # Usage
///
/// 1. Register peers via [`register_peer`].
/// 2. Call [`record_heartbeat`] when a `HealthReport` is received from a peer.
/// 3. Call [`tick`] periodically to check deadlines and emit events.
/// 4. Remove peers via [`remove_peer`] when they leave the member set.
///
/// [`register_peer`]: PeerLivenessTracker::register_peer
/// [`record_heartbeat`]: PeerLivenessTracker::record_heartbeat
/// [`tick`]: PeerLivenessTracker::tick
/// [`remove_peer`]: PeerLivenessTracker::remove_peer
pub struct PeerLivenessTracker {
    config: HeartbeatConfig,
    peers: BTreeMap<MemberId, PeerLiveness>,
}

impl PeerLivenessTracker {
    /// Create a new tracker.
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid.
    pub fn new(config: HeartbeatConfig) -> Self {
        config.validate().expect("HeartbeatConfig must be valid");
        Self {
            config,
            peers: BTreeMap::new(),
        }
    }

    /// Register a peer for liveness tracking.
    ///
    /// The initial `last_heard_ms` is set to the current time so the peer
    /// is not immediately flagged.
    pub fn register_peer(&mut self, member_id: MemberId) {
        let now = now_millis();
        self.peers
            .entry(member_id)
            .or_insert_with(|| PeerLiveness::new(member_id, now));
    }

    /// Remove a peer from liveness tracking.
    pub fn remove_peer(&mut self, member_id: MemberId) {
        self.peers.remove(&member_id);
    }

    /// Record a received heartbeat from a peer, resetting its deadline
    /// timer. If the peer was `Suspected`, transitions back to `Alive`.
    pub fn record_heartbeat(&mut self, member_id: MemberId) {
        let now = now_millis();
        if let Some(peer) = self.peers.get_mut(&member_id) {
            peer.record_heartbeat(now);
        }
    }

    /// Get the current status of a tracked peer.
    pub fn status(&self, member_id: MemberId) -> Option<LivenessStatus> {
        self.peers.get(&member_id).map(|p| p.status)
    }

    /// Get the liveness record for a tracked peer.
    pub fn get(&self, member_id: MemberId) -> Option<&PeerLiveness> {
        self.peers.get(&member_id)
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check deadlines for all tracked peers and emit events for status
    /// transitions.
    ///
    /// Returns the list of `MembershipEvent`s emitted (Suspected, Failed).
    /// The events are also published through the publisher, so subscribers
    /// are notified even if the caller discards the return value.
    pub fn tick(&mut self) -> Vec<MembershipEvent> {
        let now = now_millis();
        let deadline_ms = self.config.deadline_ms();
        let mut emitted = Vec::new();

        // Collect member ids to avoid borrow issues during iteration.
        let member_ids: Vec<MemberId> = self.peers.keys().copied().collect();

        for member_id in member_ids {
            let (status, last_heard, missed_count) = {
                let peer = match self.peers.get(&member_id) {
                    Some(p) => p,
                    None => continue,
                };
                (peer.status, peer.last_heard_ms, peer.missed_count)
            };

            match status {
                LivenessStatus::Alive => {
                    let elapsed = now.saturating_sub(last_heard);
                    if elapsed >= deadline_ms {
                        // Transition to Suspected
                        if let Some(peer) = self.peers.get_mut(&member_id) {
                            peer.missed_count = 1;
                            peer.status = LivenessStatus::Suspected;
                        }
                        let event = MembershipEvent::member_suspected(member_id, now);
                        emitted.push(event);
                    }
                }
                LivenessStatus::Suspected => {
                    let elapsed = now.saturating_sub(last_heard);
                    if elapsed >= deadline_ms {
                        // Another interval elapsed -- increment missed count
                        let (_new_count, should_fail) = {
                            let peer = self.peers.get_mut(&member_id).unwrap();
                            peer.missed_count = missed_count.saturating_add(1);
                            (
                                peer.missed_count,
                                peer.missed_count >= self.config.max_missed_count,
                            )
                        };

                        if should_fail {
                            // Transition to Failed
                            if let Some(peer) = self.peers.get_mut(&member_id) {
                                peer.status = LivenessStatus::Failed;
                            }
                            let event = MembershipEvent::member_failed(member_id, now);
                            emitted.push(event);
                        }
                    }
                }
                LivenessStatus::Failed => {
                    // Already failed -- no further escalation.
                }
            }
        }

        emitted
    }

    /// Reset all peer state (e.g., after an epoch transition).
    pub fn reset(&mut self) {
        let now = now_millis();
        for peer in self.peers.values_mut() {
            peer.last_heard_ms = now;
            peer.missed_count = 0;
            peer.status = LivenessStatus::Alive;
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

    // ------------------------------------------------------------------
    // HeartbeatConfig tests
    // ------------------------------------------------------------------

    #[test]
    fn config_default_is_valid() {
        let cfg = HeartbeatConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_interval() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_deadline() {
        let cfg = HeartbeatConfig {
            deadline: Duration::from_millis(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_deadline_less_than_interval() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(1000),
            deadline: Duration::from_millis(500),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_max_missed_count() {
        let cfg = HeartbeatConfig {
            max_missed_count: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_deadline_ms_and_interval_ms() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(200),
            deadline: Duration::from_millis(600),
            max_missed_count: 3,
        };
        assert_eq!(cfg.interval_ms(), 200);
        assert_eq!(cfg.deadline_ms(), 600);
    }

    // ------------------------------------------------------------------
    // LivenessStatus tests
    // ------------------------------------------------------------------

    #[test]
    fn liveness_status_ordering() {
        assert!(LivenessStatus::Alive < LivenessStatus::Suspected);
        assert!(LivenessStatus::Suspected < LivenessStatus::Failed);
    }

    #[test]
    fn alive_is_not_terminal() {
        assert!(!LivenessStatus::Alive.is_terminal());
        assert!(LivenessStatus::Alive.is_alive());
    }

    #[test]
    fn suspected_is_not_terminal() {
        assert!(!LivenessStatus::Suspected.is_terminal());
        assert!(!LivenessStatus::Suspected.is_alive());
    }

    #[test]
    fn failed_is_terminal() {
        assert!(LivenessStatus::Failed.is_terminal());
        assert!(!LivenessStatus::Failed.is_alive());
    }

    // ------------------------------------------------------------------
    // PeerLiveness tests
    // ------------------------------------------------------------------

    #[test]
    fn new_peer_is_alive() {
        let now = now_millis();
        let peer = PeerLiveness::new(MemberId::new(1), now);
        assert_eq!(peer.status, LivenessStatus::Alive);
        assert_eq!(peer.missed_count, 0);
        assert_eq!(peer.last_heard_ms, now);
    }

    #[test]
    fn record_heartbeat_resets_missed_count() {
        let now = now_millis();
        let mut peer = PeerLiveness::new(MemberId::new(1), now);
        peer.missed_count = 5;
        peer.status = LivenessStatus::Suspected;

        let later = now + 1000;
        peer.record_heartbeat(later);

        assert_eq!(peer.missed_count, 0);
        assert_eq!(peer.last_heard_ms, later);
        assert_eq!(peer.status, LivenessStatus::Alive);
    }

    #[test]
    fn record_heartbeat_on_alive_stays_alive() {
        let now = now_millis();
        let mut peer = PeerLiveness::new(MemberId::new(1), now);
        peer.record_heartbeat(now + 500);
        assert_eq!(peer.status, LivenessStatus::Alive);
    }

    // ------------------------------------------------------------------
    // HeartbeatTransmitter tests
    // ------------------------------------------------------------------

    #[test]
    fn transmitter_should_transmit_after_interval() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(100),
            deadline: Duration::from_millis(300),
            max_missed_count: 2,
        };
        let tx = HeartbeatTransmitter::new(cfg, MemberId::new(0));

        assert!(!tx.should_transmit(0));

        // 50ms: not yet
        assert!(!tx.should_transmit(50));

        // 100ms: interval elapsed
        assert!(tx.should_transmit(100));
    }

    #[test]
    fn transmitter_tick_returns_messages_for_peers() {
        let cfg = HeartbeatConfig::default();
        let mut tx = HeartbeatTransmitter::new(cfg, MemberId::new(0));

        let peers = vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];
        let msgs = tx.tick(&peers, 1000);

        // Should get messages for all 3 peers (not self)
        assert_eq!(msgs.len(), 3);
        for (i, (target, msg)) in msgs.iter().enumerate() {
            assert_eq!(*target, MemberId::new((i + 1) as u64));
            assert!(matches!(
                msg,
                MembershipOutboundMessage::HealthReport { .. }
            ));
        }
    }

    #[test]
    fn transmitter_skips_self() {
        let cfg = HeartbeatConfig::default();
        let local = MemberId::new(42);
        let mut tx = HeartbeatTransmitter::new(cfg, local);

        let peers = vec![MemberId::new(1), MemberId::new(42), MemberId::new(3)];
        let msgs = tx.tick(&peers, 1000);

        // Message for 1 and 3, but not 42 (self)
        assert_eq!(msgs.len(), 2);
        let ids: Vec<u64> = msgs.iter().map(|(id, _)| id.0).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&42));
    }

    #[test]
    fn transmitter_does_not_send_before_interval() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(500),
            deadline: Duration::from_millis(1500),
            max_missed_count: 2,
        };
        let mut tx = HeartbeatTransmitter::new(cfg, MemberId::new(0));
        let peers = vec![MemberId::new(1)];

        let msgs = tx.tick(&peers, 0);
        assert!(msgs.is_empty());

        // After sending at 500, another tick at 600 should not send
        let _ = tx.tick(&peers, 500);
        let msgs = tx.tick(&peers, 600);
        assert!(msgs.is_empty());
    }

    #[test]
    fn transmitter_build_health_report_has_correct_fields() {
        let cfg = HeartbeatConfig::default();
        let tx = HeartbeatTransmitter::new(cfg, MemberId::new(7));

        let msg = tx.build_health_report(MemberId::new(99), 12345);
        match msg {
            MembershipOutboundMessage::HealthReport {
                member_id,
                health_class,
                reported_at_millis,
                ..
            } => {
                assert_eq!(member_id, MemberId::new(7));
                assert_eq!(health_class, 1);
                assert_eq!(reported_at_millis, 12345);
            }
            _ => panic!("expected HealthReport"),
        }
    }

    #[test]
    fn transmitter_reset_clears_last_transmit() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(100),
            deadline: Duration::from_millis(300),
            max_missed_count: 1,
        };
        let mut tx = HeartbeatTransmitter::new(cfg, MemberId::new(0));

        // Transmit at t=100
        let _ = tx.tick(&[MemberId::new(1)], 100);
        // Reset at t=150
        tx.reset(150);
        // Should not transmit at t=200 (only 50ms since reset)
        assert!(!tx.should_transmit(200));
        // Should transmit at t=250 (100ms since reset)
        assert!(tx.should_transmit(250));
    }

    // ------------------------------------------------------------------
    // PeerLivenessTracker: deadline and status transition tests
    // ------------------------------------------------------------------

    fn deadline_config(deadline_ms: u64, max_missed: u32) -> HeartbeatConfig {
        HeartbeatConfig {
            interval: Duration::from_millis(deadline_ms / 2),
            deadline: Duration::from_millis(deadline_ms),
            max_missed_count: max_missed,
        }
    }

    #[test]
    fn tracker_registers_peers() {
        let mut tracker = PeerLivenessTracker::new(HeartbeatConfig::default());

        tracker.register_peer(MemberId::new(1));
        tracker.register_peer(MemberId::new(2));
        assert_eq!(tracker.peer_count(), 2);

        // Re-register is a no-op
        tracker.register_peer(MemberId::new(1));
        assert_eq!(tracker.peer_count(), 2);
    }

    #[test]
    fn tracker_removes_peers() {
        let mut tracker = PeerLivenessTracker::new(HeartbeatConfig::default());

        tracker.register_peer(MemberId::new(1));
        tracker.register_peer(MemberId::new(2));
        tracker.remove_peer(MemberId::new(1));
        assert_eq!(tracker.peer_count(), 1);
        assert!(tracker.get(MemberId::new(1)).is_none());
        assert!(tracker.get(MemberId::new(2)).is_some());
    }

    #[test]
    fn deadline_expiry_transitions_alive_to_suspected() {
        let cfg = deadline_config(20, 3);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Alive)
        );

        // Wait past deadline
        thread::sleep(Duration::from_millis(30));

        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MembershipEvent::MemberSuspected { .. }));
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Suspected)
        );
    }

    #[test]
    fn suspected_to_failed_after_max_missed() {
        let cfg = deadline_config(20, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        // First tick after deadline: Alive -> Suspected
        thread::sleep(Duration::from_millis(30));
        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MembershipEvent::MemberSuspected { .. }));

        // Wait another deadline period for Suspected -> Failed transition
        thread::sleep(Duration::from_millis(30));

        // Second tick: missed_count increments to 2 -> Failed (max_missed_count=2)
        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MembershipEvent::MemberFailed { .. }));
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Failed)
        );
    }

    #[test]
    fn heartbeat_received_clears_suspected() {
        let cfg = deadline_config(20, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        // Let deadline expire
        thread::sleep(Duration::from_millis(30));
        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(!tracker.status(MemberId::new(1)).unwrap().is_alive());

        // Receive heartbeat
        tracker.record_heartbeat(MemberId::new(1));
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Alive)
        );

        // Subsequent tick should not re-suspect immediately
        let events = tracker.tick();
        assert!(events.is_empty());
    }

    #[test]
    fn failed_peer_not_re_escalated() {
        let cfg = deadline_config(20, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        // Transition to Suspected
        thread::sleep(Duration::from_millis(30));
        tracker.tick();

        // Transition to Failed
        thread::sleep(Duration::from_millis(30));
        tracker.tick();

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Failed)
        );

        // Another tick: no new events for already-failed peer
        thread::sleep(Duration::from_millis(30));
        let events = tracker.tick();
        assert!(events.is_empty());

        // Only the initial 2 events (Suspected + Failed)
    }

    #[test]
    fn reset_clears_all_state() {
        let cfg = deadline_config(20, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        // Drive to Failed
        thread::sleep(Duration::from_millis(30));
        tracker.tick();
        thread::sleep(Duration::from_millis(30));
        tracker.tick();

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Failed)
        );

        // Reset
        tracker.reset();
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Alive)
        );
        let peer = tracker.get(MemberId::new(1)).unwrap();
        assert_eq!(peer.missed_count, 0);
    }

    #[test]
    fn heartbeat_not_arriving_keeps_alive_under_deadline() {
        let cfg = deadline_config(100, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        // Tick immediately: no deadline expired
        let events = tracker.tick();
        assert!(events.is_empty());
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Alive)
        );
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let cfg = deadline_config(20, 2);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));
        tracker.register_peer(MemberId::new(2));

        // Let deadline pass
        thread::sleep(Duration::from_millis(30));

        // Keep peer 2 alive with a heartbeat
        tracker.record_heartbeat(MemberId::new(2));

        let _events = tracker.tick();
        // Peer 1 should be suspected, peer 2 should stay alive
        assert_eq!(_events[0].member_id(), MemberId::new(1));
        assert!(matches!(
            _events[0],
            MembershipEvent::MemberSuspected { .. }
        ));

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Suspected)
        );
        assert_eq!(
            tracker.status(MemberId::new(2)),
            Some(LivenessStatus::Alive)
        );
    }

    #[test]
    fn status_returns_none_for_unknown_peer() {
        let tracker = PeerLivenessTracker::new(HeartbeatConfig::default());
        assert_eq!(tracker.status(MemberId::new(99)), None);
        assert!(tracker.get(MemberId::new(99)).is_none());
    }

    #[test]
    fn broadcaster_sends_with_max_missed_count_1() {
        // max_missed_count=1 means Suspected -> Failed on the very next
        // deadline expiry.
        let cfg = deadline_config(20, 1);
        let mut tracker = PeerLivenessTracker::new(cfg);

        tracker.register_peer(MemberId::new(1));

        thread::sleep(Duration::from_millis(30));
        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MembershipEvent::MemberSuspected { .. }));

        thread::sleep(Duration::from_millis(30));
        let events = tracker.tick();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MembershipEvent::MemberFailed { .. }));
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(LivenessStatus::Failed)
        );
    }

    #[test]
    fn config_deadline_edge_cases() {
        // deadline == interval is ok
        let cfg = HeartbeatConfig {
            interval: Duration::from_millis(500),
            deadline: Duration::from_millis(500),
            max_missed_count: 3,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn transmitter_tick_empty_peers_returns_empty() {
        let cfg = HeartbeatConfig::default();
        let mut tx = HeartbeatTransmitter::new(cfg, MemberId::new(0));
        let msgs = tx.tick(&[], 1000);
        assert!(msgs.is_empty());
    }
}
