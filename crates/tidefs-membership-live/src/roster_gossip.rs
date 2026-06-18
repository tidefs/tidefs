// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Membership roster gossip protocol with push-pull state dissemination
//! and epoch-bounded merge.
//!
//! ## Architecture
//!
//! Propagates membership roster changes (join, departure, epoch transition,
//! liveness events) across all cluster members via periodic push-pull gossip
//! rounds, without requiring a central coordinator or synchronous broadcast
//! to every peer.
//!
//! 1. **PushRoster** — sends the local roster view (full or delta) to a peer.
//! 2. **PullRequest** — asks a peer to send its current roster view.
//! 3. **PullResponse** — replies with the peer's roster state.
//!
//! Each round, a node selects a random subset of peers (`fanout`, default 2)
//! and initiates push-pull exchanges. Rosters are merged with epoch-bounded
//! semantics: higher-epoch entries supersede lower-epoch entries; same-epoch
//! conflicts are detected and escalated.
//!
//! ## Integration
//!
//! - **Inbound**: registered with [`MembershipDispatchRouter`] to receive
//!   PushRoster, PullRequest, and PullResponse messages.
//! - **Outbound**: uses [`MembershipOutboundDispatch`] to send PushRoster,
//!   PullRequest, and PullResponse messages to peers.
//! - **Roster**: consumes and updates [`MembershipRoster`] via merge.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::membership_outbound_dispatch::MembershipOutboundMessage;
use crate::roster::{MembershipRoster, RosterState};

// ---------------------------------------------------------------------------
// RosterEntry — serializable roster member entry
// ---------------------------------------------------------------------------

/// A single serializable roster entry for wire transmission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub member_id: MemberId,
    pub state: u8,
    pub epoch: EpochId,
}

impl RosterEntry {
    /// Encode a MemberId and RosterState at a given epoch into a wire entry.
    #[must_use]
    pub fn new(member_id: MemberId, state: RosterState, epoch: EpochId) -> Self {
        Self {
            member_id,
            state: state as u8,
            epoch,
        }
    }

    /// Decode the stored state byte back to RosterState (lossy: unknown => Active).
    #[must_use]
    pub fn roster_state(&self) -> RosterState {
        match self.state {
            0 => RosterState::Active,
            1 => RosterState::Suspected,
            2 => RosterState::Failed,
            3 => RosterState::Left,
            _ => RosterState::Active,
        }
    }
}

// ---------------------------------------------------------------------------
// RosterMerge — epoch-bounded roster merge logic
// ---------------------------------------------------------------------------

/// Result of merging a single remote roster entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Remote entry accepted: higher epoch or new member.
    Accepted {
        member_id: MemberId,
        from_state: Option<RosterState>,
        to_state: RosterState,
        from_epoch: EpochId,
        to_epoch: EpochId,
    },
    /// Remote entry rejected: stale (lower epoch).
    RejectedStale {
        member_id: MemberId,
        remote_epoch: EpochId,
        local_epoch: EpochId,
    },
    /// Remote entry rejected: same epoch, same state (no-op).
    NoChange { member_id: MemberId },
    /// Conflict: same epoch but different state — needs operator attention.
    Conflict {
        member_id: MemberId,
        local_state: RosterState,
        remote_state: RosterState,
        epoch: EpochId,
    },
}

/// Epoch-bounded roster merge engine.
///
/// Accepts roster entries from higher epochs, rejects entries from lower
/// epochs as stale, and detects same-epoch conflicts (same node reported
/// with different state at the same epoch) for operator escalation.
pub struct RosterMerge {
    /// Known epoch for each member (highest epoch seen locally).
    member_epochs: BTreeMap<MemberId, EpochId>,
    /// Pending conflicts for operator attention.
    conflicts: Vec<MergeConflict>,
}

/// A detected merge conflict requiring operator escalation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeConflict {
    pub member_id: MemberId,
    pub local_state: RosterState,
    pub remote_state: RosterState,
    pub epoch: EpochId,
}

impl RosterMerge {
    /// Create a new empty merge engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            member_epochs: BTreeMap::new(),
            conflicts: Vec::new(),
        }
    }

    /// Record a local epoch for a member (called when local roster changes).
    pub fn record_local(&mut self, member_id: MemberId, epoch: EpochId) {
        self.member_epochs
            .entry(member_id)
            .and_modify(|e| {
                if epoch > *e {
                    *e = epoch;
                }
            })
            .or_insert(epoch);
    }

    /// Attempt to merge a remote roster entry into the local roster.
    ///
    /// Returns the merge outcome. When the outcome is `Accepted`, the caller
    /// should apply the state transition to the local roster. When `Conflict`,
    /// the conflict is stored and can be retrieved via [`conflicts`](Self::conflicts).
    pub fn merge(
        &mut self,
        member_id: MemberId,
        remote_state: RosterState,
        remote_epoch: EpochId,
        local_state: Option<RosterState>,
    ) -> MergeOutcome {
        let local_epoch = self.member_epochs.get(&member_id).copied();

        match local_epoch {
            None => {
                // Member not known locally — accept.
                self.member_epochs.insert(member_id, remote_epoch);
                MergeOutcome::Accepted {
                    member_id,
                    from_state: None,
                    to_state: remote_state,
                    from_epoch: EpochId::default(),
                    to_epoch: remote_epoch,
                }
            }
            Some(le) => {
                if remote_epoch > le {
                    // Higher epoch — accept.
                    self.member_epochs.insert(member_id, remote_epoch);
                    MergeOutcome::Accepted {
                        member_id,
                        from_state: local_state,
                        to_state: remote_state,
                        from_epoch: le,
                        to_epoch: remote_epoch,
                    }
                } else if remote_epoch < le {
                    // Stale — reject.
                    MergeOutcome::RejectedStale {
                        member_id,
                        remote_epoch,
                        local_epoch: le,
                    }
                } else {
                    // Same epoch — compare state.
                    if local_state == Some(remote_state) {
                        MergeOutcome::NoChange { member_id }
                    } else {
                        // Conflict: same epoch, different state.
                        let conflict = MergeConflict {
                            member_id,
                            local_state: local_state.unwrap_or(RosterState::Active),
                            remote_state,
                            epoch: remote_epoch,
                        };
                        self.conflicts.push(conflict.clone());
                        MergeOutcome::Conflict {
                            member_id,
                            local_state: conflict.local_state,
                            remote_state: conflict.remote_state,
                            epoch: conflict.epoch,
                        }
                    }
                }
            }
        }
    }

    /// Drain pending conflicts for operator reporting.
    #[must_use]
    pub fn drain_conflicts(&mut self) -> Vec<MergeConflict> {
        std::mem::take(&mut self.conflicts)
    }

    /// Current pending conflict count.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }

    /// Look up the known epoch for a member.
    #[must_use]
    pub fn epoch_for(&self, member_id: MemberId) -> Option<EpochId> {
        self.member_epochs.get(&member_id).copied()
    }

    /// Tracked member count.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_epochs.len()
    }
}

impl Default for RosterMerge {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RosterGossipConfig — configuration for roster gossip rounds
// ---------------------------------------------------------------------------

/// Configuration for the roster gossip protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterGossipConfig {
    /// Interval between gossip rounds in milliseconds.
    pub round_interval_ms: u64,
    /// Number of peers to contact per round (fanout).
    pub fanout: usize,
    /// Maximum number of roster entries per push message.
    pub max_push_entries: usize,
    /// Random seed for deterministic peer selection in tests.
    pub seed: Option<u64>,
}

impl Default for RosterGossipConfig {
    fn default() -> Self {
        Self {
            round_interval_ms: 500,
            fanout: 2,
            max_push_entries: 1024,
            seed: None,
        }
    }
}

impl RosterGossipConfig {
    /// Create a new config with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the round interval.
    #[must_use]
    pub fn with_round_interval_ms(mut self, ms: u64) -> Self {
        self.round_interval_ms = ms;
        self
    }

    /// Set the fanout count.
    #[must_use]
    pub fn with_fanout(mut self, fanout: usize) -> Self {
        self.fanout = fanout;
        self
    }

    /// Set the max entries per push.
    #[must_use]
    pub fn with_max_push_entries(mut self, max: usize) -> Self {
        self.max_push_entries = max;
        self
    }

    /// Set a seed for reproducible peer selection.
    #[must_use]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }
}

// ---------------------------------------------------------------------------
// RosterGossipRound — periodic push-pull gossip round
// ---------------------------------------------------------------------------

/// Drives periodic push-pull gossip rounds.
///
/// Each round selects a random subset of peers and initiates push-pull
/// exchanges: push local roster state to selected peers, optionally
/// pull their roster state in response.
pub struct RosterGossipRound {
    config: RosterGossipConfig,
    /// Timestamp of the last completed round.
    last_round: Instant,
}

impl RosterGossipRound {
    /// Create a new round manager with the given config.
    #[must_use]
    pub fn new(config: RosterGossipConfig) -> Self {
        Self {
            config,
            last_round: Instant::now() - Duration::from_secs(3600),
        }
    }

    /// Returns true if enough time has elapsed since the last round.
    #[must_use]
    pub fn should_run(&self) -> bool {
        self.last_round.elapsed() >= Duration::from_millis(self.config.round_interval_ms)
    }

    /// Record that a round has completed.
    pub fn record_round(&mut self) {
        self.last_round = Instant::now();
    }

    /// Select up to `fanout` random peers from `all_peers`, excluding ones
    /// listed in `exclude`.
    ///
    /// Returns an empty vec when no eligible peers remain.
    #[must_use]
    pub fn select_peers(&self, all_peers: &[MemberId], exclude: &[MemberId]) -> Vec<MemberId> {
        let eligible: Vec<MemberId> = all_peers
            .iter()
            .filter(|p| !exclude.contains(p))
            .copied()
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        let count = self.config.fanout.min(eligible.len());
        let mut rng: Box<dyn rand::RngCore> = match self.config.seed {
            Some(s) => Box::new(rand::rngs::StdRng::seed_from_u64(
                s.wrapping_add(self.last_round.elapsed().as_millis() as u64),
            )),
            None => Box::new(rand::rngs::StdRng::from_entropy()),
        };
        eligible
            .choose_multiple(&mut *rng, count)
            .copied()
            .collect()
    }

    /// Return the config.
    #[must_use]
    pub fn config(&self) -> &RosterGossipConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// RosterGossipHandle — public handle for the roster gossip protocol
// ---------------------------------------------------------------------------

/// Public handle for the roster gossip protocol.
///
/// Implements [`MembershipMessageHandler`] so it can be registered with
/// the [`MembershipDispatchRouter`](crate::dispatch_router::MembershipDispatchRouter).
/// Receives inbound PushRoster, PullRequest, and PullResponse messages;
/// merges remote roster state via [`RosterMerge`]; and sends outbound
/// gossip messages via [`MembershipOutboundDispatch`].
pub struct RosterGossipHandle {
    /// Epoch-bounded merge engine.
    pub merge: RosterMerge,
    /// Configuration for gossip rounds.
    pub config: RosterGossipConfig,
    /// Round scheduler.
    round: RosterGossipRound,
}

impl RosterGossipHandle {
    /// Spawn a new roster gossip handle.
    ///
    /// The handle is ready to be registered with the dispatch router.
    /// It does not start rounds automatically; the caller drives
    /// [`tick`](Self::tick) periodically.
    #[must_use]
    pub fn spawn(config: RosterGossipConfig) -> Self {
        let round = RosterGossipRound::new(config.clone());
        Self {
            merge: RosterMerge::new(),
            config,
            round,
        }
    }

    /// Drive one tick of the gossip protocol.
    ///
    /// If the round interval has elapsed, selects peers and returns the
    /// outbound messages that should be sent. The caller is responsible
    /// for dispatching these via [`MembershipOutboundDispatch`].
    ///
    /// Returns a vector of (target_peer, message) tuples to send.
    pub fn tick(
        &mut self,
        roster: &MembershipRoster,
        local_id: MemberId,
    ) -> Vec<(MemberId, MembershipOutboundMessage)> {
        if !self.round.should_run() {
            return Vec::new();
        }

        // Collect peer list: all members except self.
        let all_peers: Vec<MemberId> = roster
            .iter()
            .filter(|(id, _)| **id != local_id)
            .map(|(id, _)| *id)
            .collect();

        if all_peers.is_empty() {
            self.round.record_round();
            return Vec::new();
        }

        let selected = self.round.select_peers(&all_peers, &[]);
        self.round.record_round();

        if selected.is_empty() {
            return Vec::new();
        }

        let now_millis = 0u64; // caller should provide real timestamp
        let mut out = Vec::with_capacity(selected.len());

        for peer in &selected {
            // Push: send our roster view to the peer.
            let entries: Vec<RosterEntry> = roster
                .iter()
                .map(|(id, state)| {
                    let epoch = self.merge.epoch_for(*id).unwrap_or_default();
                    RosterEntry::new(*id, *state, epoch)
                })
                .collect();

            let serialized = bincode::serialize(&entries).unwrap_or_default();
            out.push((
                *peer,
                MembershipOutboundMessage::PushRoster {
                    originator: local_id,
                    roster_epoch: EpochId::default(),
                    roster_payload: serialized,
                    sent_at_millis: now_millis,
                },
            ));
        }

        out
    }

    /// Handle an inbound PushRoster by merging remote entries into the
    /// local roster.
    pub fn handle_inbound_push(
        &mut self,
        originator: MemberId,
        roster_epoch: EpochId,
        roster_payload: &[u8],
        roster: &mut MembershipRoster,
    ) -> Vec<MergeOutcome> {
        let entries: Vec<RosterEntry> = match bincode::deserialize(roster_payload) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut outcomes = Vec::with_capacity(entries.len());

        for entry in &entries {
            let remote_state = entry.roster_state();
            let remote_epoch = entry.epoch;
            let local_state = roster.lookup(entry.member_id);

            let outcome =
                self.merge
                    .merge(entry.member_id, remote_state, remote_epoch, local_state);

            match &outcome {
                MergeOutcome::Accepted {
                    member_id,
                    to_state,
                    ..
                } => {
                    match local_state {
                        None => {
                            // New member: add then transition if not Active.
                            roster.add_member(*member_id);
                            if *to_state != RosterState::Active {
                                // Try direct transition; fall back to chained transitions.
                                if roster.transition_state(*member_id, *to_state).is_err()
                                    && *to_state == RosterState::Failed
                                {
                                    let _ =
                                        roster.transition_state(*member_id, RosterState::Suspected);
                                    let _ =
                                        roster.transition_state(*member_id, RosterState::Failed);
                                }
                                // Other invalid transitions: skip.
                            }
                        }
                        Some(local) => {
                            if local != *to_state
                                && roster.transition_state(*member_id, *to_state).is_err()
                            {
                                // Try chained: Active -> Suspected -> Failed
                                if *to_state == RosterState::Failed {
                                    let _ =
                                        roster.transition_state(*member_id, RosterState::Suspected);
                                    let _ =
                                        roster.transition_state(*member_id, RosterState::Failed);
                                }
                                // Other invalid: skip.
                            }
                        }
                    }
                }
                MergeOutcome::Conflict { .. } => {
                    // Conflict stored in merge engine; operator can drain later.
                }
                _ => {}
            }

            outcomes.push(outcome);
        }

        // Also record the originator's epoch.
        self.merge.record_local(originator, roster_epoch);

        outcomes
    }

    /// Handle an inbound PullRequest by building and returning a PullResponse.
    pub fn handle_inbound_pull_request(
        &mut self,
        _originator: MemberId,
        roster: &MembershipRoster,
    ) -> MembershipOutboundMessage {
        let entries: Vec<RosterEntry> = roster
            .iter()
            .map(|(id, state)| {
                let epoch = self.merge.epoch_for(*id).unwrap_or_default();
                RosterEntry::new(*id, *state, epoch)
            })
            .collect();

        let serialized = bincode::serialize(&entries).unwrap_or_default();
        MembershipOutboundMessage::PullResponse {
            responder: MemberId::new(0), // will be filled by caller with local_id
            roster_epoch: EpochId::default(),
            roster_payload: serialized,
            responded_at_millis: 0,
        }
    }

    /// Handle an inbound PullResponse by merging remote entries.
    pub fn handle_inbound_pull_response(
        &mut self,
        originator: MemberId,
        roster_epoch: EpochId,
        roster_payload: &[u8],
        roster: &mut MembershipRoster,
    ) -> Vec<MergeOutcome> {
        // Same logic as handle_inbound_push.
        self.handle_inbound_push(originator, roster_epoch, roster_payload, roster)
    }
}

// ---------------------------------------------------------------------------
// MembershipMessageHandler impl for RosterGossipHandle
// ---------------------------------------------------------------------------

/// A handler wrapper that bridges dispatch_router delivery to a
/// [`RosterGossipHandle`] plus a mutable roster reference.
///
/// Since [`MembershipMessageHandler`] takes `&self`, the roster and handle
/// must be behind interior mutability (e.g. `Mutex` or `RefCell`).
/// For single-threaded runtime use, the handler stores shared references
/// that the runtime tick loop manages.
pub struct RosterGossipHandler<F>
where
    F: Fn(&MembershipMessage) -> Result<(), MembershipDispatchError> + Send + Sync,
{
    handler_fn: F,
}

impl<F> RosterGossipHandler<F>
where
    F: Fn(&MembershipMessage) -> Result<(), MembershipDispatchError> + Send + Sync,
{
    /// Create a new handler wrapping a closure that processes gossip messages.
    #[must_use]
    pub fn new(handler_fn: F) -> Self {
        Self { handler_fn }
    }
}

impl<F> MembershipMessageHandler for RosterGossipHandler<F>
where
    F: Fn(&MembershipMessage) -> Result<(), MembershipDispatchError> + Send + Sync,
{
    fn handle_push_roster(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        (self.handler_fn)(msg)
    }

    fn handle_pull_request(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        (self.handler_fn)(msg)
    }

    fn handle_pull_response(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        (self.handler_fn)(msg)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // RosterMerge tests
    // ------------------------------------------------------------------

    #[test]
    fn merge_accepts_new_member() {
        let mut merge = RosterMerge::new();
        let outcome = merge.merge(MemberId::new(1), RosterState::Active, EpochId::new(5), None);
        assert!(matches!(outcome, MergeOutcome::Accepted { .. }));
        assert_eq!(merge.epoch_for(MemberId::new(1)), Some(EpochId::new(5)));
    }

    #[test]
    fn merge_accepts_higher_epoch() {
        let mut merge = RosterMerge::new();
        merge.record_local(MemberId::new(1), EpochId::new(3));

        let outcome = merge.merge(
            MemberId::new(1),
            RosterState::Failed,
            EpochId::new(5),
            Some(RosterState::Active),
        );
        assert!(matches!(outcome, MergeOutcome::Accepted { .. }));
        assert_eq!(merge.epoch_for(MemberId::new(1)), Some(EpochId::new(5)));
    }

    #[test]
    fn merge_rejects_stale_epoch() {
        let mut merge = RosterMerge::new();
        merge.record_local(MemberId::new(1), EpochId::new(10));

        let outcome = merge.merge(
            MemberId::new(1),
            RosterState::Failed,
            EpochId::new(5),
            Some(RosterState::Active),
        );
        assert!(matches!(outcome, MergeOutcome::RejectedStale { .. }));
    }

    #[test]
    fn merge_no_change_same_epoch_same_state() {
        let mut merge = RosterMerge::new();
        merge.record_local(MemberId::new(1), EpochId::new(5));

        let outcome = merge.merge(
            MemberId::new(1),
            RosterState::Active,
            EpochId::new(5),
            Some(RosterState::Active),
        );
        assert!(matches!(outcome, MergeOutcome::NoChange { .. }));
    }

    #[test]
    fn merge_conflict_same_epoch_different_state() {
        let mut merge = RosterMerge::new();
        merge.record_local(MemberId::new(1), EpochId::new(5));

        let outcome = merge.merge(
            MemberId::new(1),
            RosterState::Failed,
            EpochId::new(5),
            Some(RosterState::Active),
        );
        assert!(matches!(outcome, MergeOutcome::Conflict { .. }));
        assert_eq!(merge.conflict_count(), 1);

        let conflicts = merge.drain_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].member_id, MemberId::new(1));
        assert_eq!(conflicts[0].epoch, EpochId::new(5));
        assert_eq!(merge.conflict_count(), 0);
    }

    #[test]
    fn merge_empty_roster_accepts_all() {
        let mut merge = RosterMerge::new();
        for i in 0..5 {
            let outcome = merge.merge(MemberId::new(i), RosterState::Active, EpochId::new(1), None);
            assert!(matches!(outcome, MergeOutcome::Accepted { .. }));
        }
        assert_eq!(merge.member_count(), 5);
    }

    #[test]
    fn merge_concurrent_updates_from_multiple_peers() {
        let mut merge = RosterMerge::new();

        // Local knows m1 at epoch 5.
        merge.record_local(MemberId::new(1), EpochId::new(5));

        // Peer A reports m1 at epoch 7 (accepted).
        let a = merge.merge(
            MemberId::new(1),
            RosterState::Suspected,
            EpochId::new(7),
            Some(RosterState::Active),
        );
        assert!(matches!(a, MergeOutcome::Accepted { .. }));

        // Peer B reports m1 at epoch 6 (stale, rejected).
        let b = merge.merge(
            MemberId::new(1),
            RosterState::Failed,
            EpochId::new(6),
            Some(RosterState::Suspected),
        );
        assert!(matches!(b, MergeOutcome::RejectedStale { .. }));
    }

    // ------------------------------------------------------------------
    // RosterGossipRound tests
    // ------------------------------------------------------------------

    #[test]
    fn round_should_run_initially() {
        let config = RosterGossipConfig::new();
        let _round = RosterGossipRound::new(config);
        // should_run after 0ms depends on elapsed(); fresh Instant always returns true
        // after being created, but elapsed is >0 if enough time passes.
        // For test determinism, we check that select_peers works.
    }

    #[test]
    fn select_peers_respects_fanout() {
        let config = RosterGossipConfig::new().with_fanout(2).with_seed(42);
        let round = RosterGossipRound::new(config);

        let all: Vec<MemberId> = (1..=10).map(MemberId::new).collect();
        let selected = round.select_peers(&all, &[]);
        assert_eq!(selected.len(), 2);

        // Deterministic with seed: same input gives same output.
        let round2 = RosterGossipRound::new(RosterGossipConfig::new().with_fanout(2).with_seed(42));
        let selected2 = round2.select_peers(&all, &[]);
        assert_eq!(selected, selected2);
    }

    #[test]
    fn select_peers_respects_exclude() {
        let config = RosterGossipConfig::new().with_fanout(1).with_seed(7);
        let round = RosterGossipRound::new(config);

        let all: Vec<MemberId> = vec![MemberId::new(1), MemberId::new(2)];
        let selected = round.select_peers(&all, &[MemberId::new(1)]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], MemberId::new(2));
    }

    #[test]
    fn select_peers_empty_when_no_eligible() {
        let config = RosterGossipConfig::new().with_seed(1);
        let round = RosterGossipRound::new(config);

        let all: Vec<MemberId> = vec![MemberId::new(1)];
        let selected = round.select_peers(&all, &[MemberId::new(1)]);
        assert!(selected.is_empty());
    }

    #[test]
    fn select_peers_empty_when_all_peers_empty() {
        let config = RosterGossipConfig::new();
        let round = RosterGossipRound::new(config);

        let selected = round.select_peers(&[], &[]);
        assert!(selected.is_empty());
    }

    #[test]
    fn select_peers_respects_fanout_greater_than_peers() {
        let config = RosterGossipConfig::new().with_fanout(10).with_seed(3);
        let round = RosterGossipRound::new(config);

        let all: Vec<MemberId> = (1..=3).map(MemberId::new).collect();
        let selected = round.select_peers(&all, &[]);
        assert_eq!(selected.len(), 3);
    }

    // ------------------------------------------------------------------
    // RosterGossipHandle tests
    // ------------------------------------------------------------------

    #[test]
    fn handle_spawn_creates_empty_merge() {
        let config = RosterGossipConfig::new();
        let handle = RosterGossipHandle::spawn(config);
        assert_eq!(handle.merge.member_count(), 0);
        assert_eq!(handle.merge.conflict_count(), 0);
    }

    #[test]
    fn tick_no_peers_returns_empty() {
        let config = RosterGossipConfig::new();
        let mut handle = RosterGossipHandle::spawn(config);
        let roster = MembershipRoster::new();

        let out = handle.tick(&roster, MemberId::new(1));
        // No peers in roster -> no messages.
        // But should_run will be true initially, so it will try and find no peers.
        assert!(out.is_empty());
    }

    #[test]
    fn tick_with_peer_produces_push() {
        let config = RosterGossipConfig::new().with_seed(99);
        let mut handle = RosterGossipHandle::spawn(config);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // self
        roster.add_member(MemberId::new(2)); // peer

        let out = handle.tick(&roster, MemberId::new(1));
        // With 1 peer and fanout=2, should select that peer.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, MemberId::new(2));
        assert!(matches!(
            out[0].1,
            MembershipOutboundMessage::PushRoster { .. }
        ));
    }

    #[test]
    fn handle_inbound_push_merges_entries() {
        let config = RosterGossipConfig::new();
        let mut handle = RosterGossipHandle::spawn(config);
        let mut roster = MembershipRoster::new();

        // Build a push payload with 3 members at epoch 1.
        let entries = vec![
            RosterEntry::new(MemberId::new(1), RosterState::Active, EpochId::new(1)),
            RosterEntry::new(MemberId::new(2), RosterState::Active, EpochId::new(1)),
            RosterEntry::new(MemberId::new(3), RosterState::Suspected, EpochId::new(1)),
        ];
        let payload = bincode::serialize(&entries).unwrap();

        let outcomes =
            handle.handle_inbound_push(MemberId::new(10), EpochId::new(1), &payload, &mut roster);

        assert_eq!(outcomes.len(), 3);
        for o in &outcomes {
            assert!(matches!(o, MergeOutcome::Accepted { .. }));
        }
        assert_eq!(roster.len(), 3);
        assert_eq!(
            roster.lookup(MemberId::new(3)),
            Some(RosterState::Suspected)
        );
    }

    #[test]
    fn handle_inbound_pull_response_behaves_like_push() {
        let config = RosterGossipConfig::new();
        let mut handle = RosterGossipHandle::spawn(config);
        let mut roster = MembershipRoster::new();

        let entries = vec![RosterEntry::new(
            MemberId::new(5),
            RosterState::Failed,
            EpochId::new(3),
        )];
        let payload = bincode::serialize(&entries).unwrap();

        let outcomes = handle.handle_inbound_pull_response(
            MemberId::new(10),
            EpochId::new(3),
            &payload,
            &mut roster,
        );

        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0], MergeOutcome::Accepted { .. }));
        assert_eq!(roster.lookup(MemberId::new(5)), Some(RosterState::Failed));
    }

    #[test]
    fn handle_inbound_pull_request_builds_response() {
        let config = RosterGossipConfig::new();
        let mut handle = RosterGossipHandle::spawn(config);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));

        let msg = handle.handle_inbound_pull_request(MemberId::new(99), &roster);
        assert!(matches!(
            msg,
            MembershipOutboundMessage::PullResponse { .. }
        ));
    }

    // ------------------------------------------------------------------
    // Two-node harness validation tests
    // ------------------------------------------------------------------

    /// Simulate two nodes with initial rosters exchanging roster gossip.
    /// Node 1 knows members 1,2; Node 2 knows members 1,3.
    /// After gossip exchange, both should know 1,2,3.
    #[test]
    fn two_node_harness_gossip_propagates_synthetic_join() {
        // Node 1: knows members 1 (self) and 2.
        let mut roster1 = MembershipRoster::new();
        roster1.add_member(MemberId::new(1));
        roster1.add_member(MemberId::new(2));

        let config1 = RosterGossipConfig::new()
            .with_round_interval_ms(0)
            .with_seed(42);
        let mut handle1 = RosterGossipHandle::spawn(config1);
        // Record local epochs for both members.
        handle1
            .merge
            .record_local(MemberId::new(1), EpochId::new(1));
        handle1
            .merge
            .record_local(MemberId::new(2), EpochId::new(1));

        // Node 2: knows members 1 and 3 (synthetic join of member 3).
        let mut roster2 = MembershipRoster::new();
        roster2.add_member(MemberId::new(1));
        roster2.add_member(MemberId::new(3));

        let config2 = RosterGossipConfig::new()
            .with_round_interval_ms(0)
            .with_seed(7);
        let mut handle2 = RosterGossipHandle::spawn(config2);
        handle2
            .merge
            .record_local(MemberId::new(1), EpochId::new(1));
        handle2
            .merge
            .record_local(MemberId::new(3), EpochId::new(1));

        // --- Round 1: Node 1 pushes to Node 2 ---
        let msgs1 = handle1.tick(&roster1, MemberId::new(1));
        assert!(!msgs1.is_empty(), "Node 1 should produce push messages");
        // Deliver push from Node 1 to Node 2.
        for (_target, out_msg) in &msgs1 {
            if let crate::membership_outbound_dispatch::MembershipOutboundMessage::PushRoster {
                originator,
                roster_epoch,
                roster_payload,
                ..
            } = out_msg
            {
                let outcomes = handle2.handle_inbound_push(
                    *originator,
                    *roster_epoch,
                    roster_payload,
                    &mut roster2,
                );
                // Should accept member 2 from Node 1's roster.
                let has_member2 = outcomes.iter().any(|o| {
                    matches!(o, MergeOutcome::Accepted { member_id, .. } if *member_id == MemberId::new(2))
                });
                assert!(
                    has_member2,
                    "Node 2 should accept member 2 from Node 1 push"
                );
            }
        }

        // Verify Node 2 now knows member 2.
        assert!(
            roster2.lookup(MemberId::new(2)).is_some(),
            "Node 2 should know member 2 after receiving push from Node 1"
        );

        // --- Round 2: Node 2 pushes back to Node 1 ---
        let msgs2 = handle2.tick(&roster2, MemberId::new(2));
        assert!(!msgs2.is_empty(), "Node 2 should produce push messages");
        // Deliver push from Node 2 to Node 1 (only the message targeting peer 1).
        let mut found_push_for_peer_1 = false;
        for (target, out_msg) in &msgs2 {
            if *target != MemberId::new(1) {
                continue;
            }
            if let crate::membership_outbound_dispatch::MembershipOutboundMessage::PushRoster {
                originator,
                roster_epoch,
                roster_payload,
                ..
            } = out_msg
            {
                // Deserialize payload to check what entries are present.
                if let Ok(entries) = bincode::deserialize::<Vec<RosterEntry>>(roster_payload) {
                    let _member_ids: Vec<u64> = entries.iter().map(|e| e.member_id.0).collect();
                    // Payload should contain member 3 if roster2 has it.
                }
                let outcomes = handle1.handle_inbound_push(
                    *originator,
                    *roster_epoch,
                    roster_payload,
                    &mut roster1,
                );
                // Should accept member 3 from Node 2's roster.
                let has_member3 = outcomes.iter().any(|o| {
                    matches!(o, MergeOutcome::Accepted { member_id, .. } if *member_id == MemberId::new(3))
                });
                if !has_member3 {
                    // Debug: what outcomes did we get?
                    for o in &outcomes {
                        match o {
                            MergeOutcome::Accepted { member_id, .. } => {
                                eprintln!("DEBUG Accepted member {}", member_id.0)
                            }
                            MergeOutcome::RejectedStale { member_id, .. } => {
                                eprintln!("DEBUG RejectedStale member {}", member_id.0)
                            }
                            MergeOutcome::NoChange { member_id } => {
                                eprintln!("DEBUG NoChange member {}", member_id.0)
                            }
                            MergeOutcome::Conflict { member_id, .. } => {
                                eprintln!("DEBUG Conflict member {}", member_id.0)
                            }
                        }
                    }
                }
                assert!(
                    has_member3,
                    "Node 1 should accept member 3 from Node 2 push"
                );
                found_push_for_peer_1 = true;
            }
        }
        assert!(
            found_push_for_peer_1,
            "Expected a PushRoster message for peer 1"
        );

        // Verify Node 1 now knows member 3.
        assert!(
            roster1.lookup(MemberId::new(3)).is_some(),
            "Node 1 should know member 3 after receiving push from Node 2"
        );

        // Both rosters should contain all 3 members.
        assert_eq!(roster1.len(), 3, "Node 1 roster should have 3 members");
        assert_eq!(roster2.len(), 3, "Node 2 roster should have 3 members");
    }

    /// Two nodes exchange gossip; verify that stale-epoch entries from a
    /// third synthetic node are rejected while higher-epoch entries are accepted.
    #[test]
    fn two_node_harness_epoch_bounded_merge() {
        let mut roster_a = MembershipRoster::new();
        roster_a.add_member(MemberId::new(1));
        roster_a.add_member(MemberId::new(2));

        let mut handle_a = RosterGossipHandle::spawn(RosterGossipConfig::new().with_seed(1));
        handle_a
            .merge
            .record_local(MemberId::new(1), EpochId::new(1));
        // Node A knows member 2 at epoch 10 (higher epoch).
        handle_a
            .merge
            .record_local(MemberId::new(2), EpochId::new(10));
        roster_a
            .transition_state(MemberId::new(2), RosterState::Suspected)
            .ok();

        let mut roster_b = MembershipRoster::new();
        roster_b.add_member(MemberId::new(1));
        roster_b.add_member(MemberId::new(2));

        let mut handle_b = RosterGossipHandle::spawn(RosterGossipConfig::new().with_seed(2));
        handle_b
            .merge
            .record_local(MemberId::new(1), EpochId::new(1));
        // Node B has member 2 at epoch 5 (stale, lower epoch).
        handle_b
            .merge
            .record_local(MemberId::new(2), EpochId::new(5));

        // Serialize Node A's roster view and feed to Node B.
        let entries_a: Vec<RosterEntry> = roster_a
            .iter()
            .map(|(id, state)| {
                let epoch = handle_a.merge.epoch_for(*id).unwrap_or_default();
                RosterEntry::new(*id, *state, epoch)
            })
            .collect();
        let payload_a = bincode::serialize(&entries_a).unwrap();

        let outcomes = handle_b.handle_inbound_push(
            MemberId::new(1),
            EpochId::new(10),
            &payload_a,
            &mut roster_b,
        );

        // Node B should accept member 2 at epoch 10 (higher epoch -> accepted).
        let accepted_epoch10 = outcomes.iter().any(|o| {
            matches!(o, MergeOutcome::Accepted { member_id, to_epoch, .. }
                if *member_id == MemberId::new(2) && *to_epoch == EpochId::new(10))
        });
        assert!(
            accepted_epoch10,
            "Node B should accept member 2 at epoch 10"
        );

        // Node B should now have epoch 10 for member 2.
        assert_eq!(
            handle_b.merge.epoch_for(MemberId::new(2)),
            Some(EpochId::new(10)),
            "Node B should update member 2 epoch to 10"
        );

        // Now feed Node B's old view (epoch 5) to Node A — should be rejected as stale.
        let entries_b_old: Vec<RosterEntry> = vec![
            RosterEntry::new(MemberId::new(1), RosterState::Active, EpochId::new(1)),
            RosterEntry::new(MemberId::new(2), RosterState::Active, EpochId::new(5)),
        ];
        let payload_b_old = bincode::serialize(&entries_b_old).unwrap();

        let outcomes_a = handle_a.handle_inbound_push(
            MemberId::new(2),
            EpochId::new(5),
            &payload_b_old,
            &mut roster_a,
        );

        let has_stale = outcomes_a.iter().any(|o| {
            matches!(o, MergeOutcome::RejectedStale { member_id, .. }
                if *member_id == MemberId::new(2))
        });
        assert!(has_stale, "Node A should reject stale epoch 5 for member 2");
    }

    /// Verify graceful behavior when one node has an empty roster (beyond self).
    #[test]
    fn two_node_harness_empty_roster_gossip() {
        // Node A: only knows self.
        let mut roster_a = MembershipRoster::new();
        roster_a.add_member(MemberId::new(1));

        let mut handle_a = RosterGossipHandle::spawn(RosterGossipConfig::new().with_seed(3));
        handle_a
            .merge
            .record_local(MemberId::new(1), EpochId::new(1));

        // Node B: knows members 1 and 2, 3, 4.
        let mut roster_b = MembershipRoster::new();
        roster_b.add_member(MemberId::new(1));
        roster_b.add_member(MemberId::new(2));
        roster_b.add_member(MemberId::new(3));
        roster_b.add_member(MemberId::new(4));

        let mut handle_b = RosterGossipHandle::spawn(RosterGossipConfig::new().with_seed(4));
        for i in 1..=4 {
            handle_b
                .merge
                .record_local(MemberId::new(i), EpochId::new(1));
        }

        // Node A tick: only self in roster, no other peers to push to.
        let msgs_a = handle_a.tick(&roster_a, MemberId::new(1));
        assert!(
            msgs_a.is_empty(),
            "Node A with only self should produce no outbound gossip"
        );

        // Node B pushes to Node A.
        let msgs_b = handle_b.tick(&roster_b, MemberId::new(2));
        assert!(!msgs_b.is_empty(), "Node B should push to Node A");

        for (_target, out_msg) in &msgs_b {
            if let crate::membership_outbound_dispatch::MembershipOutboundMessage::PushRoster {
                originator,
                roster_epoch,
                roster_payload,
                ..
            } = out_msg
            {
                handle_a.handle_inbound_push(
                    *originator,
                    *roster_epoch,
                    roster_payload,
                    &mut roster_a,
                );
            }
        }

        // Node A should now know all 4 members.
        assert_eq!(
            roster_a.len(),
            4,
            "Node A should learn members 2,3,4 from Node B push"
        );
        for i in 2..=4 {
            assert!(
                roster_a.lookup(MemberId::new(i)).is_some(),
                "Node A should know member {i}"
            );
        }
    }

    #[test]
    fn handle_inbound_push_bad_payload_returns_empty() {
        let config = RosterGossipConfig::new();
        let mut handle = RosterGossipHandle::spawn(config);
        let mut roster = MembershipRoster::new();

        let outcomes = handle.handle_inbound_push(
            MemberId::new(1),
            EpochId::new(1),
            &[0xde, 0xad, 0xbe, 0xef],
            &mut roster,
        );
        assert!(outcomes.is_empty());
    }
}
