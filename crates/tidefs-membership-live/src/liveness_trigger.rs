//! Liveness-to-epoch trigger dispatch: bridges health-score-driven
//! peer liveness state transitions to epoch-advance proposal generation.
//!
//! The [`LivenessTriggerDispatcher`] sits between the
//! [`crate::peer_liveness::HealthScoreLivenessTracker`] (health scorer,
//! #6035) and the [`crate::epoch_coordinator::EpochAdvanceCoordinator`]
//! (#5962). It detects state transitions — Alive→Suspect, Suspect→Dead,
//! Suspect→Alive, Dead→Alive — and maps them to [`PeerLivenessChange`]
//! events that drive epoch-advance proposals.
//!
//! ## Transition mapping
//!
//! | Health Scorer Transition | Binary Liveness Change  | Proposal |
//! |--------------------------|-------------------------|----------|
//! | Unknown → Alive          | no-op                   | none     |
//! | Alive → Suspect          | no-op (pass-through)    | none     |
//! | Suspect → Dead           | Alive → Dead            | removal  |
//! | Alive → Dead (direct)    | Alive → Dead            | removal  |
//! | Suspect → Alive          | Dead → Alive            | reinstate|
//! | Dead → Alive             | Dead → Alive            | reinstate|
//!
//! ## Debounce
//!
//! Each peer enters a cooldown window after a proposal is generated.
//! Further transitions within the cooldown window are suppressed to
//! prevent proposal flapping on rapid health-score oscillation.
//!
//! ## Security model
//!
//! This module is pure event-driven dispatch operating within the existing
//! transport/session security boundary. No new wire types, framing, or
//! protocol layers are introduced.

use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

use crate::epoch_coordinator::{EpochAdvanceCoordinator, PeerLivenessChange, PeerLivenessStatus};
use crate::peer_liveness::{HealthScoreLivenessTracker, PeerLivenessState};

// ---------------------------------------------------------------------------
// LivenessTriggerConfig
// ---------------------------------------------------------------------------

/// Configuration for the liveness trigger dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivenessTriggerConfig {
    /// Cooldown period in milliseconds after a proposal is generated
    /// for a peer before that peer can trigger another proposal.
    /// Prevents rapid flapping on repeated transitions.
    pub cooldown_ms: u64,
    /// Whether to generate reinstatement proposals when a peer recovers
    /// from Suspect or Dead back to Alive.
    pub enable_reinstatement: bool,
}

impl Default for LivenessTriggerConfig {
    fn default() -> Self {
        Self {
            cooldown_ms: 5_000,
            enable_reinstatement: true,
        }
    }
}

impl LivenessTriggerConfig {
    /// Create a new config with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cooldown period in milliseconds.
    #[must_use]
    pub fn with_cooldown(mut self, cooldown_ms: u64) -> Self {
        self.cooldown_ms = cooldown_ms;
        self
    }

    /// Enable or disable reinstatement proposals.
    #[must_use]
    pub fn with_reinstatement(mut self, enable: bool) -> Self {
        self.enable_reinstatement = enable;
        self
    }
}

// ---------------------------------------------------------------------------
// TriggerOutcome
// ---------------------------------------------------------------------------

/// Outcome of processing one peer's liveness state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerOutcome {
    /// No proposal generated: no-op transition, peer not tracked, or
    /// cooldown window active.
    Suppressed,
    /// A removal proposal was generated (peer transitioned to Dead).
    RemovalProposed {
        /// The peer that was proposed for removal.
        member_id: MemberId,
    },
    /// A reinstatement proposal was generated (peer recovered to Alive).
    ReinstatementProposed {
        /// The peer that was proposed for reinstatement.
        member_id: MemberId,
    },
}

impl TriggerOutcome {
    /// Whether any proposal was generated.
    #[must_use]
    pub fn is_proposed(&self) -> bool {
        matches!(
            self,
            TriggerOutcome::RemovalProposed { .. } | TriggerOutcome::ReinstatementProposed { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// LivenessTriggerDispatcher
// ---------------------------------------------------------------------------

/// Bridges health-score-driven peer liveness transitions from
/// [`HealthScoreLivenessTracker`] to [`EpochAdvanceCoordinator`],
/// generating epoch-advance proposals when peers transition between
/// Alive, Suspect, and Dead states.
///
/// # Usage
///
/// 1. Construct with [`Self::new`].
/// 2. Call [`Self::process_tracker`] periodically (e.g., each runtime
///    tick) with the current tracker state and a timestamp.
/// 3. Outcomes are returned immediately; proposals flow into the
///    coordinator automatically.
pub struct LivenessTriggerDispatcher {
    config: LivenessTriggerConfig,
    /// Last known state per peer (used to detect transitions).
    previous_state: BTreeMap<MemberId, PeerLivenessState>,
    /// Last time a proposal was generated for each peer (milliseconds
    /// since epoch), used for cooldown enforcement.
    last_proposal_time: BTreeMap<MemberId, u64>,
}

impl LivenessTriggerDispatcher {
    /// Create a new dispatcher with the given configuration.
    #[must_use]
    pub fn new(config: LivenessTriggerConfig) -> Self {
        Self {
            config,
            previous_state: BTreeMap::new(),
            last_proposal_time: BTreeMap::new(),
        }
    }

    /// Create a dispatcher with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LivenessTriggerConfig::default())
    }

    /// Process all tracked peers from the health scorer, detecting
    /// state transitions and feeding appropriate proposals into the
    /// epoch-advance coordinator.
    ///
    /// `now_ms` is the current time in milliseconds since epoch, used
    /// for cooldown enforcement and liveness-change timestamps.
    ///
    /// Returns one [`TriggerOutcome`] per peer that was processed.
    /// Peers that are not tracked by the health scorer are skipped.
    pub fn process_tracker(
        &mut self,
        tracker: &HealthScoreLivenessTracker,
        coordinator: &mut EpochAdvanceCoordinator,
        now_ms: u64,
    ) -> Vec<TriggerOutcome> {
        let mut outcomes = Vec::new();

        // Collect current states for all tracked peers
        let current_states: Vec<(MemberId, PeerLivenessState)> = tracker.iter().collect();

        for (member_id, current_state) in current_states {
            let previous = self.previous_state.get(&member_id).copied();

            // Store current state for next poll
            self.previous_state.insert(member_id, current_state);

            // Detect transition
            let outcome =
                self.evaluate_transition(member_id, previous, current_state, coordinator, now_ms);
            outcomes.push(outcome);
        }

        outcomes
    }

    /// Process a single peer's state transition explicitly, without
    /// consulting the health scorer tracker. Useful for testing and
    /// for injecting externally-detected transitions.
    ///
    /// Returns the [`TriggerOutcome`] for this transition.
    pub fn process_single(
        &mut self,
        member_id: MemberId,
        previous_state: PeerLivenessState,
        current_state: PeerLivenessState,
        coordinator: &mut EpochAdvanceCoordinator,
        now_ms: u64,
    ) -> TriggerOutcome {
        self.previous_state.insert(member_id, current_state);
        self.evaluate_transition(
            member_id,
            Some(previous_state),
            current_state,
            coordinator,
            now_ms,
        )
    }

    /// Reset tracking state for a specific peer (e.g., on reconnect).
    pub fn reset_peer(&mut self, member_id: MemberId) {
        self.previous_state.remove(&member_id);
        self.last_proposal_time.remove(&member_id);
    }

    /// Reset all tracking state.
    pub fn reset_all(&mut self) {
        self.previous_state.clear();
        self.last_proposal_time.clear();
    }

    /// Number of peers with known previous state.
    #[must_use]
    pub fn tracked_peer_count(&self) -> usize {
        self.previous_state.len()
    }

    /// Check whether a peer is currently in the cooldown window.
    #[must_use]
    pub fn in_cooldown(&self, member_id: MemberId, now_ms: u64) -> bool {
        self.last_proposal_time
            .get(&member_id)
            .is_some_and(|&last| now_ms.saturating_sub(last) < self.config.cooldown_ms)
    }

    /// Access the configuration.
    #[must_use]
    pub fn config(&self) -> &LivenessTriggerConfig {
        &self.config
    }

    // -- private --

    /// Evaluate a single state transition and, if appropriate, feed a
    /// proposal into the coordinator.
    fn evaluate_transition(
        &mut self,
        member_id: MemberId,
        previous: Option<PeerLivenessState>,
        current: PeerLivenessState,
        coordinator: &mut EpochAdvanceCoordinator,
        now_ms: u64,
    ) -> TriggerOutcome {
        // No previous state → first observation, store and skip
        let prev = match previous {
            Some(s) => s,
            None => return TriggerOutcome::Suppressed,
        };

        // Same state → no transition
        if prev == current {
            return TriggerOutcome::Suppressed;
        }

        // Map the 3-state transition to a binary PeerLivenessChange.
        // The match covers all reachable transitions; same-state pairs
        // are unreachable due to the guard above.  The wildcard arm
        // satisfies exhaustiveness but is never executed.
        #[allow(unreachable_patterns)]
        let change = match (prev, current) {
            // Alive → Suspect: suppressed (pass-through, no proposal)
            (PeerLivenessState::Alive, PeerLivenessState::Suspect) => {
                return TriggerOutcome::Suppressed;
            }
            // Suspect → Dead: removal proposal
            (PeerLivenessState::Suspect, PeerLivenessState::Dead) => Some(PeerLivenessChange::new(
                member_id,
                PeerLivenessStatus::Alive,
                PeerLivenessStatus::Dead,
                now_ms,
            )),
            // Alive → Dead (direct, e.g. set_state override): removal
            (PeerLivenessState::Alive, PeerLivenessState::Dead) => Some(PeerLivenessChange::new(
                member_id,
                PeerLivenessStatus::Alive,
                PeerLivenessStatus::Dead,
                now_ms,
            )),
            // Suspect → Alive: reinstatement (if enabled)
            (PeerLivenessState::Suspect, PeerLivenessState::Alive) => {
                if self.config.enable_reinstatement {
                    Some(PeerLivenessChange::new(
                        member_id,
                        PeerLivenessStatus::Dead,
                        PeerLivenessStatus::Alive,
                        now_ms,
                    ))
                } else {
                    return TriggerOutcome::Suppressed;
                }
            }
            // Dead → Alive: reinstatement (if enabled)
            (PeerLivenessState::Dead, PeerLivenessState::Alive) => {
                if self.config.enable_reinstatement {
                    Some(PeerLivenessChange::new(
                        member_id,
                        PeerLivenessStatus::Dead,
                        PeerLivenessStatus::Alive,
                        now_ms,
                    ))
                } else {
                    return TriggerOutcome::Suppressed;
                }
            }
            // Unknown → Alive: initial observation, no proposal
            (PeerLivenessState::Unknown, PeerLivenessState::Alive) => {
                return TriggerOutcome::Suppressed;
            }
            // Unknown → anything else: unexpected, suppress
            (PeerLivenessState::Unknown, _) => {
                return TriggerOutcome::Suppressed;
            }
            // Any → Unknown: reset, no proposal
            (_, PeerLivenessState::Unknown) => {
                return TriggerOutcome::Suppressed;
            }
            // All remaining combos unreachable due to same-state guard:
            _ => return TriggerOutcome::Suppressed,
        };

        let change = match change {
            Some(c) => c,
            None => return TriggerOutcome::Suppressed,
        };

        // Cooldown check: suppress if within cooldown window
        if self.in_cooldown(member_id, now_ms) {
            return TriggerOutcome::Suppressed;
        }

        // Feed the change into the coordinator
        coordinator.on_liveness_change(change);

        // Record proposal time for cooldown
        self.last_proposal_time.insert(member_id, now_ms);

        // Return the appropriate outcome
        match current {
            PeerLivenessState::Dead => TriggerOutcome::RemovalProposed { member_id },
            PeerLivenessState::Alive => TriggerOutcome::ReinstatementProposed { member_id },
            _ => TriggerOutcome::Suppressed,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_coordinator::EpochView;
    use crate::peer_liveness::HealthScoreLivenessConfig;
    use std::sync::{Arc, Mutex};

    // -- helpers --

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    struct TestSubscriber {
        views: Arc<Mutex<Vec<EpochView>>>,
    }

    impl TestSubscriber {
        fn new_with_handle() -> (Self, Arc<Mutex<Vec<EpochView>>>) {
            let handle = Arc::new(Mutex::new(Vec::new()));
            let sub = Self {
                views: Arc::clone(&handle),
            };
            (sub, handle)
        }
    }

    impl crate::epoch_coordinator::EpochCommitSubscriber for TestSubscriber {
        fn on_epoch_committed(&self, view: &EpochView) {
            self.views.lock().unwrap().push(view.clone());
        }
    }

    fn new_coordinator(members: Vec<MemberId>) -> EpochAdvanceCoordinator {
        let mut c = EpochAdvanceCoordinator::new(1);
        c.initialize(members, now_ms());
        c
    }

    fn new_tracker_with_peers(member_ids: &[u64]) -> HealthScoreLivenessTracker {
        let cfg = HealthScoreLivenessConfig::default();
        let mut tracker = HealthScoreLivenessTracker::new(cfg);
        for &id in member_ids {
            tracker.update_score(MemberId::new(id), 0.9);
        }
        tracker
    }

    // -- Dead transition: Suspect -> Dead generates removal proposal --

    #[test]
    fn suspect_to_dead_generates_removal() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let outcome = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );

        assert_eq!(
            outcome,
            TriggerOutcome::RemovalProposed {
                member_id: MemberId::new(2)
            }
        );

        let view = coord.current_view().unwrap();
        assert!(!view.contains(MemberId::new(2)));
        assert_eq!(view.member_count(), 2);

        let views = handle.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert!(!views[0].contains(MemberId::new(2)));
    }

    // -- Alive -> Dead (direct) --

    #[test]
    fn alive_to_dead_direct_generates_removal() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let outcome = dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Alive,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );

        assert_eq!(
            outcome,
            TriggerOutcome::RemovalProposed {
                member_id: MemberId::new(1)
            }
        );

        let view = coord.current_view().unwrap();
        assert!(!view.contains(MemberId::new(1)));
    }

    // -- Alive -> Suspect: suppressed --

    #[test]
    fn alive_to_suspect_is_suppressed() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let outcome = dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Alive,
            PeerLivenessState::Suspect,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 0);
        let view = coord.current_view().unwrap();
        assert_eq!(view.member_count(), 2);
        assert!(view.contains(MemberId::new(1)));
    }

    // -- Suspect -> Alive: reinstatement --

    #[test]
    fn suspect_to_alive_generates_reinstatement() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms(),
        );

        assert_eq!(
            outcome,
            TriggerOutcome::ReinstatementProposed {
                member_id: MemberId::new(2)
            }
        );

        let view = coord.current_view().unwrap();
        assert!(view.contains(MemberId::new(1)));
        assert!(view.contains(MemberId::new(2)));
        assert_eq!(view.member_count(), 2);
    }

    // -- Dead -> Alive: reinstatement --

    #[test]
    fn dead_to_alive_generates_reinstatement() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(3),
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms(),
        );

        assert_eq!(
            outcome,
            TriggerOutcome::ReinstatementProposed {
                member_id: MemberId::new(3)
            }
        );

        let view = coord.current_view().unwrap();
        assert!(view.contains(MemberId::new(3)));
    }

    // -- Reinstatement disabled --

    #[test]
    fn reinstatement_suppressed_when_disabled() {
        let config = LivenessTriggerConfig::default().with_reinstatement(false);
        let mut dispatcher = LivenessTriggerDispatcher::new(config);
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
        let view = coord.current_view().unwrap();
        assert!(!view.contains(MemberId::new(2)));
    }

    // -- Same state suppressed --

    #[test]
    fn same_state_is_suppressed() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let outcome = dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Alive,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 0);
    }

    // -- Unknown -> Alive suppressed --

    #[test]
    fn unknown_to_alive_is_suppressed() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Unknown,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 0);
    }

    // -- Unknown -> Suspect suppressed --

    #[test]
    fn unknown_to_suspect_is_suppressed() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Unknown,
            PeerLivenessState::Suspect,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
    }

    // -- Cooldown: rapid flapping suppressed --

    #[test]
    fn rapid_flapping_within_cooldown_is_suppressed() {
        let config = LivenessTriggerConfig::default().with_cooldown(10_000);
        let mut dispatcher = LivenessTriggerDispatcher::new(config);
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        let outcome1 = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );
        assert!(outcome1.is_proposed());
        assert_eq!(coord.epoch_counter(), 1);

        let outcome2 = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms() + 1_000,
        );
        assert_eq!(outcome2, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 1);

        let outcome3 = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Alive,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms() + 2_000,
        );
        assert_eq!(outcome3, TriggerOutcome::Suppressed);
    }

    // -- Cooldown expires --

    #[test]
    fn proposal_allowed_after_cooldown_expires() {
        let config = LivenessTriggerConfig::default().with_cooldown(5_000);
        let mut dispatcher = LivenessTriggerDispatcher::new(config);
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        let outcome1 = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );
        assert!(outcome1.is_proposed());

        let outcome2 = dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            now_ms() + 6_000,
        );
        assert_eq!(
            outcome2,
            TriggerOutcome::ReinstatementProposed {
                member_id: MemberId::new(2)
            }
        );
        assert_eq!(coord.epoch_counter(), 2);
    }

    // -- process_tracker with real HealthScoreLivenessTracker --

    #[test]
    fn process_tracker_detects_active_transitions() {
        let mut tracker = HealthScoreLivenessTracker::new(HealthScoreLivenessConfig::default());
        tracker.update_score(MemberId::new(1), 0.9);
        tracker.update_score(MemberId::new(2), 0.9);
        tracker.update_score(MemberId::new(2), 0.1);
        tracker.update_score(MemberId::new(2), 0.0);
        tracker.update_score(MemberId::new(3), 0.9);

        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        dispatcher
            .previous_state
            .insert(MemberId::new(1), PeerLivenessState::Alive);
        dispatcher
            .previous_state
            .insert(MemberId::new(2), PeerLivenessState::Alive);
        dispatcher
            .previous_state
            .insert(MemberId::new(3), PeerLivenessState::Alive);

        let outcomes = dispatcher.process_tracker(&tracker, &mut coord, now_ms());

        let peer2_outcome: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, TriggerOutcome::RemovalProposed { member_id } if *member_id == MemberId::new(2)))
            .collect();
        assert!(
            !peer2_outcome.is_empty(),
            "peer 2 should trigger removal: outcomes={outcomes:?}"
        );

        let view = coord.current_view().unwrap();
        assert!(!view.contains(MemberId::new(2)));
    }

    // -- process_tracker only processes peers in tracker --

    #[test]
    fn process_tracker_only_sees_tracked_peers() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let tracker = new_tracker_with_peers(&[1]);

        let outcomes = dispatcher.process_tracker(&tracker, &mut coord, now_ms());
        assert_eq!(outcomes.len(), 1);
    }

    // -- reset_peer and reset_all --

    #[test]
    fn reset_peer_clears_state() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );

        assert!(dispatcher.tracked_peer_count() >= 1);
        assert!(dispatcher.in_cooldown(MemberId::new(1), now_ms()));

        dispatcher.reset_peer(MemberId::new(1));
        assert!(!dispatcher.in_cooldown(MemberId::new(1), now_ms()));
    }

    #[test]
    fn reset_all_clears_everything() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );
        dispatcher.process_single(
            MemberId::new(2),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms() + 1,
        );

        assert!(dispatcher.tracked_peer_count() >= 2);

        dispatcher.reset_all();
        assert_eq!(dispatcher.tracked_peer_count(), 0);
    }

    // -- Config builder methods --

    #[test]
    fn config_builder_methods() {
        let cfg = LivenessTriggerConfig::new()
            .with_cooldown(15_000)
            .with_reinstatement(false);

        assert_eq!(cfg.cooldown_ms, 15_000);
        assert!(!cfg.enable_reinstatement);
    }

    #[test]
    fn default_config_values() {
        let cfg = LivenessTriggerConfig::default();
        assert_eq!(cfg.cooldown_ms, 5_000);
        assert!(cfg.enable_reinstatement);
    }

    // -- TriggerOutcome::is_proposed --

    #[test]
    fn outcome_is_proposed() {
        assert!(TriggerOutcome::RemovalProposed {
            member_id: MemberId::new(1)
        }
        .is_proposed());
        assert!(TriggerOutcome::ReinstatementProposed {
            member_id: MemberId::new(1)
        }
        .is_proposed());
        assert!(!TriggerOutcome::Suppressed.is_proposed());
    }

    // -- Full pipeline: Alive->Suspect->Dead --

    #[test]
    fn full_pipeline_alive_suspect_dead() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let id = MemberId::new(2);

        let o1 = dispatcher.process_single(
            id,
            PeerLivenessState::Alive,
            PeerLivenessState::Suspect,
            &mut coord,
            now_ms(),
        );
        assert_eq!(o1, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 0);

        let o2 = dispatcher.process_single(
            id,
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms() + 1_000,
        );
        assert_eq!(o2, TriggerOutcome::RemovalProposed { member_id: id });
        assert_eq!(coord.epoch_counter(), 1);

        let views = handle.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert!(!views[0].contains(id));
    }

    // -- Recovery pipeline: Dead->Alive after cooldown --

    #[test]
    fn recovery_pipeline_dead_alive_after_cooldown() {
        let config = LivenessTriggerConfig::default().with_cooldown(5_000);
        let mut dispatcher = LivenessTriggerDispatcher::new(config);
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let id = MemberId::new(2);
        let t0 = now_ms();

        dispatcher.process_single(
            id,
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            t0,
        );
        assert!(!coord.current_view().unwrap().contains(id));

        let o2 = dispatcher.process_single(
            id,
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            t0 + 2_000,
        );
        assert_eq!(o2, TriggerOutcome::Suppressed);

        let o3 = dispatcher.process_single(
            id,
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            t0 + 6_000,
        );
        assert_eq!(o3, TriggerOutcome::ReinstatementProposed { member_id: id });
        assert!(coord.current_view().unwrap().contains(id));
        assert_eq!(coord.epoch_counter(), 2);
    }

    // -- Any -> Unknown suppressed --

    #[test]
    fn any_to_unknown_is_suppressed() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let outcome = dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Dead,
            PeerLivenessState::Unknown,
            &mut coord,
            now_ms(),
        );

        assert_eq!(outcome, TriggerOutcome::Suppressed);
        assert_eq!(coord.epoch_counter(), 0);
    }

    // -- in_cooldown query --

    #[test]
    fn in_cooldown_query_after_proposal() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let t0 = now_ms();
        dispatcher.process_single(
            MemberId::new(1),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            t0,
        );

        assert!(dispatcher.in_cooldown(MemberId::new(1), t0 + 1_000));
        assert!(!dispatcher.in_cooldown(MemberId::new(1), t0 + 6_000));
        assert!(!dispatcher.in_cooldown(MemberId::new(99), t0));
    }

    // -- Peer not in roster: coordinator handles it --

    #[test]
    fn dead_non_member_is_noop_in_coordinator() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1)]);

        let outcome = dispatcher.process_single(
            MemberId::new(99),
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            now_ms(),
        );

        assert_eq!(
            outcome,
            TriggerOutcome::RemovalProposed {
                member_id: MemberId::new(99)
            }
        );

        assert_eq!(coord.epoch_counter(), 0);
    }

    // -- Five transition sequence --

    #[test]
    fn five_transition_sequence() {
        let mut dispatcher = LivenessTriggerDispatcher::with_defaults();
        let mut coord = new_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let id = MemberId::new(2);
        let mut t = now_ms();

        let o1 = dispatcher.process_single(
            id,
            PeerLivenessState::Alive,
            PeerLivenessState::Suspect,
            &mut coord,
            t,
        );
        assert_eq!(o1, TriggerOutcome::Suppressed);
        t += 1_000;

        let o2 = dispatcher.process_single(
            id,
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            t,
        );
        assert!(matches!(o2, TriggerOutcome::RemovalProposed { .. }));
        t += 6_000;

        let o3 = dispatcher.process_single(
            id,
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
            &mut coord,
            t,
        );
        assert!(matches!(o3, TriggerOutcome::ReinstatementProposed { .. }));
        t += 6_000;

        let _ = dispatcher.process_single(
            id,
            PeerLivenessState::Alive,
            PeerLivenessState::Suspect,
            &mut coord,
            t,
        );
        t += 1_000;
        let o5 = dispatcher.process_single(
            id,
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            &mut coord,
            t,
        );
        assert!(matches!(o5, TriggerOutcome::RemovalProposed { .. }));

        let views = handle.lock().unwrap().clone();
        assert_eq!(views.len(), 3);
        assert_eq!(views[0].epoch_number.0, 1);
        assert_eq!(views[1].epoch_number.0, 2);
        assert_eq!(views[2].epoch_number.0, 3);
    }
}
